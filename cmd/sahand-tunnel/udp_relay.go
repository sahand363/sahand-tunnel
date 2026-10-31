package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	udpRelayMagic0 byte = 0x55 // 'U'
	udpRelayMagic1 byte = 0x52 // 'R'

	udpRelayTypeProbe        byte = 0x01
	udpRelayTypeProbeAck     byte = 0x02
	udpRelayTypeParitySync   byte = 0x03
	udpRelayTypeParityAck    byte = 0x04
	udpRelayTypeData         byte = 0x05

	// 16-byte compact binary UDP Relay header:
	// [Magic:2][Type:1][Flags:1][SessionID:4][TargetPort:2][HMAC-48:6]
	udpRelayHeaderSize = 16
	udpRelayIdleTTL    = 60 * time.Second
)

func computeUDPRelayTag(authKey []byte, pktType, flags byte, sessionID uint32, targetPort uint16, payload []byte) [6]byte {
	var hdr [10]byte
	hdr[0] = udpRelayMagic0
	hdr[1] = udpRelayMagic1
	hdr[2] = pktType
	hdr[3] = flags
	binary.BigEndian.PutUint32(hdr[4:8], sessionID)
	binary.BigEndian.PutUint16(hdr[8:10], targetPort)

	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write(hdr[:])
	if len(payload) > 64 {
		_, _ = mac.Write(payload[:64])
	} else {
		_, _ = mac.Write(payload)
	}
	sum := mac.Sum(nil)
	var tag [6]byte
	copy(tag[:], sum[:6])
	return tag
}

func packUDPRelayDatagram(
	authKey []byte,
	pktType, flags byte,
	sessionID uint32,
	targetPort uint16,
	payload []byte,
) []byte {
	tag := computeUDPRelayTag(authKey, pktType, flags, sessionID, targetPort, payload)
	out := make([]byte, udpRelayHeaderSize+len(payload))
	out[0] = udpRelayMagic0
	out[1] = udpRelayMagic1
	out[2] = pktType
	out[3] = flags
	binary.BigEndian.PutUint32(out[4:8], sessionID)
	binary.BigEndian.PutUint16(out[8:10], targetPort)
	copy(out[10:16], tag[:])
	copy(out[16:], payload)
	return out
}

func unpackUDPRelayDatagram(authKey []byte, raw []byte) (byte, byte, uint32, uint16, []byte, error) {
	if len(raw) < udpRelayHeaderSize || raw[0] != udpRelayMagic0 || raw[1] != udpRelayMagic1 {
		return 0, 0, 0, 0, nil, errors.New("invalid udp relay header")
	}
	pktType := raw[2]
	flags := raw[3]
	sessionID := binary.BigEndian.Uint32(raw[4:8])
	targetPort := binary.BigEndian.Uint16(raw[8:10])
	payload := raw[udpRelayHeaderSize:]

	expected := computeUDPRelayTag(authKey, pktType, flags, sessionID, targetPort, payload)
	if subtle.ConstantTimeCompare(raw[10:16], expected[:]) != 1 {
		return 0, 0, 0, 0, nil, errors.New("udp relay hmac verification failed")
	}
	return pktType, flags, sessionID, targetPort, payload, nil
}

// ============================================================================
// SERVER LISTENER (:11315 UDP + STREAM FALLBACK) & SESSION MANAGERS
// ============================================================================

type udpRelayExitSession struct {
	sessionID    uint32
	targetPort   uint16
	clientAddr   *net.UDPAddr
	serverConn   *net.UDPConn
	localConn    *net.UDPConn
	authKey      []byte
	lastActivity atomic.Int64
	closed       atomic.Bool
}

type udpRelayExitManager struct {
	mu       sync.RWMutex
	sessions map[uint32]*udpRelayExitSession
	limiter  io.Writer
	stopCh   chan struct{}
	closed   atomic.Bool
}

func newUDPRelayExitManager(speedLimitMBps string) *udpRelayExitManager {
	m := &udpRelayExitManager{
		sessions: make(map[uint32]*udpRelayExitSession),
		limiter:  newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(speedLimitMBps)),
		stopCh:   make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *udpRelayExitManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Unix() - int64(udpRelayIdleTTL.Seconds())
			m.mu.Lock()
			for sid, s := range m.sessions {
				if s.lastActivity.Load() < cutoff {
					if s.closed.CompareAndSwap(false, true) {
						_ = s.localConn.Close()
					}
					delete(m.sessions, sid)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *udpRelayExitManager) closeAll() {
	if m.closed.Swap(true) {
		return
	}
	close(m.stopCh)
	m.mu.Lock()
	for sid, s := range m.sessions {
		if s.closed.CompareAndSwap(false, true) {
			_ = s.localConn.Close()
		}
		delete(m.sessions, sid)
	}
	m.mu.Unlock()
}

func (m *udpRelayExitManager) handleDataDatagram(
	serverConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	authKey []byte,
	sessionID uint32,
	targetPort uint16,
	defaultPorts string,
	payload []byte,
) {
	if len(payload) == 0 {
		return
	}
	if targetPort == 0 {
		ports := parsePortList(defaultPorts)
		if len(ports) > 0 {
			if p, err := strconv.Atoi(ports[0]); err == nil {
				targetPort = uint16(p)
			}
		}
		if targetPort == 0 {
			targetPort = 2053
		}
	}

	sess, err := m.getOrCreateSession(serverConn, clientAddr, authKey, sessionID, targetPort)
	if err != nil {
		return
	}
	sess.lastActivity.Store(time.Now().Unix())
	atomic.AddUint64(&appRxBytes, uint64(len(payload)))
	_, _ = sess.localConn.Write(payload)
}

func (m *udpRelayExitManager) getOrCreateSession(
	serverConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	authKey []byte,
	sid uint32,
	targetPort uint16,
) (*udpRelayExitSession, error) {
	now := time.Now().Unix()
	m.mu.RLock()
	if s, ok := m.sessions[sid]; ok && !s.closed.Load() {
		s.lastActivity.Store(now)
		m.mu.RUnlock()
		return s, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sid]; ok && !s.closed.Load() {
		s.lastActivity.Store(now)
		return s, nil
	}

	dstAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(targetPort)}
	localUDP, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		return nil, err
	}
	addrCopy := &net.UDPAddr{
		IP:   append([]byte(nil), clientAddr.IP...),
		Port: clientAddr.Port,
		Zone: clientAddr.Zone,
	}
	keyCopy := append([]byte(nil), authKey...)

	s := &udpRelayExitSession{
		sessionID:  sid,
		targetPort: targetPort,
		clientAddr: addrCopy,
		serverConn: serverConn,
		localConn:  localUDP,
		authKey:    keyCopy,
	}
	s.lastActivity.Store(now)
	m.sessions[sid] = s

	go func(sess *udpRelayExitSession) {
		defer func() {
			if sess.closed.CompareAndSwap(false, true) {
				_ = sess.localConn.Close()
			}
			m.mu.Lock()
			if cur, ok := m.sessions[sess.sessionID]; ok && cur == sess {
				delete(m.sessions, sess.sessionID)
			}
			m.mu.Unlock()
		}()

		buf := make([]byte, 16384)
		for {
			_ = sess.localConn.SetReadDeadline(time.Now().Add(udpRelayIdleTTL))
			n, err := sess.localConn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				sess.lastActivity.Store(time.Now().Unix())
				_, _ = m.limiter.Write(buf[:n])
				pkt := packUDPRelayDatagram(sess.authKey, udpRelayTypeData, 0, sess.sessionID, sess.targetPort, buf[:n])
				_, _ = sess.serverConn.WriteToUDP(pkt, sess.clientAddr)
			}
		}
	}(s)

	return s, nil
}

var (
	udpRelayMu          sync.RWMutex
	udpRelayExitMuxes   = make(map[string]*udpRelayExitManager)
	udpRelayEntryMuxes  = make(map[string]*udpRelayEntryManager)
)

func stopUDPRelayPeerResources(peerID string) {
	udpRelayMu.Lock()
	if exitMux, ok := udpRelayExitMuxes[peerID]; ok {
		exitMux.closeAll()
		delete(udpRelayExitMuxes, peerID)
	}
	for k, entryMux := range udpRelayEntryMuxes {
		if strings.HasPrefix(k, peerID+"|") {
			entryMux.closeAll()
			delete(udpRelayEntryMuxes, k)
		}
	}
	udpRelayMu.Unlock()
}

func startUDPRelayServer(peer ServerPeer, tc TunnelConfig) (net.PacketConn, net.Listener) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))

	udpRelayMu.Lock()
	if old, ok := udpRelayExitMuxes[peer.ID]; ok {
		old.closeAll()
	}
	exitMux := newUDPRelayExitManager(tc.SpeedLimitMBps)
	udpRelayExitMuxes[peer.ID] = exitMux
	udpRelayMu.Unlock()

	var boundUDP net.PacketConn
	if uAddr, err := net.ResolveUDPAddr("udp", listenAddr); err == nil {
		if uConn, err := net.ListenUDP("udp", uAddr); err == nil {
			configureUDPSocketBuffers(uConn)
			boundUDP = uConn
			go serveUDPRelayDatagramServer(uConn, peer, tc, exitMux)
		}
	}

	// Companion stream listener on the same port number for TCP-based forwarded services
	var boundTCP net.Listener
	if tLn, err := startRawTCPServerListener(peer, tc); err == nil {
		boundTCP = tLn
	}

	return boundUDP, boundTCP
}

func serveUDPRelayDatagramServer(
	uConn *net.UDPConn,
	peer ServerPeer,
	tc TunnelConfig,
	exitMux *udpRelayExitManager,
) {
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := uConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < udpRelayHeaderSize {
			continue
		}
		pktCopy := make([]byte, n)
		copy(pktCopy, buf[:n])

		stateMu.RLock()
		cfgSnapshot := appCfg
		stateMu.RUnlock()

		authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
		if err != nil {
			continue
		}

		pktType, flags, sessionID, targetPort, payload, err := unpackUDPRelayDatagram(authKey, pktCopy)
		if err != nil {
			continue
		}

		switch pktType {
		case udpRelayTypeProbe:
			if len(payload) > 0 {
				applyMasterTimeHeader(string(payload))
			}
			markPeerConnectedInbound(peer.ID, clientAddr.IP.String(), tc.ID, tc.ListenPort, 1)
			ack := packUDPRelayDatagram(authKey, udpRelayTypeProbeAck, flags, sessionID, targetPort, []byte(buildMasterTimeHeader()))
			_, _ = uConn.WriteToUDP(ack, clientAddr)

		case udpRelayTypeParitySync:
			var syncPkt SyncPacket
			if json.Unmarshal(payload, &syncPkt) == nil {
				resp := processIncomingSync(peer.ID, clientAddr.IP.String(), syncPkt)
				if respBytes, err := json.Marshal(resp); err == nil {
					ack := packUDPRelayDatagram(authKey, udpRelayTypeParityAck, 0, sessionID, targetPort, respBytes)
					_, _ = uConn.WriteToUDP(ack, clientAddr)
				}
			}

		case udpRelayTypeData:
			if !tc.Enabled || exitMux == nil {
				continue
			}
			exitMux.handleDataDatagram(uConn, clientAddr, authKey, sessionID, targetPort, tc.ForwardPorts, payload)
		}
	}
}

// ============================================================================
// ENGINE 1: PROBE & PARITY SYNC OVER UDP RELAY
// ============================================================================

func probeUDPRelay(peer ServerPeer, tc TunnelConfig, localNodeID string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		res.Success = false
		res.ErrorReason = "Authentication failure"
		return res
	}

	targetAddr := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))
	rAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err == nil {
		uConn, dErr := net.DialUDP("udp", nil, rAddr)
		if dErr == nil {
			start := time.Now()
			_ = uConn.SetDeadline(time.Now().Add(2200 * time.Millisecond))
			seq := uint32(1 + randomIntN(100000))
			pkt := packUDPRelayDatagram(authKey, udpRelayTypeProbe, 0, seq, uint16(tc.ListenPort), []byte(buildMasterTimeHeader()))
			if _, wErr := uConn.Write(pkt); wErr == nil {
				rep := make([]byte, 2048)
				if n, rErr := uConn.Read(rep); rErr == nil && n >= udpRelayHeaderSize {
					rType, _, rSid, _, rPayload, uErr := unpackUDPRelayDatagram(authKey, rep[:n])
					if uErr == nil && rType == udpRelayTypeProbeAck && rSid == seq {
						if len(rPayload) > 0 {
							applyMasterTimeHeader(string(rPayload))
						}
						_ = uConn.Close()
						rtt := time.Since(start).Milliseconds()
						if rtt <= 0 {
							rtt = 1
						}
						res.Success = true
						res.LatencyMS = rtt
						res.MinLatencyMS = rtt
						res.MaxLatencyMS = rtt
						return res
					}
				}
			}
			_ = uConn.Close()
		}
	}

	// Fallback to companion stream probe if upstream network drops raw UDP
	return probeRawTCP(peer, tc, localNodeID)
}

func pushUDPRelayParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	stateMu.RLock()
	cfgSnapshot := appCfg
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err == nil {
		targetAddr := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))
		if rAddr, err := net.ResolveUDPAddr("udp", targetAddr); err == nil {
			if uConn, err := net.DialUDP("udp", nil, rAddr); err == nil {
				_ = uConn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
				pkt := SyncPacket{
					Type:          "parity_sync",
					SenderID:      senderID,
					PeerID:        peer.ID,
					MethodID:      tc.ID,
					Port:          tc.ListenPort,
					LatencyMS:     latencyMS,
					ConfigVersion: peer.ConfigVersion,
					CertPin:       certPin,
				}
				if role == "master" {
					now := time.Now()
					zName, zOff := now.Zone()
					pkt.MasterUnix = now.Unix()
					pkt.MasterTZName = zName
					pkt.MasterTZOff = zOff
					pkt.Tunnels = peer.Tunnels
				}
				if rawPkt, err := json.Marshal(pkt); err == nil && len(rawPkt) < 1200 {
					seq := uint32(1 + randomIntN(100000))
					dgram := packUDPRelayDatagram(authKey, udpRelayTypeParitySync, 0, seq, uint16(tc.ListenPort), rawPkt)
					if _, err := uConn.Write(dgram); err == nil {
						rep := make([]byte, 8192)
						if n, err := uConn.Read(rep); err == nil && n >= udpRelayHeaderSize {
							rType, _, rSid, _, rPayload, uErr := unpackUDPRelayDatagram(authKey, rep[:n])
							if uErr == nil && rType == udpRelayTypeParityAck && rSid == seq {
								var resp SyncResponse
								if json.Unmarshal(rPayload, &resp) == nil && resp.OK {
									_ = uConn.Close()
									applySyncResponseToPeer(peer.ID, resp)
									return true
								}
							}
						}
					}
				}
				_ = uConn.Close()
			}
		}
	}

	return pushRawTCPParitySync(peer, tc, latencyMS)
}

// ============================================================================
// ENGINE 2: ENTRY-SIDE UDP RELAY FORWARDER
// ============================================================================

type udpRelayEntrySession struct {
	sessionID    uint32
	clientAddr   *net.UDPAddr
	entryConn    *net.UDPConn
	remoteConn   *net.UDPConn
	lastActivity atomic.Int64
	closed       atomic.Bool
}

type udpRelayEntryManager struct {
	mu         sync.RWMutex
	peer       ServerPeer
	tunnel     TunnelConfig
	targetPort uint16
	byAddr     map[string]*udpRelayEntrySession
	nextID     atomic.Uint32
	limiter    io.Writer
	stopCh     chan struct{}
	closed     atomic.Bool
}

func newUDPRelayEntryManager(peer ServerPeer, tc TunnelConfig, targetPort uint16) *udpRelayEntryManager {
	m := &udpRelayEntryManager{
		peer:       peer,
		tunnel:     tc,
		targetPort: targetPort,
		byAddr:     make(map[string]*udpRelayEntrySession),
		limiter:    newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(tc.SpeedLimitMBps)),
		stopCh:     make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *udpRelayEntryManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Unix() - int64(udpRelayIdleTTL.Seconds())
			m.mu.Lock()
			for k, s := range m.byAddr {
				if s.lastActivity.Load() < cutoff {
					if s.closed.CompareAndSwap(false, true) {
						_ = s.remoteConn.Close()
					}
					delete(m.byAddr, k)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *udpRelayEntryManager) closeAll() {
	if m.closed.Swap(true) {
		return
	}
	close(m.stopCh)
	m.mu.Lock()
	for k, s := range m.byAddr {
		if s.closed.CompareAndSwap(false, true) {
			_ = s.remoteConn.Close()
		}
		delete(m.byAddr, k)
	}
	m.mu.Unlock()
}

func (m *udpRelayEntryManager) handleClientPacket(entryConn *net.UDPConn, clientAddr *net.UDPAddr, payload []byte) {
	if len(payload) == 0 {
		return
	}
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, m.peer)
	if err != nil {
		return
	}

	sess, err := m.getOrCreateSession(entryConn, clientAddr, authKey)
	if err != nil {
		return
	}

	sess.lastActivity.Store(time.Now().Unix())
	_, _ = m.limiter.Write(payload)
	dgram := packUDPRelayDatagram(authKey, udpRelayTypeData, 0, sess.sessionID, m.targetPort, payload)
	_, _ = sess.remoteConn.Write(dgram)
}

func (m *udpRelayEntryManager) getOrCreateSession(
	entryConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	authKey []byte,
) (*udpRelayEntrySession, error) {
	key := clientAddr.String()
	now := time.Now().Unix()

	m.mu.RLock()
	if s, ok := m.byAddr[key]; ok && !s.closed.Load() {
		s.lastActivity.Store(now)
		m.mu.RUnlock()
		return s, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.byAddr[key]; ok && !s.closed.Load() {
		s.lastActivity.Store(now)
		return s, nil
	}

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(strings.TrimSpace(m.peer.IP), strconv.Itoa(m.tunnel.ListenPort)))
	if err != nil {
		return nil, err
	}
	remConn, err := net.DialUDP("udp", nil, remoteUDPAddr)
	if err != nil {
		return nil, err
	}
	configureUDPSocketBuffers(remConn)

	sid := m.nextID.Add(1)
	if sid == 0 {
		sid = m.nextID.Add(1)
	}
	addrCopy := &net.UDPAddr{
		IP:   append([]byte(nil), clientAddr.IP...),
		Port: clientAddr.Port,
		Zone: clientAddr.Zone,
	}
	keyCopy := append([]byte(nil), authKey...)

	s := &udpRelayEntrySession{
		sessionID:  sid,
		clientAddr: addrCopy,
		entryConn:  entryConn,
		remoteConn: remConn,
	}
	s.lastActivity.Store(now)
	m.byAddr[key] = s

	go func(sess *udpRelayEntrySession, aKey []byte) {
		defer func() {
			if sess.closed.CompareAndSwap(false, true) {
				_ = sess.remoteConn.Close()
			}
			m.mu.Lock()
			if cur, ok := m.byAddr[key]; ok && cur == sess {
				delete(m.byAddr, key)
			}
			m.mu.Unlock()
		}()

		buf := make([]byte, 65535)
		for {
			_ = sess.remoteConn.SetReadDeadline(time.Now().Add(udpRelayIdleTTL))
			n, err := sess.remoteConn.Read(buf)
			if err != nil {
				return
			}
			if n >= udpRelayHeaderSize {
				rType, _, rSid, _, rPayload, uErr := unpackUDPRelayDatagram(aKey, buf[:n])
				if uErr == nil && rType == udpRelayTypeData && rSid == sess.sessionID && len(rPayload) > 0 {
					sess.lastActivity.Store(time.Now().Unix())
					atomic.AddUint64(&appRxBytes, uint64(len(rPayload)))
					_, _ = sess.entryConn.WriteToUDP(rPayload, sess.clientAddr)
				}
			}
		}
	}(s, keyCopy)

	return s, nil
}

func startUDPRelayEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
	portNum, err := strconv.Atoi(strings.TrimSpace(targetPort))
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(portNum)))
	if err != nil {
		return nil
	}
	entryConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil
	}
	configureUDPSocketBuffers(entryConn)

	muxKey := fmt.Sprintf("%s|%d", peer.ID, portNum)
	udpRelayMu.Lock()
	if old, ok := udpRelayEntryMuxes[muxKey]; ok {
		old.closeAll()
	}
	mgr := newUDPRelayEntryManager(peer, tc, uint16(portNum))
	udpRelayEntryMuxes[muxKey] = mgr
	udpRelayMu.Unlock()

	go func() {
		defer mgr.closeAll()
		buf := make([]byte, 16384)
		for {
			n, clientAddr, err := entryConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				mgr.handleClientPacket(entryConn, clientAddr, pkt)
			}
		}
	}()
	return entryConn
}
