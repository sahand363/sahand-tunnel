package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
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
	revTCPMagicByte0   byte = 0x52 // 'R'
	revTCPMagicByte1   byte = 0x54 // 'T'
	revTCPProtoVersion byte = 0x01

	// Handshake roles / modes on port 11311
	revTCPModeProbe          byte = 0x01
	revTCPModeParitySync     byte = 0x02
	revTCPModeControlChannel byte = 0x03
	revTCPModeReversePool    byte = 0x04
	revTCPModeDirectForward  byte = 0x05

	// Handshake status codes
	revTCPStatusOK           byte = 0x00
	revTCPStatusUnauthorized byte = 0x01
	revTCPStatusForbidden    byte = 0x02
	revTCPStatusUnreachable  byte = 0x03

	// Control channel commands (Entry Server -> Exit Server)
	revTCPCmdHeartbeat     byte = 0x01
	revTCPCmdHeartbeatAck  byte = 0x02
	revTCPCmdSpawnPoolConn byte = 0x03

	// Reverse pool socket activation command
	revTCPActivateForward byte = 0x10

	revTCPWarmPoolTarget  = 3
	revTCPMaxPoolSize     = 64
	revTCPHandoverTimeout = 6 * time.Second
)

type revTCPHandshakeMeta struct {
	PeerID     string `json:"pid"`
	NodeID     string `json:"nid"`
	TargetPort string `json:"port,omitempty"`
	TimeHdr    string `json:"tm,omitempty"`
}

func computeRevTCPAuthDigest(authKey []byte, nonce [32]byte, mode byte) [32]byte {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-reverse-tcp-v1:"))
	_, _ = mac.Write([]byte{mode})
	_, _ = mac.Write(nonce[:])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// Performs the client-side Reverse TCP challenge-response handshake on rawConn.
func clientRevTCPHandshake(
	conn net.Conn,
	mode byte,
	peer ServerPeer,
	authKey []byte,
	targetPort string,
) error {
	// Step 1: Read 32-byte server challenge nonce
	var challenge [32]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		return err
	}

	stateMu.RLock()
	localNodeID := appCfg.NodeID
	stateMu.RUnlock()

	meta := revTCPHandshakeMeta{
		PeerID:     peer.ID,
		NodeID:     localNodeID,
		TargetPort: targetPort,
		TimeHdr:    buildMasterTimeHeader(),
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	digest := computeRevTCPAuthDigest(authKey, challenge, mode)

	// Step 2: Send [Magic:2][Version:1][Mode:1][HMAC:32][MetaLen:2][MetaBytes]
	pkt := make([]byte, 38+len(metaBytes))
	pkt[0] = revTCPMagicByte0
	pkt[1] = revTCPMagicByte1
	pkt[2] = revTCPProtoVersion
	pkt[3] = mode
	copy(pkt[4:36], digest[:])
	binary.BigEndian.PutUint16(pkt[36:38], uint16(len(metaBytes)))
	copy(pkt[38:], metaBytes)

	if _, err := conn.Write(pkt); err != nil {
		return err
	}

	// Step 3: Read 1-byte status
	var status [1]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return err
	}
	if status[0] != revTCPStatusOK {
		return errors.New("reverse tcp authentication rejected")
	}
	return nil
}

// Performs the server-side Reverse TCP challenge-response handshake on rawConn.
func serverRevTCPHandshake(
	conn net.Conn,
	authKey []byte,
) (byte, revTCPHandshakeMeta, error) {
	var meta revTCPHandshakeMeta

	var challenge [32]byte
	if _, err := io.ReadFull(rand.Reader, challenge[:]); err != nil {
		return 0, meta, err
	}
	if _, err := conn.Write(challenge[:]); err != nil {
		return 0, meta, err
	}

	var hdr [38]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, meta, err
	}
	if hdr[0] != revTCPMagicByte0 || hdr[1] != revTCPMagicByte1 || hdr[2] != revTCPProtoVersion {
		return 0, meta, errors.New("invalid reverse tcp preface")
	}
	mode := hdr[3]
	expectedDigest := computeRevTCPAuthDigest(authKey, challenge, mode)
	if subtle.ConstantTimeCompare(hdr[4:36], expectedDigest[:]) != 1 {
		_, _ = conn.Write([]byte{revTCPStatusUnauthorized})
		return 0, meta, errors.New("reverse tcp hmac mismatch")
	}

	metaLen := int(binary.BigEndian.Uint16(hdr[36:38]))
	if metaLen <= 0 || metaLen > 4096 {
		return 0, meta, errors.New("invalid reverse tcp metadata length")
	}
	metaBuf := make([]byte, metaLen)
	if _, err := io.ReadFull(conn, metaBuf); err != nil {
		return 0, meta, err
	}
	if err := json.Unmarshal(metaBuf, &meta); err != nil {
		return 0, meta, err
	}
	if meta.TimeHdr != "" {
		applyMasterTimeHeader(meta.TimeHdr)
	}

	if _, err := conn.Write([]byte{revTCPStatusOK}); err != nil {
		return 0, meta, err
	}
	return mode, meta, nil
}

// ============================================================================
// REVERSE TCP SESSION & WARM SOCKET POOL MANAGER
// ============================================================================

type revTCPControlBroker struct {
	mu       sync.Mutex
	peerID   string
	ctrlConn net.Conn
	poolCh   chan net.Conn
	closed   atomic.Bool
}

func newRevTCPControlBroker(peerID string, ctrlConn net.Conn) *revTCPControlBroker {
	return &revTCPControlBroker{
		peerID:   peerID,
		ctrlConn: ctrlConn,
		poolCh:   make(chan net.Conn, revTCPMaxPoolSize),
	}
}

func (b *revTCPControlBroker) pushPooledConn(c net.Conn) bool {
	if b.closed.Load() {
		_ = c.Close()
		return false
	}
	select {
	case b.poolCh <- c:
		return true
	default:
		_ = c.Close()
		return false
	}
}

func (b *revTCPControlBroker) requestSpawn(count byte) error {
	if b.closed.Load() || b.ctrlConn == nil {
		return errors.New("reverse tcp control channel closed")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.ctrlConn.SetWriteDeadline(time.Now().Add(4 * time.Second))
	_, err := b.ctrlConn.Write([]byte{revTCPCmdSpawnPoolConn, count})
	_ = b.ctrlConn.SetWriteDeadline(time.Time{})
	return err
}

// Claims a reverse socket from the warm standby pool or requests an immediate spawn from the Exit Server.
func (b *revTCPControlBroker) acquireReverseConn(targetPort uint16) (net.Conn, error) {
	if b.closed.Load() {
		return nil, errors.New("reverse tcp broker closed")
	}

	// 1. Check warm standby pool first for 0-RTT handover
	for {
		select {
		case c := <-b.poolCh:
			if c == nil {
				continue
			}
			// Replenish warm pool asynchronously
			_ = b.requestSpawn(1)
			if err := activatePooledReverseConn(c, targetPort); err != nil {
				_ = c.Close()
				continue
			}
			return c, nil
		default:
		}
		break
	}

	// 2. Pool is empty: signal Exit Server to spawn a reverse socket now
	if err := b.requestSpawn(2); err != nil {
		return nil, err
	}

	timer := time.NewTimer(revTCPHandoverTimeout)
	defer timer.Stop()
	select {
	case c := <-b.poolCh:
		if c == nil {
			return nil, errors.New("reverse tcp socket closed")
		}
		if err := activatePooledReverseConn(c, targetPort); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	case <-timer.C:
		return nil, errors.New("reverse tcp socket handover timeout")
	}
}

func activatePooledReverseConn(c net.Conn, targetPort uint16) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var cmd [3]byte
	cmd[0] = revTCPActivateForward
	binary.BigEndian.PutUint16(cmd[1:3], targetPort)
	if _, err := c.Write(cmd[:]); err != nil {
		return err
	}
	var ack [1]byte
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		return err
	}
	if ack[0] != revTCPStatusOK {
		return errors.New("remote target port unreachable")
	}
	_ = c.SetDeadline(time.Time{})
	return nil
}

func (b *revTCPControlBroker) close() {
	if b.closed.Swap(true) {
		return
	}
	if b.ctrlConn != nil {
		_ = b.ctrlConn.Close()
	}
	for {
		select {
		case c := <-b.poolCh:
			if c != nil {
				_ = c.Close()
			}
		default:
			return
		}
	}
}

var (
	revTCPMu            sync.RWMutex
	revTCPBrokersByPeer = make(map[string]*revTCPControlBroker)
	revTCPWorkerCancel  = make(map[string]chan struct{})
)

func getOrRegisterRevTCPBroker(peerID string, ctrlConn net.Conn) *revTCPControlBroker {
	revTCPMu.Lock()
	defer revTCPMu.Unlock()

	if old, ok := revTCPBrokersByPeer[peerID]; ok {
		if ctrlConn != nil {
			old.close()
		} else if !old.closed.Load() {
			return old
		}
	}
	b := newRevTCPControlBroker(peerID, ctrlConn)
	revTCPBrokersByPeer[peerID] = b
	return b
}

func stopReverseTCPPeerResources(peerID string) {
	revTCPMu.Lock()
	if ch, ok := revTCPWorkerCancel[peerID]; ok {
		close(ch)
		delete(revTCPWorkerCancel, peerID)
	}
	if b, ok := revTCPBrokersByPeer[peerID]; ok {
		b.close()
		delete(revTCPBrokersByPeer, peerID)
	}
	revTCPMu.Unlock()
}

// ============================================================================
// SERVER LISTENER (:11311) & INCOMING CONNECTION DISPATCH
// ============================================================================

func startReverseTCPServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			enableKeepAlive(rawConn)
			go handleIncomingReverseTCPConn(rawConn, peer, tc)
		}
	}()
	return ln, nil
}

func handleIncomingReverseTCPConn(rawConn net.Conn, peer ServerPeer, tc TunnelConfig) {
	_ = rawConn.SetDeadline(time.Now().Add(12 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		_ = rawConn.Close()
		return
	}

	mode, meta, err := serverRevTCPHandshake(rawConn, authKey)
	if err != nil {
		_ = rawConn.Close()
		return
	}

	remoteHost, _, _ := net.SplitHostPort(rawConn.RemoteAddr().String())
	effectivePeerID := peer.ID
	if meta.PeerID != "" {
		effectivePeerID = meta.PeerID
	}

	switch mode {
	case revTCPModeProbe:
		defer rawConn.Close()
		var ping [12]byte
		if _, err := io.ReadFull(rawConn, ping[:]); err != nil {
			return
		}
		_, _ = rawConn.Write(ping[:])
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)

	case revTCPModeParitySync:
		defer rawConn.Close()
		handleRevTCPParitySyncServer(rawConn, effectivePeerID, remoteHost)

	case revTCPModeControlChannel:
		if !tc.Enabled {
			_ = rawConn.Close()
			return
		}
		_ = rawConn.SetDeadline(time.Time{})
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)
		serveRevTCPControlChannel(rawConn, effectivePeerID, remoteHost, tc)

	case revTCPModeReversePool:
		if !tc.Enabled {
			_ = rawConn.Close()
			return
		}
		_ = rawConn.SetDeadline(time.Time{})
		revTCPMu.RLock()
		broker := revTCPBrokersByPeer[effectivePeerID]
		revTCPMu.RUnlock()
		if broker == nil {
			broker = getOrRegisterRevTCPBroker(effectivePeerID, nil)
		}
		broker.pushPooledConn(rawConn)

	case revTCPModeDirectForward:
		defer rawConn.Close()
		if !tc.Enabled {
			return
		}
		_ = rawConn.SetDeadline(time.Time{})
		handleRevTCPDirectForwardServer(rawConn, tc, meta.TargetPort)

	default:
		_ = rawConn.Close()
	}
}

func serveRevTCPControlChannel(ctrlConn net.Conn, peerID, remoteHost string, tc TunnelConfig) {
	broker := getOrRegisterRevTCPBroker(peerID, ctrlConn)
	defer func() {
		revTCPMu.Lock()
		if cur, ok := revTCPBrokersByPeer[peerID]; ok && cur == broker {
			delete(revTCPBrokersByPeer, peerID)
		}
		revTCPMu.Unlock()
		broker.close()
	}()

	// Request initial warm standby pool of reverse TCP sockets
	_ = broker.requestSpawn(revTCPWarmPoolTarget)

	hbSec := tc.HeartbeatSec
	if hbSec <= 0 {
		hbSec = 25
	}
	ticker := time.NewTicker(time.Duration(hbSec) * time.Second)
	defer ticker.Stop()

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		var buf [1]byte
		for {
			_ = ctrlConn.SetReadDeadline(time.Now().Add(time.Duration(hbSec*2+15) * time.Second))
			if _, err := io.ReadFull(ctrlConn, buf[:]); err != nil {
				return
			}
			if buf[0] == revTCPCmdHeartbeatAck {
				markPeerConnectedInbound(peerID, remoteHost, tc.ID, tc.ListenPort, 1)
			}
		}
	}()

	for {
		select {
		case <-doneCh:
			return
		case <-ticker.C:
			broker.mu.Lock()
			_ = ctrlConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := ctrlConn.Write([]byte{revTCPCmdHeartbeat})
			_ = ctrlConn.SetWriteDeadline(time.Time{})
			broker.mu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

// ============================================================================
// REVERSE TCP CLIENT WORKER (DIALS OUTBOUND CONTROL + WARM STANDBY POOL)
// ============================================================================

func startReverseTCPClientWorker(peer ServerPeer, tc TunnelConfig) {
	revTCPMu.Lock()
	if ch, ok := revTCPWorkerCancel[peer.ID]; ok {
		close(ch)
	}
	stopCh := make(chan struct{})
	revTCPWorkerCancel[peer.ID] = stopCh
	revTCPMu.Unlock()

	go func() {
		for {
			select {
			case <-stopCh:
				return
			default:
			}

			runReverseTCPClientControlSession(peer, tc, stopCh)

			timer := time.NewTimer(5 * time.Second)
			select {
			case <-stopCh:
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func dialRevTCPAuthenticated(
	peer ServerPeer,
	tc TunnelConfig,
	mode byte,
	targetPort string,
	timeout time.Duration,
) (net.Conn, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return nil, err
	}

	targetAddr := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, err
	}
	enableKeepAlive(rawConn)
	_ = rawConn.SetDeadline(time.Now().Add(timeout + 2*time.Second))

	if err := clientRevTCPHandshake(rawConn, mode, peer, authKey, targetPort); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return rawConn, nil
}

func runReverseTCPClientControlSession(peer ServerPeer, tc TunnelConfig, stopCh <-chan struct{}) {
	ctrlConn, err := dialRevTCPAuthenticated(peer, tc, revTCPModeControlChannel, "control", 5*time.Second)
	if err != nil {
		return
	}
	defer ctrlConn.Close()
	_ = ctrlConn.SetDeadline(time.Time{})

	go func() {
		<-stopCh
		_ = ctrlConn.Close()
	}()

	var cmd [1]byte
	for {
		_ = ctrlConn.SetReadDeadline(time.Now().Add(90 * time.Second))
		if _, err := io.ReadFull(ctrlConn, cmd[:]); err != nil {
			return
		}
		switch cmd[0] {
		case revTCPCmdHeartbeat:
			_ = ctrlConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = ctrlConn.Write([]byte{revTCPCmdHeartbeatAck})
			_ = ctrlConn.SetWriteDeadline(time.Time{})

		case revTCPCmdSpawnPoolConn:
			var countBuf [1]byte
			if _, err := io.ReadFull(ctrlConn, countBuf[:]); err != nil {
				return
			}
			count := int(countBuf[0])
			if count <= 0 {
				count = 1
			}
			if count > 8 {
				count = 8
			}
			for i := 0; i < count; i++ {
				go spawnReverseTCPPoolSocket(peer, tc, stopCh)
			}
		}
	}
}

func spawnReverseTCPPoolSocket(peer ServerPeer, tc TunnelConfig, stopCh <-chan struct{}) {
	poolConn, err := dialRevTCPAuthenticated(peer, tc, revTCPModeReversePool, "pool", 5*time.Second)
	if err != nil {
		return
	}
	defer poolConn.Close()

	// Wait in standby until the Entry Server sends [revTCPActivateForward][TargetPort:uint16]
	_ = poolConn.SetReadDeadline(time.Now().Add(3 * time.Minute))
	doneWait := make(chan struct{})
	go func() {
		select {
		case <-stopCh:
			_ = poolConn.Close()
		case <-doneWait:
		}
	}()

	var cmd [3]byte
	_, err = io.ReadFull(poolConn, cmd[:])
	close(doneWait)
	if err != nil || cmd[0] != revTCPActivateForward {
		return
	}
	_ = poolConn.SetReadDeadline(time.Time{})

	portNum := int(binary.BigEndian.Uint16(cmd[1:3]))
	targetPort := strconv.Itoa(portNum)
	if portNum <= 0 {
		ports := parsePortList(tc.ForwardPorts)
		if len(ports) > 0 {
			targetPort = ports[0]
		} else {
			targetPort = "2053"
		}
	}

	handleRevTCPDirectForwardServer(poolConn, tc, targetPort)
}

func handleRevTCPDirectForwardServer(conn net.Conn, tc TunnelConfig, targetPort string) {
	if strings.TrimSpace(targetPort) == "" {
		ports := parsePortList(tc.ForwardPorts)
		if len(ports) > 0 {
			targetPort = ports[0]
		} else {
			targetPort = "2053"
		}
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", targetPort), 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{revTCPStatusUnreachable})
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	if _, err := conn.Write([]byte{revTCPStatusOK}); err != nil {
		return
	}

	pipeRevTCPConnections(conn, target, tc.SpeedLimitMBps)
}

// ============================================================================
// ENGINE 1: PROBE & PARITY SYNC OVER REVERSE TCP
// ============================================================================

func probeReverseTCP(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	conn, err := dialRevTCPAuthenticated(peer, tc, revTCPModeProbe, fmt.Sprintf("probe:%d", tc.ListenPort), 4*time.Second)
	if err != nil {
		res.Success = false
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(err.Error(), "rejected") || strings.Contains(err.Error(), "hmac") {
			res.ErrorReason = "Authentication failure"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}
	defer conn.Close()

	var ping [12]byte
	var pong [12]byte
	binary.BigEndian.PutUint32(ping[0:4], 1)
	binary.BigEndian.PutUint64(ping[4:12], uint64(time.Now().UnixNano()))

	if _, err := conn.Write(ping[:]); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}
	if _, err := io.ReadFull(conn, pong[:]); err != nil || !bytes.Equal(ping[:], pong[:]) {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

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

func pushReverseTCPParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	conn, err := dialRevTCPAuthenticated(peer, tc, revTCPModeParitySync, strconv.Itoa(tc.ListenPort), 4*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	stateMu.RLock()
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	stateMu.RUnlock()

	padLen := 32 + randomIntN(128)
	padHex, _ := randomHex(padLen)

	pkt := SyncPacket{
		Type:          "parity_sync",
		SenderID:      senderID,
		PeerID:        peer.ID,
		MethodID:      tc.ID,
		Port:          tc.ListenPort,
		LatencyMS:     latencyMS,
		ConfigVersion: peer.ConfigVersion,
		CertPin:       certPin,
		Padding:       padHex,
	}
	if role == "master" {
		now := time.Now()
		zName, zOff := now.Zone()
		pkt.MasterUnix = now.Unix()
		pkt.MasterTZName = zName
		pkt.MasterTZOff = zOff
		pkt.Tunnels = peer.Tunnels
	}

	rawPkt, err := json.Marshal(pkt)
	if err != nil {
		return false
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(rawPkt)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := conn.Write(rawPkt); err != nil {
		return false
	}

	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBytes); err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func handleRevTCPParitySyncServer(conn net.Conn, effectivePeerID, remoteHost string) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen == 0 || pktLen > 256*1024 {
		return
	}
	rawPkt := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, rawPkt); err != nil {
		return
	}
	var pkt SyncPacket
	if json.Unmarshal(rawPkt, &pkt) != nil {
		return
	}

	resp := processIncomingSync(effectivePeerID, remoteHost, pkt)
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return
	}
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(respBytes)))
	_, _ = conn.Write(lenBuf[:])
	_, _ = conn.Write(respBytes)
}

// ============================================================================
// ENGINE 2: FORWARDING (REVERSE POOL PRIMARY + DIRECT FALLBACK)
// ============================================================================

func forwardReverseTCPTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	portNum, _ := strconv.Atoi(strings.TrimSpace(targetPort))
	if portNum <= 0 {
		portNum = 2053
	}

	// 1. Primary: Acquire pre-established Reverse TCP socket from the Exit Server's pool
	revTCPMu.RLock()
	broker := revTCPBrokersByPeer[peer.ID]
	revTCPMu.RUnlock()

	if broker != nil && !broker.closed.Load() {
		if revConn, err := broker.acquireReverseConn(uint16(portNum)); err == nil {
			defer revConn.Close()
			pipeRevTCPConnections(revConn, client, tc.SpeedLimitMBps)
			return
		}
	}

	// 2. Fallback: Direct authenticated TCP connection if reverse pool is not connected yet
	directConn, err := dialRevTCPAuthenticated(peer, tc, revTCPModeDirectForward, strconv.Itoa(portNum), 5*time.Second)
	if err != nil {
		return
	}
	defer directConn.Close()

	var status [1]byte
	if _, err := io.ReadFull(directConn, status[:]); err != nil || status[0] != revTCPStatusOK {
		return
	}
	_ = directConn.SetDeadline(time.Time{})

	pipeRevTCPConnections(directConn, client, tc.SpeedLimitMBps)
}

func pipeRevTCPConnections(tunnelConn net.Conn, localConn net.Conn, speedLimitMBps string) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	toTunnel := newThrottledWriter(tunnelConn, &appTxBytes, mbLimit)
	toLocal := newThrottledWriter(localConn, &appRxBytes, mbLimit)

	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toTunnel, localConn, buf)
		if tc, ok := tunnelConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = tunnelConn.Close()
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toLocal, tunnelConn, buf)
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = localConn.Close()
		}
		done <- struct{}{}
	}()
	<-done
}
