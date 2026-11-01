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
	// Yamux-style 12-byte binary frame header:
	// [Version:1][Type:1][FlagsOrPort:2][StreamID:4][Length:4]
	tcpMuxProtoVersion byte = 0x01
	tcpMuxHeaderSize        = 12

	tcpMuxTypeData          byte = 0x00
	tcpMuxTypePing          byte = 0x01
	tcpMuxTypePong          byte = 0x02
	tcpMuxTypeStreamOpen    byte = 0x03
	tcpMuxTypeStreamOpenAck byte = 0x04
	tcpMuxTypeStreamFIN     byte = 0x05
	tcpMuxTypeStreamRST     byte = 0x06

	tcpMuxPortParitySync uint16 = 0xFFFF
	tcpMuxMaxChunkSize          = 32 * 1024
)

func computeTCPMuxHandshakeMAC(authKey []byte, nonce [24]byte) [16]byte {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-yamux-tcp-v1:"))
	_, _ = mac.Write(nonce[:])
	sum := mac.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// ============================================================================
// YAMUX-STYLE MULTIPLEXED STREAM & SESSION ENGINE
// ============================================================================

type tcpMuxStream struct {
	session    *tcpMuxSession
	id         uint32
	targetPort uint16
	readCh     chan []byte
	readMu     sync.Mutex
	readBuf    bytes.Buffer
	openAckCh  chan bool
	closedRead atomic.Bool
	closed     atomic.Bool
}

func newTCPMuxStream(s *tcpMuxSession, id uint32, targetPort uint16) *tcpMuxStream {
	return &tcpMuxStream{
		session:    s,
		id:         id,
		targetPort: targetPort,
		readCh:     make(chan []byte, 256),
		openAckCh:  make(chan bool, 1),
	}
}

func (st *tcpMuxStream) pushInboundData(chunk []byte) {
	if st.closedRead.Load() {
		return
	}
	cp := make([]byte, len(chunk))
	copy(cp, chunk)
	select {
	case st.readCh <- cp:
	default:
		// If consumer is stalled and buffer is full, block up to 3s before dropping stream
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case st.readCh <- cp:
		case <-timer.C:
			st.markRemoteClosed()
		}
	}
}

func (st *tcpMuxStream) markRemoteClosed() {
	if st.closedRead.CompareAndSwap(false, true) {
		close(st.readCh)
	}
}

func (st *tcpMuxStream) Read(p []byte) (int, error) {
	st.readMu.Lock()
	defer st.readMu.Unlock()

	if st.readBuf.Len() > 0 {
		return st.readBuf.Read(p)
	}
	chunk, ok := <-st.readCh
	if !ok {
		return 0, io.EOF
	}
	st.readBuf.Write(chunk)
	return st.readBuf.Read(p)
}

func (st *tcpMuxStream) Write(p []byte) (int, error) {
	if st.closed.Load() || st.session.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > tcpMuxMaxChunkSize {
			chunk = p[:tcpMuxMaxChunkSize]
		}
		if err := st.session.writeFrame(tcpMuxTypeData, 0, st.id, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (st *tcpMuxStream) CloseWrite() error {
	if st.closed.CompareAndSwap(false, true) {
		_ = st.session.writeFrame(tcpMuxTypeStreamFIN, 0, st.id, nil)
		st.session.removeStream(st.id)
	}
	return nil
}

func (st *tcpMuxStream) Close() error {
	_ = st.CloseWrite()
	st.markRemoteClosed()
	return nil
}

type tcpMuxSession struct {
	conn       net.Conn
	writeMu    sync.Mutex
	streamsMu  sync.RWMutex
	streams    map[uint32]*tcpMuxStream
	nextID     atomic.Uint32
	pingMu     sync.Mutex
	pingWait   map[uint32]chan time.Duration
	isClient   bool
	peer       ServerPeer
	tunnel     TunnelConfig
	remoteHost string
	closed     atomic.Bool
}

func newTCPMuxSession(conn net.Conn, isClient bool, peer ServerPeer, tc TunnelConfig, remoteHost string) *tcpMuxSession {
	s := &tcpMuxSession{
		conn:       conn,
		streams:    make(map[uint32]*tcpMuxStream),
		pingWait:   make(map[uint32]chan time.Duration),
		isClient:   isClient,
		peer:       peer,
		tunnel:     tc,
		remoteHost: remoteHost,
	}
	if isClient {
		s.nextID.Store(1)
	} else {
		s.nextID.Store(2)
	}
	go s.readLoop()
	return s
}

func (s *tcpMuxSession) writeFrame(frameType byte, flagsOrPort uint16, streamID uint32, payload []byte) error {
	if s.closed.Load() {
		return net.ErrClosed
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var hdr [tcpMuxHeaderSize]byte
	hdr[0] = tcpMuxProtoVersion
	hdr[1] = frameType
	binary.BigEndian.PutUint16(hdr[2:4], flagsOrPort)
	binary.BigEndian.PutUint32(hdr[4:8], streamID)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(payload)))

	_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := s.conn.Write(hdr[:]); err != nil {
		_ = s.conn.SetWriteDeadline(time.Time{})
		s.closeAll()
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			_ = s.conn.SetWriteDeadline(time.Time{})
			s.closeAll()
			return err
		}
	}
	_ = s.conn.SetWriteDeadline(time.Time{})
	return nil
}

func (s *tcpMuxSession) removeStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

func (s *tcpMuxSession) closeAll() {
	if s.closed.Swap(true) {
		return
	}
	_ = s.conn.Close()

	s.streamsMu.Lock()
	for id, st := range s.streams {
		st.markRemoteClosed()
		delete(s.streams, id)
	}
	s.streamsMu.Unlock()

	s.pingMu.Lock()
	for seq, ch := range s.pingWait {
		close(ch)
		delete(s.pingWait, seq)
	}
	s.pingMu.Unlock()
}

func (s *tcpMuxSession) openClientStream(targetPort uint16, timeout time.Duration) (*tcpMuxStream, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	maxStreams := s.tunnel.StreamLimit
	if maxStreams <= 0 {
		maxStreams = 64
	}

	s.streamsMu.Lock()
	if len(s.streams) >= maxStreams {
		s.streamsMu.Unlock()
		return nil, errors.New("tcp multiplex stream limit reached")
	}
	sid := s.nextID.Add(2)
	st := newTCPMuxStream(s, sid, targetPort)
	s.streams[sid] = st
	s.streamsMu.Unlock()

	if err := s.writeFrame(tcpMuxTypeStreamOpen, targetPort, sid, []byte(buildMasterTimeHeader())); err != nil {
		s.removeStream(sid)
		return nil, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ok := <-st.openAckCh:
		if !ok {
			s.removeStream(sid)
			return nil, errors.New("remote rejected multiplexed stream")
		}
		return st, nil
	case <-timer.C:
		s.removeStream(sid)
		return nil, errors.New("multiplexed stream open timeout")
	}
}

func (s *tcpMuxSession) ping(timeout time.Duration) (time.Duration, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	seq := s.nextID.Add(1)
	ch := make(chan time.Duration, 1)

	s.pingMu.Lock()
	s.pingWait[seq] = ch
	s.pingMu.Unlock()

	defer func() {
		s.pingMu.Lock()
		delete(s.pingWait, seq)
		s.pingMu.Unlock()
	}()

	start := time.Now()
	var payload [8]byte
	binary.BigEndian.PutUint64(payload[:], uint64(start.UnixNano()))
	if err := s.writeFrame(tcpMuxTypePing, 0, seq, payload[:]); err != nil {
		return 0, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case _, ok := <-ch:
		if !ok {
			return 0, errors.New("mux session closed during ping")
		}
		return time.Since(start), nil
	case <-timer.C:
		return 0, errors.New("mux ping timeout")
	}
}

func (s *tcpMuxSession) readLoop() {
	defer s.closeAll()

	var hdr [tcpMuxHeaderSize]byte
	for {
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return
		}
		if hdr[0] != tcpMuxProtoVersion {
			return
		}
		frameType := hdr[1]
		flagsOrPort := binary.BigEndian.Uint16(hdr[2:4])
		streamID := binary.BigEndian.Uint32(hdr[4:8])
		length := int(binary.BigEndian.Uint32(hdr[8:12]))

		if length < 0 || length > 256*1024 {
			return
		}
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				return
			}
		}

		switch frameType {
		case tcpMuxTypePing:
			markPeerConnectedInbound(s.peer.ID, s.remoteHost, s.tunnel.ID, s.tunnel.ListenPort, 1)
			_ = s.writeFrame(tcpMuxTypePong, flagsOrPort, streamID, payload)

		case tcpMuxTypePong:
			s.pingMu.Lock()
			if ch, ok := s.pingWait[streamID]; ok {
				select {
				case ch <- time.Millisecond:
				default:
				}
			}
			s.pingMu.Unlock()

		case tcpMuxTypeStreamOpen:
			if len(payload) > 0 {
				applyMasterTimeHeader(string(payload))
			}
			st := newTCPMuxStream(s, streamID, flagsOrPort)
			s.streamsMu.Lock()
			s.streams[streamID] = st
			s.streamsMu.Unlock()

			go s.handleServerStream(st, flagsOrPort)

		case tcpMuxTypeStreamOpenAck:
			s.streamsMu.RLock()
			st := s.streams[streamID]
			s.streamsMu.RUnlock()
			if st != nil {
				select {
				case st.openAckCh <- (flagsOrPort == 0):
				default:
				}
			}

		case tcpMuxTypeData:
			s.streamsMu.RLock()
			st := s.streams[streamID]
			s.streamsMu.RUnlock()
			if st != nil && len(payload) > 0 {
				st.pushInboundData(payload)
			}

		case tcpMuxTypeStreamFIN, tcpMuxTypeStreamRST:
			s.streamsMu.RLock()
			st := s.streams[streamID]
			s.streamsMu.RUnlock()
			if st != nil {
				st.markRemoteClosed()
				s.removeStream(streamID)
			}
		}
	}
}

func (s *tcpMuxSession) handleServerStream(st *tcpMuxStream, targetPort uint16) {
	defer st.Close()

	// Engine 1: Parity Sync Stream
	if targetPort == tcpMuxPortParitySync {
		if err := s.writeFrame(tcpMuxTypeStreamOpenAck, 0, st.id, nil); err != nil {
			return
		}
		handleWebTransportParitySyncStream(st, s.peer.ID, s.remoteHost)
		return
	}

	// Engine 2: Forwarded TCP Stream
	if !s.tunnel.Enabled {
		_ = s.writeFrame(tcpMuxTypeStreamOpenAck, 1, st.id, nil)
		return
	}

	portStr := strconv.Itoa(int(targetPort))
	if targetPort == 0 {
		ports := parsePortList(s.tunnel.ForwardPorts)
		if len(ports) > 0 {
			portStr = ports[0]
		} else {
			portStr = strconv.Itoa(32000 + s.tunnel.ID)
		}
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", portStr), 5*time.Second)
	if err != nil {
		_ = s.writeFrame(tcpMuxTypeStreamOpenAck, 1, st.id, nil)
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	if err := s.writeFrame(tcpMuxTypeStreamOpenAck, 0, st.id, nil); err != nil {
		return
	}

	pipeTCPMuxStreamAndLocal(st, target, s.tunnel.SpeedLimitMBps)
}

func pipeTCPMuxStreamAndLocal(muxStream *tcpMuxStream, localConn net.Conn, speedLimitMBps string) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	toMux := newThrottledWriter(muxStream, &appTxBytes, mbLimit)
	toLocal := newThrottledWriter(localConn, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toMux, localConn, buf)
		_ = muxStream.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toLocal, muxStream, buf)
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// ============================================================================
// PERSISTENT CLIENT SESSION POOL & SERVER LISTENER (:28021)
// ============================================================================

var (
	tcpMuxPoolMu   sync.Mutex
	tcpMuxSessions = make(map[string]*tcpMuxSession)
)

func stopTCPMultiplexPeerResources(peerID string) {
	tcpMuxPoolMu.Lock()
	if sess, ok := tcpMuxSessions[peerID]; ok {
		sess.closeAll()
		delete(tcpMuxSessions, peerID)
	}
	tcpMuxPoolMu.Unlock()
}

func getOrDialTCPMuxSession(peer ServerPeer, tc TunnelConfig, timeout time.Duration) (*tcpMuxSession, error) {
	tcpMuxPoolMu.Lock()
	existing := tcpMuxSessions[peer.ID]
	if existing != nil && !existing.closed.Load() && existing.tunnel.ListenPort == tc.ListenPort {
		tcpMuxPoolMu.Unlock()
		return existing, nil
	}
	if existing != nil {
		existing.closeAll()
		delete(tcpMuxSessions, peer.ID)
	}
	tcpMuxPoolMu.Unlock()

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

	// Read 24-byte server challenge nonce
	var nonce [24]byte
	if _, err := io.ReadFull(rawConn, nonce[:]); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	tag := computeTCPMuxHandshakeMAC(authKey, nonce)

	// Send [YMUX][Tag:16]
	var authPkt [20]byte
	copy(authPkt[0:4], []byte("YMUX"))
	copy(authPkt[4:20], tag[:])
	if _, err := rawConn.Write(authPkt[:]); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	var status [1]byte
	if _, err := io.ReadFull(rawConn, status[:]); err != nil || status[0] != 0x00 {
		_ = rawConn.Close()
		return nil, errors.New("tcp multiplex handshake rejected")
	}
	_ = rawConn.SetDeadline(time.Time{})

	sess := newTCPMuxSession(rawConn, true, peer, tc, strings.TrimSpace(peer.IP))

	tcpMuxPoolMu.Lock()
	if old, ok := tcpMuxSessions[peer.ID]; ok && old != sess {
		old.closeAll()
	}
	tcpMuxSessions[peer.ID] = sess
	tcpMuxPoolMu.Unlock()

	return sess, nil
}

func startTCPMultiplexServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
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
			go handleIncomingTCPMultiplexConn(rawConn, peer, tc)
		}
	}()
	return ln, nil
}

func handleIncomingTCPMultiplexConn(rawConn net.Conn, peer ServerPeer, tc TunnelConfig) {
	_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		_ = rawConn.Close()
		return
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		_ = rawConn.Close()
		return
	}
	if _, err := rawConn.Write(nonce[:]); err != nil {
		_ = rawConn.Close()
		return
	}

	var authPkt [20]byte
	if _, err := io.ReadFull(rawConn, authPkt[:]); err != nil {
		_ = rawConn.Close()
		return
	}
	if string(authPkt[0:4]) != "YMUX" {
		_ = rawConn.Close()
		return
	}
	expectedTag := computeTCPMuxHandshakeMAC(authKey, nonce)
	if subtle.ConstantTimeCompare(authPkt[4:20], expectedTag[:]) != 1 {
		_, _ = rawConn.Write([]byte{0x01})
		_ = rawConn.Close()
		return
	}
	if _, err := rawConn.Write([]byte{0x00}); err != nil {
		_ = rawConn.Close()
		return
	}
	_ = rawConn.SetDeadline(time.Time{})

	remoteHost, _, _ := net.SplitHostPort(rawConn.RemoteAddr().String())
	_ = newTCPMuxSession(rawConn, false, peer, tc, remoteHost)
}

// ============================================================================
// ENGINE 1 & ENGINE 2 ENTRY POINTS FOR TCP MULTIPLEX
// ============================================================================

func probeTCPMultiplex(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	sess, err := getOrDialTCPMuxSession(peer, tc, 4*time.Second)
	if err != nil {
		res.Success = false
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(msg, "rejected") {
			res.ErrorReason = "Authentication failure"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}

	rttDur, err := sess.ping(3 * time.Second)
	if err != nil {
		sess.closeAll()
		res.Success = false
		res.ErrorReason = fmt.Sprintf("Timeout (%v)", err)
		res.ErrorReason = "Timeout"
		return res
	}

	rtt := rttDur.Milliseconds()
	if rtt <= 0 {
		rtt = 1
	}
	res.Success = true
	res.LatencyMS = rtt
	res.MinLatencyMS = rtt
	res.MaxLatencyMS = rtt
	return res
}

func pushTCPMultiplexParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	sess, err := getOrDialTCPMuxSession(peer, tc, 4*time.Second)
	if err != nil {
		return false
	}

	st, err := sess.openClientStream(tcpMuxPortParitySync, 4*time.Second)
	if err != nil {
		sess.closeAll()
		return false
	}
	defer st.Close()

	stateMu.RLock()
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	stateMu.RUnlock()

	padLen := 32 + randomIntN(96)
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
	if _, err := st.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := st.Write(rawPkt); err != nil {
		return false
	}

	if _, err := io.ReadFull(st, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(st, respBytes); err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func forwardTCPMultiplexTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	portNum, _ := strconv.Atoi(strings.TrimSpace(targetPort))
	if portNum <= 0 {
		portNum = 32000 + tc.ID
	}

	sess, err := getOrDialTCPMuxSession(peer, tc, 5*time.Second)
	if err != nil {
		return
	}

	st, err := sess.openClientStream(uint16(portNum), 5*time.Second)
	if err != nil {
		return
	}
	defer st.Close()

	pipeTCPMuxStreamAndLocal(st, client, tc.SpeedLimitMBps)
}
