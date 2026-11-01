package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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
	// RFC 6455 Opcodes
	wsOpcodeBinary byte = 0x02
	wsOpcodeClose  byte = 0x08
	wsOpcodePing   byte = 0x09
	wsOpcodePong   byte = 0x0A

	// Multiplexer Sub-Commands inside RFC 6455 Binary Payload:
	// [SubCmd:1][Status:1][Port:2][StreamID:4][Payload...] = 8-byte mux header
	wsMuxSubHeaderSize = 8

	wsMuxCmdOpen    byte = 0x01
	wsMuxCmdOpenAck byte = 0x02
	wsMuxCmdData    byte = 0x03
	wsMuxCmdFIN     byte = 0x04

	wsMuxPortParitySync uint16 = 0xFFFF
	wsMuxMaxChunkSize          = 28 * 1024
)

func computeWSAcceptKey(secKey string) string {
	h := sha1.New()
	_, _ = h.Write([]byte(strings.TrimSpace(secKey) + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func computeWSMuxHandshakeAuth(authKey []byte, secKey, peerID string) string {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-wsmux-v1:" + secKey + "|" + peerID))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// ============================================================================
// RFC 6455 BINARY WEBSOCKET FRAME CODEC (WITH SECTION 5.3 CLIENT MASKING)
// ============================================================================

func writeRFC6455Frame(w io.Writer, isClient bool, opcode byte, payload []byte) error {
	length := len(payload)
	if length > 65535 {
		return errors.New("websocket frame exceeds 64KB")
	}

	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|opcode) // FIN = 1

	maskBit := byte(0x00)
	if isClient {
		maskBit = 0x80
	}

	if length <= 125 {
		hdr = append(hdr, maskBit|byte(length))
	} else {
		hdr = append(hdr, maskBit|126)
		var extLen [2]byte
		binary.BigEndian.PutUint16(extLen[:], uint16(length))
		hdr = append(hdr, extLen[:]...)
	}

	if isClient {
		var maskKey [4]byte
		_, _ = io.ReadFull(rand.Reader, maskKey[:])
		hdr = append(hdr, maskKey[:]...)
		masked := make([]byte, length)
		for i := 0; i < length; i++ {
			masked[i] = payload[i] ^ maskKey[i&3]
		}
		if _, err := w.Write(hdr); err != nil {
			return err
		}
		if length > 0 {
			_, err := w.Write(masked)
			return err
		}
		return nil
	}

	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if length > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

func readRFC6455Frame(r io.Reader) (byte, []byte, error) {
	var firstTwo [2]byte
	if _, err := io.ReadFull(r, firstTwo[:]); err != nil {
		return 0, nil, err
	}
	opcode := firstTwo[0] & 0x0F
	masked := (firstTwo[1] & 0x80) != 0
	length := int(firstTwo[1] & 0x7F)

	switch length {
	case 126:
		var ext16 [2]byte
		if _, err := io.ReadFull(r, ext16[:]); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint16(ext16[:]))
	case 127:
		var ext64 [8]byte
		if _, err := io.ReadFull(r, ext64[:]); err != nil {
			return 0, nil, err
		}
		u64 := binary.BigEndian.Uint64(ext64[:])
		if u64 > 256*1024 {
			return 0, nil, errors.New("websocket frame too large")
		}
		length = int(u64)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := 0; i < length; i++ {
				payload[i] ^= maskKey[i&3]
			}
		}
	}
	return opcode, payload, nil
}

// ============================================================================
// WEBSOCKET MULTIPLEX STREAM & SESSION ENGINE
// ============================================================================

type wsMuxStream struct {
	session    *wsMuxSession
	id         uint32
	targetPort uint16
	readCh     chan []byte
	readMu     sync.Mutex
	readBuf    bytes.Buffer
	openAckCh  chan bool
	closedRead atomic.Bool
	closed     atomic.Bool
}

func newWSMuxStream(s *wsMuxSession, id uint32, targetPort uint16) *wsMuxStream {
	return &wsMuxStream{
		session:    s,
		id:         id,
		targetPort: targetPort,
		readCh:     make(chan []byte, 256),
		openAckCh:  make(chan bool, 1),
	}
}

func (st *wsMuxStream) pushInboundData(chunk []byte) {
	if st.closedRead.Load() {
		return
	}
	cp := make([]byte, len(chunk))
	copy(cp, chunk)
	select {
	case st.readCh <- cp:
	default:
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case st.readCh <- cp:
		case <-timer.C:
			st.markRemoteClosed()
		}
	}
}

func (st *wsMuxStream) markRemoteClosed() {
	if st.closedRead.CompareAndSwap(false, true) {
		close(st.readCh)
	}
}

func (st *wsMuxStream) Read(p []byte) (int, error) {
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

func (st *wsMuxStream) Write(p []byte) (int, error) {
	if st.closed.Load() || st.session.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > wsMuxMaxChunkSize {
			chunk = p[:wsMuxMaxChunkSize]
		}
		if err := st.session.writeMuxFrame(wsMuxCmdData, 0, st.targetPort, st.id, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (st *wsMuxStream) CloseWrite() error {
	if st.closed.CompareAndSwap(false, true) {
		_ = st.session.writeMuxFrame(wsMuxCmdFIN, 0, st.targetPort, st.id, nil)
		st.session.removeStream(st.id)
	}
	return nil
}

func (st *wsMuxStream) Close() error {
	_ = st.CloseWrite()
	st.markRemoteClosed()
	return nil
}

type wsMuxSession struct {
	conn       net.Conn
	br         *bufio.Reader
	writeMu    sync.Mutex
	streamsMu  sync.RWMutex
	streams    map[uint32]*wsMuxStream
	nextID     atomic.Uint32
	pingMu     sync.Mutex
	pingWait   map[uint32]chan struct{}
	isClient   bool
	peer       ServerPeer
	tunnel     TunnelConfig
	remoteHost string
	closed     atomic.Bool
}

func newWSMuxSession(
	conn net.Conn,
	br *bufio.Reader,
	isClient bool,
	peer ServerPeer,
	tc TunnelConfig,
	remoteHost string,
) *wsMuxSession {
	if br == nil {
		br = bufio.NewReader(conn)
	}
	s := &wsMuxSession{
		conn:       conn,
		br:         br,
		streams:    make(map[uint32]*wsMuxStream),
		pingWait:   make(map[uint32]chan struct{}),
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

func (s *wsMuxSession) writeMuxFrame(subCmd, status byte, port uint16, streamID uint32, data []byte) error {
	if s.closed.Load() {
		return net.ErrClosed
	}
	buf := make([]byte, wsMuxSubHeaderSize+len(data))
	buf[0] = subCmd
	buf[1] = status
	binary.BigEndian.PutUint16(buf[2:4], port)
	binary.BigEndian.PutUint32(buf[4:8], streamID)
	copy(buf[8:], data)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := writeRFC6455Frame(s.conn, s.isClient, wsOpcodeBinary, buf)
	_ = s.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		s.closeAll()
	}
	return err
}

func (s *wsMuxSession) writeControlFrame(opcode byte, payload []byte) error {
	if s.closed.Load() {
		return net.ErrClosed
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	err := writeRFC6455Frame(s.conn, s.isClient, opcode, payload)
	_ = s.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		s.closeAll()
	}
	return err
}

func (s *wsMuxSession) removeStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

func (s *wsMuxSession) closeAll() {
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

func (s *wsMuxSession) ping(timeout time.Duration) (time.Duration, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	seq := s.nextID.Add(1)
	ch := make(chan struct{}, 1)

	s.pingMu.Lock()
	s.pingWait[seq] = ch
	s.pingMu.Unlock()

	defer func() {
		s.pingMu.Lock()
		delete(s.pingWait, seq)
		s.pingMu.Unlock()
	}()

	start := time.Now()
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], seq)
	if err := s.writeControlFrame(wsOpcodePing, payload[:]); err != nil {
		return 0, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case _, ok := <-ch:
		if !ok {
			return 0, errors.New("ws mux session closed")
		}
		return time.Since(start), nil
	case <-timer.C:
		return 0, errors.New("ws mux ping timeout")
	}
}

func (s *wsMuxSession) openClientStream(targetPort uint16, timeout time.Duration) (*wsMuxStream, error) {
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
		return nil, errors.New("websocket multiplex stream limit reached")
	}
	sid := s.nextID.Add(2)
	st := newWSMuxStream(s, sid, targetPort)
	s.streams[sid] = st
	s.streamsMu.Unlock()

	if err := s.writeMuxFrame(wsMuxCmdOpen, 0, targetPort, sid, []byte(buildMasterTimeHeader())); err != nil {
		s.removeStream(sid)
		return nil, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ok := <-st.openAckCh:
		if !ok {
			s.removeStream(sid)
			return nil, errors.New("remote rejected websocket mux stream")
		}
		return st, nil
	case <-timer.C:
		s.removeStream(sid)
		return nil, errors.New("websocket mux stream open timeout")
	}
}

func (s *wsMuxSession) readLoop() {
	defer s.closeAll()

	for {
		opcode, payload, err := readRFC6455Frame(s.br)
		if err != nil {
			return
		}

		switch opcode {
		case wsOpcodePing:
			markPeerConnectedInbound(s.peer.ID, s.remoteHost, s.tunnel.ID, s.tunnel.ListenPort, 1)
			_ = s.writeControlFrame(wsOpcodePong, payload)

		case wsOpcodePong:
			if len(payload) >= 4 {
				seq := binary.BigEndian.Uint32(payload[0:4])
				s.pingMu.Lock()
				if ch, ok := s.pingWait[seq]; ok {
					select {
					case ch <- struct{}{}:
					default:
					}
				}
				s.pingMu.Unlock()
			}

		case wsOpcodeClose:
			return

		case wsOpcodeBinary:
			if len(payload) < wsMuxSubHeaderSize {
				continue
			}
			subCmd := payload[0]
			status := payload[1]
			port := binary.BigEndian.Uint16(payload[2:4])
			streamID := binary.BigEndian.Uint32(payload[4:8])
			data := payload[8:]

			switch subCmd {
			case wsMuxCmdOpen:
				if len(data) > 0 {
					applyMasterTimeHeader(string(data))
				}
				st := newWSMuxStream(s, streamID, port)
				s.streamsMu.Lock()
				s.streams[streamID] = st
				s.streamsMu.Unlock()

				go s.handleServerStream(st, port)

			case wsMuxCmdOpenAck:
				s.streamsMu.RLock()
				st := s.streams[streamID]
				s.streamsMu.RUnlock()
				if st != nil {
					select {
					case st.openAckCh <- (status == 0):
					default:
					}
				}

			case wsMuxCmdData:
				s.streamsMu.RLock()
				st := s.streams[streamID]
				s.streamsMu.RUnlock()
				if st != nil && len(data) > 0 {
					st.pushInboundData(data)
				}

			case wsMuxCmdFIN:
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
}

func (s *wsMuxSession) handleServerStream(st *wsMuxStream, targetPort uint16) {
	defer st.Close()

	if targetPort == wsMuxPortParitySync {
		if err := s.writeMuxFrame(wsMuxCmdOpenAck, 0, targetPort, st.id, nil); err != nil {
			return
		}
		handleWebTransportParitySyncStream(st, s.peer.ID, s.remoteHost)
		return
	}

	if !s.tunnel.Enabled {
		_ = s.writeMuxFrame(wsMuxCmdOpenAck, 1, targetPort, st.id, nil)
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
		_ = s.writeMuxFrame(wsMuxCmdOpenAck, 1, targetPort, st.id, nil)
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	if err := s.writeMuxFrame(wsMuxCmdOpenAck, 0, targetPort, st.id, nil); err != nil {
		return
	}

	mbLimit := parseSpeedLimit(s.tunnel.SpeedLimitMBps)
	toWSMux := newThrottledWriter(st, &appTxBytes, mbLimit)
	toLocal := newThrottledWriter(target, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 28*1024)
		_, _ = io.CopyBuffer(toWSMux, target, buf)
		_ = st.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 28*1024)
		_, _ = io.CopyBuffer(toLocal, st, buf)
		if tc, ok := target.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// ============================================================================
// PERSISTENT CLIENT SESSION POOL & SERVER LISTENER (:28022)
// ============================================================================

var (
	wsMuxPoolMu   sync.Mutex
	wsMuxSessions = make(map[string]*wsMuxSession)
)

func stopWSMultiplexPeerResources(peerID string) {
	wsMuxPoolMu.Lock()
	if sess, ok := wsMuxSessions[peerID]; ok {
		sess.closeAll()
		delete(wsMuxSessions, peerID)
	}
	wsMuxPoolMu.Unlock()
}

func getOrDialWSMuxSession(peer ServerPeer, tc TunnelConfig, timeout time.Duration) (*wsMuxSession, error) {
	wsMuxPoolMu.Lock()
	existing := wsMuxSessions[peer.ID]
	if existing != nil && !existing.closed.Load() && existing.tunnel.ListenPort == tc.ListenPort {
		wsMuxPoolMu.Unlock()
		return existing, nil
	}
	if existing != nil {
		existing.closeAll()
		delete(wsMuxSessions, peer.ID)
	}
	wsMuxPoolMu.Unlock()

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

	sni := strings.TrimSpace(tc.SNI)
	if sni == "" {
		sni = "www.speedtest.net"
	}
	pin := strings.TrimSpace(tc.CertPin)
	if pin == "" {
		pin = peer.RemoteCertPin
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	var keyBytes [16]byte
	_, _ = io.ReadFull(rand.Reader, keyBytes[:])
	secKey := base64.StdEncoding.EncodeToString(keyBytes[:])
	authSig := computeWSMuxHandshakeAuth(authKey, secKey, peer.ID)
	wsPath := normalizePollPath(tc.WSPath)

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Protocol: wsmux.v1\r\n"+
			"X-WSMux-Peer: %s\r\n"+
			"X-WSMux-Auth: %s\r\n"+
			"X-Sahand-Time: %s\r\n\r\n",
		wsPath, sni, secKey, peer.ID, authSig, buildMasterTimeHeader(),
	)

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	br := bufio.NewReader(tlsConn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		_ = tlsConn.Close()
		return nil, errors.New("websocket multiplex upgrade rejected")
	}

	var acceptHdr string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-accept:") {
			acceptHdr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	if acceptHdr != computeWSAcceptKey(secKey) {
		_ = tlsConn.Close()
		return nil, errors.New("invalid sec-websocket-accept header")
	}
	_ = tlsConn.SetDeadline(time.Time{})

	sess := newWSMuxSession(tlsConn, br, true, peer, tc, strings.TrimSpace(peer.IP))

	wsMuxPoolMu.Lock()
	if old, ok := wsMuxSessions[peer.ID]; ok && old != sess {
		old.closeAll()
	}
	wsMuxSessions[peer.ID] = sess
	wsMuxPoolMu.Unlock()

	return sess, nil
}

func startWSMultiplexServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{localCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	ln, err := tls.Listen("tcp", listenAddr, tlsCfg)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleIncomingWSMultiplexConn(conn, peer, tc)
		}
	}()
	return ln, nil
}

func handleIncomingWSMultiplexConn(conn net.Conn, peer ServerPeer, tc TunnelConfig) {
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		_ = conn.Close()
		return
	}

	br := bufio.NewReader(conn)
	firstLine, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(firstLine, "GET ") {
		_ = conn.Close()
		return
	}

	var secKey, peerHdr, authHdr, timeHdr string
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		low := strings.ToLower(line)
		switch {
		case strings.HasPrefix(low, "sec-websocket-key:"):
			secKey = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		case strings.HasPrefix(low, "x-wsmux-peer:"):
			peerHdr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		case strings.HasPrefix(low, "x-wsmux-auth:"):
			authHdr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		case strings.HasPrefix(low, "x-sahand-time:"):
			timeHdr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}

	if timeHdr != "" {
		applyMasterTimeHeader(timeHdr)
	}
	expectedAuth := computeWSMuxHandshakeAuth(authKey, secKey, peerHdr)
	if secKey == "" || authHdr == "" || subtle.ConstantTimeCompare([]byte(authHdr), []byte(expectedAuth)) != 1 {
		_, _ = conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n"))
		_ = conn.Close()
		return
	}

	acceptKey := computeWSAcceptKey(secKey)
	resp := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"Sec-WebSocket-Protocol: wsmux.v1\r\n\r\n",
		acceptKey,
	)
	if _, err := conn.Write([]byte(resp)); err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	_ = newWSMuxSession(conn, br, false, peer, tc, remoteHost)
}

// ============================================================================
// ENGINE 1 & ENGINE 2 ENTRY POINTS FOR WEBSOCKET MULTIPLEX
// ============================================================================

func probeWSMultiplex(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	sess, err := getOrDialWSMuxSession(peer, tc, 4*time.Second)
	if err != nil {
		res.Success = false
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(msg, "tls") || strings.Contains(msg, "pin") {
			res.ErrorReason = "TLS failure"
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

func pushWSMultiplexParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	sess, err := getOrDialWSMuxSession(peer, tc, 4*time.Second)
	if err != nil {
		return false
	}

	st, err := sess.openClientStream(wsMuxPortParitySync, 4*time.Second)
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

func forwardWSMultiplexTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	portNum, _ := strconv.Atoi(strings.TrimSpace(targetPort))
	if portNum <= 0 {
		portNum = 32000 + tc.ID
	}

	sess, err := getOrDialWSMuxSession(peer, tc, 5*time.Second)
	if err != nil {
		return
	}

	st, err := sess.openClientStream(uint16(portNum), 5*time.Second)
	if err != nil {
		return
	}
	defer st.Close()

	mbLimit := parseSpeedLimit(tc.SpeedLimitMBps)
	toWSMux := newThrottledWriter(st, &appTxBytes, mbLimit)
	toLocal := newThrottledWriter(client, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 28*1024)
		_, _ = io.CopyBuffer(toWSMux, client, buf)
		_ = st.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 28*1024)
		_, _ = io.CopyBuffer(toLocal, st, buf)
		if tcpC, ok := client.(*net.TCPConn); ok {
			_ = tcpC.CloseWrite()
		}
	}()

	wg.Wait()
}
