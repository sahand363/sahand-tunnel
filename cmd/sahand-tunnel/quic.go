package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/quic-go/quic-go"
)

const (
	// Dedicated ALPN identifier for Sahand Tunnel QUIC transport.
	// Never advertises "h3" because this transport is native multiplexed QUIC, not HTTP/3.
	quicALPN = "sahand-quic-v1"

	quicStreamTypeProbe      byte = 0x01
	quicStreamTypeParitySync byte = 0x02
	quicStreamTypeTCPForward byte = 0x03
	quicStreamTypeUDPAuth    byte = 0x04

	quicStatusOK           byte = 0x00
	quicStatusUnauthorized byte = 0x01
	quicStatusForbidden    byte = 0x02
	quicStatusUnreachable  byte = 0x03

	quicDatagramFlagRaw      byte = 0x00
	quicDatagramFlagFragment byte = 0x01
	quicDatagramFlagClose    byte = 0x02

	// Wire header for unfragmented QUIC DATAGRAM frames:
	// [Flag:1][SessionID:4][TargetPort:2] = 7 bytes
	quicDatagramRawHeaderSize = 7

	// Wire header for optional fragmented QUIC DATAGRAM frames:
	// [Flag:1][SessionID:4][TargetPort:2][FragID:2][FragIndex:1][FragTotal:1] = 11 bytes
	quicDatagramFragHeaderSize = 11

	quicDefaultMaxDatagramPayload = 1180
	quicMaxOriginalDatagramSize   = 8192
	quicMaxFragmentsPerDatagram   = 8
	quicMaxReassemblyBytes        = 512 * 1024
	quicReassemblyTTL             = 2 * time.Second

	quicProbeSampleCount      = 4
	quicProbeSampleTimeout    = 1500 * time.Millisecond
	quicReplayWindowSec       = 120
	quicMaxReplayCacheEntries = 4096
	quicMaxUDPSessionsPerPeer = 2048
	quicUDPSessionIdleTTL     = 60 * time.Second
	quicSocketBufferBytes     = 4 * 1024 * 1024
)

var (
	ErrQUICDatagramTooLarge = errors.New("udp payload exceeds negotiated quic datagram size")
	ErrQUICUnauthorizedPeer = errors.New("quic peer authentication failed")
	ErrQUICSessionLimit     = errors.New("quic udp session limit reached")

	// Optional datagram fragmentation toggle (disabled by default to preserve strict datagram boundaries;
	// can be enabled explicitly when oversized UDP payloads must be carried).
	quicAllowDatagramFragmentation atomic.Bool
)

// quicConnectionIdentity uniquely identifies a pooled QUIC connection so Engine 1 (control)
// and Engine 2 (data), multiple peers, and configuration changes never collide.
type quicConnectionIdentity struct {
	PeerID         string
	LocalNodeID    string
	MethodID       int
	Plane          string // "control" or "data"
	RemoteEndpoint string
	ListenPort     int
	ConfigGen      string
}

type quicStreamHandshake struct {
	Version    int    `json:"v"`
	StreamType byte   `json:"t"`
	PeerID     string `json:"pid"`
	NodeID     string `json:"nid"`
	CertPin    string `json:"pin,omitempty"`
	TargetPort string `json:"port,omitempty"`
	TimeHdr    string `json:"tm,omitempty"`
	Timestamp  int64  `json:"ts"`
	Nonce      string `json:"nc"`
	Signature  string `json:"sig"`
}

type quicReplayGuard struct {
	mu     sync.Mutex
	seen   map[string]int64
	lastGC int64
}

func newQUICReplayGuard() *quicReplayGuard {
	return &quicReplayGuard{
		seen: make(map[string]int64),
	}
}

func (rg *quicReplayGuard) checkAndRecord(nonce string, ts int64) bool {
	now := time.Now().Unix()
	diff := now - ts
	if diff < -quicReplayWindowSec || diff > quicReplayWindowSec {
		return false
	}
	rg.mu.Lock()
	defer rg.mu.Unlock()

	if now-rg.lastGC > 30 || len(rg.seen) >= quicMaxReplayCacheEntries {
		for k, exp := range rg.seen {
			if now > exp {
				delete(rg.seen, k)
			}
		}
		rg.lastGC = now
		if len(rg.seen) >= quicMaxReplayCacheEntries {
			return false
		}
	}
	if _, exists := rg.seen[nonce]; exists {
		return false
	}
	rg.seen[nonce] = now + quicReplayWindowSec + 10
	return true
}

var globalQUICReplayGuard = newQUICReplayGuard()

func signQUICHandshake(hs quicStreamHandshake, key []byte) string {
	canonical := fmt.Sprintf("%d|%d|%s|%s|%s|%s|%d|%s",
		hs.Version, hs.StreamType, hs.PeerID, hs.NodeID, hs.CertPin, hs.TargetPort, hs.Timestamp, hs.Nonce)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyQUICHandshake(hs quicStreamHandshake, key []byte) bool {
	if len(key) == 0 || hs.PeerID == "" || hs.NodeID == "" || hs.Nonce == "" || hs.Signature == "" {
		return false
	}
	expected := signQUICHandshake(hs, key)
	if subtle.ConstantTimeCompare([]byte(hs.Signature), []byte(expected)) != 1 {
		return false
	}
	return globalQUICReplayGuard.checkAndRecord(hs.PeerID+"|"+hs.Nonce, hs.Timestamp)
}

func writeQUICHandshake(w io.Writer, hs quicStreamHandshake) error {
	raw, err := json.Marshal(hs)
	if err != nil {
		return err
	}
	if len(raw) > 8192 {
		return errors.New("quic handshake header too large")
	}
	var hdr [3]byte
	hdr[0] = hs.StreamType
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(raw)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func readQUICHandshake(r io.Reader) (quicStreamHandshake, error) {
	var hs quicStreamHandshake
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return hs, err
	}
	msgLen := int(binary.BigEndian.Uint16(hdr[1:3]))
	if msgLen <= 0 || msgLen > 8192 {
		return hs, errors.New("invalid quic handshake header length")
	}
	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return hs, err
	}
	if err := json.Unmarshal(buf, &hs); err != nil {
		return hs, err
	}
	hs.StreamType = hdr[0]
	return hs, nil
}

// ============================================================================
// SHARED UDP LISTENER REGISTRY & CONNECTION POOL
// ============================================================================

type quicPeerRegistration struct {
	Peer       ServerPeer
	Tunnel     TunnelConfig
	AuthKey    []byte
	ExitUDPMux *quicUDPExitSessionManager
}

type quicSharedPortListener struct {
	mu          sync.RWMutex
	port        int
	udpConn     *net.UDPConn
	transport   *quic.Transport
	listener    *quic.Listener
	peers       map[string]*quicPeerRegistration
	activeConns map[*quic.Conn]struct{}
	closed      bool
}

type quicManagedClientConn struct {
	mu               sync.Mutex
	identity         quicConnectionIdentity
	udpConn          *net.UDPConn
	transport        *quic.Transport
	conn             *quic.Conn
	maxDatagramBytes atomic.Int64
	udpAuthed        atomic.Bool
	entryUDPMux      *quicUDPEntrySessionManager
}

var (
	quicRegistryMu       sync.Mutex
	quicSharedListeners  = make(map[int]*quicSharedPortListener)
	quicPeerPortBindings = make(map[string]int)
	quicClientPool       = make(map[quicConnectionIdentity]*quicManagedClientConn)
	quicEntryUDPMuxes    = make(map[string]*quicUDPEntrySessionManager)

	quicBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 2048)
			return &b
		},
	}
)

func configureUDPSocketBuffers(conn *net.UDPConn) {
	_ = conn.SetReadBuffer(quicSocketBufferBytes)
	_ = conn.SetWriteBuffer(quicSocketBufferBytes)
}

func buildQUICConfig(tc TunnelConfig) *quic.Config {
	hbSec := tc.HeartbeatSec
	if hbSec <= 0 {
		hbSec = 20
	}
	if hbSec > 60 {
		hbSec = 60
	}
	streamLimit := tc.StreamLimit
	if streamLimit <= 0 {
		streamLimit = 64
	}
	if streamLimit > 1024 {
		streamLimit = 1024
	}
	return &quic.Config{
		Versions:                       []quic.Version{quic.Version1, quic.Version2},
		HandshakeIdleTimeout:           6 * time.Second,
		MaxIdleTimeout:                 90 * time.Second,
		KeepAlivePeriod:                time.Duration(hbSec) * time.Second,
		MaxIncomingStreams:             int64(streamLimit),
		MaxIncomingUniStreams:          16,
		InitialStreamReceiveWindow:     2 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,
		MaxConnectionReceiveWindow:     32 * 1024 * 1024,
		EnableDatagrams:                true,
		Allow0RTT:                      false,
	}
}

func buildQUICClientTLSConfig(peer ServerPeer, tc TunnelConfig) *tls.Config {
	sni := strings.TrimSpace(tc.SNI)
	if sni == "" {
		sni = "www.speedtest.net"
	}
	pin := strings.TrimSpace(tc.CertPin)
	if pin == "" {
		pin = peer.RemoteCertPin
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{localCert},
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{quicALPN},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}
}

func buildQUICServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{localCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{quicALPN},
	}
}

func makeQUICConnectionIdentity(peer ServerPeer, tc TunnelConfig, plane string) quicConnectionIdentity {
	stateMu.RLock()
	localNodeID := appCfg.NodeID
	stateMu.RUnlock()

	pin := strings.TrimSpace(tc.CertPin)
	if pin == "" {
		pin = peer.RemoteCertPin
	}
	gen := fmt.Sprintf("v%d|p%d|sni:%s|pin:%s|hb:%d|sl:%d",
		peer.ConfigVersion, tc.ListenPort, strings.TrimSpace(tc.SNI), pin, tc.HeartbeatSec, tc.StreamLimit)

	return quicConnectionIdentity{
		PeerID:         peer.ID,
		LocalNodeID:    localNodeID,
		MethodID:       tc.ID,
		Plane:          plane,
		RemoteEndpoint: fmt.Sprintf("%s:%d", strings.TrimSpace(peer.IP), tc.ListenPort),
		ListenPort:     tc.ListenPort,
		ConfigGen:      gen,
	}
}

func registerQUICPeerListener(peer ServerPeer, tc TunnelConfig) error {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, _ := derivePeerAuthKey(cfgSnapshot, peer)

	quicRegistryMu.Lock()
	defer quicRegistryMu.Unlock()

	if oldPort, ok := quicPeerPortBindings[peer.ID]; ok && oldPort != tc.ListenPort {
		removePeerFromSharedListenerLocked(peer.ID, oldPort)
	}

	spl, exists := quicSharedListeners[tc.ListenPort]
	if !exists || spl.closed {
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", tc.ListenPort))
		if err != nil {
			return err
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		configureUDPSocketBuffers(udpConn)

		tr := &quic.Transport{Conn: udpConn}
		tlsCfg := buildQUICServerTLSConfig()
		quicCfg := buildQUICConfig(tc)

		ln, err := tr.Listen(tlsCfg, quicCfg)
		if err != nil {
			_ = tr.Close()
			_ = udpConn.Close()
			return err
		}

		spl = &quicSharedPortListener{
			port:        tc.ListenPort,
			udpConn:     udpConn,
			transport:   tr,
			listener:    ln,
			peers:       make(map[string]*quicPeerRegistration),
			activeConns: make(map[*quic.Conn]struct{}),
		}
		quicSharedListeners[tc.ListenPort] = spl
		go spl.acceptLoop()
	}

	spl.mu.Lock()
	if oldReg, ok := spl.peers[peer.ID]; ok && oldReg.ExitUDPMux != nil {
		oldReg.ExitUDPMux.closeAll()
	}
	spl.peers[peer.ID] = &quicPeerRegistration{
		Peer:       peer,
		Tunnel:     tc,
		AuthKey:    authKey,
		ExitUDPMux: newQUICUDPExitSessionManager(tc.SpeedLimitMBps),
	}
	spl.mu.Unlock()

	quicPeerPortBindings[peer.ID] = tc.ListenPort
	return nil
}

func removePeerFromSharedListenerLocked(peerID string, port int) {
	spl, ok := quicSharedListeners[port]
	if !ok {
		return
	}
	spl.mu.Lock()
	if reg, exists := spl.peers[peerID]; exists {
		if reg.ExitUDPMux != nil {
			reg.ExitUDPMux.closeAll()
		}
		delete(spl.peers, peerID)
	}
	remaining := len(spl.peers)
	spl.mu.Unlock()

	if remaining == 0 {
		spl.close()
		delete(quicSharedListeners, port)
	}
}

func stopQUICPeerResources(peerID string) {
	quicRegistryMu.Lock()
	if port, ok := quicPeerPortBindings[peerID]; ok {
		removePeerFromSharedListenerLocked(peerID, port)
		delete(quicPeerPortBindings, peerID)
	}
	for id, mc := range quicClientPool {
		if id.PeerID == peerID {
			mc.close()
			delete(quicClientPool, id)
		}
	}
	for k, mux := range quicEntryUDPMuxes {
		if strings.HasPrefix(k, peerID+"|") {
			mux.closeAll()
			delete(quicEntryUDPMuxes, k)
		}
	}
	quicRegistryMu.Unlock()
}

func (spl *quicSharedPortListener) close() {
	spl.mu.Lock()
	if spl.closed {
		spl.mu.Unlock()
		return
	}
	spl.closed = true
	for _, reg := range spl.peers {
		if reg.ExitUDPMux != nil {
			reg.ExitUDPMux.closeAll()
		}
	}
	for c := range spl.activeConns {
		_ = c.CloseWithError(0, "listener shutting down")
	}
	spl.activeConns = make(map[*quic.Conn]struct{})
	spl.mu.Unlock()

	if spl.listener != nil {
		_ = spl.listener.Close()
	}
	if spl.transport != nil {
		_ = spl.transport.Close()
	}
	if spl.udpConn != nil {
		_ = spl.udpConn.Close()
	}
}

func (spl *quicSharedPortListener) acceptLoop() {
	for {
		conn, err := spl.listener.Accept(context.Background())
		if err != nil {
			return
		}
		spl.mu.Lock()
		if spl.closed {
			spl.mu.Unlock()
			_ = conn.CloseWithError(0, "listener closed")
			return
		}
		spl.activeConns[conn] = struct{}{}
		spl.mu.Unlock()

		go spl.serveConnection(conn)
	}
}

func (spl *quicSharedPortListener) resolveRegistration(peerID, remoteIP string) *quicPeerRegistration {
	spl.mu.RLock()
	defer spl.mu.RUnlock()

	if reg, ok := spl.peers[peerID]; ok {
		return reg
	}
	for _, reg := range spl.peers {
		if reg.Peer.IP == remoteIP {
			return reg
		}
	}
	if len(spl.peers) == 1 {
		for _, reg := range spl.peers {
			return reg
		}
	}
	return nil
}

func (spl *quicSharedPortListener) serveConnection(conn *quic.Conn) {
	defer func() {
		spl.mu.Lock()
		delete(spl.activeConns, conn)
		spl.mu.Unlock()
		_ = conn.CloseWithError(0, "connection closed")
	}()

	var authedReg atomic.Pointer[quicPeerRegistration]
	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// Start exit-side QUIC DATAGRAM receiver loop once the connection is authenticated
	go func() {
		for {
			dgram, err := conn.ReceiveDatagram(conn.Context())
			if err != nil {
				return
			}
			reg := authedReg.Load()
			if reg == nil || !reg.Tunnel.Enabled || reg.ExitUDPMux == nil {
				continue
			}
			reg.ExitUDPMux.handleIncomingDatagram(conn, reg.Tunnel, dgram)
		}
	}()

	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		go spl.handleIncomingStream(conn, stream, remoteHost, &authedReg)
	}
}

func (spl *quicSharedPortListener) handleIncomingStream(
	conn *quic.Conn,
	stream *quic.Stream,
	remoteHost string,
	authedReg *atomic.Pointer[quicPeerRegistration],
) {
	defer func() {
		_ = stream.Close()
		stream.CancelRead(0)
	}()

	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	hs, err := readQUICHandshake(stream)
	if err != nil {
		stream.CancelWrite(1)
		return
	}

	reg := spl.resolveRegistration(hs.PeerID, remoteHost)
	if reg == nil || !verifyQUICHandshake(hs, reg.AuthKey) {
		_, _ = stream.Write([]byte{quicStatusUnauthorized})
		_ = conn.CloseWithError(0x401, "unauthorized peer")
		return
	}

	if hs.TimeHdr != "" {
		applyMasterTimeHeader(hs.TimeHdr)
	}
	authedReg.Store(reg)

	switch hs.StreamType {
	case quicStreamTypeProbe:
		handleQUICProbeStream(stream, reg, remoteHost)

	case quicStreamTypeParitySync:
		handleQUICParitySyncStream(stream, reg, remoteHost)

	case quicStreamTypeUDPAuth:
		if !reg.Tunnel.Enabled {
			_, _ = stream.Write([]byte{quicStatusForbidden})
			return
		}
		_, _ = stream.Write([]byte{quicStatusOK})

	case quicStreamTypeTCPForward:
		if !reg.Tunnel.Enabled {
			_, _ = stream.Write([]byte{quicStatusForbidden})
			return
		}
		_ = stream.SetDeadline(time.Time{})
		handleQUICTCPForwardStream(stream, reg.Tunnel, hs.TargetPort)
	}
}

// ============================================================================
// OUTBOUND QUIC CONNECTION POOL MANAGEMENT
// ============================================================================

func (mc *quicManagedClientConn) close() {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.conn != nil {
		_ = mc.conn.CloseWithError(0, "client pool closing")
		mc.conn = nil
	}
	if mc.transport != nil {
		_ = mc.transport.Close()
		mc.transport = nil
	}
	if mc.udpConn != nil {
		_ = mc.udpConn.Close()
		mc.udpConn = nil
	}
}

func getOrDialQUICConnection(
	ctx context.Context,
	peer ServerPeer,
	tc TunnelConfig,
	plane string,
	entryUDPMux *quicUDPEntrySessionManager,
) (*quic.Conn, *quicManagedClientConn, error) {
	id := makeQUICConnectionIdentity(peer, tc, plane)

	quicRegistryMu.Lock()
	mc, exists := quicClientPool[id]
	if !exists {
		mc = &quicManagedClientConn{
			identity:    id,
			entryUDPMux: entryUDPMux,
		}
		mc.maxDatagramBytes.Store(quicDefaultMaxDatagramPayload)
		quicClientPool[id] = mc
	} else if entryUDPMux != nil {
		mc.entryUDPMux = entryUDPMux
	}
	quicRegistryMu.Unlock()

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.conn != nil && mc.conn.Context().Err() == nil {
		return mc.conn, mc, nil
	}

	if mc.conn != nil {
		_ = mc.conn.CloseWithError(0, "reconnecting")
		mc.conn = nil
	}
	if mc.transport != nil {
		_ = mc.transport.Close()
		mc.transport = nil
	}
	if mc.udpConn != nil {
		_ = mc.udpConn.Close()
		mc.udpConn = nil
	}
	mc.udpAuthed.Store(false)

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", id.RemoteEndpoint)
	if err != nil {
		return nil, nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, err
	}
	configureUDPSocketBuffers(udpConn)

	tr := &quic.Transport{Conn: udpConn}
	tlsCfg := buildQUICClientTLSConfig(peer, tc)
	quicCfg := buildQUICConfig(tc)

	conn, err := tr.Dial(ctx, remoteUDPAddr, tlsCfg, quicCfg)
	if err != nil {
		_ = tr.Close()
		_ = udpConn.Close()
		return nil, nil, err
	}

	st := conn.ConnectionState()
	if st.TLS.Version != tls.VersionTLS13 || st.TLS.NegotiatedProtocol != quicALPN {
		_ = conn.CloseWithError(0x400, "invalid tls or alpn")
		_ = tr.Close()
		_ = udpConn.Close()
		return nil, nil, errors.New("TLS 1.3 or ALPN negotiation failed")
	}

	mc.udpConn = udpConn
	mc.transport = tr
	mc.conn = conn

	if plane == "data" {
		go func(c *quic.Conn, clientWrapper *quicManagedClientConn) {
			for {
				dgram, rErr := c.ReceiveDatagram(c.Context())
				if rErr != nil {
					return
				}
				if clientWrapper.entryUDPMux != nil {
					clientWrapper.entryUDPMux.handleInboundReplyDatagram(dgram)
				}
			}
		}(conn, mc)
	}

	return conn, mc, nil
}

func buildSignedHandshake(streamType byte, peer ServerPeer, targetPort string) (quicStreamHandshake, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return quicStreamHandshake{}, err
	}
	nonce, err := randomHex(8)
	if err != nil {
		return quicStreamHandshake{}, err
	}
	hs := quicStreamHandshake{
		Version:    peer.ConfigVersion,
		StreamType: streamType,
		PeerID:     peer.ID,
		NodeID:     cfgSnapshot.NodeID,
		CertPin:    cfgSnapshot.CertPin,
		TargetPort: targetPort,
		TimeHdr:    buildMasterTimeHeader(),
		Timestamp:  time.Now().Unix(),
		Nonce:      nonce,
	}
	hs.Signature = signQUICHandshake(hs, authKey)
	return hs, nil
}

// ============================================================================
// ENGINE 1: GENUINE QUIC PROBE (RTT, MIN/AVG/MAX, JITTER, LOSS) & PARITY SYNC
// ============================================================================

func classifyQUICError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "pin mismatch") || strings.Contains(msg, "certificate") || strings.Contains(msg, "tls"):
		return "TLS failure"
	case strings.Contains(msg, "unauthorized") || strings.Contains(msg, "auth"):
		return "Authentication failure"
	case strings.Contains(msg, "alpn") || strings.Contains(msg, "version"):
		return "Protocol mismatch"
	case strings.Contains(msg, "refused") || strings.Contains(msg, "unreachable") || strings.Contains(msg, "network is down"):
		return "Port unreachable"
	default:
		return "Timeout"
	}
}

func probeQUIC(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer dialCancel()

	conn, _, err := getOrDialQUICConnection(dialCtx, peer, tc, "control", nil)
	if err != nil {
		res.Success = false
		res.PacketLossPct = 100
		res.ErrorReason = classifyQUICError(err)
		return res
	}

	st := conn.ConnectionState()
	if !st.SupportsDatagrams.Remote || !st.SupportsDatagrams.Local {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	streamCtx, streamCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer streamCancel()

	stream, err := conn.OpenStreamSync(streamCtx)
	if err != nil {
		_ = conn.CloseWithError(0, "stream open failed")
		res.Success = false
		res.PacketLossPct = 100
		res.ErrorReason = classifyQUICError(err)
		return res
	}
	defer func() {
		_ = stream.Close()
		stream.CancelRead(0)
	}()

	hs, err := buildSignedHandshake(quicStreamTypeProbe, peer, fmt.Sprintf("probe:%d", tc.ListenPort))
	if err != nil {
		res.Success = false
		res.ErrorReason = "Authentication failure"
		return res
	}

	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeQUICHandshake(stream, hs); err != nil {
		res.Success = false
		res.ErrorReason = "Timeout"
		return res
	}

	var status [1]byte
	if _, err := io.ReadFull(stream, status[:]); err != nil {
		res.Success = false
		res.ErrorReason = "Timeout"
		return res
	}
	if status[0] != quicStatusOK {
		res.Success = false
		res.ErrorReason = "Authentication failure"
		return res
	}

	var samples []int64
	var sendBuf [12]byte
	var recvBuf [12]byte

	for seq := 0; seq < quicProbeSampleCount; seq++ {
		_ = stream.SetDeadline(time.Now().Add(quicProbeSampleTimeout))
		sampleStart := time.Now()
		binary.BigEndian.PutUint32(sendBuf[0:4], uint32(seq))
		binary.BigEndian.PutUint64(sendBuf[4:12], uint64(sampleStart.UnixNano()))

		if _, wErr := stream.Write(sendBuf[:]); wErr != nil {
			continue
		}
		if _, rErr := io.ReadFull(stream, recvBuf[:]); rErr != nil {
			continue
		}
		echoSeq := int(binary.BigEndian.Uint32(recvBuf[0:4]))
		if echoSeq != seq {
			continue
		}
		rtt := time.Since(sampleStart).Milliseconds()
		if rtt <= 0 {
			rtt = 1
		}
		samples = append(samples, rtt)
	}

	if len(samples) == 0 {
		res.Success = false
		res.PacketLossPct = 100
		res.ErrorReason = "Timeout"
		return res
	}

	var sum, minRTT, maxRTT, jitterSum int64
	minRTT = samples[0]
	maxRTT = samples[0]
	for i, s := range samples {
		sum += s
		if s < minRTT {
			minRTT = s
		}
		if s > maxRTT {
			maxRTT = s
		}
		if i > 0 {
			diff := s - samples[i-1]
			if diff < 0 {
				diff = -diff
			}
			jitterSum += diff
		}
	}

	res.Success = true
	res.LatencyMS = sum / int64(len(samples))
	res.MinLatencyMS = minRTT
	res.MaxLatencyMS = maxRTT
	if len(samples) > 1 {
		res.JitterMS = jitterSum / int64(len(samples)-1)
	}
	res.PacketLossPct = ((quicProbeSampleCount - len(samples)) * 100) / quicProbeSampleCount
	return res
}

func handleQUICProbeStream(stream *quic.Stream, reg *quicPeerRegistration, remoteHost string) {
	if _, err := stream.Write([]byte{quicStatusOK}); err != nil {
		return
	}
	var buf [12]byte
	var measuredLatency int64 = 1
	for i := 0; i < quicProbeSampleCount; i++ {
		_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(stream, buf[:]); err != nil {
			break
		}
		if _, err := stream.Write(buf[:]); err != nil {
			break
		}
	}
	markPeerConnectedInbound(reg.Peer.ID, remoteHost, reg.Tunnel.ID, reg.Tunnel.ListenPort, measuredLatency)
}

func pushQUICParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := getOrDialQUICConnection(ctx, peer, tc, "control", nil)
	if err != nil {
		return false
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return false
	}
	defer func() {
		_ = stream.Close()
		stream.CancelRead(0)
	}()

	hs, err := buildSignedHandshake(quicStreamTypeParitySync, peer, strconv.Itoa(tc.ListenPort))
	if err != nil {
		return false
	}
	_ = stream.SetDeadline(time.Now().Add(6 * time.Second))
	if err := writeQUICHandshake(stream, hs); err != nil {
		return false
	}

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
	if _, err := stream.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := stream.Write(rawPkt); err != nil {
		return false
	}

	var status [1]byte
	if _, err := io.ReadFull(stream, status[:]); err != nil || status[0] != quicStatusOK {
		return false
	}
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBytes); err != nil {
		return false
	}

	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func handleQUICParitySyncStream(stream *quic.Stream, reg *quicPeerRegistration, remoteHost string) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen == 0 || pktLen > 256*1024 {
		return
	}
	rawPkt := make([]byte, pktLen)
	if _, err := io.ReadFull(stream, rawPkt); err != nil {
		return
	}
	var pkt SyncPacket
	if json.Unmarshal(rawPkt, &pkt) != nil {
		return
	}

	resp := processIncomingSync(reg.Peer.ID, remoteHost, pkt)
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return
	}

	_, _ = stream.Write([]byte{quicStatusOK})
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(respBytes)))
	_, _ = stream.Write(lenBuf[:])
	_, _ = stream.Write(respBytes)
}

// ============================================================================
// ENGINE 2: BIDIRECTIONAL TCP FORWARDING OVER QUIC STREAMS
// ============================================================================

func forwardQUICTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	conn, _, err := getOrDialQUICConnection(ctx, peer, tc, "data", nil)
	cancel()
	if err != nil {
		return
	}

	openCtx, openCancel := context.WithTimeout(context.Background(), 5*time.Second)
	stream, err := conn.OpenStreamSync(openCtx)
	openCancel()
	if err != nil {
		return
	}

	hs, err := buildSignedHandshake(quicStreamTypeTCPForward, peer, targetPort)
	if err != nil {
		_ = stream.Close()
		stream.CancelRead(0)
		return
	}

	_ = stream.SetDeadline(time.Now().Add(6 * time.Second))
	if err := writeQUICHandshake(stream, hs); err != nil {
		_ = stream.Close()
		stream.CancelRead(0)
		return
	}

	var status [1]byte
	if _, err := io.ReadFull(stream, status[:]); err != nil || status[0] != quicStatusOK {
		_ = stream.Close()
		stream.CancelRead(0)
		return
	}
	_ = stream.SetDeadline(time.Time{})

	pipeQUICStreamAndTCP(stream, client, tc.SpeedLimitMBps)
}

func handleQUICTCPForwardStream(stream *quic.Stream, tc TunnelConfig, targetPort string) {
	if targetPort == "" {
		ports := parsePortList(tc.ForwardPorts)
		if len(ports) > 0 {
			targetPort = ports[0]
		} else {
			targetPort = "2053"
		}
	}

	target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		_, _ = stream.Write([]byte{quicStatusUnreachable})
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	if _, err := stream.Write([]byte{quicStatusOK}); err != nil {
		return
	}

	pipeQUICStreamAndTCP(stream, target, tc.SpeedLimitMBps)
}

func pipeQUICStreamAndTCP(stream *quic.Stream, tcpConn net.Conn, speedLimitMBps string) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	toStream := newThrottledWriter(stream, &appTxBytes, mbLimit)
	toTCP := newThrottledWriter(tcpConn, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	// TCP -> QUIC Stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toStream, tcpConn, buf)
		_ = stream.Close() // Sends QUIC FIN on write direction
	}()

	// QUIC Stream -> TCP
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toTCP, stream, buf)
		if tc, ok := tcpConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
	stream.CancelRead(0)
	stream.CancelWrite(0)
}

// ============================================================================
// ENGINE 2: RFC 9221 QUIC DATAGRAM BIDIRECTIONAL UDP SESSION MANAGER
// ============================================================================

type quicFragReassemblyEntry struct {
	sessionID uint32
	port      uint16
	total     int
	received  int
	byteSize  int
	createdAt time.Time
	chunks    [][]byte
}

type quicDatagramReassembler struct {
	mu           sync.Mutex
	entries      map[uint64]*quicFragReassemblyEntry
	currentBytes int
}

func newQUICDatagramReassembler() *quicDatagramReassembler {
	return &quicDatagramReassembler{
		entries: make(map[uint64]*quicFragReassemblyEntry),
	}
}

func (r *quicDatagramReassembler) insertFragment(
	sessionID uint32,
	targetPort uint16,
	fragID uint16,
	fragIndex byte,
	fragTotal byte,
	payload []byte,
) ([]byte, bool) {
	if fragTotal == 0 || fragTotal > quicMaxFragmentsPerDatagram || fragIndex >= fragTotal {
		return nil, false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for k, ent := range r.entries {
		if now.Sub(ent.createdAt) > quicReassemblyTTL {
			r.currentBytes -= ent.byteSize
			delete(r.entries, k)
		}
	}

	key := (uint64(sessionID) << 16) | uint64(fragID)
	ent, exists := r.entries[key]
	if !exists {
		if r.currentBytes+len(payload) > quicMaxReassemblyBytes {
			return nil, false
		}
		ent = &quicFragReassemblyEntry{
			sessionID: sessionID,
			port:      targetPort,
			total:     int(fragTotal),
			createdAt: now,
			chunks:    make([][]byte, int(fragTotal)),
		}
		r.entries[key] = ent
	}

	if ent.chunks[fragIndex] != nil {
		return nil, false
	}
	if ent.byteSize+len(payload) > quicMaxOriginalDatagramSize || r.currentBytes+len(payload) > quicMaxReassemblyBytes {
		r.currentBytes -= ent.byteSize
		delete(r.entries, key)
		return nil, false
	}

	chunkCopy := make([]byte, len(payload))
	copy(chunkCopy, payload)
	ent.chunks[fragIndex] = chunkCopy
	ent.byteSize += len(chunkCopy)
	ent.received++
	r.currentBytes += len(chunkCopy)

	if ent.received < ent.total {
		return nil, false
	}

	assembled := make([]byte, 0, ent.byteSize)
	for _, c := range ent.chunks {
		assembled = append(assembled, c...)
	}
	r.currentBytes -= ent.byteSize
	delete(r.entries, key)
	return assembled, true
}

func encodeQUICRawDatagram(sessionID uint32, targetPort uint16, payload []byte) []byte {
	frame := make([]byte, quicDatagramRawHeaderSize+len(payload))
	frame[0] = quicDatagramFlagRaw
	binary.BigEndian.PutUint32(frame[1:5], sessionID)
	binary.BigEndian.PutUint16(frame[5:7], targetPort)
	copy(frame[7:], payload)
	return frame
}

var nextQUICFragID atomic.Uint32

func sendQUICUDPDatagram(conn *quic.Conn, maxPayloadHint *atomic.Int64, sessionID uint32, targetPort uint16, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	maxTotal := int(maxPayloadHint.Load())
	if maxTotal <= quicDatagramRawHeaderSize+64 {
		maxTotal = quicDefaultMaxDatagramPayload
	}

	if len(payload)+quicDatagramRawHeaderSize <= maxTotal {
		frame := encodeQUICRawDatagram(sessionID, targetPort, payload)
		err := conn.SendDatagram(frame)
		if err == nil {
			return nil
		}
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) && tooLarge.MaxDatagramPayloadSize > quicDatagramFragHeaderSize+64 {
			maxPayloadHint.Store(tooLarge.MaxDatagramPayloadSize)
			maxTotal = int(tooLarge.MaxDatagramPayloadSize)
		} else {
			return err
		}
	}

	if !quicAllowDatagramFragmentation.Load() {
		return ErrQUICDatagramTooLarge
	}

	if len(payload) > quicMaxOriginalDatagramSize {
		return ErrQUICDatagramTooLarge
	}
	chunkCap := maxTotal - quicDatagramFragHeaderSize
	if chunkCap < 128 {
		return ErrQUICDatagramTooLarge
	}
	totalFrags := (len(payload) + chunkCap - 1) / chunkCap
	if totalFrags > quicMaxFragmentsPerDatagram {
		return ErrQUICDatagramTooLarge
	}

	fragID := uint16(nextQUICFragID.Add(1))
	for idx := 0; idx < totalFrags; idx++ {
		start := idx * chunkCap
		end := start + chunkCap
		if end > len(payload) {
			end = len(payload)
		}
		part := payload[start:end]
		frame := make([]byte, quicDatagramFragHeaderSize+len(part))
		frame[0] = quicDatagramFlagFragment
		binary.BigEndian.PutUint32(frame[1:5], sessionID)
		binary.BigEndian.PutUint16(frame[5:7], targetPort)
		binary.BigEndian.PutUint16(frame[7:9], fragID)
		frame[9] = byte(idx)
		frame[10] = byte(totalFrags)
		copy(frame[11:], part)

		if err := conn.SendDatagram(frame); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) && tooLarge.MaxDatagramPayloadSize > quicDatagramFragHeaderSize+64 {
				maxPayloadHint.Store(tooLarge.MaxDatagramPayloadSize)
			}
			return err
		}
	}
	return nil
}

// Entry-Side UDP Session Manager
type quicUDPEntrySession struct {
	sessionID    uint32
	clientAddr   *net.UDPAddr
	entryConn    *net.UDPConn
	targetPort   uint16
	lastActivity atomic.Int64
}

type quicUDPEntrySessionManager struct {
	mu          sync.RWMutex
	peer        ServerPeer
	tunnel      TunnelConfig
	byAddr      map[string]*quicUDPEntrySession
	bySessionID map[uint32]*quicUDPEntrySession
	nextID      atomic.Uint32
	reassembler *quicDatagramReassembler
	limiter     io.Writer
	stopCh      chan struct{}
	closed      atomic.Bool
}

func newQUICUDPEntrySessionManager(peer ServerPeer, tc TunnelConfig) *quicUDPEntrySessionManager {
	mgr := &quicUDPEntrySessionManager{
		peer:        peer,
		tunnel:      tc,
		byAddr:      make(map[string]*quicUDPEntrySession),
		bySessionID: make(map[uint32]*quicUDPEntrySession),
		reassembler: newQUICDatagramReassembler(),
		limiter:     newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(tc.SpeedLimitMBps)),
		stopCh:      make(chan struct{}),
	}
	go mgr.janitorLoop()
	return mgr
}

func (m *quicUDPEntrySessionManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			now := time.Now().Unix()
			cutoff := now - int64(quicUDPSessionIdleTTL.Seconds())
			m.mu.Lock()
			for addrKey, sess := range m.byAddr {
				if sess.lastActivity.Load() < cutoff {
					delete(m.byAddr, addrKey)
					delete(m.bySessionID, sess.sessionID)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *quicUDPEntrySessionManager) closeAll() {
	if m.closed.Swap(true) {
		return
	}
	close(m.stopCh)
	m.mu.Lock()
	m.byAddr = make(map[string]*quicUDPEntrySession)
	m.bySessionID = make(map[uint32]*quicUDPEntrySession)
	m.mu.Unlock()
}

func (m *quicUDPEntrySessionManager) getOrCreateSession(
	entryConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	targetPort uint16,
) (*quicUDPEntrySession, error) {
	addrKey := fmt.Sprintf("%s->%d", clientAddr.String(), targetPort)
	now := time.Now().Unix()

	m.mu.RLock()
	if sess, ok := m.byAddr[addrKey]; ok {
		sess.lastActivity.Store(now)
		m.mu.RUnlock()
		return sess, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	if sess, ok := m.byAddr[addrKey]; ok {
		sess.lastActivity.Store(now)
		return sess, nil
	}
	if len(m.bySessionID) >= quicMaxUDPSessionsPerPeer {
		return nil, ErrQUICSessionLimit
	}

	var sid uint32
	for {
		sid = m.nextID.Add(1)
		if sid == 0 {
			continue
		}
		if _, exists := m.bySessionID[sid]; !exists {
			break
		}
	}

	addrCopy := &net.UDPAddr{
		IP:   append([]byte(nil), clientAddr.IP...),
		Port: clientAddr.Port,
		Zone: clientAddr.Zone,
	}
	sess := &quicUDPEntrySession{
		sessionID:  sid,
		clientAddr: addrCopy,
		entryConn:  entryConn,
		targetPort: targetPort,
	}
	sess.lastActivity.Store(now)
	m.byAddr[addrKey] = sess
	m.bySessionID[sid] = sess
	return sess, nil
}

func (m *quicUDPEntrySessionManager) ensureDataConnUDPAuthed(conn *quic.Conn, mc *quicManagedClientConn) bool {
	if mc.udpAuthed.Load() {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return false
	}
	defer func() {
		_ = stream.Close()
		stream.CancelRead(0)
	}()

	hs, err := buildSignedHandshake(quicStreamTypeUDPAuth, m.peer, "udp")
	if err != nil {
		return false
	}
	_ = stream.SetDeadline(time.Now().Add(4 * time.Second))
	if err := writeQUICHandshake(stream, hs); err != nil {
		return false
	}
	var status [1]byte
	if _, err := io.ReadFull(stream, status[:]); err != nil || status[0] != quicStatusOK {
		return false
	}
	mc.udpAuthed.Store(true)
	return true
}

func (m *quicUDPEntrySessionManager) handleOutboundClientPacket(
	entryConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	targetPort uint16,
	payload []byte,
) error {
	sess, err := m.getOrCreateSession(entryConn, clientAddr, targetPort)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	conn, mc, err := getOrDialQUICConnection(ctx, m.peer, m.tunnel, "data", m)
	cancel()
	if err != nil {
		return err
	}

	if !m.ensureDataConnUDPAuthed(conn, mc) {
		return ErrQUICUnauthorizedPeer
	}

	_, _ = m.limiter.Write(payload)
	return sendQUICUDPDatagram(conn, &mc.maxDatagramBytes, sess.sessionID, targetPort, payload)
}

func (m *quicUDPEntrySessionManager) handleInboundReplyDatagram(raw []byte) {
	if len(raw) < quicDatagramRawHeaderSize {
		return
	}
	flag := raw[0]
	sessionID := binary.BigEndian.Uint32(raw[1:5])
	targetPort := binary.BigEndian.Uint16(raw[5:7])

	var payload []byte
	switch flag {
	case quicDatagramFlagRaw:
		payload = raw[quicDatagramRawHeaderSize:]
	case quicDatagramFlagFragment:
		if len(raw) < quicDatagramFragHeaderSize {
			return
		}
		fragID := binary.BigEndian.Uint16(raw[7:9])
		fragIdx := raw[9]
		fragTotal := raw[10]
		assembled, ok := m.reassembler.insertFragment(sessionID, targetPort, fragID, fragIdx, fragTotal, raw[quicDatagramFragHeaderSize:])
		if !ok {
			return
		}
		payload = assembled
	case quicDatagramFlagClose:
		m.mu.Lock()
		if sess, ok := m.bySessionID[sessionID]; ok {
			delete(m.byAddr, fmt.Sprintf("%s->%d", sess.clientAddr.String(), sess.targetPort))
			delete(m.bySessionID, sessionID)
		}
		m.mu.Unlock()
		return
	default:
		return
	}

	m.mu.RLock()
	sess, ok := m.bySessionID[sessionID]
	m.mu.RUnlock()
	if !ok || len(payload) == 0 {
		return
	}

	sess.lastActivity.Store(time.Now().Unix())
	atomic.AddUint64(&appRxBytes, uint64(len(payload)))
	_, _ = sess.entryConn.WriteToUDP(payload, sess.clientAddr)
}

// Exit-Side Persistent UDP Socket Session Manager
type quicUDPExitSession struct {
	sessionID    uint32
	targetPort   uint16
	localConn    *net.UDPConn
	quicConn     *quic.Conn
	lastActivity atomic.Int64
	closed       atomic.Bool
}

type quicUDPExitSessionManager struct {
	mu               sync.RWMutex
	sessions         map[uint32]*quicUDPExitSession
	reassembler      *quicDatagramReassembler
	maxDatagramBytes atomic.Int64
	limiter          io.Writer
	stopCh           chan struct{}
	closed           atomic.Bool
}

func newQUICUDPExitSessionManager(speedLimitMBps string) *quicUDPExitSessionManager {
	mgr := &quicUDPExitSessionManager{
		sessions:    make(map[uint32]*quicUDPExitSession),
		reassembler: newQUICDatagramReassembler(),
		limiter:     newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(speedLimitMBps)),
		stopCh:      make(chan struct{}),
	}
	mgr.maxDatagramBytes.Store(quicDefaultMaxDatagramPayload)
	go mgr.janitorLoop()
	return mgr
}

func (m *quicUDPExitSessionManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			now := time.Now().Unix()
			cutoff := now - int64(quicUDPSessionIdleTTL.Seconds())
			m.mu.Lock()
			for sid, sess := range m.sessions {
				if sess.lastActivity.Load() < cutoff || sess.quicConn.Context().Err() != nil {
					sess.close()
					delete(m.sessions, sid)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (s *quicUDPExitSession) close() {
	if s.closed.Swap(true) {
		return
	}
	if s.localConn != nil {
		_ = s.localConn.Close()
	}
}

func (m *quicUDPExitSessionManager) closeAll() {
	if m.closed.Swap(true) {
		return
	}
	close(m.stopCh)
	m.mu.Lock()
	for sid, sess := range m.sessions {
		sess.close()
		delete(m.sessions, sid)
	}
	m.mu.Unlock()
}

func (m *quicUDPExitSessionManager) handleIncomingDatagram(conn *quic.Conn, tc TunnelConfig, raw []byte) {
	if len(raw) < quicDatagramRawHeaderSize {
		return
	}
	flag := raw[0]
	sessionID := binary.BigEndian.Uint32(raw[1:5])
	targetPort := binary.BigEndian.Uint16(raw[5:7])

	var payload []byte
	switch flag {
	case quicDatagramFlagRaw:
		payload = raw[quicDatagramRawHeaderSize:]
	case quicDatagramFlagFragment:
		if len(raw) < quicDatagramFragHeaderSize {
			return
		}
		fragID := binary.BigEndian.Uint16(raw[7:9])
		fragIdx := raw[9]
		fragTotal := raw[10]
		assembled, ok := m.reassembler.insertFragment(sessionID, targetPort, fragID, fragIdx, fragTotal, raw[quicDatagramFragHeaderSize:])
		if !ok {
			return
		}
		payload = assembled
	case quicDatagramFlagClose:
		m.mu.Lock()
		if sess, ok := m.sessions[sessionID]; ok {
			sess.close()
			delete(m.sessions, sessionID)
		}
		m.mu.Unlock()
		return
	default:
		return
	}

	if len(payload) == 0 {
		return
	}
	if targetPort == 0 {
		ports := parsePortList(tc.ForwardPorts)
		if len(ports) > 0 {
			if p, err := strconv.Atoi(ports[0]); err == nil {
				targetPort = uint16(p)
			}
		}
		if targetPort == 0 {
			targetPort = 2053
		}
	}

	sess, err := m.getOrCreateExitSession(conn, sessionID, targetPort)
	if err != nil {
		return
	}

	sess.lastActivity.Store(time.Now().Unix())
	atomic.AddUint64(&appRxBytes, uint64(len(payload)))
	_, _ = sess.localConn.Write(payload)
}

func (m *quicUDPExitSessionManager) getOrCreateExitSession(
	conn *quic.Conn,
	sessionID uint32,
	targetPort uint16,
) (*quicUDPExitSession, error) {
	now := time.Now().Unix()

	m.mu.RLock()
	if sess, ok := m.sessions[sessionID]; ok && !sess.closed.Load() {
		sess.lastActivity.Store(now)
		m.mu.RUnlock()
		return sess, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	if sess, ok := m.sessions[sessionID]; ok && !sess.closed.Load() {
		sess.lastActivity.Store(now)
		return sess, nil
	}
	if len(m.sessions) >= quicMaxUDPSessionsPerPeer {
		return nil, ErrQUICSessionLimit
	}

	dstAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(targetPort)}
	localUDP, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		return nil, err
	}
	configureUDPSocketBuffers(localUDP)

	sess := &quicUDPExitSession{
		sessionID:  sessionID,
		targetPort: targetPort,
		localConn:  localUDP,
		quicConn:   conn,
	}
	sess.lastActivity.Store(now)
	m.sessions[sessionID] = sess

	go m.readLocalUDPRepliesLoop(sess)
	return sess, nil
}

func (m *quicUDPExitSessionManager) readLocalUDPRepliesLoop(sess *quicUDPExitSession) {
	defer func() {
		sess.close()
		m.mu.Lock()
		if cur, ok := m.sessions[sess.sessionID]; ok && cur == sess {
			delete(m.sessions, sess.sessionID)
		}
		m.mu.Unlock()
	}()

	buf := make([]byte, quicMaxOriginalDatagramSize)
	for {
		_ = sess.localConn.SetReadDeadline(time.Now().Add(quicUDPSessionIdleTTL))
		n, err := sess.localConn.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			sess.lastActivity.Store(time.Now().Unix())
			_, _ = m.limiter.Write(buf[:n])
			_ = sendQUICUDPDatagram(sess.quicConn, &m.maxDatagramBytes, sess.sessionID, sess.targetPort, buf[:n])
		}
	}
}

func startQUICUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
	return startQUICUDPEntryForwarderWithDest(peer, tc, targetPort, targetPort)
}

func startQUICUDPEntryForwarderWithDest(peer ServerPeer, tc TunnelConfig, listenPortStr, destPortStr string) net.PacketConn {
	listenPortNum, err := strconv.Atoi(strings.TrimSpace(listenPortStr))
	if err != nil || listenPortNum < 1 || listenPortNum > 65535 {
		return nil
	}
	destPortNum, err := strconv.Atoi(strings.TrimSpace(destPortStr))
	if err != nil || destPortNum < 1 || destPortNum > 65535 {
		return nil
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:"+strconv.Itoa(listenPortNum))
	if err != nil {
		return nil
	}
	entryConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil
	}
	configureUDPSocketBuffers(entryConn)

	muxKey := fmt.Sprintf("%s|%d", peer.ID, listenPortNum)
	quicRegistryMu.Lock()
	if oldMux, ok := quicEntryUDPMuxes[muxKey]; ok {
		oldMux.closeAll()
	}
	entryMux := newQUICUDPEntrySessionManager(peer, tc)
	quicEntryUDPMuxes[muxKey] = entryMux
	quicRegistryMu.Unlock()

	go func(uDestPort uint16, mgr *quicUDPEntrySessionManager) {
		defer mgr.closeAll()
		for {
			bufPtr := quicBufPool.Get().(*[]byte)
			buf := *bufPtr
			n, clientAddr, rErr := entryConn.ReadFromUDP(buf)
			if rErr != nil {
				quicBufPool.Put(bufPtr)
				return
			}
			if n > 0 {
				_ = mgr.handleOutboundClientPacket(entryConn, clientAddr, uDestPort, buf[:n])
			}
			quicBufPool.Put(bufPtr)
		}
	}(uint16(destPortNum), entryMux)

	return entryConn
}
