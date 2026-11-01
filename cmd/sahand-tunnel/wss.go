package main

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	wssReadBufferSize      = 32 * 1024
	wssWriteBufferSize     = 32 * 1024
	wssStreamChunkSize     = 32 * 1024
	wssMaxIncomingMsgBytes = 512 * 1024

	wssHandshakeTimeout    = 6 * time.Second
	wssWriteTimeout        = 15 * time.Second
	wssDefaultPingInterval = 25 * time.Second
	wssCloseGraceTimeout   = 3 * time.Second
)

var (
	wssUpgrader = websocket.Upgrader{
		ReadBufferSize:    wssReadBufferSize,
		WriteBufferSize:   wssWriteBufferSize,
		EnableCompression: false,
		CheckOrigin: func(_ *http.Request) bool {
			return true
		},
	}

	wssServersMu     sync.Mutex
	wssActiveServers = make(map[string][]*http.Server)
)

func stopWSSPeerResources(peerID string) {
	wssServersMu.Lock()
	servers, ok := wssActiveServers[peerID]
	if ok {
		delete(wssActiveServers, peerID)
	}
	wssServersMu.Unlock()

	for _, srv := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
		_ = srv.Close()
	}
}

func normalizeWSSPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "/ws"
	}
	if !strings.HasPrefix(trimmed, "/") {
		return "/" + trimmed
	}
	return trimmed
}

func normalizeWSSSNI(raw string) string {
	sni := strings.TrimSpace(raw)
	if sni == "" {
		return "www.speedtest.net"
	}
	return sni
}

func resolveWSSPingTiming(tc TunnelConfig) (pingInterval time.Duration, pongTimeout time.Duration) {
	pingInterval = wssDefaultPingInterval
	if tc.HeartbeatSec > 0 {
		hb := time.Duration(tc.HeartbeatSec) * time.Second
		if hb < 5*time.Second {
			hb = 5 * time.Second
		} else if hb > 60*time.Second {
			hb = 60 * time.Second
		}
		pingInterval = hb
	}
	pongTimeout = pingInterval*2 + 10*time.Second
	return pingInterval, pongTimeout
}

func parseExpectedPinBytes(rawPin string) ([]byte, error) {
	clean := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(rawPin, ":", "")))
	if clean == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(clean)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("invalid certificate pin format (expected 64 hex chars)")
	}
	return decoded, nil
}

func verifyWSSPinnedCertificate(rawCerts [][]byte, expectedPinBytes []byte, sni string) error {
	if len(rawCerts) == 0 {
		return errors.New("no peer certificate presented")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("invalid peer leaf certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return errors.New("peer certificate is expired or not yet valid")
	}
	if len(expectedPinBytes) != sha256.Size {
		return errors.New("certificate pin is not configured")
	}
	actualSum := sha256.Sum256(rawCerts[0])
	if subtle.ConstantTimeCompare(actualSum[:], expectedPinBytes) != 1 {
		return errors.New("certificate pin mismatch")
	}
	// If the certificate does not use the default self-signed placeholder CN, enforce hostname match when SNI is set.
	if sni != "" && len(leaf.DNSNames) > 0 && leaf.Subject.CommonName != "www.speedtest.net" {
		if err := leaf.VerifyHostname(sni); err != nil {
			return fmt.Errorf("certificate hostname mismatch: %w", err)
		}
	}
	return nil
}

func buildWSSRootCAPool() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	stateMu.RLock()
	certPEM := appCfg.TLSCertPEM
	localRaw := localCert.Certificate
	stateMu.RUnlock()

	if certPEM != "" {
		_ = pool.AppendCertsFromPEM([]byte(certPEM))
	}
	for _, der := range localRaw {
		if cert, err := x509.ParseCertificate(der); err == nil {
			pool.AddCert(cert)
		}
	}
	return pool
}

// Builds the TLS client configuration for RFC 6455 WSS over HTTP/1.1.
// - Forces ALPN NextProtos to ["http/1.1"] so HTTP/2 is never negotiated.
// - When no pin is configured, uses standard X.509 chain and hostname verification (InsecureSkipVerify: false).
// - When a pin is configured (tc.CertPin or peer.RemoteCertPin), validates the SHA-256 pin in constant time.
func buildWSSClientTLSConfig(peer ServerPeer, tc TunnelConfig) (*tls.Config, error) {
	sni := normalizeWSSSNI(tc.SNI)
	rawPin := strings.TrimSpace(tc.CertPin)
	if rawPin == "" {
		rawPin = strings.TrimSpace(peer.RemoteCertPin)
	}

	expectedPinBytes, err := parseExpectedPinBytes(rawPin)
	if err != nil {
		return nil, err
	}

	rootPool := buildWSSRootCAPool()

	if len(expectedPinBytes) == 0 {
		return &tls.Config{
			ServerName:         sni,
			RootCAs:            rootPool,
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		}, nil
	}

	return &tls.Config{
		ServerName:         sni,
		RootCAs:            rootPool,
		InsecureSkipVerify: true, // Custom VerifyConnection enforces cryptographic SHA-256 certificate pinning
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyWSSPinnedCertificate(rawCerts, expectedPinBytes, sni)
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != "" && cs.NegotiatedProtocol != "http/1.1" {
				return fmt.Errorf("unexpected ALPN protocol %q for RFC 6455 websocket", cs.NegotiatedProtocol)
			}
			rawCerts := make([][]byte, 0, len(cs.PeerCertificates))
			for _, cert := range cs.PeerCertificates {
				rawCerts = append(rawCerts, cert.Raw)
			}
			return verifyWSSPinnedCertificate(rawCerts, expectedPinBytes, sni)
		},
	}, nil
}

func buildWSSServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{localCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
}

func buildWSSURL(host string, port int, wsPath string) string {
	u := url.URL{
		Scheme: "wss",
		Host:   net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port)),
		Path:   normalizeWSSPath(wsPath),
	}
	return u.String()
}

func newWSSClientDialer(peer ServerPeer, tc TunnelConfig, timeout time.Duration) (*websocket.Dialer, error) {
	tlsCfg, err := buildWSSClientTLSConfig(peer, tc)
	if err != nil {
		return nil, err
	}
	netDialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 20 * time.Second,
	}
	return &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := netDialer.DialContext(ctx, network, addr)
			if err == nil {
				enableKeepAlive(c)
			}
			return c, err
		},
		TLSClientConfig:   tlsCfg,
		HandshakeTimeout:  timeout,
		ReadBufferSize:    wssReadBufferSize,
		WriteBufferSize:   wssWriteBufferSize,
		EnableCompression: false,
	}, nil
}

// ============================================================================
// THREAD-SAFE RFC 6455 WEBSOCKET CONNECTION & BIDIRECTIONAL TCP STREAM BRIDGE
// ============================================================================

type wssSafeConn struct {
	conn      *websocket.Conn
	writeMu   sync.Mutex
	closeOnce sync.Once
	closed    atomic.Bool
}

func newWSSSafeConn(conn *websocket.Conn) *wssSafeConn {
	return &wssSafeConn{conn: conn}
}

func (w *wssSafeConn) writeBinary(payload []byte, timeout time.Duration) error {
	if w.closed.Load() {
		return net.ErrClosed
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if w.closed.Load() {
		return net.ErrClosed
	}
	_ = w.conn.SetWriteDeadline(time.Now().Add(timeout))
	err := w.conn.WriteMessage(websocket.BinaryMessage, payload)
	_ = w.conn.SetWriteDeadline(time.Time{})
	return err
}

func (w *wssSafeConn) writePing(payload []byte, timeout time.Duration) error {
	if w.closed.Load() {
		return net.ErrClosed
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if w.closed.Load() {
		return net.ErrClosed
	}
	return w.conn.WriteControl(websocket.PingMessage, payload, time.Now().Add(timeout))
}

func (w *wssSafeConn) writePong(payload []byte, timeout time.Duration) error {
	if w.closed.Load() {
		return net.ErrClosed
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if w.closed.Load() {
		return net.ErrClosed
	}
	return w.conn.WriteControl(websocket.PongMessage, payload, time.Now().Add(timeout))
}

func (w *wssSafeConn) writeCloseFrame(closeCode int, text string) {
	w.closeOnce.Do(func() {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()
		msg := websocket.FormatCloseMessage(closeCode, text)
		_ = w.conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(wssCloseGraceTimeout))
	})
}

func (w *wssSafeConn) closeRaw() {
	w.closed.Store(true)
	_ = w.conn.Close()
}

// Bridges a continuous bidirectional TCP byte stream (`tcpConn`) and an RFC 6455
// WebSocket connection (`wsConn`) using binary frames, periodic Ping/Pong control
// frames, read/write deadlines, speed throttling, and clean shutdown semantics.
func bridgeWSSAndTCP(
	wsConn *websocket.Conn,
	tcpConn net.Conn,
	tc TunnelConfig,
	onHealthyPing func(),
) {
	safeWS := newWSSSafeConn(wsConn)
	pingInterval, pongTimeout := resolveWSSPingTiming(tc)

	wsConn.SetReadLimit(wssMaxIncomingMsgBytes)
	_ = wsConn.SetReadDeadline(time.Now().Add(pongTimeout))

	wsConn.SetPongHandler(func(_ string) error {
		if onHealthyPing != nil {
			onHealthyPing()
		}
		return wsConn.SetReadDeadline(time.Now().Add(pongTimeout))
	})

	wsConn.SetPingHandler(func(appData string) error {
		if onHealthyPing != nil {
			onHealthyPing()
		}
		_ = wsConn.SetReadDeadline(time.Now().Add(pongTimeout))
		return safeWS.writePong([]byte(appData), wssWriteTimeout)
	})

	doneCh := make(chan struct{})
	var shutdownOnce sync.Once
	shutdownBridge := func() {
		shutdownOnce.Do(func() {
			close(doneCh)
			safeWS.closeRaw()
			_ = tcpConn.Close()
		})
	}
	defer shutdownBridge()

	mbLimit := parseSpeedLimit(tc.SpeedLimitMBps)
	txLimiter := newThrottledWriter(io.Discard, &appTxBytes, mbLimit)
	toTCPWriter := newThrottledWriter(tcpConn, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(3)

	// 1. WebSocket Control-Frame Keepalive (Periodic Ping -> Pong timeout detection)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()

		var seq uint32
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				seq++
				var pingPayload [8]byte
				binary.BigEndian.PutUint32(pingPayload[0:4], seq)
				binary.BigEndian.PutUint32(pingPayload[4:8], uint32(time.Now().Unix()))
				if err := safeWS.writePing(pingPayload[:], wssWriteTimeout); err != nil {
					shutdownBridge()
					return
				}
			}
		}
	}()

	// 2. TCP -> WebSocket Binary Messages
	go func() {
		defer wg.Done()
		buf := make([]byte, wssStreamChunkSize)
		for {
			n, rErr := tcpConn.Read(buf)
			if n > 0 {
				_, _ = txLimiter.Write(buf[:n])
				if wErr := safeWS.writeBinary(buf[:n], wssWriteTimeout); wErr != nil {
					shutdownBridge()
					return
				}
			}
			if rErr != nil {
				if errors.Is(rErr, io.EOF) {
					safeWS.writeCloseFrame(websocket.CloseNormalClosure, "")
				} else {
					safeWS.writeCloseFrame(websocket.CloseInternalServerErr, "")
				}
				shutdownBridge()
				return
			}
		}
	}()

	// 3. WebSocket Binary Messages -> TCP
	go func() {
		defer wg.Done()
		copyBuf := make([]byte, wssStreamChunkSize)
		for {
			msgType, reader, rErr := wsConn.NextReader()
			if rErr != nil {
				shutdownBridge()
				return
			}
			_ = wsConn.SetReadDeadline(time.Now().Add(pongTimeout))

			if msgType != websocket.BinaryMessage {
				safeWS.writeCloseFrame(websocket.CloseUnsupportedData, "binary messages required")
				shutdownBridge()
				return
			}

			if _, wErr := io.CopyBuffer(toTCPWriter, reader, copyBuf); wErr != nil {
				safeWS.writeCloseFrame(websocket.CloseInternalServerErr, "")
				shutdownBridge()
				return
			}
		}
	}()

	wg.Wait()
}

// ============================================================================
// AGENT-SIDE RFC 6455 WEBSOCKET SERVER & UPGRADER (:28001)
// ============================================================================

func startWSSServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	tlsCfg := buildWSSServerTLSConfig()

	ln, err := tls.Listen("tcp", listenAddr, tlsCfg)
	if err != nil {
		return nil, err
	}

	handler := &wssServerHandler{
		peer:   peer,
		tunnel: tc,
	}

	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	wssServersMu.Lock()
	wssActiveServers[peer.ID] = append(wssActiveServers[peer.ID], httpSrv)
	wssServersMu.Unlock()

	go func() {
		_ = httpSrv.Serve(ln)
	}()

	return ln, nil
}

type wssServerHandler struct {
	peer   ServerPeer
	tunnel TunnelConfig
}

func (h *wssServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if timeHdr := strings.TrimSpace(r.Header.Get("X-Sahand-Time")); timeHdr != "" {
		applyMasterTimeHeader(timeHdr)
	}

	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	effectivePeerID := h.peer.ID
	if peerHdr := strings.TrimSpace(r.Header.Get("X-Sahand-Peer")); peerHdr != "" {
		effectivePeerID = peerHdr
	}

	// Engine 1: Parity Sync over HTTPS on the WSS port
	if syncB64 := strings.TrimSpace(r.Header.Get("X-Sahand-Sync")); syncB64 != "" {
		handleWSSParitySyncHTTP(w, effectivePeerID, remoteHost, syncB64)
		return
	}

	// Validate configured WSS path
	expectedPath := normalizeWSSPath(h.tunnel.WSPath)
	reqPath := normalizeWSSPath(r.URL.Path)
	if reqPath != expectedPath && r.URL.Path != "/" {
		http.Error(w, "invalid websocket path", http.StatusNotFound)
		return
	}

	targetPort := strings.TrimSpace(r.Header.Get("X-Target-Port"))

	// Engine 1: Genuine RFC 6455 WebSocket Probe
	if strings.HasPrefix(targetPort, "probe:") {
		handleWSSProbeUpgrade(w, r, h.peer, h.tunnel, effectivePeerID, remoteHost)
		return
	}

	// Engine 2: Actual Traffic Forwarding
	handleWSSIncomingTraffic(w, r, h.peer, h.tunnel, effectivePeerID, remoteHost, targetPort)
}

func handleWSSParitySyncHTTP(w http.ResponseWriter, effectivePeerID, remoteHost, syncPayloadB64 string) {
	raw, err := base64.StdEncoding.DecodeString(syncPayloadB64)
	if err != nil {
		http.Error(w, "invalid sync encoding", http.StatusBadRequest)
		return
	}
	var pkt SyncPacket
	if err := json.Unmarshal(raw, &pkt); err != nil {
		http.Error(w, "invalid sync payload", http.StatusBadRequest)
		return
	}
	resp := processIncomingSync(effectivePeerID, remoteHost, pkt)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func handleWSSProbeUpgrade(
	w http.ResponseWriter,
	r *http.Request,
	_ ServerPeer,
	tc TunnelConfig,
	effectivePeerID string,
	remoteHost string,
) {
	wsConn, err := wssUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer wsConn.Close()

	wsConn.SetReadLimit(4096)
	_ = wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_ = wsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	msgType, payload, err := wsConn.ReadMessage()
	if err != nil || msgType != websocket.BinaryMessage || len(payload) == 0 {
		return
	}

	if err := wsConn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		return
	}

	markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)

	closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	_ = wsConn.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(2*time.Second))
}

func handleWSSIncomingTraffic(
	w http.ResponseWriter,
	r *http.Request,
	_ ServerPeer,
	tc TunnelConfig,
	effectivePeerID string,
	remoteHost string,
	targetPort string,
) {
	if !tc.Enabled {
		http.Error(w, "traffic tunnel disabled", http.StatusForbidden)
		return
	}

	if targetPort == "" {
		ports := parsePortList(tc.ForwardPorts)
		if len(ports) > 0 {
			targetPort = ports[0]
		} else {
			targetPort = strconv.Itoa(32000 + tc.ID)
		}
	}
	if portNum, err := strconv.Atoi(targetPort); err != nil || portNum < 1 || portNum > 65535 {
		http.Error(w, "invalid target port", http.StatusBadRequest)
		return
	}

	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", targetPort), 5*time.Second)
	if err != nil {
		http.Error(w, "target service unreachable", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	enableKeepAlive(targetConn)

	respHdr := http.Header{}
	respHdr.Set("X-Sahand-Target", targetPort)

	wsConn, err := wssUpgrader.Upgrade(w, r, respHdr)
	if err != nil {
		return
	}
	defer wsConn.Close()

	if netConn := wsConn.UnderlyingConn(); netConn != nil {
		enableKeepAlive(netConn)
	}

	markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)

	bridgeWSSAndTCP(wsConn, targetConn, tc, func() {
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)
	})
}

// ============================================================================
// MASTER-SIDE RFC 6455 WEBSOCKET CLIENT & PROBE
// ============================================================================

func classifyWSSError(err error, resp *http.Response) string {
	if resp != nil {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "Authentication failure"
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			return "Protocol mismatch"
		}
	}
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return "Timeout"
	case strings.Contains(msg, "certificate") || strings.Contains(msg, "pin") || strings.Contains(msg, "tls") || strings.Contains(msg, "x509"):
		return "TLS failure"
	case strings.Contains(msg, "handshake") || strings.Contains(msg, "websocket") || strings.Contains(msg, "alpn"):
		return "Protocol mismatch"
	default:
		return "Port unreachable"
	}
}

func probeWSS(peer ServerPeer, tc TunnelConfig, localNodeID string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	dialer, err := newWSSClientDialer(peer, tc, 4*time.Second)
	if err != nil {
		res.Success = false
		res.ErrorReason = "TLS failure"
		return res
	}

	sni := normalizeWSSSNI(tc.SNI)
	wsURL := buildWSSURL(peer.IP, tc.ListenPort, tc.WSPath)

	reqHeader := http.Header{}
	reqHeader.Set("Host", sni)
	reqHeader.Set("X-Sahand-Peer", peer.ID)
	reqHeader.Set("X-Sahand-Node", localNodeID)
	reqHeader.Set("X-Sahand-Time", buildMasterTimeHeader())
	reqHeader.Set("X-Target-Port", fmt.Sprintf("probe:%d", tc.ListenPort))

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	start := time.Now()
	wsConn, resp, err := dialer.DialContext(ctx, wsURL, reqHeader)
	if err != nil {
		res.Success = false
		res.ErrorReason = classifyWSSError(err, resp)
		return res
	}
	defer wsConn.Close()

	if resp == nil || resp.StatusCode != http.StatusSwitchingProtocols {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	// Build a 32-byte binary probe frame: [16B prefix][8B random nonce][8B unix nano]
	var probePayload [32]byte
	copy(probePayload[0:16], []byte("SAHAND-WSS-PROBE"))
	_, _ = io.ReadFull(rand.Reader, probePayload[16:24])
	binary.BigEndian.PutUint64(probePayload[24:32], uint64(time.Now().UnixNano()))

	_ = wsConn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := wsConn.WriteMessage(websocket.BinaryMessage, probePayload[:]); err != nil {
		res.Success = false
		res.ErrorReason = classifyWSSError(err, nil)
		return res
	}

	_ = wsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	msgType, reply, err := wsConn.ReadMessage()
	if err != nil || msgType != websocket.BinaryMessage || !bytes.Equal(reply, probePayload[:]) {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	_ = wsConn.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(2*time.Second))

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

func forwardWSSTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	dialer, err := newWSSClientDialer(peer, tc, wssHandshakeTimeout)
	if err != nil {
		return
	}

	if strings.TrimSpace(targetPort) == "" {
		ports := parsePortList(tc.ForwardPorts)
		if len(ports) > 0 {
			targetPort = ports[0]
		} else {
			targetPort = strconv.Itoa(32000 + tc.ID)
		}
	}

	sni := normalizeWSSSNI(tc.SNI)
	wsURL := buildWSSURL(peer.IP, tc.ListenPort, tc.WSPath)

	reqHeader := http.Header{}
	reqHeader.Set("Host", sni)
	reqHeader.Set("X-Sahand-Peer", peer.ID)
	reqHeader.Set("X-Target-Port", targetPort)
	reqHeader.Set("X-Sahand-Time", buildMasterTimeHeader())

	ctx, cancel := context.WithTimeout(context.Background(), wssHandshakeTimeout)
	wsConn, resp, err := dialer.DialContext(ctx, wsURL, reqHeader)
	cancel()
	if err != nil {
		return
	}
	defer wsConn.Close()

	if resp == nil || resp.StatusCode != http.StatusSwitchingProtocols {
		return
	}

	if netConn := wsConn.UnderlyingConn(); netConn != nil {
		enableKeepAlive(netConn)
	}

	bridgeWSSAndTCP(wsConn, client, tc, nil)
}
