package main

import (
	"bytes"
	"context"
	"crypto/hmac"
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

	wssHandshakeTimeout      = 6 * time.Second
	wssWriteTimeout          = 15 * time.Second
	wssDefaultPingInterval   = 25 * time.Second
	wssCloseGraceTimeout     = 3 * time.Second
	wssCloseHandshakeTimeout = 5 * time.Second
	wssAuthSkewWindowSec     = 300
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

// ============================================================================
// PEER AUTHENTICATION, PIN CHANNEL BINDING & TARGET-PORT AUTHORIZATION
// ============================================================================

func computeWSSRequestMAC(authKey []byte, peerID, purpose, tsStr, nonce, clientPin string) string {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-rfc6455-wss-auth-v1:"))
	_, _ = mac.Write([]byte(peerID + "|" + purpose + "|" + tsStr + "|" + nonce + "|" + clientPin))
	return hex.EncodeToString(mac.Sum(nil))
}

func computeWSSResponsePinMAC(authKey []byte, peerID, reqNonce, serverPin string) string {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-rfc6455-wss-resp-pin-v1:"))
	_, _ = mac.Write([]byte(peerID + "|" + reqNonce + "|" + strings.ToLower(strings.TrimSpace(serverPin))))
	return hex.EncodeToString(mac.Sum(nil))
}

func attachWSSAuthHeaders(hdr http.Header, peer ServerPeer, purpose string) error {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return err
	}
	nonce, err := randomHex(8)
	if err != nil {
		return err
	}
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	clientPin := strings.ToLower(strings.TrimSpace(cfgSnapshot.CertPin))
	sig := computeWSSRequestMAC(authKey, peer.ID, purpose, tsStr, nonce, clientPin)

	hdr.Set("X-Sahand-Peer", peer.ID)
	hdr.Set("X-Sahand-TS", tsStr)
	hdr.Set("X-Sahand-Nonce", nonce)
	hdr.Set("X-Sahand-Pin", clientPin)
	hdr.Set("X-Sahand-Auth", sig)
	return nil
}

func saveLearnedRemoteCertPin(peerID, rawPin string) {
	pinBytes, err := parseExpectedPinBytes(rawPin)
	if err != nil || len(pinBytes) != sha256.Size {
		return
	}
	normalizedPin := hex.EncodeToString(pinBytes)

	stateMu.Lock()
	changed := false
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peerID {
			if appCfg.Servers[i].RemoteCertPin != normalizedPin {
				appCfg.Servers[i].RemoteCertPin = normalizedPin
				changed = true
			}
			break
		}
	}
	if changed {
		_ = saveConfig(configPath(), appCfg)
	}
	stateMu.Unlock()
}

func verifyWSSPeerRequest(r *http.Request, expectedPeer ServerPeer, purpose string) error {
	peerHdr := strings.TrimSpace(r.Header.Get("X-Sahand-Peer"))
	if peerHdr == "" || expectedPeer.ID == "" {
		return errors.New("missing peer identity")
	}
	if subtle.ConstantTimeCompare([]byte(peerHdr), []byte(expectedPeer.ID)) != 1 {
		return errors.New("peer identity mismatch")
	}

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, expectedPeer)
	if err != nil {
		return err
	}

	tsStr := strings.TrimSpace(r.Header.Get("X-Sahand-TS"))
	nonce := strings.TrimSpace(r.Header.Get("X-Sahand-Nonce"))
	clientPin := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Sahand-Pin")))
	authSig := strings.TrimSpace(r.Header.Get("X-Sahand-Auth"))
	if tsStr == "" || nonce == "" || authSig == "" {
		return errors.New("missing authentication headers")
	}

	tsSec, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return errors.New("invalid authentication timestamp")
	}
	diff := time.Now().Unix() - tsSec
	if diff < -wssAuthSkewWindowSec || diff > wssAuthSkewWindowSec {
		return errors.New("authentication timestamp out of window")
	}

	expectedSig := computeWSSRequestMAC(authKey, expectedPeer.ID, purpose, tsStr, nonce, clientPin)
	if subtle.ConstantTimeCompare([]byte(authSig), []byte(expectedSig)) != 1 {
		return errors.New("invalid request signature")
	}

	if clientPin != "" {
		saveLearnedRemoteCertPin(expectedPeer.ID, clientPin)
	}
	return nil
}

// Validates that the requested targetPort is explicitly listed in tc.ForwardPorts.
// If requestedPort is empty, selects the first configured port in tc.ForwardPorts.
// Rejects any port not present in tc.ForwardPorts before dialing localhost.
func authorizeWSSTargetPort(tc TunnelConfig, requestedPort string) (string, error) {
	allowedPorts := parsePortList(tc.ForwardPorts)
	if len(allowedPorts) == 0 {
		return "", errors.New("no forwarding ports configured for this tunnel")
	}

	candidate := strings.TrimSpace(requestedPort)
	if candidate == "" {
		candidate = allowedPorts[0]
	}

	portNum, err := strconv.Atoi(candidate)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", errors.New("invalid target port")
	}
	normalizedCandidate := strconv.Itoa(portNum)

	for _, allowed := range allowedPorts {
		if subtle.ConstantTimeCompare([]byte(normalizedCandidate), []byte(allowed)) == 1 {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("target port %s is not authorized for this tunnel", normalizedCandidate)
}

// ============================================================================
// TLS VERIFICATION & CERTIFICATE PINNING
// ============================================================================

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

// Validates the peer leaf certificate's expiration bounds, hostname/SAN identity,
// and cryptographic self-signature (compatible with both IsCA:true and legacy IsCA:false certs).
func verifyWSSLeafIdentityAndValidity(leaf *x509.Certificate, sni string) error {
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return errors.New("peer certificate is not yet valid")
	}
	if now.After(leaf.NotAfter) {
		return errors.New("peer certificate has expired")
	}

	if sni != "" {
		if err := leaf.VerifyHostname(sni); err != nil {
			return fmt.Errorf("certificate hostname mismatch: %w", err)
		}
	}

	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		// Use CheckSignature rather than CheckSignatureFrom so standard self-signed
		// leaf certificates with IsCA:false in existing config.json files are verified
		// cryptographically without failing X.509 CA basic constraint checks.
		if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
			return fmt.Errorf("invalid self-signed certificate signature: %w", err)
		}
	}
	return nil
}

// Explicitly validates the peer's leaf certificate when pinning is configured:
// 1. Parses the X.509 certificate chain.
// 2. Verifies NotBefore and NotAfter expiration bounds.
// 3. Always verifies the certificate's SANs (DNSNames / IPAddresses) against the configured SNI.
// 4. Verifies the cryptographic self-signature if self-issued.
// 5. Verifies the SHA-256 certificate pin in constant time.
func verifyWSSPinnedCertificate(rawCerts [][]byte, expectedPinBytes []byte, sni string) error {
	if len(rawCerts) == 0 {
		return errors.New("no peer certificate presented")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("invalid peer leaf certificate: %w", err)
	}

	if err := verifyWSSLeafIdentityAndValidity(leaf, sni); err != nil {
		return err
	}

	if len(expectedPinBytes) != sha256.Size {
		return errors.New("certificate pin is not configured")
	}
	actualSum := sha256.Sum256(leaf.Raw)
	if subtle.ConstantTimeCompare(actualSum[:], expectedPinBytes) != 1 {
		return errors.New("certificate pin mismatch")
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
	stateMu.RUnlock()

	if certPEM != "" {
		_ = pool.AppendCertsFromPEM([]byte(certPEM))
	}
	return pool
}

// Builds the TLS client configuration for RFC 6455 WSS over HTTP/1.1:
// - Restricts ALPN NextProtos to ["http/1.1"] so HTTP/2 is never negotiated.
// - Unpinned mode: Uses standard X.509 certificate-chain, expiration, and hostname verification (InsecureSkipVerify: false).
// - Pinned mode: Uses verifyWSSPinnedCertificate to enforce expiration, hostname/SAN verification, signature validity, and SHA-256 pinning.
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
			VerifyConnection: func(cs tls.ConnectionState) error {
				if cs.NegotiatedProtocol != "" && cs.NegotiatedProtocol != "http/1.1" {
					return fmt.Errorf("unexpected ALPN protocol %q for RFC 6455 websocket", cs.NegotiatedProtocol)
				}
				return nil
			},
		}, nil
	}

	return &tls.Config{
		ServerName:         sni,
		RootCAs:            rootPool,
		InsecureSkipVerify: true, // Custom VerifyPeerCertificate & VerifyConnection enforce pin + hostname + expiration + signature
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

func isStoredServerPinEmpty(peerID string) bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peerID {
			return strings.TrimSpace(appCfg.Servers[i].RemoteCertPin) == ""
		}
	}
	return false
}

// Performs an HMAC-authenticated, channel-bound certificate pin exchange with the remote peer
// when the Master has not yet learned the Agent's self-signed certificate pin (or when the
// Agent rotated its certificate).
//
// Security properties:
//   - Never overrides an explicit per-tunnel `tc.CertPin`.
//   - Enforces X.509 expiration (`NotBefore` / `NotAfter`), SAN/hostname (`VerifyHostname(sni)`),
//     and cryptographic signature validity during the TLS handshake.
//   - Requires the responder to prove possession of the shared token key (`derivePeerAuthKey`)
//     by returning an HMAC-SHA256 signature (`X-Sahand-Resp-Auth`) over the request nonce and the
//     exact SHA-256 fingerprint of the leaf certificate presented on the TLS connection.
func bootstrapWSSRemoteCertPin(peer *ServerPeer, tc TunnelConfig) bool {
	if peer == nil || strings.TrimSpace(tc.CertPin) != "" {
		return false
	}

	stateMu.RLock()
	cfgSnapshot := appCfg
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, *peer)
	if err != nil {
		return false
	}

	sni := normalizeWSSSNI(tc.SNI)
	var presentedLeafPin atomic.Value

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // VerifyPeerCertificate & VerifyConnection enforce expiration, hostname, signature, and channel binding
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificate presented")
			}
			leaf, pErr := x509.ParseCertificate(rawCerts[0])
			if pErr != nil {
				return pErr
			}
			if vErr := verifyWSSLeafIdentityAndValidity(leaf, sni); vErr != nil {
				return vErr
			}
			sum := sha256.Sum256(leaf.Raw)
			presentedLeafPin.Store(hex.EncodeToString(sum[:]))
			return nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != "" && cs.NegotiatedProtocol != "http/1.1" {
				return fmt.Errorf("unexpected ALPN protocol %q", cs.NegotiatedProtocol)
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate presented")
			}
			return verifyWSSLeafIdentityAndValidity(cs.PeerCertificates[0], sni)
		},
	}

	padLen := 32 + randomIntN(64)
	padHex, _ := randomHex(padLen)

	pkt := SyncPacket{
		Type:          "parity_sync",
		SenderID:      senderID,
		PeerID:        peer.ID,
		MethodID:      tc.ID,
		Port:          tc.ListenPort,
		LatencyMS:     peer.ActiveLatencyMS,
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
	b64 := base64.StdEncoding.EncodeToString(rawPkt)

	syncURL := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort)),
		Path:   normalizeWSSPath(tc.WSPath),
	}

	req, err := http.NewRequest(http.MethodGet, syncURL.String(), nil)
	if err != nil {
		return false
	}
	req.Host = sni
	req.Header.Set("X-Sahand-Time", buildMasterTimeHeader())
	req.Header.Set("X-Sahand-Sync", b64)
	if err := attachWSSAuthHeaders(req.Header, *peer, "sync:"+b64); err != nil {
		return false
	}
	reqNonce := req.Header.Get("X-Sahand-Nonce")

	httpClient := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: false,
			DisableKeepAlives: true,
		},
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	tlsPinStr, _ := presentedLeafPin.Load().(string)
	if tlsPinStr == "" {
		return false
	}

	respPinHdr := strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Sahand-Server-Pin")))
	respAuthHdr := strings.TrimSpace(resp.Header.Get("X-Sahand-Resp-Auth"))
	if respPinHdr == "" || respAuthHdr == "" {
		return false
	}

	// 1. Verify HMAC-SHA256 proof that the remote server possesses authKey for respPinHdr
	expectedRespMAC := computeWSSResponsePinMAC(authKey, peer.ID, reqNonce, respPinHdr)
	if subtle.ConstantTimeCompare([]byte(respAuthHdr), []byte(expectedRespMAC)) != 1 {
		return false
	}

	// 2. Channel binding: verify that the TLS certificate presented on the socket matches respPinHdr
	if subtle.ConstantTimeCompare([]byte(tlsPinStr), []byte(respPinHdr)) != 1 {
		return false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return false
	}
	var syncResp SyncResponse
	if json.Unmarshal(body, &syncResp) != nil || !syncResp.OK {
		return false
	}

	peer.RemoteCertPin = tlsPinStr
	saveLearnedRemoteCertPin(peer.ID, tlsPinStr)
	applySyncResponseToPeer(peer.ID, syncResp)
	return true
}

// ============================================================================
// THREAD-SAFE RFC 6455 WEBSOCKET CONNECTION & BIDIRECTIONAL TCP STREAM BRIDGE
// ============================================================================

type wssSafeConn struct {
	conn      *websocket.Conn
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeSent atomic.Bool
	closed    atomic.Bool
}

func newWSSSafeConn(conn *websocket.Conn) *wssSafeConn {
	return &wssSafeConn{conn: conn}
}

func (w *wssSafeConn) writeBinary(payload []byte, timeout time.Duration) error {
	if w.closed.Load() || w.closeSent.Load() {
		return net.ErrClosed
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if w.closed.Load() || w.closeSent.Load() {
		return net.ErrClosed
	}
	_ = w.conn.SetWriteDeadline(time.Now().Add(timeout))
	err := w.conn.WriteMessage(websocket.BinaryMessage, payload)
	_ = w.conn.SetWriteDeadline(time.Time{})
	return err
}

func (w *wssSafeConn) writePing(payload []byte, timeout time.Duration) error {
	if w.closed.Load() || w.closeSent.Load() {
		return net.ErrClosed
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if w.closed.Load() || w.closeSent.Load() {
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
		w.closeSent.Store(true)
		w.writeMu.Lock()
		defer w.writeMu.Unlock()
		if w.closed.Load() {
			return
		}
		msg := websocket.FormatCloseMessage(closeCode, text)
		_ = w.conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(wssCloseGraceTimeout))
	})
}

func (w *wssSafeConn) closeRaw() {
	w.closed.Store(true)
	_ = w.conn.Close()
}

func closeWriteTCP(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

type wssBridgeOptions struct {
	pingInterval          time.Duration
	pongTimeout           time.Duration
	writeTimeout          time.Duration
	closeHandshakeTimeout time.Duration
	onHealthyPing         func()
}

func defaultWSSBridgeOptions(tc TunnelConfig, onHealthyPing func()) wssBridgeOptions {
	pingInterval, pongTimeout := resolveWSSPingTiming(tc)
	return wssBridgeOptions{
		pingInterval:          pingInterval,
		pongTimeout:           pongTimeout,
		writeTimeout:          wssWriteTimeout,
		closeHandshakeTimeout: wssCloseHandshakeTimeout,
		onHealthyPing:         onHealthyPing,
	}
}

// Bridges a bidirectional TCP stream (`tcpConn`) and an RFC 6455 WebSocket (`wsConn`).
//
// Half-Close & Closing Handshake Semantics:
//   - RFC 6455 Section 5.5.1 / Section 7.1.2 does not provide a separate application half-close frame;
//     once an endpoint sends a Close control frame, it MUST NOT send any more data frames, though it
//     MAY continue to receive data frames until the peer responds with its own Close frame.
//   - When `tcpConn` reaches EOF first (local TCP half-close), `tcpToWS` sends a WebSocket Close frame
//     and waits up to `closeHandshakeTimeout` for `wsToTCP` to finish forwarding any remaining inbound
//     WebSocket BinaryMessages to `tcpConn` and receive the peer's Close response.
//   - When `wsConn` receives a Close frame from the peer first, `SetCloseHandler` / `wsToTCP` performs
//     a TCP half-close (`closeWriteTCP(tcpConn)`) so the local TCP endpoint sees EOF, while `tcpToWS`
//     is given up to `closeHandshakeTimeout` to drain remaining outbound TCP bytes before sending the
//     reply WebSocket Close frame.
func bridgeWSSAndTCP(
	wsConn *websocket.Conn,
	tcpConn net.Conn,
	tc TunnelConfig,
	onHealthyPing func(),
) {
	bridgeWSSAndTCPWithOptions(wsConn, tcpConn, tc, defaultWSSBridgeOptions(tc, onHealthyPing))
}

func bridgeWSSAndTCPWithOptions(
	wsConn *websocket.Conn,
	tcpConn net.Conn,
	tc TunnelConfig,
	opts wssBridgeOptions,
) {
	if opts.pingInterval <= 0 {
		opts.pingInterval = wssDefaultPingInterval
	}
	if opts.pongTimeout <= 0 {
		opts.pongTimeout = opts.pingInterval*2 + 10*time.Second
	}
	if opts.writeTimeout <= 0 {
		opts.writeTimeout = wssWriteTimeout
	}
	if opts.closeHandshakeTimeout <= 0 {
		opts.closeHandshakeTimeout = wssCloseHandshakeTimeout
	}

	safeWS := newWSSSafeConn(wsConn)

	var peerCloseSeen atomic.Bool
	wsToTCPDone := make(chan struct{})
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

	wsConn.SetReadLimit(wssMaxIncomingMsgBytes)
	_ = wsConn.SetReadDeadline(time.Now().Add(opts.pongTimeout))

	wsConn.SetPongHandler(func(_ string) error {
		if opts.onHealthyPing != nil {
			opts.onHealthyPing()
		}
		return wsConn.SetReadDeadline(time.Now().Add(opts.pongTimeout))
	})

	wsConn.SetPingHandler(func(appData string) error {
		if opts.onHealthyPing != nil {
			opts.onHealthyPing()
		}
		_ = wsConn.SetReadDeadline(time.Now().Add(opts.pongTimeout))
		return safeWS.writePong([]byte(appData), opts.writeTimeout)
	})

	wsConn.SetCloseHandler(func(_ int, _ string) error {
		peerCloseSeen.Store(true)
		closeWriteTCP(tcpConn)
		return nil
	})

	mbLimit := parseSpeedLimit(tc.SpeedLimitMBps)
	txLimiter := newThrottledWriter(io.Discard, &appTxBytes, mbLimit)
	toTCPWriter := newThrottledWriter(tcpConn, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(3)

	// 1. WebSocket Control-Frame Keepalive (Periodic Ping -> Pong timeout detection)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(opts.pingInterval)
		defer ticker.Stop()

		var seq uint32
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				if safeWS.closeSent.Load() || peerCloseSeen.Load() {
					return
				}
				seq++
				var pingPayload [8]byte
				binary.BigEndian.PutUint32(pingPayload[0:4], seq)
				binary.BigEndian.PutUint32(pingPayload[4:8], uint32(time.Now().Unix()))
				if err := safeWS.writePing(pingPayload[:], opts.writeTimeout); err != nil {
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
				if wErr := safeWS.writeBinary(buf[:n], opts.writeTimeout); wErr != nil {
					shutdownBridge()
					return
				}
			}
			if rErr != nil {
				if errors.Is(rErr, io.EOF) || peerCloseSeen.Load() {
					safeWS.writeCloseFrame(websocket.CloseNormalClosure, "")
					if !peerCloseSeen.Load() {
						_ = wsConn.SetReadDeadline(time.Now().Add(opts.closeHandshakeTimeout))
					}
					select {
					case <-wsToTCPDone:
					case <-doneCh:
					case <-time.After(opts.closeHandshakeTimeout):
					}
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
		defer func() {
			close(wsToTCPDone)
			wg.Done()
		}()

		copyBuf := make([]byte, wssStreamChunkSize)
		for {
			msgType, reader, rErr := wsConn.NextReader()
			if rErr != nil {
				if peerCloseSeen.Load() || websocket.IsCloseError(
					rErr,
					websocket.CloseNormalClosure,
					websocket.CloseGoingAway,
					websocket.CloseNoStatusReceived,
				) {
					peerCloseSeen.Store(true)
					closeWriteTCP(tcpConn)
					if !safeWS.closeSent.Load() {
						drainTimer := time.AfterFunc(opts.closeHandshakeTimeout, func() {
							_ = tcpConn.SetReadDeadline(time.Now())
						})
						select {
						case <-doneCh:
							drainTimer.Stop()
						case <-time.After(opts.closeHandshakeTimeout + 100*time.Millisecond):
							drainTimer.Stop()
							shutdownBridge()
						}
					}
					return
				}
				shutdownBridge()
				return
			}
			_ = wsConn.SetReadDeadline(time.Now().Add(opts.pongTimeout))

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

func (h *wssServerHandler) attachServerPinResponseHeaders(hOut http.Header, r *http.Request) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	serverPin := strings.ToLower(strings.TrimSpace(appCfg.CertPin))
	stateMu.RUnlock()

	if serverPin == "" {
		return
	}
	authKey, err := derivePeerAuthKey(cfgSnapshot, h.peer)
	if err != nil {
		return
	}
	reqNonce := strings.TrimSpace(r.Header.Get("X-Sahand-Nonce"))
	hOut.Set("X-Sahand-Server-Pin", serverPin)
	hOut.Set("X-Sahand-Resp-Auth", computeWSSResponsePinMAC(authKey, h.peer.ID, reqNonce, serverPin))
}

func (h *wssServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Engine 1: Authenticated Parity Sync over HTTPS on the WSS port
	if syncB64 := strings.TrimSpace(r.Header.Get("X-Sahand-Sync")); syncB64 != "" {
		if err := verifyWSSPeerRequest(r, h.peer, "sync:"+syncB64); err != nil {
			http.Error(w, "unauthorized peer sync request", http.StatusUnauthorized)
			return
		}
		if timeHdr := strings.TrimSpace(r.Header.Get("X-Sahand-Time")); timeHdr != "" {
			applyMasterTimeHeader(timeHdr)
		}
		h.attachServerPinResponseHeaders(w.Header(), r)
		handleWSSParitySyncHTTP(w, h.peer, remoteHost, syncB64)
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

	// Engine 1: Authenticated RFC 6455 WebSocket Probe
	if strings.HasPrefix(targetPort, "probe:") {
		if err := verifyWSSPeerRequest(r, h.peer, "probe:"+targetPort); err != nil {
			http.Error(w, "unauthorized peer probe request", http.StatusUnauthorized)
			return
		}
		if timeHdr := strings.TrimSpace(r.Header.Get("X-Sahand-Time")); timeHdr != "" {
			applyMasterTimeHeader(timeHdr)
		}
		handleWSSProbeUpgrade(w, r, h.peer, h.tunnel, h.peer.ID, remoteHost)
		return
	}

	// Engine 2: Authenticated & Target-Port Authorized Traffic Forwarding
	if err := verifyWSSPeerRequest(r, h.peer, "forward:"+targetPort); err != nil {
		http.Error(w, "unauthorized peer forwarding request", http.StatusUnauthorized)
		return
	}
	if timeHdr := strings.TrimSpace(r.Header.Get("X-Sahand-Time")); timeHdr != "" {
		applyMasterTimeHeader(timeHdr)
	}
	handleWSSIncomingTraffic(w, r, h.peer, h.tunnel, h.peer.ID, remoteHost, targetPort)
}

func handleWSSParitySyncHTTP(w http.ResponseWriter, boundPeer ServerPeer, remoteHost, syncPayloadB64 string) {
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
	if strings.TrimSpace(pkt.SenderID) == "" || subtle.ConstantTimeCompare([]byte(pkt.PeerID), []byte(boundPeer.ID)) != 1 {
		http.Error(w, "forged peer identity in sync payload", http.StatusUnauthorized)
		return
	}

	resp := processIncomingSync(boundPeer.ID, remoteHost, pkt)
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

	// Strictly validate targetPort against the configured tc.ForwardPorts allowlist before dialing localhost
	authorizedPort, err := authorizeWSSTargetPort(tc, targetPort)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", authorizedPort), 5*time.Second)
	if err != nil {
		http.Error(w, "target service unreachable", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	enableKeepAlive(targetConn)

	respHdr := http.Header{}
	respHdr.Set("X-Sahand-Target", authorizedPort)

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
// MASTER-SIDE RFC 6455 WEBSOCKET CLIENT, PROBE & PARITY SYNC
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
	case strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "pin") ||
		strings.Contains(msg, "tls") ||
		strings.Contains(msg, "x509") ||
		strings.Contains(msg, "expired") ||
		strings.Contains(msg, "hostname"):
		return "TLS failure"
	case strings.Contains(msg, "handshake") || strings.Contains(msg, "websocket") || strings.Contains(msg, "alpn"):
		return "Protocol mismatch"
	default:
		return "Port unreachable"
	}
}

func dialWSSWithPinRecovery(
	peer *ServerPeer,
	tc TunnelConfig,
	purpose string,
	targetPortHeader string,
	localNodeID string,
	timeout time.Duration,
) (*websocket.Conn, *http.Response, error) {
	// If the server peer in config.json has never learned RemoteCertPin yet, bootstrap it via HMAC channel binding
	if strings.TrimSpace(tc.CertPin) == "" && strings.TrimSpace(peer.RemoteCertPin) == "" && isStoredServerPinEmpty(peer.ID) {
		bootstrapWSSRemoteCertPin(peer, tc)
	}

	attemptDial := func(currentPeer ServerPeer) (*websocket.Conn, *http.Response, error) {
		dialer, err := newWSSClientDialer(currentPeer, tc, timeout)
		if err != nil {
			return nil, nil, err
		}
		sni := normalizeWSSSNI(tc.SNI)
		wsURL := buildWSSURL(currentPeer.IP, tc.ListenPort, tc.WSPath)

		reqHeader := http.Header{}
		reqHeader.Set("Host", sni)
		if localNodeID != "" {
			reqHeader.Set("X-Sahand-Node", localNodeID)
		}
		reqHeader.Set("X-Sahand-Time", buildMasterTimeHeader())
		reqHeader.Set("X-Target-Port", targetPortHeader)
		if err := attachWSSAuthHeaders(reqHeader, currentPeer, purpose); err != nil {
			return nil, nil, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return dialer.DialContext(ctx, wsURL, reqHeader)
	}

	wsConn, resp, err := attemptDial(*peer)
	if err != nil && strings.TrimSpace(tc.CertPin) == "" && strings.Contains(strings.ToLower(err.Error()), "certificate pin mismatch") {
		if bootstrapWSSRemoteCertPin(peer, tc) {
			return attemptDial(*peer)
		}
	}
	return wsConn, resp, err
}

func probeWSS(peer ServerPeer, tc TunnelConfig, localNodeID string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	if _, err := buildWSSClientTLSConfig(peer, tc); err != nil {
		res.Success = false
		res.ErrorReason = "TLS failure"
		return res
	}

	probeTarget := fmt.Sprintf("probe:%d", tc.ListenPort)
	start := time.Now()
	wsConn, resp, err := dialWSSWithPinRecovery(&peer, tc, "probe:"+probeTarget, probeTarget, localNodeID, 4*time.Second)
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

func pushWSSParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	if strings.TrimSpace(tc.CertPin) == "" && strings.TrimSpace(peer.RemoteCertPin) == "" && isStoredServerPinEmpty(peer.ID) {
		if bootstrapWSSRemoteCertPin(&peer, tc) {
			return true
		}
	}

	tlsCfg, err := buildWSSClientTLSConfig(peer, tc)
	if err != nil {
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
	b64 := base64.StdEncoding.EncodeToString(rawPkt)

	syncURL := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort)),
		Path:   normalizeWSSPath(tc.WSPath),
	}

	req, err := http.NewRequest(http.MethodGet, syncURL.String(), nil)
	if err != nil {
		return false
	}
	req.Host = normalizeWSSSNI(tc.SNI)
	req.Header.Set("X-Sahand-Time", buildMasterTimeHeader())
	req.Header.Set("X-Sahand-Sync", b64)
	if err := attachWSSAuthHeaders(req.Header, peer, "sync:"+b64); err != nil {
		return false
	}

	httpClient := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: false,
			DisableKeepAlives: true,
		},
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if strings.TrimSpace(tc.CertPin) == "" && strings.Contains(strings.ToLower(err.Error()), "certificate pin mismatch") {
			return bootstrapWSSRemoteCertPin(&peer, tc)
		}
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return false
	}
	var syncResp SyncResponse
	if json.Unmarshal(body, &syncResp) != nil || !syncResp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, syncResp)
	return true
}

func forwardWSSTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	authorizedPort, err := authorizeWSSTargetPort(tc, targetPort)
	if err != nil {
		return
	}

	wsConn, resp, err := dialWSSWithPinRecovery(&peer, tc, "forward:"+authorizedPort, authorizedPort, "", wssHandshakeTimeout)
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
