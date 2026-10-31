package main

import (
	"bytes"
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
	webTransportALPN = "h3"

	// RFC 9297 Quarter-Stream-ID Context Varint 0x00 for WebTransport Datagrams
	webTransportQuarterStreamID byte = 0x00

	wtModeProbe      byte = 0x01
	wtModeParitySync byte = 0x02
	wtModeTCPForward byte = 0x03
	wtModeUDPAuth    byte = 0x04

	wtStatusOK           byte = 0x00
	wtStatusUnauthorized byte = 0x01
	wtStatusForbidden    byte = 0x02
	wtStatusUnreachable  byte = 0x03

	// WebTransport Datagram Header:
	// [QuarterStreamID:1 (0x00)][SessionID:4][TargetPort:2] = 7 bytes
	wtDatagramHeaderSize = 7
	wtUDPIdleTTL         = 60 * time.Second
)

// WebTransport Extended CONNECT Session Frame (draft-ietf-webtrans-http3 / RFC 9297)
type webTransportConnectHeader struct {
	Method     string `json:":method"`
	Protocol   string `json:":protocol"`
	Scheme     string `json:":scheme"`
	Authority  string `json:":authority"`
	Path       string `json:":path"`
	Mode       byte   `json:"wt_mode"`
	PeerID     string `json:"wt_pid"`
	NodeID     string `json:"wt_nid"`
	TargetPort string `json:"wt_port,omitempty"`
	TimeHdr    string `json:"wt_tm,omitempty"`
	Timestamp  int64  `json:"wt_ts"`
	Nonce      string `json:"wt_nc"`
	Signature  string `json:"wt_sig"`
}

func signWebTransportConnect(hdr webTransportConnectHeader, authKey []byte) string {
	canonical := fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s|%d|%s",
		hdr.Method, hdr.Protocol, hdr.Authority, hdr.Mode, hdr.PeerID, hdr.NodeID, hdr.TargetPort, hdr.Timestamp, hdr.Nonce)
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-webtransport-h3-v1:"))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyWebTransportConnect(hdr webTransportConnectHeader, authKey []byte) bool {
	if len(authKey) == 0 || hdr.Method != "CONNECT" || hdr.Protocol != "webtransport" {
		return false
	}
	expected := signWebTransportConnect(hdr, authKey)
	return subtle.ConstantTimeCompare([]byte(hdr.Signature), []byte(expected)) == 1
}

func writeWebTransportConnectFrame(w io.Writer, hdr webTransportConnectHeader) error {
	raw, err := json.Marshal(hdr)
	if err != nil || len(raw) > 8192 {
		return errors.New("invalid webtransport connect header")
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(raw)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func readWebTransportConnectFrame(r io.Reader) (webTransportConnectHeader, error) {
	var hdr webTransportConnectHeader
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return hdr, err
	}
	frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if frameLen <= 0 || frameLen > 8192 {
		return hdr, errors.New("invalid webtransport connect header length")
	}
	buf := make([]byte, frameLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return hdr, err
	}
	err := json.Unmarshal(buf, &hdr)
	return hdr, err
}

func handleWebTransportParitySyncStream(rw io.ReadWriter, effectivePeerID, remoteHost string) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(rw, lenBuf[:]); err != nil {
		return
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen == 0 || pktLen > 256*1024 {
		return
	}
	rawPkt := make([]byte, pktLen)
	if _, err := io.ReadFull(rw, rawPkt); err != nil {
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
	_, _ = rw.Write(lenBuf[:])
	_, _ = rw.Write(respBytes)
}

// ============================================================================
// WEBTRANSPORT QUIC/H3 CLIENT & SERVER MANAGERS (+ TLS/TCP FALLBACK)
// ============================================================================

type wtManagedClient struct {
	mu          sync.Mutex
	endpoint    string
	udpConn     *net.UDPConn
	transport   *quic.Transport
	conn        *quic.Conn
	udpAuthed   atomic.Bool
	entryUDPMux atomic.Pointer[wtUDPEntryManager]
}

func (mc *wtManagedClient) close() {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.conn != nil {
		_ = mc.conn.CloseWithError(0, "closing webtransport client")
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

var (
	wtMu            sync.RWMutex
	wtClientsByPeer = make(map[string]*wtManagedClient)
	wtExitUDPMuxes  = make(map[string]*wtUDPExitManager)
	wtEntryUDPMuxes = make(map[string]*wtUDPEntryManager)
	wtUDPBlockedMap = make(map[string]int64)
)

func markWTUDPBlocked(endpoint string) {
	wtMu.Lock()
	wtUDPBlockedMap[endpoint] = time.Now().Unix() + 60
	wtMu.Unlock()
}

func clearWTUDPBlocked(endpoint string) {
	wtMu.Lock()
	delete(wtUDPBlockedMap, endpoint)
	wtMu.Unlock()
}

func isWTUDPBlocked(endpoint string) bool {
	wtMu.RLock()
	until, ok := wtUDPBlockedMap[endpoint]
	wtMu.RUnlock()
	return ok && time.Now().Unix() < until
}

func stopWebTransportPeerResources(peerID string) {
	wtMu.Lock()
	if mc, ok := wtClientsByPeer[peerID]; ok {
		mc.close()
		delete(wtClientsByPeer, peerID)
	}
	if exitMux, ok := wtExitUDPMuxes[peerID]; ok {
		exitMux.closeAll()
		delete(wtExitUDPMuxes, peerID)
	}
	for k, entryMux := range wtEntryUDPMuxes {
		if strings.HasPrefix(k, peerID+"|") {
			entryMux.closeAll()
			delete(wtEntryUDPMuxes, k)
		}
	}
	wtMu.Unlock()
}

func getOrDialWebTransportQUIC(
	ctx context.Context,
	peer ServerPeer,
	tc TunnelConfig,
	entryMux *wtUDPEntryManager,
) (*quic.Conn, *wtManagedClient, error) {
	endpoint := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))

	wtMu.Lock()
	mc, exists := wtClientsByPeer[peer.ID]
	if !exists || mc.endpoint != endpoint {
		if exists {
			mc.close()
		}
		mc = &wtManagedClient{endpoint: endpoint}
		wtClientsByPeer[peer.ID] = mc
	}
	if entryMux != nil {
		mc.entryUDPMux.Store(entryMux)
	}
	wtMu.Unlock()

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

	rAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, err
	}
	configureUDPSocketBuffers(udpConn)

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
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{webTransportALPN},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}

	tr := &quic.Transport{Conn: udpConn}
	conn, err := tr.Dial(ctx, rAddr, tlsCfg, buildQUICConfig(tc))
	if err != nil {
		_ = tr.Close()
		_ = udpConn.Close()
		return nil, nil, err
	}

	mc.udpConn = udpConn
	mc.transport = tr
	mc.conn = conn
	clearWTUDPBlocked(endpoint)

	go func(c *quic.Conn, wrapper *wtManagedClient) {
		for {
			dgram, rErr := c.ReceiveDatagram(c.Context())
			if rErr != nil {
				return
			}
			if mux := wrapper.entryUDPMux.Load(); mux != nil {
				mux.handleReplyDatagram(dgram)
			}
		}
	}(conn, mc)

	return conn, mc, nil
}

func buildWebTransportConnectHeader(mode byte, peer ServerPeer, tc TunnelConfig, targetPort string) (webTransportConnectHeader, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return webTransportConnectHeader{}, err
	}
	sni := strings.TrimSpace(tc.SNI)
	if sni == "" {
		sni = "www.speedtest.net"
	}
	nonce, _ := randomHex(8)
	hdr := webTransportConnectHeader{
		Method:     "CONNECT",
		Protocol:   "webtransport",
		Scheme:     "https",
		Authority:  sni,
		Path:       "/webtransport",
		Mode:       mode,
		PeerID:     peer.ID,
		NodeID:     cfgSnapshot.NodeID,
		TargetPort: targetPort,
		TimeHdr:    buildMasterTimeHeader(),
		Timestamp:  time.Now().Unix(),
		Nonce:      nonce,
	}
	hdr.Signature = signWebTransportConnect(hdr, authKey)
	return hdr, nil
}

// ============================================================================
// SERVER LISTENER (:11319 QUIC H3/WEBTRANSPORT + TLS/TCP WEBTRANSPORT)
// ============================================================================

type wtQUICCloser struct {
	udpConn   *net.UDPConn
	transport *quic.Transport
	listener  *quic.Listener
}

func (c *wtQUICCloser) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.udpConn.ReadFrom(p)
}
func (c *wtQUICCloser) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.udpConn.WriteTo(p, addr)
}
func (c *wtQUICCloser) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}
func (c *wtQUICCloser) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}
func (c *wtQUICCloser) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}
func (c *wtQUICCloser) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}
func (c *wtQUICCloser) Close() error {
	if c.listener != nil {
		_ = c.listener.Close()
	}
	if c.transport != nil {
		_ = c.transport.Close()
	}
	return c.udpConn.Close()
}

func startWebTransportServer(peer ServerPeer, tc TunnelConfig) (net.PacketConn, net.Listener) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))

	wtMu.Lock()
	if old, ok := wtExitUDPMuxes[peer.ID]; ok {
		old.closeAll()
	}
	exitMux := newWTUDPExitManager(tc.SpeedLimitMBps)
	wtExitUDPMuxes[peer.ID] = exitMux
	wtMu.Unlock()

	var boundUDP net.PacketConn
	if uAddr, err := net.ResolveUDPAddr("udp", listenAddr); err == nil {
		if uConn, err := net.ListenUDP("udp", uAddr); err == nil {
			configureUDPSocketBuffers(uConn)
			tr := &quic.Transport{Conn: uConn}
			tlsCfg := &tls.Config{
				Certificates: []tls.Certificate{localCert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{webTransportALPN},
			}
			if qLn, err := tr.Listen(tlsCfg, buildQUICConfig(tc)); err == nil {
				boundUDP = &wtQUICCloser{
					udpConn:   uConn,
					transport: tr,
					listener:  qLn,
				}
				go acceptWebTransportQUICLoop(qLn, peer, tc, exitMux)
			} else {
				_ = tr.Close()
				_ = uConn.Close()
			}
		}
	}

	// Companion WebTransport-over-HTTP/2/TLS TCP listener on the same port number
	var boundTCP net.Listener
	tlsTCPCfg := &tls.Config{
		Certificates: []tls.Certificate{localCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	if tLn, err := tls.Listen("tcp", listenAddr, tlsTCPCfg); err == nil {
		boundTCP = tLn
		go func() {
			for {
				conn, err := tLn.Accept()
				if err != nil {
					return
				}
				go handleIncomingWebTransportTCPConn(conn, peer, tc)
			}
		}()
	}

	return boundUDP, boundTCP
}

func acceptWebTransportQUICLoop(
	qLn *quic.Listener,
	peer ServerPeer,
	tc TunnelConfig,
	exitMux *wtUDPExitManager,
) {
	for {
		conn, err := qLn.Accept(context.Background())
		if err != nil {
			return
		}
		go serveWebTransportQUICConn(conn, peer, tc, exitMux)
	}
}

func serveWebTransportQUICConn(
	conn *quic.Conn,
	peer ServerPeer,
	tc TunnelConfig,
	exitMux *wtUDPExitManager,
) {
	defer func() {
		_ = conn.CloseWithError(0, "webtransport session closed")
	}()

	var authed atomic.Bool
	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	go func() {
		for {
			dgram, err := conn.ReceiveDatagram(conn.Context())
			if err != nil {
				return
			}
			if !authed.Load() || !tc.Enabled || exitMux == nil {
				continue
			}
			exitMux.handleIncomingDatagram(conn, tc.ForwardPorts, dgram)
		}
	}()

	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		go handleWebTransportQUICStream(conn, stream, peer, tc, remoteHost, &authed)
	}
}

func handleWebTransportQUICStream(
	conn *quic.Conn,
	stream *quic.Stream,
	peer ServerPeer,
	tc TunnelConfig,
	remoteHost string,
	authed *atomic.Bool,
) {
	defer func() {
		_ = stream.Close()
		stream.CancelRead(0)
	}()

	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return
	}

	hdr, err := readWebTransportConnectFrame(stream)
	if err != nil || !verifyWebTransportConnect(hdr, authKey) {
		_, _ = stream.Write([]byte{wtStatusUnauthorized})
		_ = conn.CloseWithError(0x401, "unauthorized webtransport session")
		return
	}
	if hdr.TimeHdr != "" {
		applyMasterTimeHeader(hdr.TimeHdr)
	}
	authed.Store(true)

	effectivePeerID := peer.ID
	if hdr.PeerID != "" {
		effectivePeerID = hdr.PeerID
	}

	switch hdr.Mode {
	case wtModeProbe:
		if _, err := stream.Write([]byte{wtStatusOK}); err != nil {
			return
		}
		var ping [12]byte
		if _, err := io.ReadFull(stream, ping[:]); err != nil {
			return
		}
		_, _ = stream.Write(ping[:])
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)

	case wtModeParitySync:
		if _, err := stream.Write([]byte{wtStatusOK}); err != nil {
			return
		}
		handleWebTransportParitySyncStream(stream, effectivePeerID, remoteHost)

	case wtModeUDPAuth:
		if !tc.Enabled {
			_, _ = stream.Write([]byte{wtStatusForbidden})
			return
		}
		_, _ = stream.Write([]byte{wtStatusOK})

	case wtModeTCPForward:
		if !tc.Enabled {
			_, _ = stream.Write([]byte{wtStatusForbidden})
			return
		}
		targetPort := strings.TrimSpace(hdr.TargetPort)
		if targetPort == "" {
			ports := parsePortList(tc.ForwardPorts)
			if len(ports) > 0 {
				targetPort = ports[0]
			} else {
				targetPort = "2053"
			}
		}
		target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", targetPort), 5*time.Second)
		if err != nil {
			_, _ = stream.Write([]byte{wtStatusUnreachable})
			return
		}
		defer target.Close()
		enableKeepAlive(target)

		if _, err := stream.Write([]byte{wtStatusOK}); err != nil {
			return
		}
		_ = stream.SetDeadline(time.Time{})

		pipeQUICStreamAndTCP(stream, target, tc.SpeedLimitMBps)
	}
}

func handleIncomingWebTransportTCPConn(conn net.Conn, peer ServerPeer, tc TunnelConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return
	}

	hdr, err := readWebTransportConnectFrame(conn)
	if err != nil || !verifyWebTransportConnect(hdr, authKey) {
		_, _ = conn.Write([]byte{wtStatusUnauthorized})
		return
	}
	if hdr.TimeHdr != "" {
		applyMasterTimeHeader(hdr.TimeHdr)
	}

	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	effectivePeerID := peer.ID
	if hdr.PeerID != "" {
		effectivePeerID = hdr.PeerID
	}

	switch hdr.Mode {
	case wtModeProbe:
		if _, err := conn.Write([]byte{wtStatusOK}); err != nil {
			return
		}
		var ping [12]byte
		if _, err := io.ReadFull(conn, ping[:]); err != nil {
			return
		}
		_, _ = conn.Write(ping[:])
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)

	case wtModeParitySync:
		if _, err := conn.Write([]byte{wtStatusOK}); err != nil {
			return
		}
		handleWebTransportParitySyncStream(conn, effectivePeerID, remoteHost)

	case wtModeTCPForward:
		if !tc.Enabled {
			_, _ = conn.Write([]byte{wtStatusForbidden})
			return
		}
		targetPort := strings.TrimSpace(hdr.TargetPort)
		if targetPort == "" {
			ports := parsePortList(tc.ForwardPorts)
			if len(ports) > 0 {
				targetPort = ports[0]
			} else {
				targetPort = "2053"
			}
		}
		target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", targetPort), 5*time.Second)
		if err != nil {
			_, _ = conn.Write([]byte{wtStatusUnreachable})
			return
		}
		defer target.Close()
		enableKeepAlive(target)

		if _, err := conn.Write([]byte{wtStatusOK}); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})

		pipeRawTCPStreams(conn, target, tc.SpeedLimitMBps)
	}
}

func dialWebTransportTCPFallback(
	peer ServerPeer,
	tc TunnelConfig,
	mode byte,
	targetPort string,
	timeout time.Duration,
) (net.Conn, error) {
	hdr, err := buildWebTransportConnectHeader(mode, peer, tc, targetPort)
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
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	if err := writeWebTransportConnectFrame(tlsConn, hdr); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	var status [1]byte
	if _, err := io.ReadFull(tlsConn, status[:]); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if status[0] != wtStatusOK {
		_ = tlsConn.Close()
		return nil, errors.New("webtransport session rejected")
	}
	return tlsConn, nil
}

// ============================================================================
// ENGINE 1: PROBE & PARITY SYNC OVER WEBTRANSPORT
// ============================================================================

func probeWebTransport(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	hdr, err := buildWebTransportConnectHeader(wtModeProbe, peer, tc, strconv.Itoa(tc.ListenPort))
	if err != nil {
		res.Success = false
		res.ErrorReason = "Authentication failure"
		return res
	}

	endpoint := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))

	// 1. Primary: Genuine WebTransport over QUIC/H3
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2200*time.Millisecond)
	start := time.Now()
	conn, mc, err := getOrDialWebTransportQUIC(dialCtx, peer, tc, nil)
	dialCancel()

	if err == nil {
		sCtx, sCancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		stream, sErr := conn.OpenStreamSync(sCtx)
		sCancel()
		if sErr == nil {
			_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
			if wErr := writeWebTransportConnectFrame(stream, hdr); wErr == nil {
				var status [1]byte
				if _, rErr := io.ReadFull(stream, status[:]); rErr == nil && status[0] == wtStatusOK {
					var ping [12]byte
					var pong [12]byte
					binary.BigEndian.PutUint32(ping[0:4], 1)
					binary.BigEndian.PutUint64(ping[4:12], uint64(time.Now().UnixNano()))
					if _, errW := stream.Write(ping[:]); errW == nil {
						if _, errR := io.ReadFull(stream, pong[:]); errR == nil && bytes.Equal(ping[:], pong[:]) {
							_ = stream.Close()
							stream.CancelRead(0)
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
			}
			_ = stream.Close()
			stream.CancelRead(0)
		}
		mc.close()
	}

	// 2. Fallback: WebTransport over TLS 1.3 TCP when upstream ISP blocks UDP
	markWTUDPBlocked(endpoint)
	tStart := time.Now()
	tConn, err := dialWebTransportTCPFallback(peer, tc, wtModeProbe, strconv.Itoa(tc.ListenPort), 3500*time.Millisecond)
	if err != nil {
		res.Success = false
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(msg, "tls") || strings.Contains(msg, "pin") {
			res.ErrorReason = "TLS failure"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}
	defer tConn.Close()

	var ping [12]byte
	var pong [12]byte
	binary.BigEndian.PutUint32(ping[0:4], 1)
	binary.BigEndian.PutUint64(ping[4:12], uint64(time.Now().UnixNano()))
	if _, err := tConn.Write(ping[:]); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}
	if _, err := io.ReadFull(tConn, pong[:]); err != nil || !bytes.Equal(ping[:], pong[:]) {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	rtt := time.Since(tStart).Milliseconds()
	if rtt <= 0 {
		rtt = 1
	}
	res.Success = true
	res.LatencyMS = rtt
	res.MinLatencyMS = rtt
	res.MaxLatencyMS = rtt
	return res
}

func pushWebTransportParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
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

	tConn, err := dialWebTransportTCPFallback(peer, tc, wtModeParitySync, strconv.Itoa(tc.ListenPort), 4*time.Second)
	if err != nil {
		return false
	}
	defer tConn.Close()

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(rawPkt)))
	if _, err := tConn.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := tConn.Write(rawPkt); err != nil {
		return false
	}

	if _, err := io.ReadFull(tConn, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(tConn, respBytes); err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

// ============================================================================
// ENGINE 2: BIDIRECTIONAL TCP & UDP FORWARDING OVER WEBTRANSPORT
// ============================================================================

func forwardWebTransportTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	endpoint := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))

	if !isWTUDPBlocked(endpoint) {
		ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Millisecond)
		conn, mc, err := getOrDialWebTransportQUIC(ctx, peer, tc, nil)
		cancel()
		if err == nil {
			sCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
			stream, sErr := conn.OpenStreamSync(sCtx)
			sCancel()
			if sErr == nil {
				hdr, hErr := buildWebTransportConnectHeader(wtModeTCPForward, peer, tc, targetPort)
				if hErr == nil {
					_ = stream.SetDeadline(time.Now().Add(4 * time.Second))
					if wErr := writeWebTransportConnectFrame(stream, hdr); wErr == nil {
						var status [1]byte
						if _, rErr := io.ReadFull(stream, status[:]); rErr == nil && status[0] == wtStatusOK {
							_ = stream.SetDeadline(time.Time{})
							defer client.Close()
							pipeQUICStreamAndTCP(stream, client, tc.SpeedLimitMBps)
							return
						}
					}
				}
				_ = stream.Close()
				stream.CancelRead(0)
			}
			mc.close()
		}
		markWTUDPBlocked(endpoint)
	}

	defer client.Close()
	tConn, err := dialWebTransportTCPFallback(peer, tc, wtModeTCPForward, targetPort, 5*time.Second)
	if err != nil {
		return
	}
	defer tConn.Close()
	_ = tConn.SetDeadline(time.Time{})

	pipeRawTCPStreams(tConn, client, tc.SpeedLimitMBps)
}

func encodeWTDatagram(sessionID uint32, targetPort uint16, payload []byte) []byte {
	frame := make([]byte, wtDatagramHeaderSize+len(payload))
	frame[0] = webTransportQuarterStreamID
	binary.BigEndian.PutUint32(frame[1:5], sessionID)
	binary.BigEndian.PutUint16(frame[5:7], targetPort)
	copy(frame[7:], payload)
	return frame
}

type wtUDPEntrySession struct {
	sessionID    uint32
	clientAddr   *net.UDPAddr
	entryConn    *net.UDPConn
	lastActivity atomic.Int64
}

type wtUDPEntryManager struct {
	mu          sync.RWMutex
	peer        ServerPeer
	tunnel      TunnelConfig
	targetPort  uint16
	byAddr      map[string]*wtUDPEntrySession
	bySessionID map[uint32]*wtUDPEntrySession
	nextID      atomic.Uint32
	limiter     io.Writer
	stopCh      chan struct{}
	closed      atomic.Bool
}

func newWTUDPEntryManager(peer ServerPeer, tc TunnelConfig, targetPort uint16) *wtUDPEntryManager {
	m := &wtUDPEntryManager{
		peer:        peer,
		tunnel:      tc,
		targetPort:  targetPort,
		byAddr:      make(map[string]*wtUDPEntrySession),
		bySessionID: make(map[uint32]*wtUDPEntrySession),
		limiter:     newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(tc.SpeedLimitMBps)),
		stopCh:      make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *wtUDPEntryManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Unix() - int64(wtUDPIdleTTL.Seconds())
			m.mu.Lock()
			for k, s := range m.byAddr {
				if s.lastActivity.Load() < cutoff {
					delete(m.byAddr, k)
					delete(m.bySessionID, s.sessionID)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *wtUDPEntryManager) closeAll() {
	if m.closed.Swap(true) {
		return
	}
	close(m.stopCh)
}

func (m *wtUDPEntryManager) getOrCreateSession(entryConn *net.UDPConn, clientAddr *net.UDPAddr) *wtUDPEntrySession {
	key := clientAddr.String()
	now := time.Now().Unix()

	m.mu.RLock()
	if s, ok := m.byAddr[key]; ok {
		s.lastActivity.Store(now)
		m.mu.RUnlock()
		return s
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.byAddr[key]; ok {
		s.lastActivity.Store(now)
		return s
	}
	sid := m.nextID.Add(1)
	if sid == 0 {
		sid = m.nextID.Add(1)
	}
	addrCopy := &net.UDPAddr{
		IP:   append([]byte(nil), clientAddr.IP...),
		Port: clientAddr.Port,
		Zone: clientAddr.Zone,
	}
	s := &wtUDPEntrySession{
		sessionID:  sid,
		clientAddr: addrCopy,
		entryConn:  entryConn,
	}
	s.lastActivity.Store(now)
	m.byAddr[key] = s
	m.bySessionID[sid] = s
	return s
}

func (m *wtUDPEntryManager) handleClientPacket(entryConn *net.UDPConn, clientAddr *net.UDPAddr, payload []byte) {
	if len(payload) == 0 || len(payload) > 1150 {
		return
	}
	sess := m.getOrCreateSession(entryConn, clientAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, mc, err := getOrDialWebTransportQUIC(ctx, m.peer, m.tunnel, m)
	cancel()
	if err != nil {
		return
	}

	if !mc.udpAuthed.Load() {
		sCtx, sCancel := context.WithTimeout(context.Background(), 3*time.Second)
		stream, sErr := conn.OpenStreamSync(sCtx)
		sCancel()
		if sErr != nil {
			return
		}
		hdr, hErr := buildWebTransportConnectHeader(wtModeUDPAuth, m.peer, m.tunnel, strconv.Itoa(int(m.targetPort)))
		if hErr == nil {
			_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
			if writeWebTransportConnectFrame(stream, hdr) == nil {
				var status [1]byte
				if _, rErr := io.ReadFull(stream, status[:]); rErr == nil && status[0] == wtStatusOK {
					mc.udpAuthed.Store(true)
				}
			}
		}
		_ = stream.Close()
		stream.CancelRead(0)
		if !mc.udpAuthed.Load() {
			return
		}
	}

	_, _ = m.limiter.Write(payload)
	_ = conn.SendDatagram(encodeWTDatagram(sess.sessionID, m.targetPort, payload))
}

func (m *wtUDPEntryManager) handleReplyDatagram(raw []byte) {
	if len(raw) <= wtDatagramHeaderSize || raw[0] != webTransportQuarterStreamID {
		return
	}
	sid := binary.BigEndian.Uint32(raw[1:5])
	payload := raw[wtDatagramHeaderSize:]

	m.mu.RLock()
	sess, ok := m.bySessionID[sid]
	m.mu.RUnlock()
	if ok {
		sess.lastActivity.Store(time.Now().Unix())
		atomic.AddUint64(&appRxBytes, uint64(len(payload)))
		_, _ = sess.entryConn.WriteToUDP(payload, sess.clientAddr)
	}
}

type wtUDPExitSession struct {
	sessionID    uint32
	targetPort   uint16
	localConn    *net.UDPConn
	quicConn     *quic.Conn
	lastActivity atomic.Int64
	closed       atomic.Bool
}

type wtUDPExitManager struct {
	mu       sync.RWMutex
	sessions map[uint32]*wtUDPExitSession
	limiter  io.Writer
	stopCh   chan struct{}
	closed   atomic.Bool
}

func newWTUDPExitManager(speedLimitMBps string) *wtUDPExitManager {
	m := &wtUDPExitManager{
		sessions: make(map[uint32]*wtUDPExitSession),
		limiter:  newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(speedLimitMBps)),
		stopCh:   make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *wtUDPExitManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Unix() - int64(wtUDPIdleTTL.Seconds())
			m.mu.Lock()
			for sid, s := range m.sessions {
				if s.lastActivity.Load() < cutoff || s.quicConn.Context().Err() != nil {
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

func (m *wtUDPExitManager) closeAll() {
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

func (m *wtUDPExitManager) handleIncomingDatagram(conn *quic.Conn, defaultPorts string, raw []byte) {
	if len(raw) <= wtDatagramHeaderSize || raw[0] != webTransportQuarterStreamID {
		return
	}
	sid := binary.BigEndian.Uint32(raw[1:5])
	targetPort := binary.BigEndian.Uint16(raw[5:7])
	payload := raw[wtDatagramHeaderSize:]

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

	sess, err := m.getOrCreateSession(conn, sid, targetPort)
	if err != nil {
		return
	}
	sess.lastActivity.Store(time.Now().Unix())
	atomic.AddUint64(&appRxBytes, uint64(len(payload)))
	_, _ = sess.localConn.Write(payload)
}

func (m *wtUDPExitManager) getOrCreateSession(conn *quic.Conn, sid uint32, targetPort uint16) (*wtUDPExitSession, error) {
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
	s := &wtUDPExitSession{
		sessionID:  sid,
		targetPort: targetPort,
		localConn:  localUDP,
		quicConn:   conn,
	}
	s.lastActivity.Store(now)
	m.sessions[sid] = s

	go func(sess *wtUDPExitSession) {
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
		buf := make([]byte, 1400)
		for {
			_ = sess.localConn.SetReadDeadline(time.Now().Add(wtUDPIdleTTL))
			n, err := sess.localConn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				sess.lastActivity.Store(time.Now().Unix())
				_, _ = m.limiter.Write(buf[:n])
				_ = sess.quicConn.SendDatagram(encodeWTDatagram(sess.sessionID, sess.targetPort, buf[:n]))
			}
		}
	}(s)

	return s, nil
}

func startWebTransportUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
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
	wtMu.Lock()
	if old, ok := wtEntryUDPMuxes[muxKey]; ok {
		old.closeAll()
	}
	mgr := newWTUDPEntryManager(peer, tc, uint16(portNum))
	wtEntryUDPMuxes[muxKey] = mgr
	wtMu.Unlock()

	go func() {
		defer mgr.closeAll()
		buf := make([]byte, 2048)
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
