package main

import (
	"bufio"
	"bytes"
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
	"time"
)

const (
	httpPollModeProbe      = "probe"
	httpPollModeParitySync = "sync"
	httpPollModeForward    = "stream"
)

func computeHTTPLongPollToken(authKey []byte, peerID, mode, targetPort, tsStr string) string {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-http-long-poll-v1:"))
	_, _ = mac.Write([]byte(peerID + "|" + mode + "|" + targetPort + "|" + tsStr))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func normalizePollPath(raw string) string {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "/ws"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func dialHTTPLongPollingSession(
	peer ServerPeer,
	tc TunnelConfig,
	mode string,
	targetPort string,
	timeout time.Duration,
) (net.Conn, *bufio.Reader, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return nil, nil, err
	}

	targetAddr := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}

	pollPath := normalizePollPath(tc.WSPath)
	sessionID, _ := randomHex(8)
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	sig := computeHTTPLongPollToken(authKey, peer.ID, mode, targetPort, tsStr)

	req := fmt.Sprintf(
		"POST %s?session=%s&mode=%s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"+
			"Accept: text/event-stream, application/octet-stream\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Cache-Control: no-cache, no-transform\r\n"+
			"Connection: keep-alive\r\n"+
			"X-Poll-Peer: %s\r\n"+
			"X-Poll-Mode: %s\r\n"+
			"X-Poll-Port: %s\r\n"+
			"X-Poll-TS: %s\r\n"+
			"X-Poll-Auth: %s\r\n"+
			"X-Sahand-Time: %s\r\n\r\n",
		pollPath, sessionID, mode, sni, peer.ID, mode, targetPort, tsStr, sig, buildMasterTimeHeader(),
	)

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		_ = tlsConn.Close()
		return nil, nil, err
	}

	br := bufio.NewReader(tlsConn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = tlsConn.Close()
		return nil, nil, err
	}
	if !strings.Contains(statusLine, "200") {
		_ = tlsConn.Close()
		if strings.Contains(statusLine, "401") || strings.Contains(statusLine, "403") {
			return nil, nil, errors.New("http long polling authentication rejected")
		}
		return nil, nil, errors.New("http long polling unexpected status")
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = tlsConn.Close()
			return nil, nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	return tlsConn, br, nil
}

func startHTTPLongPollingServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
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
			go handleIncomingHTTPLongPollingConn(conn, peer, tc)
		}
	}()
	return ln, nil
}

func writeHTTPLongPollHeaders(w io.Writer, status string) error {
	resp := fmt.Sprintf(
		"HTTP/1.1 %s\r\n"+
			"Content-Type: text/event-stream\r\n"+
			"Cache-Control: no-cache, no-store, no-transform\r\n"+
			"Connection: keep-alive\r\n"+
			"X-Accel-Buffering: no\r\n\r\n",
		status,
	)
	_, err := w.Write([]byte(resp))
	return err
}

func handleIncomingHTTPLongPollingConn(conn net.Conn, peer ServerPeer, tc TunnelConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return
	}

	br := bufio.NewReader(conn)
	firstLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return
	}

	var peerHdr, modeHdr, portHdr, tsHdr, authHdr, timeHdr string
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		low := strings.ToLower(line)
		switch {
		case strings.HasPrefix(low, "x-poll-peer:"):
			peerHdr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		case strings.HasPrefix(low, "x-poll-mode:"):
			modeHdr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		case strings.HasPrefix(low, "x-poll-port:"):
			portHdr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		case strings.HasPrefix(low, "x-poll-ts:"):
			tsHdr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		case strings.HasPrefix(low, "x-poll-auth:"):
			authHdr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		case strings.HasPrefix(low, "x-sahand-time:"):
			timeHdr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}

	if timeHdr != "" {
		applyMasterTimeHeader(timeHdr)
	}

	expectedSig := computeHTTPLongPollToken(authKey, peerHdr, modeHdr, portHdr, tsHdr)
	if authHdr == "" || subtle.ConstantTimeCompare([]byte(authHdr), []byte(expectedSig)) != 1 {
		_ = writeHTTPLongPollHeaders(conn, "401 Unauthorized")
		return
	}

	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	effectivePeerID := peer.ID
	if peerHdr != "" {
		effectivePeerID = peerHdr
	}

	switch modeHdr {
	case httpPollModeProbe:
		if err := writeHTTPLongPollHeaders(conn, "200 OK"); err != nil {
			return
		}
		var ping [12]byte
		if _, err := io.ReadFull(br, ping[:]); err != nil {
			return
		}
		_, _ = conn.Write(ping[:])
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)

	case httpPollModeParitySync:
		if err := writeHTTPLongPollHeaders(conn, "200 OK"); err != nil {
			return
		}
		var lenBuf [4]byte
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			return
		}
		pktLen := binary.BigEndian.Uint32(lenBuf[:])
		if pktLen == 0 || pktLen > 256*1024 {
			return
		}
		rawPkt := make([]byte, pktLen)
		if _, err := io.ReadFull(br, rawPkt); err != nil {
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

	case httpPollModeForward:
		if !tc.Enabled {
			_ = writeHTTPLongPollHeaders(conn, "403 Forbidden")
			return
		}
		targetPort := strings.TrimSpace(portHdr)
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
			_ = writeHTTPLongPollHeaders(conn, "502 Bad Gateway")
			return
		}
		defer target.Close()
		enableKeepAlive(target)

		if err := writeHTTPLongPollHeaders(conn, "200 OK"); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})

		if br.Buffered() > 0 {
			buf := make([]byte, br.Buffered())
			n, _ := br.Read(buf)
			if n > 0 {
				_, _ = target.Write(buf[:n])
			}
		}

		pipeRawTCPStreams(conn, target, tc.SpeedLimitMBps)
	}
}

func probeHTTPLongPolling(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	conn, br, err := dialHTTPLongPollingSession(peer, tc, httpPollModeProbe, strconv.Itoa(tc.ListenPort), 4*time.Second)
	if err != nil {
		res.Success = false
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(msg, "rejected") {
			res.ErrorReason = "Authentication failure"
		} else if strings.Contains(msg, "tls") || strings.Contains(msg, "pin") {
			res.ErrorReason = "TLS failure"
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
	if _, err := io.ReadFull(br, pong[:]); err != nil || !bytes.Equal(ping[:], pong[:]) {
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

func pushHTTPLongPollingParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	conn, br, err := dialHTTPLongPollingSession(peer, tc, httpPollModeParitySync, strconv.Itoa(tc.ListenPort), 4*time.Second)
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

	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(br, respBytes); err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func forwardHTTPLongPollingTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	conn, br, err := dialHTTPLongPollingSession(peer, tc, httpPollModeForward, targetPort, 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})

	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		n, _ := br.Read(buf)
		if n > 0 {
			_, _ = client.Write(buf[:n])
		}
	}

	pipeRawTCPStreams(conn, client, tc.SpeedLimitMBps)
}
