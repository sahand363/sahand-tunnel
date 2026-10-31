package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func probeHTTPConnect(peer ServerPeer, tc TunnelConfig, localNodeID string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  time.Now().UTC().Format("15:04:05 UTC"),
	}

	targetAddr := fmt.Sprintf("%s:%d", peer.IP, tc.ListenPort)
	start := time.Now()
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		res.Success = false
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

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
		res.Success = false
		res.ErrorReason = "TLS failure"
		return res
	}
	defer tlsConn.Close()

	req := fmt.Sprintf("CONNECT probe:%d HTTP/1.1\r\nHost: %s:443\r\nProxy-Connection: Keep-Alive\r\nX-Sahand-Peer: %s\r\nX-Sahand-Node: %s\r\nX-Target-Port: probe:%d\r\n\r\n",
		tc.ListenPort, sni, peer.ID, localNodeID, tc.ListenPort)

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	br := bufio.NewReader(tlsConn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		res.Success = false
		res.ErrorReason = "Timeout"
		return res
	}
	if !strings.Contains(statusLine, "200") {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	res.Success = true
	res.LatencyMS = time.Since(start).Milliseconds()
	if res.LatencyMS <= 0 {
		res.LatencyMS = 1
	}
	return res
}

func handleHTTPConnectProbeReply(conn net.Conn) {
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: Sahand-Tunnel\r\n\r\n"))
}

func handleHTTPConnectIncomingTraffic(conn net.Conn, br *bufio.Reader, tc TunnelConfig, targetPort string) {
	target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: Sahand-Tunnel\r\n\r\n"))

	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		n, _ := br.Read(buf)
		if n > 0 {
			_, _ = target.Write(buf[:n])
		}
	}

	mbLimit := parseSpeedLimit(tc.SpeedLimitMBps)
	txW := newThrottledWriter(target, &appRxBytes, mbLimit)
	rxW := newThrottledWriter(conn, &appTxBytes, mbLimit)

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(txW, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(rxW, target); done <- struct{}{} }()
	<-done
}

func forwardHTTPConnectTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	remoteAddr := fmt.Sprintf("%s:%d", peer.IP, tc.ListenPort)
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	rawConn, err := dialer.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer rawConn.Close()
	enableKeepAlive(rawConn)

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
		return
	}
	defer tlsConn.Close()

	req := fmt.Sprintf("CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: %s:443\r\nProxy-Connection: Keep-Alive\r\nX-Sahand-Peer: %s\r\nX-Target-Port: %s\r\n\r\n",
		targetPort, sni, peer.ID, targetPort)

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return
	}

	br := bufio.NewReader(tlsConn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		return
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		n, _ := br.Read(buf)
		if n > 0 {
			_, _ = client.Write(buf[:n])
		}
	}

	mbLimit := parseSpeedLimit(tc.SpeedLimitMBps)
	txW := newThrottledWriter(tlsConn, &appTxBytes, mbLimit)
	rxW := newThrottledWriter(client, &appRxBytes, mbLimit)

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(txW, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(rxW, tlsConn); done <- struct{}{} }()
	<-done
}
