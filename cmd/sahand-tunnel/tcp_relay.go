package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func probeTCPRelay(peer ServerPeer, tc TunnelConfig, localNodeID string) MethodResult {
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
	enableKeepAlive(rawConn)
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	req := fmt.Sprintf("RELAY probe:%d SAHAND/1.0\r\nX-Tunnel-Mode: tcp-relay\r\nX-Sahand-Peer: %s\r\nX-Sahand-Node: %s\r\nX-Target-Port: probe:%d\r\n\r\n",
		tc.ListenPort, peer.ID, localNodeID, tc.ListenPort)

	if _, err := rawConn.Write([]byte(req)); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	br := bufio.NewReader(rawConn)
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

func handleTCPRelayProbeReply(conn net.Conn) {
	_, _ = conn.Write([]byte("SAHAND/1.0 200 OK\r\n\r\n"))
}

func handleTCPRelayIncomingTraffic(conn net.Conn, br *bufio.Reader, tc TunnelConfig, targetPort string) {
	target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte("SAHAND/1.0 502 UNREACHABLE\r\n\r\n"))
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	_, _ = conn.Write([]byte("SAHAND/1.0 200 STREAM\r\n\r\n"))

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

func forwardTCPRelayTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	remoteAddr := fmt.Sprintf("%s:%d", peer.IP, tc.ListenPort)
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	rawConn, err := dialer.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer rawConn.Close()
	enableKeepAlive(rawConn)

	req := fmt.Sprintf("RELAY 127.0.0.1:%s SAHAND/1.0\r\nX-Tunnel-Mode: tcp-relay\r\nX-Sahand-Peer: %s\r\nX-Target-Port: %s\r\n\r\n",
		targetPort, peer.ID, targetPort)

	if _, err := rawConn.Write([]byte(req)); err != nil {
		return
	}

	br := bufio.NewReader(rawConn)
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
	txW := newThrottledWriter(rawConn, &appTxBytes, mbLimit)
	rxW := newThrottledWriter(client, &appRxBytes, mbLimit)

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(txW, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(rxW, rawConn); done <- struct{}{} }()
	<-done
}
