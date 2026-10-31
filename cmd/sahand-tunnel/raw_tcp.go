package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	rawTCPProtoVersion byte = 0x01

	rawTCPModeProbe      byte = 0x01
	rawTCPModeParitySync byte = 0x02
	rawTCPModeForward    byte = 0x03

	rawTCPStatusOK           byte = 0x00
	rawTCPStatusUnauthorized byte = 0x01
	rawTCPStatusForbidden    byte = 0x02
	rawTCPStatusUnreachable  byte = 0x03

	// 24-byte compact binary preamble:
	// [Version:1][Mode:1][TargetPort:2][Timestamp:4][HMAC-128:16]
	rawTCPHeaderSize = 24
)

func computeRawTCPHeaderMAC(authKey []byte, ver, mode byte, targetPort uint16, ts uint32) [16]byte {
	var msg [8]byte
	msg[0] = ver
	msg[1] = mode
	binary.BigEndian.PutUint16(msg[2:4], targetPort)
	binary.BigEndian.PutUint32(msg[4:8], ts)

	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-raw-tcp-v1:"))
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)

	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func dialRawTCPBinary(
	peer ServerPeer,
	tc TunnelConfig,
	mode byte,
	targetPort uint16,
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
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, err
	}
	enableKeepAlive(conn)
	_ = conn.SetDeadline(time.Now().Add(timeout + 2*time.Second))

	ts := uint32(time.Now().Unix())
	tag := computeRawTCPHeaderMAC(authKey, rawTCPProtoVersion, mode, targetPort, ts)

	var hdr [rawTCPHeaderSize]byte
	hdr[0] = rawTCPProtoVersion
	hdr[1] = mode
	binary.BigEndian.PutUint16(hdr[2:4], targetPort)
	binary.BigEndian.PutUint32(hdr[4:8], ts)
	copy(hdr[8:24], tag[:])

	if _, err := conn.Write(hdr[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}

	var status [1]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if status[0] != rawTCPStatusOK {
		_ = conn.Close()
		if status[0] == rawTCPStatusUnauthorized {
			return nil, errors.New("raw tcp authentication rejected")
		}
		return nil, errors.New("raw tcp session rejected")
	}

	return conn, nil
}

func startRawTCPServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			enableKeepAlive(conn)
			go handleIncomingRawTCPConn(conn, peer, tc)
		}
	}()
	return ln, nil
}

func handleIncomingRawTCPConn(conn net.Conn, peer ServerPeer, tc TunnelConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return
	}

	var hdr [rawTCPHeaderSize]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	ver := hdr[0]
	mode := hdr[1]
	targetPort := binary.BigEndian.Uint16(hdr[2:4])
	ts := binary.BigEndian.Uint32(hdr[4:8])

	if ver != rawTCPProtoVersion {
		return
	}
	expectedTag := computeRawTCPHeaderMAC(authKey, ver, mode, targetPort, ts)
	if subtle.ConstantTimeCompare(hdr[8:24], expectedTag[:]) != 1 {
		_, _ = conn.Write([]byte{rawTCPStatusUnauthorized})
		return
	}

	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	switch mode {
	case rawTCPModeProbe:
		if _, err := conn.Write([]byte{rawTCPStatusOK}); err != nil {
			return
		}
		var ping [12]byte
		if _, err := io.ReadFull(conn, ping[:]); err != nil {
			return
		}
		_, _ = conn.Write(ping[:])
		markPeerConnectedInbound(peer.ID, remoteHost, tc.ID, tc.ListenPort, 1)

	case rawTCPModeParitySync:
		if _, err := conn.Write([]byte{rawTCPStatusOK}); err != nil {
			return
		}
		handleRawTCPParitySyncServer(conn, peer.ID, remoteHost)

	case rawTCPModeForward:
		if !tc.Enabled {
			_, _ = conn.Write([]byte{rawTCPStatusForbidden})
			return
		}
		portStr := strconv.Itoa(int(targetPort))
		if targetPort == 0 {
			ports := parsePortList(tc.ForwardPorts)
			if len(ports) > 0 {
				portStr = ports[0]
			} else {
				portStr = "2053"
			}
		}
		target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", portStr), 5*time.Second)
		if err != nil {
			_, _ = conn.Write([]byte{rawTCPStatusUnreachable})
			return
		}
		defer target.Close()
		enableKeepAlive(target)

		if _, err := conn.Write([]byte{rawTCPStatusOK}); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})

		pipeRawTCPStreams(conn, target, tc.SpeedLimitMBps)
	}
}

func probeRawTCP(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	conn, err := dialRawTCPBinary(peer, tc, rawTCPModeProbe, uint16(tc.ListenPort), 4*time.Second)
	if err != nil {
		res.Success = false
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(err.Error(), "rejected") {
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

func pushRawTCPParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	conn, err := dialRawTCPBinary(peer, tc, rawTCPModeParitySync, uint16(tc.ListenPort), 4*time.Second)
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

func handleRawTCPParitySyncServer(conn net.Conn, effectivePeerID, remoteHost string) {
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

func forwardRawTCPTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	portNum, _ := strconv.Atoi(strings.TrimSpace(targetPort))
	if portNum <= 0 {
		portNum = 2053
	}

	conn, err := dialRawTCPBinary(peer, tc, rawTCPModeForward, uint16(portNum), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})

	pipeRawTCPStreams(conn, client, tc.SpeedLimitMBps)
}

func pipeRawTCPStreams(tunnelConn net.Conn, localConn net.Conn, speedLimitMBps string) {
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
