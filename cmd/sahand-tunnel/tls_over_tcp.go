package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
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
	tlsOverTCPMagic0       byte = 0x17
	tlsOverTCPMagic1       byte = 0x03
	tlsOverTCPProtoVersion byte = 0x01

	tlsOverTCPModeProbe      byte = 0x01
	tlsOverTCPModeParitySync byte = 0x02
	tlsOverTCPModeForward    byte = 0x03

	tlsOverTCPStatusOK           byte = 0x00
	tlsOverTCPStatusUnauthorized byte = 0x01
	tlsOverTCPStatusForbidden    byte = 0x02
	tlsOverTCPStatusUnreachable  byte = 0x03

	// Fixed preamble before variable padding:
	// [Magic:2][Ver:1][Mode:1][TargetPort:2][Timestamp:4][PadLen:1][HMAC-128:16] = 27 bytes
	tlsOverTCPHeaderSize = 27
)

func computeTLSOverTCPMAC(
	authKey []byte,
	ver, mode byte,
	targetPort uint16,
	ts uint32,
	pad []byte,
) [16]byte {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-tls-over-tcp-v1:"))
	var hdr [8]byte
	hdr[0] = ver
	hdr[1] = mode
	binary.BigEndian.PutUint16(hdr[2:4], targetPort)
	binary.BigEndian.PutUint32(hdr[4:8], ts)
	_, _ = mac.Write(hdr[:])
	_, _ = mac.Write(pad)
	sum := mac.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func dialTLSOverTCPSession(
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

	padLen := byte(16 + randomIntN(48))
	pad := make([]byte, int(padLen))
	_, _ = io.ReadFull(rand.Reader, pad)

	ts := uint32(time.Now().Unix())
	tag := computeTLSOverTCPMAC(authKey, tlsOverTCPProtoVersion, mode, targetPort, ts, pad)

	frame := make([]byte, tlsOverTCPHeaderSize+len(pad))
	frame[0] = tlsOverTCPMagic0
	frame[1] = tlsOverTCPMagic1
	frame[2] = tlsOverTCPProtoVersion
	frame[3] = mode
	binary.BigEndian.PutUint16(frame[4:6], targetPort)
	binary.BigEndian.PutUint32(frame[6:10], ts)
	frame[10] = padLen
	copy(frame[11:27], tag[:])
	copy(frame[27:], pad)

	if _, err := tlsConn.Write(frame); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	var status [1]byte
	if _, err := io.ReadFull(tlsConn, status[:]); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if status[0] != tlsOverTCPStatusOK {
		_ = tlsConn.Close()
		if status[0] == tlsOverTCPStatusUnauthorized {
			return nil, errors.New("tls over tcp authentication rejected")
		}
		return nil, errors.New("tls over tcp session rejected")
	}

	return tlsConn, nil
}

func startTLSOverTCPServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
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
			go handleIncomingTLSOverTCPConn(conn, peer, tc)
		}
	}()
	return ln, nil
}

func handleIncomingTLSOverTCPConn(conn net.Conn, peer ServerPeer, tc TunnelConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return
	}

	var hdr [tlsOverTCPHeaderSize]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	if hdr[0] != tlsOverTCPMagic0 || hdr[1] != tlsOverTCPMagic1 || hdr[2] != tlsOverTCPProtoVersion {
		return
	}
	mode := hdr[3]
	targetPort := binary.BigEndian.Uint16(hdr[4:6])
	ts := binary.BigEndian.Uint32(hdr[6:10])
	padLen := int(hdr[10])

	var pad []byte
	if padLen > 0 {
		pad = make([]byte, padLen)
		if _, err := io.ReadFull(conn, pad); err != nil {
			return
		}
	}

	expectedTag := computeTLSOverTCPMAC(authKey, hdr[2], mode, targetPort, ts, pad)
	if subtle.ConstantTimeCompare(hdr[11:27], expectedTag[:]) != 1 {
		_, _ = conn.Write([]byte{tlsOverTCPStatusUnauthorized})
		return
	}

	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	switch mode {
	case tlsOverTCPModeProbe:
		if _, err := conn.Write([]byte{tlsOverTCPStatusOK}); err != nil {
			return
		}
		var ping [12]byte
		if _, err := io.ReadFull(conn, ping[:]); err != nil {
			return
		}
		_, _ = conn.Write(ping[:])
		markPeerConnectedInbound(peer.ID, remoteHost, tc.ID, tc.ListenPort, 1)

	case tlsOverTCPModeParitySync:
		if _, err := conn.Write([]byte{tlsOverTCPStatusOK}); err != nil {
			return
		}
		handleRawTCPParitySyncServer(conn, peer.ID, remoteHost)

	case tlsOverTCPModeForward:
		if !tc.Enabled {
			_, _ = conn.Write([]byte{tlsOverTCPStatusForbidden})
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
			_, _ = conn.Write([]byte{tlsOverTCPStatusUnreachable})
			return
		}
		defer target.Close()
		enableKeepAlive(target)

		if _, err := conn.Write([]byte{tlsOverTCPStatusOK}); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})

		pipeRawTCPStreams(conn, target, tc.SpeedLimitMBps)
	}
}

func probeTLSOverTCP(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	conn, err := dialTLSOverTCPSession(peer, tc, tlsOverTCPModeProbe, uint16(tc.ListenPort), 4*time.Second)
	if err != nil {
		res.Success = false
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(msg, "pin") || strings.Contains(msg, "tls") {
			res.ErrorReason = "TLS failure"
		} else if strings.Contains(msg, "rejected") {
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

func pushTLSOverTCPParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	conn, err := dialTLSOverTCPSession(peer, tc, tlsOverTCPModeParitySync, uint16(tc.ListenPort), 4*time.Second)
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

func forwardTLSOverTCPTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	portNum, _ := strconv.Atoi(strings.TrimSpace(targetPort))
	if portNum <= 0 {
		portNum = 2053
	}

	conn, err := dialTLSOverTCPSession(peer, tc, tlsOverTCPModeForward, uint16(portNum), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})

	pipeRawTCPStreams(conn, client, tc.SpeedLimitMBps)
}
