package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
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
	socks5Version byte = 0x05

	// RFC 1928 Auth Methods
	socks5AuthNone         byte = 0x00
	socks5AuthUserPass     byte = 0x02
	socks5AuthNoAcceptable byte = 0xFF

	// RFC 1929 Subnegotiation Version & Status
	socks5UserPassVersion byte = 0x01
	socks5AuthStatusOK    byte = 0x00
	socks5AuthStatusFail  byte = 0x01

	// RFC 1928 Commands
	socks5CmdConnect      byte = 0x01
	socks5CmdBind         byte = 0x02
	socks5CmdUDPAssociate byte = 0x03

	// RFC 1928 Address Types
	socks5ATYPIPv4   byte = 0x01
	socks5ATYPDomain byte = 0x03
	socks5ATYPIPv6   byte = 0x04

	// RFC 1928 Reply Codes
	socks5RepSucceeded        byte = 0x00
	socks5RepGeneralFailure   byte = 0x01
	socks5RepNotAllowed       byte = 0x02
	socks5RepHostUnreachable  byte = 0x04
	socks5RepConnectionRefused byte = 0x05
	socks5RepCmdNotSupported  byte = 0x07

	// Internal Engine 1 / UDP target domains carried over ATYP=0x03
	socks5DomainProbe      = "probe.sahand"
	socks5DomainParitySync = "sync.sahand"
	socks5DomainUDPTunnel  = "udp.sahand"

	socks5UDPIdleTTL = 60 * time.Second
)

type socks5UserMetadata struct {
	PeerID    string `json:"pid"`
	NodeID    string `json:"nid"`
	TimeHdr   string `json:"tm,omitempty"`
	Timestamp int64  `json:"ts"`
	Nonce     string `json:"nc"`
}

func computeSOCKS5PasswdMAC(authKey []byte, rawUser []byte) string {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-rfc1929-socks5:"))
	_, _ = mac.Write(rawUser)
	return hex.EncodeToString(mac.Sum(nil)[:24]) // 48-char hex password (< 255 byte RFC 1929 limit)
}

// ============================================================================
// 1. RFC 1928 + RFC 1929 CLIENT & SERVER HANDSHAKES
// ============================================================================

func dialSOCKS5Authenticated(
	peer ServerPeer,
	tc TunnelConfig,
	cmd byte,
	atyp byte,
	dstHost string,
	dstPort uint16,
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

	// Step 1: RFC 1928 Greeting -> [VER=0x05, NMETHODS=0x01, METHOD=0x02]
	if _, err := conn.Write([]byte{socks5Version, 0x01, socks5AuthUserPass}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var methodReply [2]byte
	if _, err := io.ReadFull(conn, methodReply[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if methodReply[0] != socks5Version || methodReply[1] != socks5AuthUserPass {
		_ = conn.Close()
		return nil, errors.New("socks5 method negotiation failed")
	}

	// Step 2: RFC 1929 Username/Password Subnegotiation
	nonce, _ := randomHex(6)
	uMeta := socks5UserMetadata{
		PeerID:    peer.ID,
		NodeID:    cfgSnapshot.NodeID,
		TimeHdr:   buildMasterTimeHeader(),
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}
	unameBytes, err := json.Marshal(uMeta)
	if err != nil || len(unameBytes) > 250 {
		_ = conn.Close()
		return nil, errors.New("socks5 username metadata too long")
	}
	passwdStr := computeSOCKS5PasswdMAC(authKey, unameBytes)
	passwdBytes := []byte(passwdStr)

	authReq := make([]byte, 0, 3+len(unameBytes)+len(passwdBytes))
	authReq = append(authReq, socks5UserPassVersion)
	authReq = append(authReq, byte(len(unameBytes)))
	authReq = append(authReq, unameBytes...)
	authReq = append(authReq, byte(len(passwdBytes)))
	authReq = append(authReq, passwdBytes...)

	if _, err := conn.Write(authReq); err != nil {
		_ = conn.Close()
		return nil, err
	}

	var authResp [2]byte
	if _, err := io.ReadFull(conn, authResp[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if authResp[0] != socks5UserPassVersion || authResp[1] != socks5AuthStatusOK {
		_ = conn.Close()
		return nil, errors.New("socks5 authentication rejected")
	}

	// Step 3: RFC 1928 Request -> [VER=0x05][CMD][RSV=0x00][ATYP][DST.ADDR][DST.PORT]
	reqBuf := make([]byte, 0, 32)
	reqBuf = append(reqBuf, socks5Version, cmd, 0x00, atyp)
	switch atyp {
	case socks5ATYPIPv4:
		ip4 := net.ParseIP(dstHost).To4()
		if ip4 == nil {
			ip4 = net.IPv4(127, 0, 0, 1).To4()
		}
		reqBuf = append(reqBuf, ip4...)
	case socks5ATYPDomain:
		domBytes := []byte(dstHost)
		reqBuf = append(reqBuf, byte(len(domBytes)))
		reqBuf = append(reqBuf, domBytes...)
	default:
		_ = conn.Close()
		return nil, errors.New("unsupported socks5 atyp")
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], dstPort)
	reqBuf = append(reqBuf, portBytes[:]...)

	if _, err := conn.Write(reqBuf); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Step 4: Read RFC 1928 Reply -> [VER=0x05][REP][RSV=0x00][ATYP][BND.ADDR][BND.PORT]
	var repHdr [4]byte
	if _, err := io.ReadFull(conn, repHdr[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if repHdr[0] != socks5Version || repHdr[1] != socks5RepSucceeded {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 request failed with rep=0x%02x", repHdr[1])
	}
	if err := discardSOCKS5AddressAndPort(conn, repHdr[3]); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func discardSOCKS5AddressAndPort(r io.Reader, atyp byte) error {
	switch atyp {
	case socks5ATYPIPv4:
		var buf [6]byte // 4B IPv4 + 2B Port
		_, err := io.ReadFull(r, buf[:])
		return err
	case socks5ATYPIPv6:
		var buf [18]byte // 16B IPv6 + 2B Port
		_, err := io.ReadFull(r, buf[:])
		return err
	case socks5ATYPDomain:
		var lenByte [1]byte
		if _, err := io.ReadFull(r, lenByte[:]); err != nil {
			return err
		}
		buf := make([]byte, int(lenByte[0])+2)
		_, err := io.ReadFull(r, buf)
		return err
	default:
		return errors.New("unknown socks5 address type")
	}
}

func writeSOCKS5Reply(w io.Writer, rep byte) error {
	// [VER=0x05][REP][RSV=0x00][ATYP=0x01][127.0.0.1][Port=0]
	reply := []byte{socks5Version, rep, 0x00, socks5ATYPIPv4, 127, 0, 0, 1, 0, 0}
	_, err := w.Write(reply)
	return err
}

// ============================================================================
// 2. SOCKS5 SERVER LISTENER (:11312) & REQUEST DISPATCH
// ============================================================================

var (
	socks5Mu          sync.RWMutex
	socks5ExitUDPMux  = make(map[string]*socks5UDPExitManager)
	socks5EntryUDPMux = make(map[string]*socks5UDPEntryManager)
)

func stopSOCKS5PeerResources(peerID string) {
	socks5Mu.Lock()
	if exitMux, ok := socks5ExitUDPMux[peerID]; ok {
		exitMux.closeAll()
		delete(socks5ExitUDPMux, peerID)
	}
	for k, entryMux := range socks5EntryUDPMux {
		if strings.HasPrefix(k, peerID+"|") {
			entryMux.closeAll()
			delete(socks5EntryUDPMux, k)
		}
	}
	socks5Mu.Unlock()
}

func startSOCKS5ServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}

	socks5Mu.Lock()
	if old, ok := socks5ExitUDPMux[peer.ID]; ok {
		old.closeAll()
	}
	exitMux := newSOCKS5UDPExitManager(tc.SpeedLimitMBps)
	socks5ExitUDPMux[peer.ID] = exitMux
	socks5Mu.Unlock()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			enableKeepAlive(conn)
			go handleIncomingSOCKS5Conn(conn, peer, tc, exitMux)
		}
	}()
	return ln, nil
}

func handleIncomingSOCKS5Conn(
	conn net.Conn,
	peer ServerPeer,
	tc TunnelConfig,
	exitMux *socks5UDPExitManager,
) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return
	}

	// Step 1: Read RFC 1928 Greeting -> [VER=0x05][NMETHODS][METHODS...]
	var greetHdr [2]byte
	if _, err := io.ReadFull(conn, greetHdr[:]); err != nil || greetHdr[0] != socks5Version {
		return
	}
	nMethods := int(greetHdr[1])
	if nMethods <= 0 || nMethods > 64 {
		return
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	supportsUserPass := false
	for _, m := range methods {
		if m == socks5AuthUserPass {
			supportsUserPass = true
			break
		}
	}
	if !supportsUserPass {
		_, _ = conn.Write([]byte{socks5Version, socks5AuthNoAcceptable})
		return
	}
	if _, err := conn.Write([]byte{socks5Version, socks5AuthUserPass}); err != nil {
		return
	}

	// Step 2: Read RFC 1929 Username/Password Subnegotiation
	var subHdr [2]byte
	if _, err := io.ReadFull(conn, subHdr[:]); err != nil || subHdr[0] != socks5UserPassVersion {
		return
	}
	uLen := int(subHdr[1])
	if uLen <= 0 || uLen > 255 {
		return
	}
	unameBytes := make([]byte, uLen)
	if _, err := io.ReadFull(conn, unameBytes); err != nil {
		return
	}
	var pLenBuf [1]byte
	if _, err := io.ReadFull(conn, pLenBuf[:]); err != nil {
		return
	}
	pLen := int(pLenBuf[0])
	if pLen <= 0 || pLen > 255 {
		return
	}
	passwdBytes := make([]byte, pLen)
	if _, err := io.ReadFull(conn, passwdBytes); err != nil {
		return
	}

	expectedPasswd := computeSOCKS5PasswdMAC(authKey, unameBytes)
	if subtle.ConstantTimeCompare(passwdBytes, []byte(expectedPasswd)) != 1 {
		_, _ = conn.Write([]byte{socks5UserPassVersion, socks5AuthStatusFail})
		return
	}

	var uMeta socks5UserMetadata
	if json.Unmarshal(unameBytes, &uMeta) != nil {
		_, _ = conn.Write([]byte{socks5UserPassVersion, socks5AuthStatusFail})
		return
	}
	if uMeta.TimeHdr != "" {
		applyMasterTimeHeader(uMeta.TimeHdr)
	}
	if _, err := conn.Write([]byte{socks5UserPassVersion, socks5AuthStatusOK}); err != nil {
		return
	}

	// Step 3: Read RFC 1928 Request -> [VER=0x05][CMD][RSV=0x00][ATYP][DST.ADDR][DST.PORT]
	var reqHdr [4]byte
	if _, err := io.ReadFull(conn, reqHdr[:]); err != nil || reqHdr[0] != socks5Version {
		return
	}
	cmd := reqHdr[1]
	atyp := reqHdr[3]

	var dstHost string
	switch atyp {
	case socks5ATYPIPv4:
		var ip4 [4]byte
		if _, err := io.ReadFull(conn, ip4[:]); err != nil {
			return
		}
		dstHost = net.IP(ip4[:]).String()
	case socks5ATYPDomain:
		var dLen [1]byte
		if _, err := io.ReadFull(conn, dLen[:]); err != nil {
			return
		}
		dom := make([]byte, int(dLen[0]))
		if _, err := io.ReadFull(conn, dom); err != nil {
			return
		}
		dstHost = string(dom)
	case socks5ATYPIPv6:
		var ip6 [16]byte
		if _, err := io.ReadFull(conn, ip6[:]); err != nil {
			return
		}
		dstHost = net.IP(ip6[:]).String()
	default:
		_ = writeSOCKS5Reply(conn, socks5RepCmdNotSupported)
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return
	}
	dstPort := binary.BigEndian.Uint16(portBuf[:])

	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	effectivePeerID := peer.ID
	if uMeta.PeerID != "" {
		effectivePeerID = uMeta.PeerID
	}

	// Engine 1: Probe
	if dstHost == socks5DomainProbe {
		if err := writeSOCKS5Reply(conn, socks5RepSucceeded); err != nil {
			return
		}
		var ping [12]byte
		if _, err := io.ReadFull(conn, ping[:]); err != nil {
			return
		}
		_, _ = conn.Write(ping[:])
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)
		return
	}

	// Engine 1: Parity Sync
	if dstHost == socks5DomainParitySync {
		if err := writeSOCKS5Reply(conn, socks5RepSucceeded); err != nil {
			return
		}
		handleSOCKS5ParitySyncServer(conn, effectivePeerID, remoteHost)
		return
	}

	// Engine 2 requires Traffic Tunnel toggle to be ON
	if !tc.Enabled {
		_ = writeSOCKS5Reply(conn, socks5RepNotAllowed)
		return
	}

	// Engine 2: RFC 1928 UDP Associate / Encapsulated UDP Datagram Stream
	if cmd == socks5CmdUDPAssociate || dstHost == socks5DomainUDPTunnel {
		if err := writeSOCKS5Reply(conn, socks5RepSucceeded); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		if exitMux != nil {
			exitMux.serveUDPTunnelStream(conn, dstPort)
		}
		return
	}

	// Engine 2: Standard RFC 1928 TCP CONNECT (0x01)
	if cmd != socks5CmdConnect {
		_ = writeSOCKS5Reply(conn, socks5RepCmdNotSupported)
		return
	}

	targetPortStr := strconv.Itoa(int(dstPort))
	if dstPort == 0 {
		ports := parsePortList(tc.ForwardPorts)
		if len(ports) > 0 {
			targetPortStr = ports[0]
		} else {
			targetPortStr = "2053"
		}
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", targetPortStr), 5*time.Second)
	if err != nil {
		_ = writeSOCKS5Reply(conn, socks5RepConnectionRefused)
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	if err := writeSOCKS5Reply(conn, socks5RepSucceeded); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	pipeSOCKS5Connections(conn, target, tc.SpeedLimitMBps)
}

// ============================================================================
// 3. ENGINE 1: PROBE & PARITY SYNC OVER SOCKS5
// ============================================================================

func probeSOCKS5(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	conn, err := dialSOCKS5Authenticated(
		peer,
		tc,
		socks5CmdConnect,
		socks5ATYPDomain,
		socks5DomainProbe,
		uint16(tc.ListenPort),
		4*time.Second,
	)
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

func pushSOCKS5ParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	conn, err := dialSOCKS5Authenticated(
		peer,
		tc,
		socks5CmdConnect,
		socks5ATYPDomain,
		socks5DomainParitySync,
		uint16(tc.ListenPort),
		4*time.Second,
	)
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

func handleSOCKS5ParitySyncServer(conn net.Conn, effectivePeerID, remoteHost string) {
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

// ============================================================================
// 4. ENGINE 2: TCP CONNECT & RFC 1928 UDP DATAGRAM FORWARDING
// ============================================================================

func forwardSOCKS5Traffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	portNum, _ := strconv.Atoi(strings.TrimSpace(targetPort))
	if portNum <= 0 {
		portNum = 2053
	}

	conn, err := dialSOCKS5Authenticated(
		peer,
		tc,
		socks5CmdConnect,
		socks5ATYPIPv4,
		"127.0.0.1",
		uint16(portNum),
		5*time.Second,
	)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})

	pipeSOCKS5Connections(conn, client, tc.SpeedLimitMBps)
}

func pipeSOCKS5Connections(socksConn net.Conn, localConn net.Conn, speedLimitMBps string) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	toSOCKS := newThrottledWriter(socksConn, &appTxBytes, mbLimit)
	toLocal := newThrottledWriter(localConn, &appRxBytes, mbLimit)

	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toSOCKS, localConn, buf)
		if tc, ok := socksConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = socksConn.Close()
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toLocal, socksConn, buf)
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = localConn.Close()
		}
		done <- struct{}{}
	}()
	<-done
}

// Builds a genuine RFC 1928 Section 7 UDP Request Header:
// [RSV:2 (0x0000)][FRAG:1 (0x00)][ATYP:1 (0x01)][DST.ADDR:4 (127.0.0.1)][DST.PORT:2][DATA]
func packRFC1928UDPDatagram(targetPort uint16, payload []byte) []byte {
	out := make([]byte, 10+len(payload))
	out[0] = 0x00
	out[1] = 0x00
	out[2] = 0x00 // FRAG = 0
	out[3] = socks5ATYPIPv4
	out[4] = 127
	out[5] = 0
	out[6] = 0
	out[7] = 1
	binary.BigEndian.PutUint16(out[8:10], targetPort)
	copy(out[10:], payload)
	return out
}

func unpackRFC1928UDPDatagram(pkt []byte) (uint16, []byte, error) {
	if len(pkt) < 10 || pkt[2] != 0x00 || pkt[3] != socks5ATYPIPv4 {
		return 0, nil, errors.New("invalid rfc1928 udp header")
	}
	port := binary.BigEndian.Uint16(pkt[8:10])
	return port, pkt[10:], nil
}

type socks5UDPEntrySession struct {
	sessionID    uint32
	clientAddr   *net.UDPAddr
	entryConn    *net.UDPConn
	lastActivity atomic.Int64
}

type socks5UDPEntryManager struct {
	mu          sync.RWMutex
	peer        ServerPeer
	tunnel      TunnelConfig
	targetPort  uint16
	byAddr      map[string]*socks5UDPEntrySession
	bySessionID map[uint32]*socks5UDPEntrySession
	nextID      atomic.Uint32
	connMu      sync.Mutex
	tunnelConn  net.Conn
	limiter     io.Writer
	stopCh      chan struct{}
	closed      atomic.Bool
}

func newSOCKS5UDPEntryManager(peer ServerPeer, tc TunnelConfig, targetPort uint16) *socks5UDPEntryManager {
	m := &socks5UDPEntryManager{
		peer:        peer,
		tunnel:      tc,
		targetPort:  targetPort,
		byAddr:      make(map[string]*socks5UDPEntrySession),
		bySessionID: make(map[uint32]*socks5UDPEntrySession),
		limiter:     newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(tc.SpeedLimitMBps)),
		stopCh:      make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *socks5UDPEntryManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Unix() - int64(socks5UDPIdleTTL.Seconds())
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

func (m *socks5UDPEntryManager) closeAll() {
	if m.closed.Swap(true) {
		return
	}
	close(m.stopCh)
	m.connMu.Lock()
	if m.tunnelConn != nil {
		_ = m.tunnelConn.Close()
		m.tunnelConn = nil
	}
	m.connMu.Unlock()
}

func (m *socks5UDPEntryManager) getOrCreateSession(entryConn *net.UDPConn, clientAddr *net.UDPAddr) *socks5UDPEntrySession {
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
	s := &socks5UDPEntrySession{
		sessionID:  sid,
		clientAddr: addrCopy,
		entryConn:  entryConn,
	}
	s.lastActivity.Store(now)
	m.byAddr[key] = s
	m.bySessionID[sid] = s
	return s
}

func (m *socks5UDPEntryManager) getOrOpenUDPTunnel() (net.Conn, error) {
	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.tunnelConn != nil {
		return m.tunnelConn, nil
	}
	c, err := dialSOCKS5Authenticated(
		m.peer,
		m.tunnel,
		socks5CmdUDPAssociate,
		socks5ATYPDomain,
		socks5DomainUDPTunnel,
		m.targetPort,
		5*time.Second,
	)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	m.tunnelConn = c
	go m.readRepliesLoop(c)
	return c, nil
}

func (m *socks5UDPEntryManager) readRepliesLoop(c net.Conn) {
	defer func() {
		_ = c.Close()
		m.connMu.Lock()
		if m.tunnelConn == c {
			m.tunnelConn = nil
		}
		m.connMu.Unlock()
	}()

	var hdr [6]byte // [SessionID:4][FrameLen:2]
	for {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		sid := binary.BigEndian.Uint32(hdr[0:4])
		frameLen := int(binary.BigEndian.Uint16(hdr[4:6]))
		if frameLen < 10 || frameLen > 65507 {
			return
		}
		rfcPkt := make([]byte, frameLen)
		if _, err := io.ReadFull(c, rfcPkt); err != nil {
			return
		}
		_, payload, err := unpackRFC1928UDPDatagram(rfcPkt)
		if err != nil || len(payload) == 0 {
			continue
		}
		m.mu.RLock()
		sess, ok := m.bySessionID[sid]
		m.mu.RUnlock()
		if ok {
			sess.lastActivity.Store(time.Now().Unix())
			atomic.AddUint64(&appRxBytes, uint64(len(payload)))
			_, _ = sess.entryConn.WriteToUDP(payload, sess.clientAddr)
		}
	}
}

func (m *socks5UDPEntryManager) handleClientPacket(entryConn *net.UDPConn, clientAddr *net.UDPAddr, payload []byte) {
	if len(payload) == 0 || len(payload) > 16384 {
		return
	}
	sess := m.getOrCreateSession(entryConn, clientAddr)
	c, err := m.getOrOpenUDPTunnel()
	if err != nil {
		return
	}
	_, _ = m.limiter.Write(payload)

	rfcPkt := packRFC1928UDPDatagram(m.targetPort, payload)
	frame := make([]byte, 6+len(rfcPkt))
	binary.BigEndian.PutUint32(frame[0:4], sess.sessionID)
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(rfcPkt)))
	copy(frame[6:], rfcPkt)

	m.connMu.Lock()
	_, wErr := c.Write(frame)
	m.connMu.Unlock()
	if wErr != nil {
		_ = c.Close()
	}
}

type socks5UDPExitSession struct {
	sessionID    uint32
	targetPort   uint16
	localConn    *net.UDPConn
	lastActivity atomic.Int64
	closed       atomic.Bool
}

type socks5UDPExitManager struct {
	mu       sync.RWMutex
	sessions map[uint32]*socks5UDPExitSession
	writeMu  sync.Mutex
	limiter  io.Writer
	stopCh   chan struct{}
	closed   atomic.Bool
}

func newSOCKS5UDPExitManager(speedLimitMBps string) *socks5UDPExitManager {
	m := &socks5UDPExitManager{
		sessions: make(map[uint32]*socks5UDPExitSession),
		limiter:  newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(speedLimitMBps)),
		stopCh:   make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *socks5UDPExitManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Unix() - int64(socks5UDPIdleTTL.Seconds())
			m.mu.Lock()
			for sid, s := range m.sessions {
				if s.lastActivity.Load() < cutoff {
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

func (m *socks5UDPExitManager) closeAll() {
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

func (m *socks5UDPExitManager) serveUDPTunnelStream(c net.Conn, defaultPort uint16) {
	defer c.Close()
	var hdr [6]byte
	for {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		sid := binary.BigEndian.Uint32(hdr[0:4])
		frameLen := int(binary.BigEndian.Uint16(hdr[4:6]))
		if frameLen < 10 || frameLen > 65507 {
			return
		}
		rfcPkt := make([]byte, frameLen)
		if _, err := io.ReadFull(c, rfcPkt); err != nil {
			return
		}
		tPort, payload, err := unpackRFC1928UDPDatagram(rfcPkt)
		if err != nil || len(payload) == 0 {
			continue
		}
		if tPort == 0 {
			tPort = defaultPort
		}

		sess, err := m.getOrCreateExitSession(c, sid, tPort)
		if err != nil {
			continue
		}
		sess.lastActivity.Store(time.Now().Unix())
		atomic.AddUint64(&appRxBytes, uint64(len(payload)))
		_, _ = sess.localConn.Write(payload)
	}
}

func (m *socks5UDPExitManager) getOrCreateExitSession(
	tunnelConn net.Conn,
	sid uint32,
	targetPort uint16,
) (*socks5UDPExitSession, error) {
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
	s := &socks5UDPExitSession{
		sessionID:  sid,
		targetPort: targetPort,
		localConn:  localUDP,
	}
	s.lastActivity.Store(now)
	m.sessions[sid] = s

	go func(sess *socks5UDPExitSession) {
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
		buf := make([]byte, 16384)
		for {
			_ = sess.localConn.SetReadDeadline(time.Now().Add(socks5UDPIdleTTL))
			n, err := sess.localConn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				sess.lastActivity.Store(time.Now().Unix())
				_, _ = m.limiter.Write(buf[:n])
				rfcPkt := packRFC1928UDPDatagram(sess.targetPort, buf[:n])
				frame := make([]byte, 6+len(rfcPkt))
				binary.BigEndian.PutUint32(frame[0:4], sess.sessionID)
				binary.BigEndian.PutUint16(frame[4:6], uint16(len(rfcPkt)))
				copy(frame[6:], rfcPkt)

				m.writeMu.Lock()
				_, wErr := tunnelConn.Write(frame)
				m.writeMu.Unlock()
				if wErr != nil {
					return
				}
			}
		}
	}(s)

	return s, nil
}

func startSOCKS5UDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
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

	muxKey := fmt.Sprintf("%s|%d", peer.ID, portNum)
	socks5Mu.Lock()
	if old, ok := socks5EntryUDPMux[muxKey]; ok {
		old.closeAll()
	}
	mgr := newSOCKS5UDPEntryManager(peer, tc, uint16(portNum))
	socks5EntryUDPMux[muxKey] = mgr
	socks5Mu.Unlock()

	go func() {
		defer mgr.closeAll()
		buf := make([]byte, 16384)
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
