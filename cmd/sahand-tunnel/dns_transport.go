package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
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
	// RFC 1035 DNS Header Flags
	dnsFlagsStandardQuery    uint16 = 0x0100 // QR=0, Opcode=0, RD=1
	dnsFlagsStandardResponse uint16 = 0x8180 // QR=1, Opcode=0, AA=0, RD=1, RA=1, RCODE=0

	// RFC 1035 Resource Record Types & Class
	dnsTypeNULL uint16 = 10 // RFC 1035 Section 3.3.10 arbitrary binary RDATA (up to 65535 bytes)
	dnsClassIN  uint16 = 1

	// Tunnel sub-commands inside authenticated DNS RDATA
	dnsCmdProbe      byte = 0x01
	dnsCmdProbeAck   byte = 0x02
	dnsCmdParitySync byte = 0x03
	dnsCmdParityAck  byte = 0x04
	dnsCmdTCPForward byte = 0x05
	dnsCmdUDPData    byte = 0x06

	dnsStatusOK          byte = 0x00
	dnsStatusForbidden   byte = 0x01
	dnsStatusUnreachable byte = 0x02

	dnsMaxChunkPayload = 24 * 1024
	dnsUDPIdleTTL      = 60 * time.Second
)

// Encodes a domain name (e.g. "a1b2.www.speedtest.net") into RFC 1035 length-prefixed labels
func encodeDNSQName(domain string) []byte {
	domain = strings.Trim(strings.TrimSpace(domain), ".")
	if domain == "" {
		domain = "www.speedtest.net"
	}
	parts := strings.Split(domain, ".")
	out := make([]byte, 0, len(domain)+2)
	for _, label := range parts {
		if len(label) == 0 {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0x00) // Root label terminator
	return out
}

// Skips an RFC 1035 QNAME starting at offset idx and returns the new offset
func skipDNSName(pkt []byte, idx int) (int, error) {
	for {
		if idx >= len(pkt) {
			return idx, errors.New("truncated dns name")
		}
		l := int(pkt[idx])
		if l == 0 {
			return idx + 1, nil
		}
		// RFC 1035 Section 4.1.4 compression pointer (0xC0 mask)
		if (l & 0xC0) == 0xC0 {
			if idx+2 > len(pkt) {
				return idx, errors.New("truncated dns pointer")
			}
			return idx + 2, nil
		}
		idx += 1 + l
	}
}

func computeDNSRDATATag(authKey []byte, txID uint16, cmd byte, targetPort uint16, payload []byte) [8]byte {
	var hdr [5]byte
	binary.BigEndian.PutUint16(hdr[0:2], txID)
	hdr[2] = cmd
	binary.BigEndian.PutUint16(hdr[3:5], targetPort)

	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-rfc1035-dns-v1:"))
	_, _ = mac.Write(hdr[:])
	if len(payload) > 64 {
		_, _ = mac.Write(payload[:64])
	} else {
		_, _ = mac.Write(payload)
	}
	sum := mac.Sum(nil)
	var tag [8]byte
	copy(tag[:], sum[:8])
	return tag
}

// Builds a genuine RFC 1035 DNS wire packet (Query or Response) carrying authenticated RDATA
// inside a NULL Resource Record (TYPE=10, CLASS=1).
func buildRFC1035DNSPacket(
	authKey []byte,
	txID uint16,
	isResponse bool,
	qnameDomain string,
	cmd byte,
	targetPort uint16,
	payload []byte,
) []byte {
	qname := encodeDNSQName(qnameDomain)
	tag := computeDNSRDATATag(authKey, txID, cmd, targetPort, payload)

	// RDATA layout: [Cmd:1][TargetPort:2][HMAC-64:8][Payload...]
	rdataLen := 11 + len(payload)

	// 12-byte RFC 1035 Header + Question (len(qname)+4) + Answer RR (12 + rdataLen)
	pkt := make([]byte, 0, 12+len(qname)+4+12+rdataLen)

	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], txID)
	if isResponse {
		binary.BigEndian.PutUint16(hdr[2:4], dnsFlagsStandardResponse)
	} else {
		binary.BigEndian.PutUint16(hdr[2:4], dnsFlagsStandardQuery)
	}
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT = 1
	binary.BigEndian.PutUint16(hdr[6:8], 1) // ANCOUNT = 1 (carries tunnel RDATA)
	binary.BigEndian.PutUint16(hdr[8:10], 0)
	binary.BigEndian.PutUint16(hdr[10:12], 0)
	pkt = append(pkt, hdr[:]...)

	// Question Section: QNAME + QTYPE(NULL=10) + QCLASS(IN=1)
	pkt = append(pkt, qname...)
	var qTail [4]byte
	binary.BigEndian.PutUint16(qTail[0:2], dnsTypeNULL)
	binary.BigEndian.PutUint16(qTail[2:4], dnsClassIN)
	pkt = append(pkt, qTail[:]...)

	// Answer Resource Record: Name Pointer (0xC00C) + TYPE(10) + CLASS(1) + TTL(60) + RDLENGTH + RDATA
	var rrHdr [12]byte
	rrHdr[0] = 0xC0
	rrHdr[1] = 0x0C // Pointer to offset 12 (QNAME)
	binary.BigEndian.PutUint16(rrHdr[2:4], dnsTypeNULL)
	binary.BigEndian.PutUint16(rrHdr[4:6], dnsClassIN)
	binary.BigEndian.PutUint32(rrHdr[6:10], 60) // TTL = 60s
	binary.BigEndian.PutUint16(rrHdr[10:12], uint16(rdataLen))
	pkt = append(pkt, rrHdr[:]...)

	// RDATA
	var rdataHdr [11]byte
	rdataHdr[0] = cmd
	binary.BigEndian.PutUint16(rdataHdr[1:3], targetPort)
	copy(rdataHdr[3:11], tag[:])
	pkt = append(pkt, rdataHdr[:]...)
	pkt = append(pkt, payload...)

	return pkt
}

func parseRFC1035DNSPacket(authKey []byte, pkt []byte) (uint16, byte, uint16, []byte, error) {
	if len(pkt) < 28 {
		return 0, 0, 0, nil, errors.New("dns packet too short")
	}
	txID := binary.BigEndian.Uint16(pkt[0:2])
	qdCount := int(binary.BigEndian.Uint16(pkt[4:6]))
	anCount := int(binary.BigEndian.Uint16(pkt[6:8]))
	if qdCount < 1 || anCount < 1 {
		return 0, 0, 0, nil, errors.New("dns packet missing question or answer section")
	}

	idx := 12
	for q := 0; q < qdCount; q++ {
		nextIdx, err := skipDNSName(pkt, idx)
		if err != nil || nextIdx+4 > len(pkt) {
			return 0, 0, 0, nil, errors.New("invalid dns question section")
		}
		idx = nextIdx + 4
	}

	nextIdx, err := skipDNSName(pkt, idx)
	if err != nil || nextIdx+10 > len(pkt) {
		return 0, 0, 0, nil, errors.New("invalid dns answer section")
	}
	idx = nextIdx
	rdLen := int(binary.BigEndian.Uint16(pkt[idx+8 : idx+10]))
	idx += 10
	if rdLen < 11 || idx+rdLen > len(pkt) {
		return 0, 0, 0, nil, errors.New("truncated dns rdata")
	}

	rdata := pkt[idx : idx+rdLen]
	cmd := rdata[0]
	targetPort := binary.BigEndian.Uint16(rdata[1:3])
	payload := rdata[11:]

	expectedTag := computeDNSRDATATag(authKey, txID, cmd, targetPort, payload)
	if subtle.ConstantTimeCompare(rdata[3:11], expectedTag[:]) != 1 {
		return 0, 0, 0, nil, errors.New("dns rdata hmac mismatch")
	}
	return txID, cmd, targetPort, payload, nil
}

// ============================================================================
// RFC 1035 SECTION 4.2.2 DNS-OVER-TCP STREAM CONN (2-Byte Length Prefixed)
// ============================================================================

type dnsTCPConn struct {
	net.Conn
	readMu     sync.Mutex
	writeMu    sync.Mutex
	authKey    []byte
	isServer   bool
	baseDomain string
	targetPort uint16
	readBuf    bytes.Buffer
}

func newDNSTCPConn(
	c net.Conn,
	authKey []byte,
	isServer bool,
	baseDomain string,
	targetPort uint16,
) *dnsTCPConn {
	if strings.TrimSpace(baseDomain) == "" {
		baseDomain = "www.speedtest.net"
	}
	return &dnsTCPConn{
		Conn:       c,
		authKey:    authKey,
		isServer:   isServer,
		baseDomain: baseDomain,
		targetPort: targetPort,
	}
}

func writeRFC1035TCPMessage(w io.Writer, dnsPkt []byte) error {
	var lenPrefix [2]byte
	binary.BigEndian.PutUint16(lenPrefix[:], uint16(len(dnsPkt)))
	if _, err := w.Write(lenPrefix[:]); err != nil {
		return err
	}
	_, err := w.Write(dnsPkt)
	return err
}

func readRFC1035TCPMessage(r io.Reader) ([]byte, error) {
	var lenPrefix [2]byte
	if _, err := io.ReadFull(r, lenPrefix[:]); err != nil {
		return nil, err
	}
	msgLen := int(binary.BigEndian.Uint16(lenPrefix[:]))
	if msgLen < 28 || msgLen > 65535 {
		return nil, errors.New("invalid dns tcp message length")
	}
	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (dc *dnsTCPConn) Write(p []byte) (int, error) {
	dc.writeMu.Lock()
	defer dc.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > dnsMaxChunkPayload {
			chunk = p[:dnsMaxChunkPayload]
		}
		var txIDBytes [2]byte
		_, _ = rand.Read(txIDBytes[:])
		txID := binary.BigEndian.Uint16(txIDBytes[:])

		qDomain := fmt.Sprintf("t%x.%s", txID, dc.baseDomain)
		dnsPkt := buildRFC1035DNSPacket(dc.authKey, txID, dc.isServer, qDomain, dnsCmdTCPForward, dc.targetPort, chunk)
		if err := writeRFC1035TCPMessage(dc.Conn, dnsPkt); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (dc *dnsTCPConn) Read(p []byte) (int, error) {
	dc.readMu.Lock()
	defer dc.readMu.Unlock()

	if dc.readBuf.Len() > 0 {
		return dc.readBuf.Read(p)
	}
	dnsPkt, err := readRFC1035TCPMessage(dc.Conn)
	if err != nil {
		return 0, err
	}
	_, _, _, payload, err := parseRFC1035DNSPacket(dc.authKey, dnsPkt)
	if err != nil {
		return 0, err
	}
	dc.readBuf.Write(payload)
	return dc.readBuf.Read(p)
}

// ============================================================================
// SERVER LISTENERS (:11316 UDP DNS + TCP DNS)
// ============================================================================

var (
	dnsTransportMu         sync.RWMutex
	dnsTransportExitMuxes  = make(map[string]*udpRelayExitManager)
	dnsTransportEntryMuxes = make(map[string]*dnsUDPEntryManager)
)

func stopDNSTransportPeerResources(peerID string) {
	dnsTransportMu.Lock()
	if exitMux, ok := dnsTransportExitMuxes[peerID]; ok {
		exitMux.closeAll()
		delete(dnsTransportExitMuxes, peerID)
	}
	for k, entryMux := range dnsTransportEntryMuxes {
		if strings.HasPrefix(k, peerID+"|") {
			entryMux.closeAll()
			delete(dnsTransportEntryMuxes, k)
		}
	}
	dnsTransportMu.Unlock()
}

func startDNSTransportServer(peer ServerPeer, tc TunnelConfig) (net.PacketConn, net.Listener) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))

	dnsTransportMu.Lock()
	if old, ok := dnsTransportExitMuxes[peer.ID]; ok {
		old.closeAll()
	}
	exitMux := newUDPRelayExitManager(tc.SpeedLimitMBps)
	dnsTransportExitMuxes[peer.ID] = exitMux
	dnsTransportMu.Unlock()

	var boundUDP net.PacketConn
	if uAddr, err := net.ResolveUDPAddr("udp", listenAddr); err == nil {
		if uConn, err := net.ListenUDP("udp", uAddr); err == nil {
			configureUDPSocketBuffers(uConn)
			boundUDP = uConn
			go serveDNSUDPServer(uConn, peer, tc)
		}
	}

	var boundTCP net.Listener
	if tLn, err := net.Listen("tcp", listenAddr); err == nil {
		boundTCP = tLn
		go func() {
			for {
				conn, err := tLn.Accept()
				if err != nil {
					return
				}
				enableKeepAlive(conn)
				go handleIncomingDNSTCPConn(conn, peer, tc)
			}
		}()
	}

	return boundUDP, boundTCP
}

func serveDNSUDPServer(uConn *net.UDPConn, peer ServerPeer, tc TunnelConfig) {
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := uConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 28 {
			continue
		}
		pktCopy := make([]byte, n)
		copy(pktCopy, buf[:n])

		stateMu.RLock()
		cfgSnapshot := appCfg
		stateMu.RUnlock()

		authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
		if err != nil {
			continue
		}

		txID, cmd, targetPort, payload, err := parseRFC1035DNSPacket(authKey, pktCopy)
		if err != nil {
			continue
		}

		baseDomain := strings.TrimSpace(tc.SNI)
		if baseDomain == "" {
			baseDomain = "www.speedtest.net"
		}

		switch cmd {
		case dnsCmdProbe:
			if len(payload) > 0 {
				applyMasterTimeHeader(string(payload))
			}
			markPeerConnectedInbound(peer.ID, clientAddr.IP.String(), tc.ID, tc.ListenPort, 1)
			respPkt := buildRFC1035DNSPacket(authKey, txID, true, baseDomain, dnsCmdProbeAck, targetPort, []byte(buildMasterTimeHeader()))
			_, _ = uConn.WriteToUDP(respPkt, clientAddr)

		case dnsCmdUDPData:
			if !tc.Enabled || len(payload) < 4 {
				continue
			}
			sid := binary.BigEndian.Uint32(payload[0:4])
			rawUDP := payload[4:]
			go forwardDNSUDPPacketToLocal(uConn, clientAddr, authKey, txID, baseDomain, sid, targetPort, tc.ForwardPorts, rawUDP)
		}
	}
}

func forwardDNSUDPPacketToLocal(
	uConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	authKey []byte,
	txID uint16,
	baseDomain string,
	sid uint32,
	targetPort uint16,
	defaultPorts string,
	rawUDP []byte,
) {
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
	atomic.AddUint64(&appRxBytes, uint64(len(rawUDP)))
	dstAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(targetPort)}
	localUDP, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		return
	}
	defer localUDP.Close()
	_ = localUDP.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := localUDP.Write(rawUDP); err != nil {
		return
	}
	rep := make([]byte, 16384)
	n, err := localUDP.Read(rep)
	if err == nil && n > 0 {
		atomic.AddUint64(&appTxBytes, uint64(n))
		body := make([]byte, 4+n)
		binary.BigEndian.PutUint32(body[0:4], sid)
		copy(body[4:], rep[:n])
		respPkt := buildRFC1035DNSPacket(authKey, txID, true, baseDomain, dnsCmdUDPData, targetPort, body)
		_, _ = uConn.WriteToUDP(respPkt, clientAddr)
	}
}

func handleIncomingDNSTCPConn(conn net.Conn, peer ServerPeer, tc TunnelConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return
	}

	firstMsg, err := readRFC1035TCPMessage(conn)
	if err != nil {
		return
	}
	txID, cmd, targetPort, payload, err := parseRFC1035DNSPacket(authKey, firstMsg)
	if err != nil {
		return
	}

	baseDomain := strings.TrimSpace(tc.SNI)
	if baseDomain == "" {
		baseDomain = "www.speedtest.net"
	}
	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	switch cmd {
	case dnsCmdProbe:
		if len(payload) > 0 {
			applyMasterTimeHeader(string(payload))
		}
		markPeerConnectedInbound(peer.ID, remoteHost, tc.ID, tc.ListenPort, 1)
		ack := buildRFC1035DNSPacket(authKey, txID, true, baseDomain, dnsCmdProbeAck, targetPort, []byte(buildMasterTimeHeader()))
		_ = writeRFC1035TCPMessage(conn, ack)

	case dnsCmdParitySync:
		var pkt SyncPacket
		if json.Unmarshal(payload, &pkt) != nil {
			return
		}
		resp := processIncomingSync(peer.ID, remoteHost, pkt)
		respBytes, err := json.Marshal(resp)
		if err != nil {
			return
		}
		ack := buildRFC1035DNSPacket(authKey, txID, true, baseDomain, dnsCmdParityAck, targetPort, respBytes)
		_ = writeRFC1035TCPMessage(conn, ack)

	case dnsCmdTCPForward:
		if !tc.Enabled {
			ack := buildRFC1035DNSPacket(authKey, txID, true, baseDomain, dnsCmdTCPForward, targetPort, []byte{dnsStatusForbidden})
			_ = writeRFC1035TCPMessage(conn, ack)
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
			ack := buildRFC1035DNSPacket(authKey, txID, true, baseDomain, dnsCmdTCPForward, targetPort, []byte{dnsStatusUnreachable})
			_ = writeRFC1035TCPMessage(conn, ack)
			return
		}
		defer target.Close()
		enableKeepAlive(target)

		ack := buildRFC1035DNSPacket(authKey, txID, true, baseDomain, dnsCmdTCPForward, targetPort, []byte{dnsStatusOK})
		if err := writeRFC1035TCPMessage(conn, ack); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})

		dnsStream := newDNSTCPConn(conn, authKey, true, baseDomain, targetPort)
		pipeRawTCPStreams(dnsStream, target, tc.SpeedLimitMBps)
	}
}

// ============================================================================
// ENGINE 1: PROBE & PARITY SYNC OVER DNS TRANSPORT
// ============================================================================

func probeDNSTransport(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		res.Success = false
		res.ErrorReason = "Authentication failure"
		return res
	}

	baseDomain := strings.TrimSpace(tc.SNI)
	if baseDomain == "" {
		baseDomain = "www.speedtest.net"
	}
	targetAddr := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))

	// 1. Primary: RFC 1035 UDP DNS Query/Response Probe
	if rAddr, err := net.ResolveUDPAddr("udp", targetAddr); err == nil {
		if uConn, err := net.DialUDP("udp", nil, rAddr); err == nil {
			start := time.Now()
			_ = uConn.SetDeadline(time.Now().Add(2000 * time.Millisecond))
			txID := uint16(1 + randomIntN(60000))
			qDomain := fmt.Sprintf("q%x.%s", txID, baseDomain)
			pkt := buildRFC1035DNSPacket(authKey, txID, false, qDomain, dnsCmdProbe, uint16(tc.ListenPort), []byte(buildMasterTimeHeader()))
			if _, wErr := uConn.Write(pkt); wErr == nil {
				rep := make([]byte, 2048)
				if n, rErr := uConn.Read(rep); rErr == nil && n >= 28 {
					rTxID, rCmd, _, rPayload, pErr := parseRFC1035DNSPacket(authKey, rep[:n])
					if pErr == nil && rTxID == txID && rCmd == dnsCmdProbeAck {
						if len(rPayload) > 0 {
							applyMasterTimeHeader(string(rPayload))
						}
						_ = uConn.Close()
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
			_ = uConn.Close()
		}
	}

	// 2. Fallback: RFC 1035 Section 4.2.2 TCP DNS Probe
	start := time.Now()
	conn, err := net.DialTimeout("tcp", targetAddr, 3500*time.Millisecond)
	if err != nil {
		res.Success = false
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}
	defer conn.Close()
	enableKeepAlive(conn)
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	txID := uint16(1 + randomIntN(60000))
	qDomain := fmt.Sprintf("q%x.%s", txID, baseDomain)
	pkt := buildRFC1035DNSPacket(authKey, txID, false, qDomain, dnsCmdProbe, uint16(tc.ListenPort), []byte(buildMasterTimeHeader()))
	if err := writeRFC1035TCPMessage(conn, pkt); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}
	rep, err := readRFC1035TCPMessage(conn)
	if err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}
	rTxID, rCmd, _, rPayload, err := parseRFC1035DNSPacket(authKey, rep)
	if err != nil || rTxID != txID || rCmd != dnsCmdProbeAck {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}
	if len(rPayload) > 0 {
		applyMasterTimeHeader(string(rPayload))
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

func pushDNSTransportParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	stateMu.RLock()
	cfgSnapshot := appCfg
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return false
	}

	targetAddr := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))
	conn, err := net.DialTimeout("tcp", targetAddr, 4*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	enableKeepAlive(conn)
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

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

	baseDomain := strings.TrimSpace(tc.SNI)
	if baseDomain == "" {
		baseDomain = "www.speedtest.net"
	}
	txID := uint16(1 + randomIntN(60000))
	qDomain := fmt.Sprintf("sync%x.%s", txID, baseDomain)

	dnsMsg := buildRFC1035DNSPacket(authKey, txID, false, qDomain, dnsCmdParitySync, uint16(tc.ListenPort), rawPkt)
	if err := writeRFC1035TCPMessage(conn, dnsMsg); err != nil {
		return false
	}
	repMsg, err := readRFC1035TCPMessage(conn)
	if err != nil {
		return false
	}
	rTxID, rCmd, _, rPayload, err := parseRFC1035DNSPacket(authKey, repMsg)
	if err != nil || rTxID != txID || rCmd != dnsCmdParityAck {
		return false
	}

	var resp SyncResponse
	if json.Unmarshal(rPayload, &resp) != nil || !resp.OK {
		return false
	}
	applySyncResponseToPeer(peer.ID, resp)
	return true
}

// ============================================================================
// ENGINE 2: TCP & UDP FORWARDING OVER DNS TRANSPORT
// ============================================================================

func forwardDNSTransportTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return
	}

	portNum, _ := strconv.Atoi(strings.TrimSpace(targetPort))
	if portNum <= 0 {
		portNum = 2053
	}

	targetAddr := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))
	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	enableKeepAlive(conn)
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	baseDomain := strings.TrimSpace(tc.SNI)
	if baseDomain == "" {
		baseDomain = "www.speedtest.net"
	}
	txID := uint16(1 + randomIntN(60000))
	qDomain := fmt.Sprintf("c%x.%s", txID, baseDomain)

	openPkt := buildRFC1035DNSPacket(authKey, txID, false, qDomain, dnsCmdTCPForward, uint16(portNum), []byte("OPEN"))
	if err := writeRFC1035TCPMessage(conn, openPkt); err != nil {
		return
	}
	repPkt, err := readRFC1035TCPMessage(conn)
	if err != nil {
		return
	}
	_, rCmd, _, rPayload, err := parseRFC1035DNSPacket(authKey, repPkt)
	if err != nil || rCmd != dnsCmdTCPForward || len(rPayload) == 0 || rPayload[0] != dnsStatusOK {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	dnsStream := newDNSTCPConn(conn, authKey, false, baseDomain, uint16(portNum))
	pipeRawTCPStreams(dnsStream, client, tc.SpeedLimitMBps)
}

type dnsUDPEntryManager struct {
	peer       ServerPeer
	tunnel     TunnelConfig
	targetPort uint16
	limiter    io.Writer
	closed     atomic.Bool
}

func (m *dnsUDPEntryManager) closeAll() {
	m.closed.Store(true)
}

func startDNSTransportUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
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
	dnsTransportMu.Lock()
	if old, ok := dnsTransportEntryMuxes[muxKey]; ok {
		old.closeAll()
	}
	mgr := &dnsUDPEntryManager{
		peer:       peer,
		tunnel:     tc,
		targetPort: uint16(portNum),
		limiter:    newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(tc.SpeedLimitMBps)),
	}
	dnsTransportEntryMuxes[muxKey] = mgr
	dnsTransportMu.Unlock()

	go func() {
		buf := make([]byte, 16384)
		for {
			n, clientAddr, err := entryConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 && !mgr.closed.Load() {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				go mgr.forwardSingleDNSUDPPacket(entryConn, clientAddr, chunk)
			}
		}
	}()
	return entryConn
}

func (m *dnsUDPEntryManager) forwardSingleDNSUDPPacket(
	entryConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	chunk []byte,
) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, m.peer)
	if err != nil {
		return
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(strings.TrimSpace(m.peer.IP), strconv.Itoa(m.tunnel.ListenPort)))
	if err != nil {
		return
	}
	remConn, err := net.DialUDP("udp", nil, remoteUDPAddr)
	if err != nil {
		return
	}
	defer remConn.Close()
	_ = remConn.SetDeadline(time.Now().Add(4 * time.Second))

	_, _ = m.limiter.Write(chunk)
	txID := uint16(1 + randomIntN(60000))
	baseDomain := strings.TrimSpace(m.tunnel.SNI)
	if baseDomain == "" {
		baseDomain = "www.speedtest.net"
	}
	qDomain := fmt.Sprintf("u%x.%s", txID, baseDomain)

	body := make([]byte, 4+len(chunk))
	binary.BigEndian.PutUint32(body[0:4], uint32(txID))
	copy(body[4:], chunk)

	dnsPkt := buildRFC1035DNSPacket(authKey, txID, false, qDomain, dnsCmdUDPData, m.targetPort, body)
	if _, err := remConn.Write(dnsPkt); err != nil {
		return
	}
	rep := make([]byte, 16384)
	n, err := remConn.Read(rep)
	if err != nil || n < 28 {
		return
	}
	rTxID, rCmd, _, rPayload, err := parseRFC1035DNSPacket(authKey, rep[:n])
	if err == nil && rTxID == txID && rCmd == dnsCmdUDPData && len(rPayload) > 4 {
		replyData := rPayload[4:]
		atomic.AddUint64(&appRxBytes, uint64(len(replyData)))
		_, _ = entryConn.WriteToUDP(replyData, clientAddr)
	}
}
