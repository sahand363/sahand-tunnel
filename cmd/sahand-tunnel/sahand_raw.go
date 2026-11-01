package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	sahandRawVersion byte   = 0x01
	sahandRawMagic   uint16 = 0x5352 // 'S''R'

	// Explicit transport selection modes
	RawTransportModeAuto  = "auto"
	RawTransportModeRawIP = "raw_ip"
	RawTransportModeUDP   = "udp"

	// Explicit backend identifiers
	RawBackendNameRawIP       = "RAW_IP"
	RawBackendNameUDPFallback = "UDP_FALLBACK"

	// Raw TCP Header flags (RFC 793)
	rawTCPFlagFIN byte = 0x01
	rawTCPFlagSYN byte = 0x02
	rawTCPFlagRST byte = 0x04
	rawTCPFlagPSH byte = 0x08
	rawTCPFlagACK byte = 0x10

	// SAHAND-RAW Wire Packet Types
	rawPktHandshakeInit byte = 0x01
	rawPktHandshakeResp byte = 0x02
	rawPktData          byte = 0x03
	rawPktRekey         byte = 0x04
	rawPktSelfTest      byte = 0x7F

	// Encrypted ARQ & Multiplexer Commands
	rawARQCmdStreamOpen    byte = 0x01
	rawARQCmdStreamOpenAck byte = 0x02
	rawARQCmdStreamData    byte = 0x03
	rawARQCmdStreamFIN     byte = 0x04
	rawARQCmdStreamRST     byte = 0x05
	rawARQCmdACK           byte = 0x06
	rawARQCmdPing          byte = 0x07
	rawARQCmdPong          byte = 0x08
	rawARQCmdUDPDatagram   byte = 0x09
	rawARQCmdProbe         byte = 0x0A
	rawARQCmdProbeAck      byte = 0x0B

	// Reserved virtual port for multiplexed Parity Sync streams
	rawARQPortParitySync uint16 = 0xFFFF

	rawTCPHeaderLen      = 20
	rawEnvelopeHeaderLen = 18
	rawUDPFrameHeaderLen = 8
	rawARQHeaderLen      = 17

	// MTU & Buffer bounds (clamped to prevent IP fragmentation over PPPoE/GRE/VPN)
	rawMaxWireMTU          = 1280
	rawMaxFragmentPayload  = 1024
	rawRekeyPacketInterval = 32768
	rawStreamBufferCap     = 256
	rawSessionIdleTTL      = 90 * time.Second
)

var rawPacketBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	cp := make(net.IP, len(ip))
	copy(cp, ip)
	return cp
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   cloneIP(addr.IP),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func normalizeRawTransportMode(raw string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch mode {
	case "", RawTransportModeAuto:
		return RawTransportModeAuto, nil
	case RawTransportModeRawIP:
		return RawTransportModeRawIP, nil
	case RawTransportModeUDP:
		return RawTransportModeUDP, nil
	default:
		return "", fmt.Errorf("invalid SAHAND-RAW transport mode %q (expected raw_ip, udp, or auto)", raw)
	}
}

// ============================================================================
// LAYER A: PACKET ENGINE & INDEPENDENT TRANSPORT BACKENDS (RAW_IP vs UDP_FALLBACK)
// ============================================================================

type rawTCPPacket struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32
	AckNum   uint32
	Flags    byte
	Window   uint16
	Checksum uint16
	Urgent   uint16
	Payload  []byte
}

// Computes the RFC 1071 16-bit one's complement checksum over the IPv4 or IPv6
// pseudo-header + TCP header + payload.
func computeRFC1071TCPChecksum(srcIP, dstIP net.IP, tcpHeaderAndPayload []byte) uint16 {
	var sum uint32
	tcpLen := uint32(len(tcpHeaderAndPayload))

	if ip4Src := srcIP.To4(); ip4Src != nil {
		ip4Dst := dstIP.To4()
		if ip4Dst == nil {
			ip4Dst = net.IPv4zero.To4()
		}
		sum += uint32(binary.BigEndian.Uint16(ip4Src[0:2]))
		sum += uint32(binary.BigEndian.Uint16(ip4Src[2:4]))
		sum += uint32(binary.BigEndian.Uint16(ip4Dst[0:2]))
		sum += uint32(binary.BigEndian.Uint16(ip4Dst[2:4]))
		sum += uint32(6) // IPPROTO_TCP
		sum += tcpLen
	} else if ip6Src := srcIP.To16(); ip6Src != nil {
		ip6Dst := dstIP.To16()
		if ip6Dst == nil {
			ip6Dst = net.IPv6zero
		}
		for i := 0; i < 16; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(ip6Src[i : i+2]))
			sum += uint32(binary.BigEndian.Uint16(ip6Dst[i : i+2]))
		}
		sum += tcpLen >> 16
		sum += tcpLen & 0xFFFF
		sum += uint32(6) // Next Header: TCP
	}

	limit := len(tcpHeaderAndPayload) - 1
	for i := 0; i < limit; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpHeaderAndPayload[i : i+2]))
	}
	if len(tcpHeaderAndPayload)%2 == 1 {
		sum += uint32(tcpHeaderAndPayload[len(tcpHeaderAndPayload)-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func encodeRawTCPPacket(pkt rawTCPPacket) ([]byte, error) {
	if len(pkt.Payload) > rawMaxWireMTU {
		return nil, errors.New("raw packet payload exceeds MTU")
	}
	if len(pkt.SrcIP) == 0 || len(pkt.DstIP) == 0 {
		return nil, errors.New("raw TCP packet requires valid source and destination IPs for checksum calculation")
	}
	totalLen := rawTCPHeaderLen + len(pkt.Payload)
	out := make([]byte, totalLen)

	binary.BigEndian.PutUint16(out[0:2], pkt.SrcPort)
	binary.BigEndian.PutUint16(out[2:4], pkt.DstPort)
	binary.BigEndian.PutUint32(out[4:8], pkt.SeqNum)
	binary.BigEndian.PutUint32(out[8:12], pkt.AckNum)
	out[12] = (rawTCPHeaderLen / 4) << 4 // Data offset = 5 (20 bytes)
	out[13] = pkt.Flags
	win := pkt.Window
	if win == 0 {
		win = 65535
	}
	binary.BigEndian.PutUint16(out[14:16], win)
	binary.BigEndian.PutUint16(out[16:18], 0)
	binary.BigEndian.PutUint16(out[18:20], pkt.Urgent)
	copy(out[rawTCPHeaderLen:], pkt.Payload)

	csum := computeRFC1071TCPChecksum(pkt.SrcIP, pkt.DstIP, out)
	binary.BigEndian.PutUint16(out[16:18], csum)
	return out, nil
}

func decodeRawTCPPacket(srcIP, dstIP net.IP, raw []byte, verifyChecksum bool) (rawTCPPacket, error) {
	var pkt rawTCPPacket
	if len(raw) < rawTCPHeaderLen {
		return pkt, errors.New("packet shorter than 20-byte TCP header")
	}
	dataOffset := int(raw[12]>>4) * 4
	if dataOffset < rawTCPHeaderLen || len(raw) < dataOffset {
		return pkt, errors.New("invalid TCP data offset")
	}

	pkt.SrcIP = cloneIP(srcIP)
	pkt.DstIP = cloneIP(dstIP)
	pkt.SrcPort = binary.BigEndian.Uint16(raw[0:2])
	pkt.DstPort = binary.BigEndian.Uint16(raw[2:4])
	pkt.SeqNum = binary.BigEndian.Uint32(raw[4:8])
	pkt.AckNum = binary.BigEndian.Uint32(raw[8:12])
	pkt.Flags = raw[13]
	pkt.Window = binary.BigEndian.Uint16(raw[14:16])
	pkt.Checksum = binary.BigEndian.Uint16(raw[16:18])
	pkt.Urgent = binary.BigEndian.Uint16(raw[18:20])

	if pkt.Flags&rawTCPFlagRST != 0 {
		return pkt, errors.New("ignoring TCP RST packet")
	}
	if pkt.SrcPort == 0 || pkt.DstPort == 0 {
		return pkt, errors.New("invalid zero TCP source or destination port")
	}

	if verifyChecksum {
		if len(srcIP) == 0 || len(dstIP) == 0 {
			return pkt, errors.New("missing source or destination IP for TCP checksum verification")
		}
		verifyCopy := make([]byte, len(raw))
		copy(verifyCopy, raw)
		binary.BigEndian.PutUint16(verifyCopy[16:18], 0)
		expected := computeRFC1071TCPChecksum(srcIP, dstIP, verifyCopy)
		if pkt.Checksum != expected {
			return pkt, fmt.Errorf("TCP checksum mismatch: got 0x%04x, expected 0x%04x", pkt.Checksum, expected)
		}
	}

	payload := make([]byte, len(raw)-dataOffset)
	copy(payload, raw[dataOffset:])
	pkt.Payload = payload
	return pkt, nil
}

// Extracts the TCP segment and source/destination IPv4 addresses from a raw socket read buffer,
// handling both stripped TCP segments (returned by Go's net.IPConn.ReadFromIP) and raw IPv4-prefixed packets.
func extractTCPFromRawIPBuffer(raw []byte, fromIP net.IP, defaultDstIP net.IP) (srcIP, dstIP net.IP, tcpSeg []byte, err error) {
	if len(raw) < rawTCPHeaderLen {
		return nil, nil, nil, errors.New("raw IP buffer shorter than TCP header")
	}

	// Check if an outer IPv4 header is present by inspecting Version==4, Protocol==6 (TCP),
	// TotalLength==len(raw), and verifying that the SAHAND-RAW magic sits after the IPv4+TCP headers.
	if len(raw) >= 40 && (raw[0]>>4) == 4 {
		ihl := int(raw[0]&0x0F) * 4
		totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
		proto := raw[9]
		if ihl >= 20 && proto == 6 && totalLen == len(raw) && len(raw) >= ihl+rawTCPHeaderLen {
			tcpOffset := int(raw[ihl+12]>>4) * 4
			if tcpOffset >= rawTCPHeaderLen && len(raw) >= ihl+tcpOffset+3 {
				if binary.BigEndian.Uint16(raw[ihl+tcpOffset:ihl+tcpOffset+2]) == sahandRawMagic &&
					raw[ihl+tcpOffset+2] == sahandRawVersion {
					sIP := cloneIP( net.IP(raw[12:16]).To4() )
					dIP := cloneIP( net.IP(raw[16:20]).To4() )
					return sIP, dIP, raw[ihl:], nil
				}
			}
		}
	}

	sIP := cloneIP(fromIP.To4())
	dIP := cloneIP(defaultDstIP.To4())
	if sIP != nil && sIP.IsLoopback() {
		dIP = net.IPv4(127, 0, 0, 1).To4()
	}
	return sIP, dIP, raw, nil
}

func resolveOutboundInterfaceIP(remoteHost string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(remoteHost))
	if ip != nil && ip.IsLoopback() {
		return net.IPv4(127, 0, 0, 1).To4()
	}
	network := "udp4"
	target := "8.8.8.8:53"
	if ip != nil {
		if ip.To4() == nil {
			network = "udp6"
		}
		target = net.JoinHostPort(ip.String(), "80")
	}
	c, err := net.DialTimeout(network, target, 500*time.Millisecond)
	if err != nil {
		return net.IPv4(127, 0, 0, 1).To4()
	}
	defer c.Close()
	if udpAddr, ok := c.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP != nil {
		if ip4 := udpAddr.IP.To4(); ip4 != nil {
			return cloneIP(ip4)
		}
		return cloneIP(udpAddr.IP)
	}
	return net.IPv4(127, 0, 0, 1).To4()
}

// Manages Linux iptables rules to suppress kernel-generated TCP RST packets
// when the RAW_IP backend is active on a port.
type rawKernelRSTGuard struct {
	port    int
	applied bool
}

func acquireKernelRSTGuard(port int) (*rawKernelRSTGuard, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("kernel RST suppression requires Linux iptables")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d for kernel RST guard", port)
	}
	g := &rawKernelRSTGuard{port: port}
	portStr := strconv.Itoa(port)

	checkCmd := exec.Command("iptables", "-C", "OUTPUT", "-p", "tcp", "--sport", portStr, "--tcp-flags", "RST", "RST", "-j", "DROP")
	if checkCmd.Run() == nil {
		return g, nil
	}

	addCmd := exec.Command("iptables", "-I", "OUTPUT", "-p", "tcp", "--sport", portStr, "--tcp-flags", "RST", "RST", "-j", "DROP")
	if err := addCmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to install iptables TCP RST drop rule on port %d: %w", port, err)
	}
	g.applied = true
	return g, nil
}

func (g *rawKernelRSTGuard) release() {
	if g == nil || !g.applied || runtime.GOOS != "linux" || g.port <= 0 {
		return
	}
	portStr := strconv.Itoa(g.port)
	_ = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", portStr, "--tcp-flags", "RST", "RST", "-j", "DROP").Run()
	g.applied = false
}

// Transport Backend Abstraction
type rawInboundPacket struct {
	Payload    []byte
	SenderAddr *net.UDPAddr
	TCPSeq     uint32
	TCPAck     uint32
	TCPFlags   byte
}

type rawTransportBackend interface {
	BackendName() string
	TransportMode() string
	FallbackReason() string
	LocalPort() uint16
	SendPacket(dstAddr *net.UDPAddr, seq, ack uint32, flags byte, payload []byte) error
	ReceivePacket(deadline time.Time) (rawInboundPacket, error)
	Close() error
}

// Low-level raw IP packet socket interface (implemented by *net.IPConn in production
// and testable via in-memory raw IP link in unit tests without root).
type rawIPConnHandle interface {
	ReadFromIP(b []byte) (int, *net.IPAddr, error)
	WriteToIP(b []byte, addr *net.IPAddr) (int, error)
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Close() error
}

var (
	rawIPTestHookMu      sync.RWMutex
	rawIPCustomDialer    func(listenIP net.IP, localPort uint16) (rawIPConnHandle, error)
	rawIPSkipIPTablesForTest atomic.Bool
)

// ============================================================================
// BACKEND A: RAW_IP (Bidirectional Linux IPv4 Raw TCP Socket Backend)
// ============================================================================

type rawIPSocketBackend struct {
	localIP        net.IP
	localPort      uint16
	expectedPeerIP net.IP
	rawConn        rawIPConnHandle
	rstGuard       *rawKernelRSTGuard
	writeMu        sync.Mutex
	closed         atomic.Bool
}

func allocateEphemeralRawTCPPort() uint16 {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err == nil {
		p := uint16(ln.Addr().(*net.TCPAddr).Port)
		_ = ln.Close()
		if p >= 1024 {
			return p
		}
	}
	return uint16(42000 + randomIntN(16000))
}

func newRawIPSocketBackend(listenIP string, port int, peerIP net.IP) (*rawIPSocketBackend, error) {
	rawIPTestHookMu.RLock()
	customDialer := rawIPCustomDialer
	rawIPTestHookMu.RUnlock()

	if customDialer == nil && runtime.GOOS != "linux" {
		return nil, errors.New("RAW_IP backend requires Linux ip4:tcp raw socket support")
	}

	actualPort := uint16(port)
	if actualPort == 0 {
		actualPort = allocateEphemeralRawTCPPort()
	}

	resolvedLocalIP := net.ParseIP(strings.TrimSpace(listenIP))
	if resolvedLocalIP == nil || resolvedLocalIP.IsUnspecified() {
		if len(peerIP) > 0 && !peerIP.IsUnspecified() {
			resolvedLocalIP = resolveOutboundInterfaceIP(peerIP.String())
		} else {
			resolvedLocalIP = resolveOutboundInterfaceIP("8.8.8.8")
		}
	}
	resolvedLocalIP = resolvedLocalIP.To4()
	if resolvedLocalIP == nil {
		resolvedLocalIP = net.IPv4(127, 0, 0, 1).To4()
	}

	var rstGuard *rawKernelRSTGuard
	if !rawIPSkipIPTablesForTest.Load() {
		var err error
		rstGuard, err = acquireKernelRSTGuard(int(actualPort))
		if err != nil {
			return nil, fmt.Errorf("kernel RST guard failed: %w", err)
		}
	}

	var handle rawIPConnHandle
	if customDialer != nil {
		var err error
		handle, err = customDialer(resolvedLocalIP, actualPort)
		if err != nil {
			if rstGuard != nil {
				rstGuard.release()
			}
			return nil, err
		}
	} else {
		bindAddr := &net.IPAddr{IP: net.IPv4zero}
		if ip := net.ParseIP(strings.TrimSpace(listenIP)); ip != nil && !ip.IsUnspecified() {
			if ip4 := ip.To4(); ip4 != nil {
				bindAddr = &net.IPAddr{IP: ip4}
			}
		}
		ipConn, err := net.ListenIP("ip4:tcp", bindAddr)
		if err != nil {
			if rstGuard != nil {
				rstGuard.release()
			}
			return nil, fmt.Errorf("ip4:tcp raw socket listen failed: %w", err)
		}
		_ = ipConn.SetReadBuffer(4 * 1024 * 1024)
		_ = ipConn.SetWriteBuffer(4 * 1024 * 1024)
		handle = ipConn
	}

	var peerIPv4 net.IP
	if len(peerIP) > 0 {
		peerIPv4 = cloneIP(peerIP.To4())
	}

	b := &rawIPSocketBackend{
		localIP:        cloneIP(resolvedLocalIP),
		localPort:      actualPort,
		expectedPeerIP: peerIPv4,
		rawConn:        handle,
		rstGuard:       rstGuard,
	}

	// Verify that RAW_IP can actually transmit, capture, filter, and checksum-validate
	// a real raw TCP packet before reporting the backend as operational.
	if err := b.verifySelfTest(); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("RAW_IP operational self-test failed: %w", err)
	}

	return b, nil
}

func (b *rawIPSocketBackend) verifySelfTest() error {
	var token [16]byte
	if _, err := io.ReadFull(rand.Reader, token[:]); err != nil {
		return err
	}

	probeWire := make([]byte, rawEnvelopeHeaderLen+len(token))
	binary.BigEndian.PutUint16(probeWire[0:2], sahandRawMagic)
	probeWire[2] = sahandRawVersion
	probeWire[3] = rawPktSelfTest
	copy(probeWire[rawEnvelopeHeaderLen:], token[:])

	loopbackDst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: int(b.localPort)}
	if err := b.SendPacket(loopbackDst, 1, 1, rawTCPFlagPSH|rawTCPFlagACK, probeWire); err != nil {
		return fmt.Errorf("self-test raw transmit failed: %w", err)
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		pkt, err := b.receiveInternal(deadline, true)
		if err != nil {
			return fmt.Errorf("self-test raw receive failed: %w", err)
		}
		if len(pkt.Payload) == len(probeWire) &&
			pkt.Payload[3] == rawPktSelfTest &&
			subtle.ConstantTimeCompare(pkt.Payload[rawEnvelopeHeaderLen:], token[:]) == 1 {
			return nil
		}
	}
	return errors.New("self-test packet was not received on ip4:tcp socket")
}

func (b *rawIPSocketBackend) BackendName() string {
	return RawBackendNameRawIP
}

func (b *rawIPSocketBackend) TransportMode() string {
	return RawTransportModeRawIP
}

func (b *rawIPSocketBackend) FallbackReason() string {
	return ""
}

func (b *rawIPSocketBackend) LocalPort() uint16 {
	return b.localPort
}

func (b *rawIPSocketBackend) SendPacket(dstAddr *net.UDPAddr, seq, ack uint32, flags byte, payload []byte) error {
	if b.closed.Load() || dstAddr == nil {
		return net.ErrClosed
	}
	dstIP := dstAddr.IP.To4()
	if dstIP == nil {
		return errors.New("RAW_IP backend requires an IPv4 destination address")
	}
	if dstAddr.Port <= 0 || dstAddr.Port > 65535 {
		return errors.New("RAW_IP backend requires a valid destination port")
	}

	srcIP := b.localIP
	if dstIP.IsLoopback() {
		srcIP = net.IPv4(127, 0, 0, 1).To4()
	}

	rawSegment, err := encodeRawTCPPacket(rawTCPPacket{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: b.localPort,
		DstPort: uint16(dstAddr.Port),
		SeqNum:  seq,
		AckNum:  ack,
		Flags:   flags,
		Window:  65535,
		Payload: payload,
	})
	if err != nil {
		return err
	}

	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	if b.closed.Load() {
		return net.ErrClosed
	}
	_ = b.rawConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = b.rawConn.WriteToIP(rawSegment, &net.IPAddr{IP: dstIP})
	_ = b.rawConn.SetWriteDeadline(time.Time{})
	return err
}

func (b *rawIPSocketBackend) ReceivePacket(deadline time.Time) (rawInboundPacket, error) {
	return b.receiveInternal(deadline, false)
}

func (b *rawIPSocketBackend) receiveInternal(deadline time.Time, allowSelfTest bool) (rawInboundPacket, error) {
	var empty rawInboundPacket
	if b.closed.Load() {
		return empty, net.ErrClosed
	}
	_ = b.rawConn.SetReadDeadline(deadline)

	bufPtr := rawPacketBufPool.Get().(*[]byte)
	defer rawPacketBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		if b.closed.Load() {
			return empty, net.ErrClosed
		}
		n, rAddr, err := b.rawConn.ReadFromIP(buf)
		if err != nil {
			return empty, err
		}
		if n < rawTCPHeaderLen {
			continue
		}

		var fromIP net.IP
		if rAddr != nil {
			fromIP = rAddr.IP
		}
		srcIP, dstIP, tcpSeg, err := extractTCPFromRawIPRead(buf[:n], fromIP, b.localIP)
		if err != nil || len(tcpSeg) < rawTCPHeaderLen {
			continue
		}

		// 1. Fast destination port filter: ignore unrelated host TCP traffic
		dstPort := binary.BigEndian.Uint16(tcpSeg[2:4])
		if dstPort != b.localPort {
			continue
		}

		// 2. Source address filter when bound to a specific peer IP
		if !allowSelfTest && len(b.expectedPeerIP) > 0 && !b.expectedPeerIP.IsLoopback() && !srcIP.IsLoopback() {
			if !srcIP.Equal(b.expectedPeerIP) {
				continue
			}
		}

		// 3. Full RFC 793 TCP decode, RST rejection, and RFC 1071 checksum verification
		pkt, err := decodeRawTCPPacket(srcIP, dstIP, tcpSeg, true)
		if err != nil {
			continue
		}

		// 4. SAHAND-RAW protocol magic & version validation
		if len(pkt.Payload) < rawEnvelopeHeaderLen {
			continue
		}
		if binary.BigEndian.Uint16(pkt.Payload[0:2]) != sahandRawMagic || pkt.Payload[2] != sahandRawVersion {
			continue
		}
		if !allowSelfTest && pkt.Payload[3] == rawPktSelfTest {
			continue
		}

		return rawInboundPacket{
			Payload: pkt.Payload,
			SenderAddr: &net.UDPAddr{
				IP:   cloneIP(srcIP),
				Port: int(pkt.SrcPort),
			},
			TCPSeq:   pkt.SeqNum,
			TCPAck:   pkt.AckNum,
			TCPFlags: pkt.Flags,
		}, nil
	}
}

func extractTCPFromRawIPRead(raw []byte, fromIP net.IP, defaultDstIP net.IP) (srcIP, dstIP net.IP, tcpSeg []byte, err error) {
	return extractTCPFromRawIPBuffer(raw, fromIP, defaultDstIP)
}

func (b *rawIPSocketBackend) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	if b.rstGuard != nil {
		b.rstGuard.release()
	}
	if b.rawConn != nil {
		return b.rawConn.Close()
	}
	return nil
}

// ============================================================================
// BACKEND B: UDP_FALLBACK (Independent Normal UDP Socket Backend)
// ============================================================================

type udpFallbackBackend struct {
	udpConn        *net.UDPConn
	localPort      uint16
	fallbackReason string
	closed         atomic.Bool
}

func newUDPFallbackBackend(listenIP string, port int, fallbackReason string) (*udpFallbackBackend, error) {
	bindHost := strings.TrimSpace(listenIP)
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	uAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(bindHost, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	uConn, err := net.ListenUDP("udp4", uAddr)
	if err != nil {
		return nil, err
	}
	configureUDPSocketBuffers(uConn)

	actualPort := uint16(uConn.LocalAddr().(*net.UDPAddr).Port)
	return &udpFallbackBackend{
		udpConn:        uConn,
		localPort:      actualPort,
		fallbackReason: fallbackReason,
	}, nil
}

func (u *udpFallbackBackend) BackendName() string {
	return RawBackendNameUDPFallback
}

func (u *udpFallbackBackend) TransportMode() string {
	return RawTransportModeUDP
}

func (u *udpFallbackBackend) FallbackReason() string {
	return u.fallbackReason
}

func (u *udpFallbackBackend) LocalPort() uint16 {
	return u.localPort
}

func (u *udpFallbackBackend) SendPacket(dstAddr *net.UDPAddr, seq, _ uint32, flags byte, payload []byte) error {
	if u.closed.Load() || dstAddr == nil {
		return net.ErrClosed
	}
	if len(payload)+rawUDPFrameHeaderLen > rawMaxWireMTU {
		return errors.New("UDP_FALLBACK frame exceeds MTU")
	}

	// 8-byte UDP_FALLBACK transport header: [Magic:2(0x5352)][Ver:1(0x01)][Flags:1][Seq:4][Payload...]
	frame := make([]byte, rawUDPFrameHeaderLen+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], sahandRawMagic)
	frame[2] = sahandRawVersion
	frame[3] = flags
	binary.BigEndian.PutUint32(frame[4:8], seq)
	copy(frame[rawUDPFrameHeaderLen:], payload)

	_, err := u.udpConn.WriteToUDP(frame, dstAddr)
	return err
}

func (u *udpFallbackBackend) ReceivePacket(deadline time.Time) (rawInboundPacket, error) {
	var empty rawInboundPacket
	if u.closed.Load() {
		return empty, net.ErrClosed
	}
	_ = u.udpConn.SetReadDeadline(deadline)

	bufPtr := rawPacketBufPool.Get().(*[]byte)
	defer rawPacketBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		if u.closed.Load() {
			return empty, net.ErrClosed
		}
		n, rAddr, err := u.udpConn.ReadFromUDP(buf)
		if err != nil {
			return empty, err
		}
		if n < rawUDPFrameHeaderLen+rawEnvelopeHeaderLen {
			continue
		}
		if binary.BigEndian.Uint16(buf[0:2]) != sahandRawMagic || buf[2] != sahandRawVersion {
			continue
		}
		flags := buf[3]
		seq := binary.BigEndian.Uint32(buf[4:8])
		payload := make([]byte, n-rawUDPFrameHeaderLen)
		copy(payload, buf[rawUDPFrameHeaderLen:n])

		return rawInboundPacket{
			Payload:    payload,
			SenderAddr: cloneUDPAddr(rAddr),
			TCPSeq:     seq,
			TCPFlags:   flags,
		}, nil
	}
}

func (u *udpFallbackBackend) Close() error {
	if u.closed.Swap(true) {
		return nil
	}
	return u.udpConn.Close()
}

// ============================================================================
// TRANSPORT SELECTION FACTORY (raw_ip | udp | auto)
// ============================================================================

func openSahandRawBackend(requestedMode string, listenIP string, port int, peerIP net.IP) (rawTransportBackend, error) {
	mode, err := normalizeRawTransportMode(requestedMode)
	if err != nil {
		return nil, err
	}

	switch mode {
	case RawTransportModeRawIP:
		rawBackend, err := newRawIPSocketBackend(listenIP, port, peerIP)
		if err != nil {
			return nil, fmt.Errorf("SAHAND-RAW raw_ip mode initialization failed: %w", err)
		}
		return rawBackend, nil

	case RawTransportModeUDP:
		udpBackend, err := newUDPFallbackBackend(listenIP, port, "")
		if err != nil {
			return nil, fmt.Errorf("SAHAND-RAW udp mode initialization failed: %w", err)
		}
		return udpBackend, nil

	default: // RawTransportModeAuto
		rawBackend, rawErr := newRawIPSocketBackend(listenIP, port, peerIP)
		if rawErr == nil {
			return rawBackend, nil
		}
		reason := fmt.Sprintf("RAW_IP unavailable (%v); fell back to UDP_FALLBACK", rawErr)
		udpBackend, udpErr := newUDPFallbackBackend(listenIP, port, reason)
		if udpErr != nil {
			return nil, fmt.Errorf("%s, and UDP_FALLBACK failed: %w", reason, udpErr)
		}
		return udpBackend, nil
	}
}

// ============================================================================
// LAYER B: SECURITY ENGINE (X25519 HANDSHAKE, CHACHA20-POLY1305, REPLAY, REKEY)
// ============================================================================

type rawReplayFilter struct {
	mu      sync.Mutex
	highest uint64
	bitmap  uint64
}

func (rf *rawReplayFilter) accept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if rf.highest == 0 {
		rf.highest = seq
		rf.bitmap = 1
		return true
	}
	if seq > rf.highest {
		shift := seq - rf.highest
		if shift >= 64 {
			rf.bitmap = 1
		} else {
			rf.bitmap = (rf.bitmap << shift) | 1
		}
		rf.highest = seq
		return true
	}
	diff := rf.highest - seq
	if diff >= 64 {
		return false
	}
	mask := uint64(1) << diff
	if (rf.bitmap & mask) != 0 {
		return false
	}
	rf.bitmap |= mask
	return true
}

type rawSecurityBox struct {
	mu          sync.RWMutex
	isInitiator bool
	sessionID   uint32
	baseSecret  [32]byte
	currentEp   uint16
	txKey       [32]byte
	rxKey       [32]byte
	prevTxKey   [32]byte
	prevRxKey   [32]byte
	hasPrev     bool
	txSeq       atomic.Uint64
	replay      rawReplayFilter
}

func deriveRawEpochKeys(baseSecret [32]byte, epoch uint16, isInitiator bool) (txKey [32]byte, rxKey [32]byte) {
	var epBytes [2]byte
	binary.BigEndian.PutUint16(epBytes[:], epoch)

	mac1 := hmac.New(sha256.New, baseSecret[:])
	_, _ = mac1.Write([]byte("sahand-raw-epoch-i2r:"))
	_, _ = mac1.Write(epBytes[:])
	i2r := mac1.Sum(nil)

	mac2 := hmac.New(sha256.New, baseSecret[:])
	_, _ = mac2.Write([]byte("sahand-raw-epoch-r2i:"))
	_, _ = mac2.Write(epBytes[:])
	r2i := mac2.Sum(nil)

	if isInitiator {
		copy(txKey[:], i2r[:32])
		copy(rxKey[:], r2i[:32])
	} else {
		copy(txKey[:], r2i[:32])
		copy(rxKey[:], i2r[:32])
	}
	return txKey, rxKey
}

func newRawSecurityBox(sessionID uint32, sharedSecret []byte, authKey []byte, isInitiator bool) *rawSecurityBox {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-raw-master-kdf-v1:"))
	_, _ = mac.Write(sharedSecret)
	var sidBuf [4]byte
	binary.BigEndian.PutUint32(sidBuf[:], sessionID)
	_, _ = mac.Write(sidBuf[:])
	sum := mac.Sum(nil)

	var base [32]byte
	copy(base[:], sum[:32])

	txK, rxK := deriveRawEpochKeys(base, 1, isInitiator)
	return &rawSecurityBox{
		isInitiator: isInitiator,
		sessionID:   sessionID,
		baseSecret:  base,
		currentEp:   1,
		txKey:       txK,
		rxKey:       rxK,
	}
}

func (sb *rawSecurityBox) RotateEpoch(newEpoch uint16) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if newEpoch <= sb.currentEp {
		return
	}
	sb.prevTxKey = sb.txKey
	sb.prevRxKey = sb.rxKey
	sb.hasPrev = true
	sb.currentEp = newEpoch
	sb.txKey, sb.rxKey = deriveRawEpochKeys(sb.baseSecret, newEpoch, sb.isInitiator)
}

func buildRawAEADNonce(epoch uint16, isInitiator bool, seq uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint16(nonce[0:2], epoch)
	if isInitiator {
		nonce[2] = 0x01
	} else {
		nonce[2] = 0x02
	}
	nonce[3] = 0x00
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return nonce
}

func (sb *rawSecurityBox) SealEnvelope(pktType byte, plaintext []byte) ([]byte, uint64, error) {
	seq := sb.txSeq.Add(1)
	if seq > 0 && seq%rawRekeyPacketInterval == 0 {
		sb.mu.RLock()
		nextEp := sb.currentEp + 1
		sb.mu.RUnlock()
		sb.RotateEpoch(nextEp)
	}

	sb.mu.RLock()
	ep := sb.currentEp
	key := sb.txKey
	initFlag := sb.isInitiator
	sid := sb.sessionID
	sb.mu.RUnlock()

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, 0, err
	}

	var hdr [rawEnvelopeHeaderLen]byte
	binary.BigEndian.PutUint16(hdr[0:2], sahandRawMagic)
	hdr[2] = sahandRawVersion
	hdr[3] = pktType
	binary.BigEndian.PutUint32(hdr[4:8], sid)
	binary.BigEndian.PutUint16(hdr[8:10], ep)
	binary.BigEndian.PutUint64(hdr[10:18], seq)

	nonce := buildRawAEADNonce(ep, initFlag, seq)
	out := make([]byte, rawEnvelopeHeaderLen, rawEnvelopeHeaderLen+len(plaintext)+aead.Overhead())
	copy(out, hdr[:])
	out = aead.Seal(out, nonce[:], plaintext, hdr[:])
	return out, seq, nil
}

func (sb *rawSecurityBox) OpenEnvelope(wire []byte) (byte, []byte, uint64, error) {
	if len(wire) < rawEnvelopeHeaderLen+chacha20poly1305.Overhead {
		return 0, nil, 0, errors.New("raw envelope too short")
	}
	magic := binary.BigEndian.Uint16(wire[0:2])
	ver := wire[2]
	pktType := wire[3]
	sid := binary.BigEndian.Uint32(wire[4:8])
	ep := binary.BigEndian.Uint16(wire[8:10])
	seq := binary.BigEndian.Uint64(wire[10:18])

	if magic != sahandRawMagic || ver != sahandRawVersion {
		return 0, nil, 0, errors.New("invalid raw envelope header")
	}

	sb.mu.RLock()
	expectedSID := sb.sessionID
	curEp := sb.currentEp
	rxKey := sb.rxKey
	prevRxKey := sb.prevRxKey
	hasPrev := sb.hasPrev
	senderIsInitiator := !sb.isInitiator
	sb.mu.RUnlock()

	if sid != expectedSID {
		return 0, nil, 0, errors.New("session ID mismatch")
	}

	var keyToUse [32]byte
	if ep == curEp {
		keyToUse = rxKey
	} else if hasPrev && ep == curEp-1 {
		keyToUse = prevRxKey
	} else if ep > curEp && ep <= curEp+2 {
		sb.RotateEpoch(ep)
		sb.mu.RLock()
		keyToUse = sb.rxKey
		sb.mu.RUnlock()
	} else {
		return 0, nil, 0, errors.New("invalid key epoch")
	}

	aead, err := chacha20poly1305.New(keyToUse[:])
	if err != nil {
		return 0, nil, 0, err
	}

	nonce := buildRawAEADNonce(ep, senderIsInitiator, seq)
	plaintext, err := aead.Open(nil, nonce[:], wire[rawEnvelopeHeaderLen:], wire[:rawEnvelopeHeaderLen])
	if err != nil {
		return 0, nil, 0, errors.New("AEAD authentication failed")
	}

	if !sb.replay.accept(seq) {
		return 0, nil, 0, errors.New("replayed or duplicate packet rejected")
	}

	return pktType, plaintext, seq, nil
}

// ============================================================================
// MUTUAL X25519 HANDSHAKE FRAMES
// ============================================================================

const rawHandshakeFrameLen = 78

func buildRawHandshakePacket(pktType byte, sessionID uint32, pubKey []byte, authKey []byte) ([]byte, error) {
	if len(pubKey) != 32 || len(authKey) == 0 {
		return nil, errors.New("invalid handshake key material")
	}
	buf := make([]byte, rawHandshakeFrameLen)
	binary.BigEndian.PutUint16(buf[0:2], sahandRawMagic)
	buf[2] = sahandRawVersion
	buf[3] = pktType
	binary.BigEndian.PutUint32(buf[4:8], sessionID)
	binary.BigEndian.PutUint64(buf[8:16], uint64(time.Now().Unix()))
	copy(buf[16:48], pubKey)

	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-raw-x25519-hs-v1:"))
	_, _ = mac.Write(buf[:48])
	sum := mac.Sum(nil)
	copy(buf[48:78], sum[:30])
	return buf, nil
}

func parseAndVerifyRawHandshakePacket(wire []byte, authKey []byte) (byte, uint32, []byte, error) {
	if len(wire) < rawHandshakeFrameLen || len(authKey) == 0 {
		return 0, 0, nil, errors.New("handshake packet too short")
	}
	if binary.BigEndian.Uint16(wire[0:2]) != sahandRawMagic || wire[2] != sahandRawVersion {
		return 0, 0, nil, errors.New("invalid handshake magic")
	}
	pktType := wire[3]
	if pktType != rawPktHandshakeInit && pktType != rawPktHandshakeResp {
		return 0, 0, nil, errors.New("unexpected handshake packet type")
	}
	sessionID := binary.BigEndian.Uint32(wire[4:8])
	ts := int64(binary.BigEndian.Uint64(wire[8:16]))
	diff := time.Now().Unix() - ts
	if diff < -wssAuthSkewWindowSec || diff > wssAuthSkewWindowSec {
		return 0, 0, nil, errors.New("handshake timestamp out of window")
	}

	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-raw-x25519-hs-v1:"))
	_, _ = mac.Write(wire[:48])
	expected := mac.Sum(nil)[:30]
	if subtle.ConstantTimeCompare(wire[48:78], expected) != 1 {
		return 0, 0, nil, errors.New("handshake HMAC authentication failed")
	}

	pubKey := make([]byte, 32)
	copy(pubKey, wire[16:48])
	return pktType, sessionID, pubKey, nil
}

// ============================================================================
// LAYER C & D: RELIABLE ARQ TRANSPORT + STREAM MULTIPLEXER
// ============================================================================

type rawARQFrame struct {
	Cmd        byte
	StreamID   uint32
	TargetPort uint16
	FragSeq    uint32
	AckUna     uint32
	Payload    []byte
}

func encodeRawARQFrame(f rawARQFrame) []byte {
	out := make([]byte, rawARQHeaderLen+len(f.Payload))
	out[0] = f.Cmd
	binary.BigEndian.PutUint32(out[1:5], f.StreamID)
	binary.BigEndian.PutUint16(out[5:7], f.TargetPort)
	binary.BigEndian.PutUint32(out[7:11], f.FragSeq)
	binary.BigEndian.PutUint32(out[11:15], f.AckUna)
	binary.BigEndian.PutUint16(out[15:17], uint16(len(f.Payload)))
	copy(out[rawARQHeaderLen:], f.Payload)
	return out
}

func decodeRawARQFrame(raw []byte) (rawARQFrame, error) {
	var f rawARQFrame
	if len(raw) < rawARQHeaderLen {
		return f, errors.New("ARQ frame too short")
	}
	f.Cmd = raw[0]
	f.StreamID = binary.BigEndian.Uint32(raw[1:5])
	f.TargetPort = binary.BigEndian.Uint16(raw[5:7])
	f.FragSeq = binary.BigEndian.Uint32(raw[7:11])
	f.AckUna = binary.BigEndian.Uint32(raw[11:15])
	pLen := int(binary.BigEndian.Uint16(raw[15:17]))
	if pLen < 0 || rawARQHeaderLen+pLen > len(raw) {
		return f, errors.New("ARQ frame payload length mismatch")
	}
	if pLen > 0 {
		f.Payload = make([]byte, pLen)
		copy(f.Payload, raw[rawARQHeaderLen:rawARQHeaderLen+pLen])
	}
	return f, nil
}

type rawMuxStream struct {
	session     *rawARQSession
	id          uint32
	targetPort  uint16
	sendMu      sync.Mutex
	nextSendSeq uint32
	ackChMapMu  sync.Mutex
	ackWaiters  map[uint32]chan struct{}
	recvMu      sync.Mutex
	expectedSeq uint32
	oooBuffer   map[uint32][]byte
	readCh      chan []byte
	readMu      sync.Mutex
	readBuf     bytes.Buffer
	openAckCh   chan bool
	closedRead  atomic.Bool
	closedWrite atomic.Bool
}

func newRawMuxStream(sess *rawARQSession, id uint32, targetPort uint16) *rawMuxStream {
	return &rawMuxStream{
		session:     sess,
		id:          id,
		targetPort:  targetPort,
		nextSendSeq: 1,
		expectedSeq: 1,
		ackWaiters:  make(map[uint32]chan struct{}),
		oooBuffer:   make(map[uint32][]byte),
		readCh:      make(chan []byte, rawStreamBufferCap),
		openAckCh:   make(chan bool, 1),
	}
}

func (st *rawMuxStream) handleIncomingSegment(fragSeq uint32, payload []byte) {
	st.recvMu.Lock()
	defer st.recvMu.Unlock()

	if st.closedRead.Load() {
		return
	}

	_ = st.session.sendEncryptedARQFrame(rawARQFrame{
		Cmd:        rawARQCmdACK,
		StreamID:   st.id,
		TargetPort: st.targetPort,
		FragSeq:    fragSeq,
		AckUna:     st.expectedSeq,
	})

	if fragSeq < st.expectedSeq {
		return
	}
	if fragSeq > st.expectedSeq {
		if len(st.oooBuffer) < 128 {
			if _, exists := st.oooBuffer[fragSeq]; !exists {
				cp := make([]byte, len(payload))
				copy(cp, payload)
				st.oooBuffer[fragSeq] = cp
			}
		}
		return
	}

	st.deliverChunkLocked(payload)
	st.expectedSeq++

	for {
		nextChunk, ok := st.oooBuffer[st.expectedSeq]
		if !ok {
			break
		}
		delete(st.oooBuffer, st.expectedSeq)
		st.deliverChunkLocked(nextChunk)
		st.expectedSeq++
	}
}

func (st *rawMuxStream) deliverChunkLocked(chunk []byte) {
	if st.closedRead.Load() || len(chunk) == 0 {
		return
	}
	cp := make([]byte, len(chunk))
	copy(cp, chunk)
	select {
	case st.readCh <- cp:
	default:
		timer := time.NewTimer(4 * time.Second)
		defer timer.Stop()
		select {
		case st.readCh <- cp:
		case <-timer.C:
			st.markRemoteEOF()
		}
	}
}

func (st *rawMuxStream) markAckReceived(fragSeq uint32) {
	st.ackChMapMu.Lock()
	if ch, ok := st.ackWaiters[fragSeq]; ok {
		delete(st.ackWaiters, fragSeq)
		close(ch)
	}
	st.ackChMapMu.Unlock()
}

func (st *rawMuxStream) markRemoteEOF() {
	if st.closedRead.CompareAndSwap(false, true) {
		close(st.readCh)
	}
	st.ackChMapMu.Lock()
	for k, ch := range st.ackWaiters {
		delete(st.ackWaiters, k)
		close(ch)
	}
	st.ackChMapMu.Unlock()
}

func (st *rawMuxStream) Read(p []byte) (int, error) {
	st.readMu.Lock()
	defer st.readMu.Unlock()

	if st.readBuf.Len() > 0 {
		return st.readBuf.Read(p)
	}
	chunk, ok := <-st.readCh
	if !ok {
		return 0, io.EOF
	}
	st.readBuf.Write(chunk)
	return st.readBuf.Read(p)
}

func (st *rawMuxStream) Write(p []byte) (int, error) {
	if st.closedWrite.Load() || st.session.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	st.sendMu.Lock()
	defer st.sendMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > rawMaxFragmentPayload {
			chunk = p[:rawMaxFragmentPayload]
		}
		seq := st.nextSendSeq
		st.nextSendSeq++

		if err := st.sendReliableSegment(seq, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (st *rawMuxStream) sendReliableSegment(fragSeq uint32, chunk []byte) error {
	ackCh := make(chan struct{})
	st.ackChMapMu.Lock()
	st.ackWaiters[fragSeq] = ackCh
	st.ackChMapMu.Unlock()

	defer func() {
		st.ackChMapMu.Lock()
		delete(st.ackWaiters, fragSeq)
		st.ackChMapMu.Unlock()
	}()

	frame := rawARQFrame{
		Cmd:        rawARQCmdStreamData,
		StreamID:   st.id,
		TargetPort: st.targetPort,
		FragSeq:    fragSeq,
		Payload:    chunk,
	}

	rto := st.session.currentRTO()
	for attempt := 0; attempt < 12; attempt++ {
		if st.closedWrite.Load() || st.session.closed.Load() {
			return io.ErrClosedPipe
		}
		start := time.Now()
		if err := st.session.sendEncryptedARQFrame(frame); err != nil {
			return err
		}

		timer := time.NewTimer(rto)
		select {
		case <-ackCh:
			timer.Stop()
			if attempt == 0 {
				st.session.updateRTT(time.Since(start))
			}
			return nil
		case <-st.session.stopCh:
			timer.Stop()
			return io.ErrClosedPipe
		case <-timer.C:
			rto = rto * 3 / 2
			if rto > 600*time.Millisecond {
				rto = 600 * time.Millisecond
			}
		}
	}
	return errors.New("SAHAND-RAW ARQ segment retransmission limit exceeded")
}

func (st *rawMuxStream) CloseWrite() error {
	if st.closedWrite.CompareAndSwap(false, true) {
		_ = st.session.sendEncryptedARQFrame(rawARQFrame{
			Cmd:        rawARQCmdStreamFIN,
			StreamID:   st.id,
			TargetPort: st.targetPort,
		})
	}
	return nil
}

func (st *rawMuxStream) Close() error {
	_ = st.CloseWrite()
	st.markRemoteEOF()
	st.session.removeStream(st.id)
	return nil
}

// ============================================================================
// SAHAND-RAW ARQ SESSION MANAGER
// ============================================================================

type rawTxHookFunc func(sendFn func() error) error

type rawARQSession struct {
	sessionID    uint32
	backend      rawTransportBackend
	ownsBackend  bool
	remoteAddr   atomic.Pointer[net.UDPAddr]
	sec          *rawSecurityBox
	peer         ServerPeer
	tunnel       TunnelConfig
	isClient     bool

	streamsMu    sync.RWMutex
	streams      map[uint32]*rawMuxStream
	nextStreamID atomic.Uint32

	pingMu      sync.Mutex
	pingWaiters map[uint32]chan time.Duration

	ctrlMu      sync.Mutex
	ctrlWaiters map[uint32]chan []byte

	rttMu sync.Mutex
	srtt  time.Duration
	rto   time.Duration

	tcpSeq       atomic.Uint32
	tcpAck       atomic.Uint32
	lastActivity atomic.Int64
	stopCh       chan struct{}
	closed       atomic.Bool

	txHook atomic.Pointer[rawTxHookFunc]
}

func newRawARQSession(
	sessionID uint32,
	backend rawTransportBackend,
	ownsBackend bool,
	remoteAddr *net.UDPAddr,
	sec *rawSecurityBox,
	peer ServerPeer,
	tc TunnelConfig,
	isClient bool,
) *rawARQSession {
	s := &rawARQSession{
		sessionID:   sessionID,
		backend:     backend,
		ownsBackend: ownsBackend,
		sec:         sec,
		peer:        peer,
		tunnel:      tc,
		isClient:    isClient,
		streams:     make(map[uint32]*rawMuxStream),
		pingWaiters: make(map[uint32]chan time.Duration),
		ctrlWaiters: make(map[uint32]chan []byte),
		srtt:        40 * time.Millisecond,
		rto:         80 * time.Millisecond,
		stopCh:      make(chan struct{}),
	}
	s.remoteAddr.Store(cloneUDPAddr(remoteAddr))
	if isClient {
		s.nextStreamID.Store(1)
	} else {
		s.nextStreamID.Store(2)
	}
	s.tcpSeq.Store(uint32(10000 + randomIntN(90000)))
	s.tcpAck.Store(uint32(10000 + randomIntN(90000)))
	s.lastActivity.Store(time.Now().Unix())
	return s
}

func (s *rawARQSession) BackendName() string {
	if s.backend == nil {
		return ""
	}
	return s.backend.BackendName()
}

func (s *rawARQSession) TransportMode() string {
	if s.backend == nil {
		return ""
	}
	return s.backend.TransportMode()
}

func (s *rawARQSession) FallbackReason() string {
	if s.backend == nil {
		return ""
	}
	return s.backend.FallbackReason()
}

func (s *rawARQSession) setTxHook(fn rawTxHookFunc) {
	if fn == nil {
		s.txHook.Store(nil)
		return
	}
	s.txHook.Store(&fn)
}

func (s *rawARQSession) updateRTT(sample time.Duration) {
	if sample <= 0 {
		sample = time.Millisecond
	}
	s.rttMu.Lock()
	s.srtt = (s.srtt*7 + sample) / 8
	rto := s.srtt * 2
	if rto < 25*time.Millisecond {
		rto = 25 * time.Millisecond
	} else if rto > 400*time.Millisecond {
		rto = 400 * time.Millisecond
	}
	s.rto = rto
	s.rttMu.Unlock()
}

func (s *rawARQSession) currentRTO() time.Duration {
	s.rttMu.Lock()
	defer s.rttMu.Unlock()
	return s.rto
}

func (s *rawARQSession) sendEncryptedARQFrame(frame rawARQFrame) error {
	if s.closed.Load() || s.backend == nil {
		return net.ErrClosed
	}
	dst := s.remoteAddr.Load()
	if dst == nil {
		return net.ErrClosed
	}

	rawFrame := encodeRawARQFrame(frame)
	wire, pktSeq, err := s.sec.SealEnvelope(rawPktData, rawFrame)
	if err != nil {
		return err
	}

	seq := s.tcpSeq.Add(uint32(len(wire)))
	ack := s.tcpAck.Load() + uint32(pktSeq)
	flags := rawTCPFlagPSH | rawTCPFlagACK

	sendFn := func() error {
		if s.closed.Load() {
			return net.ErrClosed
		}
		return s.backend.SendPacket(dst, seq, ack, flags, wire)
	}
	if hookPtr := s.txHook.Load(); hookPtr != nil && *hookPtr != nil {
		return (*hookPtr)(sendFn)
	}
	return sendFn()
}

func (s *rawARQSession) handleIncomingWireEnvelope(wire []byte, senderAddr *net.UDPAddr) {
	if s.closed.Load() {
		return
	}
	pktType, plaintext, _, err := s.sec.OpenEnvelope(wire)
	if err != nil || pktType != rawPktData {
		return
	}

	s.lastActivity.Store(time.Now().Unix())
	if senderAddr != nil {
		cur := s.remoteAddr.Load()
		if cur == nil || cur.Port != senderAddr.Port || !cur.IP.Equal(senderAddr.IP) {
			s.remoteAddr.Store(cloneUDPAddr(senderAddr))
		}
	}

	frame, err := decodeRawARQFrame(plaintext)
	if err != nil {
		return
	}

	switch frame.Cmd {
	case rawARQCmdStreamOpen:
		if len(frame.Payload) > 0 {
			applyMasterTimeHeader(string(frame.Payload))
		}
		maxStreams := s.tunnel.StreamLimit
		if maxStreams <= 0 {
			maxStreams = 64
		}
		s.streamsMu.Lock()
		if len(s.streams) >= maxStreams {
			s.streamsMu.Unlock()
			_ = s.sendEncryptedARQFrame(rawARQFrame{
				Cmd:        rawARQCmdStreamOpenAck,
				StreamID:   frame.StreamID,
				TargetPort: 1,
			})
			return
		}
		st, exists := s.streams[frame.StreamID]
		if !exists {
			st = newRawMuxStream(s, frame.StreamID, frame.TargetPort)
			s.streams[frame.StreamID] = st
			go s.handleServerStream(st, frame.TargetPort)
		} else {
			_ = s.sendEncryptedARQFrame(rawARQFrame{
				Cmd:        rawARQCmdStreamOpenAck,
				StreamID:   frame.StreamID,
				TargetPort: 0,
			})
		}
		s.streamsMu.Unlock()

	case rawARQCmdStreamOpenAck:
		s.streamsMu.RLock()
		st := s.streams[frame.StreamID]
		s.streamsMu.RUnlock()
		if st != nil {
			select {
			case st.openAckCh <- (frame.TargetPort == 0):
			default:
			}
		}

	case rawARQCmdStreamData:
		s.streamsMu.RLock()
		st := s.streams[frame.StreamID]
		s.streamsMu.RUnlock()
		if st != nil {
			st.handleIncomingSegment(frame.FragSeq, frame.Payload)
		}

	case rawARQCmdACK:
		s.streamsMu.RLock()
		st := s.streams[frame.StreamID]
		s.streamsMu.RUnlock()
		if st != nil {
			st.markAckReceived(frame.FragSeq)
		}

	case rawARQCmdStreamFIN, rawARQCmdStreamRST:
		s.streamsMu.RLock()
		st := s.streams[frame.StreamID]
		s.streamsMu.RUnlock()
		if st != nil {
			st.markRemoteEOF()
			s.removeStream(frame.StreamID)
		}

	case rawARQCmdPing:
		if rem := s.remoteAddr.Load(); rem != nil {
			markPeerConnectedInbound(s.peer.ID, rem.IP.String(), s.tunnel.ID, s.tunnel.ListenPort, 1)
		}
		_ = s.sendEncryptedARQFrame(rawARQFrame{
			Cmd:      rawARQCmdPong,
			StreamID: frame.StreamID,
			FragSeq:  frame.FragSeq,
			Payload:  frame.Payload,
		})

	case rawARQCmdPong:
		s.pingMu.Lock()
		if ch, ok := s.pingWaiters[frame.FragSeq]; ok {
			select {
			case ch <- time.Millisecond:
			default:
			}
		}
		s.pingMu.Unlock()

	case rawARQCmdProbe:
		if len(frame.Payload) > 0 {
			applyMasterTimeHeader(string(frame.Payload))
		}
		if rem := s.remoteAddr.Load(); rem != nil {
			markPeerConnectedInbound(s.peer.ID, rem.IP.String(), s.tunnel.ID, s.tunnel.ListenPort, 1)
		}
		_ = s.sendEncryptedARQFrame(rawARQFrame{
			Cmd:     rawARQCmdProbeAck,
			FragSeq: frame.FragSeq,
			Payload: []byte(buildMasterTimeHeader()),
		})

	case rawARQCmdProbeAck:
		s.ctrlMu.Lock()
		if ch, ok := s.ctrlWaiters[frame.FragSeq]; ok {
			cp := make([]byte, len(frame.Payload))
			copy(cp, frame.Payload)
			select {
			case ch <- cp:
			default:
			}
		}
		s.ctrlMu.Unlock()

	case rawARQCmdUDPDatagram:
		if !s.tunnel.Enabled {
			return
		}
		if s.isClient {
			deliverSahandRawUDPReply(s.peer.ID, frame.StreamID, frame.Payload)
		} else {
			go s.forwardUDPDatagramToLocal(frame.StreamID, frame.TargetPort, frame.Payload)
		}
	}
}

func (s *rawARQSession) forwardUDPDatagramToLocal(udpSessionID uint32, targetPort uint16, payload []byte) {
	if len(payload) == 0 {
		return
	}
	authorizedPort, err := authorizeWSSTargetPort(s.tunnel, strconv.Itoa(int(targetPort)))
	if err != nil {
		return
	}
	portNum, _ := strconv.Atoi(authorizedPort)
	atomic.AddUint64(&appRxBytes, uint64(len(payload)))

	dstAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portNum}
	localUDP, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		return
	}
	defer localUDP.Close()
	_ = localUDP.SetDeadline(time.Now().Add(4 * time.Second))

	if _, err := localUDP.Write(payload); err != nil {
		return
	}
	rep := make([]byte, 16384)
	n, err := localUDP.Read(rep)
	if err == nil && n > 0 {
		atomic.AddUint64(&appTxBytes, uint64(n))
		_ = s.sendEncryptedARQFrame(rawARQFrame{
			Cmd:        rawARQCmdUDPDatagram,
			StreamID:   udpSessionID,
			TargetPort: uint16(portNum),
			Payload:    rep[:n],
		})
	}
}

func (s *rawARQSession) handleServerStream(st *rawMuxStream, targetPort uint16) {
	defer st.Close()

	if targetPort == rawARQPortParitySync {
		if err := s.sendEncryptedARQFrame(rawARQFrame{
			Cmd:        rawARQCmdStreamOpenAck,
			StreamID:   st.id,
			TargetPort: 0,
		}); err != nil {
			return
		}
		remoteHost := ""
		if rem := s.remoteAddr.Load(); rem != nil {
			remoteHost = rem.IP.String()
		}
		handleWebTransportParitySyncStream(st, s.peer.ID, remoteHost)
		return
	}

	if !s.tunnel.Enabled {
		_ = s.sendEncryptedARQFrame(rawARQFrame{
			Cmd:        rawARQCmdStreamOpenAck,
			StreamID:   st.id,
			TargetPort: 1,
		})
		return
	}

	authorizedPort, err := authorizeWSSTargetPort(s.tunnel, strconv.Itoa(int(targetPort)))
	if err != nil {
		_ = s.sendEncryptedARQFrame(rawARQFrame{
			Cmd:        rawARQCmdStreamOpenAck,
			StreamID:   st.id,
			TargetPort: 1,
		})
		return
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", authorizedPort), 5*time.Second)
	if err != nil {
		_ = s.sendEncryptedARQFrame(rawARQFrame{
			Cmd:        rawARQCmdStreamOpenAck,
			StreamID:   st.id,
			TargetPort: 1,
		})
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	if err := s.sendEncryptedARQFrame(rawARQFrame{
		Cmd:        rawARQCmdStreamOpenAck,
		StreamID:   st.id,
		TargetPort: 0,
	}); err != nil {
		return
	}

	pipeRawMuxStreamAndTCP(st, target, s.tunnel.SpeedLimitMBps)
}

func pipeRawMuxStreamAndTCP(muxSt *rawMuxStream, tcpConn net.Conn, speedLimitMBps string) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	toMux := newThrottledWriter(muxSt, &appTxBytes, mbLimit)
	toTCP := newThrottledWriter(tcpConn, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toMux, tcpConn, buf)
		_ = muxSt.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toTCP, muxSt, buf)
		closeWriteTCP(tcpConn)
	}()

	wg.Wait()
}

func (s *rawARQSession) OpenStream(targetPort uint16, timeout time.Duration) (*rawMuxStream, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	maxStreams := s.tunnel.StreamLimit
	if maxStreams <= 0 {
		maxStreams = 64
	}

	s.streamsMu.Lock()
	if len(s.streams) >= maxStreams {
		s.streamsMu.Unlock()
		return nil, errors.New("SAHAND-RAW stream limit reached")
	}
	sid := s.nextStreamID.Add(2)
	st := newRawMuxStream(s, sid, targetPort)
	s.streams[sid] = st
	s.streamsMu.Unlock()

	openFrame := rawARQFrame{
		Cmd:        rawARQCmdStreamOpen,
		StreamID:   sid,
		TargetPort: targetPort,
		Payload:    []byte(buildMasterTimeHeader()),
	}

	rto := s.currentRTO()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := s.sendEncryptedARQFrame(openFrame); err != nil {
			s.removeStream(sid)
			return nil, err
		}
		waitTimer := time.NewTimer(rto)
		select {
		case ok := <-st.openAckCh:
			waitTimer.Stop()
			if !ok {
				s.removeStream(sid)
				return nil, errors.New("SAHAND-RAW target port rejected by peer")
			}
			return st, nil
		case <-s.stopCh:
			waitTimer.Stop()
			s.removeStream(sid)
			return nil, net.ErrClosed
		case <-waitTimer.C:
			rto = rto * 3 / 2
			if rto > 400*time.Millisecond {
				rto = 400 * time.Millisecond
			}
		}
	}
	s.removeStream(sid)
	return nil, errors.New("SAHAND-RAW stream open timeout")
}

func (s *rawARQSession) ExchangeControlFrame(cmd byte, payload []byte, timeout time.Duration) ([]byte, time.Duration, error) {
	if s.closed.Load() {
		return nil, 0, net.ErrClosed
	}
	seq := s.nextStreamID.Add(1)
	ch := make(chan []byte, 1)

	s.ctrlMu.Lock()
	s.ctrlWaiters[seq] = ch
	s.ctrlMu.Unlock()

	defer func() {
		s.ctrlMu.Lock()
		delete(s.ctrlWaiters, seq)
		s.ctrlMu.Unlock()
	}()

	frame := rawARQFrame{
		Cmd:     cmd,
		FragSeq: seq,
		Payload: payload,
	}

	start := time.Now()
	rto := s.currentRTO()
	deadline := start.Add(timeout)

	for time.Now().Before(deadline) {
		if err := s.sendEncryptedARQFrame(frame); err != nil {
			return nil, 0, err
		}
		timer := time.NewTimer(rto)
		select {
		case rep := <-ch:
			timer.Stop()
			rtt := time.Since(start)
			s.updateRTT(rtt)
			return rep, rtt, nil
		case <-s.stopCh:
			timer.Stop()
			return nil, 0, net.ErrClosed
		case <-timer.C:
			rto = rto * 3 / 2
			if rto > 400*time.Millisecond {
				rto = 400 * time.Millisecond
			}
		}
	}
	return nil, 0, errors.New("SAHAND-RAW control exchange timeout")
}

func (s *rawARQSession) startClientReadAndKeepaliveLoop() {
	go func() {
		defer s.Close()
		for {
			pkt, err := s.backend.ReceivePacket(time.Now().Add(rawSessionIdleTTL))
			if err != nil {
				return
			}
			if len(pkt.Payload) >= rawEnvelopeHeaderLen {
				s.handleIncomingWireEnvelope(pkt.Payload, pkt.SenderAddr)
			}
		}
	}()

	go func() {
		hbSec := s.tunnel.HeartbeatSec
		if hbSec <= 0 {
			hbSec = 25
		}
		ticker := time.NewTicker(time.Duration(hbSec) * time.Second)
		defer ticker.Stop()
		var seq uint32
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				seq++
				_ = s.sendEncryptedARQFrame(rawARQFrame{
					Cmd:     rawARQCmdPing,
					FragSeq: seq,
				})
			}
		}
	}()
}

func (s *rawARQSession) removeStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

func (s *rawARQSession) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.setTxHook(nil)
	close(s.stopCh)
	if s.ownsBackend && s.backend != nil {
		_ = s.backend.Close()
	}
	s.streamsMu.Lock()
	for id, st := range s.streams {
		st.markRemoteEOF()
		delete(s.streams, id)
	}
	s.streamsMu.Unlock()
	return nil
}

// ============================================================================
// LAYER E: TUNNEL ADAPTER, SERVER DEMULTIPLEXER & CLIENT SESSION POOL (:28024)
// ============================================================================

var (
	sahandRawMu            sync.RWMutex
	sahandRawClientByPeer  = make(map[string]*rawARQSession)
	sahandRawServerByPeer  = make(map[string]*rawServerMux)
	sahandRawUDPEntryByKey = make(map[string]*rawUDPEntryForwarder)
)

type rawServerMux struct {
	backend  rawTransportBackend
	peer     ServerPeer
	tunnel   TunnelConfig
	mu       sync.RWMutex
	sessions map[uint32]*rawARQSession
	stopCh   chan struct{}
	closed   atomic.Bool
}

type rawServerCloser struct {
	sm *rawServerMux
}

func (c *rawServerCloser) ReadFrom(_ []byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *rawServerCloser) WriteTo(_ []byte, _ net.Addr) (int, error) {
	return 0, net.ErrClosed
}
func (c *rawServerCloser) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: int(c.sm.backend.LocalPort())}
}
func (c *rawServerCloser) SetDeadline(_ time.Time) error      { return nil }
func (c *rawServerCloser) SetReadDeadline(_ time.Time) error  { return nil }
func (c *rawServerCloser) SetWriteDeadline(_ time.Time) error { return nil }
func (c *rawServerCloser) Close() error {
	c.sm.closeAll()
	return nil
}

func stopSahandRawPeerResources(peerID string) {
	sahandRawMu.Lock()
	if cli, ok := sahandRawClientByPeer[peerID]; ok {
		_ = cli.Close()
		delete(sahandRawClientByPeer, peerID)
	}
	if srv, ok := sahandRawServerByPeer[peerID]; ok {
		srv.closeAll()
		delete(sahandRawServerByPeer, peerID)
	}
	for k, uFwd := range sahandRawUDPEntryByKey {
		if strings.HasPrefix(k, peerID+"|") {
			uFwd.closeAll()
			delete(sahandRawUDPEntryByKey, k)
		}
	}
	sahandRawMu.Unlock()
}

func (sm *rawServerMux) BackendName() string {
	return sm.backend.BackendName()
}

func (sm *rawServerMux) TransportMode() string {
	return sm.backend.TransportMode()
}

func (sm *rawServerMux) FallbackReason() string {
	return sm.backend.FallbackReason()
}

func (sm *rawServerMux) closeAll() {
	if sm.closed.Swap(true) {
		return
	}
	close(sm.stopCh)
	_ = sm.backend.Close()
	sm.mu.Lock()
	for sid, sess := range sm.sessions {
		_ = sess.Close()
		delete(sm.sessions, sid)
	}
	sm.mu.Unlock()
}

func startSahandRawServer(peer ServerPeer, tc TunnelConfig) (net.PacketConn, error) {
	peerIP := net.ParseIP(strings.TrimSpace(peer.IP))
	backend, err := openSahandRawBackend(tc.RawTransport, "0.0.0.0", tc.ListenPort, peerIP)
	if err != nil {
		return nil, err
	}
	if reason := backend.FallbackReason(); reason != "" {
		log.Printf("SAHAND-RAW server (peer %s, port %d): %s", peer.ID, backend.LocalPort(), reason)
	}

	sm := &rawServerMux{
		backend:  backend,
		peer:     peer,
		tunnel:   tc,
		sessions: make(map[uint32]*rawARQSession),
		stopCh:   make(chan struct{}),
	}

	sahandRawMu.Lock()
	if old, ok := sahandRawServerByPeer[peer.ID]; ok {
		old.closeAll()
	}
	sahandRawServerByPeer[peer.ID] = sm
	sahandRawMu.Unlock()

	go sm.serveLoop()
	return &rawServerCloser{sm: sm}, nil
}

func (sm *rawServerMux) serveLoop() {
	defer sm.closeAll()

	for {
		pkt, err := sm.backend.ReceivePacket(time.Time{})
		if err != nil {
			return
		}
		if len(pkt.Payload) < rawEnvelopeHeaderLen {
			continue
		}

		if len(pkt.Payload) == rawHandshakeFrameLen && pkt.Payload[3] == rawPktHandshakeInit {
			sm.handleHandshakeInit(pkt)
			continue
		}

		sid := binary.BigEndian.Uint32(pkt.Payload[4:8])
		sm.mu.RLock()
		sess := sm.sessions[sid]
		sm.mu.RUnlock()
		if sess != nil {
			sess.handleIncomingWireEnvelope(pkt.Payload, pkt.SenderAddr)
		}
	}
}

func (sm *rawServerMux) handleHandshakeInit(pkt rawInboundPacket) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, sm.peer)
	if err != nil {
		return
	}

	_, sessionID, cliPubBytes, err := parseAndVerifyRawHandshakePacket(pkt.Payload, authKey)
	if err != nil {
		return
	}

	curve := ecdh.X25519()
	cliPub, err := curve.NewPublicKey(cliPubBytes)
	if err != nil {
		return
	}
	srvPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	sharedSecret, err := srvPriv.ECDH(cliPub)
	if err != nil {
		return
	}

	respWire, err := buildRawHandshakePacket(rawPktHandshakeResp, sessionID, srvPriv.PublicKey().Bytes(), authKey)
	if err != nil {
		return
	}

	secBox := newRawSecurityBox(sessionID, sharedSecret, authKey, false)
	sess := newRawARQSession(sessionID, sm.backend, false, pkt.SenderAddr, secBox, sm.peer, sm.tunnel, false)

	sm.mu.Lock()
	if old, exists := sm.sessions[sessionID]; exists {
		_ = old.Close()
	}
	sm.sessions[sessionID] = sess
	sm.mu.Unlock()

	_ = sm.backend.SendPacket(
		pkt.SenderAddr,
		sess.tcpSeq.Load(),
		pkt.TCPSeq+1,
		rawTCPFlagSYN|rawTCPFlagACK,
		respWire,
	)
}

func getOrDialSahandRawSession(peer ServerPeer, tc TunnelConfig, timeout time.Duration) (*rawARQSession, error) {
	reqMode, err := normalizeRawTransportMode(tc.RawTransport)
	if err != nil {
		return nil, err
	}

	sahandRawMu.RLock()
	existing := sahandRawClientByPeer[peer.ID]
	sahandRawMu.RUnlock()

	if existing != nil && !existing.closed.Load() && existing.tunnel.ListenPort == tc.ListenPort {
		if reqMode == RawTransportModeAuto || existing.TransportMode() == reqMode {
			return existing, nil
		}
	}

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return nil, err
	}

	rAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort)))
	if err != nil {
		return nil, err
	}

	backend, err := openSahandRawBackend(tc.RawTransport, "0.0.0.0", 0, rAddr.IP)
	if err != nil {
		return nil, err
	}
	if reason := backend.FallbackReason(); reason != "" {
		log.Printf("SAHAND-RAW client (peer %s): %s", peer.ID, reason)
	}

	curve := ecdh.X25519()
	cliPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		_ = backend.Close()
		return nil, err
	}

	var sidBytes [4]byte
	_, _ = rand.Read(sidBytes[:])
	sessionID := binary.BigEndian.Uint32(sidBytes[:])
	if sessionID == 0 {
		sessionID = 1
	}

	initWire, err := buildRawHandshakePacket(rawPktHandshakeInit, sessionID, cliPriv.PublicKey().Bytes(), authKey)
	if err != nil {
		_ = backend.Close()
		return nil, err
	}

	initSeq := uint32(10000 + randomIntN(90000))
	deadline := time.Now().Add(timeout)
	var srvPubBytes []byte

	for attempt := 0; attempt < 4 && time.Now().Before(deadline); attempt++ {
		if err := backend.SendPacket(rAddr, initSeq, 0, rawTCPFlagSYN, initWire); err != nil {
			_ = backend.Close()
			return nil, err
		}
		waitUntil := time.Now().Add(700 * time.Millisecond)
		if waitUntil.After(deadline) {
			waitUntil = deadline
		}
		repPkt, rErr := backend.ReceivePacket(waitUntil)
		if rErr != nil {
			continue
		}
		pType, rSID, pub, vErr := parseAndVerifyRawHandshakePacket(repPkt.Payload, authKey)
		if vErr == nil && pType == rawPktHandshakeResp && rSID == sessionID {
			srvPubBytes = pub
			break
		}
	}

	if len(srvPubBytes) != 32 {
		_ = backend.Close()
		return nil, fmt.Errorf("SAHAND-RAW (%s) handshake timeout", backend.BackendName())
	}

	srvPub, err := curve.NewPublicKey(srvPubBytes)
	if err != nil {
		_ = backend.Close()
		return nil, err
	}
	sharedSecret, err := cliPriv.ECDH(srvPub)
	if err != nil {
		_ = backend.Close()
		return nil, err
	}

	secBox := newRawSecurityBox(sessionID, sharedSecret, authKey, true)
	sess := newRawARQSession(sessionID, backend, true, rAddr, secBox, peer, tc, true)
	sess.startClientReadAndKeepaliveLoop()

	sahandRawMu.Lock()
	if old, ok := sahandRawClientByPeer[peer.ID]; ok && old != sess {
		_ = old.Close()
	}
	sahandRawClientByPeer[peer.ID] = sess
	sahandRawMu.Unlock()

	return sess, nil
}

// ============================================================================
// ENGINE 1 (PROBE & PARITY SYNC) AND ENGINE 2 (TCP & UDP FORWARDING)
// ============================================================================

func probeSahandRaw(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	reqMode, modeErr := normalizeRawTransportMode(tc.RawTransport)
	if modeErr != nil {
		res.Success = false
		res.ErrorReason = modeErr.Error()
		return res
	}

	start := time.Now()
	sess, err := getOrDialSahandRawSession(peer, tc, 3500*time.Millisecond)
	if err != nil {
		res.Success = false
		msg := strings.ToLower(err.Error())
		if reqMode == RawTransportModeRawIP && strings.Contains(msg, "raw_ip") {
			res.ErrorReason = fmt.Sprintf("Raw IP init failed: %v", err)
		} else if strings.Contains(msg, "timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(msg, "auth") || strings.Contains(msg, "token") {
			res.ErrorReason = "Authentication failure"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}

	// Never report Raw IP as active if raw_ip was explicitly requested and the session is not RAW_IP
	if reqMode == RawTransportModeRawIP && sess.BackendName() != RawBackendNameRawIP {
		res.Success = false
		res.ErrorReason = "Raw IP backend not active"
		return res
	}

	rep, _, err := sess.ExchangeControlFrame(rawARQCmdProbe, []byte(buildMasterTimeHeader()), 3*time.Second)
	if err != nil {
		_ = sess.Close()
		res.Success = false
		res.ErrorReason = "Timeout"
		return res
	}
	if len(rep) > 0 {
		applyMasterTimeHeader(string(rep))
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

func pushSahandRawParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	sess, err := getOrDialSahandRawSession(peer, tc, 4*time.Second)
	if err != nil {
		return false
	}

	st, err := sess.OpenStream(rawARQPortParitySync, 4*time.Second)
	if err != nil {
		_ = sess.Close()
		return false
	}
	defer st.Close()

	stateMu.RLock()
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	stateMu.RUnlock()

	padLen := 24 + randomIntN(64)
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
	if _, err := st.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := st.Write(rawPkt); err != nil {
		return false
	}

	if _, err := io.ReadFull(st, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(st, respBytes); err != nil {
		return false
	}

	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func forwardSahandRawTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	authorizedPort, err := authorizeWSSTargetPort(tc, targetPort)
	if err != nil {
		return
	}
	portNum, _ := strconv.Atoi(authorizedPort)

	sess, err := getOrDialSahandRawSession(peer, tc, 5*time.Second)
	if err != nil {
		return
	}

	st, err := sess.OpenStream(uint16(portNum), 5*time.Second)
	if err != nil {
		return
	}
	defer st.Close()

	pipeRawMuxStreamAndTCP(st, client, tc.SpeedLimitMBps)
}

type rawUDPEntryForwarder struct {
	peer       ServerPeer
	tunnel     TunnelConfig
	targetPort uint16
	entryConn  *net.UDPConn
	mu         sync.RWMutex
	byAddr     map[string]uint32
	bySID      map[uint32]*net.UDPAddr
	nextSID    atomic.Uint32
	limiter    io.Writer
	closed     atomic.Bool
}

func (uf *rawUDPEntryForwarder) closeAll() {
	if uf.closed.Swap(true) {
		return
	}
	if uf.entryConn != nil {
		_ = uf.entryConn.Close()
	}
}

func deliverSahandRawUDPReply(peerID string, udpSID uint32, payload []byte) {
	if len(payload) == 0 {
		return
	}
	sahandRawMu.RLock()
	for k, uFwd := range sahandRawUDPEntryByKey {
		if strings.HasPrefix(k, peerID+"|") {
			uFwd.mu.RLock()
			cliAddr, ok := uFwd.bySID[udpSID]
			uFwd.mu.RUnlock()
			if ok && cliAddr != nil {
				atomic.AddUint64(&appRxBytes, uint64(len(payload)))
				_, _ = uFwd.entryConn.WriteToUDP(payload, cliAddr)
				sahandRawMu.RUnlock()
				return
			}
		}
	}
	sahandRawMu.RUnlock()
}

func startSahandRawUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
	portNum, err := strconv.Atoi(strings.TrimSpace(targetPort))
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil
	}
	uAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(portNum)))
	if err != nil {
		return nil
	}
	entryConn, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		return nil
	}
	configureUDPSocketBuffers(entryConn)

	uFwd := &rawUDPEntryForwarder{
		peer:       peer,
		tunnel:     tc,
		targetPort: uint16(portNum),
		entryConn:  entryConn,
		byAddr:     make(map[string]uint32),
		bySID:      make(map[uint32]*net.UDPAddr),
		limiter:    newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(tc.SpeedLimitMBps)),
	}

	muxKey := fmt.Sprintf("%s|%d", peer.ID, portNum)
	sahandRawMu.Lock()
	if old, ok := sahandRawUDPEntryByKey[muxKey]; ok {
		old.closeAll()
	}
	sahandRawUDPEntryByKey[muxKey] = uFwd
	sahandRawMu.Unlock()

	go func() {
		buf := make([]byte, rawMaxFragmentPayload)
		for {
			n, cliAddr, err := entryConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n <= 0 || uFwd.closed.Load() {
				continue
			}
			addrKey := cliAddr.String()
			uFwd.mu.Lock()
			sid, ok := uFwd.byAddr[addrKey]
			if !ok {
				sid = uFwd.nextSID.Add(1)
				uFwd.byAddr[addrKey] = sid
				uFwd.bySID[sid] = cloneUDPAddr(cliAddr)
			}
			uFwd.mu.Unlock()

			sess, sErr := getOrDialSahandRawSession(uFwd.peer, uFwd.tunnel, 3*time.Second)
			if sErr != nil {
				continue
			}
			_, _ = uFwd.limiter.Write(buf[:n])
			_ = sess.sendEncryptedARQFrame(rawARQFrame{
				Cmd:        rawARQCmdUDPDatagram,
				StreamID:   sid,
				TargetPort: uFwd.targetPort,
				Payload:    buf[:n],
			})
		}
	}()

	return entryConn
}
