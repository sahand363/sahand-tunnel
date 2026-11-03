package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setupSahandRawTestEnv(t *testing.T) (ServerPeer, TunnelConfig) {
	t.Helper()
	peer, _ := setupWSSTestEnv(t)
	var rawTC TunnelConfig
	for _, tc := range peer.Tunnels {
		if tc.ID == 24 {
			rawTC = tc
			break
		}
	}
	if rawTC.ID != 24 {
		t.Fatalf("Method 24 (SAHAND-RAW) not found in defaultTunnelsForServer")
	}
	return peer, rawTC
}

func allocateFreeUDPPort(t *testing.T) int {
	t.Helper()
	uAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	uConn, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	port := uConn.LocalAddr().(*net.UDPAddr).Port
	_ = uConn.Close()
	return port
}

// In-memory IPv4 raw socket switch (`ip4:tcp`) used to test the complete RAW_IP backend
// (bidirectional raw TCP packet transmission, reception, port/IP filtering, and RFC 1071 checksums)
// in unprivileged CI environments where CAP_NET_RAW is not granted.
type mockRawIPPacket struct {
	srcIP      net.IP
	rawSegment []byte
}

type mockRawIPSwitch struct {
	mu      sync.RWMutex
	sockets map[int]*mockRawIPSocket
	nextID  int
}

func newMockRawIPSwitch() *mockRawIPSwitch {
	return &mockRawIPSwitch{
		sockets: make(map[int]*mockRawIPSocket),
	}
}

type mockRawIPSocket struct {
	id         int
	sw         *mockRawIPSwitch
	localIP    net.IP
	inbox      chan mockRawIPPacket
	closedCh   chan struct{}
	deadlineMu sync.Mutex
	readTimer  *time.Timer
	deadlineCh chan struct{}
	closed     atomic.Bool
}

func (sw *mockRawIPSwitch) newSocket(localIP net.IP) *mockRawIPSocket {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.nextID++
	s := &mockRawIPSocket{
		id:         sw.nextID,
		sw:         sw,
		localIP:    cloneIP(localIP.To4()),
		inbox:      make(chan mockRawIPPacket, 512),
		closedCh:   make(chan struct{}),
		deadlineCh: make(chan struct{}),
	}
	sw.sockets[s.id] = s
	return s
}

func (s *mockRawIPSocket) WriteToIP(b []byte, addr *net.IPAddr) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	cp := make([]byte, len(b))
	copy(cp, b)

	srcIP := s.localIP
	if addr != nil && addr.IP != nil && addr.IP.IsLoopback() {
		srcIP = net.IPv4(127, 0, 0, 1).To4()
	}

	s.sw.mu.RLock()
	defer s.sw.mu.RUnlock()

	// Just like Linux's ip4:tcp raw socket subsystem, every open ip4:tcp socket
	// receives a copy of incoming IPPROTO_TCP segments and must filter by port/IP/checksum.
	for _, sock := range s.sw.sockets {
		if !sock.closed.Load() {
			select {
			case sock.inbox <- mockRawIPPacket{srcIP: cloneIP(srcIP), rawSegment: cp}:
			case <-sock.closedCh:
			default:
			}
		}
	}
	return len(b), nil
}

func (s *mockRawIPSocket) ReadFromIP(b []byte) (int, *net.IPAddr, error) {
	if s.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	s.deadlineMu.Lock()
	dlCh := s.deadlineCh
	s.deadlineMu.Unlock()

	select {
	case <-s.closedCh:
		return 0, nil, net.ErrClosed
	case pkt := <-s.inbox:
		if s.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		n := copy(b, pkt.rawSegment)
		return n, &net.IPAddr{IP: pkt.srcIP}, nil
	case <-dlCh:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (s *mockRawIPSocket) SetReadDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()

	if s.readTimer != nil {
		s.readTimer.Stop()
		s.readTimer = nil
	}
	select {
	case <-s.deadlineCh:
		s.deadlineCh = make(chan struct{})
	default:
	}

	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	ch := s.deadlineCh
	if d <= 0 {
		close(ch)
		return nil
	}
	s.readTimer = time.AfterFunc(d, func() {
		s.deadlineMu.Lock()
		defer s.deadlineMu.Unlock()
		select {
		case <-ch:
		default:
			close(ch)
		}
	})
	return nil
}

func (s *mockRawIPSocket) SetWriteDeadline(_ time.Time) error {
	return nil
}

func (s *mockRawIPSocket) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.sw.mu.Lock()
	delete(s.sw.sockets, s.id)
	s.sw.mu.Unlock()
	close(s.closedCh)
	return nil
}

func TestSahandRawPacketCodecAndRFC1071Checksums(t *testing.T) {
	srcIPv4 := net.ParseIP("198.51.100.10")
	dstIPv4 := net.ParseIP("203.0.113.25")
	payload := []byte("sahand-raw-packet-engine-test-payload-0123456789")

	orig := rawTCPPacket{
		SrcIP:   srcIPv4,
		DstIP:   dstIPv4,
		SrcPort: 28024,
		DstPort: 49152,
		SeqNum:  0x10203040,
		AckNum:  0x50607080,
		Flags:   rawTCPFlagPSH | rawTCPFlagACK,
		Window:  65535,
		Payload: payload,
	}

	encoded, err := encodeRawTCPPacket(orig)
	if err != nil {
		t.Fatalf("encodeRawTCPPacket failed: %v", err)
	}
	if len(encoded) != rawTCPHeaderLen+len(payload) {
		t.Fatalf("expected wire length %d, got %d", rawTCPHeaderLen+len(payload), len(encoded))
	}

	decoded, err := decodeRawTCPPacket(srcIPv4, dstIPv4, encoded, true)
	if err != nil {
		t.Fatalf("decodeRawTCPPacket IPv4 failed: %v", err)
	}
	if decoded.SrcPort != orig.SrcPort ||
		decoded.DstPort != orig.DstPort ||
		decoded.SeqNum != orig.SeqNum ||
		decoded.AckNum != orig.AckNum ||
		decoded.Flags != orig.Flags ||
		!bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("decoded IPv4 packet fields did not match original")
	}

	corrupted := make([]byte, len(encoded))
	copy(corrupted, encoded)
	corrupted[len(corrupted)-1] ^= 0x01
	if _, err := decodeRawTCPPacket(srcIPv4, dstIPv4, corrupted, true); err == nil {
		t.Fatalf("expected corrupted TCP packet to fail RFC 1071 checksum verification")
	}

	rstPkt := orig
	rstPkt.Flags = rawTCPFlagRST
	rstEncoded, err := encodeRawTCPPacket(rstPkt)
	if err != nil {
		t.Fatalf("encodeRawTCPPacket RST failed: %v", err)
	}
	if _, err := decodeRawTCPPacket(srcIPv4, dstIPv4, rstEncoded, true); err == nil {
		t.Fatalf("expected TCP RST packet to be rejected by decodeRawTCPPacket")
	}

	srcIPv6 := net.ParseIP("2001:db8::1")
	dstIPv6 := net.ParseIP("2001:db8::2")
	origV6 := orig
	origV6.SrcIP = srcIPv6
	origV6.DstIP = dstIPv6

	encodedV6, err := encodeRawTCPPacket(origV6)
	if err != nil {
		t.Fatalf("encodeRawTCPPacket IPv6 failed: %v", err)
	}
	decodedV6, err := decodeRawTCPPacket(srcIPv6, dstIPv6, encodedV6, true)
	if err != nil || !bytes.Equal(decodedV6.Payload, payload) {
		t.Fatalf("decodeRawTCPPacket IPv6 failed: %v", err)
	}
}

func TestSahandRawSecurityAEADReplayAndKeyRotation(t *testing.T) {
	sharedSecret := make([]byte, 32)
	authKey := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, sharedSecret)
	_, _ = io.ReadFull(rand.Reader, authKey)

	clientBox := newRawSecurityBox(0xCAFEBABE, sharedSecret, authKey, true)
	serverBox := newRawSecurityBox(0xCAFEBABE, sharedSecret, authKey, false)

	plain := []byte("confidential-tunnel-frame-payload")
	wire, seq, err := clientBox.SealEnvelope(rawPktData, plain)
	if err != nil {
		t.Fatalf("SealEnvelope failed: %v", err)
	}

	pType, opened, rSeq, err := serverBox.OpenEnvelope(wire)
	if err != nil {
		t.Fatalf("OpenEnvelope failed: %v", err)
	}
	if pType != rawPktData || rSeq != seq || !bytes.Equal(opened, plain) {
		t.Fatalf("decrypted envelope mismatch")
	}

	if _, _, _, err := serverBox.OpenEnvelope(wire); err == nil {
		t.Fatalf("expected replayed packet to be rejected by anti-replay window")
	}

	wire2, _, _ := clientBox.SealEnvelope(rawPktData, []byte("pkt-2"))
	wire3, _, _ := clientBox.SealEnvelope(rawPktData, []byte("pkt-3"))
	wire4, _, _ := clientBox.SealEnvelope(rawPktData, []byte("pkt-4"))

	if _, _, _, err := serverBox.OpenEnvelope(wire4); err != nil {
		t.Fatalf("expected out-of-order wire4 to succeed: %v", err)
	}
	if _, _, _, err := serverBox.OpenEnvelope(wire2); err != nil {
		t.Fatalf("expected out-of-order wire2 within window to succeed: %v", err)
	}
	if _, _, _, err := serverBox.OpenEnvelope(wire3); err != nil {
		t.Fatalf("expected out-of-order wire3 within window to succeed: %v", err)
	}
	if _, _, _, err := serverBox.OpenEnvelope(wire2); err == nil {
		t.Fatalf("expected second delivery of wire2 to be rejected")
	}

	wireOldEpoch, _, _ := clientBox.SealEnvelope(rawPktData, []byte("in-flight-before-rekey"))
	clientBox.RotateEpoch(2)
	wireNewEpoch, _, _ := clientBox.SealEnvelope(rawPktData, []byte("after-rekey-epoch-2"))

	if _, outNew, _, err := serverBox.OpenEnvelope(wireNewEpoch); err != nil || string(outNew) != "after-rekey-epoch-2" {
		t.Fatalf("expected epoch 2 packet to auto-ratchet and decrypt: %v", err)
	}
	if _, outOld, _, err := serverBox.OpenEnvelope(wireOldEpoch); err != nil || string(outOld) != "in-flight-before-rekey" {
		t.Fatalf("expected in-flight epoch 1 packet to decrypt via previous-epoch grace key: %v", err)
	}

	tampered := make([]byte, len(wireNewEpoch))
	copy(tampered, wireNewEpoch)
	tampered[len(tampered)-1] ^= 0xFF
	if _, _, _, err := serverBox.OpenEnvelope(tampered); err == nil {
		t.Fatalf("expected tampered ciphertext to fail AEAD authentication")
	}
}

func TestSahandRawTransportModeSelectionAndBidirectionalRawIP(t *testing.T) {
	peer, tc := setupSahandRawTestEnv(t)
	targetPort, closeTarget := startLocalTCPEchoTarget(t)
	defer closeTarget()
	tc.Enabled = true
	tc.ForwardPorts = strconv.Itoa(targetPort)

	rawIPSkipIPTablesForTest.Store(true)
	rawIPTestHookMu.Lock()
	rawIPCustomDialer = func(_ net.IP, _ uint16) (rawIPConnHandle, error) {
		return nil, errors.New("operation not permitted (CAP_NET_RAW missing)")
	}
	rawIPTestHookMu.Unlock()
	defer func() {
		rawIPTestHookMu.Lock()
		rawIPCustomDialer = nil
		rawIPTestHookMu.Unlock()
		rawIPSkipIPTablesForTest.Store(false)
	}()

	if _, err := openSahandRawBackend(RawTransportModeRawIP, "127.0.0.1", 0, net.IPv4(127, 0, 0, 1)); err == nil {
		t.Fatalf("expected explicit raw_ip mode to fail when raw socket initialization fails")
	}

	autoBackend, err := openSahandRawBackend(RawTransportModeAuto, "127.0.0.1", 0, net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("expected auto mode to fall back to UDP_FALLBACK, got error: %v", err)
	}
	if autoBackend.BackendName() != RawBackendNameUDPFallback {
		t.Fatalf("expected autoBackend to report %q, got %q", RawBackendNameUDPFallback, autoBackend.BackendName())
	}
	if !strings.Contains(autoBackend.FallbackReason(), "CAP_NET_RAW") {
		t.Fatalf("expected autoBackend.FallbackReason() to explain why RAW_IP failed, got %q", autoBackend.FallbackReason())
	}
	_ = autoBackend.Close()

	udpBackend, err := openSahandRawBackend(RawTransportModeUDP, "127.0.0.1", 0, net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("expected explicit udp mode to succeed, got: %v", err)
	}
	if udpBackend.BackendName() != RawBackendNameUDPFallback || udpBackend.FallbackReason() != "" {
		t.Fatalf("unexpected UDP backend state: name=%q reason=%q", udpBackend.BackendName(), udpBackend.FallbackReason())
	}
	_ = udpBackend.Close()

	sw := newMockRawIPSwitch()
	rawIPTestHookMu.Lock()
	rawIPCustomDialer = func(listenIP net.IP, _ uint16) (rawIPConnHandle, error) {
		return sw.newSocket(listenIP), nil
	}
	rawIPTestHookMu.Unlock()

	tc.ListenPort = 28924
	tc.RawTransport = RawTransportModeRawIP

	pConn, err := startSahandRawServer(peer, tc)
	if err != nil {
		t.Fatalf("startSahandRawServer in raw_ip mode failed: %v", err)
	}
	defer func() {
		stopSahandRawPeerResources(peer.ID)
		_ = pConn.Close()
	}()

	sahandRawMu.RLock()
	srvMux := sahandRawServerByPeer[peer.ID]
	sahandRawMu.RUnlock()
	if srvMux == nil || srvMux.BackendName() != RawBackendNameRawIP {
		t.Fatalf("expected server to run on %q backend, got %v", RawBackendNameRawIP, srvMux)
	}

	noiseSock := sw.newSocket(net.IPv4(127, 0, 0, 1))
	defer noiseSock.Close()
	wrongPortPkt, _ := encodeRawTCPPacket(rawTCPPacket{
		SrcIP:   net.IPv4(127, 0, 0, 1).To4(),
		DstIP:   net.IPv4(127, 0, 0, 1).To4(),
		SrcPort: 55555,
		DstPort: 9999,
		SeqNum:  1,
		Flags:   rawTCPFlagPSH | rawTCPFlagACK,
		Payload: make([]byte, 32),
	})
	_, _ = noiseSock.WriteToIP(wrongPortPkt, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})

	badCsumPkt, _ := encodeRawTCPPacket(rawTCPPacket{
		SrcIP:   net.IPv4(127, 0, 0, 1).To4(),
		DstIP:   net.IPv4(127, 0, 0, 1).To4(),
		SrcPort: 55555,
		DstPort: uint16(tc.ListenPort),
		SeqNum:  2,
		Flags:   rawTCPFlagPSH | rawTCPFlagACK,
		Payload: make([]byte, 32),
	})
	binary.BigEndian.PutUint16(badCsumPkt[16:18], 0xDEAD)
	_, _ = noiseSock.WriteToIP(badCsumPkt, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})

	probeRes := probeSahandRaw(peer, tc, "master-node-01")
	if !probeRes.Success {
		t.Fatalf("expected probeSahandRaw over RAW_IP backend to succeed, got: %s", probeRes.ErrorReason)
	}

	sess, err := getOrDialSahandRawSession(peer, tc, 4*time.Second)
	if err != nil {
		t.Fatalf("getOrDialSahandRawSession over RAW_IP failed: %v", err)
	}
	if sess.BackendName() != RawBackendNameRawIP {
		t.Fatalf("expected client session to use %q, got %q", RawBackendNameRawIP, sess.BackendName())
	}

	st, err := sess.OpenStream(uint16(targetPort), 4*time.Second)
	if err != nil {
		t.Fatalf("OpenStream over RAW_IP failed: %v", err)
	}

	testData := make([]byte, 16*1024)
	_, _ = io.ReadFull(rand.Reader, testData)
	go func() {
		_, _ = st.Write(testData)
	}()
	echoed := make([]byte, len(testData))
	if _, err := io.ReadFull(st, echoed); err != nil || !bytes.Equal(testData, echoed) {
		t.Fatalf("bidirectional stream over RAW_IP failed: err=%v", err)
	}
	_ = st.Close()
}

func TestSahandRawTransportLossDuplicationAndReordering(t *testing.T) {
	peer, tc := setupSahandRawTestEnv(t)

	targetPort, closeTarget := startLocalTCPEchoTarget(t)
	defer closeTarget()

	tc.ListenPort = allocateFreeUDPPort(t)
	tc.RawTransport = RawTransportModeUDP
	tc.Enabled = true
	tc.ForwardPorts = strconv.Itoa(targetPort)

	pConn, err := startSahandRawServer(peer, tc)
	if err != nil {
		t.Fatalf("startSahandRawServer failed: %v", err)
	}
	defer func() {
		stopSahandRawPeerResources(peer.ID)
		_ = pConn.Close()
	}()

	sess, err := getOrDialSahandRawSession(peer, tc, 4*time.Second)
	if err != nil {
		t.Fatalf("getOrDialSahandRawSession failed: %v", err)
	}

	var pktCounter atomic.Uint64
	var reorderWG sync.WaitGroup
	sess.setTxHook(func(sendFn func() error) error {
		n := pktCounter.Add(1)
		if n%5 == 0 {
			return nil
		}
		if n%7 == 0 {
			_ = sendFn()
			return sendFn()
		}
		if n%9 == 0 {
			reorderWG.Add(1)
			go func() {
				defer reorderWG.Done()
				time.Sleep(15 * time.Millisecond)
				_ = sendFn()
			}()
			return nil
		}
		return sendFn()
	})
	defer func() {
		sess.setTxHook(nil)
		reorderWG.Wait()
	}()

	st, err := sess.OpenStream(uint16(targetPort), 5*time.Second)
	if err != nil {
		t.Fatalf("OpenStream under loss/reordering failed: %v", err)
	}
	defer st.Close()

	payload := make([]byte, 64*1024)
	_, _ = io.ReadFull(rand.Reader, payload)

	errCh := make(chan error, 1)
	go func() {
		_, wErr := st.Write(payload)
		errCh <- wErr
	}()

	received := make([]byte, len(payload))
	if _, err := io.ReadFull(st, received); err != nil {
		t.Fatalf("io.ReadFull under simulated loss/reordering failed: %v", err)
	}
	if wErr := <-errCh; wErr != nil {
		t.Fatalf("st.Write failed: %v", wErr)
	}
	if !bytes.Equal(payload, received) {
		t.Fatalf("reassembled stream payload corrupted under packet loss/reordering")
	}
}

func TestSahandRawProbeParitySyncAndMultiStreamIntegration(t *testing.T) {
	peer, tc := setupSahandRawTestEnv(t)

	tcpTarget1, closeTCP1 := startLocalTCPEchoTarget(t)
	defer closeTCP1()
	tcpTarget2, closeTCP2 := startLocalTCPEchoTarget(t)
	defer closeTCP2()

	udpTargetAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpTargetConn, err := net.ListenUDP("udp", udpTargetAddr)
	if err != nil {
		t.Fatalf("ListenUDP target failed: %v", err)
	}
	defer udpTargetConn.Close()
	udpTargetPort := udpTargetConn.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rErr := udpTargetConn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			_, _ = udpTargetConn.WriteToUDP(buf[:n], addr)
		}
	}()

	tc.ListenPort = allocateFreeUDPPort(t)
	tc.RawTransport = RawTransportModeAuto
	tc.Enabled = true
	tc.StreamLimit = 32
	tc.ForwardPorts = strconv.Itoa(tcpTarget1) + "," + strconv.Itoa(tcpTarget2) + "," + strconv.Itoa(udpTargetPort)

	pConn, err := startSahandRawServer(peer, tc)
	if err != nil {
		t.Fatalf("startSahandRawServer failed: %v", err)
	}
	defer func() {
		stopSahandRawPeerResources(peer.ID)
		_ = pConn.Close()
	}()

	probeRes := probeSahandRaw(peer, tc, "master-node-01")
	if !probeRes.Success {
		t.Fatalf("expected probeSahandRaw to succeed, got: %s", probeRes.ErrorReason)
	}

	if !pushSahandRawParitySync(peer, tc, probeRes.LatencyMS) {
		t.Fatalf("expected pushSahandRawParitySync to succeed")
	}

	sess, err := getOrDialSahandRawSession(peer, tc, 4*time.Second)
	if err != nil {
		t.Fatalf("getOrDialSahandRawSession failed: %v", err)
	}
	if _, err := sess.OpenStream(65000, 2*time.Second); err == nil {
		t.Fatalf("expected unauthorized target port 65000 to be rejected")
	}

	entryLn1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("entryLn1 failed: %v", err)
	}
	defer entryLn1.Close()
	go acceptTrafficEntryLoop(entryLn1, peer, tc, strconv.Itoa(tcpTarget1))

	entryLn2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("entryLn2 failed: %v", err)
	}
	defer entryLn2.Close()
	go acceptTrafficEntryLoop(entryLn2, peer, tc, strconv.Itoa(tcpTarget2))

	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		addr := entryLn1.Addr().String()
		if i%2 == 1 {
			addr = entryLn2.Addr().String()
		}
		go func(entryAddr string) {
			defer wg.Done()
			c, dErr := net.DialTimeout("tcp", entryAddr, 5*time.Second)
			if dErr != nil {
				errCh <- dErr
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))

			data := make([]byte, 32*1024)
			_, _ = io.ReadFull(rand.Reader, data)
			go func() {
				_, _ = c.Write(data)
			}()
			echo := make([]byte, len(data))
			if _, rErr := io.ReadFull(c, echo); rErr != nil {
				errCh <- rErr
				return
			}
			if !bytes.Equal(data, echo) {
				errCh <- io.ErrUnexpectedEOF
			}
		}(addr)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil {
			t.Fatalf("concurrent multiplexed TCP stream failed: %v", e)
		}
	}

	sessUDP, err := getOrDialSahandRawSession(peer, tc, 4*time.Second)
	if err != nil {
		t.Fatalf("getOrDialSahandRawSession for UDP failed: %v", err)
	}
	udpTestPayload := []byte("sahand-raw-udp-datagram-test")
	if err := sessUDP.sendEncryptedARQFrame(rawARQFrame{
		Cmd:        rawARQCmdUDPDatagram,
		StreamID:   77,
		TargetPort: uint16(udpTargetPort),
		Payload:    udpTestPayload,
	}); err != nil {
		t.Fatalf("sendEncryptedARQFrame UDP failed: %v", err)
	}
}

func BenchmarkSahandRawPacketAndAEAD(b *testing.B) {
	sharedSecret := make([]byte, 32)
	authKey := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, sharedSecret)
	_, _ = io.ReadFull(rand.Reader, authKey)

	txBox := newRawSecurityBox(101, sharedSecret, authKey, true)
	rxBox := newRawSecurityBox(101, sharedSecret, authKey, false)

	srcIP := net.ParseIP("198.51.100.1")
	dstIP := net.ParseIP("203.0.113.1")
	payload := make([]byte, 1024)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		env, seq, err := txBox.SealEnvelope(rawPktData, payload)
		if err != nil {
			b.Fatal(err)
		}
		pkt, err := encodeRawTCPPacket(rawTCPPacket{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: 28024,
			DstPort: 28024,
			SeqNum:  uint32(seq),
			AckNum:  1,
			Flags:   rawTCPFlagPSH | rawTCPFlagACK,
			Payload: env,
		})
		if err != nil {
			b.Fatal(err)
		}
		decPkt, err := decodeRawTCPPacket(srcIP, dstIP, pkt, true)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, _, err := rxBox.OpenEnvelope(decPkt.Payload); err != nil {
			b.Fatal(err)
		}
	}
}
