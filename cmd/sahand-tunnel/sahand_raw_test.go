package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"strconv"
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

func TestSahandRawPacketCodecAndRFC1071Checksums(t *testing.T) {
	// 1. IPv4 RFC 793 TCP packet construction & RFC 1071 checksum verification
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

	// Corrupt 1 bit in payload and verify RFC 1071 checksum validation rejects the packet
	corrupted := make([]byte, len(encoded))
	copy(corrupted, encoded)
	corrupted[len(corrupted)-1] ^= 0x01
	if _, err := decodeRawTCPPacket(srcIPv4, dstIPv4, corrupted, true); err == nil {
		t.Fatalf("expected corrupted TCP packet to fail RFC 1071 checksum verification")
	}

	// Verify TCP RST packets are filtered out by the Packet Engine
	rstPkt := orig
	rstPkt.Flags = rawTCPFlagRST
	rstEncoded, err := encodeRawTCPPacket(rstPkt)
	if err != nil {
		t.Fatalf("encodeRawTCPPacket RST failed: %v", err)
	}
	if _, err := decodeRawTCPPacket(srcIPv4, dstIPv4, rstEncoded, true); err == nil {
		t.Fatalf("expected TCP RST packet to be rejected by decodeRawTCPPacket")
	}

	// 2. IPv6 pseudo-header checksum readiness verification
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

	// 1. Encrypt and authenticate
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

	// 2. Replay protection: re-submitting the exact same wire packet must be rejected
	if _, _, _, err := serverBox.OpenEnvelope(wire); err == nil {
		t.Fatalf("expected replayed packet to be rejected by anti-replay window")
	}

	// 3. Out-of-order acceptance within the 64-packet sliding window
	wire2, _, _ := clientBox.SealEnvelope(rawPktData, []byte("pkt-2"))
	wire3, _, _ := clientBox.SealEnvelope(rawPktData, []byte("pkt-3"))
	wire4, _, _ := clientBox.SealEnvelope(rawPktData, []byte("pkt-4"))

	// Deliver pkt-4 first, then pkt-2, then pkt-3
	if _, _, _, err := serverBox.OpenEnvelope(wire4); err != nil {
		t.Fatalf("expected out-of-order wire4 to succeed: %v", err)
	}
	if _, _, _, err := serverBox.OpenEnvelope(wire2); err != nil {
		t.Fatalf("expected out-of-order wire2 within window to succeed: %v", err)
	}
	if _, _, _, err := serverBox.OpenEnvelope(wire3); err != nil {
		t.Fatalf("expected out-of-order wire3 within window to succeed: %v", err)
	}
	// Duplicate wire2 must now fail
	if _, _, _, err := serverBox.OpenEnvelope(wire2); err == nil {
		t.Fatalf("expected second delivery of wire2 to be rejected")
	}

	// 4. Key rotation across epochs + previous-epoch grace window
	wireOldEpoch, _, _ := clientBox.SealEnvelope(rawPktData, []byte("in-flight-before-rekey"))
	clientBox.RotateEpoch(2)
	wireNewEpoch, _, _ := clientBox.SealEnvelope(rawPktData, []byte("after-rekey-epoch-2"))

	// Server receives epoch 2 packet first (auto-ratchets to epoch 2), then receives delayed epoch 1 packet
	if _, outNew, _, err := serverBox.OpenEnvelope(wireNewEpoch); err != nil || string(outNew) != "after-rekey-epoch-2" {
		t.Fatalf("expected epoch 2 packet to auto-ratchet and decrypt: %v", err)
	}
	if _, outOld, _, err := serverBox.OpenEnvelope(wireOldEpoch); err != nil || string(outOld) != "in-flight-before-rekey" {
		t.Fatalf("expected in-flight epoch 1 packet to decrypt via previous-epoch grace key: %v", err)
	}

	// 5. Tampered ciphertext must fail Poly1305 authentication
	tampered := make([]byte, len(wireNewEpoch))
	copy(tampered, wireNewEpoch)
	tampered[len(tampered)-1] ^= 0xFF
	if _, _, _, err := serverBox.OpenEnvelope(tampered); err == nil {
		t.Fatalf("expected tampered ciphertext to fail AEAD authentication")
	}
}

func TestSahandRawTransportLossDuplicationAndReordering(t *testing.T) {
	peer, tc := setupSahandRawTestEnv(t)

	targetPort, closeTarget := startLocalTCPEchoTarget(t)
	defer closeTarget()

	tc.ListenPort = allocateFreeUDPPort(t)
	tc.Enabled = true
	tc.ForwardPorts = strconv.Itoa(targetPort)

	pConn, err := startSahandRawServer(peer, tc)
	if err != nil {
		t.Fatalf("startSahandRawServer failed: %v", err)
	}
	defer func() {
		_ = pConn.Close()
		stopSahandRawPeerResources(peer.ID)
	}()

	sess, err := getOrDialSahandRawSession(peer, tc, 4*time.Second)
	if err != nil {
		t.Fatalf("getOrDialSahandRawSession failed: %v", err)
	}

	// Inject a deterministic chaos hook into the client ARQ session:
	// - Every 5th packet is dropped (simulating 20% packet loss, forcing ARQ retransmission)
	// - Every 7th packet is sent twice (simulating packet duplication)
	// - Every 9th packet is delayed by 15ms in a goroutine (simulating packet reordering)
	var pktCounter atomic.Uint64
	sess.txHook = func(sendFn func() error) error {
		n := pktCounter.Add(1)
		if n%5 == 0 {
			// Drop first attempt
			return nil
		}
		if n%7 == 0 {
			// Duplicate packet
			_ = sendFn()
			return sendFn()
		}
		if n%9 == 0 {
			// Reorder packet
			go func() {
				time.Sleep(15 * time.Millisecond)
				_ = sendFn()
			}()
			return nil
		}
		return sendFn()
	}

	st, err := sess.OpenStream(uint16(targetPort), 5*time.Second)
	if err != nil {
		t.Fatalf("OpenStream under loss/reordering failed: %v", err)
	}
	defer st.Close()

	// Transfer 64 KB across 64 fragments through the lossy/reordered/duplicated link
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

	// Start a local UDP echo target
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
	tc.Enabled = true
	tc.StreamLimit = 32
	tc.ForwardPorts = strconv.Itoa(tcpTarget1) + "," + strconv.Itoa(tcpTarget2) + "," + strconv.Itoa(udpTargetPort)

	pConn, err := startSahandRawServer(peer, tc)
	if err != nil {
		t.Fatalf("startSahandRawServer failed: %v", err)
	}
	defer func() {
		_ = pConn.Close()
		stopSahandRawPeerResources(peer.ID)
	}()

	// 1. Engine 1 Probe
	probeRes := probeSahandRaw(peer, tc, "master-node-01")
	if !probeRes.Success {
		t.Fatalf("expected probeSahandRaw to succeed, got: %s", probeRes.ErrorReason)
	}

	// 2. Engine 1 Parity Sync
	if !pushSahandRawParitySync(peer, tc, probeRes.LatencyMS) {
		t.Fatalf("expected pushSahandRawParitySync to succeed")
	}

	// 3. Unauthorized target port rejection
	sess, err := getOrDialSahandRawSession(peer, tc, 4*time.Second)
	if err != nil {
		t.Fatalf("getOrDialSahandRawSession failed: %v", err)
	}
	if _, err := sess.OpenStream(65000, 2*time.Second); err == nil {
		t.Fatalf("expected unauthorized target port 65000 to be rejected")
	}

	// 4. Engine 2 Concurrent Multiplexed TCP Streams across multiple ports
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

	// 5. Engine 2 Generic UDP Datagram Forwarding
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
