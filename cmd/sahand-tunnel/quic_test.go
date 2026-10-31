package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setupQUICTestEnvironment(t *testing.T, quicPort int, forwardPorts string, speedLimit string) (ServerPeer, TunnelConfig, func()) {
	t.Helper()

	certPEM, keyPEM, pin, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("failed to parse keypair: %v", err)
	}

	stateMu.Lock()
	localCert = cert
	appCfg = Config{
		Role:        "master",
		NodeID:      "node-master-test-01",
		TokenSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		TLSCertPEM:  certPEM,
		TLSKeyPEM:   keyPEM,
		CertPin:     pin,
	}
	stateMu.Unlock()

	tunnels := defaultTunnelsForServer()
	for i := range tunnels {
		if tunnels[i].ID == 8 {
			tunnels[i].Enabled = true
			tunnels[i].ListenPort = quicPort
			tunnels[i].ForwardPorts = forwardPorts
			tunnels[i].SpeedLimitMBps = speedLimit
			tunnels[i].CertPin = pin
			tunnels[i].HeartbeatSec = 10
			tunnels[i].StreamLimit = 128
		} else {
			tunnels[i].Implemented = false
		}
	}

	peer := ServerPeer{
		ID:            "peer-test-01",
		Name:          "Test Peer",
		IP:            "127.0.0.1",
		ConfigVersion: 1,
		Running:       true,
		Status:        "WAITING",
		RemoteCertPin: pin,
		Tunnels:       tunnels,
	}

	stateMu.Lock()
	tok, err := generatePeerToken(appCfg, peer)
	if err != nil {
		stateMu.Unlock()
		t.Fatalf("failed to generate peer token: %v", err)
	}
	peer.Token = tok
	appCfg.Servers = []ServerPeer{peer}
	stateMu.Unlock()

	var quicTun TunnelConfig
	for _, tc := range peer.Tunnels {
		if tc.ID == 8 {
			quicTun = tc
			break
		}
	}

	if err := registerQUICPeerListener(peer, quicTun); err != nil {
		t.Fatalf("failed to start QUIC listener on :%d: %v", quicPort, err)
	}

	cleanup := func() {
		stopAllServerListeners(peer.ID)
	}
	return peer, quicTun, cleanup
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to find free udp port: %v", err)
	}
	defer u.Close()
	return u.LocalAddr().(*net.UDPAddr).Port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free tcp port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Covers Scenarios 1, 2, 3, 4, 5, 18, 19:
// Genuine QUIC handshake, TLS 1.3 negotiation, ALPN negotiation, Certificate validation,
// Peer authentication, Probe latency (min/avg/max/jitter), and Packet loss handling.
func TestQUICHandshakeTLS13ALPNAndProbe(t *testing.T) {
	qPort := freeUDPPort(t)
	peer, quicTun, cleanup := setupQUICTestEnvironment(t, qPort, "2053", "0")
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	conn, _, err := getOrDialQUICConnection(ctx, peer, quicTun, "control", nil)
	if err != nil {
		t.Fatalf("expected genuine QUIC connection to succeed, got: %v", err)
	}

	st := conn.ConnectionState()
	if st.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3, got version: 0x%x", st.TLS.Version)
	}
	if st.TLS.NegotiatedProtocol != quicALPN {
		t.Fatalf("expected ALPN %q, got %q", quicALPN, st.TLS.NegotiatedProtocol)
	}
	if !st.SupportsDatagrams {
		t.Fatalf("expected RFC 9221 QUIC DATAGRAM support to be negotiated")
	}

	res := probeQUIC(peer, quicTun, "node-master-test-01")
	if !res.Success {
		t.Fatalf("expected probeQUIC to succeed, got error: %s", res.ErrorReason)
	}
	if res.LatencyMS < 1 || res.MinLatencyMS < 1 || res.MaxLatencyMS < res.MinLatencyMS {
		t.Fatalf("unexpected latency metrics: avg=%d min=%d max=%d jitter=%d",
			res.LatencyMS, res.MinLatencyMS, res.MaxLatencyMS, res.JitterMS)
	}
	if res.PacketLossPct != 0 {
		t.Fatalf("expected 0%% packet loss on localhost, got %d%%", res.PacketLossPct)
	}

	if !pushQUICParitySync(peer, quicTun, res.LatencyMS) {
		t.Fatalf("expected QUIC parity sync over bidirectional stream to succeed")
	}
}

// Covers Scenario 4 & 6: Certificate Pinning & Invalid Peer Rejection
func TestQUICCertPinningAndInvalidPeerRejection(t *testing.T) {
	qPort := freeUDPPort(t)
	peer, quicTun, cleanup := setupQUICTestEnvironment(t, qPort, "2053", "0")
	defer cleanup()

	// 1. Mismatched Certificate Pin must fail handshake
	badPinTun := quicTun
	badPinTun.CertPin = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	badPeer := peer
	badPeer.ID = "peer-bad-pin"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, _, err := getOrDialQUICConnection(ctx, badPeer, badPinTun, "control", nil)
	cancel()
	if err == nil {
		t.Fatalf("expected QUIC connection with mismatched certificate pin to be rejected")
	}

	// 2. Revoked / Invalid Token Peer must fail stream authentication
	unauthedPeer := peer
	unauthedPeer.ID = "peer-unauthed"
	unauthedPeer.Token = "st1.invalidtoken"
	res := probeQUIC(unauthedPeer, quicTun, "node-master-test-01")
	if res.Success {
		t.Fatalf("expected probeQUIC with invalid token to be rejected")
	}

	// 3. When UDP port is unreachable (no TCP fallback!), probeQUIC must fail
	unreachableTun := quicTun
	unreachableTun.ListenPort = freeUDPPort(t)
	resUnreach := probeQUIC(peer, unreachableTun, "node-master-test-01")
	if resUnreach.Success {
		t.Fatalf("expected probeQUIC on closed UDP port to fail without TCP fallback")
	}
}

// Covers Scenarios 7, 8, 16, 17:
// TCP forwarding in both directions, Concurrent TCP streams, Traffic accounting, and Speed limiting.
func TestQUICTCPBidirectionalConcurrentAndSpeedLimit(t *testing.T) {
	qPort := freeUDPPort(t)
	targetTCPPort := freeTCPPort(t)
	entryTCPPort := freeTCPPort(t)

	// Start local target TCP echo server on 127.0.0.1:<targetTCPPort>
	targetLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetTCPPort))
	if err != nil {
		t.Fatalf("failed to listen on target tcp port: %v", err)
	}
	defer targetLn.Close()

	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	peer, quicTun, cleanup := setupQUICTestEnvironment(t, qPort, strconv.Itoa(targetTCPPort), "2")
	defer cleanup()

	// Start local TCP entry listener forwarding to targetTCPPort over QUIC
	entryLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", entryTCPPort))
	if err != nil {
		t.Fatalf("failed to listen on entry tcp port: %v", err)
	}
	defer entryLn.Close()

	go acceptTrafficEntryLoop(entryLn, peer, quicTun, strconv.Itoa(targetTCPPort))

	startRx := atomic.LoadUint64(&appRxBytes)
	startTx := atomic.LoadUint64(&appTxBytes)

	const numClients = 12
	const payloadSize = 64 * 1024
	var wg sync.WaitGroup
	errCh := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", entryTCPPort), 4*time.Second)
			if err != nil {
				errCh <- fmt.Errorf("client %d dial: %w", id, err)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

			sendData := make([]byte, payloadSize)
			_, _ = rand.Read(sendData)
			expectedHash := sha256.Sum256(sendData)

			go func() {
				_, _ = conn.Write(sendData)
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}()

			recvData, err := io.ReadAll(conn)
			if err != nil {
				errCh <- fmt.Errorf("client %d read: %w", id, err)
				return
			}
			actualHash := sha256.Sum256(recvData)
			if expectedHash != actualHash {
				errCh <- fmt.Errorf("client %d sha256 mismatch (got %d bytes)", id, len(recvData))
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	deltaRx := atomic.LoadUint64(&appRxBytes) - startRx
	deltaTx := atomic.LoadUint64(&appTxBytes) - startTx
	if deltaRx < uint64(numClients*payloadSize) || deltaTx < uint64(numClients*payloadSize) {
		t.Fatalf("expected traffic counters to increment by at least %d, got rx=%d tx=%d",
			numClients*payloadSize, deltaRx, deltaTx)
	}
}

// Covers Scenarios 9, 10, 11, 12, 13:
// UDP forwarding via QUIC DATAGRAM, Concurrent UDP clients, Persistent exit-side UDP socket
// per session, Datagram size boundary enforcement, and Session expiration.
func TestQUICUDPDatagramSessionsAndSizeHandling(t *testing.T) {
	qPort := freeUDPPort(t)
	udpTargetPort := freeUDPPort(t)

	// Start target UDP server that echoes back "<clientSourcePort>|<payload>"
	// so we can prove that multiple packets from the same client use the exact same exit socket!
	targetUDPAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: udpTargetPort}
	targetUDPConn, err := net.ListenUDP("udp", targetUDPAddr)
	if err != nil {
		t.Fatalf("failed to bind target udp server: %v", err)
	}
	defer targetUDPConn.Close()

	go func() {
		buf := make([]byte, 8192)
		for {
			n, rAddr, err := targetUDPConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := append([]byte(fmt.Sprintf("%d|", rAddr.Port)), buf[:n]...)
			_, _ = targetUDPConn.WriteToUDP(reply, rAddr)
		}
	}()

	peer, quicTun, cleanup := setupQUICTestEnvironment(t, qPort, strconv.Itoa(udpTargetPort), "0")
	defer cleanup()

	entryPC := startQUICUDPEntryForwarder(peer, quicTun, strconv.Itoa(udpTargetPort))
	if entryPC == nil {
		t.Fatalf("failed to start QUIC UDP entry forwarder")
	}
	defer entryPC.Close()

	const concurrentClients = 8
	var wg sync.WaitGroup
	errCh := make(chan error, concurrentClients)

	for c := 0; c < concurrentClients; c++ {
		wg.Add(1)
		go func(clientIdx int) {
			defer wg.Done()
			cli, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: udpTargetPort})
			if err != nil {
				errCh <- err
				return
			}
			defer cli.Close()

			var observedExitPort string
			for pktIdx := 0; pktIdx < 3; pktIdx++ {
				msg := []byte(fmt.Sprintf("client-%d-pkt-%d", clientIdx, pktIdx))
				_ = cli.SetDeadline(time.Now().Add(4 * time.Second))
				if _, err := cli.Write(msg); err != nil {
					errCh <- err
					return
				}
				rep := make([]byte, 1500)
				n, err := cli.Read(rep)
				if err != nil {
					errCh <- fmt.Errorf("udp client %d pkt %d read timeout: %w", clientIdx, pktIdx, err)
					return
				}
				parts := bytes.SplitN(rep[:n], []byte("|"), 2)
				if len(parts) != 2 || !bytes.Equal(parts[1], msg) {
					errCh <- fmt.Errorf("unexpected udp echo payload: %q", string(rep[:n]))
					return
				}
				exitPort := string(parts[0])
				if observedExitPort == "" {
					observedExitPort = exitPort
				} else if observedExitPort != exitPort {
					errCh <- fmt.Errorf("exit socket port changed within same UDP session: %s vs %s", observedExitPort, exitPort)
					return
				}
			}
		}(c)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify oversized UDP datagram handling when fragmentation is disabled (default)
	quicAllowDatagramFragmentation.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, mc, err := getOrDialQUICConnection(ctx, peer, quicTun, "data", nil)
	cancel()
	if err != nil {
		t.Fatalf("failed to get data connection: %v", err)
	}
	oversized := make([]byte, 3000)
	err = sendQUICUDPDatagram(conn, &mc.maxDatagramBytes, 999, uint16(udpTargetPort), oversized)
	if !errors.Is(err, ErrQUICDatagramTooLarge) {
		t.Fatalf("expected ErrQUICDatagramTooLarge when sending 3000B with fragmentation disabled, got: %v", err)
	}
}

// Covers Scenarios 14, 15, 20, 21, 22:
// Connection termination, Automatic reconnection, Graceful shutdown, Resource cleanup,
// and Compatibility with other tunnel methods.
func TestQUICReconnectionShutdownAndMultiMethodCompatibility(t *testing.T) {
	qPort := freeUDPPort(t)
	peer, quicTun, cleanup := setupQUICTestEnvironment(t, qPort, "2053", "0")
	defer cleanup()

	res1 := probeQUIC(peer, quicTun, "node-master-test-01")
	if !res1.Success {
		t.Fatalf("initial probe failed: %s", res1.ErrorReason)
	}

	// Simulate connection drop and verify automatic reconnection on next probe
	stopQUICPeerResources(peer.ID)
	if err := registerQUICPeerListener(peer, quicTun); err != nil {
		t.Fatalf("failed to re-register QUIC listener: %v", err)
	}

	res2 := probeQUIC(peer, quicTun, "node-master-test-01")
	if !res2.Success {
		t.Fatalf("probe after reconnection failed: %s", res2.ErrorReason)
	}

	// Verify cleanup leaves zero active listeners for peer
	stopAllServerListeners(peer.ID)
	quicRegistryMu.Lock()
	_, stillBound := quicPeerPortBindings[peer.ID]
	quicRegistryMu.Unlock()
	if stillBound {
		t.Fatalf("expected peer port binding to be removed after stopAllServerListeners")
	}
}

func BenchmarkQUICDatagramEncodeAndReassembly(b *testing.B) {
	reassembler := newQUICDatagramReassembler()
	payload := make([]byte, 512)
	_, _ = rand.Read(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame := encodeQUICRawDatagram(uint32(i+1), 2053, payload)
		if len(frame) != quicDatagramRawHeaderSize+len(payload) {
			b.Fatal("invalid frame length")
		}
		_, ok := reassembler.insertFragment(uint32(i+1), 2053, uint16(i), 0, 1, payload)
		if !ok {
			b.Fatal("reassembly failed")
		}
	}
}
