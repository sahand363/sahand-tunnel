package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setupWSSTestEnv(t *testing.T) (ServerPeer, TunnelConfig) {
	t.Helper()

	tmpDir := t.TempDir()
	t.Setenv("SAHAND_CONFIG", filepath.Join(tmpDir, "config.json"))

	cPEM, kPEM, pin, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert failed: %v", err)
	}
	sec, err := randomHex(32)
	if err != nil {
		t.Fatalf("randomHex failed: %v", err)
	}

	cfg := Config{
		Role:          "master",
		NodeID:        "master-node-01",
		PanelPort:     18080,
		ListenAddr:    ":18080",
		AdminUsername: "admin",
		TokenSecret:   sec,
		TLSCertPEM:    cPEM,
		TLSKeyPEM:     kPEM,
		CertPin:       pin,
	}

	peer := ServerPeer{
		ID:            "agent-peer-01",
		Name:          "Test-Agent",
		IP:            "127.0.0.1",
		ConfigVersion: 1,
		Running:       true,
		Status:        "CONNECTED",
		RemoteCertPin: pin,
		Tunnels:       defaultTunnelsForServer(),
	}

	if _, err := ensureCryptoMaterial(&cfg); err != nil {
		t.Fatalf("ensureCryptoMaterial failed: %v", err)
	}
	tok, err := generatePeerToken(cfg, peer)
	if err != nil {
		t.Fatalf("generatePeerToken failed: %v", err)
	}
	peer.Token = tok
	cfg.Servers = []ServerPeer{peer}

	stateMu.Lock()
	appCfg = cfg
	stateMu.Unlock()

	return peer, peer.Tunnels[0]
}

func startLocalTCPEchoTarget(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local TCP target: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return port, func() {
		_ = ln.Close()
	}
}

func allocateFreeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free TCP port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestWSSRFC6455ProbeAndPinVerification(t *testing.T) {
	peer, tc := setupWSSTestEnv(t)
	tc.ListenPort = allocateFreeTCPPort(t)
	tc.Enabled = true
	tc.WSPath = "/ws"
	tc.SNI = "www.speedtest.net"

	ln, err := startWSSServerListener(peer, tc)
	if err != nil {
		t.Fatalf("startWSSServerListener failed: %v", err)
	}
	defer func() {
		_ = ln.Close()
		stopWSSPeerResources(peer.ID)
	}()

	// 1. Valid RFC 6455 probe with pinned certificate
	res := probeWSS(peer, tc, "master-node-01")
	if !res.Success {
		t.Fatalf("expected RFC 6455 probeWSS to succeed, got error: %s", res.ErrorReason)
	}
	if res.LatencyMS <= 0 {
		t.Fatalf("expected positive latency_ms, got %d", res.LatencyMS)
	}

	// 2. Valid RFC 6455 probe with empty pin (uses standard RootCAs + hostname verification)
	unpinnedPeer := peer
	unpinnedPeer.RemoteCertPin = ""
	unpinnedTC := tc
	unpinnedTC.CertPin = ""
	resUnpinned := probeWSS(unpinnedPeer, unpinnedTC, "master-node-01")
	if !resUnpinned.Success {
		t.Fatalf("expected unpinned standard X.509 verified probeWSS to succeed, got: %s", resUnpinned.ErrorReason)
	}

	// 3. Invalid certificate pin must fail with TLS failure
	badTC := tc
	badTC.CertPin = "0000000000000000000000000000000000000000000000000000000000000000"
	resBad := probeWSS(peer, badTC, "master-node-01")
	if resBad.Success {
		t.Fatalf("expected probeWSS with mismatched cert pin to fail")
	}
	if resBad.ErrorReason != "TLS failure" {
		t.Fatalf("expected TLS failure for mismatched pin, got %q", resBad.ErrorReason)
	}
}

func TestWSSRFC6455MultiPortAndLargeStreamForwarding(t *testing.T) {
	peer, tc := setupWSSTestEnv(t)

	targetPort1, closeTarget1 := startLocalTCPEchoTarget(t)
	defer closeTarget1()
	targetPort2, closeTarget2 := startLocalTCPEchoTarget(t)
	defer closeTarget2()

	tc.ListenPort = allocateFreeTCPPort(t)
	tc.Enabled = true
	tc.WSPath = "/ws"
	tc.SNI = "www.speedtest.net"
	tc.HeartbeatSec = 5
	tc.ForwardPorts = strconv.Itoa(targetPort1) + "," + strconv.Itoa(targetPort2)

	ln, err := startWSSServerListener(peer, tc)
	if err != nil {
		t.Fatalf("startWSSServerListener failed: %v", err)
	}
	defer func() {
		_ = ln.Close()
		stopWSSPeerResources(peer.ID)
	}()

	// Start Master-side entry listeners for both forwarded ports
	entryLn1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind entry listener 1: %v", err)
	}
	defer entryLn1.Close()
	go acceptTrafficEntryLoop(entryLn1, peer, tc, strconv.Itoa(targetPort1))

	entryLn2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind entry listener 2: %v", err)
	}
	defer entryLn2.Close()
	go acceptTrafficEntryLoop(entryLn2, peer, tc, strconv.Itoa(targetPort2))

	startRx := atomic.LoadUint64(&appRxBytes)
	startTx := atomic.LoadUint64(&appTxBytes)

	// Run 6 concurrent TCP streams across both target ports, including 256 KB multi-chunk transfers
	var wg sync.WaitGroup
	errCh := make(chan error, 6)

	for i := 0; i < 6; i++ {
		wg.Add(1)
		entryAddr := entryLn1.Addr().String()
		if i%2 == 1 {
			entryAddr = entryLn2.Addr().String()
		}
		payloadSize := 256 * 1024
		go func(addr string, size int) {
			defer wg.Done()
			c, dErr := net.DialTimeout("tcp", addr, 5*time.Second)
			if dErr != nil {
				errCh <- dErr
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))

			sent := make([]byte, size)
			_, _ = io.ReadFull(rand.Reader, sent)

			go func() {
				_, _ = c.Write(sent)
			}()

			received := make([]byte, size)
			if _, rErr := io.ReadFull(c, received); rErr != nil {
				errCh <- rErr
				return
			}
			if !bytes.Equal(sent, received) {
				errCh <- io.ErrUnexpectedEOF
			}
		}(entryAddr, payloadSize)
	}

	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil {
			t.Fatalf("concurrent WSS stream forwarding failed: %v", e)
		}
	}

	endRx := atomic.LoadUint64(&appRxBytes)
	endTx := atomic.LoadUint64(&appTxBytes)
	if endRx <= startRx || endTx <= startTx {
		t.Fatalf("expected traffic counters to advance: rx %d->%d, tx %d->%d", startRx, endRx, startTx, endTx)
	}
}
