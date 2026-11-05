package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func setupSpoofNativeTestEnv(t *testing.T) (ServerPeer, TunnelConfig, TunnelConfig) {
	t.Helper()
	peer, _ := setupWSSTestEnv(t)
	var m26, m27 TunnelConfig
	for _, tc := range peer.Tunnels {
		if tc.ID == 26 {
			m26 = tc
		}
		if tc.ID == 27 {
			m27 = tc
		}
	}
	if m26.ID != 26 || m26.Name != "Spoof + WireGuard" {
		t.Fatalf("Method 26 (Spoof + WireGuard) missing or modified")
	}
	if m27.ID != 27 || m27.Name != "Native Spoof Engine" || !m27.Implemented {
		t.Fatalf("Method 27 (Native Spoof Engine) not properly initialized: %+v", m27)
	}
	return peer, m26, m27
}

// Simulates the bidirectional UDP datagram pipe provided by `spoof run -c`:
// Listens on `127.0.0.1:corePort` (Master side) and forwards every UDP datagram
// to `127.0.0.1:adapterPort` (Agent side), and forwards replies back.
func startSimulatedSpoofUDPPipe(t *testing.T) (corePort int, adapterPort int, closeFn func()) {
	t.Helper()
	adapterPort = allocateFreeUDPPort(t)
	coreAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	coreConn, err := net.ListenUDP("udp", coreAddr)
	if err != nil {
		t.Fatalf("ListenUDP coreConn failed: %v", err)
	}
	corePort = coreConn.LocalAddr().(*net.UDPAddr).Port

	adapterAddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(adapterPort)))
	upstreamConn, err := net.DialUDP("udp", nil, adapterAddr)
	if err != nil {
		_ = coreConn.Close()
		t.Fatalf("DialUDP adapterAddr failed: %v", err)
	}

	var lastClientMu sync.RWMutex
	var lastClientAddr *net.UDPAddr

	go func() {
		buf := make([]byte, 65535)
		for {
			n, cliAddr, rErr := coreConn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			lastClientMu.Lock()
			lastClientAddr = cloneUDPAddr(cliAddr)
			lastClientMu.Unlock()
			_, _ = upstreamConn.Write(buf[:n])
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, rErr := upstreamConn.Read(buf)
			if rErr != nil {
				return
			}
			lastClientMu.RLock()
			dst := lastClientAddr
			lastClientMu.RUnlock()
			if dst != nil {
				_, _ = coreConn.WriteToUDP(buf[:n], dst)
			}
		}
	}()

	return corePort, adapterPort, func() {
		_ = coreConn.Close()
		_ = upstreamConn.Close()
	}
}

func TestMethod27IsolationFromMethod26AndBundleExchange(t *testing.T) {
	tmpDir := t.TempDir()
	origM26Dir := spoofDir
	origM27Dir := spoofM27Dir
	origWG26Dir := wgConfDir
	origWG27Dir := wgM27ConfDir

	spoofDir = filepath.Join(tmpDir, "spoof-m26")
	spoofM27Dir = filepath.Join(tmpDir, "spoof-m27")
	wgConfDir = filepath.Join(tmpDir, "wg")
	wgM27ConfDir = wgConfDir
	defer func() {
		spoofDir = origM26Dir
		spoofM27Dir = origM27Dir
		wgConfDir = origWG26Dir
		wgM27ConfDir = origWG27Dir
	}()

	_, m26, m27 := setupSpoofNativeTestEnv(t)

	// 1. Verify complete resource isolation between Method 26 and Method 27
	if m26.ListenPort == m27.ListenPort || m26.ForwardPorts == m27.ForwardPorts {
		t.Fatalf("Method 26 and Method 27 ports collide: m26=%d/%s m27=%d/%s",
			m26.ListenPort, m26.ForwardPorts, m27.ListenPort, m27.ForwardPorts)
	}
	if m26.SpoofWG.SpoofListenPort == m27.SpoofNative.SpoofListenPort ||
		m26.SpoofWG.RecvPort == m27.SpoofNative.RecvPort ||
		m26.SpoofWG.CorePort == m27.SpoofNative.CorePort ||
		m26.SpoofWG.WGInterface == m27.SpoofNative.WGInterface ||
		m26.SpoofWG.WGLocalIP == m27.SpoofNative.WGLocalIP {
		t.Fatalf("Method 26 and Method 27 internal spoof/WG defaults collide")
	}

	// 2. Test Method 27 bundle round-trip across all 4 modes ("pure", "wireguard", "quic", "noise")
	for _, mode := range []string{"pure", "wireguard", "quic", "noise"} {
		localCfg := defaultSpoofNativeConfig()
		localCfg.Role = "local"
		localCfg.Mode = mode
		localCfg.StrictRealSpoof = true
		localCfg.LocalPublicIP = "203.0.113.10"
		localCfg.PeerPublicIP = "198.51.100.20"
		localCfg.SpoofIPs = []string{"8.8.8.8", "1.1.1.1"}
		localCfg.SendTransport = "tcp"
		localCfg.RecvTransport = "icmp"

		bStr, err := makeSpoofNativeBundle(localCfg, "")
		if err != nil {
			t.Fatalf("makeSpoofNativeBundle(%s) failed: %v", mode, err)
		}
		if !strings.HasPrefix(bStr, "m27spf1_") {
			t.Fatalf("expected m27spf1_ prefix for mode %s, got %q", mode, bStr)
		}

		// Ensure Method 26 rejects Method 27 bundles and vice versa
		if _, err := importSpoofWGBundle(bStr, nil); err == nil {
			t.Fatalf("Method 26 should reject Method 27 m27spf1_ bundle")
		}

		imported, err := importSpoofNativeBundle(bStr, &SpoofNativeConfig{SpoofIPs: []string{"9.9.9.9"}})
		if err != nil {
			t.Fatalf("importSpoofNativeBundle(%s) failed: %v", mode, err)
		}
		if imported.Role != "remote" || imported.Mode != mode {
			t.Fatalf("imported role/mode mismatch: role=%s mode=%s", imported.Role, imported.Mode)
		}
		if imported.SendTransport != "icmp" || imported.RecvTransport != "tcp" {
			t.Fatalf("expected mirrored transports icmp/tcp, got %s/%s", imported.SendTransport, imported.RecvTransport)
		}
		if mode == "wireguard" && (imported.WGPubKey != localCfg.WGPeerPub || imported.WGPeerPub != localCfg.WGPubKey) {
			t.Fatalf("WireGuard keys did not cross-match in mode=wireguard")
		}
		if mode == "noise" && (imported.NoisePubKey != localCfg.NoisePeerPub || imported.NoisePeerPub != localCfg.NoisePubKey) {
			t.Fatalf("Noise keys did not cross-match in mode=noise")
		}

		// 3. Verify config file isolation
		if err := writeSpoofNativeConfigs(localCfg); err != nil {
			t.Fatalf("writeSpoofNativeConfigs(%s) failed: %v", mode, err)
		}
		if _, err := os.Stat(spoofM27CoreConfigPath()); err != nil {
			t.Fatalf("Method 27 config.json was not written: %v", err)
		}
		if _, err := os.Stat(spoofCoreConfigPath()); err == nil {
			t.Fatalf("Method 27 erroneously wrote into Method 26 directory %s", spoofDir)
		}
		if mode == "pure" {
			if _, err := os.Stat(spoofM27WGConfPath(localCfg.WGInterface)); err == nil {
				t.Fatalf("Pure Spoof mode must NOT write a WireGuard config file")
			}
		} else if mode == "wireguard" {
			if _, err := os.Stat(spoofM27WGConfPath(localCfg.WGInterface)); err != nil {
				t.Fatalf("WireGuard mode failed to write %s: %v", localCfg.WGInterface, err)
			}
		}
	}
}

func TestMethod27PureAndNoiseAdaptersStrictVerificationAndForwarding(t *testing.T) {
	peer, m26, m27 := setupSpoofNativeTestEnv(t)

	tcpTargetPort, closeTCP := startLocalTCPEchoTarget(t)
	defer closeTCP()

	udpTargetAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpTargetConn, err := net.ListenUDP("udp", udpTargetAddr)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer udpTargetConn.Close()
	udpTargetPort := udpTargetConn.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 8192)
		for {
			n, addr, rErr := udpTargetConn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			_, _ = udpTargetConn.WriteToUDP(buf[:n], addr)
		}
	}()

	// Also start Method 26 simultaneously to prove zero interference
	m26.ListenPort = allocateFreeTCPPort(t)
	m26Ln, err := startSpoofWGServerListener(peer, m26)
	if err != nil {
		t.Fatalf("Method 26 startSpoofWGServerListener failed: %v", err)
	}
	defer func() {
		_ = m26Ln.Close()
		stopSpoofWGPeerResources(peer.ID)
	}()

	for _, mode := range []string{"pure", "noise", "quic"} {
		corePort, adapterPort, closePipe := startSimulatedSpoofUDPPipe(t)

		m27.ListenPort = allocateFreeUDPPort(t)
		m27.Enabled = true
		m27.ForwardPorts = strconv.Itoa(tcpTargetPort) + "," + strconv.Itoa(udpTargetPort)
		m27.SpoofNative = defaultSpoofNativeConfig()
		m27.SpoofNative.Mode = mode
		m27.SpoofNative.StrictRealSpoof = true
		m27.SpoofNative.SpoofIPs = []string{"8.8.8.8"}
		m27.SpoofNative.CorePort = corePort
		m27.SpoofNative.AdapterPort = adapterPort

		stateMu.Lock()
		appCfg.Servers[0].Tunnels[26] = m27
		peer = appCfg.Servers[0]
		stateMu.Unlock()

		tLn, uConn, err := startSpoofNativeServer(peer, m27)
		if err != nil {
			closePipe()
			t.Fatalf("startSpoofNativeServer(%s) failed: %v", mode, err)
		}

		// 1. Verify end-to-end probe over simulated Spoof Pipe succeeds in Strict Mode
		res := probeSpoofNative(peer, m27, "master-node-01")
		if !res.Success {
			closePipe()
			stopSpoofNativePeerResources(peer.ID)
			t.Fatalf("probeSpoofNative(%s) over Spoof Pipe failed: %s", mode, res.ErrorReason)
		}

		health := querySpoofNativeRuntimeHealth(peer.ID, m27.SpoofNative)
		if !health.RealSpoofActive || health.ConnectionState != "REAL SPOOF ACTIVE" {
			closePipe()
			stopSpoofNativePeerResources(peer.ID)
			t.Fatalf("expected REAL SPOOF ACTIVE for mode %s, got state=%q badge=%q",
				mode, health.ConnectionState, health.StatusBadge)
		}

		// 2. Verify Parity Sync over Spoof Pipe
		if !pushSpoofNativeParitySync(peer, m27, res.LatencyMS) {
			closePipe()
			stopSpoofNativePeerResources(peer.ID)
			t.Fatalf("pushSpoofNativeParitySync(%s) failed", mode)
		}

		// 3. Verify TCP stream forwarding over Spoof Pipe
		entryLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			closePipe()
			stopSpoofNativePeerResources(peer.ID)
			t.Fatalf("entryLn failed: %v", err)
		}
		go acceptTrafficEntryLoop(entryLn, peer, m27, strconv.Itoa(tcpTargetPort))

		cli, err := net.DialTimeout("tcp", entryLn.Addr().String(), 4*time.Second)
		if err != nil {
			_ = entryLn.Close()
			closePipe()
			stopSpoofNativePeerResources(peer.ID)
			t.Fatalf("DialTimeout entryLn(%s) failed: %v", mode, err)
		}
		_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
		msg := make([]byte, 8192)
		_, _ = io.ReadFull(rand.Reader, msg)
		go func() {
			_, _ = cli.Write(msg)
		}()
		echoed := make([]byte, len(msg))
		if _, err := io.ReadFull(cli, echoed); err != nil || !bytes.Equal(msg, echoed) {
			_ = cli.Close()
			_ = entryLn.Close()
			closePipe()
			stopSpoofNativePeerResources(peer.ID)
			t.Fatalf("Method 27 (%s) TCP echo mismatch: err=%v", mode, err)
		}
		_ = cli.Close()
		_ = entryLn.Close()

		// 4. Verify Strict Real Spoof blocks direct fallback when the Spoof Pipe is closed!
		closePipe()
		strictFailRes := probeSpoofNative(peer, m27, "master-node-01")
		if strictFailRes.Success {
			stopSpoofNativePeerResources(peer.ID)
			t.Fatalf("StrictRealSpoof=true MUST fail when Spoof Pipe is down (mode=%s), but succeeded!", mode)
		}

		// 5. Verify Method 26 still works simultaneously without any impact
		if m26Res := probeSpoofWG(peer, m26, "master-node-01"); !m26Res.Success {
			stopSpoofNativePeerResources(peer.ID)
			t.Fatalf("Method 26 probe failed while Method 27 was active: %s", m26Res.ErrorReason)
		}

		if tLn != nil {
			_ = tLn.Close()
		}
		if uConn != nil {
			_ = uConn.Close()
		}
		stopSpoofNativePeerResources(peer.ID)
	}
}
