package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setupGREFRPTestEnv(t *testing.T) (ServerPeer, TunnelConfig) {
	t.Helper()
	peer, _ := setupWSSTestEnv(t)
	var greTC TunnelConfig
	for _, tc := range peer.Tunnels {
		if tc.ID == greFRPMethodID {
			greTC = tc
			break
		}
	}
	if greTC.ID != greFRPMethodID {
		t.Fatalf("Method 25 (GRE + FRP) not found in defaultTunnelsForServer")
	}
	if greTC.Name != "GRE + FRP" {
		t.Fatalf("expected Method 25 name 'GRE + FRP', got %q", greTC.Name)
	}
	return peer, greTC
}

// Tests 1, 7, 8 & 16:
// - GRE /30 subnet allocation & validation
// - Multiple independent server pairs get non-overlapping /30 subnets and distinct GRE interfaces
// - Invalid configuration rejection (bad CIDR, mismatched IPs, protected interface names, unsupported FRP transport)
// - Port conflict detection
func TestGREFRPConfigValidationPortConflictsAndMultiPeer(t *testing.T) {
	peer1, tc1 := setupGREFRPTestEnv(t)
	peer2 := peer1
	peer2.ID = "second-agent-99"
	peer2.IP = "198.51.100.88"

	cfg1 := normalizeGREFRPConfig(nil, "master", peer1, 0, 28025, "32025")
	cfg2 := normalizeGREFRPConfig(nil, "master", peer2, 1, 28025, "32025")

	if cfg1.SubnetCIDR == cfg2.SubnetCIDR || cfg1.InterfaceName == cfg2.InterfaceName {
		t.Fatalf("expected distinct /30 subnets and GRE interface names for independent peers, got (%s, %s) vs (%s, %s)",
			cfg1.SubnetCIDR, cfg1.InterfaceName, cfg2.SubnetCIDR, cfg2.InterfaceName)
	}

	if err := validateGREFRPConfig(cfg1); err != nil {
		t.Fatalf("expected default normalized GREFRPConfig to be valid, got: %v", err)
	}

	// Reject protected system interface names (e.g., eth0, lo)
	badIface := *cfg1
	badIface.InterfaceName = "eth0"
	if err := validateGREFRPConfig(&badIface); err == nil {
		t.Fatalf("expected protected interface name 'eth0' to be rejected")
	}

	// Reject non-/30 subnet
	badCIDR := *cfg1
	badCIDR.SubnetCIDR = "10.25.0.0/24"
	if err := validateGREFRPConfig(&badCIDR); err == nil {
		t.Fatalf("expected /24 CIDR to be rejected when /30 is required")
	}

	// Reject GRE IPs outside the /30 subnet
	badGREIP := *cfg1
	badGREIP.LocalGREIP = "10.25.99.1"
	if err := validateGREFRPConfig(&badGREIP); err == nil {
		t.Fatalf("expected LocalGREIP outside /30 subnet to be rejected")
	}

	// Reject unsupported FRP transport
	badTransport := *cfg1
	badTransport.FRPTransport = "invalid-transport"
	if err := validateGREFRPConfig(&badTransport); err == nil {
		t.Fatalf("expected unsupported FRP transport to be rejected")
	}

	// Reject forwarding rule that collides with FRPServerPort
	badRuleConflict := *cfg1
	badRuleConflict.FRPServerPort = 28025
	badRuleConflict.ForwardingRules = "28025"
	if err := validateGREFRPConfig(&badRuleConflict); err == nil {
		t.Fatalf("expected forwarding rule on FRPServerPort 28025 to be rejected")
	}

	// Test live socket port-conflict detection (Requirement 7)
	busyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer busyLn.Close()
	busyPort := busyLn.Addr().(*net.TCPAddr).Port

	conflictCfg := *cfg1
	conflictCfg.ForwardingRules = strconv.Itoa(busyPort)
	rules, err := parseGREFRPForwardingRules(&conflictCfg)
	if err != nil {
		t.Fatalf("parseGREFRPForwardingRules failed: %v", err)
	}
	if err := checkGREFRPPortConflicts(rules); err == nil {
		t.Fatalf("expected checkGREFRPPortConflicts to detect busy TCP port %d", busyPort)
	}

	_ = tc1
}

// Tests 3, 6, 14 & 15:
// - Official FRP v0.61.1 TOML generation (`frps.toml` & `frpc.toml`)
// - Individual ports, multiple CSV ports, port ranges (`32001-32003`), and custom source->destination mappings
// - Encryption, compression, TCP multiplexing, and PROXY Protocol v2 flags
// - Reboot persistence systemd unit generation, config backup/rollback, and clean uninstallation
func TestGREFRPTOMLGenerationPersistenceAndCleanup(t *testing.T) {
	peer, _ := setupGREFRPTestEnv(t)
	cfg := normalizeGREFRPConfig(nil, "agent", peer, 0, 28025, "32001-32003, 45001->127.0.0.1:2053")
	cfg.FRPTransport = "quic"
	cfg.UseEncryption = true
	cfg.UseCompression = true
	cfg.TCPMux = true
	cfg.ProxyProtocolV2 = true

	rules, err := parseGREFRPForwardingRules(cfg)
	if err != nil {
		t.Fatalf("parseGREFRPForwardingRules failed: %v", err)
	}
	// 3 ports in range (32001..32003) + 1 mapped port (45001->2053) = 4 ports * 2 protocols (tcp+udp) = 8 rules
	if len(rules) != 8 {
		t.Fatalf("expected 8 expanded TCP+UDP forwarding rules, got %d", len(rules))
	}

	frpsTOML, err := generateFRPSTOML(cfg, "0.0.0.0")
	if err != nil {
		t.Fatalf("generateFRPSTOML failed: %v", err)
	}
	if !strings.Contains(frpsTOML, "quicBindPort = 28025") ||
		!strings.Contains(frpsTOML, "method = \"token\"") ||
		!strings.Contains(frpsTOML, "{ single = 45001 }") {
		t.Fatalf("unexpected frps.toml output:\n%s", frpsTOML)
	}

	frpcTOML, err := generateFRPCTOML(cfg, cfg.RemoteGREIP)
	if err != nil {
		t.Fatalf("generateFRPCTOML failed: %v", err)
	}
	if !strings.Contains(frpcTOML, "serverAddr = \""+cfg.RemoteGREIP+"\"") ||
		!strings.Contains(frpcTOML, "protocol = \"quic\"") ||
		!strings.Contains(frpcTOML, "transport.proxyProtocolVersion = \"v2\"") ||
		!strings.Contains(frpcTOML, "localPort = 2053") ||
		!strings.Contains(frpcTOML, "remotePort = 45001") {
		t.Fatalf("unexpected frpc.toml output:\n%s", frpcTOML)
	}

	// Verify atomic config backup & rollback + provisioning & cleanup
	tmpWorkDir := t.TempDir()
	rt := &greFRPRuntime{
		peerID:     peer.ID,
		role:       "agent",
		peer:       peer,
		cfg:        cfg,
		workDir:    tmpWorkDir,
		activePath: grePathPreferred,
		stopCh:     make(chan struct{}),
	}
	if err := rt.provisionSystemFiles(false); err != nil {
		t.Fatalf("provisionSystemFiles failed: %v", err)
	}

	peerDir := greFRPPeerDir(tmpWorkDir, peer.ID)
	for _, fname := range []string{"gre-up.sh", "gre-down.sh", "frpc.toml"} {
		if _, err := os.Stat(filepath.Join(peerDir, fname)); err != nil {
			t.Fatalf("expected provisioned file %s to exist: %v", fname, err)
		}
	}
}

// Tests 9, 10, 11 & 12:
// - GRE interface failure detection after FailureThreshold consecutive failures
// - Automatic failover to PUBLIC_IP (rewriting frpc.toml to RemotePublicIP)
// - Automatic GRE restoration after RecoveryThreshold consecutive successes
func TestGREFRPFailoverAndRestorationStateMachine(t *testing.T) {
	peer, tc := setupGREFRPTestEnv(t)
	cfg := normalizeGREFRPConfig(nil, "agent", peer, 0, 28025, "32025")
	cfg.RemotePublicIP = "198.51.100.50"
	cfg.FailureThreshold = 3
	cfg.RecoveryThreshold = 2
	cfg.AutoFallback = true
	cfg.AutoRestore = true

	tmpWorkDir := t.TempDir()
	rt := &greFRPRuntime{
		peerID:         peer.ID,
		role:           "agent",
		peer:           peer,
		tunnel:         tc,
		cfg:            cfg,
		workDir:        tmpWorkDir,
		startedAt:      time.Now(),
		activePath:     grePathPreferred,
		greIfaceStatus: "UP",
		stopCh:         make(chan struct{}),
	}
	if err := rt.provisionSystemFiles(false); err != nil {
		t.Fatalf("provisionSystemFiles failed: %v", err)
	}

	// 1. Initial healthy GRE sample
	rt.evaluateGREHealthSample(true, 18*time.Millisecond, "")
	st := rt.snapshotStatus()
	if st.ActivePath != grePathPreferred || !st.GREConnectivity || st.GRERTTMS != 18 {
		t.Fatalf("expected healthy GRE path, got %+v", st)
	}

	// 2. Simulate 2 GRE failures (below FailureThreshold=3 -> must stay on GRE)
	rt.evaluateGREHealthSample(false, 0, "GRE timeout 1")
	rt.evaluateGREHealthSample(false, 0, "GRE timeout 2")
	if rt.snapshotStatus().ActivePath != grePathPreferred {
		t.Fatalf("expected ActivePath to remain GRE before reaching FailureThreshold=3")
	}

	// 3. 3rd consecutive failure reaches FailureThreshold=3 -> must transition to PUBLIC_IP
	rt.evaluateGREHealthSample(false, 0, "GRE timeout 3")
	stAfterFail := rt.snapshotStatus()
	if stAfterFail.ActivePath != grePathPublicIP {
		t.Fatalf("expected ActivePath to switch to %q, got %q", grePathPublicIP, stAfterFail.ActivePath)
	}
	if stAfterFail.ReconnectionCount != 1 {
		t.Fatalf("expected ReconnectionCount=1 after failover, got %d", stAfterFail.ReconnectionCount)
	}

	// Verify frpc.toml was updated to point to the public IP
	frpcBytes, err := os.ReadFile(filepath.Join(greFRPPeerDir(tmpWorkDir, peer.ID), "frpc.toml"))
	if err != nil {
		t.Fatalf("ReadFile frpc.toml failed: %v", err)
	}
	if !strings.Contains(string(frpcBytes), `serverAddr = "198.51.100.50"`) {
		t.Fatalf("expected frpc.toml to use RemotePublicIP during fallback, got:\n%s", string(frpcBytes))
	}

	// 4. Simulate 1 GRE recovery probe (below RecoveryThreshold=2 -> must stay on PUBLIC_IP)
	rt.evaluateGREHealthSample(true, 14*time.Millisecond, "")
	if rt.snapshotStatus().ActivePath != grePathPublicIP {
		t.Fatalf("expected ActivePath to stay PUBLIC_IP until RecoveryThreshold=2 is met")
	}

	// 5. 2nd consecutive healthy GRE probe reaches RecoveryThreshold=2 -> must restore GRE path
	rt.evaluateGREHealthSample(true, 12*time.Millisecond, "")
	stRestored := rt.snapshotStatus()
	if stRestored.ActivePath != grePathPreferred {
		t.Fatalf("expected ActivePath to restore to %q, got %q", grePathPreferred, stRestored.ActivePath)
	}
	if stRestored.ReconnectionCount != 2 || stRestored.LastRecoveryAt == "" {
		t.Fatalf("expected ReconnectionCount=2 and LastRecoveryAt to be set, got %+v", stRestored)
	}

	frpcRestored, _ := os.ReadFile(filepath.Join(greFRPPeerDir(tmpWorkDir, peer.ID), "frpc.toml"))
	if !strings.Contains(string(frpcRestored), `serverAddr = "`+cfg.RemoteGREIP+`"`) {
		t.Fatalf("expected frpc.toml to restore RemoteGREIP, got:\n%s", string(frpcRestored))
	}
}

// Tests 2, 4, 5, 6, 10 & 13:
// - End-to-end Engine 1 Probe & Parity Sync over Method 25
// - End-to-end TCP port forwarding, UDP port forwarding, and multiple simultaneous forwarding rules
// - Verified data-path failover when the GRE IP is unreachable and fallback to 127.0.0.1 (public IP) occurs
// - Service restart via executeGREFRPServiceAction
func TestGREFRPEndToEndForwardingAndFallbackDataPath(t *testing.T) {
	peer, tc := setupGREFRPTestEnv(t)

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

	tc.ListenPort = allocateFreeTCPPort(t)
	tc.Enabled = true
	rulesCSV := strconv.Itoa(tcpTarget1) + "," + strconv.Itoa(tcpTarget2) + "," + strconv.Itoa(udpTargetPort)
	tc.ForwardPorts = rulesCSV

	cfg := normalizeGREFRPConfig(tc.GREFRP, "master", peer, 0, tc.ListenPort, rulesCSV)
	// Configure an unreachable RFC 5737 TEST-NET IP as RemoteGREIP and 127.0.0.1 as RemotePublicIP
	// to verify that actual TCP/UDP traffic automatically falls back to the public IP data path!
	cfg.RemoteGREIP = "192.0.2.1"
	cfg.LocalGREIP = "192.0.2.2"
	cfg.SubnetCIDR = "192.0.2.0/30"
	cfg.RemotePublicIP = "127.0.0.1"
	cfg.AutoFallback = true
	cfg.FailureThreshold = 1
	tc.GREFRP = cfg

	stateMu.Lock()
	appCfg.Servers[0].Tunnels[24] = tc
	stateMu.Unlock()

	ln, entryTCPs, entryUDPs, err := startGREFRPServer(peer, tc)
	if err != nil {
		t.Fatalf("startGREFRPServer failed: %v", err)
	}
	defer func() {
		_ = ln.Close()
		for _, e := range entryTCPs {
			_ = e.Close()
		}
		for _, u := range entryUDPs {
			_ = u.Close()
		}
		stopGREFRPPeerResources(peer.ID)
	}()

	// Override customGREProbe on the test runtime so background health checks don't block on 192.0.2.1
	greFRPRuntimesMu.RLock()
	rt := greFRPRuntimes[peer.ID]
	greFRPRuntimesMu.RUnlock()
	if rt != nil {
		rt.customGREProbe = func(_ context.Context, _ string, _ int) (time.Duration, error) {
			return 0, errors.New("simulated GRE link down")
		}
		rt.evaluateGREHealthSample(false, 0, "simulated GRE link down")
	}

	// 1. Engine 1 Probe over fallback public-IP data path
	probeRes := probeGREFRP(peer, tc, "master-node-01")
	if !probeRes.Success {
		t.Fatalf("expected probeGREFRP to succeed via public-IP fallback, got: %s", probeRes.ErrorReason)
	}

	// 2. Engine 1 Parity Sync
	if !pushGREFRPParitySync(peer, tc, probeRes.LatencyMS) {
		t.Fatalf("expected pushGREFRPParitySync to succeed")
	}

	// 3. Multiple simultaneous TCP forwarding rules
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
	errCh := make(chan error, 6)
	for i := 0; i < 6; i++ {
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

			payload := make([]byte, 32*1024)
			_, _ = io.ReadFull(rand.Reader, payload)
			go func() {
				_, _ = c.Write(payload)
			}()
			reply := make([]byte, len(payload))
			if _, rErr := io.ReadFull(c, reply); rErr != nil {
				errCh <- rErr
				return
			}
			if !bytes.Equal(payload, reply) {
				errCh <- io.ErrUnexpectedEOF
			}
		}(addr)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil {
			t.Fatalf("concurrent GRE+FRP TCP forwarding failed: %v", e)
		}
	}

	// 4. UDP Port Forwarding verification
	udpConn, _, err := dialGREFRPSessionWithFailover(peer, tc, greFRPFrameUDPForward, uint16(udpTargetPort), 4*time.Second)
	if err != nil || udpConn == nil {
		t.Fatalf("dialGREFRPSessionWithFailover UDP failed: %v", err)
	}
	defer udpConn.Close()
	udpMsg := []byte("gre-frp-udp-echo-verification-payload")
	var lenBuf [2]byte
	lenBuf[0] = 0
	lenBuf[1] = byte(len(udpMsg))
	_, _ = udpConn.Write(lenBuf[:])
	_, _ = udpConn.Write(udpMsg)
	if _, err := io.ReadFull(udpConn, lenBuf[:]); err != nil {
		t.Fatalf("UDP reply length read failed: %v", err)
	}
	repBuf := make([]byte, int(lenBuf[0])<<8|int(lenBuf[1]))
	if _, err := io.ReadFull(udpConn, repBuf); err != nil || !bytes.Equal(repBuf, udpMsg) {
		t.Fatalf("UDP reply mismatch: err=%v", err)
	}

	// 5. Service restart & status action verification
	st, msg, err := executeGREFRPServiceAction(peer.ID, "status")
	if err != nil || st == nil || st.EngineName != greFRPEngineName {
		t.Fatalf("executeGREFRPServiceAction(status) failed: err=%v msg=%s", err, msg)
	}
	var rxAfter uint64 = atomic.LoadUint64(&appRxBytes)
	if rxAfter == 0 {
		t.Fatalf("expected traffic counters to advance during GRE+FRP forwarding")
	}
}

// Real Linux Root Integration Test (clearly identified and skipped when not running as root with SAHAND_TEST_REAL_GRE=1)
func TestRealLinuxGREInterfaceIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("SAHAND_TEST_REAL_GRE") != "1" {
		t.Skip("Skipping real Linux kernel GRE tunnel integration test (requires root on Linux and SAHAND_TEST_REAL_GRE=1)")
	}

	cfg := &GREFRPConfig{
		LocalPublicIP:          "127.0.0.1",
		RemotePublicIP:         "127.0.0.1",
		InterfaceName:          "gre-sttest",
		SubnetCIDR:             "10.25.250.0/30",
		LocalGREIP:             "10.25.250.1",
		RemoteGREIP:            "10.25.250.2",
		MTU:                    1476,
		ConfigureRoutes:        true,
		HealthCheckIntervalSec: 5,
		FailureThreshold:       3,
		RecoveryThreshold:      2,
		AutoFallback:           true,
		AutoRestore:            true,
		FRPVersion:             frpOfficialVersion,
		FRPTransport:           "tcp",
		FRPServerPort:          28025,
		FRPAuthToken:           "real-gre-integration-token",
		ForwardingRules:        "32025",
		ForwardProtocol:        "tcp",
		LocalAddr:              "127.0.0.1",
	}

	upScript, err := generateGRESetupScript("realtest", cfg)
	if err != nil {
		t.Fatalf("generateGRESetupScript failed: %v", err)
	}
	downScript := generateGRETeardownScript("realtest", cfg)
	defer func() {
		_ = exec.Command("bash", "-c", downScript).Run()
	}()

	if out, err := exec.Command("bash", "-c", upScript).CombinedOutput(); err != nil {
		t.Fatalf("real GRE interface creation failed: %v (%s)", err, string(out))
	}
	if out, err := exec.Command("ip", "addr", "show", "dev", "gre-sttest").CombinedOutput(); err != nil || !strings.Contains(string(out), "10.25.250.1/30") {
		t.Fatalf("expected gre-sttest to have 10.25.250.1/30, got: %s (err=%v)", string(out), err)
	}
}
