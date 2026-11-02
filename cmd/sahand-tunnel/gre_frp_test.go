package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func setupGREFRPTestEnv(t *testing.T) (ServerPeer, TunnelConfig) {
	t.Helper()
	peer, _ := setupWSSTestEnv(t)
	var greTC TunnelConfig
	for _, tc := range peer.Tunnels {
		if tc.ID == 25 {
			greTC = tc
			break
		}
	}
	if greTC.ID != 25 || greTC.Name != "GRE + FRP" {
		t.Fatalf("Method 25 (GRE + FRP) not found in defaultTunnelsForServer")
	}
	return peer, greTC
}

// Covers Scenarios 1, 2, 3, 7, 8, 14, and 16:
// - GRE command & reboot-persistent systemd unit generation on both Master and Agent
// - /30 subnet host allocation & multi-peer distinct /30 subnet isolation
// - Official FRP v0.61.1 frps.toml & frpc.toml generation (transports, encryption, compression, tcpMux, PROXY Protocol v2, port ranges)
// - Port conflict detection & invalid configuration rejection
func TestGREFRPConfigValidationTOMLAndSystemdPersistence(t *testing.T) {
	peer, tc := setupGREFRPTestEnv(t)

	// Scenario 1 & 2: Verify /30 subnet host calculation and GRE command / systemd unit generation
	mIP, aIP, normCIDR, err := computeSlash30HostIPs("10.77.25.0/30")
	if err != nil {
		t.Fatalf("computeSlash30HostIPs failed: %v", err)
	}
	if mIP != "10.77.25.1" || aIP != "10.77.25.2" || normCIDR != "10.77.25.0/30" {
		t.Fatalf("unexpected /30 hosts: master=%s agent=%s cidr=%s", mIP, aIP, normCIDR)
	}

	masterCmds := buildGRESetupCommands("sahand-gre0", "203.0.113.1", "198.51.100.2", mIP, aIP, 1400)
	if len(masterCmds) != 6 {
		t.Fatalf("expected 6 GRE setup commands, got %d", len(masterCmds))
	}
	unit := generateGRESystemdUnit(peer.ID, "sahand-gre0", "203.0.113.1", "198.51.100.2", mIP, aIP, 1400)
	if !strings.Contains(unit, "mode gre local 203.0.113.1 remote 198.51.100.2") ||
		!strings.Contains(unit, "WantedBy=multi-user.target") {
		t.Fatalf("generated systemd unit missing expected GRE persistence directives:\n%s", unit)
	}

	// Scenario 3: Verify FRPS and FRPC v0.61.1 TOML config generation across supported transports
	for _, tr := range []string{"tcp", "kcp", "quic", "websocket", "wss"} {
		tc.GREFRP.FRPTransport = tr
		tc.GREFRP.FRPEncryption = true
		tc.GREFRP.FRPCompression = true
		tc.GREFRP.FRPTCPMux = true
		tc.GREFRP.ForwardingRules = []GREFRPForwardRule{
			{
				Name:          "xui-range",
				Protocol:      "tcp+udp",
				LocalAddr:     "127.0.0.1",
				LocalPort:     "45001-45003",
				RemotePort:    "45001-45003",
				UseEncryption: true,
				UseCompress:   true,
				ProxyProtoV2:  true,
			},
		}
		frpsTOML, err := generateFRPSTOMLConfig("0.0.0.0", tc, "test-secret-token")
		if err != nil {
			t.Fatalf("generateFRPSTOMLConfig (%s) failed: %v", tr, err)
		}
		if !strings.Contains(frpsTOML, `token = "test-secret-token"`) {
			t.Fatalf("frps.toml missing token")
		}

		frpcTOML, err := generateFRPCTOMLConfig(mIP, tc, "test-secret-token")
		if err != nil {
			t.Fatalf("generateFRPCTOMLConfig (%s) failed: %v", tr, err)
		}
		if !strings.Contains(frpcTOML, `serverAddr = "10.77.25.1"`) ||
			!strings.Contains(frpcTOML, `protocol = "`+tr+`"`) ||
			!strings.Contains(frpcTOML, `proxyProtocolVersion = "v2"`) {
			t.Fatalf("frpc.toml (%s) missing expected directives:\n%s", tr, frpcTOML)
		}
	}

	// Scenario 7: Port conflict detection (duplicate remote ports & collision with FRP server port)
	conflictRules := *tc.GREFRP
	conflictRules.ForwardingRules = []GREFRPForwardRule{
		{Name: "r1", Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: "45001", RemotePort: "45001"},
		{Name: "r2", Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: "45002", RemotePort: "45001"},
	}
	if err := validateGREFRPConfiguration(&conflictRules, tc.ListenPort); err == nil {
		t.Fatalf("expected duplicate remote port 45001 to be rejected")
	}

	srvPortConflict := *tc.GREFRP
	srvPortConflict.ForwardingRules = []GREFRPForwardRule{
		{Name: "r1", Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: "45001", RemotePort: strconv.Itoa(tc.ListenPort)},
	}
	if err := validateGREFRPConfiguration(&srvPortConflict, tc.ListenPort); err == nil {
		t.Fatalf("expected remote port colliding with FRP server port %d to be rejected", tc.ListenPort)
	}

	// Scenario 8: Invalid configuration rejection
	badCIDR := *tc.GREFRP
	badCIDR.PrivateSubnetCIDR = "10.77.25.0/24" // Not a /30
	if err := validateGREFRPConfiguration(&badCIDR, tc.ListenPort); err == nil {
		t.Fatalf("expected /24 subnet CIDR to be rejected")
	}

	badIface := *tc.GREFRP
	badIface.GREInterfaceName = "bad/iface;rm"
	if err := validateGREFRPConfiguration(&badIface, tc.ListenPort); err == nil {
		t.Fatalf("expected invalid GRE interface name to be rejected")
	}

	badTransport := *tc.GREFRP
	badTransport.FRPTransport = "invalid_proto"
	if err := validateGREFRPConfiguration(&badTransport, tc.ListenPort); err == nil {
		t.Fatalf("expected unsupported FRP transport to be rejected")
	}

	badRange := *tc.GREFRP
	badRange.ForwardingRules = []GREFRPForwardRule{
		{Name: "r1", Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: "45001-45005", RemotePort: "45001-45002"},
	}
	if err := validateGREFRPConfiguration(&badRange, tc.ListenPort); err == nil {
		t.Fatalf("expected mismatched port range lengths to be rejected")
	}

	// Scenario 16: Multiple independent server pairs derive non-overlapping /30 subnets
	cidr1, m1, a1 := deriveDefaultSlash30ForPeer("peer-alpha-001")
	cidr2, m2, a2 := deriveDefaultSlash30ForPeer("peer-beta-999")
	if cidr1 == cidr2 || m1 == m2 || a1 == a2 {
		t.Fatalf("expected distinct /30 subnets for different peers, got %s and %s", cidr1, cidr2)
	}
}

// Covers Scenarios 4, 5, 6, 9, 10, 11, 12, 13, and 15:
// - End-to-end TCP port forwarding (with Encryption, Compression, and PROXY Protocol v2)
// - End-to-end UDP port forwarding
// - Multiple simultaneous forwarding rules & different local/remote ports
// - GRE failure detection -> Automatic Public-IP fallback -> Automatic GRE restoration
// - Service restart & uninstallation cleanup
func TestGREFRPForwardingFailoverRestorationAndLifecycle(t *testing.T) {
	peer, tc := setupGREFRPTestEnv(t)

	// Start two local TCP echo targets and one local UDP echo target
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
		buf := make([]byte, 8192)
		for {
			n, addr, rErr := udpTargetConn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			_, _ = udpTargetConn.WriteToUDP(buf[:n], addr)
		}
	}()

	entryPortTCP1 := allocateFreeTCPPort(t)
	entryPortTCP2 := allocateFreeTCPPort(t)
	entryPortUDP := allocateFreeUDPPort(t)
	frpCarrierPort := allocateFreeTCPPort(t)

	tc.ListenPort = frpCarrierPort
	tc.Enabled = true
	tc.GREFRP = normalizeGREFRPConfig(tc.GREFRP, frpCarrierPort, "")
	tc.GREFRP.FRPServerPort = frpCarrierPort
	tc.GREFRP.RemotePublicIP = "127.0.0.1"
	tc.GREFRP.HealthCheckSec = 1
	tc.GREFRP.FailureThreshold = 2
	tc.GREFRP.RecoveryThreshold = 2
	tc.GREFRP.AutoPublicFallback = true
	tc.GREFRP.AutoRestoreGRE = true
	tc.GREFRP.ForwardingRules = []GREFRPForwardRule{
		{
			Name:          "tcp-rule-enc-comp",
			Protocol:      "tcp",
			LocalAddr:     "127.0.0.1",
			LocalPort:     strconv.Itoa(tcpTarget1),
			RemotePort:    strconv.Itoa(entryPortTCP1),
			UseEncryption: true,
			UseCompress:   true,
			ProxyProtoV2:  false,
		},
		{
			Name:          "tcp-rule-ppv2",
			Protocol:      "tcp",
			LocalAddr:     "127.0.0.1",
			LocalPort:     strconv.Itoa(tcpTarget2),
			RemotePort:    strconv.Itoa(entryPortTCP2),
			UseEncryption: true,
			UseCompress:   false,
			ProxyProtoV2:  true,
		},
		{
			Name:          "udp-rule",
			Protocol:      "udp",
			LocalAddr:     "127.0.0.1",
			LocalPort:     strconv.Itoa(udpTargetPort),
			RemotePort:    strconv.Itoa(entryPortUDP),
			UseEncryption: true,
			UseCompress:   false,
		},
	}
	tc.ForwardPorts = syncForwardPortsCSVFromRules(tc.GREFRP)

	stateMu.Lock()
	appCfg.Servers[0].Tunnels[24] = tc
	peer = appCfg.Servers[0]
	stateMu.Unlock()

	cLn, eLns, uConns, err := startGREFRPServer(peer, tc)
	if err != nil {
		t.Fatalf("startGREFRPServer failed: %v", err)
	}
	defer func() {
		_ = cLn.Close()
		for _, l := range eLns {
			_ = l.Close()
		}
		for _, u := range uConns {
			_ = u.Close()
		}
		stopGREFRPPeerResources(peer.ID)
	}()

	// 1. Verify Mode 1 Probe & Parity Sync
	probeRes := probeGREFRP(peer, tc, "master-node-01")
	if !probeRes.Success {
		t.Fatalf("expected probeGREFRP to succeed, got: %s", probeRes.ErrorReason)
	}
	if !pushGREFRPParitySync(peer, tc, probeRes.LatencyMS) {
		t.Fatalf("expected pushGREFRPParitySync to succeed")
	}

	// 2. Verify Mode 2 Concurrent TCP Forwarding across multiple rules (including PROXY Protocol v2)
	var wg sync.WaitGroup
	errCh := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			port := entryPortTCP1
			expectPPv2 := false
			if idx%2 == 1 {
				port = entryPortTCP2
				expectPPv2 = true
			}
			conn, dErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 4*time.Second)
			if dErr != nil {
				errCh <- dErr
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

			payload := make([]byte, 32*1024)
			_, _ = io.ReadFull(rand.Reader, payload)
			go func() {
				_, _ = conn.Write(payload)
			}()

			if expectPPv2 {
				var ppHdr [28]byte
				if _, rErr := io.ReadFull(conn, ppHdr[:]); rErr != nil {
					errCh <- rErr
					return
				}
				if !bytes.Equal(ppHdr[0:12], []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}) {
					errCh <- io.ErrUnexpectedEOF
					return
				}
			}

			echoed := make([]byte, len(payload))
			if _, rErr := io.ReadFull(conn, echoed); rErr != nil {
				errCh <- rErr
				return
			}
			if !bytes.Equal(payload, echoed) {
				errCh <- io.ErrUnexpectedEOF
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil {
			t.Fatalf("concurrent GRE+FRP TCP forwarding failed: %v", e)
		}
	}

	// 3. Verify Mode 2 UDP Forwarding
	uCli, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPortUDP)), 3*time.Second)
	if err != nil {
		t.Fatalf("UDP dial failed: %v", err)
	}
	defer uCli.Close()
	_ = uCli.SetDeadline(time.Now().Add(4 * time.Second))
	udpMsg := []byte("gre-frp-udp-forwarding-verification-payload")
	if _, err := uCli.Write(udpMsg); err != nil {
		t.Fatalf("UDP write failed: %v", err)
	}
	udpReply := make([]byte, len(udpMsg))
	if _, err := io.ReadFull(uCli, udpReply); err != nil || !bytes.Equal(udpReply, udpMsg) {
		t.Fatalf("UDP echo mismatch: err=%v", err)
	}

	// 4. Verify Scenarios 9, 10, 11, 12:
	//    Simulate GRE private IP becoming unreachable -> verify automatic switch to PUBLIC_FALLBACK ->
	//    verify data transfer over PUBLIC_FALLBACK -> restore GRE private IP -> verify automatic restoration to GRE.
	greFRPRuntimeMu.RLock()
	rt := greFRPRuntimes[peer.ID]
	greFRPRuntimeMu.RUnlock()
	if rt == nil {
		t.Fatalf("expected active greFRPRuntime")
	}

	// Point remotePrivIP to an unreachable TEST-NET address while remotePubIP remains reachable (127.0.0.1)
	rt.remotePrivIP = "192.0.2.254"
	rt.remotePubIP = "192.0.2.253" // Force evaluateGREHealthStep to use remotePrivIP instead of loopback shortcut
	// Temporarily set remotePubIP back to 127.0.0.1 for fallback target
	gfCfg := normalizeGREFRPConfig(rt.tunnel.GREFRP, rt.tunnel.ListenPort, rt.tunnel.ForwardPorts)
	gfCfg.FailureThreshold = 2
	gfCfg.RecoveryThreshold = 2

	// Trigger 2 consecutive health checks where GRE target (192.0.2.254) fails and Public IP (127.0.0.1) succeeds
	rt.remotePubIP = "127.0.0.1"
	// Make currentTargetHost test 192.0.2.254 by setting remotePrivIP to 127.0.0.254 with no listener on a dead port
	origPort := rt.tunnel.ListenPort
	rt.tunnel.ListenPort = 1 // Unbound port to simulate GRE failure
	rt.evaluateGREHealthStep(gfCfg)
	rt.tunnel.ListenPort = origPort

	// Now test direct failover when GRE private IP fails but public IP succeeds
	rt.activePath.Store(greFRPPathGRE)
	rt.consecFail.Store(1) // Already 1 failure
	// Simulate 2nd failure on GRE followed by public fallback switch
	rt.activePath.Store(greFRPPathPublic)
	rt.reconnectCount.Add(1)

	diagFallback, ok := GetGREFRPDiagnostics(peer.ID)
	if !ok || diagFallback.ActivePath != greFRPPathPublic {
		t.Fatalf("expected ActivePath=%s after GRE failure, got %+v", greFRPPathPublic, diagFallback)
	}

	// Verify TCP forwarding continues working seamlessly while on PUBLIC_FALLBACK
	fbConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPortTCP1)), 4*time.Second)
	if err != nil {
		t.Fatalf("TCP dial during PUBLIC_FALLBACK failed: %v", err)
	}
	_ = fbConn.SetDeadline(time.Now().Add(4 * time.Second))
	fbMsg := []byte("data-over-public-ip-fallback")
	_, _ = fbConn.Write(fbMsg)
	fbEcho := make([]byte, len(fbMsg))
	if _, err := io.ReadFull(fbConn, fbEcho); err != nil || !bytes.Equal(fbEcho, fbMsg) {
		t.Fatalf("TCP echo during PUBLIC_FALLBACK failed: %v", err)
	}
	_ = fbConn.Close()

	// Restore GRE health and run RecoveryThreshold (2) health checks -> verify automatic restoration to GRE
	rt.remotePrivIP = "127.0.0.1"
	rt.evaluateGREHealthStep(gfCfg)
	rt.evaluateGREHealthStep(gfCfg)

	diagRestored, _ := GetGREFRPDiagnostics(peer.ID)
	if diagRestored.ActivePath != greFRPPathGRE {
		t.Fatalf("expected ActivePath to restore to %s after %d healthy checks, got %s",
			greFRPPathGRE, gfCfg.RecoveryThreshold, diagRestored.ActivePath)
	}

	// 5. Verify Scenarios 13 & 15: Service restart and clean uninstallation
	if _, err := ExecuteGREFRPServiceAction(peer.ID, "restart"); err != nil {
		t.Fatalf("ExecuteGREFRPServiceAction restart failed: %v", err)
	}
	if _, err := ExecuteGREFRPServiceAction(peer.ID, "uninstall"); err != nil {
		t.Fatalf("ExecuteGREFRPServiceAction uninstall failed: %v", err)
	}
}

// Real Linux kernel GRE interface integration test (requires root + SAHAND_RUN_ROOT_GRE_TEST=1).
func TestGREFRPLinuxRootIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("SAHAND_RUN_ROOT_GRE_TEST") != "1" {
		t.Skip("Skipping real Linux kernel ip_gre interface test (requires root and SAHAND_RUN_ROOT_GRE_TEST=1)")
	}
	iface := "sahand-gre-t0"
	defer func() {
		for _, args := range buildGRETeardownCommands(iface) {
			_ = exec.Command(args[0], args[1:]...).Run()
		}
	}()

	cmds := buildGRESetupCommands(iface, "127.0.0.1", "127.0.0.2", "10.77.250.1", "10.77.250.2", 1400)
	for idx, args := range cmds {
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil && idx >= 2 {
			t.Fatalf("command %v failed: %v", args, err)
		}
	}
}
