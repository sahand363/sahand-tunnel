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
	"testing"
	"time"
)

func setupSpoofWGTestEnv(t *testing.T) (ServerPeer, TunnelConfig) {
	t.Helper()
	peer, _ := setupWSSTestEnv(t)
	var swgTC TunnelConfig
	for _, tc := range peer.Tunnels {
		if tc.ID == 26 {
			swgTC = tc
			break
		}
	}
	if swgTC.ID != 26 || swgTC.Name != "Spoof + WireGuard" {
		t.Fatalf("Method 26 (Spoof + WireGuard) not found in defaultTunnelsForServer")
	}
	return peer, swgTC
}

func TestSpoofWGKeygenBundleAndConfigGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	origSpoofDir := spoofDir
	origWGDir := wgConfDir
	spoofDir = filepath.Join(tmpDir, "spoof")
	wgConfDir = filepath.Join(tmpDir, "wireguard")
	defer func() {
		spoofDir = origSpoofDir
		wgConfDir = origWGDir
	}()

	// 1. Curve25519 WireGuard keypair generation & public key derivation
	priv, pub, err := spoofGenKeypair()
	if err != nil {
		t.Fatalf("spoofGenKeypair failed: %v", err)
	}
	derivedPub, err := spoofPubFromPriv(priv)
	if err != nil || derivedPub != pub {
		t.Fatalf("spoofPubFromPriv mismatch: got %q, want %q (err=%v)", derivedPub, pub, err)
	}

	// 2. Bundle generation on Iran ("local") role and import on Foreign ("remote") role
	localCfg := defaultSpoofWGConfig()
	localCfg.Role = "local"
	localCfg.LocalPublicIP = "203.0.113.10"
	localCfg.PeerPublicIP = "198.51.100.20"
	localCfg.SpoofIPs = []string{"8.8.8.8", "1.1.1.1"}
	localCfg.SendTransport = "tcp"
	localCfg.RecvTransport = "udp"

	bundleStr, err := makeSpoofWGBundle(localCfg, "")
	if err != nil {
		t.Fatalf("makeSpoofWGBundle failed: %v", err)
	}
	if !strings.HasPrefix(bundleStr, "spf1_") {
		t.Fatalf("expected spf1_ bundle prefix, got %q", bundleStr)
	}

	remoteCfg, err := importSpoofWGBundle(bundleStr, nil)
	if err != nil {
		t.Fatalf("importSpoofWGBundle failed: %v", err)
	}
	if remoteCfg.Role != "remote" {
		t.Fatalf("expected imported role to be remote, got %q", remoteCfg.Role)
	}
	if remoteCfg.PeerPublicIP != "203.0.113.10" {
		t.Fatalf("expected imported PeerPublicIP 203.0.113.10, got %q", remoteCfg.PeerPublicIP)
	}
	// Transports must mirror between local and remote
	if remoteCfg.SendTransport != "udp" || remoteCfg.RecvTransport != "tcp" {
		t.Fatalf("expected mirrored transports udp/tcp on remote, got %s/%s",
			remoteCfg.SendTransport, remoteCfg.RecvTransport)
	}
	// WireGuard overlay IPs and keys must match across endpoints
	if remoteCfg.WGLocalIP != "10.20.0.2" || remoteCfg.WGPeerIP != "10.20.0.1" {
		t.Fatalf("unexpected remote WG IPs: local=%s peer=%s", remoteCfg.WGLocalIP, remoteCfg.WGPeerIP)
	}
	if remoteCfg.WGPubKey != localCfg.WGPeerPub || remoteCfg.WGPeerPub != localCfg.WGPubKey {
		t.Fatalf("WireGuard public keys did not cross-match between local and imported remote configs")
	}

	// 3. Verify /etc/spoof/config.json, /etc/spoof/spoof-ips.txt, and /etc/wireguard/wg-spoof.conf generation
	if err := writeSpoofAndWGConfigs(localCfg); err != nil {
		t.Fatalf("writeSpoofAndWGConfigs failed: %v", err)
	}
	ipFileBytes, err := os.ReadFile(spoofIPFilePath())
	if err != nil || !strings.Contains(string(ipFileBytes), "8.8.8.8\n1.1.1.1") {
		t.Fatalf("spoof-ips.txt missing expected round-robin IPs: err=%v", err)
	}
	wgConfBytes, err := os.ReadFile(spoofWGConfPath())
	if err != nil || !strings.Contains(string(wgConfBytes), "Endpoint = 127.0.0.1:5000") ||
		!strings.Contains(string(wgConfBytes), "PersistentKeepalive = 25") {
		t.Fatalf("wg-spoof.conf missing expected WireGuard directives:\n%s", string(wgConfBytes))
	}
}

func TestSpoofWGProbeParitySyncAndBidirectionalForwarding(t *testing.T) {
	peer, tc := setupSpoofWGTestEnv(t)

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

	tc.ListenPort = allocateFreeTCPPort(t)
	tc.Enabled = true
	tc.ForwardPorts = strconv.Itoa(tcpTargetPort) + "," + strconv.Itoa(udpTargetPort)

	stateMu.Lock()
	appCfg.Servers[0].Tunnels[25] = tc
	peer = appCfg.Servers[0]
	stateMu.Unlock()

	ln, err := startSpoofWGServerListener(peer, tc)
	if err != nil {
		t.Fatalf("startSpoofWGServerListener failed: %v", err)
	}
	defer func() {
		_ = ln.Close()
		stopSpoofWGPeerResources(peer.ID)
	}()

	// 1. Engine 1 Probe & Parity Sync
	probeRes := probeSpoofWG(peer, tc, "master-node-01")
	if !probeRes.Success {
		t.Fatalf("expected probeSpoofWG to succeed, got: %s", probeRes.ErrorReason)
	}
	if !pushSpoofWGParitySync(peer, tc, probeRes.LatencyMS) {
		t.Fatalf("expected pushSpoofWGParitySync to succeed")
	}

	// 2. Engine 2 TCP Forwarding
	entryLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("entryLn failed: %v", err)
	}
	defer entryLn.Close()
	go acceptTrafficEntryLoop(entryLn, peer, tc, strconv.Itoa(tcpTargetPort))

	cli, err := net.DialTimeout("tcp", entryLn.Addr().String(), 4*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout entryLn failed: %v", err)
	}
	defer cli.Close()
	_ = cli.SetDeadline(time.Now().Add(6 * time.Second))

	payload := make([]byte, 32*1024)
	_, _ = io.ReadFull(rand.Reader, payload)
	go func() {
		_, _ = cli.Write(payload)
	}()
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(cli, echoed); err != nil || !bytes.Equal(payload, echoed) {
		t.Fatalf("Spoof+WG TCP forwarding echo mismatch: err=%v", err)
	}

	// 3. Engine 2 UDP Forwarding
	udpEntryPort := allocateFreeUDPPort(t)
	tcUDP := tc
	tcUDP.ForwardPorts = strconv.Itoa(udpEntryPort)
	// Map udpEntryPort to udpTargetPort by testing direct dialSpoofWGCarrier UDP command
	uCarrier, err := dialSpoofWGCarrier(peer, tc, spoofWGCmdUDP, udpTargetPort, 4*time.Second)
	if err != nil {
		t.Fatalf("dialSpoofWGCarrier UDP failed: %v", err)
	}
	defer uCarrier.Close()

	dgram := []byte("spoof-wg-udp-datagram-verification")
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(dgram)))
	_, _ = uCarrier.Write(lenBuf[:])
	_, _ = uCarrier.Write(dgram)
	if _, err := io.ReadFull(uCarrier, lenBuf[:]); err != nil {
		t.Fatalf("UDP reply length read failed: %v", err)
	}
	rep := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(uCarrier, rep); err != nil || !bytes.Equal(rep, dgram) {
		t.Fatalf("Spoof+WG UDP echo mismatch: err=%v", err)
	}
}
