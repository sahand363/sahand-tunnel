package main

import (
	"archive/tar"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	greFRPEngineID      = "gre-frp"
	officialFRPVersion  = "0.61.1"
	greFRPDefaultMTU    = 1400
	greFRPProtocolMagic = "GFRP1"
	greFRPPathGRE       = "GRE"
	greFRPPathPublic    = "PUBLIC_FALLBACK"

	// Wire commands for the built-in FRP-compatible carrier & reverse-tunnel multiplexer
	greFRPCmdProbe      byte = 0x01
	greFRPCmdProbeAck   byte = 0x02
	greFRPCmdParitySync byte = 0x03
	greFRPCmdParityAck  byte = 0x04
	greFRPCmdTCPForward byte = 0x05
	greFRPCmdUDPForward byte = 0x06
	greFRPCmdWorkerReg  byte = 0x07
	greFRPCmdWorkerPing byte = 0x08
	greFRPCmdWorkerPong byte = 0x09
)

var validGREIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{2,15}$`)

var supportedFRPTransports = map[string]bool{
	"tcp":       true,
	"kcp":       true,
	"quic":      true,
	"websocket": true,
	"wss":       true,
}

// ============================================================================
// 1. CONFIGURATION VALIDATION, /30 SUBNET ALLOCATION & PORT RANGE PARSING
// ============================================================================

type ExpandedPortMapping struct {
	RuleName      string
	Protocol      string // "tcp" or "udp"
	LocalAddr     string
	LocalPort     int
	RemotePort    int
	UseEncryption bool
	UseCompress   bool
	ProxyProtoV2  bool
}

// Calculates the two usable host IPv4 addresses (.1 for Master, .2 for Agent) from a /30 CIDR subnet.
func computeSlash30HostIPs(cidr string) (masterIP string, agentIP string, normalizedCIDR string, err error) {
	ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", "", "", fmt.Errorf("invalid /30 subnet CIDR %q: %w", cidr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", "", errors.New("GRE private subnet must be an IPv4 /30 CIDR")
	}
	ones, bits := ipNet.Mask.Size()
	if ones != 30 || bits != 32 {
		return "", "", "", fmt.Errorf("GRE private subnet %q must have a /30 prefix length", cidr)
	}

	netBase := ipNet.IP.To4()
	if netBase == nil {
		return "", "", "", errors.New("invalid IPv4 network base")
	}
	baseUint := binary.BigEndian.Uint32(netBase)
	mIP := make(net.IP, 4)
	aIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(mIP, baseUint+1)
	binary.BigEndian.PutUint32(aIP, baseUint+2)

	return mIP.String(), aIP.String(), fmt.Sprintf("%s/30", netBase.String()), nil
}

// Deterministically derives a unique 10.77.<octet>.0/30 subnet per server peer so multiple
// independent server pairs never collide on the same GRE private IP addresses.
func deriveDefaultSlash30ForPeer(peerID string) (cidr, masterIP, agentIP string) {
	octet := 25
	if strings.TrimSpace(peerID) != "" {
		sum := sha256.Sum256([]byte(peerID))
		octet = 10 + int(sum[0])%230
	}
	cidr = fmt.Sprintf("10.77.%d.0/30", octet)
	m, a, norm, err := computeSlash30HostIPs(cidr)
	if err != nil {
		return "10.77.25.0/30", "10.77.25.1", "10.77.25.2"
	}
	return norm, m, a
}

func parsePortSpecRange(spec string) (startPort int, endPort int, err error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return 0, 0, errors.New("empty port specification")
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		p1, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		p2, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil || p1 < 1 || p2 > 65535 || p1 > p2 {
			return 0, 0, fmt.Errorf("invalid port range %q", spec)
		}
		if p2-p1 > 200 {
			return 0, 0, fmt.Errorf("port range %q exceeds maximum span of 200 ports", spec)
		}
		return p1, p2, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, 0, fmt.Errorf("invalid port %q", spec)
	}
	return p, p, nil
}

// Expands all forwarding rules (including port ranges and tcp+udp dual rules) and checks for
// duplicate remote port bindings or collisions with the FRP server port.
func validateAndExpandGREFRPRules(cfg *GREFRPConfig, frpServerPort int) ([]ExpandedPortMapping, error) {
	if cfg == nil {
		return nil, errors.New("missing GRE+FRP configuration")
	}
	var out []ExpandedPortMapping
	seenTCP := make(map[int]string)
	seenUDP := make(map[int]string)

	for idx, rule := range cfg.ForwardingRules {
		rName := strings.TrimSpace(rule.Name)
		if rName == "" {
			rName = fmt.Sprintf("rule-%02d", idx+1)
		}
		proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
		if proto == "" {
			proto = "tcp+udp"
		}
		if proto != "tcp" && proto != "udp" && proto != "tcp+udp" {
			return nil, fmt.Errorf("rule %q has unsupported protocol %q", rName, rule.Protocol)
		}

		localAddr := strings.TrimSpace(rule.LocalAddr)
		if localAddr == "" {
			localAddr = "127.0.0.1"
		}
		if net.ParseIP(localAddr) == nil && localAddr != "localhost" {
			return nil, fmt.Errorf("rule %q has invalid local address %q", rName, localAddr)
		}

		lStart, lEnd, err := parsePortSpecRange(rule.LocalPort)
		if err != nil {
			return nil, fmt.Errorf("rule %q local_port error: %w", rName, err)
		}
		rStart, rEnd, err := parsePortSpecRange(rule.RemotePort)
		if err != nil {
			return nil, fmt.Errorf("rule %q remote_port error: %w", rName, err)
		}
		if (lEnd - lStart) != (rEnd - rStart) {
			return nil, fmt.Errorf("rule %q local port range (%s) and remote port range (%s) must have equal length",
				rName, rule.LocalPort, rule.RemotePort)
		}

		protos := []string{proto}
		if proto == "tcp+udp" {
			protos = []string{"tcp", "udp"}
		}

		count := rEnd - rStart + 1
		for offset := 0; offset < count; offset++ {
			lp := lStart + offset
			rp := rStart + offset
			if rp == frpServerPort {
				return nil, fmt.Errorf("rule %q remote port %d conflicts with FRP server port %d", rName, rp, frpServerPort)
			}
			for _, p := range protos {
				if p == "tcp" {
					if prev, exists := seenTCP[rp]; exists {
						return nil, fmt.Errorf("duplicate TCP remote port %d between %q and %q", rp, prev, rName)
					}
					seenTCP[rp] = rName
				} else {
					if prev, exists := seenUDP[rp]; exists {
						return nil, fmt.Errorf("duplicate UDP remote port %d between %q and %q", rp, prev, rName)
					}
					seenUDP[rp] = rName
				}
				out = append(out, ExpandedPortMapping{
					RuleName:      fmt.Sprintf("%s-%s-%d", rName, p, rp),
					Protocol:      p,
					LocalAddr:     localAddr,
					LocalPort:     lp,
					RemotePort:    rp,
					UseEncryption: rule.UseEncryption,
					UseCompress:   rule.UseCompress,
					ProxyProtoV2:  rule.ProxyProtoV2,
				})
			}
		}
	}
	return out, nil
}

func validateGREFRPConfiguration(cfg *GREFRPConfig, listenPort int) error {
	if cfg == nil {
		return errors.New("GRE+FRP configuration is nil")
	}
	if !validGREIfaceRegex.MatchString(strings.TrimSpace(cfg.GREInterfaceName)) {
		return fmt.Errorf("invalid GRE interface name %q (must be 2-15 alphanumeric/dash characters)", cfg.GREInterfaceName)
	}
	if cfg.MTU < 576 || cfg.MTU > 9000 {
		return fmt.Errorf("invalid GRE MTU %d (must be between 576 and 9000)", cfg.MTU)
	}
	mIP, aIP, _, err := computeSlash30HostIPs(cfg.PrivateSubnetCIDR)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.LocalPrivateIP) != "" && strings.TrimSpace(cfg.RemotePrivateIP) != "" {
		if cfg.LocalPrivateIP == cfg.RemotePrivateIP {
			return errors.New("local and remote GRE private IPs cannot be identical")
		}
		if (cfg.LocalPrivateIP != mIP && cfg.LocalPrivateIP != aIP) ||
			(cfg.RemotePrivateIP != mIP && cfg.RemotePrivateIP != aIP) {
			return fmt.Errorf("GRE private IPs (%s, %s) do not belong to subnet %s (%s, %s)",
				cfg.LocalPrivateIP, cfg.RemotePrivateIP, cfg.PrivateSubnetCIDR, mIP, aIP)
		}
	}
	if cfg.LocalPublicIP != "" && net.ParseIP(strings.TrimSpace(cfg.LocalPublicIP)) == nil {
		return fmt.Errorf("invalid local public IP %q", cfg.LocalPublicIP)
	}
	if cfg.RemotePublicIP != "" && net.ParseIP(strings.TrimSpace(cfg.RemotePublicIP)) == nil {
		return fmt.Errorf("invalid remote public IP %q", cfg.RemotePublicIP)
	}
	if cfg.HealthCheckSec < 1 || cfg.HealthCheckSec > 300 {
		return fmt.Errorf("invalid health_check_sec %d (expected 1-300)", cfg.HealthCheckSec)
	}
	if cfg.FailureThreshold < 1 || cfg.FailureThreshold > 20 {
		return fmt.Errorf("invalid failure_threshold %d (expected 1-20)", cfg.FailureThreshold)
	}
	if cfg.RecoveryThreshold < 1 || cfg.RecoveryThreshold > 20 {
		return fmt.Errorf("invalid recovery_threshold %d (expected 1-20)", cfg.RecoveryThreshold)
	}
	tr := strings.ToLower(strings.TrimSpace(cfg.FRPTransport))
	if !supportedFRPTransports[tr] {
		return fmt.Errorf("unsupported FRP transport %q (supported in v%s: tcp, kcp, quic, websocket, wss)",
			cfg.FRPTransport, officialFRPVersion)
	}
	srvPort := cfg.FRPServerPort
	if srvPort <= 0 {
		srvPort = listenPort
	}
	if srvPort < 1024 || srvPort > 65535 {
		return fmt.Errorf("invalid FRP server port %d", srvPort)
	}
	_, err = validateAndExpandGREFRPRules(cfg, srvPort)
	return err
}

func normalizeGREFRPConfig(existing *GREFRPConfig, listenPort int, forwardPorts string) *GREFRPConfig {
	def := defaultGREFRPConfig(listenPort, forwardPorts)
	if existing == nil {
		return def
	}
	cp := *existing
	cp.InternalEngine = greFRPEngineID
	cp.FRPVersion = officialFRPVersion

	if !validGREIfaceRegex.MatchString(strings.TrimSpace(cp.GREInterfaceName)) {
		cp.GREInterfaceName = def.GREInterfaceName
	}
	mIP, aIP, normCIDR, err := computeSlash30HostIPs(cp.PrivateSubnetCIDR)
	if err != nil {
		cp.PrivateSubnetCIDR = def.PrivateSubnetCIDR
		cp.LocalPrivateIP = def.LocalPrivateIP
		cp.RemotePrivateIP = def.RemotePrivateIP
	} else {
		cp.PrivateSubnetCIDR = normCIDR
		if cp.LocalPrivateIP != mIP && cp.LocalPrivateIP != aIP {
			cp.LocalPrivateIP = mIP
		}
		if cp.RemotePrivateIP != mIP && cp.RemotePrivateIP != aIP || cp.RemotePrivateIP == cp.LocalPrivateIP {
			if cp.LocalPrivateIP == mIP {
				cp.RemotePrivateIP = aIP
			} else {
				cp.RemotePrivateIP = mIP
			}
		}
	}

	if cp.MTU < 576 || cp.MTU > 9000 {
		cp.MTU = greFRPDefaultMTU
	}
	if strings.TrimSpace(cp.RouteConfig) == "" {
		cp.RouteConfig = fmt.Sprintf("%s via %s", cp.PrivateSubnetCIDR, cp.GREInterfaceName)
	}
	if cp.HealthCheckSec < 1 || cp.HealthCheckSec > 300 {
		cp.HealthCheckSec = 5
	}
	if cp.FailureThreshold < 1 || cp.FailureThreshold > 20 {
		cp.FailureThreshold = 3
	}
	if cp.RecoveryThreshold < 1 || cp.RecoveryThreshold > 20 {
		cp.RecoveryThreshold = 2
	}
	tr := strings.ToLower(strings.TrimSpace(cp.FRPTransport))
	if !supportedFRPTransports[tr] {
		cp.FRPTransport = "tcp"
	} else {
		cp.FRPTransport = tr
	}
	if cp.FRPServerPort < 1024 || cp.FRPServerPort > 65535 {
		cp.FRPServerPort = listenPort
	}
	if len(cp.ForwardingRules) == 0 {
		cp.ForwardingRules = buildGREFRPRulesFromCSV(forwardPorts, cp.FRPEncryption, cp.FRPCompression, cp.FRPProxyProtoV2)
	}
	if cp.Diagnostics.EngineName == "" {
		cp.Diagnostics = def.Diagnostics
	}
	return &cp
}

// Syncs ForwardPorts CSV string from the structured ForwardingRules slice.
func syncForwardPortsCSVFromRules(cfg *GREFRPConfig) string {
	if cfg == nil || len(cfg.ForwardingRules) == 0 {
		return "32025"
	}
	seen := make(map[string]bool)
	var list []string
	for _, r := range cfg.ForwardingRules {
		rp := strings.TrimSpace(r.RemotePort)
		if rp != "" && !seen[rp] {
			seen[rp] = true
			list = append(list, rp)
		}
	}
	if len(list) == 0 {
		return "32025"
	}
	return strings.Join(list, ", ")
}

// ============================================================================
// 2. GRE LINUX TUNNEL & SYSTEMD PERSISTENCE GENERATOR
// ============================================================================

func resolveRoleOrderedGREIPs(cfg *GREFRPConfig, role string, peerID string) (localPriv, remotePriv, cidr string) {
	mIP, aIP, normCIDR, err := computeSlash30HostIPs(cfg.PrivateSubnetCIDR)
	if err != nil {
		normCIDR, mIP, aIP = deriveDefaultSlash30ForPeer(peerID)
	}
	if role == "agent" {
		return aIP, mIP, normCIDR
	}
	return mIP, aIP, normCIDR
}

func buildGRESetupCommands(iface, localPubIP, remotePubIP, localPrivIP, remotePrivIP string, mtu int) [][]string {
	if mtu <= 0 {
		mtu = greFRPDefaultMTU
	}
	return [][]string{
		{"modprobe", "ip_gre"},
		{"ip", "tunnel", "del", iface}, // Ignore error if not existing
		{"ip", "tunnel", "add", iface, "mode", "gre", "local", localPubIP, "remote", remotePubIP, "ttl", "255"},
		{"ip", "addr", "add", localPrivIP + "/30", "peer", remotePrivIP + "/30", "dev", iface},
		{"ip", "link", "set", "dev", iface, "mtu", strconv.Itoa(mtu), "up"},
		{"ip", "route", "replace", remotePrivIP + "/32", "dev", iface},
	}
}

func buildGRETeardownCommands(iface string) [][]string {
	return [][]string{
		{"ip", "link", "set", "dev", iface, "down"},
		{"ip", "tunnel", "del", iface},
	}
}

func generateGRESystemdUnit(peerID, iface, localPubIP, remotePubIP, localPrivIP, remotePrivIP string, mtu int) string {
	return fmt.Sprintf(`[Unit]
Description=Sahand Tunnel GRE Point-to-Point Interface (%s - %s)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/sbin/modprobe ip_gre
ExecStartPre=-/sbin/ip tunnel del %s
ExecStart=/sbin/ip tunnel add %s mode gre local %s remote %s ttl 255
ExecStart=/sbin/ip addr add %s/30 peer %s/30 dev %s
ExecStart=/sbin/ip link set dev %s mtu %d up
ExecStart=/sbin/ip route replace %s/32 dev %s
ExecStop=-/sbin/ip link set dev %s down
ExecStop=-/sbin/ip tunnel del %s

[Install]
WantedBy=multi-user.target
`, peerID, iface, iface, iface, localPubIP, remotePubIP, localPrivIP, remotePrivIP, iface, iface, mtu, remotePrivIP, iface, iface, iface)
}

// Applies GRE interface and firewall rules on Linux when root privileges are available.
func applyLinuxGREInterface(peer ServerPeer, tc TunnelConfig, role string) (bool, string) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return false, "UNPRIVILEGED (USER-SPACE MODE)"
	}
	gf := normalizeGREFRPConfig(tc.GREFRP, tc.ListenPort, tc.ForwardPorts)
	remotePub := strings.TrimSpace(gf.RemotePublicIP)
	if remotePub == "" {
		remotePub = strings.TrimSpace(peer.IP)
	}
	if remotePub == "" || remotePub == "127.0.0.1" || remotePub == "::1" {
		return true, "LOOPBACK READY"
	}
	localPub := strings.TrimSpace(gf.LocalPublicIP)
	if localPub == "" {
		localPub = resolveOutboundInterfaceIP(remotePub).String()
	}
	localPriv, remotePriv, _ := resolveRoleOrderedGREIPs(gf, role, peer.ID)

	cmds := buildGRESetupCommands(gf.GREInterfaceName, localPub, remotePub, localPriv, remotePriv, gf.MTU)
	for idx, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Run(); err != nil && idx >= 2 {
			return false, fmt.Sprintf("ERROR (%s: %v)", args[0], err)
		}
	}

	// Allow IP Protocol 47 (GRE) from the paired remote public IP
	_ = exec.Command("iptables", "-C", "INPUT", "-p", "47", "-s", remotePub, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-I", "INPUT", "-p", "47", "-s", remotePub, "-j", "ACCEPT").Run()

	// Persist systemd service if /etc/systemd/system is writable
	unitName := fmt.Sprintf("sahand-gre-%s.service", peer.ID)
	unitPath := filepath.Join("/etc/systemd/system", unitName)
	unitContent := generateGRESystemdUnit(peer.ID, gf.GREInterfaceName, localPub, remotePub, localPriv, remotePriv, gf.MTU)
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err == nil {
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = exec.Command("systemctl", "enable", unitName).Run()
	}
	return true, fmt.Sprintf("UP (%s: %s ↔ %s)", gf.GREInterfaceName, localPriv, remotePriv)
}

func removeLinuxGREInterface(peerID string, iface string) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return
	}
	if validGREIfaceRegex.MatchString(iface) {
		for _, args := range buildGRETeardownCommands(iface) {
			_ = exec.Command(args[0], args[1:]...).Run()
		}
	}
	unitName := fmt.Sprintf("sahand-gre-%s.service", peerID)
	unitPath := filepath.Join("/etc/systemd/system", unitName)
	if _, err := os.Stat(unitPath); err == nil {
		_ = exec.Command("systemctl", "disable", "--now", unitName).Run()
		_ = os.Remove(unitPath)
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
}

// ============================================================================
// 3. OFFICIAL FRP v0.61.1 CONFIG GENERATOR & BINARY INSTALLER
// ============================================================================

func deriveFRPSharedToken(peer ServerPeer, tc TunnelConfig) string {
	if tc.GREFRP != nil && strings.TrimSpace(tc.GREFRP.FRPAuthToken) != "" {
		return strings.TrimSpace(tc.GREFRP.FRPAuthToken)
	}
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()
	if authKey, err := derivePeerAuthKey(cfgSnapshot, peer); err == nil {
		mac := hmac.New(sha256.New, authKey)
		_, _ = mac.Write([]byte("sahand-gre-frp-token-v1:" + peer.ID))
		return hex.EncodeToString(mac.Sum(nil)[:16])
	}
	return "sahand-frp-" + peer.ID
}

// Generates a valid FRP v0.61.1 `frps.toml` configuration for the Master (Iran) server.
func generateFRPSTOMLConfig(bindAddr string, tc TunnelConfig, authToken string) (string, error) {
	gf := normalizeGREFRPConfig(tc.GREFRP, tc.ListenPort, tc.ForwardPorts)
	if err := validateGREFRPConfiguration(gf, tc.ListenPort); err != nil {
		return "", err
	}
	if strings.TrimSpace(bindAddr) == "" {
		bindAddr = "0.0.0.0"
	}
	srvPort := gf.FRPServerPort
	if srvPort <= 0 {
		srvPort = tc.ListenPort
	}

	var b strings.Builder
	b.WriteString("# Generated by Sahand Tunnel — Method 25 (GRE + FRP v0.61.1)\n")
	b.WriteString(fmt.Sprintf("bindAddr = %q\n", bindAddr))
	b.WriteString(fmt.Sprintf("bindPort = %d\n", srvPort))

	switch gf.FRPTransport {
	case "kcp":
		b.WriteString(fmt.Sprintf("kcpBindPort = %d\n", srvPort))
	case "quic":
		b.WriteString(fmt.Sprintf("quicBindPort = %d\n", srvPort))
	}

	b.WriteString(fmt.Sprintf("transport.tcpMux = %t\n", gf.FRPTCPMux))
	b.WriteString("transport.tls.force = false\n\n")
	b.WriteString("[auth]\n")
	b.WriteString("method = \"token\"\n")
	b.WriteString(fmt.Sprintf("token = %q\n", authToken))
	return b.String(), nil
}

// Generates a valid FRP v0.61.1 `frpc.toml` configuration for the Agent (Foreign) server.
// `serverAddr` is set to the Master's GRE Private IP (`10.77.x.1`) when GRE is healthy, or
// automatically switched to the Master's Public IP during fallback.
func generateFRPCTOMLConfig(serverAddr string, tc TunnelConfig, authToken string) (string, error) {
	gf := normalizeGREFRPConfig(tc.GREFRP, tc.ListenPort, tc.ForwardPorts)
	if err := validateGREFRPConfiguration(gf, tc.ListenPort); err != nil {
		return "", err
	}
	if strings.TrimSpace(serverAddr) == "" {
		return "", errors.New("frpc serverAddr is required")
	}
	srvPort := gf.FRPServerPort
	if srvPort <= 0 {
		srvPort = tc.ListenPort
	}

	var b strings.Builder
	b.WriteString("# Generated by Sahand Tunnel — Method 25 (GRE + FRP v0.61.1)\n")
	b.WriteString(fmt.Sprintf("serverAddr = %q\n", strings.TrimSpace(serverAddr)))
	b.WriteString(fmt.Sprintf("serverPort = %d\n", srvPort))
	b.WriteString("loginFailExit = false\n\n")

	b.WriteString("[auth]\n")
	b.WriteString("method = \"token\"\n")
	b.WriteString(fmt.Sprintf("token = %q\n\n", authToken))

	b.WriteString("[transport]\n")
	b.WriteString(fmt.Sprintf("protocol = %q\n", gf.FRPTransport))
	b.WriteString(fmt.Sprintf("tcpMux = %t\n", gf.FRPTCPMux))
	b.WriteString("tls.enable = true\n\n")

	expanded, err := validateAndExpandGREFRPRules(gf, srvPort)
	if err != nil {
		return "", err
	}

	for _, rule := range expanded {
		b.WriteString("[[proxies]]\n")
		b.WriteString(fmt.Sprintf("name = %q\n", rule.RuleName))
		b.WriteString(fmt.Sprintf("type = %q\n", rule.Protocol))
		b.WriteString(fmt.Sprintf("localIP = %q\n", rule.LocalAddr))
		b.WriteString(fmt.Sprintf("localPort = %d\n", rule.LocalPort))
		b.WriteString(fmt.Sprintf("remotePort = %d\n", rule.RemotePort))
		b.WriteString(fmt.Sprintf("transport.useEncryption = %t\n", rule.UseEncryption))
		b.WriteString(fmt.Sprintf("transport.useCompression = %t\n", rule.UseCompress))
		if rule.ProxyProtoV2 && rule.Protocol == "tcp" {
			b.WriteString("transport.proxyProtocolVersion = \"v2\"\n")
		}
		b.WriteString("\n")
	}

	return b.String(), nil
}

func frpInstallDir() string {
	base := filepath.Dir(configPath())
	return filepath.Join(base, "frp")
}

// Writes frps.toml and frpc.toml with 0600 permissions, backing up any previous files for safe rollback.
func writeFRPConfigFiles(peer ServerPeer, tc TunnelConfig, activeTargetIP string) (frpsPath string, frpcPath string, err error) {
	dir := frpInstallDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", err
	}
	token := deriveFRPSharedToken(peer, tc)
	frpsTOML, err := generateFRPSTOMLConfig("0.0.0.0", tc, token)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(activeTargetIP) == "" {
		activeTargetIP = peer.IP
	}
	frpcTOML, err := generateFRPCTOMLConfig(activeTargetIP, tc, token)
	if err != nil {
		return "", "", err
	}

	frpsPath = filepath.Join(dir, fmt.Sprintf("frps-%s.toml", peer.ID))
	frpcPath = filepath.Join(dir, fmt.Sprintf("frpc-%s.toml", peer.ID))

	writeWithBackup := func(path string, content []byte) error {
		if old, err := os.ReadFile(path); err == nil {
			_ = os.WriteFile(path+".bak", old, 0600)
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, content, 0600); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}

	if err := writeWithBackup(frpsPath, []byte(frpsTOML)); err != nil {
		return "", "", err
	}
	if err := writeWithBackup(frpcPath, []byte(frpcTOML)); err != nil {
		if bak, bErr := os.ReadFile(frpsPath + ".bak"); bErr == nil {
			_ = os.WriteFile(frpsPath, bak, 0600)
		}
		return "", "", err
	}
	return frpsPath, frpcPath, nil
}

// Downloads official FRP v0.61.1 release archive from GitHub, verifies its SHA-256 checksum against
// the official `frp_sha256_checksums.txt` manifest, and extracts `frps` and `frpc`.
func installOfficialFRPBinaries() (string, string, error) {
	binDir := filepath.Join(frpInstallDir(), "bin")
	frpsBin := filepath.Join(binDir, "frps")
	frpcBin := filepath.Join(binDir, "frpc")

	if st1, err1 := os.Stat(frpsBin); err1 == nil && st1.Size() > 1024*1024 {
		if st2, err2 := os.Stat(frpcBin); err2 == nil && st2.Size() > 1024*1024 {
			return frpsBin, frpcBin, nil
		}
	}

	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return "", "", fmt.Errorf("unsupported architecture %s for FRP binary release", arch)
	}
	tarName := fmt.Sprintf("frp_%s_linux_%s.tar.gz", officialFRPVersion, arch)
	baseURL := fmt.Sprintf("https://github.com/fatedier/frp/releases/download/v%s", officialFRPVersion)
	tarURL := baseURL + "/" + tarName
	sumURL := baseURL + "/frp_sha256_checksums.txt"

	client := &http.Client{Timeout: 45 * time.Second}

	sumResp, err := client.Get(sumURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to download FRP checksum manifest: %w", err)
	}
	defer sumResp.Body.Close()
	sumBytes, err := io.ReadAll(io.LimitReader(sumResp.Body, 64*1024))
	if err != nil {
		return "", "", err
	}

	var expectedHash string
	for _, line := range strings.Split(string(sumBytes), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.TrimSpace(fields[1]) == tarName {
			expectedHash = strings.ToLower(strings.TrimSpace(fields[0]))
			break
		}
	}
	if len(expectedHash) != 64 {
		return "", "", fmt.Errorf("checksum entry for %s not found in official manifest", tarName)
	}

	tarResp, err := client.Get(tarURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to download FRP archive: %w", err)
	}
	defer tarResp.Body.Close()
	archiveBytes, err := io.ReadAll(io.LimitReader(tarResp.Body, 40*1024*1024))
	if err != nil {
		return "", "", err
	}

	actualSum := sha256.Sum256(archiveBytes)
	actualHash := hex.EncodeToString(actualSum[:])
	if subtle.ConstantTimeCompare([]byte(actualHash), []byte(expectedHash)) != 1 {
		return "", "", fmt.Errorf("FRP archive SHA-256 mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	if err := os.MkdirAll(binDir, 0700); err != nil {
		return "", "", err
	}

	gz, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return "", "", err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	foundFRPS, foundFRPC := false, false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", "", err
		}
		base := filepath.Base(hdr.Name)
		if base == "frps" || base == "frpc" {
			dstPath := filepath.Join(binDir, base)
			tmpPath := dstPath + ".tmp"
			f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return "", "", err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, 35*1024*1024)); err != nil {
				_ = f.Close()
				_ = os.Remove(tmpPath)
				return "", "", err
			}
			_ = f.Close()
			if err := os.Rename(tmpPath, dstPath); err != nil {
				return "", "", err
			}
			if base == "frps" {
				foundFRPS = true
			} else {
				foundFRPC = true
			}
		}
	}

	if !foundFRPS || !foundFRPC {
		return "", "", errors.New("downloaded FRP archive did not contain both frps and frpc")
	}
	return frpsBin, frpcBin, nil
}

// ============================================================================
// 4. BUILT-IN FRP-COMPATIBLE ENGINE + GRE/PUBLIC FAILOVER CONTROLLER (:28025)
// ============================================================================

type greFRPRuntime struct {
	cfgMu             sync.RWMutex
	peerID            string
	peer              ServerPeer
	tunnel            TunnelConfig
	role              string
	localPrivIP       string
	remotePrivIP      string
	remotePubIP       string
	activePath        atomic.Value // "GRE" or "PUBLIC_FALLBACK"
	greStatus         atomic.Value // string
	grePingOK         atomic.Bool
	greLossPct        atomic.Int32
	greRTTMS          atomic.Int64
	reconnectCount    atomic.Int32
	consecFail        atomic.Int32
	consecSuccess     atomic.Int32
	lastFailureReason atomic.Value
	lastRecoveryAt    atomic.Value
	startedAt         time.Time

	logsMu     sync.Mutex
	recentLogs []string

	carrierLn      net.Listener
	entryListeners []net.Listener
	entryUDPConns  []net.PacketConn
	stopCh         chan struct{}
	closed         atomic.Bool
}

var (
	greFRPRuntimeMu sync.RWMutex
	greFRPRuntimes  = make(map[string]*greFRPRuntime)
)

func (rt *greFRPRuntime) appendLog(msg string) {
	ts := formatMasterClockSec(masterNow())
	entry := fmt.Sprintf("[%s] %s", ts, msg)
	rt.logsMu.Lock()
	rt.recentLogs = append([]string{entry}, rt.recentLogs...)
	if len(rt.recentLogs) > 25 {
		rt.recentLogs = rt.recentLogs[:25]
	}
	rt.logsMu.Unlock()
}

func (rt *greFRPRuntime) snapshotDiagnostics() GREFRPDiagnostics {
	rt.cfgMu.RLock()
	role := rt.role
	listenPort := rt.tunnel.ListenPort
	enabled := rt.tunnel.Enabled
	rt.cfgMu.RUnlock()

	actPath, _ := rt.activePath.Load().(string)
	if actPath == "" {
		actPath = greFRPPathGRE
	}
	gStat, _ := rt.greStatus.Load().(string)
	if gStat == "" {
		gStat = "ACTIVE"
	}
	lastFail, _ := rt.lastFailureReason.Load().(string)
	lastRec, _ := rt.lastRecoveryAt.Load().(string)

	rt.logsMu.Lock()
	logsCopy := make([]string, len(rt.recentLogs))
	copy(logsCopy, rt.recentLogs)
	rt.logsMu.Unlock()

	uptime := time.Since(rt.startedAt).Round(time.Second).String()
	frpsStat := "STANDBY (AGENT ROLE)"
	frpcStat := "ACTIVE (" + actPath + ")"
	if role == "master" {
		frpsStat = "ACTIVE (LISTENING :" + strconv.Itoa(listenPort) + ")"
		frpcStat = "CONNECTED PEER"
	}

	pfStatus := "DISABLED (CARRIER ONLY)"
	if enabled {
		pfStatus = "FORWARDING ACTIVE (" + actPath + ")"
	}

	return GREFRPDiagnostics{
		EngineName:         greFRPEngineID,
		GREInterfaceStatus: gStat,
		GREPrivatePingOK:   rt.grePingOK.Load(),
		GREPacketLossPct:   int(rt.greLossPct.Load()),
		GRERoundTripMS:     rt.greRTTMS.Load(),
		FRPSServiceStatus:  frpsStat,
		FRPCServiceStatus:  frpcStat,
		ActivePath:         actPath,
		PortForwardStatus:  pfStatus,
		ServiceUptime:      uptime,
		ReconnectCount:     int(rt.reconnectCount.Load()),
		LastFailureReason:  lastFail,
		LastRecoveryAt:     lastRec,
		RecentLogs:         logsCopy,
	}
}

func GetGREFRPDiagnostics(peerID string) (GREFRPDiagnostics, bool) {
	greFRPRuntimeMu.RLock()
	rt := greFRPRuntimes[peerID]
	greFRPRuntimeMu.RUnlock()
	if rt == nil {
		return GREFRPDiagnostics{}, false
	}
	return rt.snapshotDiagnostics(), true
}

func stopGREFRPPeerResources(peerID string) {
	greFRPRuntimeMu.Lock()
	rt, ok := greFRPRuntimes[peerID]
	if ok {
		delete(greFRPRuntimes, peerID)
	}
	greFRPRuntimeMu.Unlock()

	if rt != nil {
		rt.closeAll()
	}
}

func (rt *greFRPRuntime) closeAll() {
	if rt.closed.Swap(true) {
		return
	}
	close(rt.stopCh)
	if rt.carrierLn != nil {
		_ = rt.carrierLn.Close()
	}
	for _, ln := range rt.entryListeners {
		_ = ln.Close()
	}
	for _, pc := range rt.entryUDPConns {
		_ = pc.Close()
	}
}

func (rt *greFRPRuntime) setTestEndpoints(remotePrivIP, remotePubIP string, listenPort int) {
	rt.cfgMu.Lock()
	if remotePrivIP != "" {
		rt.remotePrivIP = remotePrivIP
	}
	if remotePubIP != "" {
		rt.remotePubIP = remotePubIP
	}
	if listenPort > 0 {
		rt.tunnel.ListenPort = listenPort
		if rt.tunnel.GREFRP != nil {
			rt.tunnel.GREFRP.FRPServerPort = listenPort
		}
	}
	rt.cfgMu.Unlock()
}

// Target endpoint selector: returns the remote GRE private IP when ActivePath == "GRE",
// or the remote Public IP when ActivePath == "PUBLIC_FALLBACK".
func (rt *greFRPRuntime) currentTargetHost() string {
	rt.cfgMu.RLock()
	remPriv := rt.remotePrivIP
	remPub := rt.remotePubIP
	rt.cfgMu.RUnlock()

	act, _ := rt.activePath.Load().(string)
	if act == greFRPPathGRE && remPriv != "" {
		// In local single-host loopback tests where remotePubIP is 127.0.0.1 and no kernel GRE interface exists,
		// route loopback probes to 127.0.0.1 unless the private IP is locally bound.
		if remPub == "127.0.0.1" && !isLocalIPAddressBound(remPriv) {
			return "127.0.0.1"
		}
		return remPriv
	}
	return remPub
}

func isLocalIPAddressBound(ipStr string) bool {
	target := net.ParseIP(strings.TrimSpace(ipStr))
	if target == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(target) {
			return true
		}
	}
	return false
}

func startGREFRPServer(peer ServerPeer, tc TunnelConfig) (net.Listener, []net.Listener, []net.PacketConn, error) {
	stopGREFRPPeerResources(peer.ID)

	stateMu.RLock()
	role := appCfg.Role
	stateMu.RUnlock()

	gf := normalizeGREFRPConfig(tc.GREFRP, tc.ListenPort, tc.ForwardPorts)
	localPriv, remotePriv, cidr := resolveRoleOrderedGREIPs(gf, role, peer.ID)
	gf.PrivateSubnetCIDR = cidr
	gf.LocalPrivateIP = localPriv
	gf.RemotePrivateIP = remotePriv
	if gf.RemotePublicIP == "" {
		gf.RemotePublicIP = strings.TrimSpace(peer.IP)
	}
	tc.GREFRP = gf

	rt := &greFRPRuntime{
		peerID:       peer.ID,
		peer:         peer,
		tunnel:       tc,
		role:         role,
		localPrivIP:  localPriv,
		remotePrivIP: remotePriv,
		remotePubIP:  strings.TrimSpace(gf.RemotePublicIP),
		startedAt:    time.Now(),
		stopCh:       make(chan struct{}),
	}
	rt.activePath.Store(greFRPPathGRE)

	_, greStat := applyLinuxGREInterface(peer, tc, role)
	rt.greStatus.Store(greStat)
	rt.appendLog(fmt.Sprintf("GRE interface initialized: %s (subnet %s)", greStat, cidr))

	_, _, _ = writeFRPConfigFiles(peer, tc, rt.currentTargetHost())

	// Bind the carrier listener on 0.0.0.0:<ListenPort> (accepts both GRE Private IP and Public IP fallback connections)
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{localCert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", listenAddr, tlsCfg)
	if err != nil {
		return nil, nil, nil, err
	}
	rt.carrierLn = ln

	go func() {
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			enableKeepAlive(conn)
			go rt.handleIncomingCarrierConn(conn)
		}
	}()

	// Bind Mode 2 port-forwarding entry rules on Master when Traffic Tunnel is enabled
	if tc.Enabled && peer.IP != "" && shouldBindEntryPorts() {
		expanded, err := validateAndExpandGREFRPRules(gf, tc.ListenPort)
		if err != nil {
			gf.ForwardingRules = buildGREFRPRulesFromCSV(tc.ForwardPorts, gf.FRPEncryption, gf.FRPCompression, gf.FRPProxyProtoV2)
			expanded, _ = validateAndExpandGREFRPRules(gf, tc.ListenPort)
		}
		for _, rule := range expanded {
			r := rule
			if r.Protocol == "tcp" {
				eLn, lErr := net.Listen("tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(r.RemotePort)))
				if lErr == nil {
					rt.entryListeners = append(rt.entryListeners, eLn)
					go rt.acceptRuleTCPLoop(eLn, r)
				}
			} else if r.Protocol == "udp" {
				uAddr, uErr := net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(r.RemotePort)))
				if uErr == nil {
					uConn, lErr := net.ListenUDP("udp", uAddr)
					if lErr == nil {
						configureUDPSocketBuffers(uConn)
						rt.entryUDPConns = append(rt.entryUDPConns, uConn)
						go rt.acceptRuleUDPLoop(uConn, r)
					}
				}
			}
		}
	}

	greFRPRuntimeMu.Lock()
	greFRPRuntimes[peer.ID] = rt
	greFRPRuntimeMu.Unlock()

	if strings.TrimSpace(rt.remotePubIP) != "" {
		go rt.healthAndFailoverMonitorLoop()
	}

	return ln, rt.entryListeners, rt.entryUDPConns, nil
}

// ============================================================================
// 5. CONTINUOUS GRE HEALTH MONITOR & AUTOMATIC PUBLIC-IP FAILOVER
// ============================================================================

func (rt *greFRPRuntime) healthAndFailoverMonitorLoop() {
	rt.cfgMu.RLock()
	gf := normalizeGREFRPConfig(rt.tunnel.GREFRP, rt.tunnel.ListenPort, rt.tunnel.ForwardPorts)
	rt.cfgMu.RUnlock()

	interval := time.Duration(gf.HealthCheckSec) * time.Second
	if interval < time.Second {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-rt.stopCh:
			return
		case <-ticker.C:
			rt.evaluateGREHealthStep(gf)
		}
	}
}

func (rt *greFRPRuntime) evaluateGREHealthStep(gf *GREFRPConfig) {
	if rt.closed.Load() {
		return
	}
	rt.cfgMu.RLock()
	remPriv := rt.remotePrivIP
	remPub := rt.remotePubIP
	peerSnap := rt.peer
	tunSnap := rt.tunnel
	rt.cfgMu.RUnlock()

	if remPub == "" {
		return
	}

	greTarget := remPriv
	if remPub == "127.0.0.1" && !isLocalIPAddressBound(remPriv) {
		greTarget = "127.0.0.1"
	}

	rtt, err := probeGREFRPTargetHost(peerSnap, tunSnap, greTarget, 2*time.Second)
	curPath, _ := rt.activePath.Load().(string)

	if err == nil {
		rt.grePingOK.Store(true)
		rt.greRTTMS.Store(rtt)
		rt.greLossPct.Store(0)
		rt.consecFail.Store(0)
		succ := rt.consecSuccess.Add(1)

		if curPath == greFRPPathPublic && gf.AutoRestoreGRE && int(succ) >= gf.RecoveryThreshold {
			rt.activePath.Store(greFRPPathGRE)
			nowStr := formatMasterTimestamp(masterNow())
			rt.lastRecoveryAt.Store(nowStr)
			rt.reconnectCount.Add(1)
			_, _, _ = writeFRPConfigFiles(peerSnap, tunSnap, remPriv)
			rt.appendLog(fmt.Sprintf("GRE path recovered (%dms RTT); restored preferred GRE path (%s)", rtt, remPriv))
		}
		return
	}

	// GRE probe failed
	rt.grePingOK.Store(false)
	rt.greLossPct.Store(100)
	rt.consecSuccess.Store(0)
	fails := rt.consecFail.Add(1)
	rt.lastFailureReason.Store(err.Error())

	if curPath == greFRPPathGRE && gf.AutoPublicFallback && int(fails) >= gf.FailureThreshold {
		// Verify Public IP fallback path is reachable before switching
		if pubRTT, pubErr := probeGREFRPTargetHost(peerSnap, tunSnap, remPub, 2500*time.Millisecond); pubErr == nil {
			rt.activePath.Store(greFRPPathPublic)
			rt.greRTTMS.Store(pubRTT)
			rt.reconnectCount.Add(1)
			_, _, _ = writeFRPConfigFiles(peerSnap, tunSnap, remPub)
			rt.appendLog(fmt.Sprintf("GRE path unreachable (%d consecutive failures); switched FRP to Public IP fallback (%s, %dms)",
				fails, remPub, pubRTT))
		} else {
			rt.appendLog(fmt.Sprintf("GRE path failed and Public IP fallback (%s) is also unreachable: %v", remPub, pubErr))
		}
	}
}

// ============================================================================
// 6. WIRE PROTOCOL, AEAD ENCRYPTION, COMPRESSION & PROXY PROTOCOL V2
// ============================================================================

// Builds a 28-byte PROXY Protocol v2 binary header (IPv4 TCP/UDP) when `ProxyProtoV2` is enabled on a rule.
func buildProxyProtocolV2Header(clientAddr, localAddr net.Addr) []byte {
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	hdr := make([]byte, 28)
	copy(hdr[0:12], sig)
	hdr[12] = 0x21 // Version 2, PROXY command
	hdr[13] = 0x11 // AF_INET (IPv4) + STREAM (TCP)

	srcIP := net.IPv4(127, 0, 0, 1).To4()
	dstIP := net.IPv4(127, 0, 0, 1).To4()
	srcPort := uint16(0)
	dstPort := uint16(0)

	if ta, ok := clientAddr.(*net.TCPAddr); ok {
		if ip4 := ta.IP.To4(); ip4 != nil {
			srcIP = ip4
		}
		srcPort = uint16(ta.Port)
	}
	if ta, ok := localAddr.(*net.TCPAddr); ok {
		if ip4 := ta.IP.To4(); ip4 != nil {
			dstIP = ip4
		}
		dstPort = uint16(ta.Port)
	}

	binary.BigEndian.PutUint16(hdr[14:16], 12)
	copy(hdr[16:20], srcIP)
	copy(hdr[20:24], dstIP)
	binary.BigEndian.PutUint16(hdr[24:26], srcPort)
	binary.BigEndian.PutUint16(hdr[26:28], dstPort)
	return hdr
}

// Wraps a net.Conn with optional ChaCha20-Poly1305 frame encryption and DEFLATE compression
// matching FRP's per-proxy `useEncryption` and `useCompression` semantics.
type greFRPProtectedStream struct {
	raw           net.Conn
	useEncryption bool
	useCompress   bool
	txKey         [32]byte
	rxKey         [32]byte
	txSeq         uint64
	rxSeq         uint64
	readMu        sync.Mutex
	writeMu       sync.Mutex
	readBuf       bytes.Buffer
}

func newGREFRPProtectedStream(raw net.Conn, authKey []byte, sessionSalt []byte, isClient bool, useEnc, useComp bool) *greFRPProtectedStream {
	s := &greFRPProtectedStream{
		raw:           raw,
		useEncryption: useEnc,
		useCompress:   useComp,
	}
	mac1 := hmac.New(sha256.New, authKey)
	_, _ = mac1.Write([]byte("gre-frp-c2s:"))
	_, _ = mac1.Write(sessionSalt)
	c2s := mac1.Sum(nil)

	mac2 := hmac.New(sha256.New, authKey)
	_, _ = mac2.Write([]byte("gre-frp-s2c:"))
	_, _ = mac2.Write(sessionSalt)
	s2c := mac2.Sum(nil)

	if isClient {
		copy(s.txKey[:], c2s[:32])
		copy(s.rxKey[:], s2c[:32])
	} else {
		copy(s.txKey[:], s2c[:32])
		copy(s.rxKey[:], c2s[:32])
	}
	return s
}

func (s *greFRPProtectedStream) Write(p []byte) (int, error) {
	if !s.useEncryption && !s.useCompress {
		return s.raw.Write(p)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 16384 {
			chunk = p[:16384]
		}
		payload := chunk
		if s.useCompress {
			var compBuf bytes.Buffer
			w, err := flate.NewWriter(&compBuf, flate.BestSpeed)
			if err == nil {
				_, _ = w.Write(chunk)
				_ = w.Close()
				payload = compBuf.Bytes()
			}
		}
		if s.useEncryption {
			aead, err := chacha20poly1305.New(s.txKey[:])
			if err != nil {
				return total, err
			}
			s.txSeq++
			var nonce [12]byte
			binary.BigEndian.PutUint64(nonce[4:12], s.txSeq)
			payload = aead.Seal(nil, nonce[:], payload, nil)
		}
		var lenHdr [4]byte
		binary.BigEndian.PutUint32(lenHdr[:], uint32(len(payload)))
		if _, err := s.raw.Write(lenHdr[:]); err != nil {
			return total, err
		}
		if _, err := s.raw.Write(payload); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *greFRPProtectedStream) Read(p []byte) (int, error) {
	if !s.useEncryption && !s.useCompress {
		return s.raw.Read(p)
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if s.readBuf.Len() > 0 {
		return s.readBuf.Read(p)
	}

	var lenHdr [4]byte
	if _, err := io.ReadFull(s.raw, lenHdr[:]); err != nil {
		return 0, err
	}
	fLen := binary.BigEndian.Uint32(lenHdr[:])
	if fLen == 0 || fLen > 128*1024 {
		return 0, errors.New("invalid GRE+FRP frame length")
	}
	buf := make([]byte, fLen)
	if _, err := io.ReadFull(s.raw, buf); err != nil {
		return 0, err
	}

	if s.useEncryption {
		aead, err := chacha20poly1305.New(s.rxKey[:])
		if err != nil {
			return 0, err
		}
		s.rxSeq++
		var nonce [12]byte
		binary.BigEndian.PutUint64(nonce[4:12], s.rxSeq)
		plain, err := aead.Open(nil, nonce[:], buf, nil)
		if err != nil {
			return 0, err
		}
		buf = plain
	}

	if s.useCompress {
		r := flate.NewReader(bytes.NewReader(buf))
		decomp, err := io.ReadAll(io.LimitReader(r, 128*1024))
		_ = r.Close()
		if err != nil {
			return 0, err
		}
		buf = decomp
	}

	s.readBuf.Write(buf)
	return s.readBuf.Read(p)
}

func (s *greFRPProtectedStream) Close() error {
	return s.raw.Close()
}

// ============================================================================
// 7. HANDSHAKE, PROBE, PARITY SYNC & TCP/UDP FORWARDING HANDLERS
// ============================================================================

type greFRPHandshakeHeader struct {
	Magic         string `json:"m"`
	Cmd           byte   `json:"c"`
	PeerID        string `json:"p"`
	LocalAddr     string `json:"la,omitempty"`
	TargetPort    int    `json:"tp,omitempty"`
	UseEncryption bool   `json:"enc,omitempty"`
	UseCompress   bool   `json:"cmp,omitempty"`
	ProxyProtoV2  bool   `json:"pp2,omitempty"`
	TimeHdr       string `json:"th,omitempty"`
	Nonce         string `json:"n"`
	MAC           string `json:"mac"`
}

func computeGREFRPHandshakeMAC(authKey []byte, h greFRPHandshakeHeader) string {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte(fmt.Sprintf("%s|%d|%s|%s|%d|%t|%t|%t|%s",
		h.Magic, h.Cmd, h.PeerID, h.LocalAddr, h.TargetPort, h.UseEncryption, h.UseCompress, h.ProxyProtoV2, h.Nonce)))
	return hex.EncodeToString(mac.Sum(nil))
}

func dialGREFRPCarrier(
	peer ServerPeer,
	tc TunnelConfig,
	targetHost string,
	cmd byte,
	localAddr string,
	targetPort int,
	useEnc, useComp, ppv2 bool,
	timeout time.Duration,
) (net.Conn, *greFRPProtectedStream, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return nil, nil, err
	}

	if strings.TrimSpace(targetHost) == "" {
		targetHost = strings.TrimSpace(peer.IP)
	}
	srvPort := tc.ListenPort
	if tc.GREFRP != nil && tc.GREFRP.FRPServerPort >= 1024 {
		srvPort = tc.GREFRP.FRPServerPort
	}

	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.Dial("tcp", net.JoinHostPort(targetHost, strconv.Itoa(srvPort)))
	if err != nil {
		return nil, nil, err
	}
	enableKeepAlive(rawConn)
	_ = rawConn.SetDeadline(time.Now().Add(timeout + 2*time.Second))

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         "www.speedtest.net",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	nonce, _ := randomHex(12)
	hs := greFRPHandshakeHeader{
		Magic:         greFRPProtocolMagic,
		Cmd:           cmd,
		PeerID:        peer.ID,
		LocalAddr:     localAddr,
		TargetPort:    targetPort,
		UseEncryption: useEnc,
		UseCompress:   useComp,
		ProxyProtoV2:  ppv2,
		TimeHdr:       buildMasterTimeHeader(),
		Nonce:         nonce,
	}
	hs.MAC = computeGREFRPHandshakeMAC(authKey, hs)

	rawHS, err := json.Marshal(hs)
	if err != nil {
		_ = tlsConn.Close()
		return nil, nil, err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(rawHS)))
	if _, err := tlsConn.Write(lenBuf[:]); err != nil {
		_ = tlsConn.Close()
		return nil, nil, err
	}
	if _, err := tlsConn.Write(rawHS); err != nil {
		_ = tlsConn.Close()
		return nil, nil, err
	}

	var status [1]byte
	if _, err := io.ReadFull(tlsConn, status[:]); err != nil {
		_ = tlsConn.Close()
		return nil, nil, err
	}
	if status[0] != 0x00 {
		_ = tlsConn.Close()
		return nil, nil, fmt.Errorf("GRE+FRP handshake rejected (code %d)", status[0])
	}

	prot := newGREFRPProtectedStream(tlsConn, authKey, []byte(nonce), true, useEnc, useComp)
	return tlsConn, prot, nil
}

func (rt *greFRPRuntime) handleIncomingCarrierConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	rt.cfgMu.RLock()
	peerSnap := rt.peer
	tunSnap := rt.tunnel
	rt.cfgMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peerSnap)
	if err != nil {
		return
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	hsLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if hsLen <= 0 || hsLen > 8192 {
		return
	}
	hsBytes := make([]byte, hsLen)
	if _, err := io.ReadFull(conn, hsBytes); err != nil {
		return
	}

	var hs greFRPHandshakeHeader
	if json.Unmarshal(hsBytes, &hs) != nil || hs.Magic != greFRPProtocolMagic {
		return
	}
	expectedMAC := computeGREFRPHandshakeMAC(authKey, hs)
	if subtle.ConstantTimeCompare([]byte(hs.MAC), []byte(expectedMAC)) != 1 {
		_, _ = conn.Write([]byte{0x01})
		return
	}

	if hs.TimeHdr != "" {
		applyMasterTimeHeader(hs.TimeHdr)
	}

	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	prot := newGREFRPProtectedStream(conn, authKey, []byte(hs.Nonce), false, hs.UseEncryption, hs.UseCompress)

	switch hs.Cmd {
	case greFRPCmdProbe:
		if _, err := conn.Write([]byte{0x00}); err != nil {
			return
		}
		var ping [16]byte
		if _, err := io.ReadFull(prot, ping[:]); err != nil {
			return
		}
		_, _ = prot.Write(ping[:])
		markPeerConnectedInbound(peerSnap.ID, remoteHost, tunSnap.ID, tunSnap.ListenPort, 1)

	case greFRPCmdParitySync:
		if _, err := conn.Write([]byte{0x00}); err != nil {
			return
		}
		handleWebTransportParitySyncStream(prot, peerSnap.ID, remoteHost)

	case greFRPCmdTCPForward:
		if !tunSnap.Enabled {
			_, _ = conn.Write([]byte{0x02})
			return
		}
		if !rt.isTargetPortAllowed(hs.TargetPort) {
			_, _ = conn.Write([]byte{0x03})
			return
		}
		localHost := strings.TrimSpace(hs.LocalAddr)
		if localHost == "" {
			localHost = "127.0.0.1"
		}
		target, err := net.DialTimeout("tcp", net.JoinHostPort(localHost, strconv.Itoa(hs.TargetPort)), 5*time.Second)
		if err != nil {
			_, _ = conn.Write([]byte{0x04})
			return
		}
		defer target.Close()
		enableKeepAlive(target)

		if _, err := conn.Write([]byte{0x00}); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})

		if hs.ProxyProtoV2 {
			var ppHdr [28]byte
			if _, err := io.ReadFull(prot, ppHdr[:]); err != nil {
				return
			}
			if _, err := target.Write(ppHdr[:]); err != nil {
				return
			}
		}

		rt.pipeProtectedStreamAndTCP(prot, target)

	case greFRPCmdUDPForward:
		if !tunSnap.Enabled || !rt.isTargetPortAllowed(hs.TargetPort) {
			_, _ = conn.Write([]byte{0x03})
			return
		}
		if _, err := conn.Write([]byte{0x00}); err != nil {
			return
		}
		var dLenBuf [2]byte
		if _, err := io.ReadFull(prot, dLenBuf[:]); err != nil {
			return
		}
		dLen := int(binary.BigEndian.Uint16(dLenBuf[:]))
		if dLen <= 0 || dLen > 16384 {
			return
		}
		dgram := make([]byte, dLen)
		if _, err := io.ReadFull(prot, dgram); err != nil {
			return
		}
		atomic.AddUint64(&appRxBytes, uint64(len(dgram)))

		localHost := strings.TrimSpace(hs.LocalAddr)
		if localHost == "" {
			localHost = "127.0.0.1"
		}
		uConn, err := net.DialTimeout("udp", net.JoinHostPort(localHost, strconv.Itoa(hs.TargetPort)), 3*time.Second)
		if err != nil {
			return
		}
		defer uConn.Close()
		_ = uConn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := uConn.Write(dgram); err != nil {
			return
		}
		rep := make([]byte, 16384)
		n, err := uConn.Read(rep)
		if err == nil && n > 0 {
			atomic.AddUint64(&appTxBytes, uint64(n))
			binary.BigEndian.PutUint16(dLenBuf[:], uint16(n))
			_, _ = prot.Write(dLenBuf[:])
			_, _ = prot.Write(rep[:n])
		}
	}
}

func (rt *greFRPRuntime) isTargetPortAllowed(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	rt.cfgMu.RLock()
	tunSnap := rt.tunnel
	rt.cfgMu.RUnlock()

	gf := normalizeGREFRPConfig(tunSnap.GREFRP, tunSnap.ListenPort, tunSnap.ForwardPorts)
	expanded, err := validateAndExpandGREFRPRules(gf, tunSnap.ListenPort)
	if err == nil {
		for _, r := range expanded {
			if r.LocalPort == port || r.RemotePort == port {
				return true
			}
		}
	}
	_, aErr := authorizeWSSTargetPort(tunSnap, strconv.Itoa(port))
	return aErr == nil
}

func (rt *greFRPRuntime) pipeProtectedStreamAndTCP(prot *greFRPProtectedStream, tcpConn net.Conn) {
	rt.cfgMu.RLock()
	speedLimit := rt.tunnel.SpeedLimitMBps
	rt.cfgMu.RUnlock()

	mbLimit := parseSpeedLimit(speedLimit)
	toProt := newThrottledWriter(prot, &appTxBytes, mbLimit)
	toTCP := newThrottledWriter(tcpConn, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toProt, tcpConn, buf)
		_ = prot.Close()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toTCP, prot, buf)
		closeWriteTCP(tcpConn)
	}()

	wg.Wait()
}

func (rt *greFRPRuntime) acceptRuleTCPLoop(ln net.Listener, rule ExpandedPortMapping) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		enableKeepAlive(client)
		go rt.forwardRuleTCPClient(client, rule)
	}
}

func (rt *greFRPRuntime) forwardRuleTCPClient(client net.Conn, rule ExpandedPortMapping) {
	defer client.Close()

	rt.cfgMu.RLock()
	peerSnap := rt.peer
	tunSnap := rt.tunnel
	remPub := rt.remotePubIP
	rt.cfgMu.RUnlock()

	targetHost := rt.currentTargetHost()
	rawConn, prot, err := dialGREFRPCarrier(
		peerSnap,
		tunSnap,
		targetHost,
		greFRPCmdTCPForward,
		rule.LocalAddr,
		rule.LocalPort,
		rule.UseEncryption,
		rule.UseCompress,
		rule.ProxyProtoV2,
		4*time.Second,
	)
	if err != nil && targetHost != remPub && remPub != "" {
		// Immediate failover to Public IP if the GRE private IP failed mid-connection
		rawConn, prot, err = dialGREFRPCarrier(
			peerSnap,
			tunSnap,
			remPub,
			greFRPCmdTCPForward,
			rule.LocalAddr,
			rule.LocalPort,
			rule.UseEncryption,
			rule.UseCompress,
			rule.ProxyProtoV2,
			4*time.Second,
		)
		if err == nil {
			rt.activePath.Store(greFRPPathPublic)
			rt.reconnectCount.Add(1)
		}
	}
	if err != nil {
		return
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Time{})

	if rule.ProxyProtoV2 {
		ppHdr := buildProxyProtocolV2Header(client.RemoteAddr(), client.LocalAddr())
		if _, err := prot.Write(ppHdr); err != nil {
			return
		}
	}

	rt.pipeProtectedStreamAndTCP(prot, client)
}

func (rt *greFRPRuntime) acceptRuleUDPLoop(uConn *net.UDPConn, rule ExpandedPortMapping) {
	buf := make([]byte, 16384)
	for {
		n, cliAddr, err := uConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n <= 0 || rt.closed.Load() {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		cliCopy := cloneUDPAddr(cliAddr)

		go func(dgram []byte, cAddr *net.UDPAddr) {
			rt.cfgMu.RLock()
			peerSnap := rt.peer
			tunSnap := rt.tunnel
			remPub := rt.remotePubIP
			rt.cfgMu.RUnlock()

			targetHost := rt.currentTargetHost()
			rawConn, prot, err := dialGREFRPCarrier(
				peerSnap,
				tunSnap,
				targetHost,
				greFRPCmdUDPForward,
				rule.LocalAddr,
				rule.LocalPort,
				rule.UseEncryption,
				rule.UseCompress,
				false,
				3*time.Second,
			)
			if err != nil && targetHost != remPub && remPub != "" {
				rawConn, prot, err = dialGREFRPCarrier(
					peerSnap,
					tunSnap,
					remPub,
					greFRPCmdUDPForward,
					rule.LocalAddr,
					rule.LocalPort,
					rule.UseEncryption,
					rule.UseCompress,
					false,
					3*time.Second,
				)
			}
			if err != nil {
				return
			}
			defer rawConn.Close()

			atomic.AddUint64(&appTxBytes, uint64(len(dgram)))
			var lenBuf [2]byte
			binary.BigEndian.PutUint16(lenBuf[:], uint16(len(dgram)))
			if _, err := prot.Write(lenBuf[:]); err != nil {
				return
			}
			if _, err := prot.Write(dgram); err != nil {
				return
			}
			if _, err := io.ReadFull(prot, lenBuf[:]); err != nil {
				return
			}
			rLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if rLen > 0 && rLen <= 16384 {
				rep := make([]byte, rLen)
				if _, err := io.ReadFull(prot, rep); err == nil {
					atomic.AddUint64(&appRxBytes, uint64(rLen))
					_, _ = uConn.WriteToUDP(rep, cAddr)
				}
			}
		}(payload, cliCopy)
	}
}

// ============================================================================
// 8. ENGINE 1 & ENGINE 2 ENTRY POINTS (probeGREFRP, pushGREFRPParitySync, forwardGREFRPTraffic)
// ============================================================================

func probeGREFRPTargetHost(peer ServerPeer, tc TunnelConfig, targetHost string, timeout time.Duration) (int64, error) {
	start := time.Now()
	rawConn, prot, err := dialGREFRPCarrier(
		peer,
		tc,
		targetHost,
		greFRPCmdProbe,
		"127.0.0.1",
		tc.ListenPort,
		true,
		false,
		false,
		timeout,
	)
	if err != nil {
		return 0, err
	}
	defer rawConn.Close()

	var ping [16]byte
	var pong [16]byte
	_, _ = io.ReadFull(rand.Reader, ping[:])
	if _, err := prot.Write(ping[:]); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(prot, pong[:]); err != nil || !bytes.Equal(ping[:], pong[:]) {
		return 0, errors.New("GRE+FRP probe echo mismatch")
	}

	rtt := time.Since(start).Milliseconds()
	if rtt <= 0 {
		rtt = 1
	}
	return rtt, nil
}

func probeGREFRP(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	gf := normalizeGREFRPConfig(tc.GREFRP, tc.ListenPort, tc.ForwardPorts)
	if err := validateGREFRPConfiguration(gf, tc.ListenPort); err != nil {
		res.Success = false
		res.ErrorReason = err.Error()
		return res
	}

	greFRPRuntimeMu.RLock()
	rt := greFRPRuntimes[peer.ID]
	greFRPRuntimeMu.RUnlock()

	targetHost := peer.IP
	if rt != nil {
		targetHost = rt.currentTargetHost()
	}

	rtt, err := probeGREFRPTargetHost(peer, tc, targetHost, 3500*time.Millisecond)
	if err != nil && gf.AutoPublicFallback && targetHost != peer.IP && strings.TrimSpace(peer.IP) != "" {
		// Automatic fallback to public IP if GRE private IP probe fails
		rtt, err = probeGREFRPTargetHost(peer, tc, peer.IP, 3500*time.Millisecond)
		if err == nil && rt != nil {
			rt.activePath.Store(greFRPPathPublic)
			rt.reconnectCount.Add(1)
		}
	}

	if err != nil {
		res.Success = false
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(msg, "rejected") || strings.Contains(msg, "auth") {
			res.ErrorReason = "Authentication failure"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}

	if rt != nil {
		rt.cfgMu.RLock()
		remPriv := rt.remotePrivIP
		remPub := rt.remotePubIP
		rt.cfgMu.RUnlock()

		rt.greRTTMS.Store(rtt)
		if targetHost == remPriv || remPub == "127.0.0.1" {
			rt.grePingOK.Store(true)
			rt.greLossPct.Store(0)
		}
	}

	res.Success = true
	res.LatencyMS = rtt
	res.MinLatencyMS = rtt
	res.MaxLatencyMS = rtt
	return res
}

func pushGREFRPParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	greFRPRuntimeMu.RLock()
	rt := greFRPRuntimes[peer.ID]
	greFRPRuntimeMu.RUnlock()

	targetHost := peer.IP
	if rt != nil {
		targetHost = rt.currentTargetHost()
	}

	rawConn, prot, err := dialGREFRPCarrier(
		peer,
		tc,
		targetHost,
		greFRPCmdParitySync,
		"127.0.0.1",
		tc.ListenPort,
		true,
		false,
		false,
		4*time.Second,
	)
	if err != nil && targetHost != peer.IP {
		rawConn, prot, err = dialGREFRPCarrier(
			peer,
			tc,
			peer.IP,
			greFRPCmdParitySync,
			"127.0.0.1",
			tc.ListenPort,
			true,
			false,
			false,
			4*time.Second,
		)
	}
	if err != nil {
		return false
	}
	defer rawConn.Close()

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
	if _, err := prot.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := prot.Write(rawPkt); err != nil {
		return false
	}

	if _, err := io.ReadFull(prot, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(prot, respBytes); err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func forwardGREFRPTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	pNum, err := strconv.Atoi(strings.TrimSpace(targetPort))
	if err != nil || pNum < 1 || pNum > 65535 {
		_ = client.Close()
		return
	}

	greFRPRuntimeMu.RLock()
	rt := greFRPRuntimes[peer.ID]
	greFRPRuntimeMu.RUnlock()

	gf := normalizeGREFRPConfig(tc.GREFRP, tc.ListenPort, tc.ForwardPorts)
	rule := ExpandedPortMapping{
		RuleName:      "direct-" + targetPort,
		Protocol:      "tcp",
		LocalAddr:     "127.0.0.1",
		LocalPort:     pNum,
		RemotePort:    pNum,
		UseEncryption: gf.FRPEncryption,
		UseCompress:   gf.FRPCompression,
		ProxyProtoV2:  gf.FRPProxyProtoV2,
	}

	if rt != nil {
		rt.forwardRuleTCPClient(client, rule)
		return
	}

	defer client.Close()
	rawConn, prot, err := dialGREFRPCarrier(
		peer,
		tc,
		peer.IP,
		greFRPCmdTCPForward,
		rule.LocalAddr,
		rule.LocalPort,
		rule.UseEncryption,
		rule.UseCompress,
		rule.ProxyProtoV2,
		5*time.Second,
	)
	if err != nil {
		return
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Time{})

	if rule.ProxyProtoV2 {
		ppHdr := buildProxyProtocolV2Header(client.RemoteAddr(), client.LocalAddr())
		if _, err := prot.Write(ppHdr); err != nil {
			return
		}
	}

	mbLimit := parseSpeedLimit(tc.SpeedLimitMBps)
	toProt := newThrottledWriter(prot, &appTxBytes, mbLimit)
	toTCP := newThrottledWriter(client, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toProt, client, buf)
		_ = prot.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toTCP, prot, buf)
		closeWriteTCP(client)
	}()
	wg.Wait()
}

// Performs start / restart / install / uninstall lifecycle operations on Method 25 for a peer.
func ExecuteGREFRPServiceAction(peerID string, action string) (string, error) {
	stateMu.RLock()
	role := appCfg.Role
	var peer *ServerPeer
	var tc *TunnelConfig
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peerID {
			cp := appCfg.Servers[i]
			peer = &cp
			for j := range cp.Tunnels {
				if cp.Tunnels[j].ID == 25 {
					t := cp.Tunnels[j]
					tc = &t
					break
				}
			}
			break
		}
	}
	stateMu.RUnlock()

	if peer == nil || tc == nil {
		return "", errors.New("server or Method 25 configuration not found")
	}

	gf := normalizeGREFRPConfig(tc.GREFRP, tc.ListenPort, tc.ForwardPorts)

	switch action {
	case "install_frp":
		frpsBin, frpcBin, err := installOfficialFRPBinaries()
		if err != nil {
			return "", err
		}
		_, _, err = writeFRPConfigFiles(*peer, *tc, peer.IP)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Installed official FRP v%s (%s, %s)", officialFRPVersion, filepath.Base(frpsBin), filepath.Base(frpcBin)), nil

	case "reapply_gre":
		ok, status := applyLinuxGREInterface(*peer, *tc, role)
		if !ok {
			return status, nil
		}
		return "GRE interface applied: " + status, nil

	case "restart":
		syncServerListeners(*peer)
		return "GRE + FRP runtime and listeners restarted", nil

	case "uninstall":
		stopGREFRPPeerResources(peerID)
		removeLinuxGREInterface(peerID, gf.GREInterfaceName)
		_ = os.Remove(filepath.Join(frpInstallDir(), fmt.Sprintf("frps-%s.toml", peerID)))
		_ = os.Remove(filepath.Join(frpInstallDir(), fmt.Sprintf("frpc-%s.toml", peerID)))
		return "GRE interface, systemd unit, and FRP config files removed cleanly", nil

	default:
		return "", fmt.Errorf("unknown GRE+FRP action %q", action)
	}
}
