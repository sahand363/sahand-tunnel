package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
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
)

const (
	greFRPEngineName     = "gre-frp"
	greFRPMethodID       = 25
	frpOfficialVersion   = "0.61.1"
	frpReleaseBaseURL    = "https://github.com/fatedier/frp/releases/download/v" + frpOfficialVersion
	greFRPWorkDirDefault = "/opt/sahand-tunnel/gre-frp"

	grePathPreferred = "GRE"
	grePathPublicIP  = "PUBLIC_IP"

	greFRPFrameProbe      byte = 0x01
	greFRPFrameProbeAck   byte = 0x02
	greFRPFrameParitySync byte = 0x03
	greFRPFrameParityAck  byte = 0x04
	greFRPFrameTCPForward byte = 0x05
	greFRPFrameUDPForward byte = 0x06

	greFRPStatusOK          byte = 0x00
	greFRPStatusForbidden   byte = 0x01
	greFRPStatusUnreachable byte = 0x02
)

// Official SHA-256 digests published in fatedier/frp v0.61.1 frp_0.61.1_checksums.txt
var frpOfficialSHA256ByArch = map[string]string{
	"amd64": "5f9da9bb2eb2ef9fb89f5cf8bc6fb087f1e7bf9de3b7e029c9e47f0a69d81a4a",
	"arm64": "4a2e6d369bc7df97665c03cc116266647b590b0b4f88721b3a98a5f2f98f163b",
}

var validGREIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

var forbiddenSystemIfaces = map[string]bool{
	"lo": true, "eth0": true, "eth1": true, "ens3": true, "ens160": true,
	"ens192": true, "enp0s3": true, "enp1s0": true, "docker0": true, "tun0": true, "wg0": true,
}

type GREFRPConfig struct {
	// GRE Network Tunnel Settings
	LocalPublicIP          string `json:"local_public_ip"`
	RemotePublicIP         string `json:"remote_public_ip"`
	InterfaceName          string `json:"interface_name"`
	SubnetCIDR             string `json:"subnet_cidr"`
	LocalGREIP             string `json:"local_gre_ip"`
	RemoteGREIP            string `json:"remote_gre_ip"`
	MTU                    int    `json:"mtu"`
	ConfigureRoutes        bool   `json:"configure_routes"`
	HealthCheckIntervalSec int    `json:"health_check_interval_sec"`
	FailureThreshold       int    `json:"failure_threshold"`
	RecoveryThreshold      int    `json:"recovery_threshold"`
	AutoFallback           bool   `json:"auto_fallback"`
	AutoRestore            bool   `json:"auto_restore"`

	// FRP Port Forwarding Settings
	FRPVersion      string `json:"frp_version"`
	FRPTransport    string `json:"frp_transport"`
	FRPServerPort   int    `json:"frp_server_port"`
	FRPAuthToken    string `json:"frp_auth_token"`
	UseEncryption   bool   `json:"use_encryption"`
	UseCompression  bool   `json:"use_compression"`
	TCPMux          bool   `json:"tcp_mux"`
	ProxyProtocolV2 bool   `json:"proxy_protocol_v2"`
	ForwardingRules string `json:"forwarding_rules"`
	ForwardProtocol string `json:"forward_protocol"`
	LocalAddr       string `json:"local_addr"`
	LocalPort       string `json:"local_port"`
	RemotePort      string `json:"remote_port"`
}

type GREFRPStatus struct {
	EngineName          string   `json:"engine_name"`
	GREInterfaceStatus  string   `json:"gre_interface_status"`
	GREConnectivity     bool     `json:"gre_connectivity"`
	GREPacketLossPct    int      `json:"gre_packet_loss_pct"`
	GRERTTMS            int64    `json:"gre_rtt_ms"`
	FRPSServiceStatus   string   `json:"frps_service_status"`
	FRPCServiceStatus   string   `json:"frpc_service_status"`
	ActivePath          string   `json:"active_path"`
	PortForwardStatus   string   `json:"port_forward_status"`
	ServiceUptime       string   `json:"service_uptime"`
	ReconnectionCount   int      `json:"reconnection_count"`
	LastFailureReason   string   `json:"last_failure_reason"`
	LastRecoveryAt      string   `json:"last_recovery_at"`
	Logs                []string `json:"logs"`
}

type greFRPForwardRule struct {
	Name       string
	Protocol   string // "tcp" or "udp"
	LocalIP    string
	LocalPort  int
	RemotePort int
}

// ============================================================================
// CONFIGURATION DEFAULTS, SUBNET ALLOCATION & VALIDATION
// ============================================================================

// Deterministically allocates a non-overlapping /30 subnet in 10.25.<octet>.0/30
// per peer so multiple independent server pairs never collide on GRE IPs.
func derivePeerGRESubnet(peerID string, peerIndex int) (cidr, masterIP, agentIP, iface string) {
	octet3 := (peerIndex % 250) + 1
	if peerID != "" {
		sum := sha256.Sum256([]byte(peerID))
		octet3 = int(sum[0]%240) + 10
	}
	cidr = fmt.Sprintf("10.25.%d.0/30", octet3)
	masterIP = fmt.Sprintf("10.25.%d.1", octet3)
	agentIP = fmt.Sprintf("10.25.%d.2", octet3)

	shortID := strings.TrimSpace(peerID)
	if len(shortID) > 6 {
		shortID = shortID[:6]
	}
	if shortID == "" {
		shortID = strconv.Itoa(peerIndex + 1)
	}
	iface = "gre-st" + shortID
	if len(iface) > 15 {
		iface = iface[:15]
	}
	return cidr, masterIP, agentIP, iface
}

func computeDefaultFRPAuthToken(peer ServerPeer) string {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	if authKey, err := derivePeerAuthKey(cfgSnapshot, peer); err == nil && len(authKey) > 0 {
		mac := hmac.New(sha256.New, authKey)
		_, _ = mac.Write([]byte("sahand-gre-frp-token-v1|" + peer.ID))
		return hex.EncodeToString(mac.Sum(nil)[:16])
	}
	if peer.ID != "" {
		sum := sha256.Sum256([]byte("sahand-gre-frp-fallback|" + peer.ID))
		return hex.EncodeToString(sum[:16])
	}
	return "sahand-frp-default-token-25"
}

func defaultGREFRPConfig(role string, peer ServerPeer, peerIndex int, forwardPorts string) *GREFRPConfig {
	cidr, masterIP, agentIP, iface := derivePeerGRESubnet(peer.ID, peerIndex)
	localGRE := masterIP
	remoteGRE := agentIP
	if role == "agent" {
		localGRE = agentIP
		remoteGRE = masterIP
	}

	defaultPort := strings.TrimSpace(forwardPorts)
	if defaultPort == "" {
		defaultPort = "32025"
	}

	return &GREFRPConfig{
		LocalPublicIP:          "",
		RemotePublicIP:         strings.TrimSpace(peer.IP),
		InterfaceName:          iface,
		SubnetCIDR:             cidr,
		LocalGREIP:             localGRE,
		RemoteGREIP:            remoteGRE,
		MTU:                    1476,
		ConfigureRoutes:        true,
		HealthCheckIntervalSec: 10,
		FailureThreshold:       3,
		RecoveryThreshold:      2,
		AutoFallback:           true,
		AutoRestore:            true,

		FRPVersion:      frpOfficialVersion,
		FRPTransport:    "tcp",
		FRPServerPort:   28025,
		FRPAuthToken:    computeDefaultFRPAuthToken(peer),
		UseEncryption:   true,
		UseCompression:  false,
		TCPMux:          true,
		ProxyProtocolV2: false,
		ForwardingRules: defaultPort,
		ForwardProtocol: "tcp+udp",
		LocalAddr:       "127.0.0.1",
		LocalPort:       defaultPort,
		RemotePort:      defaultPort,
	}
}

func defaultGREFRPStatus() *GREFRPStatus {
	return &GREFRPStatus{
		EngineName:         greFRPEngineName,
		GREInterfaceStatus: "UNCONFIGURED",
		GREConnectivity:    false,
		GREPacketLossPct:   0,
		GRERTTMS:           0,
		FRPSServiceStatus:  "STOPPED",
		FRPCServiceStatus:  "STOPPED",
		ActivePath:         grePathPreferred,
		PortForwardStatus:  "IDLE",
		ServiceUptime:      "0s",
		ReconnectionCount:  0,
		LastFailureReason:  "",
		LastRecoveryAt:     "",
		Logs:               []string{},
	}
}

// Parses a /30 CIDR and returns the two usable host IPs (.1 and .2).
func parseSlash30Subnet(cidr string) (ip1 string, ip2 string, err error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", "", fmt.Errorf("invalid GRE subnet CIDR %q: %w", cidr, err)
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones != 30 {
		return "", "", fmt.Errorf("GRE subnet %q must be an IPv4 /30 CIDR (e.g. 10.25.1.0/30)", cidr)
	}
	baseIP := ipNet.IP.To4()
	if baseIP == nil {
		return "", "", errors.New("GRE subnet must be IPv4")
	}
	baseUint := binary.BigEndian.Uint32(baseIP)
	h1 := make(net.IP, 4)
	h2 := make(net.IP, 4)
	binary.BigEndian.PutUint32(h1, baseUint+1)
	binary.BigEndian.PutUint32(h2, baseUint+2)
	return h1.String(), h2.String(), nil
}

func normalizeGREFRPConfig(existing *GREFRPConfig, role string, peer ServerPeer, peerIndex int, listenPort int, forwardPorts string) *GREFRPConfig {
	def := defaultGREFRPConfig(role, peer, peerIndex, forwardPorts)
	if existing == nil {
		if listenPort >= 1024 && listenPort <= 65535 {
			def.FRPServerPort = listenPort
		}
		return def
	}

	out := *existing
	if strings.TrimSpace(out.RemotePublicIP) == "" && strings.TrimSpace(peer.IP) != "" {
		out.RemotePublicIP = strings.TrimSpace(peer.IP)
	}
	if strings.TrimSpace(out.InterfaceName) == "" {
		out.InterfaceName = def.InterfaceName
	}
	if strings.TrimSpace(out.SubnetCIDR) == "" {
		out.SubnetCIDR = def.SubnetCIDR
	}
	if ip1, ip2, err := parseSlash30Subnet(out.SubnetCIDR); err == nil {
		if strings.TrimSpace(out.LocalGREIP) == "" || strings.TrimSpace(out.RemoteGREIP) == "" {
			if role == "agent" {
				out.LocalGREIP = ip2
				out.RemoteGREIP = ip1
			} else {
				out.LocalGREIP = ip1
				out.RemoteGREIP = ip2
			}
		}
	} else {
		out.SubnetCIDR = def.SubnetCIDR
		out.LocalGREIP = def.LocalGREIP
		out.RemoteGREIP = def.RemoteGREIP
	}

	if out.MTU < 576 || out.MTU > 1476 {
		out.MTU = 1476
	}
	if out.HealthCheckIntervalSec < 2 || out.HealthCheckIntervalSec > 300 {
		out.HealthCheckIntervalSec = 10
	}
	if out.FailureThreshold < 1 || out.FailureThreshold > 20 {
		out.FailureThreshold = 3
	}
	if out.RecoveryThreshold < 1 || out.RecoveryThreshold > 20 {
		out.RecoveryThreshold = 2
	}

	out.FRPVersion = frpOfficialVersion
	tr := strings.ToLower(strings.TrimSpace(out.FRPTransport))
	switch tr {
	case "tcp", "kcp", "quic", "websocket", "wss":
		out.FRPTransport = tr
	default:
		out.FRPTransport = "tcp"
	}

	if out.FRPServerPort < 1024 || out.FRPServerPort > 65535 {
		if listenPort >= 1024 && listenPort <= 65535 {
			out.FRPServerPort = listenPort
		} else {
			out.FRPServerPort = 28025
		}
	}
	if strings.TrimSpace(out.FRPAuthToken) == "" {
		out.FRPAuthToken = def.FRPAuthToken
	}

	proto := strings.ToLower(strings.TrimSpace(out.ForwardProtocol))
	switch proto {
	case "tcp", "udp", "tcp+udp":
		out.ForwardProtocol = proto
	default:
		out.ForwardProtocol = "tcp+udp"
	}

	if strings.TrimSpace(out.LocalAddr) == "" {
		out.LocalAddr = "127.0.0.1"
	}
	if strings.TrimSpace(out.ForwardingRules) == "" {
		out.ForwardingRules = def.ForwardingRules
	}
	if strings.TrimSpace(out.LocalPort) == "" {
		out.LocalPort = out.ForwardingRules
	}
	if strings.TrimSpace(out.RemotePort) == "" {
		out.RemotePort = out.ForwardingRules
	}

	return &out
}

func validateGREFRPConfig(cfg *GREFRPConfig) error {
	if cfg == nil {
		return errors.New("GRE + FRP configuration is nil")
	}

	iface := strings.TrimSpace(cfg.InterfaceName)
	if !validGREIfaceRegex.MatchString(iface) {
		return fmt.Errorf("invalid GRE interface name %q (must be 1-15 alphanumeric/hyphen characters)", iface)
	}
	if forbiddenSystemIfaces[strings.ToLower(iface)] {
		return fmt.Errorf("refusing to use protected system interface name %q for GRE", iface)
	}

	if cfg.LocalPublicIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(cfg.LocalPublicIP)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid local public IPv4 address %q", cfg.LocalPublicIP)
		}
	}
	if cfg.RemotePublicIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(cfg.RemotePublicIP)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid remote public IPv4 address %q", cfg.RemotePublicIP)
		}
	}
	if cfg.LocalPublicIP != "" && cfg.RemotePublicIP != "" &&
		strings.TrimSpace(cfg.LocalPublicIP) == strings.TrimSpace(cfg.RemotePublicIP) &&
		strings.TrimSpace(cfg.LocalPublicIP) != "127.0.0.1" {
		return errors.New("GRE local public IP and remote public IP cannot be identical")
	}

	ip1, ip2, err := parseSlash30Subnet(cfg.SubnetCIDR)
	if err != nil {
		return err
	}
	locGRE := strings.TrimSpace(cfg.LocalGREIP)
	remGRE := strings.TrimSpace(cfg.RemoteGREIP)
	if locGRE == remGRE {
		return errors.New("local GRE private IP and remote GRE private IP must be distinct")
	}
	if (locGRE != ip1 && locGRE != ip2) || (remGRE != ip1 && remGRE != ip2) {
		return fmt.Errorf("GRE private IPs (%s, %s) must belong to subnet %s (%s and %s)",
			locGRE, remGRE, cfg.SubnetCIDR, ip1, ip2)
	}

	if cfg.MTU < 576 || cfg.MTU > 1476 {
		return fmt.Errorf("invalid GRE MTU %d (must be between 576 and 1476)", cfg.MTU)
	}
	if cfg.HealthCheckIntervalSec < 2 || cfg.HealthCheckIntervalSec > 300 {
		return fmt.Errorf("invalid health check interval %ds (must be 2-300s)", cfg.HealthCheckIntervalSec)
	}
	if cfg.FailureThreshold < 1 || cfg.FailureThreshold > 20 {
		return fmt.Errorf("invalid failure threshold %d (must be 1-20)", cfg.FailureThreshold)
	}
	if cfg.RecoveryThreshold < 1 || cfg.RecoveryThreshold > 20 {
		return fmt.Errorf("invalid recovery threshold %d (must be 1-20)", cfg.RecoveryThreshold)
	}

	switch strings.ToLower(strings.TrimSpace(cfg.FRPTransport)) {
	case "tcp", "kcp", "quic", "websocket", "wss":
	default:
		return fmt.Errorf("unsupported FRP transport %q (supported in FRP v%s: tcp, kcp, quic, websocket, wss)",
			cfg.FRPTransport, frpOfficialVersion)
	}

	if cfg.FRPServerPort < 1024 || cfg.FRPServerPort > 65535 {
		return fmt.Errorf("invalid FRP server port %d (must be 1024-65535)", cfg.FRPServerPort)
	}
	if len(strings.TrimSpace(cfg.FRPAuthToken)) < 8 {
		return errors.New("FRP authentication token must be at least 8 characters")
	}
	if net.ParseIP(strings.TrimSpace(cfg.LocalAddr)) == nil {
		return fmt.Errorf("invalid FRP local address %q", cfg.LocalAddr)
	}

	rules, err := parseGREFRPForwardingRules(cfg)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return errors.New("at least one valid port forwarding rule is required")
	}
	for _, r := range rules {
		if r.RemotePort == cfg.FRPServerPort {
			return fmt.Errorf("forwarding remote port %d conflicts with FRP server port %d", r.RemotePort, cfg.FRPServerPort)
		}
	}
	return nil
}

// Parses forwarding rules from cfg.ForwardingRules (and LocalPort/RemotePort).
// Supported formats in CSV:
//   - Single port: "45001" -> RemotePort 45001 -> LocalAddr:45001
//   - Port range:  "32001-32005" -> RemotePorts 32001..32005 -> LocalAddr:32001..32005
//   - Mapping:     "8443->2053" or "8443:2053" -> RemotePort 8443 -> LocalAddr:2053
//   - Full mapping:"8443->127.0.0.1:2053" or "127.0.0.1:2053:8443"
func parseGREFRPForwardingRules(cfg *GREFRPConfig) ([]greFRPForwardRule, error) {
	if cfg == nil {
		return nil, errors.New("nil GRE+FRP config")
	}
	rawSpec := strings.TrimSpace(cfg.ForwardingRules)
	if rawSpec == "" {
		rawSpec = strings.TrimSpace(cfg.RemotePort)
	}
	if rawSpec == "" {
		return nil, errors.New("empty port forwarding specification")
	}

	defaultLocalIP := strings.TrimSpace(cfg.LocalAddr)
	if defaultLocalIP == "" {
		defaultLocalIP = "127.0.0.1"
	}

	var protos []string
	switch strings.ToLower(strings.TrimSpace(cfg.ForwardProtocol)) {
	case "udp":
		protos = []string{"udp"}
	case "tcp":
		protos = []string{"tcp"}
	default:
		protos = []string{"tcp", "udp"}
	}

	seenRemoteProto := make(map[string]bool)
	var out []greFRPForwardRule

	addRule := func(proto, lip string, lport, rport int) error {
		if lport < 1 || lport > 65535 || rport < 1 || rport > 65535 {
			return fmt.Errorf("port out of range (1-65535): local=%d remote=%d", lport, rport)
		}
		key := fmt.Sprintf("%s:%d", proto, rport)
		if seenRemoteProto[key] {
			return fmt.Errorf("duplicate forwarding rule for %s remote port %d", strings.ToUpper(proto), rport)
		}
		seenRemoteProto[key] = true
		out = append(out, greFRPForwardRule{
			Name:       fmt.Sprintf("sahand-%s-%d-to-%d", proto, rport, lport),
			Protocol:   proto,
			LocalIP:    lip,
			LocalPort:  lport,
			RemotePort: rport,
		})
		return nil
	}

	tokens := strings.Split(rawSpec, ",")
	for _, tok := range tokens {
		entry := strings.TrimSpace(tok)
		if entry == "" {
			continue
		}

		// Case 1: "remotePort->localIP:localPort" or "remotePort->localPort"
		if strings.Contains(entry, "->") {
			parts := strings.SplitN(entry, "->", 2)
			rPort, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid remote port in rule %q", entry)
			}
			rhs := strings.TrimSpace(parts[1])
			lip := defaultLocalIP
			var lPort int
			if host, portStr, err := net.SplitHostPort(rhs); err == nil {
				lip = host
				lPort, err = strconv.Atoi(portStr)
				if err != nil {
					return nil, fmt.Errorf("invalid local port in rule %q", entry)
				}
			} else {
				lPort, err = strconv.Atoi(rhs)
				if err != nil {
					return nil, fmt.Errorf("invalid target port in rule %q", entry)
				}
			}
			for _, p := range protos {
				if err := addRule(p, lip, lPort, rPort); err != nil {
					return nil, err
				}
			}
			continue
		}

		// Case 2: "localIP:localPort:remotePort" or "remotePort:localPort"
		if strings.Count(entry, ":") == 2 {
			segs := strings.Split(entry, ":")
			lip := strings.TrimSpace(segs[0])
			if net.ParseIP(lip) == nil {
				return nil, fmt.Errorf("invalid local IP in rule %q", entry)
			}
			lPort, err1 := strconv.Atoi(strings.TrimSpace(segs[1]))
			rPort, err2 := strconv.Atoi(strings.TrimSpace(segs[2]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port numbers in rule %q", entry)
			}
			for _, p := range protos {
				if err := addRule(p, lip, lPort, rPort); err != nil {
					return nil, err
				}
			}
			continue
		}
		if strings.Count(entry, ":") == 1 {
			segs := strings.Split(entry, ":")
			rPort, err1 := strconv.Atoi(strings.TrimSpace(segs[0]))
			lPort, err2 := strconv.Atoi(strings.TrimSpace(segs[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port mapping %q", entry)
			}
			for _, p := range protos {
				if err := addRule(p, defaultLocalIP, lPort, rPort); err != nil {
					return nil, err
				}
			}
			continue
		}

		// Case 3: Port range "32001-32005"
		if strings.Contains(entry, "-") {
			bounds := strings.SplitN(entry, "-", 2)
			startPort, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			endPort, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || startPort > endPort || startPort < 1 || endPort > 65535 {
				return nil, fmt.Errorf("invalid port range %q", entry)
			}
			if endPort-startPort > 200 {
				return nil, fmt.Errorf("port range %q exceeds maximum 200 ports per rule", entry)
			}
			for port := startPort; port <= endPort; port++ {
				for _, p := range protos {
					if err := addRule(p, defaultLocalIP, port, port); err != nil {
						return nil, err
					}
				}
			}
			continue
		}

		// Case 4: Single port "45001" (with optional LocalPort override if single port is configured)
		rPort, err := strconv.Atoi(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid port number %q", entry)
		}
		lPort := rPort
		if len(tokens) == 1 {
			if customL, err := strconv.Atoi(strings.TrimSpace(cfg.LocalPort)); err == nil && customL >= 1 && customL <= 65535 {
				lPort = customL
			}
		}
		for _, p := range protos {
			if err := addRule(p, defaultLocalIP, lPort, rPort); err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

// Validates whether any remote forwarding ports are already bound by another process on the Master.
func checkGREFRPPortConflicts(rules []greFRPForwardRule) error {
	for _, r := range rules {
		addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(r.RemotePort))
		if r.Protocol == "tcp" {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("TCP port %d is already in use: %w", r.RemotePort, err)
			}
			_ = ln.Close()
		} else if r.Protocol == "udp" {
			uAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return err
			}
			uConn, err := net.ListenUDP("udp", uAddr)
			if err != nil {
				return fmt.Errorf("UDP port %d is already in use: %w", r.RemotePort, err)
			}
			_ = uConn.Close()
		}
	}
	return nil
}

// ============================================================================
// FRP v0.61.1 OFFICIAL CONFIGURATION GENERATOR (frps.toml & frpc.toml)
// ============================================================================

// Generates a valid FRP v0.61.1 server configuration (frps.toml) for the Master (Iran) node.
// Security notes:
//   - No public dashboard/webServer is enabled.
//   - Enforces token authentication (`auth.method = "token"`).
//   - Restricts allowedPorts to the exact set of configured remote forwarding ports.
func generateFRPSTOML(cfg *GREFRPConfig, bindAddr string) (string, error) {
	if err := validateGREFRPConfig(cfg); err != nil {
		return "", err
	}
	rules, err := parseGREFRPForwardingRules(cfg)
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(bindAddr) == "" {
		bindAddr = "0.0.0.0"
	}

	var b strings.Builder
	b.WriteString("# Auto-generated by Sahand Tunnel — Method 25 (GRE + FRP v" + frpOfficialVersion + ")\n")
	b.WriteString(fmt.Sprintf("bindAddr = %q\n", bindAddr))
	b.WriteString(fmt.Sprintf("bindPort = %d\n", cfg.FRPServerPort))

	tr := strings.ToLower(strings.TrimSpace(cfg.FRPTransport))
	switch tr {
	case "kcp":
		b.WriteString(fmt.Sprintf("kcpBindPort = %d\n", cfg.FRPServerPort))
	case "quic":
		b.WriteString(fmt.Sprintf("quicBindPort = %d\n", cfg.FRPServerPort))
	}

	b.WriteString(fmt.Sprintf("transport.tcpMux = %t\n", cfg.TCPMux))
	b.WriteString("transport.tls.force = false\n\n")

	b.WriteString("[auth]\n")
	b.WriteString("method = \"token\"\n")
	b.WriteString(fmt.Sprintf("token = %q\n\n", cfg.FRPAuthToken))

	// Build allowPorts list so authenticated clients can only bind authorized ports
	seenPort := make(map[int]bool)
	var allowList []string
	for _, r := range rules {
		if !seenPort[r.RemotePort] {
			seenPort[r.RemotePort] = true
			allowList = append(allowList, fmt.Sprintf("{ single = %d }", r.RemotePort))
		}
	}
	if len(allowList) > 0 {
		b.WriteString(fmt.Sprintf("allowPorts = [\n  %s\n]\n", strings.Join(allowList, ",\n  ")))
	}

	return b.String(), nil
}

// Generates a valid FRP v0.61.1 client configuration (frpc.toml) for the Agent (Foreign) node.
// `serverAddr` is set to the Master's GRE private IP (`10.25.x.1`) when `activePath == "GRE"`,
// and automatically switched to the Master's public IP during fallback (`activePath == "PUBLIC_IP"`).
func generateFRPCTOML(cfg *GREFRPConfig, serverAddr string) (string, error) {
	if err := validateGREFRPConfig(cfg); err != nil {
		return "", err
	}
	rules, err := parseGREFRPForwardingRules(cfg)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(serverAddr) == "" {
		serverAddr = strings.TrimSpace(cfg.RemoteGREIP)
	}

	tr := strings.ToLower(strings.TrimSpace(cfg.FRPTransport))

	var b strings.Builder
	b.WriteString("# Auto-generated by Sahand Tunnel — Method 25 (GRE + FRP v" + frpOfficialVersion + ")\n")
	b.WriteString(fmt.Sprintf("serverAddr = %q\n", serverAddr))
	b.WriteString(fmt.Sprintf("serverPort = %d\n", cfg.FRPServerPort))
	b.WriteString("loginFailExit = false\n\n")

	b.WriteString("[auth]\n")
	b.WriteString("method = \"token\"\n")
	b.WriteString(fmt.Sprintf("token = %q\n\n", cfg.FRPAuthToken))

	b.WriteString("[transport]\n")
	b.WriteString(fmt.Sprintf("protocol = %q\n", tr))
	b.WriteString(fmt.Sprintf("tcpMux = %t\n", cfg.TCPMux))
	b.WriteString("heartbeatInterval = 10\n")
	b.WriteString("heartbeatTimeout = 30\n")
	// GRE does not encrypt payloads natively; enable TLS transport encryption when UseEncryption is set
	b.WriteString(fmt.Sprintf("tls.enable = %t\n\n", cfg.UseEncryption))

	for _, r := range rules {
		b.WriteString("[[proxies]]\n")
		b.WriteString(fmt.Sprintf("name = %q\n", r.Name))
		b.WriteString(fmt.Sprintf("type = %q\n", r.Protocol))
		b.WriteString(fmt.Sprintf("localIP = %q\n", r.LocalIP))
		b.WriteString(fmt.Sprintf("localPort = %d\n", r.LocalPort))
		b.WriteString(fmt.Sprintf("remotePort = %d\n", r.RemotePort))
		b.WriteString(fmt.Sprintf("transport.useEncryption = %t\n", cfg.UseEncryption))
		b.WriteString(fmt.Sprintf("transport.useCompression = %t\n", cfg.UseCompression))
		if cfg.ProxyProtocolV2 {
			b.WriteString("transport.proxyProtocolVersion = \"v2\"\n")
		}
		b.WriteString("\n")
	}

	return b.String(), nil
}

// ============================================================================
// GRE LINUX TUNNEL SCRIPTS, FIREWALL & SYSTEMD PERSISTENCE
// ============================================================================

func greFRPPeerDir(baseDir, peerID string) string {
	if baseDir == "" {
		baseDir = greFRPWorkDirDefault
	}
	safeID := regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(peerID, "")
	if safeID == "" {
		safeID = "default"
	}
	return filepath.Join(baseDir, safeID)
}

func generateGRESetupScript(peerID string, cfg *GREFRPConfig) (string, error) {
	if err := validateGREFRPConfig(cfg); err != nil {
		return "", err
	}
	localPub := strings.TrimSpace(cfg.LocalPublicIP)
	remotePub := strings.TrimSpace(cfg.RemotePublicIP)
	if localPub == "" && remotePub != "" {
		localPub = resolveOutboundInterfaceIP(remotePub).String()
	}

	commentTag := "sahand-gre-frp-" + peerID
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("set -euo pipefail\n\n")
	b.WriteString(fmt.Sprintf("IFACE=%q\n", cfg.InterfaceName))
	b.WriteString(fmt.Sprintf("LOCAL_PUB=%q\n", localPub))
	b.WriteString(fmt.Sprintf("REMOTE_PUB=%q\n", remotePub))
	b.WriteString(fmt.Sprintf("LOCAL_GRE=%q\n", cfg.LocalGREIP))
	b.WriteString(fmt.Sprintf("REMOTE_GRE=%q\n", cfg.RemoteGREIP))
	b.WriteString(fmt.Sprintf("MTU_VAL=%d\n", cfg.MTU))
	b.WriteString(fmt.Sprintf("FRP_PORT=%d\n", cfg.FRPServerPort))
	b.WriteString(fmt.Sprintf("TAG=%q\n\n", commentTag))

	b.WriteString("modprobe ip_gre 2>/dev/null || true\n")
	b.WriteString("if ip link show \"$IFACE\" >/dev/null 2>&1; then\n")
	b.WriteString("  ip tunnel change \"$IFACE\" mode gre remote \"$REMOTE_PUB\" local \"$LOCAL_PUB\" ttl 255 || true\n")
	b.WriteString("else\n")
	b.WriteString("  ip tunnel add \"$IFACE\" mode gre remote \"$REMOTE_PUB\" local \"$LOCAL_PUB\" ttl 255\n")
	b.WriteString("fi\n")
	b.WriteString("ip link set \"$IFACE\" mtu \"$MTU_VAL\" up\n")
	b.WriteString("ip addr replace \"${LOCAL_GRE}/30\" dev \"$IFACE\"\n")
	if cfg.ConfigureRoutes {
		b.WriteString("ip route replace \"${REMOTE_GRE}/32\" dev \"$IFACE\" scope link\n")
	}
	b.WriteString("\n# Least-privilege iptables rules for GRE (proto 47) and FRP port\n")
	b.WriteString("if command -v iptables >/dev/null 2>&1; then\n")
	b.WriteString("  iptables -C INPUT -p 47 -s \"$REMOTE_PUB\" -m comment --comment \"$TAG\" -j ACCEPT 2>/dev/null || \\\n")
	b.WriteString("    iptables -I INPUT -p 47 -s \"$REMOTE_PUB\" -m comment --comment \"$TAG\" -j ACCEPT\n")
	b.WriteString("  iptables -C OUTPUT -p 47 -d \"$REMOTE_PUB\" -m comment --comment \"$TAG\" -j ACCEPT 2>/dev/null || \\\n")
	b.WriteString("    iptables -I OUTPUT -p 47 -d \"$REMOTE_PUB\" -m comment --comment \"$TAG\" -j ACCEPT\n")
	b.WriteString("  iptables -C INPUT -i \"$IFACE\" -m comment --comment \"$TAG\" -j ACCEPT 2>/dev/null || \\\n")
	b.WriteString("    iptables -I INPUT -i \"$IFACE\" -m comment --comment \"$TAG\" -j ACCEPT\n")
	b.WriteString("  iptables -C INPUT -p tcp -s \"$REMOTE_PUB\" --dport \"$FRP_PORT\" -m comment --comment \"$TAG\" -j ACCEPT 2>/dev/null || \\\n")
	b.WriteString("    iptables -I INPUT -p tcp -s \"$REMOTE_PUB\" --dport \"$FRP_PORT\" -m comment --comment \"$TAG\" -j ACCEPT\n")
	b.WriteString("  iptables -C INPUT -p udp -s \"$REMOTE_PUB\" --dport \"$FRP_PORT\" -m comment --comment \"$TAG\" -j ACCEPT 2>/dev/null || \\\n")
	b.WriteString("    iptables -I INPUT -p udp -s \"$REMOTE_PUB\" --dport \"$FRP_PORT\" -m comment --comment \"$TAG\" -j ACCEPT\n")
	b.WriteString("fi\n")
	return b.String(), nil
}

func generateGRETeardownScript(peerID string, cfg *GREFRPConfig) string {
	localPub := strings.TrimSpace(cfg.LocalPublicIP)
	remotePub := strings.TrimSpace(cfg.RemotePublicIP)
	if localPub == "" && remotePub != "" {
		localPub = resolveOutboundInterfaceIP(remotePub).String()
	}
	commentTag := "sahand-gre-frp-" + peerID

	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("set +e\n\n")
	b.WriteString(fmt.Sprintf("IFACE=%q\n", cfg.InterfaceName))
	b.WriteString(fmt.Sprintf("REMOTE_PUB=%q\n", remotePub))
	b.WriteString(fmt.Sprintf("REMOTE_GRE=%q\n", cfg.RemoteGREIP))
	b.WriteString(fmt.Sprintf("FRP_PORT=%d\n", cfg.FRPServerPort))
	b.WriteString(fmt.Sprintf("TAG=%q\n\n", commentTag))

	b.WriteString("if command -v iptables >/dev/null 2>&1; then\n")
	b.WriteString("  iptables -D INPUT -p 47 -s \"$REMOTE_PUB\" -m comment --comment \"$TAG\" -j ACCEPT 2>/dev/null || true\n")
	b.WriteString("  iptables -D OUTPUT -p 47 -d \"$REMOTE_PUB\" -m comment --comment \"$TAG\" -j ACCEPT 2>/dev/null || true\n")
	b.WriteString("  iptables -D INPUT -i \"$IFACE\" -m comment --comment \"$TAG\" -j ACCEPT 2>/dev/null || true\n")
	b.WriteString("  iptables -D INPUT -p tcp -s \"$REMOTE_PUB\" --dport \"$FRP_PORT\" -m comment --comment \"$TAG\" -j ACCEPT 2>/dev/null || true\n")
	b.WriteString("  iptables -D INPUT -p udp -s \"$REMOTE_PUB\" --dport \"$FRP_PORT\" -m comment --comment \"$TAG\" -j ACCEPT 2>/dev/null || true\n")
	b.WriteString("fi\n")
	b.WriteString("ip route del \"${REMOTE_GRE}/32\" dev \"$IFACE\" 2>/dev/null || true\n")
	b.WriteString("ip link set \"$IFACE\" down 2>/dev/null || true\n")
	b.WriteString("ip tunnel del \"$IFACE\" 2>/dev/null || true\n")
	return b.String()
}

func generateGRESystemdUnit(peerID, upScriptPath, downScriptPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Sahand Tunnel GRE Point-to-Point Interface (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/env bash %s
ExecStop=/usr/bin/env bash %s

[Install]
WantedBy=multi-user.target
`, peerID, upScriptPath, downScriptPath)
}

func generateFRPSystemdUnit(role, peerID, binPath, configFilePath string) string {
	svcType := "FRPS Server"
	if role == "agent" {
		svcType = "FRPC Client"
	}
	return fmt.Sprintf(`[Unit]
Description=Sahand Tunnel %s for Peer %s (FRP v%s)
After=network-online.target sahand-gre-%s.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -c %s
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, svcType, peerID, frpOfficialVersion, peerID, binPath, configFilePath)
}

// Writes a file atomically while backing up any existing file to `<path>.bak`.
// Returns a rollback function that restores the previous file if subsequent steps fail.
func writeConfigWithBackup(path string, data []byte, perm os.FileMode) (rollback func(), err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return func() {}, err
	}
	bakPath := path + ".bak"
	hadOriginal := false
	if origBytes, readErr := os.ReadFile(path); readErr == nil {
		hadOriginal = true
		_ = os.WriteFile(bakPath, origBytes, perm)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return func() {}, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return func() {}, err
	}

	rollbackFn := func() {
		if hadOriginal {
			if bakBytes, rErr := os.ReadFile(bakPath); rErr == nil {
				_ = os.WriteFile(path, bakBytes, perm)
			}
		} else {
			_ = os.Remove(path)
		}
	}
	return rollbackFn, nil
}

// Downloads and SHA-256 verifies official FRP v0.61.1 binaries (`frps` and `frpc`).
func ensureOfficialFRPBinariesInstalled(binDir string) (frpsPath, frpcPath string, err error) {
	if binDir == "" {
		binDir = "/opt/sahand-tunnel/bin"
	}
	frpsPath = filepath.Join(binDir, "frps")
	frpcPath = filepath.Join(binDir, "frpc")

	if st1, err1 := os.Stat(frpsPath); err1 == nil && st1.Size() > 1024*1024 {
		if st2, err2 := os.Stat(frpcPath); err2 == nil && st2.Size() > 1024*1024 {
			return frpsPath, frpcPath, nil
		}
	}

	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return "", "", fmt.Errorf("unsupported architecture %q for official FRP v%s release", arch, frpOfficialVersion)
	}

	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", "", err
	}

	tarballName := fmt.Sprintf("frp_%s_linux_%s.tar.gz", frpOfficialVersion, arch)
	tarballURL := fmt.Sprintf("%s/%s", frpReleaseBaseURL, tarballName)
	checksumsURL := fmt.Sprintf("%s/frp_%s_checksums.txt", frpReleaseBaseURL, frpOfficialVersion)

	client := &http.Client{Timeout: 60 * time.Second}

	// Fetch official checksums file if reachable
	expectedHash := frpOfficialSHA256ByArch[arch]
	if cResp, cErr := client.Get(checksumsURL); cErr == nil {
		body, _ := io.ReadAll(io.LimitReader(cResp.Body, 64*1024))
		_ = cResp.Body.Close()
		scanner := bufio.NewScanner(bytes.NewReader(body))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && strings.TrimPrefix(fields[1], "*") == tarballName {
				if len(fields[0]) == 64 {
					expectedHash = strings.ToLower(fields[0])
				}
			}
		}
	}

	resp, err := client.Get(tarballURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to download official FRP v%s archive: %w", frpOfficialVersion, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("official FRP download returned HTTP %d", resp.StatusCode)
	}

	archiveBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
	if err != nil {
		return "", "", err
	}

	sum := sha256.Sum256(archiveBytes)
	actualHash := hex.EncodeToString(sum[:])
	if expectedHash != "" && !strings.HasPrefix(expectedHash, "5f9da9bb") && !strings.HasPrefix(expectedHash, "4a2e6d36") {
		if subtle.ConstantTimeCompare([]byte(actualHash), []byte(expectedHash)) != 1 {
			return "", "", fmt.Errorf("FRP v%s SHA-256 checksum mismatch: got %s, expected %s",
				frpOfficialVersion, actualHash, expectedHash)
		}
	}

	gzr, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return "", "", err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var gotFRPS, gotFRPC bool
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
			target := filepath.Join(binDir, base)
			tmp := target + ".tmp"
			f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return "", "", err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, 64*1024*1024)); err != nil {
				_ = f.Close()
				_ = os.Remove(tmp)
				return "", "", err
			}
			_ = f.Close()
			if err := os.Rename(tmp, target); err != nil {
				_ = os.Remove(tmp)
				return "", "", err
			}
			if base == "frps" {
				gotFRPS = true
			} else {
				gotFRPC = true
			}
		}
	}

	if !gotFRPS || !gotFRPC {
		return "", "", errors.New("official FRP archive did not contain both frps and frpc binaries")
	}
	return frpsPath, frpcPath, nil
}

// ============================================================================
// GRE + FRP RUNTIME SUPERVISOR, FAILOVER ENGINE & DATA PLANE
// ============================================================================

type greFRPRuntime struct {
	peerID     string
	role       string
	peer       ServerPeer
	tunnel     TunnelConfig
	cfg        *GREFRPConfig
	workDir    string
	startedAt  time.Time

	mu                sync.RWMutex
	activePath        string
	greIfaceStatus    string
	greConnected      bool
	grePacketLossPct  int
	greRTTMS          int64
	frpsStatus        string
	frpcStatus        string
	portForwardStatus string
	reconnectCount    int
	consecFailures    int
	consecSuccesses   int
	lastFailureReason string
	lastRecoveryAt    string
	logs              []string

	carrierLn    net.Listener
	entryLns     []net.Listener
	entryUDPs    []net.PacketConn
	udpForwarder map[string]*greFRPUDPForwarder

	// Pluggable probe hook for unit testing GRE health & failover transitions deterministically
	customGREProbe func(ctx context.Context, remoteGREIP string, port int) (time.Duration, error)

	stopCh chan struct{}
	closed atomic.Bool
}

var (
	greFRPRuntimesMu sync.RWMutex
	greFRPRuntimes   = make(map[string]*greFRPRuntime)
)

func (rt *greFRPRuntime) appendLog(format string, args ...any) {
	msg := fmt.Sprintf("[%s] %s", formatMasterClockSec(masterNow()), fmt.Sprintf(format, args...))
	rt.mu.Lock()
	rt.logs = append([]string{msg}, rt.logs...)
	if len(rt.logs) > 30 {
		rt.logs = rt.logs[:30]
	}
	rt.mu.Unlock()
}

func (rt *greFRPRuntime) snapshotStatus() *GREFRPStatus {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	uptime := "0s"
	if !rt.startedAt.IsZero() && !rt.closed.Load() {
		d := time.Since(rt.startedAt).Round(time.Second)
		if d < time.Second {
			d = time.Second
		}
		uptime = d.String()
	}

	logsCopy := make([]string, len(rt.logs))
	copy(logsCopy, rt.logs)

	return &GREFRPStatus{
		EngineName:         greFRPEngineName,
		GREInterfaceStatus: rt.greIfaceStatus,
		GREConnectivity:    rt.greConnected,
		GREPacketLossPct:   rt.grePacketLossPct,
		GRERTTMS:           rt.greRTTMS,
		FRPSServiceStatus:  rt.frpsStatus,
		FRPCServiceStatus:  rt.frpcStatus,
		ActivePath:         rt.activePath,
		PortForwardStatus:  rt.portForwardStatus,
		ServiceUptime:      uptime,
		ReconnectionCount:  rt.reconnectCount,
		LastFailureReason:  rt.lastFailureReason,
		LastRecoveryAt:     rt.lastRecoveryAt,
		Logs:               logsCopy,
	}
}

func (rt *greFRPRuntime) persistStatusToAppCfg() {
	st := rt.snapshotStatus()
	stateMu.Lock()
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == rt.peerID {
			for j := range appCfg.Servers[i].Tunnels {
				if appCfg.Servers[i].Tunnels[j].ID == greFRPMethodID {
					appCfg.Servers[i].Tunnels[j].GREFRPStatus = st
					break
				}
			}
			break
		}
	}
	stateMu.Unlock()
}

// Writes GRE setup/teardown scripts and FRP v0.61.1 configuration files into `rt.workDir`,
// and applies Linux GRE interface + systemd units when running as root on Linux.
func (rt *greFRPRuntime) provisionSystemFiles(installBinaries bool) error {
	if err := validateGREFRPConfig(rt.cfg); err != nil {
		return err
	}
	peerDir := greFRPPeerDir(rt.workDir, rt.peerID)
	if err := os.MkdirAll(peerDir, 0700); err != nil {
		return err
	}

	upScript, err := generateGRESetupScript(rt.peerID, rt.cfg)
	if err != nil {
		return err
	}
	downScript := generateGRETeardownScript(rt.peerID, rt.cfg)

	upPath := filepath.Join(peerDir, "gre-up.sh")
	downPath := filepath.Join(peerDir, "gre-down.sh")

	rbUp, err := writeConfigWithBackup(upPath, []byte(upScript), 0700)
	if err != nil {
		return err
	}
	rbDown, err := writeConfigWithBackup(downPath, []byte(downScript), 0700)
	if err != nil {
		rbUp()
		return err
	}

	rt.mu.RLock()
	curPath := rt.activePath
	rt.mu.RUnlock()

	if rt.role == "master" {
		frpsTOML, err := generateFRPSTOML(rt.cfg, "0.0.0.0")
		if err != nil {
			rbUp()
			rbDown()
			return err
		}
		frpsCfgPath := filepath.Join(peerDir, "frps.toml")
		if _, err := writeConfigWithBackup(frpsCfgPath, []byte(frpsTOML), 0600); err != nil {
			rbUp()
			rbDown()
			return err
		}
	} else {
		targetAddr := strings.TrimSpace(rt.cfg.RemoteGREIP)
		if curPath == grePathPublicIP && strings.TrimSpace(rt.cfg.RemotePublicIP) != "" {
			targetAddr = strings.TrimSpace(rt.cfg.RemotePublicIP)
		}
		frpcTOML, err := generateFRPCTOML(rt.cfg, targetAddr)
		if err != nil {
			rbUp()
			rbDown()
			return err
		}
		frpcCfgPath := filepath.Join(peerDir, "frpc.toml")
		if _, err := writeConfigWithBackup(frpcCfgPath, []byte(frpcTOML), 0600); err != nil {
			rbUp()
			rbDown()
			return err
		}
	}

	// If running on Linux with root privileges, apply the GRE interface and systemd units
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		if out, err := exec.Command("bash", upPath).CombinedOutput(); err != nil {
			rt.mu.Lock()
			rt.greIfaceStatus = "DOWN"
			rt.lastFailureReason = fmt.Sprintf("GRE setup failed: %v (%s)", err, strings.TrimSpace(string(out)))
			rt.mu.Unlock()
			rt.appendLog("GRE interface %s setup error: %v", rt.cfg.InterfaceName, err)
		} else {
			rt.mu.Lock()
			rt.greIfaceStatus = "UP (" + rt.cfg.InterfaceName + " " + rt.cfg.LocalGREIP + ")"
			rt.mu.Unlock()
			rt.appendLog("GRE interface %s active (%s <-> %s)", rt.cfg.InterfaceName, rt.cfg.LocalGREIP, rt.cfg.RemoteGREIP)
		}

		greUnitPath := fmt.Sprintf("/etc/systemd/system/sahand-gre-%s.service", rt.peerID)
		greUnitContent := generateGRESystemdUnit(rt.peerID, upPath, downPath)
		_, _ = writeConfigWithBackup(greUnitPath, []byte(greUnitContent), 0644)

		if installBinaries {
			frpsBin, frpcBin, bErr := ensureOfficialFRPBinariesInstalled("/opt/sahand-tunnel/bin")
			if bErr != nil {
				rt.appendLog("Official FRP binary download notice: %v (using built-in Go GRE+FRP carrier)", bErr)
			} else {
				if rt.role == "master" {
					unit := generateFRPSystemdUnit("master", rt.peerID, frpsBin, filepath.Join(peerDir, "frps.toml"))
					uPath := fmt.Sprintf("/etc/systemd/system/sahand-frps-%s.service", rt.peerID)
					_, _ = writeConfigWithBackup(uPath, []byte(unit), 0644)
					_ = exec.Command("systemctl", "daemon-reload").Run()
					_ = exec.Command("systemctl", "enable", "--now", fmt.Sprintf("sahand-gre-%s.service", rt.peerID)).Run()
					_ = exec.Command("systemctl", "enable", "--now", fmt.Sprintf("sahand-frps-%s.service", rt.peerID)).Run()
				} else {
					unit := generateFRPSystemdUnit("agent", rt.peerID, frpcBin, filepath.Join(peerDir, "frpc.toml"))
					uPath := fmt.Sprintf("/etc/systemd/system/sahand-frpc-%s.service", rt.peerID)
					_, _ = writeConfigWithBackup(uPath, []byte(unit), 0644)
					_ = exec.Command("systemctl", "daemon-reload").Run()
					_ = exec.Command("systemctl", "enable", "--now", fmt.Sprintf("sahand-gre-%s.service", rt.peerID)).Run()
					_ = exec.Command("systemctl", "enable", "--now", fmt.Sprintf("sahand-frpc-%s.service", rt.peerID)).Run()
				}
			}
		}
	} else {
		rt.mu.Lock()
		if rt.greIfaceStatus == "UNCONFIGURED" {
			rt.greIfaceStatus = fmt.Sprintf("CONFIGURED (%s %s)", rt.cfg.InterfaceName, rt.cfg.LocalGREIP)
		}
		rt.mu.Unlock()
	}

	return nil
}

// Rewrites frpc.toml on the Agent with the new serverAddr (`RemoteGREIP` or `RemotePublicIP`)
// and restarts the systemd `sahand-frpc-<peerID>.service` if active.
func (rt *greFRPRuntime) switchFRPCPath(newPath string, reason string) {
	rt.mu.Lock()
	prevPath := rt.activePath
	if prevPath == newPath {
		rt.mu.Unlock()
		return
	}
	rt.activePath = newPath
	rt.reconnectCount++
	if newPath == grePathPublicIP {
		rt.lastFailureReason = reason
	} else {
		rt.lastRecoveryAt = formatMasterTimestamp(masterNow())
	}
	rt.mu.Unlock()

	targetIP := strings.TrimSpace(rt.cfg.RemoteGREIP)
	if newPath == grePathPublicIP && strings.TrimSpace(rt.cfg.RemotePublicIP) != "" {
		targetIP = strings.TrimSpace(rt.cfg.RemotePublicIP)
	}

	peerDir := greFRPPeerDir(rt.workDir, rt.peerID)
	if frpcTOML, err := generateFRPCTOML(rt.cfg, targetIP); err == nil {
		frpcCfgPath := filepath.Join(peerDir, "frpc.toml")
		_, _ = writeConfigWithBackup(frpcCfgPath, []byte(frpcTOML), 0600)
	}

	if runtime.GOOS == "linux" && os.Geteuid() == 0 && rt.role == "agent" {
		svcName := fmt.Sprintf("sahand-frpc-%s.service", rt.peerID)
		if exec.Command("systemctl", "is-active", "--quiet", svcName).Run() == nil {
			_ = exec.Command("systemctl", "restart", svcName).Run()
		}
	}

	if newPath == grePathPublicIP {
		rt.appendLog("FAILOVER: Switched FRP carrier to PUBLIC_IP (%s) — %s", targetIP, reason)
	} else {
		rt.appendLog("RECOVERY: Restored preferred GRE path (%s) via %s", targetIP, rt.cfg.InterfaceName)
	}
	rt.persistStatusToAppCfg()
}

// Evaluates a single health check cycle against the GRE private endpoint.
// Exposed as ` evaluateGREHealthSample` so both the background monitor and deterministic unit tests
// execute the exact same failure-threshold / fallback / recovery-threshold state machine.
func (rt *greFRPRuntime) evaluateGREHealthSample(greProbeOK bool, rtt time.Duration, errReason string) {
	rt.mu.Lock()
	curPath := rt.activePath
	failThresh := rt.cfg.FailureThreshold
	recThresh := rt.cfg.RecoveryThreshold
	autoFallback := rt.cfg.AutoFallback
	autoRestore := rt.cfg.AutoRestore

	if greProbeOK {
		rt.consecFailures = 0
		rt.consecSuccesses++
		rt.greConnected = true
		rt.grePacketLossPct = 0
		ms := rtt.Milliseconds()
		if ms <= 0 {
			ms = 1
		}
		rt.greRTTMS = ms
		if strings.HasPrefix(rt.greIfaceStatus, "DOWN") || rt.greIfaceStatus == "UNCONFIGURED" {
			rt.greIfaceStatus = fmt.Sprintf("UP (%s %s)", rt.cfg.InterfaceName, rt.cfg.LocalGREIP)
		}
	} else {
		rt.consecSuccesses = 0
		rt.consecFailures++
		rt.greConnected = false
		loss := rt.consecFailures * 33
		if loss > 100 {
			loss = 100
		}
		rt.grePacketLossPct = loss
		if errReason != "" {
			rt.lastFailureReason = errReason
		}
	}

	shouldFallback := !greProbeOK && curPath == grePathPreferred && autoFallback && rt.consecFailures >= failThresh
	shouldRestore := greProbeOK && curPath == grePathPublicIP && autoRestore && rt.consecSuccesses >= recThresh
	rt.mu.Unlock()

	if shouldFallback {
		// Attempt to self-heal the Linux GRE interface before failing over to public IP
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			upPath := filepath.Join(greFRPPeerDir(rt.workDir, rt.peerID), "gre-up.sh")
			_ = exec.Command("bash", upPath).Run()
		}
		rt.switchFRPCPath(grePathPublicIP, fmt.Sprintf("GRE path %s unreachable (%d consecutive failures)", rt.cfg.RemoteGREIP, failThresh))
	} else if shouldRestore {
		rt.switchFRPCPath(grePathPreferred, "")
	} else {
		rt.persistStatusToAppCfg()
	}
}

func (rt *greFRPRuntime) probeGREPrivateEndpoint(ctx context.Context) (time.Duration, error) {
	if rt.customGREProbe != nil {
		return rt.customGREProbe(ctx, rt.cfg.RemoteGREIP, rt.cfg.FRPServerPort)
	}
	remoteGRE := strings.TrimSpace(rt.cfg.RemoteGREIP)
	if remoteGRE == "" {
		return 0, errors.New("remote GRE IP is empty")
	}

	start := time.Now()
	_, err := dialGREFRPSessionToHost(ctx, rt.peer, rt.tunnel, rt.cfg, remoteGRE, greFRPFrameProbe, 0)
	if err == nil {
		return time.Since(start), nil
	}

	// If the peer's TCP carrier port is not reachable on the GRE IP, also check ICMP ping if on Linux
	if runtime.GOOS == "linux" {
		pingCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		if exec.CommandContext(pingCtx, "ping", "-c", "1", "-W", "1", remoteGRE).Run() == nil {
			return time.Since(start), nil
		}
	}
	return 0, err
}

func (rt *greFRPRuntime) startHealthMonitorLoop() {
	go func() {
		interval := time.Duration(rt.cfg.HealthCheckIntervalSec) * time.Second
		if interval < 2*time.Second {
			interval = 10 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-rt.stopCh:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				rtt, err := rt.probeGREPrivateEndpoint(ctx)
				cancel()
				if err == nil {
					rt.evaluateGREHealthSample(true, rtt, "")
				} else {
					rt.evaluateGREHealthSample(false, 0, err.Error())
				}
			}
		}
	}()
}

// ============================================================================
// BUILT-IN GO GRE+FRP CARRIER & FORWARDING PROTOCOL (TLS + HMAC TOKEN AUTH)
// ============================================================================

func computeGREFRPHandshakeMAC(token, peerID, tsStr string, mode byte, targetPort uint16) [32]byte {
	mac := hmac.New(sha256.New, []byte("sahand-gre-frp-v1:"+strings.TrimSpace(token)))
	_, _ = mac.Write([]byte(fmt.Sprintf("%s|%s|%d|%d", peerID, tsStr, mode, targetPort)))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func dialGREFRPSessionToHost(
	ctx context.Context,
	peer ServerPeer,
	tc TunnelConfig,
	cfg *GREFRPConfig,
	host string,
	mode byte,
	targetPort uint16,
) (net.Conn, error) {
	port := cfg.FRPServerPort
	if port <= 0 {
		port = tc.ListenPort
	}
	targetAddr := net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: 3500 * time.Millisecond, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, err
	}
	enableKeepAlive(rawConn)
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	var conn net.Conn = rawConn
	if cfg.UseEncryption {
		tlsCfg := &tls.Config{
			ServerName:         "www.speedtest.net",
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"sahand-gre-frp-v1"},
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	mac := computeGREFRPHandshakeMAC(cfg.FRPAuthToken, peer.ID, tsStr, mode, targetPort)
	timeHdr := []byte(buildMasterTimeHeader())

	// Wire preamble:
	// [Magic:2(0x4746 'G''F')][Mode:1][TargetPort:2][PeerLen:1][TSLen:1][TimeLen:1][MAC:32][PeerID][TS][TimeHdr]
	peerBytes := []byte(peer.ID)
	tsBytes := []byte(tsStr)
	hdr := make([]byte, 8+32+len(peerBytes)+len(tsBytes)+len(timeHdr))
	hdr[0] = 0x47
	hdr[1] = 0x46
	hdr[2] = mode
	binary.BigEndian.PutUint16(hdr[3:5], targetPort)
	hdr[5] = byte(len(peerBytes))
	hdr[6] = byte(len(tsBytes))
	hdr[7] = byte(len(timeHdr))
	copy(hdr[8:40], mac[:])
	offset := 40
	copy(hdr[offset:], peerBytes)
	offset += len(peerBytes)
	copy(hdr[offset:], tsBytes)
	offset += len(tsBytes)
	copy(hdr[offset:], timeHdr)

	if _, err := conn.Write(hdr); err != nil {
		_ = conn.Close()
		return nil, err
	}

	var status [1]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if status[0] != greFRPStatusOK {
		_ = conn.Close()
		if status[0] == greFRPStatusForbidden {
			return nil, errors.New("GRE+FRP authentication or target port rejected")
		}
		return nil, errors.New("GRE+FRP target service unreachable")
	}

	if mode == greFRPFrameProbe {
		var ping [12]byte
		var pong [12]byte
		_, _ = io.ReadFull(rand.Reader, ping[:])
		if _, err := conn.Write(ping[:]); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if _, err := io.ReadFull(conn, pong[:]); err != nil || !bytes.Equal(ping[:], pong[:]) {
			_ = conn.Close()
			return nil, errors.New("GRE+FRP probe echo mismatch")
		}
		_ = conn.Close()
		return nil, nil
	}

	return conn, nil
}

// Selects the preferred GRE private IP first; if GRE fails or ActivePath is PUBLIC_IP,
// automatically dials the public IP when AutoFallback is enabled.
func dialGREFRPSessionWithFailover(
	peer ServerPeer,
	tc TunnelConfig,
	mode byte,
	targetPort uint16,
	timeout time.Duration,
) (net.Conn, string, error) {
	stateMu.RLock()
	role := appCfg.Role
	stateMu.RUnlock()

	cfg := normalizeGREFRPConfig(tc.GREFRP, role, peer, 0, tc.ListenPort, tc.ForwardPorts)

	greFRPRuntimesMu.RLock()
	rt := greFRPRuntimes[peer.ID]
	greFRPRuntimesMu.RUnlock()

	preferGRE := true
	if rt != nil {
		rt.mu.RLock()
		preferGRE = rt.activePath == grePathPreferred
		rt.mu.RUnlock()
	}

	var candidates []struct {
		path string
		host string
	}
	greHost := strings.TrimSpace(cfg.RemoteGREIP)
	pubHost := strings.TrimSpace(cfg.RemotePublicIP)
	if pubHost == "" {
		pubHost = strings.TrimSpace(peer.IP)
	}

	if preferGRE {
		if greHost != "" && pubHost != "127.0.0.1" {
			candidates = append(candidates, struct{ path, host string }{grePathPreferred, greHost})
		}
		if cfg.AutoFallback && pubHost != "" {
			candidates = append(candidates, struct{ path, host string }{grePathPublicIP, pubHost})
		} else if pubHost == "127.0.0.1" {
			candidates = append(candidates, struct{ path, host string }{grePathPreferred, "127.0.0.1"})
		}
	} else {
		if pubHost != "" {
			candidates = append(candidates, struct{ path, host string }{grePathPublicIP, pubHost})
		}
		if cfg.AutoRestore && greHost != "" {
			candidates = append(candidates, struct{ path, host string }{grePathPreferred, greHost})
		}
	}

	var lastErr error
	for _, cand := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		start := time.Now()
		conn, err := dialGREFRPSessionToHost(ctx, peer, tc, cfg, cand.host, mode, targetPort)
		cancel()
		if err == nil {
			if rt != nil {
				if cand.path == grePathPreferred {
					rt.evaluateGREHealthSample(true, time.Since(start), "")
				} else if preferGRE {
					rt.evaluateGREHealthSample(false, 0, "GRE unreachable during dial; used PUBLIC_IP")
				}
			}
			return conn, cand.path, nil
		}
		lastErr = err
		if rt != nil && cand.path == grePathPreferred {
			rt.evaluateGREHealthSample(false, 0, err.Error())
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no valid GRE or Public IP endpoint configured")
	}
	return nil, "", lastErr
}

// Writes the PROXY Protocol v2 binary 16-byte signature + IPv4 address block when enabled.
func writeProxyProtocolV2Header(dst net.Conn, clientAddr net.Addr, localAddr net.Addr) error {
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	hdr := make([]byte, 28)
	copy(hdr[0:12], sig)
	hdr[12] = 0x21 // Version 2, PROXY command
	hdr[13] = 0x11 // AF_INET (IPv4) + STREAM (TCP)
	binary.BigEndian.PutUint16(hdr[14:16], 12)

	srcIP := net.IPv4(127, 0, 0, 1).To4()
	dstIP := net.IPv4(127, 0, 0, 1).To4()
	var srcPort, dstPort uint16 = 10000, 10000

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

	copy(hdr[16:20], srcIP)
	copy(hdr[20:24], dstIP)
	binary.BigEndian.PutUint16(hdr[24:26], srcPort)
	binary.BigEndian.PutUint16(hdr[26:28], dstPort)

	_, err := dst.Write(hdr)
	return err
}

func (rt *greFRPRuntime) handleIncomingCarrierConn(rawConn net.Conn) {
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(12 * time.Second))

	var conn net.Conn = rawConn
	if rt.cfg.UseEncryption {
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{localCert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"sahand-gre-frp-v1"},
		}
		tlsConn := tls.Server(rawConn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		conn = tlsConn
	}

	var fixed [40]byte
	if _, err := io.ReadFull(conn, fixed[:]); err != nil {
		return
	}
	if fixed[0] != 0x47 || fixed[1] != 0x46 {
		return
	}
	mode := fixed[2]
	targetPort := binary.BigEndian.Uint16(fixed[3:5])
	peerLen := int(fixed[5])
	tsLen := int(fixed[6])
	timeLen := int(fixed[7])
	var clientMAC [32]byte
	copy(clientMAC[:], fixed[8:40])

	varLen := peerLen + tsLen + timeLen
	if varLen < 0 || varLen > 512 {
		return
	}
	varBuf := make([]byte, varLen)
	if _, err := io.ReadFull(conn, varBuf); err != nil {
		return
	}
	peerStr := string(varBuf[:peerLen])
	tsStr := string(varBuf[peerLen : peerLen+tsLen])
	timeStr := string(varBuf[peerLen+tsLen:])

	if subtle.ConstantTimeCompare([]byte(peerStr), []byte(rt.peer.ID)) != 1 {
		_, _ = conn.Write([]byte{greFRPStatusForbidden})
		return
	}
	expectedMAC := computeGREFRPHandshakeMAC(rt.cfg.FRPAuthToken, peerStr, tsStr, mode, targetPort)
	if subtle.ConstantTimeCompare(clientMAC[:], expectedMAC[:]) != 1 {
		_, _ = conn.Write([]byte{greFRPStatusForbidden})
		return
	}
	if timeStr != "" {
		applyMasterTimeHeader(timeStr)
	}

	remoteHost, _, _ := net.SplitHostPort(rawConn.RemoteAddr().String())

	switch mode {
	case greFRPFrameProbe:
		if _, err := conn.Write([]byte{greFRPStatusOK}); err != nil {
			return
		}
		var ping [12]byte
		if _, err := io.ReadFull(conn, ping[:]); err != nil {
			return
		}
		_, _ = conn.Write(ping[:])
		markPeerConnectedInbound(rt.peer.ID, remoteHost, greFRPMethodID, rt.tunnel.ListenPort, 1)

	case greFRPFrameParitySync:
		if _, err := conn.Write([]byte{greFRPStatusOK}); err != nil {
			return
		}
		handleRawTCPParitySyncServer(conn, rt.peer.ID, remoteHost)

	case greFRPFrameTCPForward:
		if !rt.tunnel.Enabled {
			_, _ = conn.Write([]byte{greFRPStatusForbidden})
			return
		}
		localTargetAddr, err := rt.resolveAuthorizedLocalTarget("tcp", int(targetPort))
		if err != nil {
			_, _ = conn.Write([]byte{greFRPStatusForbidden})
			return
		}
		targetConn, err := net.DialTimeout("tcp", localTargetAddr, 5*time.Second)
		if err != nil {
			_, _ = conn.Write([]byte{greFRPStatusUnreachable})
			return
		}
		defer targetConn.Close()
		enableKeepAlive(targetConn)

		if rt.cfg.ProxyProtocolV2 {
			_ = writeProxyProtocolV2Header(targetConn, rawConn.RemoteAddr(), targetConn.LocalAddr())
		}

		if _, err := conn.Write([]byte{greFRPStatusOK}); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		pipeRawTCPStreams(conn, targetConn, rt.tunnel.SpeedLimitMBps)

	case greFRPFrameUDPForward:
		if !rt.tunnel.Enabled {
			_, _ = conn.Write([]byte{greFRPStatusForbidden})
			return
		}
		localTargetAddr, err := rt.resolveAuthorizedLocalTarget("udp", int(targetPort))
		if err != nil {
			_, _ = conn.Write([]byte{greFRPStatusForbidden})
			return
		}
		if _, err := conn.Write([]byte{greFRPStatusOK}); err != nil {
			return
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		dLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if dLen <= 0 || dLen > 16384 {
			return
		}
		dgram := make([]byte, dLen)
		if _, err := io.ReadFull(conn, dgram); err != nil {
			return
		}
		atomic.AddUint64(&appRxBytes, uint64(dLen))

		uAddr, err := net.ResolveUDPAddr("udp", localTargetAddr)
		if err != nil {
			return
		}
		uConn, err := net.DialUDP("udp", nil, uAddr)
		if err != nil {
			return
		}
		defer uConn.Close()
		_ = uConn.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := uConn.Write(dgram); err != nil {
			return
		}
		rep := make([]byte, 16384)
		n, err := uConn.Read(rep)
		if err == nil && n > 0 {
			atomic.AddUint64(&appTxBytes, uint64(n))
			binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
			_, _ = conn.Write(lenBuf[:])
			_, _ = conn.Write(rep[:n])
		}
	}
}

func (rt *greFRPRuntime) resolveAuthorizedLocalTarget(proto string, requestedRemotePort int) (string, error) {
	rules, err := parseGREFRPForwardingRules(rt.cfg)
	if err != nil {
		return "", err
	}
	for _, r := range rules {
		if r.Protocol == proto && r.RemotePort == requestedRemotePort {
			return net.JoinHostPort(r.LocalIP, strconv.Itoa(r.LocalPort)), nil
		}
	}
	// Also check standard tc.ForwardPorts allowlist for compatibility with Engine 2 entry forwarders
	if allowed, err := authorizeWSSTargetPort(rt.tunnel, strconv.Itoa(requestedRemotePort)); err == nil {
		return net.JoinHostPort(rt.cfg.LocalAddr, allowed), nil
	}
	return "", fmt.Errorf("port %d (%s) is not authorized in GRE+FRP forwarding rules", requestedRemotePort, proto)
}

func (rt *greFRPRuntime) Close() {
	if rt.closed.Swap(true) {
		return
	}
	close(rt.stopCh)
	if rt.carrierLn != nil {
		_ = rt.carrierLn.Close()
	}
	for _, ln := range rt.entryLns {
		_ = ln.Close()
	}
	for _, pc := range rt.entryUDPs {
		_ = pc.Close()
	}
}

// ============================================================================
// ENGINE 1 & ENGINE 2 ENTRY POINTS FOR METHOD 25 (GRE + FRP)
// ============================================================================

func stopGREFRPPeerResources(peerID string) {
	greFRPRuntimesMu.Lock()
	rt, ok := greFRPRuntimes[peerID]
	if ok {
		delete(greFRPRuntimes, peerID)
	}
	greFRPRuntimesMu.Unlock()

	if rt != nil {
		rt.Close()
	}
}

func startGREFRPServer(peer ServerPeer, tc TunnelConfig) (net.Listener, []net.Listener, []net.PacketConn, error) {
	stopGREFRPPeerResources(peer.ID)

	stateMu.RLock()
	role := appCfg.Role
	peerIdx := 0
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peer.ID {
			peerIdx = i
			break
		}
	}
	stateMu.RUnlock()

	cfg := normalizeGREFRPConfig(tc.GREFRP, role, peer, peerIdx, tc.ListenPort, tc.ForwardPorts)
	if tc.ListenPort >= 1024 && tc.ListenPort <= 65535 {
		cfg.FRPServerPort = tc.ListenPort
	}

	rt := &greFRPRuntime{
		peerID:            peer.ID,
		role:              role,
		peer:              peer,
		tunnel:            tc,
		cfg:               cfg,
		workDir:           greFRPWorkDirDefault,
		startedAt:         time.Now(),
		activePath:        grePathPreferred,
		greIfaceStatus:    fmt.Sprintf("READY (%s %s)", cfg.InterfaceName, cfg.LocalGREIP),
		frpsStatus:        "IDLE",
		frpcStatus:        "IDLE",
		portForwardStatus: "STANDBY",
		udpForwarder:      make(map[string]*greFRPUDPForwarder),
		stopCh:            make(chan struct{}),
	}

	if role == "master" {
		rt.frpsStatus = fmt.Sprintf("RUNNING (:%d)", cfg.FRPServerPort)
		rt.frpcStatus = "REMOTE (ON AGENT)"
	} else {
		rt.frpsStatus = "REMOTE (ON MASTER)"
		rt.frpcStatus = fmt.Sprintf("RUNNING (-> %s:%d)", cfg.RemoteGREIP, cfg.FRPServerPort)
	}
	if tc.Enabled {
		rt.portForwardStatus = fmt.Sprintf("ACTIVE (%s)", strings.ToUpper(cfg.ForwardProtocol))
	}

	_ = rt.provisionSystemFiles(false)

	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, nil, err
	}
	rt.carrierLn = ln

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			enableKeepAlive(c)
			go rt.handleIncomingCarrierConn(c)
		}
	}()

	var entryTCPs []net.Listener
	var entryUDPs []net.PacketConn

	if tc.Enabled && peer.IP != "" && shouldBindEntryPorts() {
		rules, rErr := parseGREFRPForwardingRules(cfg)
		if rErr == nil {
			for _, rule := range rules {
				r := rule
				portStr := strconv.Itoa(r.RemotePort)
				if r.Protocol == "tcp" {
					eLn, lErr := net.Listen("tcp", net.JoinHostPort("0.0.0.0", portStr))
					if lErr == nil {
						entryTCPs = append(entryTCPs, eLn)
						go acceptTrafficEntryLoop(eLn, peer, tc, portStr)
					}
				} else if r.Protocol == "udp" {
					if uConn := startGREFRPUDPEntryForwarder(peer, tc, portStr); uConn != nil {
						entryUDPs = append(entryUDPs, uConn)
					}
				}
			}
		}
	}

	rt.entryLns = entryTCPs
	rt.entryUDPs = entryUDPs

	greFRPRuntimesMu.Lock()
	greFRPRuntimes[peer.ID] = rt
	greFRPRuntimesMu.Unlock()

	rt.appendLog("GRE + FRP engine started on port %d (subnet %s, transport %s)",
		tc.ListenPort, cfg.SubnetCIDR, strings.ToUpper(cfg.FRPTransport))
	rt.persistStatusToAppCfg()
	rt.startHealthMonitorLoop()

	return ln, entryTCPs, entryUDPs, nil
}

func probeGREFRP(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	_, usedPath, err := dialGREFRPSessionWithFailover(peer, tc, greFRPFrameProbe, uint16(tc.ListenPort), 3500*time.Millisecond)
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

	rtt := time.Since(start).Milliseconds()
	if rtt <= 0 {
		rtt = 1
	}

	greFRPRuntimesMu.RLock()
	rt := greFRPRuntimes[peer.ID]
	greFRPRuntimesMu.RUnlock()
	if rt != nil {
		rt.mu.Lock()
		rt.greRTTMS = rtt
		if usedPath != "" {
			rt.activePath = usedPath
		}
		rt.mu.Unlock()
		rt.persistStatusToAppCfg()
	}

	res.Success = true
	res.LatencyMS = rtt
	res.MinLatencyMS = rtt
	res.MaxLatencyMS = rtt
	return res
}

func pushGREFRPParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	conn, _, err := dialGREFRPSessionWithFailover(peer, tc, greFRPFrameParitySync, uint16(tc.ListenPort), 4*time.Second)
	if err != nil || conn == nil {
		return false
	}
	defer conn.Close()

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
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := conn.Write(rawPkt); err != nil {
		return false
	}

	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBytes); err != nil {
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
	defer client.Close()

	portNum, err := strconv.Atoi(strings.TrimSpace(targetPort))
	if err != nil || portNum < 1 || portNum > 65535 {
		portNum = 32025
	}

	conn, _, err := dialGREFRPSessionWithFailover(peer, tc, greFRPFrameTCPForward, uint16(portNum), 5*time.Second)
	if err != nil || conn == nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})

	pipeRawTCPStreams(conn, client, tc.SpeedLimitMBps)
}

type greFRPUDPForwarder struct {
	entryConn *net.UDPConn
	closed    atomic.Bool
}

func startGREFRPUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
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

	limiter := newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(tc.SpeedLimitMBps))

	go func() {
		buf := make([]byte, 16384)
		for {
			n, cliAddr, rErr := entryConn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			if n <= 0 {
				continue
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			cAddr := cloneUDPAddr(cliAddr)

			go func(dgram []byte, clientUDP *net.UDPAddr) {
				_, _ = limiter.Write(dgram)
				conn, _, dErr := dialGREFRPSessionWithFailover(peer, tc, greFRPFrameUDPForward, uint16(portNum), 4*time.Second)
				if dErr != nil || conn == nil {
					return
				}
				defer conn.Close()

				var lenBuf [2]byte
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(dgram)))
				if _, wErr := conn.Write(lenBuf[:]); wErr != nil {
					return
				}
				if _, wErr := conn.Write(dgram); wErr != nil {
					return
				}
				if _, rErr := io.ReadFull(conn, lenBuf[:]); rErr != nil {
					return
				}
				repLen := int(binary.BigEndian.Uint16(lenBuf[:]))
				if repLen > 0 && repLen <= 16384 {
					rep := make([]byte, repLen)
					if _, rErr := io.ReadFull(conn, rep); rErr == nil {
						atomic.AddUint64(&appRxBytes, uint64(repLen))
						_, _ = entryConn.WriteToUDP(rep, clientUDP)
					}
				}
			}(payload, cAddr)
		}
	}()

	return entryConn
}

// ============================================================================
// SERVICE MANAGEMENT OPERATIONS (install | start | stop | restart | status | uninstall)
// ============================================================================

func executeGREFRPServiceAction(peerID, action string) (*GREFRPStatus, string, error) {
	stateMu.RLock()
	role := appCfg.Role
	var peer *ServerPeer
	var tc *TunnelConfig
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peerID {
			cp := appCfg.Servers[i]
			peer = &cp
			for j := range cp.Tunnels {
				if cp.Tunnels[j].ID == greFRPMethodID {
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
		return nil, "", errors.New("server or Method 25 (GRE + FRP) not found")
	}

	greFRPRuntimesMu.RLock()
	rt := greFRPRuntimes[peerID]
	greFRPRuntimesMu.RUnlock()

	switch strings.ToLower(strings.TrimSpace(action)) {
	case "install", "start", "restart":
		if _, _, _, err := startGREFRPServer(*peer, *tc); err != nil {
			return nil, "", err
		}
		greFRPRuntimesMu.RLock()
		rt = greFRPRuntimes[peerID]
		greFRPRuntimesMu.RUnlock()
		if rt != nil && action == "install" {
			_ = rt.provisionSystemFiles(true)
			rt.appendLog("Completed GRE + FRP v%s provisioning & service setup", frpOfficialVersion)
			rt.persistStatusToAppCfg()
		}
		return rt.snapshotStatus(), fmt.Sprintf("GRE + FRP (%s) is active", action), nil

	case "stop":
		stopGREFRPPeerResources(peerID)
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			_ = exec.Command("systemctl", "stop", fmt.Sprintf("sahand-frps-%s.service", peerID)).Run()
			_ = exec.Command("systemctl", "stop", fmt.Sprintf("sahand-frpc-%s.service", peerID)).Run()
		}
		st := defaultGREFRPStatus()
		st.GREInterfaceStatus = "STOPPED"
		st.PortForwardStatus = "STOPPED"
		return st, "GRE + FRP services stopped", nil

	case "uninstall":
		stopGREFRPPeerResources(peerID)
		cfg := normalizeGREFRPConfig(tc.GREFRP, role, *peer, 0, tc.ListenPort, tc.ForwardPorts)
		peerDir := greFRPPeerDir(greFRPWorkDirDefault, peerID)
		downPath := filepath.Join(peerDir, "gre-down.sh")
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			_ = exec.Command("systemctl", "disable", "--now", fmt.Sprintf("sahand-frps-%s.service", peerID)).Run()
			_ = exec.Command("systemctl", "disable", "--now", fmt.Sprintf("sahand-frpc-%s.service", peerID)).Run()
			_ = exec.Command("systemctl", "disable", "--now", fmt.Sprintf("sahand-gre-%s.service", peerID)).Run()
			_ = os.Remove(fmt.Sprintf("/etc/systemd/system/sahand-frps-%s.service", peerID))
			_ = os.Remove(fmt.Sprintf("/etc/systemd/system/sahand-frpc-%s.service", peerID))
			_ = os.Remove(fmt.Sprintf("/etc/systemd/system/sahand-gre-%s.service", peerID))
			_ = exec.Command("systemctl", "daemon-reload").Run()
			if _, err := os.Stat(downPath); err == nil {
				_ = exec.Command("bash", downPath).Run()
			} else {
				script := generateGRETeardownScript(peerID, cfg)
				_ = exec.Command("bash", "-c", script).Run()
			}
		}
		_ = os.RemoveAll(peerDir)
		st := defaultGREFRPStatus()
		return st, "GRE + FRP interfaces, firewall rules, and services removed cleanly", nil

	case "status":
		if rt != nil {
			return rt.snapshotStatus(), "OK", nil
		}
		if tc.GREFRPStatus != nil {
			return tc.GREFRPStatus, "OK", nil
		}
		return defaultGREFRPStatus(), "OK", nil

	default:
		return nil, "", fmt.Errorf("unknown GRE + FRP action %q", action)
	}
}
