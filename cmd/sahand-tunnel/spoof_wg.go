package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"time"

	"golang.org/x/crypto/curve25519"
)

var (
	spoofDir   = "/etc/spoof"
	wgConfDir  = "/etc/wireguard"
	spoofIface = "wg-spoof"
)

const (
	spoofBinName        = "spoof"
	spoofCoreSvc        = "spoof-core"
	spoofWGUnitTmpl     = "wg-quick@" // wg-quick@wg-spoof
	defaultSpoofPort    = 8090        // public UDP port the remote receives on
	defaultRecvPort     = 5001        // local recv port / remote client_port
	defaultCorePort     = 5000        // local core UDP listen (WireGuard dials this)
	defaultWGListen     = 51820       // foreign WireGuard listen port
	defaultWGMTU        = 1280
	spoofHandshakeFresh = 3 * time.Minute

	spoofWGMagic            = "SPFWG1"
	spoofWGCmdProbe    byte = 0x01
	spoofWGCmdSync     byte = 0x02
	spoofWGCmdTCP      byte = 0x03
	spoofWGCmdUDP      byte = 0x04
)

var spoofTransports = []string{"tcp", "udp", "icmp", "icmpv6"}

func spoofTransportOK(t string) bool {
	low := strings.ToLower(strings.TrimSpace(t))
	for _, v := range spoofTransports {
		if low == v {
			return true
		}
	}
	return false
}

func cleanSpoofHost(raw string) string {
	h := strings.TrimSpace(raw)
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.TrimSpace(host)
	}
	return strings.Trim(h, "[]")
}

func isValidIPv4String(raw string) bool {
	ip := net.ParseIP(cleanSpoofHost(raw))
	return ip != nil && ip.To4() != nil
}

func cleanSpoofIPs(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		ip := net.ParseIP(v)
		if ip == nil || ip.To4() == nil || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func applySpoofWGRoleDefaults(s *SpoofWGConfig) {
	if s == nil {
		return
	}
	role := strings.ToLower(strings.TrimSpace(s.Role))
	if role != "local" && role != "remote" {
		if atomicIsAgent.Load() {
			role = "remote"
		} else {
			role = "local"
		}
	}
	s.Role = role

	if s.SpoofListenPort <= 0 || s.SpoofListenPort > 65535 {
		s.SpoofListenPort = defaultSpoofPort
	}
	if s.RecvPort <= 0 || s.RecvPort > 65535 {
		s.RecvPort = defaultRecvPort
	}
	if s.CorePort <= 0 || s.CorePort > 65535 {
		s.CorePort = defaultCorePort
	}
	if s.WGListen <= 0 || s.WGListen > 65535 {
		s.WGListen = defaultWGListen
	}
	if s.WGMTU < 576 || s.WGMTU > 9000 {
		s.WGMTU = defaultWGMTU
	}
	if strings.TrimSpace(s.WGInterface) == "" {
		s.WGInterface = spoofIface
	}
	if !spoofTransportOK(s.SendTransport) {
		if s.Role == "local" {
			s.SendTransport = "tcp"
		} else {
			s.SendTransport = "udp"
		}
	} else {
		s.SendTransport = strings.ToLower(strings.TrimSpace(s.SendTransport))
	}
	if !spoofTransportOK(s.RecvTransport) {
		if s.Role == "local" {
			s.RecvTransport = "udp"
		} else {
			s.RecvTransport = "tcp"
		}
	} else {
		s.RecvTransport = strings.ToLower(strings.TrimSpace(s.RecvTransport))
	}

	if s.Role == "local" {
		if !isValidIPv4String(s.WGLocalIP) {
			s.WGLocalIP = "10.20.0.1"
		}
		if !isValidIPv4String(s.WGPeerIP) || s.WGPeerIP == s.WGLocalIP {
			s.WGPeerIP = "10.20.0.2"
		}
		if s.SpoofPort <= 0 || s.SpoofPort > 65535 {
			s.SpoofPort = 443
		}
	} else {
		if !isValidIPv4String(s.WGLocalIP) {
			s.WGLocalIP = "10.20.0.2"
		}
		if !isValidIPv4String(s.WGPeerIP) || s.WGPeerIP == s.WGLocalIP {
			s.WGPeerIP = "10.20.0.1"
		}
		if s.SpoofPort <= 0 || s.SpoofPort > 65535 {
			s.SpoofPort = s.SpoofListenPort
		}
	}

	s.SpoofIPs = cleanSpoofIPs(s.SpoofIPs)
	if len(s.SpoofIPs) == 0 {
		s.SpoofIPs = []string{"8.8.8.8"}
	}
}

func normalizeSpoofWGConfig(existing *SpoofWGConfig) *SpoofWGConfig {
	def := defaultSpoofWGConfig()
	if existing == nil {
		_ = ensureSpoofWGKeys(def)
		return def
	}
	cp := *existing
	applySpoofWGRoleDefaults(&cp)
	_ = ensureSpoofWGKeys(&cp)
	return &cp
}

// ============================================================================
// 1. WIREGUARD CURVE25519 KEY GENERATION & BUNDLE (spf1_) CODEC
// ============================================================================

func spoofGenKeypair() (priv, pub string, err error) {
	var p [32]byte
	if _, err = rand.Read(p[:]); err != nil {
		return "", "", err
	}
	// WireGuard RFC 7748 Curve25519 scalar clamping
	p[0] &= 248
	p[31] &= 127
	p[31] |= 64
	pubB, err := curve25519.X25519(p[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(p[:]), base64.StdEncoding.EncodeToString(pubB), nil
}

func spoofPubFromPriv(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid WireGuard private key")
	}
	pubB, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pubB), nil
}

func ensureSpoofWGKeys(s *SpoofWGConfig) error {
	if s == nil {
		return errors.New("spoof config is nil")
	}
	if pub, err := spoofPubFromPriv(s.WGPrivKey); err == nil && pub == s.WGPubKey {
		// Local keypair is valid
	} else {
		priv, pub, err := spoofGenKeypair()
		if err != nil {
			return err
		}
		s.WGPrivKey, s.WGPubKey = priv, pub
	}
	if s.Role == "local" {
		if pub, err := spoofPubFromPriv(s.WGPeerPriv); err == nil && pub == s.WGPeerPub {
			return nil
		}
		priv, pub, err := spoofGenKeypair()
		if err != nil {
			return err
		}
		s.WGPeerPriv, s.WGPeerPub = priv, pub
	}
	return nil
}

type spoofBundle struct {
	V             int    `json:"v"`
	IranPublicIP  string `json:"iran_ip"`
	ListenPort    int    `json:"listen_port"`
	RecvPort      int    `json:"recv_port"`
	SpoofPort     int    `json:"spoof_port"`
	SendTransport string `json:"send"`
	RecvTransport string `json:"recv"`
	IranWGPub     string `json:"iran_wg_pub"`
	ForeignWGPriv string `json:"foreign_wg_priv"`
	WGIranIP      string `json:"wg_iran_ip"`
	WGForeignIP   string `json:"wg_foreign_ip"`
	WGListen      int    `json:"wg_listen"`
	CorePort      int    `json:"core_port"`
}

func (b spoofBundle) validate() error {
	portOK := func(p int) bool { return p > 0 && p <= 65535 }
	keyOK := func(v string) bool {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
		return err == nil && len(raw) == 32
	}
	switch {
	case !isValidIPv4String(b.IranPublicIP):
		return errors.New("the bundle has no valid Iran server IPv4 address")
	case !portOK(b.ListenPort) || !portOK(b.RecvPort) || !portOK(b.WGListen) || !portOK(b.CorePort):
		return errors.New("the bundle has an invalid port")
	case !spoofTransportOK(b.SendTransport) || !spoofTransportOK(b.RecvTransport):
		return errors.New("the bundle has an unknown transport")
	case !keyOK(b.IranWGPub) || !keyOK(b.ForeignWGPriv):
		return errors.New("the bundle has an invalid WireGuard key")
	case !isValidIPv4String(b.WGIranIP) || !isValidIPv4String(b.WGForeignIP) || b.WGIranIP == b.WGForeignIP:
		return errors.New("the bundle has invalid WireGuard addresses")
	}
	return nil
}

func makeSpoofWGBundle(s *SpoofWGConfig, fallbackLocalIP string) (string, error) {
	if s == nil {
		return "", errors.New("spoof configuration is missing")
	}
	applySpoofWGRoleDefaults(s)
	if err := ensureSpoofWGKeys(s); err != nil {
		return "", err
	}
	localIP := cleanSpoofHost(s.LocalPublicIP)
	if !isValidIPv4String(localIP) {
		localIP = cleanSpoofHost(fallbackLocalIP)
	}
	if !isValidIPv4String(localIP) {
		localIP = resolveOutboundInterfaceIP("8.8.8.8").String()
	}
	if !isValidIPv4String(localIP) {
		return "", errors.New("enter a valid IPv4 under Local Public IPv4 before generating the bundle")
	}
	s.LocalPublicIP = localIP

	b := spoofBundle{
		V:             1,
		IranPublicIP:  localIP,
		ListenPort:    s.SpoofListenPort,
		RecvPort:      s.RecvPort,
		SpoofPort:     s.SpoofPort,
		SendTransport: s.SendTransport,
		RecvTransport: s.RecvTransport,
		IranWGPub:     s.WGPubKey,
		ForeignWGPriv: s.WGPeerPriv,
		WGIranIP:      s.WGLocalIP,
		WGForeignIP:   s.WGPeerIP,
		WGListen:      s.WGListen,
		CorePort:      s.CorePort,
	}
	if err := b.validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	bundleStr := "spf1_" + base64.RawURLEncoding.EncodeToString(raw)
	s.LastBundle = bundleStr
	s.UpdatedAt = time.Now().Format(time.RFC3339)
	return bundleStr, nil
}

func importSpoofWGBundle(bundleStr string, prev *SpoofWGConfig) (*SpoofWGConfig, error) {
	trimmed := strings.TrimSpace(bundleStr)
	enc, ok := strings.CutPrefix(trimmed, "spf1_")
	if !ok {
		return prev, errors.New("not a spoof bundle (expected a string starting with spf1_)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return prev, errors.New("the bundle is corrupted (invalid base64url)")
	}
	var b spoofBundle
	if err := unmarshalStrictJSON(raw, &b); err != nil || b.V != 1 {
		return prev, errors.New("the bundle JSON payload is not valid")
	}
	if err := b.validate(); err != nil {
		return prev, err
	}
	foreignPub, err := spoofPubFromPriv(b.ForeignWGPriv)
	if err != nil {
		return prev, err
	}

	out := normalizeSpoofWGConfig(prev)
	out.Role = "remote"
	out.PeerPublicIP = b.IranPublicIP
	out.SpoofListenPort = b.ListenPort
	out.RecvPort = b.RecvPort
	out.SpoofPort = b.ListenPort
	out.WGPeerPriv = ""
	// Transports mirror the Iran side: remote's send is how Iran receives
	out.SendTransport = b.RecvTransport
	out.RecvTransport = b.SendTransport
	out.WGPrivKey = b.ForeignWGPriv
	out.WGPubKey = foreignPub
	out.WGPeerPub = b.IranWGPub
	out.WGLocalIP = b.WGForeignIP
	out.WGPeerIP = b.WGIranIP
	out.WGListen = b.WGListen
	out.CorePort = b.CorePort
	out.LastBundle = trimmed
	out.UpdatedAt = time.Now().Format(time.RFC3339)
	applySpoofWGRoleDefaults(out)
	return out, nil
}

// ============================================================================
// 2. CONFIG FILE & SYSTEMD UNIT GENERATORS (/etc/spoof & /etc/wireguard)
// ============================================================================

func spoofCoreConfigPath() string { return filepath.Join(spoofDir, "config.json") }
func spoofIPFilePath() string     { return filepath.Join(spoofDir, "spoof-ips.txt") }
func spoofWGConfPath() string     { return filepath.Join(wgConfDir, spoofIface+".conf") }

func buildSpoofCoreConfigMap(s *SpoofWGConfig) map[string]any {
	applySpoofWGRoleDefaults(s)
	m := map[string]any{
		"spoof_port":     s.SpoofPort,
		"send_transport": s.SendTransport,
		"recv_transport": s.RecvTransport,
	}
	if len(s.SpoofIPs) == 1 {
		m["spoof_ip"] = s.SpoofIPs[0]
	} else if len(s.SpoofIPs) > 1 {
		m["spoof_ip_file"] = spoofIPFilePath()
	}
	if s.Role == "local" {
		m["mode"] = "local"
		m["listen"] = fmt.Sprintf("127.0.0.1:%d", s.CorePort)
		m["remote"] = cleanSpoofHost(s.PeerPublicIP)
		m["remote_port"] = s.SpoofListenPort
		m["recv_port"] = s.RecvPort
	} else {
		m["mode"] = "remote"
		m["listen_port"] = s.SpoofListenPort
		m["forward"] = fmt.Sprintf("127.0.0.1:%d", s.WGListen)
		m["client_ip"] = cleanSpoofHost(s.PeerPublicIP)
		m["client_port"] = s.RecvPort
	}
	return m
}

func buildSpoofWGConfigText(s *SpoofWGConfig) string {
	applySpoofWGRoleDefaults(s)
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s/24\n", s.WGLocalIP)
	fmt.Fprintf(&b, "PrivateKey = %s\n", s.WGPrivKey)
	fmt.Fprintf(&b, "MTU = %d\n", s.WGMTU)
	if s.Role == "remote" {
		fmt.Fprintf(&b, "ListenPort = %d\n", s.WGListen)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", s.WGPeerPub)
	fmt.Fprintf(&b, "AllowedIPs = %s/32\n", s.WGPeerIP)
	if s.Role == "local" {
		fmt.Fprintf(&b, "Endpoint = 127.0.0.1:%d\n", s.CorePort)
		b.WriteString("PersistentKeepalive = 25\n")
	}
	return b.String()
}

func writeSpoofAndWGConfigs(s *SpoofWGConfig) error {
	if s == nil {
		return errors.New("spoof config is nil")
	}
	if err := os.MkdirAll(spoofDir, 0700); err != nil {
		return err
	}
	if len(s.SpoofIPs) > 1 {
		if err := os.WriteFile(spoofIPFilePath(), []byte(strings.Join(s.SpoofIPs, "\n")+"\n"), 0600); err != nil {
			return err
		}
	}
	coreBytes, err := json.MarshalIndent(buildSpoofCoreConfigMap(s), "", "  ")
	if err != nil {
		return err
	}
	tmpCore := spoofCoreConfigPath() + ".tmp"
	if err := os.WriteFile(tmpCore, coreBytes, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpCore, spoofCoreConfigPath()); err != nil {
		return err
	}

	if err := os.MkdirAll(wgConfDir, 0700); err != nil {
		return err
	}
	tmpWG := spoofWGConfPath() + ".tmp"
	if err := os.WriteFile(tmpWG, []byte(buildSpoofWGConfigText(s)), 0600); err != nil {
		return err
	}
	return os.Rename(tmpWG, spoofWGConfPath())
}

func validateSpoofWGReady(s *SpoofWGConfig) error {
	if s == nil {
		return errors.New("spoof configuration is nil")
	}
	applySpoofWGRoleDefaults(s)
	if strings.TrimSpace(s.PeerPublicIP) == "" {
		return errors.New("the other server's public IPv4 is not set")
	}
	if !isValidIPv4String(s.PeerPublicIP) {
		return errors.New("the other server's public IP must be a valid IPv4 address")
	}
	if len(s.SpoofIPs) == 0 {
		return errors.New("at least one valid IPv4 Spoof IP is required")
	}
	if strings.TrimSpace(s.WGPeerPub) == "" {
		return errors.New("peer WireGuard public key is missing (generate or import a bundle first)")
	}
	if !spoofTransportOK(s.SendTransport) || !spoofTransportOK(s.RecvTransport) {
		return fmt.Errorf("transports must be one of %s", strings.Join(spoofTransports, ", "))
	}
	return nil
}

func findSpoofBinaryPath() (string, bool) {
	candidates := []string{
		"/usr/local/bin/spoof",
		"/usr/bin/spoof",
		filepath.Join(filepath.Dir(configPath()), "bin", "spoof"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
	}
	if p, err := exec.LookPath(spoofBinName); err == nil {
		return p, true
	}
	return "/usr/local/bin/spoof", false
}

func querySpoofWGRuntimeHealth(s *SpoofWGConfig) SpoofWGHealth {
	_, binOK := findSpoofBinaryPath()
	h := SpoofWGHealth{
		BinaryInstalled: binOK,
		ActivePath:      "DIRECT_CARRIER",
	}
	if s != nil && s.LastError != "" {
		h.LastError = s.LastError
	}
	if runtime.GOOS != "linux" {
		return h
	}
	if exec.Command("systemctl", "is-active", "--quiet", spoofCoreSvc).Run() == nil {
		h.CoreActive = true
	}
	iface := spoofIface
	if s != nil && strings.TrimSpace(s.WGInterface) != "" {
		iface = strings.TrimSpace(s.WGInterface)
	}
	if exec.Command("systemctl", "is-active", "--quiet", spoofWGUnitTmpl+iface).Run() == nil {
		h.WGActive = true
	}
	if out, err := exec.Command("wg", "show", iface, "latest-handshakes").Output(); err == nil {
		fields := strings.Fields(strings.TrimSpace(string(out)))
		if len(fields) >= 2 {
			if ts, err := strconv.ParseInt(fields[len(fields)-1], 10, 64); err == nil && ts > 0 {
				age := time.Since(time.Unix(ts, 0))
				h.Handshake = age.Truncate(time.Second).String() + " ago"
				if age < spoofHandshakeFresh {
					h.PeerPing = true
					h.ActivePath = "WIREGUARD_SPOOF (" + iface + ")"
				}
			}
		}
	}
	if s != nil && isLocalIPAddressBound(s.WGLocalIP) {
		h.WGActive = true
		h.ActivePath = "WIREGUARD_SPOOF (" + s.WGLocalIP + " ↔ " + s.WGPeerIP + ")"
	}
	return h
}

func applyLinuxSpoofAndWGServices(s *SpoofWGConfig) (string, error) {
	if err := validateSpoofWGReady(s); err != nil {
		return "", err
	}
	if err := writeSpoofAndWGConfigs(s); err != nil {
		return "", fmt.Errorf("failed to write spoof/wireguard configs: %w", err)
	}
	binPath, binOK := findSpoofBinaryPath()
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || !binOK {
		s.ServiceEnabled = true
		return fmt.Sprintf("Spoof + WireGuard configuration saved (%s / %s). Built-in Sahand carrier active.", s.SendTransport, s.RecvTransport), nil
	}

	unitContent := fmt.Sprintf(`[Unit]
Description=Sahand Spoof Tunnel Core (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run -c %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, s.Role, binPath, spoofCoreConfigPath())

	unitPath := filepath.Join("/etc/systemd/system", spoofCoreSvc+".service")
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return "", err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if err := exec.Command("systemctl", "restart", spoofCoreSvc).Run(); err != nil {
		return "", fmt.Errorf("failed to start %s: %w", spoofCoreSvc, err)
	}
	_ = exec.Command("systemctl", "enable", spoofCoreSvc).Run()

	wgUnit := spoofWGUnitTmpl + s.WGInterface
	if err := exec.Command("systemctl", "restart", wgUnit).Run(); err != nil {
		return "", fmt.Errorf("failed to start WireGuard (%s): %w", wgUnit, err)
	}
	_ = exec.Command("systemctl", "enable", wgUnit).Run()
	s.ServiceEnabled = true
	return fmt.Sprintf("Spoof + WireGuard tunnel is up on %s (%s/%s, %s ↔ %s).",
		s.Role, s.SendTransport, s.RecvTransport, s.WGLocalIP, s.WGPeerIP), nil
}

func stopLinuxSpoofAndWGServices(s *SpoofWGConfig) {
	iface := spoofIface
	if s != nil && strings.TrimSpace(s.WGInterface) != "" {
		iface = strings.TrimSpace(s.WGInterface)
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		_ = exec.Command("systemctl", "disable", "--now", spoofWGUnitTmpl+iface).Run()
		_ = exec.Command("systemctl", "disable", "--now", spoofCoreSvc).Run()
	}
	if s != nil {
		s.ServiceEnabled = false
	}
}

// ============================================================================
// 3. ENGINE 1 & ENGINE 2 BUILT-IN CARRIER & FORWARDER FOR METHOD 26 (:28026)
// ============================================================================

type spoofWGRuntime struct {
	peerID     string
	peer       ServerPeer
	tunnel     TunnelConfig
	carrierLn  net.Listener
	udpEntries []*net.UDPConn
	closed     atomic.Bool
}

var (
	spoofWGRuntimeMu sync.RWMutex
	spoofWGRuntimes  = make(map[string]*spoofWGRuntime)
)

func stopSpoofWGPeerResources(peerID string) {
	spoofWGRuntimeMu.Lock()
	rt, ok := spoofWGRuntimes[peerID]
	if ok {
		delete(spoofWGRuntimes, peerID)
	}
	spoofWGRuntimeMu.Unlock()

	if rt != nil && !rt.closed.Swap(true) {
		if rt.carrierLn != nil {
			_ = rt.carrierLn.Close()
		}
		for _, u := range rt.udpEntries {
			_ = u.Close()
		}
	}
}

// Resolves the target IP for dialing the peer: prefers the WireGuard overlay IP (`WGPeerIP`, e.g. 10.20.0.2)
// if the local WireGuard interface (`WGLocalIP`, e.g. 10.20.0.1) is up on the host; otherwise dials `peer.IP`.
func resolveSpoofWGTargetHost(peer ServerPeer, tc TunnelConfig) string {
	if tc.SpoofWG != nil && isValidIPv4String(tc.SpoofWG.WGLocalIP) && isValidIPv4String(tc.SpoofWG.WGPeerIP) {
		if isLocalIPAddressBound(tc.SpoofWG.WGLocalIP) {
			return cleanSpoofHost(tc.SpoofWG.WGPeerIP)
		}
	}
	return strings.TrimSpace(peer.IP)
}

type spoofWGWireHeader struct {
	Magic      string `json:"m"`
	Cmd        byte   `json:"c"`
	PeerID     string `json:"p"`
	TargetPort int    `json:"tp,omitempty"`
	TimeHdr    string `json:"th,omitempty"`
	Nonce      string `json:"n"`
	MAC        string `json:"mac"`
}

func computeSpoofWGHeaderMAC(subKey []byte, h spoofWGWireHeader) string {
	mac := hmac.New(sha256.New, subKey)
	_, _ = mac.Write([]byte(fmt.Sprintf("%s|%d|%s|%d|%s", h.Magic, h.Cmd, h.PeerID, h.TargetPort, h.Nonce)))
	return hex.EncodeToString(mac.Sum(nil))
}

func startSpoofWGServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
	stopSpoofWGPeerResources(peer.ID)

	if tc.SpoofWG == nil {
		tc.SpoofWG = defaultSpoofWGConfig()
	}
	if tc.SpoofWG.PeerPublicIP == "" && isValidIPv4String(peer.IP) {
		tc.SpoofWG.PeerPublicIP = peer.IP
	}
	tc.SpoofWG = normalizeSpoofWGConfig(tc.SpoofWG)

	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{localCert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", listenAddr, tlsCfg)
	if err != nil {
		return nil, err
	}

	rt := &spoofWGRuntime{
		peerID:    peer.ID,
		peer:      peer,
		tunnel:    tc,
		carrierLn: ln,
	}

	spoofWGRuntimeMu.Lock()
	spoofWGRuntimes[peer.ID] = rt
	spoofWGRuntimeMu.Unlock()

	go func() {
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			enableKeepAlive(conn)
			go rt.handleIncomingConn(conn)
		}
	}()

	return ln, nil
}

func dialSpoofWGCarrier(peer ServerPeer, tc TunnelConfig, cmd byte, targetPort int, timeout time.Duration) (net.Conn, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	subKey, err := derivePeerSubKey(cfgSnapshot, peer, "spoof-wg-carrier-v1")
	if err != nil {
		return nil, err
	}

	targetHost := resolveSpoofWGTargetHost(peer, tc)
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.Dial("tcp", net.JoinHostPort(targetHost, strconv.Itoa(tc.ListenPort)))
	if err != nil && targetHost != strings.TrimSpace(peer.IP) && strings.TrimSpace(peer.IP) != "" {
		rawConn, err = dialer.Dial("tcp", net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort)))
	}
	if err != nil {
		return nil, err
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
		return nil, err
	}

	nonce, _ := randomHex(12)
	hdr := spoofWGWireHeader{
		Magic:      spoofWGMagic,
		Cmd:        cmd,
		PeerID:     peer.ID,
		TargetPort: targetPort,
		TimeHdr:    buildMasterTimeHeader(),
		Nonce:      nonce,
	}
	hdr.MAC = computeSpoofWGHeaderMAC(subKey, hdr)

	rawHdr, err := json.Marshal(hdr)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(rawHdr)))
	if _, err := tlsConn.Write(lenBuf[:]); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if _, err := tlsConn.Write(rawHdr); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	var status [1]byte
	if _, err := io.ReadFull(tlsConn, status[:]); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if status[0] != 0x00 {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("spoof-wg handshake rejected (code %d)", status[0])
	}
	return tlsConn, nil
}

func (rt *spoofWGRuntime) handleIncomingConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	subKey, err := derivePeerSubKey(cfgSnapshot, rt.peer, "spoof-wg-carrier-v1")
	if err != nil {
		return
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	hLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if hLen <= 0 || hLen > 4096 {
		return
	}
	hBytes := make([]byte, hLen)
	if _, err := io.ReadFull(conn, hBytes); err != nil {
		return
	}

	var hdr spoofWGWireHeader
	if err := unmarshalStrictJSON(hBytes, &hdr); err != nil || hdr.Magic != spoofWGMagic {
		return
	}
	expectedMAC := computeSpoofWGHeaderMAC(subKey, hdr)
	if subtle.ConstantTimeCompare([]byte(hdr.MAC), []byte(expectedMAC)) != 1 {
		_, _ = conn.Write([]byte{0x01})
		return
	}
	if hdr.TimeHdr != "" {
		applyMasterTimeHeader(hdr.TimeHdr)
	}

	remoteHost := extractRemoteHostIP(conn.RemoteAddr())

	switch hdr.Cmd {
	case spoofWGCmdProbe:
		if _, err := conn.Write([]byte{0x00}); err != nil {
			return
		}
		var ping [16]byte
		if _, err := io.ReadFull(conn, ping[:]); err != nil {
			return
		}
		_, _ = conn.Write(ping[:])
		markPeerConnectedInbound(rt.peer.ID, remoteHost, rt.tunnel.ID, rt.tunnel.ListenPort, 1)

	case spoofWGCmdSync:
		if _, err := conn.Write([]byte{0x00}); err != nil {
			return
		}
		handleWebTransportParitySyncStream(conn, rt.peer.ID, remoteHost)

	case spoofWGCmdTCP:
		if !rt.tunnel.Enabled {
			_, _ = conn.Write([]byte{0x02})
			return
		}
		authorizedPort, err := authorizeWSSTargetPort(rt.tunnel, strconv.Itoa(hdr.TargetPort))
		if err != nil {
			_, _ = conn.Write([]byte{0x03})
			return
		}
		target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", authorizedPort), 5*time.Second)
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
		pipeSpoofWGAndTCP(conn, target, rt.tunnel.SpeedLimitMBps)

	case spoofWGCmdUDP:
		if !rt.tunnel.Enabled {
			_, _ = conn.Write([]byte{0x02})
			return
		}
		authorizedPort, err := authorizeWSSTargetPort(rt.tunnel, strconv.Itoa(hdr.TargetPort))
		if err != nil {
			_, _ = conn.Write([]byte{0x03})
			return
		}
		if _, err := conn.Write([]byte{0x00}); err != nil {
			return
		}
		var dLenBuf [2]byte
		if _, err := io.ReadFull(conn, dLenBuf[:]); err != nil {
			return
		}
		dLen := int(binary.BigEndian.Uint16(dLenBuf[:]))
		if dLen <= 0 || dLen > 16384 {
			return
		}
		dgram := make([]byte, dLen)
		if _, err := io.ReadFull(conn, dgram); err != nil {
			return
		}
		atomic.AddUint64(&appRxBytes, uint64(len(dgram)))

		uConn, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", authorizedPort), 3*time.Second)
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
			_, _ = conn.Write(dLenBuf[:])
			_, _ = conn.Write(rep[:n])
		}
	}
}

func pipeSpoofWGAndTCP(carrierConn, tcpConn net.Conn, speedLimitMBps string) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	toCarrier := newThrottledWriter(carrierConn, &appTxBytes, mbLimit)
	toTCP := newThrottledWriter(tcpConn, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toCarrier, tcpConn, buf)
		closeWriteTCP(carrierConn)
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toTCP, carrierConn, buf)
		closeWriteTCP(tcpConn)
	}()

	wg.Wait()
}

func probeSpoofWG(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	conn, err := dialSpoofWGCarrier(peer, tc, spoofWGCmdProbe, tc.ListenPort, 3500*time.Millisecond)
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
	defer conn.Close()

	var ping [16]byte
	var pong [16]byte
	_, _ = io.ReadFull(rand.Reader, ping[:])
	if _, err := conn.Write(ping[:]); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}
	if _, err := io.ReadFull(conn, pong[:]); err != nil || !bytes.Equal(ping[:], pong[:]) {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	rtt := time.Since(start).Milliseconds()
	if rtt <= 0 {
		rtt = 1
	}
	res.Success = true
	res.LatencyMS = rtt
	res.MinLatencyMS = rtt
	res.MaxLatencyMS = rtt
	return res
}

func pushSpoofWGParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	conn, err := dialSpoofWGCarrier(peer, tc, spoofWGCmdSync, tc.ListenPort, 4*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	stateMu.RLock()
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	mSignPub := appCfg.MasterSigningPublicKey
	mNoisePub := appCfg.MasterNoiseStaticPublicKey
	aSignPub := appCfg.AgentSigningPublicKey
	aNoisePub := appCfg.AgentNoiseStaticPublicKey
	stateMu.RUnlock()

	padLen := 24 + randomIntN(64)
	padHex, _ := randomHex(padLen)

	pkt := SyncPacket{
		Type:                       "parity_sync",
		SenderID:                   senderID,
		PeerID:                     peer.ID,
		MethodID:                   tc.ID,
		Port:                       tc.ListenPort,
		LatencyMS:                  latencyMS,
		ConfigVersion:              peer.ConfigVersion,
		CertPin:                    certPin,
		MasterSigningPublicKey:     mSignPub,
		MasterNoiseStaticPublicKey: mNoisePub,
		AgentSigningPublicKey:      aSignPub,
		AgentNoiseStaticPublicKey:  aNoisePub,
		Padding:                    padHex,
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

func forwardSpoofWGTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	authorizedPort, err := authorizeWSSTargetPort(tc, targetPort)
	if err != nil {
		return
	}
	portNum, _ := strconv.Atoi(authorizedPort)

	conn, err := dialSpoofWGCarrier(peer, tc, spoofWGCmdTCP, portNum, 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})

	pipeSpoofWGAndTCP(conn, client, tc.SpeedLimitMBps)
}

func startSpoofWGUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
	authorizedPort, err := authorizeWSSTargetPort(tc, targetPort)
	if err != nil {
		return nil
	}
	portNum, _ := strconv.Atoi(authorizedPort)

	uAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(portNum)))
	if err != nil {
		return nil
	}
	entryConn, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		return nil
	}
	configureUDPSocketBuffers(entryConn)

	spoofWGRuntimeMu.Lock()
	if rt, ok := spoofWGRuntimes[peer.ID]; ok {
		rt.udpEntries = append(rt.udpEntries, entryConn)
	}
	spoofWGRuntimeMu.Unlock()

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
			cliCopy := cloneUDPAddr(cliAddr)

			go func(dgram []byte, cAddr *net.UDPAddr) {
				conn, dErr := dialSpoofWGCarrier(peer, tc, spoofWGCmdUDP, portNum, 4*time.Second)
				if dErr != nil {
					return
				}
				defer conn.Close()

				atomic.AddUint64(&appTxBytes, uint64(len(dgram)))
				var lenBuf [2]byte
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(dgram)))
				if _, err := conn.Write(lenBuf[:]); err != nil {
					return
				}
				if _, err := conn.Write(dgram); err != nil {
					return
				}
				if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
					return
				}
				rLen := int(binary.BigEndian.Uint16(lenBuf[:]))
				if rLen > 0 && rLen <= 16384 {
					rep := make([]byte, rLen)
					if _, err := io.ReadFull(conn, rep); err == nil {
						atomic.AddUint64(&appRxBytes, uint64(rLen))
						_, _ = entryConn.WriteToUDP(rep, cAddr)
					}
				}
			}(payload, cliCopy)
		}
	}()

	return entryConn
}
