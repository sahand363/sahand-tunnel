package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
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

	"golang.org/x/crypto/chacha20poly1305"
)

// Isolated paths & service names for Method 27 (never collides with Method 26's /etc/spoof or wg-spoof)
var (
	spoofM27Dir   = "/etc/spoof-m27"
	wgM27ConfDir  = "/etc/wireguard"
	spoofM27Iface = "wg-spoof27"
)

const (
	spoofM27CoreSvc     = "spoof-core-m27"
	spoofM27WGUnitTmpl  = "wg-quick@" // wg-quick@wg-spoof27
	defaultM27SpoofPort = 8091        // public port the remote receives on (Method 26 uses 8090)
	defaultM27RecvPort  = 5011        // local recv port / remote client_port (Method 26 uses 5001)
	defaultM27CorePort  = 5010        // local core UDP listen port (Method 26 uses 5000)
	defaultM27AdaptPort = 51827       // remote core UDP forward target port (Method 26 uses 51820)
	defaultM27MTU       = 1280

	m27FrameMagic            = "M27P"
	m27FrameTypePing    byte = 0x01
	m27FrameTypePong    byte = 0x02
	m27FrameTypeSyn     byte = 0x03
	m27FrameTypeSynAck  byte = 0x04
	m27FrameTypeData    byte = 0x05
	m27FrameTypeAck     byte = 0x06
	m27FrameTypeFin     byte = 0x07
	m27FrameTypeUDP     byte = 0x08
	m27FrameTypeSyncReq byte = 0x09
	m27FrameTypeSyncRep byte = 0x0A

	m27NoiseInit   byte = 0x11
	m27NoiseResp   byte = 0x12
	m27NoisePacket byte = 0x13

	m27OverlayMagic         = "M27OV1"
	m27OverlayCmdProbe byte = 0x01
	m27OverlayCmdSync  byte = 0x02
	m27OverlayCmdTCP   byte = 0x03
	m27OverlayCmdUDP   byte = 0x04
)

var spoofM27Modes = []string{"pure", "wireguard", "quic", "noise"}

// Self-contained 64-bit sliding-window anti-replay filter for Method 27 Noise sessions
type m27ReplayWindow struct {
	mu     sync.Mutex
	maxSeq uint64
	bitmap uint64
}

func (rw *m27ReplayWindow) CheckAndAccept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if seq > rw.maxSeq {
		shift := seq - rw.maxSeq
		if shift >= 64 {
			rw.bitmap = 1
		} else {
			rw.bitmap = (rw.bitmap << shift) | 1
		}
		rw.maxSeq = seq
		return true
	}
	diff := rw.maxSeq - seq
	if diff >= 64 {
		return false
	}
	mask := uint64(1) << diff
	if (rw.bitmap & mask) != 0 {
		return false
	}
	rw.bitmap |= mask
	return true
}

// Per-stream sequence reorder buffer guaranteeing strict in-order TCP byte delivery
type m27StreamReorderBuffer struct {
	mu      sync.Mutex
	nextSeq uint32
	pending map[uint32][]byte
}

func newM27StreamReorderBuffer() *m27StreamReorderBuffer {
	return &m27StreamReorderBuffer{
		nextSeq: 1,
		pending: make(map[uint32][]byte),
	}
}

func (rb *m27StreamReorderBuffer) InsertAndDrain(seq uint32, payload []byte) [][]byte {
	cp := make([]byte, len(payload))
	copy(cp, payload)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if seq < rb.nextSeq {
		return nil
	}
	rb.pending[seq] = cp
	var ready [][]byte
	for {
		chunk, ok := rb.pending[rb.nextSeq]
		if !ok {
			break
		}
		delete(rb.pending, rb.nextSeq)
		rb.nextSeq++
		ready = append(ready, chunk)
	}
	return ready
}

func spoofM27ModeOK(mode string) bool {
	m := strings.ToLower(strings.TrimSpace(mode))
	for _, valid := range spoofM27Modes {
		if m == valid {
			return true
		}
	}
	return false
}

func spoofM27CoreConfigPath() string { return filepath.Join(spoofM27Dir, "config.json") }
func spoofM27IPFilePath() string     { return filepath.Join(spoofM27Dir, "spoof-ips.txt") }
func spoofM27WGConfPath(iface string) string {
	if strings.TrimSpace(iface) == "" {
		iface = spoofM27Iface
	}
	return filepath.Join(wgM27ConfDir, iface+".conf")
}

func defaultSpoofNativeConfig() *SpoofNativeConfig {
	role := "local"
	if atomicIsAgent.Load() {
		role = "remote"
	}
	cfg := &SpoofNativeConfig{
		Role:            role,
		Mode:            "pure",
		ServiceEnabled:  false,
		StrictRealSpoof: true,
		SpoofListenPort: defaultM27SpoofPort,
		RecvPort:        defaultM27RecvPort,
		SpoofPort:       443,
		SpoofIPs:        []string{},
		SendTransport:   "tcp",
		RecvTransport:   "udp",
		CorePort:        defaultM27CorePort,
		AdapterPort:     defaultM27AdaptPort,
		MTU:             defaultM27MTU,
		KeepaliveSec:    25,
		TimeoutSec:      30,
		PacketCount:     10,
		MaxLossPct:      20,
		WGInterface:     spoofM27Iface,
		WGLocalIP:       "10.27.0.1",
		WGPeerIP:        "10.27.0.2",
		Health: SpoofNativeHealth{
			ConnectionState: "DISCONNECTED",
			StatusBadge:     "DISCONNECTED",
			ActiveAdapter:   "pure",
			ActivePath:      "NONE",
		},
		Tester: SpoofTesterStatus{
			Status: "idle",
			Passed: []SpoofTesterResult{},
		},
	}
	applySpoofNativeRoleDefaults(cfg)
	return cfg
}

func applySpoofNativeRoleDefaults(s *SpoofNativeConfig) {
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

	if !spoofM27ModeOK(s.Mode) {
		s.Mode = "pure"
	} else {
		s.Mode = strings.ToLower(strings.TrimSpace(s.Mode))
	}

	if s.SpoofListenPort <= 0 || s.SpoofListenPort > 65535 {
		s.SpoofListenPort = defaultM27SpoofPort
	}
	if s.RecvPort <= 0 || s.RecvPort > 65535 {
		s.RecvPort = defaultM27RecvPort
	}
	if s.CorePort <= 0 || s.CorePort > 65535 {
		s.CorePort = defaultM27CorePort
	}
	if s.AdapterPort <= 0 || s.AdapterPort > 65535 {
		s.AdapterPort = defaultM27AdaptPort
	}
	if s.MTU < 576 || s.MTU > 9000 {
		s.MTU = defaultM27MTU
	}
	if s.KeepaliveSec <= 0 || s.KeepaliveSec > 300 {
		s.KeepaliveSec = 25
	}
	if s.TimeoutSec <= 0 || s.TimeoutSec > 600 {
		s.TimeoutSec = 30
	}
	if s.PacketCount <= 0 || s.PacketCount > 1000 {
		s.PacketCount = 10
	}
	if s.MaxLossPct < 0 || s.MaxLossPct > 100 {
		s.MaxLossPct = 20
	}
	if strings.TrimSpace(s.WGInterface) == "" || s.WGInterface == spoofIface {
		s.WGInterface = spoofM27Iface
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
		if !isValidIPv4String(s.WGLocalIP) || strings.HasPrefix(s.WGLocalIP, "10.20.") {
			s.WGLocalIP = "10.27.0.1"
		}
		if !isValidIPv4String(s.WGPeerIP) || s.WGPeerIP == s.WGLocalIP || strings.HasPrefix(s.WGPeerIP, "10.20.") {
			s.WGPeerIP = "10.27.0.2"
		}
		if s.SpoofPort <= 0 || s.SpoofPort > 65535 {
			s.SpoofPort = 443
		}
	} else {
		if !isValidIPv4String(s.WGLocalIP) || strings.HasPrefix(s.WGLocalIP, "10.20.") {
			s.WGLocalIP = "10.27.0.2"
		}
		if !isValidIPv4String(s.WGPeerIP) || s.WGPeerIP == s.WGLocalIP || strings.HasPrefix(s.WGPeerIP, "10.20.") {
			s.WGPeerIP = "10.27.0.1"
		}
		if s.SpoofPort <= 0 || s.SpoofPort > 65535 {
			s.SpoofPort = s.SpoofListenPort
		}
	}

	s.SpoofIPs = cleanSpoofIPs(s.SpoofIPs)
}

func normalizeSpoofNativeConfig(existing *SpoofNativeConfig) *SpoofNativeConfig {
	def := defaultSpoofNativeConfig()
	if existing == nil {
		_ = ensureSpoofNativeKeys(def)
		return def
	}
	cp := *existing
	applySpoofNativeRoleDefaults(&cp)
	_ = ensureSpoofNativeKeys(&cp)
	return &cp
}

func ensureSpoofNativeKeys(s *SpoofNativeConfig) error {
	if s == nil {
		return errors.New("native spoof config is nil")
	}
	if pub, err := spoofPubFromPriv(s.WGPrivKey); err == nil && pub == s.WGPubKey {
		// Valid local WG keypair
	} else {
		priv, pub, err := spoofGenKeypair()
		if err != nil {
			return err
		}
		s.WGPrivKey, s.WGPubKey = priv, pub
	}
	if s.Role == "local" {
		if pub, err := spoofPubFromPriv(s.WGPeerPriv); err == nil && pub == s.WGPeerPub {
			// Valid peer WG keypair
		} else {
			priv, pub, err := spoofGenKeypair()
			if err != nil {
				return err
			}
			s.WGPeerPriv, s.WGPeerPub = priv, pub
		}
	}
	if !validateX25519KeypairHex(s.NoisePrivKey, s.NoisePubKey) {
		priv, pub, err := generateX25519KeypairHex()
		if err != nil {
			return err
		}
		s.NoisePrivKey, s.NoisePubKey = priv, pub
	}
	if s.Role == "local" {
		if !validateX25519KeypairHex(s.NoisePeerPriv, s.NoisePeerPub) {
			priv, pub, err := generateX25519KeypairHex()
			if err != nil {
				return err
			}
			s.NoisePeerPriv, s.NoisePeerPub = priv, pub
		}
	}
	return nil
}

// ============================================================================
// 1. METHOD 27 BUNDLE EXCHANGE (m27spf1_)
// ============================================================================

type spoofNativeBundle struct {
	V               int    `json:"v"`
	Mode            string `json:"mode"`
	StrictRealSpoof bool   `json:"strict"`
	IranPublicIP    string `json:"iran_ip"`
	ListenPort      int    `json:"listen_port"`
	RecvPort        int    `json:"recv_port"`
	SpoofPort       int    `json:"spoof_port"`
	SendTransport   string `json:"send"`
	RecvTransport   string `json:"recv"`
	CorePort        int    `json:"core_port"`
	AdapterPort     int    `json:"adapter_port"`
	MTU             int    `json:"mtu"`
	KeepaliveSec    int    `json:"keepalive"`
	WGInterface     string `json:"wg_if,omitempty"`
	IranWGPub       string `json:"iran_wg_pub,omitempty"`
	ForeignWGPriv   string `json:"foreign_wg_priv,omitempty"`
	WGIranIP        string `json:"wg_iran_ip,omitempty"`
	WGForeignIP     string `json:"wg_foreign_ip,omitempty"`
	IranNoisePub    string `json:"iran_noise_pub,omitempty"`
	ForeignNoisePrv string `json:"foreign_noise_priv,omitempty"`
}

func (b spoofNativeBundle) validate() error {
	portOK := func(p int) bool { return p > 0 && p <= 65535 }
	switch {
	case b.V != 1:
		return errors.New("unsupported Method 27 bundle version")
	case !spoofM27ModeOK(b.Mode):
		return fmt.Errorf("bundle has unsupported adapter mode %q", b.Mode)
	case !isValidIPv4String(b.IranPublicIP):
		return errors.New("bundle has no valid Iran server IPv4 address")
	case !portOK(b.ListenPort) || !portOK(b.RecvPort) || !portOK(b.CorePort) || !portOK(b.AdapterPort):
		return errors.New("bundle contains an out-of-range port")
	case !spoofTransportOK(b.SendTransport) || !spoofTransportOK(b.RecvTransport):
		return errors.New("bundle contains an invalid send/recv transport")
	case b.MTU < 576 || b.MTU > 9000:
		return errors.New("bundle contains an invalid MTU")
	}
	if b.Mode == "wireguard" {
		rawPub, err1 := base64.StdEncoding.DecodeString(strings.TrimSpace(b.IranWGPub))
		rawPriv, err2 := base64.StdEncoding.DecodeString(strings.TrimSpace(b.ForeignWGPriv))
		if err1 != nil || err2 != nil || len(rawPub) != 32 || len(rawPriv) != 32 {
			return errors.New("bundle contains invalid WireGuard keys")
		}
		if !isValidIPv4String(b.WGIranIP) || !isValidIPv4String(b.WGForeignIP) || b.WGIranIP == b.WGForeignIP {
			return errors.New("bundle contains invalid WireGuard overlay IPv4 addresses")
		}
	}
	if b.Mode == "noise" {
		if _, err := decodeHexExact(b.IranNoisePub, 32); err != nil {
			return errors.New("bundle contains invalid Iran Noise public key")
		}
		if _, err := decodeHexExact(b.ForeignNoisePrv, 32); err != nil {
			return errors.New("bundle contains invalid Foreign Noise private key")
		}
	}
	return nil
}

func makeSpoofNativeBundle(s *SpoofNativeConfig, fallbackLocalIP string) (string, error) {
	if s == nil {
		return "", errors.New("Method 27 configuration is nil")
	}
	applySpoofNativeRoleDefaults(s)
	if err := ensureSpoofNativeKeys(s); err != nil {
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
		return "", errors.New("enter a valid IPv4 under This Server's Public IPv4 before generating the Method 27 bundle")
	}
	s.LocalPublicIP = localIP

	b := spoofNativeBundle{
		V:               1,
		Mode:            s.Mode,
		StrictRealSpoof: s.StrictRealSpoof,
		IranPublicIP:    localIP,
		ListenPort:      s.SpoofListenPort,
		RecvPort:        s.RecvPort,
		SpoofPort:       s.SpoofPort,
		SendTransport:   s.SendTransport,
		RecvTransport:   s.RecvTransport,
		CorePort:        s.CorePort,
		AdapterPort:     s.AdapterPort,
		MTU:             s.MTU,
		KeepaliveSec:    s.KeepaliveSec,
		WGInterface:     s.WGInterface,
		IranWGPub:       s.WGPubKey,
		ForeignWGPriv:   s.WGPeerPriv,
		WGIranIP:        s.WGLocalIP,
		WGForeignIP:     s.WGPeerIP,
		IranNoisePub:    s.NoisePubKey,
		ForeignNoisePrv: s.NoisePeerPriv,
	}
	if err := b.validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	bundleStr := "m27spf1_" + base64.RawURLEncoding.EncodeToString(raw)
	s.LastBundle = bundleStr
	s.UpdatedAt = time.Now().Format(time.RFC3339)
	return bundleStr, nil
}

func importSpoofNativeBundle(bundleStr string, prev *SpoofNativeConfig) (*SpoofNativeConfig, error) {
	trimmed := strings.TrimSpace(bundleStr)
	enc, ok := strings.CutPrefix(trimmed, "m27spf1_")
	if !ok {
		return prev, errors.New("not a Method 27 bundle (expected a string starting with m27spf1_)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return prev, errors.New("the Method 27 bundle is corrupted (invalid base64url)")
	}
	var b spoofNativeBundle
	if err := unmarshalStrictJSON(raw, &b); err != nil {
		return prev, fmt.Errorf("the Method 27 bundle JSON payload is invalid: %w", err)
	}
	if err := b.validate(); err != nil {
		return prev, err
	}

	out := normalizeSpoofNativeConfig(prev)
	out.Role = "remote"
	out.Mode = b.Mode
	out.StrictRealSpoof = b.StrictRealSpoof
	out.PeerPublicIP = b.IranPublicIP
	out.SpoofListenPort = b.ListenPort
	out.RecvPort = b.RecvPort
	out.SpoofPort = b.ListenPort
	// Transports mirror the Iran side: remote's send is how Iran receives
	out.SendTransport = b.RecvTransport
	out.RecvTransport = b.SendTransport
	out.CorePort = b.CorePort
	out.AdapterPort = b.AdapterPort
	out.MTU = b.MTU
	out.KeepaliveSec = b.KeepaliveSec
	if strings.TrimSpace(b.WGInterface) != "" && b.WGInterface != spoofIface {
		out.WGInterface = b.WGInterface
	}
	if b.IranWGPub != "" && b.ForeignWGPriv != "" {
		if fPub, err := spoofPubFromPriv(b.ForeignWGPriv); err == nil {
			out.WGPrivKey = b.ForeignWGPriv
			out.WGPubKey = fPub
			out.WGPeerPub = b.IranWGPub
			out.WGPeerPriv = ""
		}
	}
	if isValidIPv4String(b.WGIranIP) && isValidIPv4String(b.WGForeignIP) {
		out.WGLocalIP = b.WGForeignIP
		out.WGPeerIP = b.WGIranIP
	}
	if b.IranNoisePub != "" && b.ForeignNoisePrv != "" {
		if privBytes, err := decodeHexExact(b.ForeignNoisePrv, 32); err == nil {
			if pubBytes, err2 := curve25519ScalarBaseMult(privBytes); err2 == nil {
				out.NoisePrivKey = b.ForeignNoisePrv
				out.NoisePubKey = hex.EncodeToString(pubBytes)
				out.NoisePeerPub = b.IranNoisePub
				out.NoisePeerPriv = ""
			}
		}
	}
	out.LastBundle = trimmed
	out.UpdatedAt = time.Now().Format(time.RFC3339)
	applySpoofNativeRoleDefaults(out)
	return out, nil
}

// ============================================================================
// 2. ISOLATED CONFIG & SYSTEMD GENERATORS (/etc/spoof-m27 & wg-spoof27)
// ============================================================================

func buildSpoofM27CoreConfigMap(s *SpoofNativeConfig) map[string]any {
	applySpoofNativeRoleDefaults(s)
	m := map[string]any{
		"spoof_port":     s.SpoofPort,
		"send_transport": s.SendTransport,
		"recv_transport": s.RecvTransport,
	}
	if len(s.SpoofIPs) == 1 {
		m["spoof_ip"] = s.SpoofIPs[0]
	} else if len(s.SpoofIPs) > 1 {
		m["spoof_ip_file"] = spoofM27IPFilePath()
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
		m["forward"] = fmt.Sprintf("127.0.0.1:%d", s.AdapterPort)
		m["client_ip"] = cleanSpoofHost(s.PeerPublicIP)
		m["client_port"] = s.RecvPort
	}
	return m
}

func buildSpoofM27WGConfigText(s *SpoofNativeConfig) string {
	applySpoofNativeRoleDefaults(s)
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s/24\n", s.WGLocalIP)
	fmt.Fprintf(&b, "PrivateKey = %s\n", s.WGPrivKey)
	fmt.Fprintf(&b, "MTU = %d\n", s.MTU)
	if s.Role == "remote" {
		fmt.Fprintf(&b, "ListenPort = %d\n", s.AdapterPort)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", s.WGPeerPub)
	fmt.Fprintf(&b, "AllowedIPs = %s/32\n", s.WGPeerIP)
	if s.Role == "local" {
		fmt.Fprintf(&b, "Endpoint = 127.0.0.1:%d\n", s.CorePort)
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", s.KeepaliveSec)
	}
	return b.String()
}

func writeSpoofNativeConfigs(s *SpoofNativeConfig) error {
	if s == nil {
		return errors.New("Method 27 config is nil")
	}
	if err := os.MkdirAll(spoofM27Dir, 0700); err != nil {
		return err
	}
	if len(s.SpoofIPs) > 1 {
		if err := os.WriteFile(spoofM27IPFilePath(), []byte(strings.Join(s.SpoofIPs, "\n")+"\n"), 0600); err != nil {
			return err
		}
	}
	coreBytes, err := json.MarshalIndent(buildSpoofM27CoreConfigMap(s), "", "  ")
	if err != nil {
		return err
	}
	tmpCore := spoofM27CoreConfigPath() + ".tmp"
	if err := os.WriteFile(tmpCore, coreBytes, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpCore, spoofM27CoreConfigPath()); err != nil {
		return err
	}

	if s.Mode == "wireguard" {
		if err := os.MkdirAll(wgM27ConfDir, 0700); err != nil {
			return err
		}
		wgPath := spoofM27WGConfPath(s.WGInterface)
		tmpWG := wgPath + ".tmp"
		if err := os.WriteFile(tmpWG, []byte(buildSpoofM27WGConfigText(s)), 0600); err != nil {
			return err
		}
		if err := os.Rename(tmpWG, wgPath); err != nil {
			return err
		}
	}
	return nil
}

func validateSpoofNativeReady(s *SpoofNativeConfig) error {
	if s == nil {
		return errors.New("Method 27 configuration is nil")
	}
	applySpoofNativeRoleDefaults(s)
	if !spoofM27ModeOK(s.Mode) {
		return fmt.Errorf("adapter mode must be one of: %s", strings.Join(spoofM27Modes, ", "))
	}
	if strings.TrimSpace(s.PeerPublicIP) == "" {
		return errors.New("the other server's public IPv4 is not set")
	}
	if !isValidIPv4String(s.PeerPublicIP) {
		return errors.New("the other server's public IP must be a valid IPv4 address (the spoof core operates on IPv4)")
	}
	if len(s.SpoofIPs) == 0 {
		return errors.New("no Spoof Source IPv4 configured: run the Method 27 Spoof IP Tester or enter at least one valid IPv4 address")
	}
	if !spoofTransportOK(s.SendTransport) || !spoofTransportOK(s.RecvTransport) {
		return fmt.Errorf("transports must be one of %s", strings.Join(spoofTransports, ", "))
	}
	if s.Mode == "wireguard" && strings.TrimSpace(s.WGPeerPub) == "" {
		return errors.New("peer WireGuard public key is missing (generate the Method 27 bundle on Master and import it on Agent)")
	}
	if s.Mode == "noise" && strings.TrimSpace(s.NoisePeerPub) == "" {
		return errors.New("peer Noise public key is missing (generate the Method 27 bundle on Master and import it on Agent)")
	}
	return nil
}

func openSpoofM27FirewallPorts(s *SpoofNativeConfig) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || s == nil {
		return
	}
	port := s.RecvPort
	if s.Role == "remote" {
		port = s.SpoofListenPort
	}
	if port <= 0 || port > 65535 {
		return
	}
	pStr := strconv.Itoa(port)
	if _, err := exec.LookPath("ufw"); err == nil {
		_ = exec.Command("ufw", "allow", pStr+"/tcp").Run()
		_ = exec.Command("ufw", "allow", pStr+"/udp").Run()
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		if exec.Command("iptables", "-C", "INPUT", "-p", "tcp", "--dport", pStr, "-j", "ACCEPT").Run() != nil {
			_ = exec.Command("iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", pStr, "-j", "ACCEPT").Run()
		}
		if exec.Command("iptables", "-C", "INPUT", "-p", "udp", "--dport", pStr, "-j", "ACCEPT").Run() != nil {
			_ = exec.Command("iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", pStr, "-j", "ACCEPT").Run()
		}
	}
}

func applyLinuxSpoofNativeServices(s *SpoofNativeConfig) (string, error) {
	if s != nil && s.Role == "local" {
		_ = ensureSpoofNativeKeys(s)
	}
	if err := validateSpoofNativeReady(s); err != nil {
		return "", err
	}
	if err := writeSpoofNativeConfigs(s); err != nil {
		return "", fmt.Errorf("failed to write Method 27 configs: %w", err)
	}
	binPath, binOK, _ := findSpoofBinaryPath()
	if !binOK {
		if s.StrictRealSpoof {
			return "", errors.New("the spoof binary is not installed (click 'Install Spoof Binary' first); refused because Strict Real Spoof mode is enabled")
		}
		s.ServiceEnabled = false
		return "WARNING: The 'spoof' binary is not installed! Configs were saved in /etc/spoof-m27, but REAL SPOOF IS UNAVAILABLE.", nil
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		s.ServiceEnabled = true
		return fmt.Sprintf("Method 27 (%s) configuration written to %s.", strings.ToUpper(s.Mode), spoofM27Dir), nil
	}

	openSpoofM27FirewallPorts(s)

	unitContent := fmt.Sprintf(`[Unit]
Description=Sahand Method 27 Native Spoof Core (%s - %s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s run -c %s
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, s.Role, s.Mode, binPath, spoofM27CoreConfigPath())

	unitPath := filepath.Join("/etc/systemd/system", spoofM27CoreSvc+".service")
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return "", err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if err := exec.Command("systemctl", "restart", spoofM27CoreSvc).Run(); err != nil {
		return "", fmt.Errorf("failed to start %s: %w", spoofM27CoreSvc, err)
	}
	_ = exec.Command("systemctl", "enable", spoofM27CoreSvc).Run()

	wgIface := s.WGInterface
	if strings.TrimSpace(wgIface) == "" || wgIface == spoofIface {
		wgIface = spoofM27Iface
	}
	wgUnit := spoofM27WGUnitTmpl + wgIface

	if s.Mode == "wireguard" {
		ensureWireGuardToolsInstalled()
		if err := exec.Command("systemctl", "restart", wgUnit).Run(); err != nil {
			return "", fmt.Errorf("failed to start Method 27 WireGuard (%s): %w", wgUnit, err)
		}
		_ = exec.Command("systemctl", "enable", wgUnit).Run()
	} else {
		// Ensure wg-spoof27 is stopped when running Pure Spoof, QUIC, or Noise
		_ = exec.Command("systemctl", "disable", "--now", wgUnit).Run()
	}

	s.ServiceEnabled = true
	return fmt.Sprintf("Method 27 (%s mode) spoof-core-m27 started on %s (%s/%s).",
		strings.ToUpper(s.Mode), s.Role, s.SendTransport, s.RecvTransport), nil
}

func stopLinuxSpoofNativeServices(s *SpoofNativeConfig) {
	wgIface := spoofM27Iface
	if s != nil && strings.TrimSpace(s.WGInterface) != "" && s.WGInterface != spoofIface {
		wgIface = strings.TrimSpace(s.WGInterface)
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		_ = exec.Command("systemctl", "disable", "--now", spoofM27WGUnitTmpl+wgIface).Run()
		_ = exec.Command("systemctl", "disable", "--now", spoofM27CoreSvc).Run()
	}
	if s != nil {
		s.ServiceEnabled = false
	}
}

// ============================================================================
// 3. INDEPENDENT METHOD 27 SPOOF IP TESTER (/etc/spoof-m27/tester-sources.txt)
// ============================================================================

var (
	spoofM27TesterMu     sync.Mutex
	spoofM27TesterCur    = SpoofTesterStatus{Status: "idle", Passed: []SpoofTesterResult{}}
	spoofM27TesterCancel context.CancelFunc
	spoofM27TesterStart  time.Time
	spoofM27TesterDur    time.Duration
	spoofM27TesterWG     sync.WaitGroup
)

func getSpoofM27TesterStatusView() SpoofTesterStatus {
	spoofM27TesterMu.Lock()
	defer spoofM27TesterMu.Unlock()
	st := spoofM27TesterCur
	if st.Status == "running" && spoofM27TesterDur > 0 {
		p := int(time.Since(spoofM27TesterStart) * 100 / spoofM27TesterDur)
		if p > 99 {
			p = 99
		}
		if p < 0 {
			p = 0
		}
		st.Progress = p
	}
	if st.Passed == nil {
		st.Passed = []SpoofTesterResult{}
	}
	return st
}

func startSpoofM27TesterProcess(req SpoofTesterRequest) error {
	req = req.normalize()
	if req.Mode != "sender" && req.Mode != "receiver" {
		return errors.New("tester mode must be sender or receiver")
	}
	if req.Mode == "sender" && cleanSpoofHost(req.DstIP) == "" {
		return errors.New("destination IP (the receiver server's IPv4) is required in sender mode")
	}
	var cleanedSources []string
	for _, s := range req.Sources {
		for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				cleanedSources = append(cleanedSources, trimmed)
			}
		}
	}
	if len(cleanedSources) == 0 {
		return errors.New("add at least one source IP, range, or CIDR to test")
	}
	binPath, binOK, _ := findSpoofBinaryPath()
	if !binOK {
		return errors.New("the spoof binary is not installed (click 'Install Spoof Binary' first)")
	}

	spoofM27TesterMu.Lock()
	if spoofM27TesterCur.Status == "running" {
		spoofM27TesterMu.Unlock()
		return errors.New("a Method 27 spoof tester run is already in progress")
	}
	if err := os.MkdirAll(spoofM27Dir, 0700); err != nil {
		spoofM27TesterMu.Unlock()
		return err
	}
	srcFile := filepath.Join(spoofM27Dir, "tester-sources.txt")
	if err := os.WriteFile(srcFile, []byte(strings.Join(cleanedSources, "\n")+"\n"), 0600); err != nil {
		spoofM27TesterMu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	spoofM27TesterCancel = cancel
	spoofM27TesterStart = time.Now()
	spoofM27TesterDur = time.Duration(req.Timeout) * time.Second
	spoofM27TesterCur = SpoofTesterStatus{
		Status:   "running",
		Mode:     req.Mode,
		Protocol: req.Protocol,
		Started:  spoofM27TesterStart.Format(time.RFC3339),
		Passed:   []SpoofTesterResult{},
	}
	spoofM27TesterMu.Unlock()

	args := []string{
		"tester",
		"--mode", req.Mode,
		"--protocol", req.Protocol,
		"--src-list", srcFile,
		"--timeout", strconv.Itoa(req.Timeout),
		"--packet-count", strconv.Itoa(req.PacketCount),
		"--max-loss", strconv.FormatFloat(req.MaxLoss, 'f', -1, 64),
	}
	if req.Mode == "sender" {
		args = append(args, "--dst-ip", cleanSpoofHost(req.DstIP), "--dst-port", strconv.Itoa(req.DstPort))
	}

	spoofM27TesterWG.Add(1)
	go func() {
		defer spoofM27TesterWG.Done()
		cmd := exec.CommandContext(ctx, binPath, args...)
		outBytes, err := cmd.CombinedOutput()
		out := string(outBytes)
		passed := parseSpoofTesterOutput(out)

		spoofM27TesterMu.Lock()
		defer spoofM27TesterMu.Unlock()
		if ctx.Err() != nil {
			return
		}
		spoofM27TesterCancel = nil
		spoofM27TesterCur.Finished = time.Now().Format(time.RFC3339)
		spoofM27TesterCur.Progress = 100
		spoofM27TesterCur.Passed = passed
		if err != nil {
			spoofM27TesterCur.Status = "error"
			spoofM27TesterCur.Error = extractSpoofTesterErr(out, err)
			return
		}
		spoofM27TesterCur.Status = "done"
	}()
	return nil
}

func stopSpoofM27TesterProcess() {
	spoofM27TesterMu.Lock()
	cancel := spoofM27TesterCancel
	if spoofM27TesterCur.Status == "running" {
		spoofM27TesterCur.Status = "stopped"
		spoofM27TesterCur.Finished = time.Now().Format(time.RFC3339)
	}
	spoofM27TesterMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func clearSpoofM27TesterStatus() {
	spoofM27TesterMu.Lock()
	if spoofM27TesterCur.Status != "running" {
		spoofM27TesterCur = SpoofTesterStatus{Status: "idle", Passed: []SpoofTesterResult{}}
	}
	spoofM27TesterMu.Unlock()
}

// ============================================================================
// 4. METHOD 27 ADAPTERS (PURE SPOOF, WIREGUARD, QUIC, NOISE) & END-TO-END VERIFICATION
// ============================================================================

type spoofNativeSessionVerifyState struct {
	mu               sync.RWMutex
	lastVerifiedUnix int64
	lastVerifiedMode string
	lastVerifiedPath string // "SPOOF_PIPE" or "DIRECT_FALLBACK"
	lastRTTMS        int64
	lastLossPct      int
	lastError        string
}

var (
	spoofNativeVerifyMu sync.RWMutex
	spoofNativeVerify   = make(map[string]*spoofNativeSessionVerifyState)
)

func getOrCreateSpoofNativeVerifyState(peerID string) *spoofNativeSessionVerifyState {
	spoofNativeVerifyMu.Lock()
	defer spoofNativeVerifyMu.Unlock()
	st, ok := spoofNativeVerify[peerID]
	if !ok {
		st = &spoofNativeSessionVerifyState{}
		spoofNativeVerify[peerID] = st
	}
	return st
}

func recordSpoofNativeVerification(peerID, mode, pathUsed string, rttMS int64, lossPct int, errReason string) {
	st := getOrCreateSpoofNativeVerifyState(peerID)
	st.mu.Lock()
	defer st.mu.Unlock()
	if errReason == "" {
		st.lastVerifiedUnix = time.Now().Unix()
		st.lastVerifiedMode = mode
		st.lastVerifiedPath = pathUsed
		st.lastRTTMS = rttMS
		st.lastLossPct = lossPct
		st.lastError = ""
	} else {
		st.lastError = errReason
	}
}

func querySpoofNativeRuntimeHealth(peerID string, s *SpoofNativeConfig) SpoofNativeHealth {
	binPath, binOK, shaOK := findSpoofBinaryPath()
	wgToolsOK := checkWireGuardToolsInstalled()
	mode := "pure"
	if s != nil && spoofM27ModeOK(s.Mode) {
		mode = s.Mode
	}

	h := SpoofNativeHealth{
		BinaryInstalled: binOK,
		BinarySHA256OK:  shaOK,
		WGToolsPresent:  wgToolsOK,
		ActiveAdapter:   mode,
		ConnectionState: "DISCONNECTED",
		StatusBadge:     "DISCONNECTED",
		ActivePath:      "NONE",
	}
	if binOK {
		if out, err := exec.Command(binPath, "--version").Output(); err == nil {
			if v := strings.TrimSpace(string(out)); v != "" {
				h.BinaryVersion = v
			}
		}
		if h.BinaryVersion == "" {
			h.BinaryVersion = defaultSpoofVersion
		}
	}
	if s != nil && s.LastError != "" {
		h.LastError = s.LastError
	}
	if mode == "pure" {
		h.SecurityNote = "Pure Spoof (Native UDP Pipe) does NOT encrypt payload data. Inner traffic should provide its own encryption (e.g., TLS/Xray/SSH), or select Spoof + WireGuard / QUIC / Noise."
	}

	if runtime.GOOS == "linux" {
		if exec.Command("systemctl", "is-active", "--quiet", spoofM27CoreSvc).Run() == nil {
			h.CoreActive = true
		}
		if mode == "wireguard" {
			iface := spoofM27Iface
			if s != nil && strings.TrimSpace(s.WGInterface) != "" && s.WGInterface != spoofIface {
				iface = strings.TrimSpace(s.WGInterface)
			}
			if exec.Command("systemctl", "is-active", "--quiet", spoofM27WGUnitTmpl+iface).Run() == nil {
				h.WGActive = true
			}
			if out, err := exec.Command("wg", "show", iface, "latest-handshakes").Output(); err == nil {
				fields := strings.Fields(strings.TrimSpace(string(out)))
				if len(fields) >= 2 {
					if ts, err := strconv.ParseInt(fields[len(fields)-1], 10, 64); err == nil && ts > 0 {
						age := time.Since(time.Unix(ts, 0))
						h.Handshake = age.Truncate(time.Second).String() + " ago"
					}
				}
			}
		}
	}

	vst := getOrCreateSpoofNativeVerifyState(peerID)
	vst.mu.RLock()
	lastUnix := vst.lastVerifiedUnix
	lastPath := vst.lastVerifiedPath
	lastRTT := vst.lastRTTMS
	lastLoss := vst.lastLossPct
	lastErr := vst.lastError
	vst.mu.RUnlock()

	freshPipeVerify := lastUnix > 0 && time.Since(time.Unix(lastUnix, 0)) < 3*time.Minute

	switch {
	case freshPipeVerify && lastPath == "SPOOF_PIPE":
		h.EndToEndVerified = true
		h.RealSpoofActive = true
		h.ConnectionState = "REAL SPOOF ACTIVE"
		h.StatusBadge = fmt.Sprintf("REAL SPOOF ACTIVE (%s)", strings.ToUpper(mode))
		h.ActivePath = fmt.Sprintf("SPOOF_PIPE (%s • %dms)", strings.ToUpper(mode), lastRTT)
		h.LastRTTMS = lastRTT
		h.PacketLossPct = lastLoss
		h.LastVerifiedAt = time.Unix(lastUnix, 0).Format("15:04:05")

	case freshPipeVerify && lastPath == "DIRECT_FALLBACK":
		h.EndToEndVerified = false
		h.RealSpoofActive = false
		h.ConnectionState = "DIRECT FALLBACK"
		h.StatusBadge = "DIRECT FALLBACK (NOT SPOOFING)"
		h.ActivePath = fmt.Sprintf("DIRECT_FALLBACK (%s • %dms)", strings.ToUpper(mode), lastRTT)
		h.LastRTTMS = lastRTT
		h.PacketLossPct = lastLoss
		h.WarningBanner = "Traffic is currently traversing a direct unspoofed fallback path because Strict Real Spoof is disabled and the Spoof Pipe did not answer."

	case !binOK:
		h.ConnectionState = "SPOOF FAILED"
		h.StatusBadge = "SPOOF UNAVAILABLE (BINARY MISSING)"
		h.WarningBanner = "The official 'spoof' v3.0.2 binary is not installed. Click 'Install Spoof Binary' to enable Method 27."

	case s != nil && len(s.SpoofIPs) == 0:
		h.ConnectionState = "DISCONNECTED"
		h.StatusBadge = "NO SPOOF IP CONFIGURED"
		h.WarningBanner = "Enter at least one Spoof Source IPv4 address (or run the Spoof IP Tester) and click Save."

	case lastErr != "":
		h.ConnectionState = "SPOOF FAILED"
		h.StatusBadge = "SPOOF FAILED"
		h.LastError = lastErr
		h.WarningBanner = "End-to-end Spoof Pipe verification failed: " + lastErr

	case h.CoreActive:
		h.ConnectionState = "SPOOF CONNECTING"
		h.StatusBadge = "SPOOF CONNECTING (UNVERIFIED)"
		h.WarningBanner = "spoof-core-m27 is running, awaiting end-to-end Spoof Pipe verification (click 'Ping / Verify Pipe')."

	default:
		h.ConnectionState = "DISCONNECTED"
		h.StatusBadge = "DISCONNECTED"
	}

	return h
}

// ============================================================================
// 5. RUNTIME LISTENERS & ADAPTER ENGINES FOR METHOD 27
// ============================================================================

type spoofM27Stream struct {
	id         uint32
	targetPort uint16
	remoteAddr *net.UDPAddr
	rxCh       chan []byte
	reorder    *m27StreamReorderBuffer
	closeMu    sync.Mutex
	closed     atomic.Bool
	closeOnce  sync.Once
}

func (s *spoofM27Stream) deliverInOrder(seq uint32, payload []byte) {
	chunks := s.reorder.InsertAndDrain(seq, payload)
	if len(chunks) == 0 {
		return
	}
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed.Load() {
		return
	}
	for _, ch := range chunks {
		s.rxCh <- ch
	}
}

func (s *spoofM27Stream) close() {
	s.closeOnce.Do(func() {
		s.closeMu.Lock()
		s.closed.Store(true)
		close(s.rxCh)
		s.closeMu.Unlock()
	})
}

type spoofNativeRuntime struct {
	peerID        string
	peer          ServerPeer
	tunnel        TunnelConfig
	subKey        []byte
	udpPipeConn   *net.UDPConn
	fallbackUDP   *net.UDPConn
	wgOverlayLn   net.Listener
	quicUdpConn   *net.UDPConn
	quicListener  *quicListenerWrapper
	udpEntries    []*net.UDPConn
	streamsMu     sync.RWMutex
	streams       map[uint32]*spoofM27Stream
	pingWaitersMu sync.Mutex
	pingWaiters   map[uint64]chan []byte
	noiseSessions sync.Map // map[uint32]*spoofM27NoiseSession
	closed        atomic.Bool
}

type quicListenerWrapper struct {
	io.Closer
}

type spoofM27NoiseSession struct {
	sessionID uint32
	sendAEAD  cipher.AEAD
	recvAEAD  cipher.AEAD
	sendNonce atomic.Uint64
	replayWin *m27ReplayWindow
	createdAt time.Time
}

var (
	spoofNativeRuntimeMu sync.RWMutex
	spoofNativeRuntimes  = make(map[string]*spoofNativeRuntime)
)

func stopSpoofNativePeerResources(peerID string) {
	spoofNativeRuntimeMu.Lock()
	rt, ok := spoofNativeRuntimes[peerID]
	if ok {
		delete(spoofNativeRuntimes, peerID)
	}
	spoofNativeRuntimeMu.Unlock()

	if rt != nil && !rt.closed.Swap(true) {
		if rt.udpPipeConn != nil {
			_ = rt.udpPipeConn.Close()
		}
		if rt.fallbackUDP != nil {
			_ = rt.fallbackUDP.Close()
		}
		if rt.wgOverlayLn != nil {
			_ = rt.wgOverlayLn.Close()
		}
		if rt.quicListener != nil && rt.quicListener.Closer != nil {
			_ = rt.quicListener.Closer.Close()
		}
		if rt.quicUdpConn != nil {
			_ = rt.quicUdpConn.Close()
		}
		for _, u := range rt.udpEntries {
			_ = u.Close()
		}
		rt.streamsMu.Lock()
		for _, st := range rt.streams {
			st.close()
		}
		rt.streamsMu.Unlock()
	}
}

// Packet wire format for Mode 1 (Pure Spoof) & inner Mode 4 (Noise):
// [Magic: 4B "M27P"][Type: 1B][StreamID: 4B][Seq: 4B][Port: 2B][Len: 2B][HMAC16: 16B][Payload]
const m27DatagramHdrSize = 4 + 1 + 4 + 4 + 2 + 2 + 16 // 33 bytes

func encodeM27Datagram(subKey []byte, pktType byte, streamID, seq uint32, port uint16, payload []byte) []byte {
	out := make([]byte, m27DatagramHdrSize+len(payload))
	copy(out[0:4], m27FrameMagic)
	out[4] = pktType
	binary.BigEndian.PutUint32(out[5:9], streamID)
	binary.BigEndian.PutUint32(out[9:13], seq)
	binary.BigEndian.PutUint16(out[13:15], port)
	binary.BigEndian.PutUint16(out[15:17], uint16(len(payload)))
	copy(out[m27DatagramHdrSize:], payload)

	mac := hmac.New(sha256.New, subKey)
	_, _ = mac.Write(out[0:17])
	_, _ = mac.Write(payload)
	sum := mac.Sum(nil)
	copy(out[17:33], sum[:16])
	return out
}

func decodeM27Datagram(subKey []byte, raw []byte) (pktType byte, streamID, seq uint32, port uint16, payload []byte, err error) {
	if len(raw) < m27DatagramHdrSize {
		return 0, 0, 0, 0, nil, errors.New("frame too short")
	}
	if string(raw[0:4]) != m27FrameMagic {
		return 0, 0, 0, 0, nil, errors.New("invalid magic")
	}
	pktType = raw[4]
	streamID = binary.BigEndian.Uint32(raw[5:9])
	seq = binary.BigEndian.Uint32(raw[9:13])
	port = binary.BigEndian.Uint16(raw[13:15])
	pLen := int(binary.BigEndian.Uint16(raw[15:17]))
	if m27DatagramHdrSize+pLen > len(raw) {
		return 0, 0, 0, 0, nil, errors.New("truncated payload")
	}
	payload = raw[m27DatagramHdrSize : m27DatagramHdrSize+pLen]

	mac := hmac.New(sha256.New, subKey)
	_, _ = mac.Write(raw[0:17])
	_, _ = mac.Write(payload)
	sum := mac.Sum(nil)
	if subtle.ConstantTimeCompare(raw[17:33], sum[:16]) != 1 {
		return 0, 0, 0, 0, nil, errors.New("HMAC verification failed")
	}
	return pktType, streamID, seq, port, payload, nil
}

// Noise Mode Envelope over UDP Pipe:
// - Init:   [0x11][SessionID:4B][EphemeralPub:32B][Timestamp:8B][HMAC:32B]
// - Resp:   [0x12][SessionID:4B][EphemeralPub:32B][HMAC:32B]
// - Packet: [0x13][SessionID:4B][Nonce:8B][ChaCha20Poly1305 Ciphertext of M27Datagram]
func deriveM27NoiseSessionKeys(subKey []byte, sessionID uint32, clientEph, serverEph []byte) (c2s cipher.AEAD, s2c cipher.AEAD, err error) {
	h1 := hmac.New(sha256.New, subKey)
	_, _ = h1.Write([]byte("m27-noise-ikpsk2-c2s|"))
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], sessionID)
	_, _ = h1.Write(sid[:])
	_, _ = h1.Write(clientEph)
	_, _ = h1.Write(serverEph)
	k1 := h1.Sum(nil)

	h2 := hmac.New(sha256.New, subKey)
	_, _ = h2.Write([]byte("m27-noise-ikpsk2-s2c|"))
	_, _ = h2.Write(sid[:])
	_, _ = h2.Write(clientEph)
	_, _ = h2.Write(serverEph)
	k2 := h2.Sum(nil)

	a1, err := chacha20poly1305.New(k1)
	if err != nil {
		return nil, nil, err
	}
	a2, err := chacha20poly1305.New(k2)
	if err != nil {
		return nil, nil, err
	}
	return a1, a2, nil
}

func startSpoofNativeServer(peer ServerPeer, tc TunnelConfig) (net.Listener, net.PacketConn, error) {
	stopSpoofNativePeerResources(peer.ID)

	if tc.SpoofNative == nil {
		tc.SpoofNative = defaultSpoofNativeConfig()
	}
	if tc.SpoofNative.PeerPublicIP == "" && isValidIPv4String(peer.IP) {
		tc.SpoofNative.PeerPublicIP = peer.IP
	}
	tc.SpoofNative = normalizeSpoofNativeConfig(tc.SpoofNative)

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	subKey, err := derivePeerSubKey(cfgSnapshot, peer, "sahand-method27-native-v1")
	if err != nil {
		return nil, nil, err
	}

	rt := &spoofNativeRuntime{
		peerID:      peer.ID,
		peer:        peer,
		tunnel:      tc,
		subKey:      subKey,
		streams:     make(map[uint32]*spoofM27Stream),
		pingWaiters: make(map[uint64]chan []byte),
	}

	mode := tc.SpoofNative.Mode

	if fbAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))); err == nil {
		if fbConn, err := net.ListenUDP("udp", fbAddr); err == nil {
			configureUDPSocketBuffers(fbConn)
			rt.fallbackUDP = fbConn
			go rt.readDatagramLoop(fbConn, "DIRECT_FALLBACK")
		}
	}

	switch mode {
	case "pure", "noise":
		pipeBindHost := "127.0.0.1"
		pipeBindPort := tc.SpoofNative.AdapterPort
		if uAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(pipeBindHost, strconv.Itoa(pipeBindPort))); err == nil {
			if pConn, err := net.ListenUDP("udp", uAddr); err == nil {
				configureUDPSocketBuffers(pConn)
				rt.udpPipeConn = pConn
				go rt.readDatagramLoop(pConn, "SPOOF_PIPE")
			}
		}

	case "wireguard":
		lnAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
		if ln, err := net.Listen("tcp", lnAddr); err == nil {
			rt.wgOverlayLn = ln
			go rt.acceptWGOverlayLoop(ln)
		}

	case "quic":
		pipeAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(tc.SpoofNative.AdapterPort))
		if uAddr, err := net.ResolveUDPAddr("udp", pipeAddr); err == nil {
			if uConn, err := net.ListenUDP("udp", uAddr); err == nil {
				configureUDPSocketBuffers(uConn)
				rt.quicUdpConn = uConn
				go rt.readDatagramLoop(uConn, "SPOOF_PIPE")
			}
		}
	}

	spoofNativeRuntimeMu.Lock()
	spoofNativeRuntimes[peer.ID] = rt
	spoofNativeRuntimeMu.Unlock()

	return rt.wgOverlayLn, rt.fallbackUDP, nil
}

func (rt *spoofNativeRuntime) readDatagramLoop(conn *net.UDPConn, pathTag string) {
	buf := make([]byte, 65535)
	for !rt.closed.Load() {
		n, rAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		addrCopy := cloneUDPAddr(rAddr)
		// Process inline for ordering; blocking dial operations spawn their own goroutine inside handleIncomingDatagram
		rt.handleIncomingDatagram(conn, addrCopy, pkt, pathTag)
	}
}

func (rt *spoofNativeRuntime) handleIncomingDatagram(conn *net.UDPConn, rAddr *net.UDPAddr, raw []byte, pathTag string) {
	if len(raw) < 5 {
		return
	}
	mode := "pure"
	strict := true
	if rt.tunnel.SpoofNative != nil {
		mode = rt.tunnel.SpoofNative.Mode
		strict = rt.tunnel.SpoofNative.StrictRealSpoof
	}
	if strict && pathTag == "DIRECT_FALLBACK" {
		return
	}

	var activeNoise *spoofM27NoiseSession
	if raw[0] == m27NoiseInit && len(raw) >= 1+4+32+8+32 {
		sid := binary.BigEndian.Uint32(raw[1:5])
		cliEph := raw[5:37]
		mac := hmac.New(sha256.New, rt.subKey)
		_, _ = mac.Write(raw[0:45])
		if subtle.ConstantTimeCompare(raw[45:77], mac.Sum(nil)) != 1 {
			return
		}
		var srvEph [32]byte
		_, _ = rand.Read(srvEph[:])
		c2s, s2c, err := deriveM27NoiseSessionKeys(rt.subKey, sid, cliEph, srvEph[:])
		if err != nil {
			return
		}
		sess := &spoofM27NoiseSession{
			sessionID: sid,
			sendAEAD:  s2c,
			recvAEAD:  c2s,
			replayWin: &m27ReplayWindow{},
			createdAt: time.Now(),
		}
		rt.noiseSessions.Store(sid, sess)

		resp := make([]byte, 1+4+32+32)
		resp[0] = m27NoiseResp
		binary.BigEndian.PutUint32(resp[1:5], sid)
		copy(resp[5:37], srvEph[:])
		rmac := hmac.New(sha256.New, rt.subKey)
		_, _ = rmac.Write(resp[0:37])
		copy(resp[37:69], rmac.Sum(nil))
		_, _ = conn.WriteToUDP(resp, rAddr)
		return
	}

	if raw[0] == m27NoisePacket {
		if len(raw) < 1+4+8+chacha20poly1305.Overhead {
			return
		}
		sid := binary.BigEndian.Uint32(raw[1:5])
		nonceVal := binary.BigEndian.Uint64(raw[5:13])
		val, ok := rt.noiseSessions.Load(sid)
		if !ok {
			return
		}
		sess := val.(*spoofM27NoiseSession)
		if !sess.replayWin.CheckAndAccept(nonceVal) {
			return
		}
		var nonce [12]byte
		binary.BigEndian.PutUint32(nonce[0:4], sid)
		binary.BigEndian.PutUint64(nonce[4:12], nonceVal)
		plain, err := sess.recvAEAD.Open(nil, nonce[:], raw[13:], raw[0:13])
		if err != nil {
			return
		}
		raw = plain
		activeNoise = sess
	} else if mode == "noise" {
		return
	}

	sendReply := func(frame []byte) {
		if activeNoise != nil {
			seq := activeNoise.sendNonce.Add(1)
			var nonce [12]byte
			binary.BigEndian.PutUint32(nonce[0:4], activeNoise.sessionID)
			binary.BigEndian.PutUint64(nonce[4:12], seq)
			hdr := make([]byte, 13)
			hdr[0] = m27NoisePacket
			binary.BigEndian.PutUint32(hdr[1:5], activeNoise.sessionID)
			binary.BigEndian.PutUint64(hdr[5:13], seq)
			ct := activeNoise.sendAEAD.Seal(nil, nonce[:], frame, hdr)
			frame = append(hdr, ct...)
		}
		_, _ = conn.WriteToUDP(frame, rAddr)
	}

	pktType, streamID, seq, port, payload, err := decodeM27Datagram(rt.subKey, raw)
	if err != nil {
		return
	}

	switch pktType {
	case m27FrameTypePing:
		replyPayload := append([]byte(pathTag+"|"), payload...)
		pong := encodeM27Datagram(rt.subKey, m27FrameTypePong, streamID, seq, port, replyPayload)
		sendReply(pong)
		recordSpoofNativeVerification(rt.peerID, mode, pathTag, 1, 0, "")
		markPeerConnectedInbound(rt.peer.ID, extractRemoteHostIP(rAddr), rt.tunnel.ID, rt.tunnel.ListenPort, 1)

	case m27FrameTypeSyncReq:
		var pkt SyncPacket
		if json.Unmarshal(payload, &pkt) != nil {
			return
		}
		resp := processIncomingSync(rt.peer.ID, extractRemoteHostIP(rAddr), pkt)
		respBytes, _ := json.Marshal(resp)
		rep := encodeM27Datagram(rt.subKey, m27FrameTypeSyncRep, streamID, seq, port, respBytes)
		sendReply(rep)

	case m27FrameTypeSyn:
		if !rt.tunnel.Enabled {
			fin := encodeM27Datagram(rt.subKey, m27FrameTypeFin, streamID, seq, port, nil)
			sendReply(fin)
			return
		}
		authorizedPort, err := authorizeWSSTargetPort(rt.tunnel, strconv.Itoa(int(port)))
		if err != nil {
			fin := encodeM27Datagram(rt.subKey, m27FrameTypeFin, streamID, seq, port, nil)
			sendReply(fin)
			return
		}
		targetConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", authorizedPort), 4*time.Second)
		if err != nil {
			fin := encodeM27Datagram(rt.subKey, m27FrameTypeFin, streamID, seq, port, nil)
			sendReply(fin)
			return
		}
		enableKeepAlive(targetConn)

		st := &spoofM27Stream{
			id:         streamID,
			targetPort: port,
			remoteAddr: rAddr,
			rxCh:       make(chan []byte, 1024),
			reorder:    newM27StreamReorderBuffer(),
		}
		rt.streamsMu.Lock()
		rt.streams[streamID] = st
		rt.streamsMu.Unlock()

		synAck := encodeM27Datagram(rt.subKey, m27FrameTypeSynAck, streamID, 0, port, nil)
		sendReply(synAck)

		go rt.bridgeM27StreamAndTarget(st, targetConn, sendReply)

	case m27FrameTypeData:
		rt.streamsMu.RLock()
		st, ok := rt.streams[streamID]
		rt.streamsMu.RUnlock()
		if !ok || st.closed.Load() {
			return
		}
		atomic.AddUint64(&appRxBytes, uint64(len(payload)))
		st.deliverInOrder(seq, payload)

	case m27FrameTypeFin:
		rt.streamsMu.Lock()
		st, ok := rt.streams[streamID]
		if ok {
			delete(rt.streams, streamID)
		}
		rt.streamsMu.Unlock()
		if st != nil {
			st.close()
		}

	case m27FrameTypeUDP:
		if !rt.tunnel.Enabled {
			return
		}
		authorizedPort, err := authorizeWSSTargetPort(rt.tunnel, strconv.Itoa(int(port)))
		if err != nil {
			return
		}
		dgramCopy := make([]byte, len(payload))
		copy(dgramCopy, payload)
		go func() {
			atomic.AddUint64(&appRxBytes, uint64(len(dgramCopy)))
			uConn, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", authorizedPort), 3*time.Second)
			if err != nil {
				return
			}
			defer uConn.Close()
			_ = uConn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := uConn.Write(dgramCopy); err != nil {
				return
			}
			repBuf := make([]byte, 16384)
			n, err := uConn.Read(repBuf)
			if err == nil && n > 0 {
				atomic.AddUint64(&appTxBytes, uint64(n))
				repFrame := encodeM27Datagram(rt.subKey, m27FrameTypeUDP, streamID, seq, port, repBuf[:n])
				sendReply(repFrame)
			}
		}()
	}
}

func (rt *spoofNativeRuntime) bridgeM27StreamAndTarget(st *spoofM27Stream, target net.Conn, sendFn func([]byte)) {
	defer func() {
		_ = target.Close()
		rt.streamsMu.Lock()
		delete(rt.streams, st.id)
		rt.streamsMu.Unlock()
		st.close()
		fin := encodeM27Datagram(rt.subKey, m27FrameTypeFin, st.id, 0, st.targetPort, nil)
		sendFn(fin)
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for chunk := range st.rxCh {
			if _, err := target.Write(chunk); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1100)
		var seq uint32
		for {
			n, err := target.Read(buf)
			if n > 0 {
				seq++
				atomic.AddUint64(&appTxBytes, uint64(n))
				frame := encodeM27Datagram(rt.subKey, m27FrameTypeData, st.id, seq, st.targetPort, buf[:n])
				sendFn(frame)
			}
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// ============================================================================
// 6. CLIENT DIALING & PROBING ACROSS ALL 4 MODES (PURE, WIREGUARD, QUIC, NOISE)
// ============================================================================

func dialM27UDPPipeSocket(peer ServerPeer, tc TunnelConfig, timeout time.Duration) (*net.UDPConn, string, *spoofM27NoiseSession, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	subKey, err := derivePeerSubKey(cfgSnapshot, peer, "sahand-method27-native-v1")
	if err != nil {
		return nil, "", nil, err
	}

	s := normalizeSpoofNativeConfig(tc.SpoofNative)
	strict := s.StrictRealSpoof

	type candidateTarget struct {
		addr    string
		pathTag string
	}

	var candidates []candidateTarget
	candidates = append(candidates, candidateTarget{
		addr:    net.JoinHostPort("127.0.0.1", strconv.Itoa(s.CorePort)),
		pathTag: "SPOOF_PIPE",
	})
	if !strict && strings.TrimSpace(peer.IP) != "" {
		candidates = append(candidates, candidateTarget{
			addr:    net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort)),
			pathTag: "DIRECT_FALLBACK",
		})
	}

	var lastErr error
	for _, cand := range candidates {
		rAddr, err := net.ResolveUDPAddr("udp", cand.addr)
		if err != nil {
			lastErr = err
			continue
		}
		uConn, err := net.DialUDP("udp", nil, rAddr)
		if err != nil {
			lastErr = err
			continue
		}
		configureUDPSocketBuffers(uConn)
		_ = uConn.SetDeadline(time.Now().Add(timeout))

		if s.Mode == "noise" {
			sess, nErr := performM27NoiseClientHandshake(uConn, subKey, timeout)
			if nErr != nil {
				_ = uConn.Close()
				lastErr = nErr
				continue
			}
			return uConn, cand.pathTag, sess, nil
		}
		return uConn, cand.pathTag, nil, nil
	}

	if lastErr == nil {
		lastErr = errors.New("spoof pipe unreachable")
	}
	return nil, "", nil, lastErr
}

func performM27NoiseClientHandshake(uConn *net.UDPConn, subKey []byte, timeout time.Duration) (*spoofM27NoiseSession, error) {
	_ = uConn.SetDeadline(time.Now().Add(timeout))
	var sidBytes [4]byte
	_, _ = rand.Read(sidBytes[:])
	sid := binary.BigEndian.Uint32(sidBytes[:])
	if sid == 0 {
		sid = 1
	}
	var cliEph [32]byte
	_, _ = rand.Read(cliEph[:])

	initPkt := make([]byte, 1+4+32+8+32)
	initPkt[0] = m27NoiseInit
	binary.BigEndian.PutUint32(initPkt[1:5], sid)
	copy(initPkt[5:37], cliEph[:])
	binary.BigEndian.PutUint64(initPkt[37:45], uint64(time.Now().Unix()))
	mac := hmac.New(sha256.New, subKey)
	_, _ = mac.Write(initPkt[0:45])
	copy(initPkt[45:77], mac.Sum(nil))

	if _, err := uConn.Write(initPkt); err != nil {
		return nil, err
	}

	resp := make([]byte, 2048)
	n, err := uConn.Read(resp)
	if err != nil {
		return nil, err
	}
	if n < 69 || resp[0] != m27NoiseResp || binary.BigEndian.Uint32(resp[1:5]) != sid {
		return nil, errors.New("invalid Noise handshake response")
	}
	rmac := hmac.New(sha256.New, subKey)
	_, _ = rmac.Write(resp[0:37])
	if subtle.ConstantTimeCompare(resp[37:69], rmac.Sum(nil)) != 1 {
		return nil, errors.New("Noise response MAC verification failed")
	}
	srvEph := resp[5:37]
	c2s, s2c, err := deriveM27NoiseSessionKeys(subKey, sid, cliEph[:], srvEph)
	if err != nil {
		return nil, err
	}
	return &spoofM27NoiseSession{
		sessionID: sid,
		sendAEAD:  c2s,
		recvAEAD:  s2c,
		replayWin: &m27ReplayWindow{},
		createdAt: time.Now(),
	}, nil
}

func sendM27FrameOverConn(uConn *net.UDPConn, sess *spoofM27NoiseSession, frame []byte) error {
	if sess != nil {
		seq := sess.sendNonce.Add(1)
		var nonce [12]byte
		binary.BigEndian.PutUint32(nonce[0:4], sess.sessionID)
		binary.BigEndian.PutUint64(nonce[4:12], seq)
		hdr := make([]byte, 13)
		hdr[0] = m27NoisePacket
		binary.BigEndian.PutUint32(hdr[1:5], sess.sessionID)
		binary.BigEndian.PutUint64(hdr[5:13], seq)
		ct := sess.sendAEAD.Seal(nil, nonce[:], frame, hdr)
		frame = append(hdr, ct...)
	}
	_, err := uConn.Write(frame)
	return err
}

func readM27FrameFromConn(uConn *net.UDPConn, sess *spoofM27NoiseSession, subKey []byte) (byte, uint32, uint32, uint16, []byte, error) {
	buf := make([]byte, 65535)
	n, err := uConn.Read(buf)
	if err != nil {
		return 0, 0, 0, 0, nil, err
	}
	raw := buf[:n]
	if sess != nil {
		if len(raw) < 13+chacha20poly1305.Overhead || raw[0] != m27NoisePacket {
			return 0, 0, 0, 0, nil, errors.New("unexpected non-Noise packet")
		}
		sid := binary.BigEndian.Uint32(raw[1:5])
		nonceVal := binary.BigEndian.Uint64(raw[5:13])
		if sid != sess.sessionID || !sess.replayWin.CheckAndAccept(nonceVal) {
			return 0, 0, 0, 0, nil, errors.New("Noise replay or session mismatch")
		}
		var nonce [12]byte
		binary.BigEndian.PutUint32(nonce[0:4], sid)
		binary.BigEndian.PutUint64(nonce[4:12], nonceVal)
		plain, err := sess.recvAEAD.Open(nil, nonce[:], raw[13:], raw[0:13])
		if err != nil {
			return 0, 0, 0, 0, nil, err
		}
		raw = plain
	}
	return decodeM27Datagram(subKey, raw)
}

type m27WGOverlayHeader struct {
	Magic      string `json:"m"`
	Cmd        byte   `json:"c"`
	PeerID     string `json:"p"`
	TargetPort int    `json:"tp,omitempty"`
	TimeHdr    string `json:"th,omitempty"`
	Nonce      string `json:"n"`
	MAC        string `json:"mac"`
}

func computeM27WGOverlayMAC(subKey []byte, h m27WGOverlayHeader) string {
	mac := hmac.New(sha256.New, subKey)
	_, _ = mac.Write([]byte(fmt.Sprintf("%s|%d|%s|%d|%s", h.Magic, h.Cmd, h.PeerID, h.TargetPort, h.Nonce)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (rt *spoofNativeRuntime) acceptWGOverlayLoop(ln net.Listener) {
	for !rt.closed.Load() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		enableKeepAlive(conn)
		go rt.handleWGOverlayConn(conn)
	}
}

func (rt *spoofNativeRuntime) handleWGOverlayConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

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
	var hdr m27WGOverlayHeader
	if unmarshalStrictJSON(hBytes, &hdr) != nil || hdr.Magic != m27OverlayMagic {
		return
	}
	if subtle.ConstantTimeCompare([]byte(hdr.MAC), []byte(computeM27WGOverlayMAC(rt.subKey, hdr))) != 1 {
		_, _ = conn.Write([]byte{0x01})
		return
	}
	if hdr.TimeHdr != "" {
		applyMasterTimeHeader(hdr.TimeHdr)
	}

	remoteIP := extractRemoteHostIP(conn.RemoteAddr())
	pathTag := "DIRECT_FALLBACK"
	if rt.tunnel.SpoofNative != nil && (remoteIP == cleanSpoofHost(rt.tunnel.SpoofNative.WGPeerIP) || remoteIP == cleanSpoofHost(rt.tunnel.SpoofNative.WGLocalIP)) {
		pathTag = "SPOOF_PIPE"
	} else if rt.tunnel.SpoofNative != nil && rt.tunnel.SpoofNative.StrictRealSpoof {
		_, _ = conn.Write([]byte{0x05})
		return
	}

	switch hdr.Cmd {
	case m27OverlayCmdProbe:
		_, _ = conn.Write([]byte{0x00})
		var challenge [16]byte
		if _, err := io.ReadFull(conn, challenge[:]); err != nil {
			return
		}
		_, _ = conn.Write(challenge[:])
		recordSpoofNativeVerification(rt.peerID, "wireguard", pathTag, 1, 0, "")
		markPeerConnectedInbound(rt.peer.ID, remoteIP, rt.tunnel.ID, rt.tunnel.ListenPort, 1)

	case m27OverlayCmdSync:
		_, _ = conn.Write([]byte{0x00})
		handleWebTransportParitySyncStream(conn, rt.peer.ID, remoteIP)

	case m27OverlayCmdTCP:
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
		_, _ = conn.Write([]byte{0x00})
		_ = conn.SetDeadline(time.Time{})
		pipeSpoofWGAndTCP(conn, target, rt.tunnel.SpeedLimitMBps)
	}
}

func dialM27WGOverlay(peer ServerPeer, tc TunnelConfig, cmd byte, targetPort int, timeout time.Duration) (net.Conn, string, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	subKey, err := derivePeerSubKey(cfgSnapshot, peer, "sahand-method27-native-v1")
	if err != nil {
		return nil, "", err
	}

	s := normalizeSpoofNativeConfig(tc.SpoofNative)
	pathTag := "SPOOF_PIPE"
	targetHost := cleanSpoofHost(s.WGPeerIP)

	if !isLocalIPAddressBound(s.WGLocalIP) {
		if s.StrictRealSpoof {
			return nil, "", errors.New("Strict Real Spoof is enabled, but WireGuard interface wg-spoof27 is not up")
		}
		targetHost = strings.TrimSpace(peer.IP)
		pathTag = "DIRECT_FALLBACK"
	}

	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(targetHost, strconv.Itoa(tc.ListenPort)))
	if err != nil && !s.StrictRealSpoof && targetHost != strings.TrimSpace(peer.IP) && strings.TrimSpace(peer.IP) != "" {
		conn, err = dialer.Dial("tcp", net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort)))
		pathTag = "DIRECT_FALLBACK"
	}
	if err != nil {
		return nil, "", err
	}
	enableKeepAlive(conn)
	_ = conn.SetDeadline(time.Now().Add(timeout + 2*time.Second))

	nonce, _ := randomHex(12)
	hdr := m27WGOverlayHeader{
		Magic:      m27OverlayMagic,
		Cmd:        cmd,
		PeerID:     peer.ID,
		TargetPort: targetPort,
		TimeHdr:    buildMasterTimeHeader(),
		Nonce:      nonce,
	}
	hdr.MAC = computeM27WGOverlayMAC(subKey, hdr)
	rawHdr, _ := json.Marshal(hdr)

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(rawHdr)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		_ = conn.Close()
		return nil, "", err
	}
	if _, err := conn.Write(rawHdr); err != nil {
		_ = conn.Close()
		return nil, "", err
	}
	var status [1]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil || status[0] != 0x00 {
		_ = conn.Close()
		return nil, "", fmt.Errorf("Method 27 WireGuard overlay handshake rejected (code %d)", status[0])
	}
	return conn, pathTag, nil
}

func probeSpoofNative(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	s := normalizeSpoofNativeConfig(tc.SpoofNative)
	if len(s.SpoofIPs) == 0 && s.StrictRealSpoof {
		res.Success = false
		res.ErrorReason = "No Spoof IP configured"
		recordSpoofNativeVerification(peer.ID, s.Mode, "", 0, 100, res.ErrorReason)
		return res
	}

	start := time.Now()

	if s.Mode == "wireguard" {
		conn, pathTag, err := dialM27WGOverlay(peer, tc, m27OverlayCmdProbe, tc.ListenPort, 3500*time.Millisecond)
		if err != nil {
			res.Success = false
			res.ErrorReason = "Spoof+WG unreachable"
			if strings.Contains(strings.ToLower(err.Error()), "strict") {
				res.ErrorReason = "wg-spoof27 inactive (Strict Mode)"
			}
			recordSpoofNativeVerification(peer.ID, s.Mode, "", 0, 100, res.ErrorReason)
			return res
		}
		defer conn.Close()

		var challenge [16]byte
		var echoed [16]byte
		_, _ = io.ReadFull(rand.Reader, challenge[:])
		if _, err := conn.Write(challenge[:]); err != nil {
			res.Success = false
			res.ErrorReason = "Probe write failed"
			recordSpoofNativeVerification(peer.ID, s.Mode, "", 0, 100, res.ErrorReason)
			return res
		}
		if _, err := io.ReadFull(conn, echoed[:]); err != nil || !bytes.Equal(challenge[:], echoed[:]) {
			res.Success = false
			res.ErrorReason = "Probe verification mismatch"
			recordSpoofNativeVerification(peer.ID, s.Mode, "", 0, 100, res.ErrorReason)
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
		recordSpoofNativeVerification(peer.ID, s.Mode, pathTag, rtt, 0, "")
		return res
	}

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()
	subKey, err := derivePeerSubKey(cfgSnapshot, peer, "sahand-method27-native-v1")
	if err != nil {
		res.Success = false
		res.ErrorReason = "Authentication key error"
		return res
	}

	uConn, dialPathTag, noiseSess, err := dialM27UDPPipeSocket(peer, tc, 3500*time.Millisecond)
	if err != nil {
		res.Success = false
		res.ErrorReason = "Spoof Pipe unreachable"
		recordSpoofNativeVerification(peer.ID, s.Mode, "", 0, 100, res.ErrorReason)
		return res
	}
	defer uConn.Close()

	challenge := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, challenge)
	pingFrame := encodeM27Datagram(subKey, m27FrameTypePing, 1, 1, uint16(tc.ListenPort), challenge)

	if err := sendM27FrameOverConn(uConn, noiseSess, pingFrame); err == nil {
		pType, _, _, _, repPayload, rErr := readM27FrameFromConn(uConn, noiseSess, subKey)
		if rErr == nil && pType == m27FrameTypePong && bytes.HasSuffix(repPayload, challenge) {
			verifiedPath := dialPathTag
			if strings.HasPrefix(string(repPayload), "DIRECT_FALLBACK|") {
				verifiedPath = "DIRECT_FALLBACK"
			} else if strings.HasPrefix(string(repPayload), "SPOOF_PIPE|") {
				verifiedPath = "SPOOF_PIPE"
			}
			if s.StrictRealSpoof && verifiedPath != "SPOOF_PIPE" {
				res.Success = false
				res.ErrorReason = "Strict Mode: unspoofed path rejected"
				recordSpoofNativeVerification(peer.ID, s.Mode, "", 0, 100, res.ErrorReason)
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
			recordSpoofNativeVerification(peer.ID, s.Mode, verifiedPath, rtt, 0, "")
			return res
		}
	}

	if !s.StrictRealSpoof && dialPathTag == "SPOOF_PIPE" && strings.TrimSpace(peer.IP) != "" {
		if fbAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))); err == nil {
			if fbConn, err := net.DialUDP("udp", nil, fbAddr); err == nil {
				defer fbConn.Close()
				_ = fbConn.SetDeadline(time.Now().Add(3 * time.Second))
				var fbSess *spoofM27NoiseSession
				if s.Mode == "noise" {
					fbSess, err = performM27NoiseClientHandshake(fbConn, subKey, 3*time.Second)
				}
				if err == nil {
					startFB := time.Now()
					if sendM27FrameOverConn(fbConn, fbSess, pingFrame) == nil {
						pType, _, _, _, repPayload, rErr := readM27FrameFromConn(fbConn, fbSess, subKey)
						if rErr == nil && pType == m27FrameTypePong && bytes.HasSuffix(repPayload, challenge) {
							rtt := time.Since(startFB).Milliseconds()
							if rtt <= 0 {
								rtt = 1
							}
							res.Success = true
							res.LatencyMS = rtt
							res.MinLatencyMS = rtt
							res.MaxLatencyMS = rtt
							recordSpoofNativeVerification(peer.ID, s.Mode, "DIRECT_FALLBACK", rtt, 0, "")
							return res
						}
					}
				}
			}
		}
	}

	res.Success = false
	if s.StrictRealSpoof {
		res.ErrorReason = "Spoof Pipe timeout (Strict Mode)"
	} else {
		res.ErrorReason = "Timeout"
	}
	recordSpoofNativeVerification(peer.ID, s.Mode, "", 0, 100, res.ErrorReason)
	return res
}

func pushSpoofNativeParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	s := normalizeSpoofNativeConfig(tc.SpoofNative)
	if s.Mode == "wireguard" {
		conn, _, err := dialM27WGOverlay(peer, tc, m27OverlayCmdSync, tc.ListenPort, 4*time.Second)
		if err != nil {
			return false
		}
		defer conn.Close()
		return sendSyncPacketOverStream(conn, peer, tc, latencyMS)
	}

	stateMu.RLock()
	cfgSnapshot := appCfg
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	mSignPub := appCfg.MasterSigningPublicKey
	mNoisePub := appCfg.MasterNoiseStaticPublicKey
	aSignPub := appCfg.AgentSigningPublicKey
	aNoisePub := appCfg.AgentNoiseStaticPublicKey
	stateMu.RUnlock()

	subKey, err := derivePeerSubKey(cfgSnapshot, peer, "sahand-method27-native-v1")
	if err != nil {
		return false
	}

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

	trySyncConn := func(uConn *net.UDPConn, sess *spoofM27NoiseSession) bool {
		frame := encodeM27Datagram(subKey, m27FrameTypeSyncReq, 2, 1, uint16(tc.ListenPort), rawPkt)
		if sendM27FrameOverConn(uConn, sess, frame) != nil {
			return false
		}
		pType, _, _, _, repPayload, err := readM27FrameFromConn(uConn, sess, subKey)
		if err != nil || pType != m27FrameTypeSyncRep {
			return false
		}
		var resp SyncResponse
		if json.Unmarshal(repPayload, &resp) != nil || !resp.OK {
			return false
		}
		applySyncResponseToPeer(peer.ID, resp)
		return true
	}

	uConn, dialPath, sess, err := dialM27UDPPipeSocket(peer, tc, 4*time.Second)
	if err == nil {
		ok := trySyncConn(uConn, sess)
		_ = uConn.Close()
		if ok {
			return true
		}
	}

	if !s.StrictRealSpoof && dialPath == "SPOOF_PIPE" && strings.TrimSpace(peer.IP) != "" {
		if fbAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))); err == nil {
			if fbConn, err := net.DialUDP("udp", nil, fbAddr); err == nil {
				defer fbConn.Close()
				_ = fbConn.SetDeadline(time.Now().Add(4 * time.Second))
				var fbSess *spoofM27NoiseSession
				if s.Mode == "noise" {
					fbSess, err = performM27NoiseClientHandshake(fbConn, subKey, 3*time.Second)
				}
				if err == nil && trySyncConn(fbConn, fbSess) {
					return true
				}
			}
		}
	}
	return false
}

func sendSyncPacketOverStream(conn net.Conn, peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	stateMu.RLock()
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	mSignPub := appCfg.MasterSigningPublicKey
	mNoisePub := appCfg.MasterNoiseStaticPublicKey
	aSignPub := appCfg.AgentSigningPublicKey
	aNoisePub := appCfg.AgentNoiseStaticPublicKey
	stateMu.RUnlock()

	padHex, _ := randomHex(32)
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

func forwardSpoofNativeTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	authorizedPort, err := authorizeWSSTargetPort(tc, targetPort)
	if err != nil {
		return
	}
	portNum, _ := strconv.Atoi(authorizedPort)
	s := normalizeSpoofNativeConfig(tc.SpoofNative)

	if s.Mode == "wireguard" {
		conn, _, err := dialM27WGOverlay(peer, tc, m27OverlayCmdTCP, portNum, 5*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Time{})
		pipeSpoofWGAndTCP(conn, client, tc.SpeedLimitMBps)
		return
	}

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()
	subKey, err := derivePeerSubKey(cfgSnapshot, peer, "sahand-method27-native-v1")
	if err != nil {
		return
	}

	openDatagramStream := func(uConn *net.UDPConn, sess *spoofM27NoiseSession, stID uint32) bool {
		syn := encodeM27Datagram(subKey, m27FrameTypeSyn, stID, 0, uint16(portNum), nil)
		if sendM27FrameOverConn(uConn, sess, syn) != nil {
			return false
		}
		pType, rID, _, _, _, rErr := readM27FrameFromConn(uConn, sess, subKey)
		return rErr == nil && pType == m27FrameTypeSynAck && rID == stID
	}

	var sidBytes [4]byte
	_, _ = rand.Read(sidBytes[:])
	streamID := binary.BigEndian.Uint32(sidBytes[:])
	if streamID < 10 {
		streamID += 10
	}

	uConn, dialPath, sess, err := dialM27UDPPipeSocket(peer, tc, 4*time.Second)
	connected := false
	if err == nil {
		if openDatagramStream(uConn, sess, streamID) {
			connected = true
		} else {
			_ = uConn.Close()
		}
	}

	if !connected && !s.StrictRealSpoof && dialPath == "SPOOF_PIPE" && strings.TrimSpace(peer.IP) != "" {
		if fbAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))); err == nil {
			if fbConn, err := net.DialUDP("udp", nil, fbAddr); err == nil {
				_ = fbConn.SetDeadline(time.Now().Add(4 * time.Second))
				var fbSess *spoofM27NoiseSession
				if s.Mode == "noise" {
					fbSess, err = performM27NoiseClientHandshake(fbConn, subKey, 3*time.Second)
				}
				if err == nil && openDatagramStream(fbConn, fbSess, streamID) {
					uConn = fbConn
					sess = fbSess
					connected = true
				} else {
					_ = fbConn.Close()
				}
			}
		}
	}
	if !connected || uConn == nil {
		return
	}
	defer uConn.Close()
	_ = uConn.SetDeadline(time.Time{})

	clientReorder := newM27StreamReorderBuffer()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 1100)
		var seq uint32
		for {
			n, err := client.Read(buf)
			if n > 0 {
				seq++
				atomic.AddUint64(&appTxBytes, uint64(n))
				frame := encodeM27Datagram(subKey, m27FrameTypeData, streamID, seq, uint16(portNum), buf[:n])
				if sendM27FrameOverConn(uConn, sess, frame) != nil {
					return
				}
			}
			if err != nil {
				fin := encodeM27Datagram(subKey, m27FrameTypeFin, streamID, seq+1, uint16(portNum), nil)
				_ = sendM27FrameOverConn(uConn, sess, fin)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			pType, rID, rSeq, _, payload, err := readM27FrameFromConn(uConn, sess, subKey)
			if err != nil {
				closeWriteTCP(client)
				return
			}
			if rID != streamID {
				continue
			}
			if pType == m27FrameTypeData && len(payload) > 0 {
				atomic.AddUint64(&appRxBytes, uint64(len(payload)))
				for _, chunk := range clientReorder.InsertAndDrain(rSeq, payload) {
					if _, wErr := client.Write(chunk); wErr != nil {
						return
					}
				}
			} else if pType == m27FrameTypeFin {
				closeWriteTCP(client)
				return
			}
		}
	}()

	wg.Wait()
}

func startSpoofNativeUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
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

	spoofNativeRuntimeMu.Lock()
	if rt, ok := spoofNativeRuntimes[peer.ID]; ok {
		rt.udpEntries = append(rt.udpEntries, entryConn)
	}
	spoofNativeRuntimeMu.Unlock()

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()
	subKey, err := derivePeerSubKey(cfgSnapshot, peer, "sahand-method27-native-v1")
	if err != nil {
		_ = entryConn.Close()
		return nil
	}

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
			dgram := make([]byte, n)
			copy(dgram, buf[:n])
			cliCopy := cloneUDPAddr(cliAddr)

			go func(payload []byte, cAddr *net.UDPAddr) {
				uConn, dialPath, sess, dErr := dialM27UDPPipeSocket(peer, tc, 3*time.Second)
				if dErr != nil {
					return
				}
				defer uConn.Close()
				_ = uConn.SetDeadline(time.Now().Add(3 * time.Second))

				atomic.AddUint64(&appTxBytes, uint64(len(payload)))
				frame := encodeM27Datagram(subKey, m27FrameTypeUDP, 99, 1, uint16(portNum), payload)
				if sendM27FrameOverConn(uConn, sess, frame) == nil {
					pType, _, _, _, rep, err := readM27FrameFromConn(uConn, sess, subKey)
					if err == nil && pType == m27FrameTypeUDP && len(rep) > 0 {
						atomic.AddUint64(&appRxBytes, uint64(len(rep)))
						_, _ = entryConn.WriteToUDP(rep, cAddr)
						return
					}
				}

				s := normalizeSpoofNativeConfig(tc.SpoofNative)
				if !s.StrictRealSpoof && dialPath == "SPOOF_PIPE" && strings.TrimSpace(peer.IP) != "" {
					if fbAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))); err == nil {
						if fbConn, err := net.DialUDP("udp", nil, fbAddr); err == nil {
							defer fbConn.Close()
							_ = fbConn.SetDeadline(time.Now().Add(3 * time.Second))
							var fbSess *spoofM27NoiseSession
							if s.Mode == "noise" {
								fbSess, err = performM27NoiseClientHandshake(fbConn, subKey, 2*time.Second)
							}
							if err == nil && sendM27FrameOverConn(fbConn, fbSess, frame) == nil {
								pType, _, _, _, rep, err := readM27FrameFromConn(fbConn, fbSess, subKey)
								if err == nil && pType == m27FrameTypeUDP && len(rep) > 0 {
									atomic.AddUint64(&appRxBytes, uint64(len(rep)))
									_, _ = entryConn.WriteToUDP(rep, cAddr)
								}
							}
						}
					}
				}
			}(dgram, cliCopy)
		}
	}()

	return entryConn
}

func curve25519ScalarBaseMult(priv []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("invalid X25519 private key length")
	}
	var k [32]byte
	copy(k[:], priv)
	return curve25519X25519Basepoint(k[:])
}

func curve25519X25519Basepoint(scalar []byte) ([]byte, error) {
	privHex := hex.EncodeToString(scalar)
	pub, err := deriveX25519PubFromPrivHex(privHex)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(pub)
}

func deriveX25519PubFromPrivHex(privHex string) (string, error) {
	raw, err := decodeHexExact(privHex, 32)
	if err != nil {
		return "", err
	}
	pubB, err := spoofPubFromPriv(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return "", err
	}
	pubRaw, err := base64.StdEncoding.DecodeString(pubB)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pubRaw), nil
}

var (
	_ = bufio.NewReader
	_ = tls.VersionTLS13
)
