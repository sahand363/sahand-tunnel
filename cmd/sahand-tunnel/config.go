package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Role          string       `json:"role"`
	NodeID        string       `json:"node_id"`
	ListenAddr    string       `json:"listen_addr"`
	PanelURL      string       `json:"panel_url,omitempty"`
	PanelPort     int          `json:"panel_port"`
	AdminUsername string       `json:"admin_username"`
	AdminSalt     string       `json:"admin_salt"`
	AdminHash     string       `json:"admin_hash"`
	TokenSecret   string       `json:"token_secret,omitempty"`
	TLSCertPEM    string       `json:"tls_cert_pem,omitempty"`
	TLSKeyPEM     string       `json:"tls_key_pem,omitempty"`
	CertPin       string       `json:"cert_pin,omitempty"`
	Servers       []ServerPeer `json:"servers,omitempty"`
	CreatedAt     time.Time    `json:"created_at"`
}

type MethodCatalogueItem struct {
	ID               int      `json:"id"`
	Name             string   `json:"name"`
	Security         int      `json:"security"`
	SupportedTraffic string   `json:"supported_traffic"`
	Implemented      bool     `json:"implemented"`
	DefaultPort      int      `json:"default_port"`
	Fields           []string `json:"fields"`
}

type MethodResult struct {
	MethodID    int    `json:"method_id"`
	Success     bool   `json:"success"`
	Direction   string `json:"direction"`
	LatencyMS   int64  `json:"latency_ms"`
	ErrorReason string `json:"error_reason,omitempty"`
	TestedAt    string `json:"tested_at,omitempty"`
}

type LifelineEvent struct {
	MethodID    int    `json:"method_id"`
	MethodName  string `json:"method_name"`
	Port        int    `json:"port"`
	Security    int    `json:"security"`
	LatencyMS   int64  `json:"latency_ms"`
	Direction   string `json:"direction"`
	ConnectedAt string `json:"connected_at"`
}

type TunnelConfig struct {
	ID             int          `json:"id"`
	Name           string       `json:"name"`
	Security       int          `json:"security"`
	TrafficType    string       `json:"traffic_type"`
	Implemented    bool         `json:"implemented"`
	Enabled        bool         `json:"enabled"`
	ListenPort     int          `json:"listen_port"`
	ForwardPorts   string       `json:"forward_ports"`
	SNI            string       `json:"sni,omitempty"`
	WSPath         string       `json:"ws_path,omitempty"`
	CertPin        string       `json:"cert_pin,omitempty"`
	HeartbeatSec   int          `json:"heartbeat_sec,omitempty"`
	StreamLimit    int          `json:"stream_limit,omitempty"`
	SpeedLimitMBps string       `json:"speed_limit_mbps,omitempty"`
	LastDiscovery  MethodResult `json:"last_discovery"`
}

type ServerPeer struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	IP              string          `json:"ip"`
	Token           string          `json:"token"`
	TokenRevoked    bool            `json:"token_revoked,omitempty"`
	ConfigVersion   int             `json:"config_version"`
	SyncState       string          `json:"sync_state"`
	Status          string          `json:"status"`
	Running         bool            `json:"running"`
	ActiveMethodID  int             `json:"active_method_id"`
	ActiveMethod    string          `json:"active_method"`
	ActivePort      int             `json:"active_port"`
	ActiveSecurity  int             `json:"active_security"`
	ActiveLatencyMS int64           `json:"active_latency_ms"`
	NextRetryAt     string          `json:"next_retry_at,omitempty"`
	RemoteCertPin   string          `json:"remote_cert_pin,omitempty"`
	RecentLifelines []LifelineEvent `json:"recent_lifelines"`
	Tunnels         []TunnelConfig  `json:"tunnels"`
}

type TokenPayload struct {
	V     int    `json:"v"`
	MID   string `json:"mid"`
	AID   string `json:"aid"`
	MIP   string `json:"mip,omitempty"`
	Pin   string `json:"pin,omitempty"`
	TS    int64  `json:"ts"`
	Exp   int64  `json:"exp"`
	Ports []int  `json:"ports"`
	Key   string `json:"key"`
	Sig   string `json:"sig"`
}

type SyncPacket struct {
	Type          string         `json:"type"`
	SenderID      string         `json:"sender_id"`
	PeerID        string         `json:"peer_id"`
	MethodID      int            `json:"method_id"`
	Port          int            `json:"port"`
	LatencyMS     int64          `json:"latency_ms"`
	ConfigVersion int            `json:"config_version"`
	Tunnels       []TunnelConfig `json:"tunnels,omitempty"`
	CertPin       string         `json:"cert_pin,omitempty"`
	Padding       string         `json:"pad,omitempty"`
}

type SyncResponse struct {
	OK            bool           `json:"ok"`
	NodeID        string         `json:"node_id"`
	ConfigVersion int            `json:"config_version"`
	Tunnels       []TunnelConfig `json:"tunnels,omitempty"`
	CertPin       string         `json:"cert_pin,omitempty"`
}

type DailyUsage struct {
	Date    string `json:"date"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

type AnalyticsStore struct {
	LastRawRx uint64       `json:"last_raw_rx"`
	LastRawTx uint64       `json:"last_raw_tx"`
	Days      []DailyUsage `json:"days"`
}

type NodeInfo struct {
	AppVersion string `json:"app_version"`
	Role       string `json:"role"`
	NodeID     string `json:"node_id"`
	Status     string `json:"status"`
	PanelURL   string `json:"panel_url"`
}

type Session struct {
	ExpiresAt time.Time
}

var methodCatalogue = []MethodCatalogueItem{
	{1, "WSS", 95, "tcp", true, 11301, []string{"listen_port", "forward_ports", "sni", "ws_path", "speed_limit_mbps"}},
	{2, "gRPC", 95, "tcp", true, 11302, []string{"listen_port", "forward_ports", "sni", "cert_pin", "stream_limit", "speed_limit_mbps"}},
	{3, "HTTP/2", 90, "tcp", true, 11303, []string{"listen_port", "forward_ports", "sni", "heartbeat_sec", "speed_limit_mbps"}},
	{4, "HTTP CONNECT", 76, "tcp", true, 11304, []string{"listen_port", "forward_ports", "sni", "speed_limit_mbps"}},
	{5, "HTTPS Proxy", 82, "tcp", false, 11305, []string{"listen_port", "forward_ports", "sni"}},
	{6, "TCP Relay", 45, "tcp", false, 11306, []string{"listen_port", "forward_ports"}},
	{7, "TLS Stream", 88, "tcp", false, 11307, []string{"listen_port", "forward_ports", "sni", "cert_pin"}},
	{8, "QUIC", 92, "tcp+udp", false, 11308, []string{"listen_port", "forward_ports", "sni", "heartbeat_sec"}},
	{9, "HTTP/3", 92, "tcp+udp", false, 11309, []string{"listen_port", "forward_ports", "sni"}},
	{10, "WebSocket TCP", 65, "tcp", false, 11310, []string{"listen_port", "forward_ports", "ws_path"}},
	{11, "Reverse TCP", 50, "tcp", false, 11311, []string{"listen_port", "forward_ports", "heartbeat_sec"}},
	{12, "SOCKS5", 60, "tcp+udp", false, 11312, []string{"listen_port", "forward_ports"}},
	{13, "SSH Tunnel", 86, "tcp", false, 11313, []string{"listen_port", "forward_ports", "heartbeat_sec"}},
	{14, "Raw TCP", 35, "tcp", false, 11314, []string{"listen_port", "forward_ports"}},
	{15, "UDP Relay", 40, "udp", false, 11315, []string{"listen_port", "forward_ports"}},
	{16, "DNS Transport", 70, "tcp+udp", false, 11316, []string{"listen_port", "forward_ports"}},
	{17, "TLS over TCP", 84, "tcp", false, 11317, []string{"listen_port", "forward_ports", "sni"}},
	{18, "HTTP Long Polling", 72, "tcp", false, 11318, []string{"listen_port", "forward_ports", "ws_path"}},
	{19, "WebTransport", 93, "tcp+udp", false, 11319, []string{"listen_port", "forward_ports", "sni"}},
	{20, "mTLS Stream", 99, "tcp", false, 11320, []string{"listen_port", "forward_ports", "sni", "cert_pin"}},
	{21, "TCP Multiplex", 68, "tcp", false, 11321, []string{"listen_port", "forward_ports", "stream_limit"}},
	{22, "WebSocket Multiplex", 89, "tcp", false, 11322, []string{"listen_port", "forward_ports", "sni", "ws_path", "stream_limit"}},
	{23, "HTTP Upgrade", 74, "tcp", false, 11323, []string{"listen_port", "forward_ports", "ws_path"}},
	{24, "Reverse Proxy", 78, "tcp", false, 11324, []string{"listen_port", "forward_ports", "sni"}},
	{25, "Secure Relay", 85, "tcp", false, 11325, []string{"listen_port", "forward_ports", "sni"}},
	{26, "Stream Bridge", 80, "tcp+udp", false, 11326, []string{"listen_port", "forward_ports", "stream_limit"}},
	{27, "Fallback TCP", 42, "tcp", false, 11327, []string{"listen_port", "forward_ports"}},
	{28, "Custom TLS", 91, "tcp", false, 11328, []string{"listen_port", "forward_ports", "sni", "cert_pin"}},
	{29, "Hybrid Transport", 87, "tcp+udp", false, 11329, []string{"listen_port", "forward_ports", "sni"}},
	{30, "Experimental", 62, "tcp+udp", false, 11330, []string{"listen_port", "forward_ports"}},
}

var (
	stateMu   sync.RWMutex
	appCfg    Config
	localCert tls.Certificate
)

func configPath() string {
	if p := os.Getenv("SAHAND_CONFIG"); p != "" {
		return p
	}
	return "./data/config.json"
}

func analyticsPath() string {
	return filepath.Join(filepath.Dir(configPath()), "analytics.json")
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomIntN(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	const hashLen = 32
	blocks := (keyLen + hashLen - 1) / hashLen
	result := make([]byte, 0, blocks*hashLen)

	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write([]byte{
			byte(block >> 24), byte(block >> 16),
			byte(block >> 8), byte(block),
		})
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:keyLen]
}

func hashPassword(password string) (string, string, error) {
	salt, err := randomHex(16)
	if err != nil {
		return "", "", err
	}
	saltBytes, _ := hex.DecodeString(salt)
	hash := pbkdf2SHA256([]byte(password), saltBytes, passwordRounds, 32)
	return salt, hex.EncodeToString(hash), nil
}

func verifyPassword(password, saltHex, hashHex string) bool {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(hashHex)
	if err != nil || len(expected) != 32 {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), salt, passwordRounds, 32)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func readPasswordFromStdin() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	password = strings.TrimRight(password, "\r\n")
	if len(password) < 12 {
		return "", errors.New("administrator password must contain at least 12 characters")
	}
	if len(password) > 1024 {
		return "", errors.New("administrator password is too long")
	}
	return password, nil
}

func generateSelfSignedCert() (string, string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "www.speedtest.net",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"www.speedtest.net", "localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	sum := sha256.Sum256(derBytes)
	pin := hex.EncodeToString(sum[:])
	return string(certPEM), string(keyPEM), pin, nil
}

func defaultTunnelsForServer() []TunnelConfig {
	list := make([]TunnelConfig, 0, len(methodCatalogue))
	for _, item := range methodCatalogue {
		tc := TunnelConfig{
			ID:           item.ID,
			Name:         item.Name,
			Security:     item.Security,
			TrafficType:  item.SupportedTraffic,
			Implemented:  item.Implemented,
			Enabled:      item.ID == 1,
			ListenPort:   item.DefaultPort,
			ForwardPorts: "2053",
			LastDiscovery: MethodResult{
				MethodID: item.ID,
			},
		}
		for _, f := range item.Fields {
			switch f {
			case "sni":
				tc.SNI = "www.speedtest.net"
			case "ws_path":
				tc.WSPath = "/ws"
			case "heartbeat_sec":
				tc.HeartbeatSec = 30
			case "stream_limit":
				tc.StreamLimit = 64
			case "speed_limit_mbps":
				tc.SpeedLimitMBps = "0"
			}
		}
		list = append(list, tc)
	}
	return list
}

func normalizeTunnels(existing []TunnelConfig) []TunnelConfig {
	defaults := defaultTunnelsForServer()
	byID := make(map[int]TunnelConfig, len(existing))
	for _, t := range existing {
		byID[t.ID] = t
	}
	out := make([]TunnelConfig, 0, len(defaults))
	for _, def := range defaults {
		if cur, ok := byID[def.ID]; ok {
			cur.Name = def.Name
			cur.Security = def.Security
			cur.TrafficType = def.TrafficType
			cur.Implemented = def.Implemented
			if cur.ListenPort < 1024 || cur.ListenPort > 65535 || cur.ListenPort == 10200+def.ID {
				cur.ListenPort = def.ListenPort
			}
			if strings.TrimSpace(cur.ForwardPorts) == "" {
				cur.ForwardPorts = def.ForwardPorts
			}
			if cur.SNI == "" {
				cur.SNI = def.SNI
			}
			if cur.WSPath == "" {
				cur.WSPath = def.WSPath
			}
			if cur.SpeedLimitMBps == "" {
				cur.SpeedLimitMBps = def.SpeedLimitMBps
			}
			out = append(out, cur)
		} else {
			out = append(out, def)
		}
	}
	return out
}

func loadExistingConfig(path string) (Config, bool, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, false, nil
	}
	if err != nil {
		return cfg, false, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, true, fmt.Errorf("cannot read existing configuration: %w", err)
	}
	return cfg, true, nil
}

func saveConfig(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func ensureCryptoMaterial(cfg *Config) (bool, error) {
	changed := false
	if cfg.TokenSecret == "" {
		sec, err := randomHex(32)
		if err != nil {
			return false, err
		}
		cfg.TokenSecret = sec
		changed = true
	}
	if cfg.TLSCertPEM == "" || cfg.TLSKeyPEM == "" || cfg.CertPin == "" {
		cPEM, kPEM, pin, err := generateSelfSignedCert()
		if err != nil {
			return false, err
		}
		cfg.TLSCertPEM = cPEM
		cfg.TLSKeyPEM = kPEM
		cfg.CertPin = pin
		changed = true
	}
	cert, err := tls.X509KeyPair([]byte(cfg.TLSCertPEM), []byte(cfg.TLSKeyPEM))
	if err != nil {
		cPEM, kPEM, pin, genErr := generateSelfSignedCert()
		if genErr != nil {
			return false, genErr
		}
		cfg.TLSCertPEM = cPEM
		cfg.TLSKeyPEM = kPEM
		cfg.CertPin = pin
		changed = true
		cert, err = tls.X509KeyPair([]byte(cfg.TLSCertPEM), []byte(cfg.TLSKeyPEM))
		if err != nil {
			return false, err
		}
	}
	localCert = cert
	for i := range cfg.Servers {
		cfg.Servers[i].Tunnels = normalizeTunnels(cfg.Servers[i].Tunnels)
		if cfg.Servers[i].ConfigVersion <= 0 {
			cfg.Servers[i].ConfigVersion = 1
		}
		if cfg.Servers[i].Status == "" {
			cfg.Servers[i].Status = "WAITING"
		}
		if cfg.Servers[i].SyncState == "" {
			cfg.Servers[i].SyncState = "synced"
		}
		if cfg.Servers[i].RecentLifelines == nil {
			cfg.Servers[i].RecentLifelines = []LifelineEvent{}
		}
		if cfg.Role == "master" {
			if tok, err := generatePeerToken(*cfg, cfg.Servers[i]); err == nil && tok != cfg.Servers[i].Token {
				cfg.Servers[i].Token = tok
				changed = true
			}
		}
	}
	return changed, nil
}

func signTokenPayload(tp TokenPayload, secret string) string {
	portsStr := make([]string, len(tp.Ports))
	for i, p := range tp.Ports {
		portsStr[i] = strconv.Itoa(p)
	}
	canonical := fmt.Sprintf("%d|%s|%s|%s|%d|%d|%s|%s",
		tp.V, tp.MID, tp.AID, tp.Pin, tp.TS, tp.Exp, strings.Join(portsStr, ","), tp.Key)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func generatePeerToken(cfg Config, peer ServerPeer) (string, error) {
	ports := make([]int, 0, 30)
	tunnels := normalizeTunnels(peer.Tunnels)
	for _, t := range tunnels {
		ports = append(ports, t.ListenPort)
	}
	now := time.Now().UTC()
	sharedKeyMac := hmac.New(sha256.New, []byte(cfg.TokenSecret))
	_, _ = sharedKeyMac.Write([]byte(peer.ID + "|" + strconv.Itoa(peer.ConfigVersion)))
	derivedKey := hex.EncodeToString(sharedKeyMac.Sum(nil)[:16])

	tp := TokenPayload{
		V:     peer.ConfigVersion,
		MID:   cfg.NodeID,
		AID:   peer.ID,
		Pin:   cfg.CertPin,
		TS:    now.Unix(),
		Exp:   now.Add(365 * 24 * time.Hour).Unix(),
		Ports: ports,
		Key:   derivedKey,
	}
	tp.Sig = signTokenPayload(tp, cfg.TokenSecret)
	raw, err := json.Marshal(tp)
	if err != nil {
		return "", err
	}
	return "st1." + base64.RawURLEncoding.EncodeToString(raw), nil
}

func parseAndValidateToken(rawToken string) (TokenPayload, error) {
	var tp TokenPayload
	trimmed := strings.TrimSpace(rawToken)
	if !strings.HasPrefix(trimmed, "st1.") {
		return tp, errors.New("invalid token prefix (expected st1.)")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(trimmed, "st1."))
	if err != nil {
		return tp, errors.New("invalid token encoding")
	}
	if err := json.Unmarshal(decoded, &tp); err != nil {
		return tp, errors.New("corrupted token payload")
	}
	if tp.MID == "" || tp.AID == "" || len(tp.Ports) != 30 || tp.Key == "" || tp.Sig == "" {
		return tp, errors.New("incomplete token fields")
	}
	if time.Now().UTC().Unix() > tp.Exp {
		return tp, errors.New("token has expired")
	}
	return tp, nil
}
