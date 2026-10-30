package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The frontend is built by GitHub Actions before Go compilation.
//
//go:embed web/dist
var webAssets embed.FS

const (
	AppName        = "sahand-tunnel"
	AppVersion     = "0.4.0"
	defaultPort    = 18080
	passwordRounds = 310000
	sessionTTL     = 12 * time.Hour
	wsGUID         = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
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
	{1, "WSS", 95, "tcp", true, 10201, []string{"listen_port", "forward_ports", "sni", "ws_path", "speed_limit_mbps"}},
	{2, "gRPC", 95, "tcp", true, 10202, []string{"listen_port", "forward_ports", "sni", "cert_pin", "stream_limit", "speed_limit_mbps"}},
	{3, "HTTP/2", 90, "tcp", false, 10203, []string{"listen_port", "forward_ports", "sni", "heartbeat_sec"}},
	{4, "HTTP CONNECT", 76, "tcp", false, 10204, []string{"listen_port", "forward_ports", "sni"}},
	{5, "HTTPS Proxy", 82, "tcp", false, 10205, []string{"listen_port", "forward_ports", "sni"}},
	{6, "TCP Relay", 45, "tcp", false, 10206, []string{"listen_port", "forward_ports"}},
	{7, "TLS Stream", 88, "tcp", false, 10207, []string{"listen_port", "forward_ports", "sni", "cert_pin"}},
	{8, "QUIC", 92, "tcp+udp", false, 10208, []string{"listen_port", "forward_ports", "sni", "heartbeat_sec"}},
	{9, "HTTP/3", 92, "tcp+udp", false, 10209, []string{"listen_port", "forward_ports", "sni"}},
	{10, "WebSocket TCP", 65, "tcp", false, 10210, []string{"listen_port", "forward_ports", "ws_path"}},
	{11, "Reverse TCP", 50, "tcp", false, 10211, []string{"listen_port", "forward_ports", "heartbeat_sec"}},
	{12, "SOCKS5", 60, "tcp+udp", false, 10212, []string{"listen_port", "forward_ports"}},
	{13, "SSH Tunnel", 86, "tcp", false, 10213, []string{"listen_port", "forward_ports", "heartbeat_sec"}},
	{14, "Raw TCP", 35, "tcp", false, 10214, []string{"listen_port", "forward_ports"}},
	{15, "UDP Relay", 40, "udp", false, 10215, []string{"listen_port", "forward_ports"}},
	{16, "DNS Transport", 70, "tcp+udp", false, 10216, []string{"listen_port", "forward_ports"}},
	{17, "TLS over TCP", 84, "tcp", false, 10217, []string{"listen_port", "forward_ports", "sni"}},
	{18, "HTTP Long Polling", 72, "tcp", false, 10218, []string{"listen_port", "forward_ports", "ws_path"}},
	{19, "WebTransport", 93, "tcp+udp", false, 10219, []string{"listen_port", "forward_ports", "sni"}},
	{20, "mTLS Stream", 99, "tcp", false, 10220, []string{"listen_port", "forward_ports", "sni", "cert_pin"}},
	{21, "TCP Multiplex", 68, "tcp", false, 10221, []string{"listen_port", "forward_ports", "stream_limit"}},
	{22, "WebSocket Multiplex", 89, "tcp", false, 10222, []string{"listen_port", "forward_ports", "sni", "ws_path", "stream_limit"}},
	{23, "HTTP Upgrade", 74, "tcp", false, 10223, []string{"listen_port", "forward_ports", "ws_path"}},
	{24, "Reverse Proxy", 78, "tcp", false, 10224, []string{"listen_port", "forward_ports", "sni"}},
	{25, "Secure Relay", 85, "tcp", false, 10225, []string{"listen_port", "forward_ports", "sni"}},
	{26, "Stream Bridge", 80, "tcp+udp", false, 10226, []string{"listen_port", "forward_ports", "stream_limit"}},
	{27, "Fallback TCP", 42, "tcp", false, 10227, []string{"listen_port", "forward_ports"}},
	{28, "Custom TLS", 91, "tcp", false, 10228, []string{"listen_port", "forward_ports", "sni", "cert_pin"}},
	{29, "Hybrid Transport", 87, "tcp+udp", false, 10229, []string{"listen_port", "forward_ports", "sni"}},
	{30, "Experimental", 62, "tcp+udp", false, 10230, []string{"listen_port", "forward_ports"}},
}

var (
	stateMu   sync.RWMutex
	appCfg    Config
	localCert tls.Certificate

	sessionsMu sync.Mutex
	sessions   = make(map[string]Session)

	loginMu       sync.Mutex
	loginAttempts = make(map[string][]time.Time)

	discoveryMu     sync.Mutex
	discoveryCancel = make(map[string]chan struct{})

	engineMu        sync.Mutex
	activeListeners = make(map[string][]net.Listener)

	analyticsMu   sync.Mutex
	analyticsData AnalyticsStore

	appRxBytes uint64
	appTxBytes uint64
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("%s %s\n", AppName, AppVersion)
	case "init":
		if err := runInit(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "serve":
		if err := runServer(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case "menu":
		runMenu()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Sahand Tunnel")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  sahand-tunnel init [options]")
	fmt.Println("  sahand-tunnel serve")
	fmt.Println("  sahand-tunnel menu")
	fmt.Println("  sahand-tunnel version")
}

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
			Enabled:      item.ID == 1, // WSS enabled by default per spec
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
			if cur.ListenPort < 1024 || cur.ListenPort > 65535 {
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
	}
	return changed, nil
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	role := fs.String("role", "", "master or agent")
	listen := fs.String("listen", "", "application listen address")
	panelPort := fs.Int("panel-port", 0, "panel port")
	panelURL := fs.String("panel-url", "", "optional public HTTPS panel URL")
	adminUser := fs.String("admin-user", "", "administrator username")
	passwordStdin := fs.Bool("admin-password-stdin", false, "read password from stdin")

	if err := fs.Parse(args); err != nil {
		return err
	}

	path := configPath()
	cfg, exists, err := loadExistingConfig(path)
	if err != nil {
		return err
	}

	if !exists {
		cfg.CreatedAt = time.Now().UTC()
		cfg.NodeID, err = randomHex(16)
		if err != nil {
			return err
		}
	}

	if *role != "" {
		if *role != "master" && *role != "agent" {
			return errors.New("role must be master or agent")
		}
		cfg.Role = *role
	}
	if cfg.Role != "master" && cfg.Role != "agent" {
		return errors.New("role is required: use --role master or --role agent")
	}

	if *panelPort != 0 {
		if *panelPort < 1024 || *panelPort > 65535 {
			return errors.New("panel port must be between 1024 and 65535")
		}
		cfg.PanelPort = *panelPort
	}
	if cfg.PanelPort == 0 {
		cfg.PanelPort = defaultPort
	}

	if *listen != "" {
		cfg.ListenAddr = *listen
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = fmt.Sprintf(":%d", cfg.PanelPort)
	}

	if *panelURL != "" {
		cfg.PanelURL = strings.TrimRight(*panelURL, "/")
	}

	if *adminUser != "" {
		cfg.AdminUsername = strings.TrimSpace(*adminUser)
	}
	if cfg.AdminUsername == "" {
		return errors.New("administrator username is required")
	}

	if *passwordStdin {
		password, err := readPasswordFromStdin()
		if err != nil {
			return err
		}
		cfg.AdminSalt, cfg.AdminHash, err = hashPassword(password)
		if err != nil {
			return err
		}
	}
	if cfg.AdminSalt == "" || cfg.AdminHash == "" {
		return errors.New("administrator password is required; use --admin-password-stdin")
	}

	if cfg.NodeID == "" {
		cfg.NodeID, err = randomHex(16)
		if err != nil {
			return err
		}
	}
	if cfg.CreatedAt.IsZero() {
		cfg.CreatedAt = time.Now().UTC()
	}

	if _, err := ensureCryptoMaterial(&cfg); err != nil {
		return err
	}

	if err := saveConfig(path, cfg); err != nil {
		return err
	}

	fmt.Println("Installation configured successfully.")
	fmt.Printf("Role: %s\n", cfg.Role)
	fmt.Printf("Node ID: %s\n", cfg.NodeID)
	fmt.Printf("Panel port: %d\n", cfg.PanelPort)
	if cfg.PanelURL != "" {
		fmt.Printf("Panel URL: %s\n", cfg.PanelURL)
	} else {
		fmt.Println("Panel URL: not configured (HTTP/IP mode)")
	}
	fmt.Printf("Config: %s\n", path)
	return nil
}

// ============================================================================
// TOKEN GENERATION & VALIDATION
// ============================================================================

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

// ============================================================================
// ENGINE 2: TRAFFIC TUNNELING & LISTENERS (WSS + gRPC)
// ============================================================================

type sharedThrottleBucket struct {
	mu               sync.Mutex
	bytesLimitPerSec int64
	bytesSentThisSec int64
	lastSecStart     time.Time
}

type throttledWriter struct {
	w       io.Writer
	counter *uint64
	bucket  *sharedThrottleBucket
}

var (
	sharedBuckets   = make(map[int64]*sharedThrottleBucket)
	sharedBucketsMu sync.Mutex
)

func newThrottledWriter(w io.Writer, counter *uint64, mbPerSec float64) io.Writer {
	limit := int64(mbPerSec * 1024.0 * 1024.0)
	if limit <= 0 {
		return &throttledWriter{w: w, counter: counter, bucket: nil}
	}
	sharedBucketsMu.Lock()
	b, ok := sharedBuckets[limit]
	if !ok {
		b = &sharedThrottleBucket{
			bytesLimitPerSec: limit,
			lastSecStart:     time.Now(),
		}
		sharedBuckets[limit] = b
	}
	sharedBucketsMu.Unlock()
	return &throttledWriter{w: w, counter: counter, bucket: b}
}

func parseSpeedLimit(raw string) float64 {
	val, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || val < 0 {
		return 0
	}
	return val
}

func (t *throttledWriter) Write(p []byte) (int, error) {
	if t.bucket == nil || t.bucket.bytesLimitPerSec <= 0 {
		n, err := t.w.Write(p)
		if n > 0 {
			atomic.AddUint64(t.counter, uint64(n))
		}
		return n, err
	}
	total := 0
	for len(p) > 0 {
		t.bucket.mu.Lock()
		now := time.Now()
		if now.Sub(t.bucket.lastSecStart) >= 250*time.Millisecond {
			t.bucket.bytesSentThisSec = 0
			t.bucket.lastSecStart = now
		}
		windowLimit := t.bucket.bytesLimitPerSec / 4
		if windowLimit < 16384 {
			windowLimit = 16384
		}
		avail := windowLimit - t.bucket.bytesSentThisSec
		if avail <= 0 {
			t.bucket.mu.Unlock()
			time.Sleep(15 * time.Millisecond)
			continue
		}
		chunk := int64(len(p))
		if chunk > avail {
			chunk = avail
		}
		if chunk > 32768 {
			chunk = 32768
		}
		t.bucket.bytesSentThisSec += chunk
		t.bucket.mu.Unlock()

		n, err := t.w.Write(p[:chunk])
		total += n
		if n > 0 {
			atomic.AddUint64(t.counter, uint64(n))
		}
		if err != nil {
			return total, err
		}
		p = p[chunk:]
	}
	return total, nil
}

func computeWSAccept(key string) string {
	h := sha1.New()
	_, _ = h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func enableKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
		_ = tcp.SetNoDelay(true)
	}
}

func verifyCertPin(rawCerts [][]byte, expectedPin string) error {
	expectedPin = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(expectedPin, ":", "")))
	if expectedPin == "" {
		return nil
	}
	if len(rawCerts) == 0 {
		return errors.New("no peer certificate presented")
	}
	sum := sha256.Sum256(rawCerts[0])
	actualPin := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actualPin, expectedPin) {
		return fmt.Errorf("certificate pin mismatch")
	}
	return nil
}

func parsePortList(raw string) []string {
	var res []string
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if strings.Contains(p, ":") {
			segs := strings.Split(p, ":")
			p = segs[len(segs)-1]
		}
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
			res = append(res, strconv.Itoa(n))
		}
	}
	return res
}

func stopAllServerListeners(peerID string) {
	engineMu.Lock()
	defer engineMu.Unlock()
	if list, ok := activeListeners[peerID]; ok {
		for _, ln := range list {
			_ = ln.Close()
		}
		delete(activeListeners, peerID)
	}
}

// Rebuilds listeners for both Engine 1 (Discovery responders) and Engine 2 (Traffic Tunnels)
func syncServerListeners(peer ServerPeer) {
	stopAllServerListeners(peer.ID)

	var bound []net.Listener
	tunnels := normalizeTunnels(peer.Tunnels)

	for _, tun := range tunnels {
		tc := tun
		if !tc.Implemented {
			continue
		}
		// Always bind the tunnel listen port so Engine 1 discovery probes & parity syncs succeed,
		// while Engine 2 only forwards real traffic if tc.Enabled is true.
		listenAddr := fmt.Sprintf("0.0.0.0:%d", tc.ListenPort)
		nextProtos := []string{"http/1.1"}
		if tc.ID == 2 {
			nextProtos = []string{"h2", "http/1.1"}
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{localCert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   nextProtos,
		}
		ln, err := tls.Listen("tcp", listenAddr, tlsCfg)
		if err == nil {
			bound = append(bound, ln)
			go acceptTunnelServerLoop(ln, peer.ID, tc)
		}

		// Engine 2: Bind local forwarding entry ports ONLY when Traffic Tunnel toggle is ON
		if tc.Enabled && peer.IP != "" {
			forwardPorts := parsePortList(tc.ForwardPorts)
			for _, fp := range forwardPorts {
				targetPort := fp
				entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
				if err != nil {
					continue
				}
				bound = append(bound, entryLn)
				go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
			}
		}
	}

	engineMu.Lock()
	activeListeners[peer.ID] = bound
	engineMu.Unlock()
}

func acceptTunnelServerLoop(ln net.Listener, peerID string, tc TunnelConfig) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleIncomingTunnelConn(conn, peerID, tc)
	}
}

func handleIncomingTunnelConn(conn net.Conn, peerID string, tc TunnelConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	br := bufio.NewReader(conn)
	firstLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return
	}

	var wsKey, targetPort, syncPayloadB64, grpcMode string
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "sec-websocket-key:") {
			wsKey = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(low, "x-target-port:") {
			targetPort = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(low, "x-sahand-sync:") {
			syncPayloadB64 = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(low, "x-tunnel-mode:") {
			grpcMode = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}

	// Engine 1: Config Sync & Lifeline Handshake
	if syncPayloadB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(syncPayloadB64)
		if err != nil {
			return
		}
		var pkt SyncPacket
		if json.Unmarshal(raw, &pkt) != nil {
			return
		}
		resp := processIncomingSync(peerID, pkt)
		respBytes, _ := json.Marshal(resp)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"))
		_, _ = conn.Write(respBytes)
		return
	}

	// Engine 1: Discovery Probe (works regardless of whether Traffic Tunnel toggle is ON or OFF)
	if strings.HasPrefix(targetPort, "probe:") {
		if tc.ID == 2 || grpcMode == "grpc" {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\nX-Grpc-Status: 0\r\n\r\n"))
			frame := make([]byte, 7)
			binary.BigEndian.PutUint32(frame[1:5], 2)
			copy(frame[5:], []byte("OK"))
			_, _ = conn.Write(frame)
			return
		}
		_, _ = conn.Write([]byte(fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", computeWSAccept(wsKey))))
		return
	}

	// Engine 2: Actual Traffic Forwarding (strictly requires Traffic Tunnel toggle to be ON)
	if !tc.Enabled {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
		return
	}

	_ = conn.SetDeadline(time.Time{})
	if targetPort == "" {
		ports := parsePortList(tc.ForwardPorts)
		if len(ports) > 0 {
			targetPort = ports[0]
		} else {
			targetPort = "2053"
		}
	}

	target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	if tc.ID == 2 || grpcMode == "grpc" {
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\n\r\n"))
	} else {
		_, _ = conn.Write([]byte(fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", computeWSAccept(wsKey))))
	}

	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		n, _ := br.Read(buf)
		if n > 0 {
			_, _ = target.Write(buf[:n])
		}
	}

	mbLimit := parseSpeedLimit(tc.SpeedLimitMBps)
	txW := newThrottledWriter(target, &appRxBytes, mbLimit)
	rxW := newThrottledWriter(conn, &appTxBytes, mbLimit)

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(txW, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(rxW, target); done <- struct{}{} }()
	<-done
}

func acceptTrafficEntryLoop(ln net.Listener, peer ServerPeer, tc TunnelConfig, targetPort string) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		enableKeepAlive(client)
		go handleTrafficEntryClient(client, peer, tc, targetPort)
	}
}

func handleTrafficEntryClient(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	remoteAddr := fmt.Sprintf("%s:%d", peer.IP, tc.ListenPort)
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	rawConn, err := dialer.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer rawConn.Close()
	enableKeepAlive(rawConn)

	sni := strings.TrimSpace(tc.SNI)
	if sni == "" {
		sni = "www.speedtest.net"
	}
	pin := strings.TrimSpace(tc.CertPin)
	if pin == "" {
		pin = peer.RemoteCertPin
	}
	nextProtos := []string{"http/1.1"}
	if tc.ID == 2 {
		nextProtos = []string{"h2", "http/1.1"}
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         nextProtos,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	wsPath := strings.TrimSpace(tc.WSPath)
	if wsPath == "" {
		wsPath = "/ws"
	}
	if !strings.HasPrefix(wsPath, "/") {
		wsPath = "/" + wsPath
	}

	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	var req string
	if tc.ID == 2 {
		req = fmt.Sprintf("POST /GhoghnoosService/TunnelStream HTTP/1.1\r\nHost: %s\r\nContent-Type: application/grpc\r\nX-Tunnel-Mode: grpc\r\nX-Target-Port: %s\r\n\r\n",
			sni, targetPort)
	} else {
		req = fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nX-Target-Port: %s\r\n\r\n",
			wsPath, sni, wsKey, targetPort)
	}

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return
	}

	br := bufio.NewReader(tlsConn)
	statusLine, err := br.ReadString('\n')
	if err != nil || (!strings.Contains(statusLine, "101") && !strings.Contains(statusLine, "200")) {
		return
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		n, _ := br.Read(buf)
		if n > 0 {
			_, _ = client.Write(buf[:n])
		}
	}

	mbLimit := parseSpeedLimit(tc.SpeedLimitMBps)
	txW := newThrottledWriter(tlsConn, &appTxBytes, mbLimit)
	rxW := newThrottledWriter(client, &appRxBytes, mbLimit)

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(txW, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(rxW, tlsConn); done <- struct{}{} }()
	<-done
}

// ============================================================================
// ENGINE 1: SILENT CONNECTION DISCOVERY & LIFELINE
// ============================================================================

func recordLifelineEvent(peer *ServerPeer, mID int, mName string, sec int, lat int64, dir string) {
	ev := LifelineEvent{
		MethodID:    mID,
		MethodName:  mName,
		Security:    sec,
		LatencyMS:   lat,
		Direction:   dir,
		ConnectedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
	}
	history := []LifelineEvent{ev}
	for _, old := range peer.RecentLifelines {
		if len(history) >= 5 {
			break
		}
		history = append(history, old)
	}
	peer.RecentLifelines = history
}

func processIncomingSync(localPeerID string, pkt SyncPacket) SyncResponse {
	stateMu.Lock()
	defer stateMu.Unlock()

	var resp SyncResponse
	resp.OK = true
	resp.NodeID = appCfg.NodeID
	resp.CertPin = appCfg.CertPin

	for i := range appCfg.Servers {
		srv := &appCfg.Servers[i]
		if srv.ID == localPeerID || srv.ID == pkt.PeerID || srv.ID == pkt.SenderID {
			if appCfg.Role == "agent" && len(pkt.Tunnels) == 30 && pkt.ConfigVersion >= srv.ConfigVersion {
				srv.Tunnels = normalizeTunnels(pkt.Tunnels)
				srv.ConfigVersion = pkt.ConfigVersion
				srv.SyncState = "synced"
				go syncServerListeners(*srv)
			}
			srv.Status = "CONNECTED"
			srv.NextRetryAt = ""
			for _, m := range methodCatalogue {
				if m.ID == pkt.MethodID {
					srv.ActiveMethodID = m.ID
					srv.ActiveMethod = m.Name
					srv.ActiveSecurity = m.Security
					recordLifelineEvent(srv, m.ID, m.Name, m.Security, srv.ActiveLatencyMS, "inbound")
					break
				}
			}
			resp.ConfigVersion = srv.ConfigVersion
			resp.Tunnels = srv.Tunnels
			_ = saveConfig(configPath(), appCfg)
			break
		}
	}
	return resp
}

func probeSingleMethod(peer ServerPeer, tc TunnelConfig) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  time.Now().UTC().Format("15:04:05 UTC"),
	}

	if !tc.Implemented {
		res.Success = false
		res.ErrorReason = "Driver not implemented"
		return res
	}
	if strings.TrimSpace(peer.IP) == "" {
		res.Success = false
		res.ErrorReason = "Remote IP missing"
		return res
	}

	targetAddr := fmt.Sprintf("%s:%d", peer.IP, tc.ListenPort)
	start := time.Now()
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		res.Success = false
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	sni := strings.TrimSpace(tc.SNI)
	if sni == "" {
		sni = "www.speedtest.net"
	}
	pin := strings.TrimSpace(tc.CertPin)
	if pin == "" {
		pin = peer.RemoteCertPin
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		res.Success = false
		res.ErrorReason = "TLS failure"
		return res
	}
	defer tlsConn.Close()

	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	var req string
	if tc.ID == 2 {
		req = fmt.Sprintf("POST /GhoghnoosService/TunnelStream HTTP/1.1\r\nHost: %s\r\nContent-Type: application/grpc\r\nX-Tunnel-Mode: grpc\r\nX-Target-Port: probe:%d\r\n\r\n",
			sni, tc.ListenPort)
	} else {
		wsPath := strings.TrimSpace(tc.WSPath)
		if wsPath == "" {
			wsPath = "/ws"
		}
		req = fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nX-Target-Port: probe:%d\r\n\r\n",
			wsPath, sni, wsKey, tc.ListenPort)
	}

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	br := bufio.NewReader(tlsConn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		res.Success = false
		res.ErrorReason = "Timeout"
		return res
	}
	if (tc.ID == 1 && !strings.Contains(statusLine, "101")) || (tc.ID == 2 && !strings.Contains(statusLine, "200")) {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	res.Success = true
	res.LatencyMS = time.Since(start).Milliseconds()
	if res.LatencyMS <= 0 {
		res.LatencyMS = 1
	}
	return res
}

func pushParitySyncOverMethod(peer ServerPeer, tc TunnelConfig) bool {
	stateMu.RLock()
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	stateMu.RUnlock()

	targetAddr := fmt.Sprintf("%s:%d", peer.IP, tc.ListenPort)
	rawConn, err := net.DialTimeout("tcp", targetAddr, 4*time.Second)
	if err != nil {
		return false
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(6 * time.Second))

	sni := strings.TrimSpace(tc.SNI)
	if sni == "" {
		sni = "www.speedtest.net"
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	defer tlsConn.Close()

	// Add random-length jitter padding to avoid static handshake fingerprint
	padLen := 32 + rand.IntN(128)
	padHex, _ := randomHex(padLen)

	pkt := SyncPacket{
		Type:          "parity_sync",
		SenderID:      senderID,
		PeerID:        peer.ID,
		MethodID:      tc.ID,
		ConfigVersion: peer.ConfigVersion,
		CertPin:       certPin,
		Padding:       padHex,
	}
	if role == "master" {
		pkt.Tunnels = peer.Tunnels
	}
	rawPkt, _ := json.Marshal(pkt)
	b64 := base64.StdEncoding.EncodeToString(rawPkt)

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nX-Sahand-Sync: %s\r\n\r\n", sni, b64)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return false
	}

	br := bufio.NewReader(tlsConn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		return false
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	body, err := io.ReadAll(br)
	if err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(body, &resp) != nil || !resp.OK {
		return false
	}

	stateMu.Lock()
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peer.ID {
			if appCfg.Role == "agent" && len(resp.Tunnels) == 30 && resp.ConfigVersion >= appCfg.Servers[i].ConfigVersion {
				appCfg.Servers[i].Tunnels = normalizeTunnels(resp.Tunnels)
				appCfg.Servers[i].ConfigVersion = resp.ConfigVersion
				go syncServerListeners(appCfg.Servers[i])
			}
			if resp.CertPin != "" {
				appCfg.Servers[i].RemoteCertPin = resp.CertPin
			}
			appCfg.Servers[i].SyncState = "synced"
			_ = saveConfig(configPath(), appCfg)
			break
		}
	}
	stateMu.Unlock()
	return true
}

func startDiscoveryLoop(peerID string) {
	discoveryMu.Lock()
	if ch, ok := discoveryCancel[peerID]; ok {
		close(ch)
	}
	stopCh := make(chan struct{})
	discoveryCancel[peerID] = stopCh
	discoveryMu.Unlock()

	go func() {
		for {
			select {
			case <-stopCh:
				return
			default:
			}

			stateMu.Lock()
			var peer *ServerPeer
			for i := range appCfg.Servers {
				if appCfg.Servers[i].ID == peerID {
					peer = &appCfg.Servers[i]
					break
				}
			}
			if peer == nil || !peer.Running {
				stateMu.Unlock()
				return
			}
			peer.Status = "TESTING"
			peer.NextRetryAt = ""
			peerSnapshot := *peer
			tunnelsSnapshot := make([]TunnelConfig, len(peer.Tunnels))
			copy(tunnelsSnapshot, peer.Tunnels)
			stateMu.Unlock()

			// Test ALL 30 methods regardless of Traffic Tunnel toggle, sorted by Security % descending
			order := make([]int, len(tunnelsSnapshot))
			for i := range tunnelsSnapshot {
				order[i] = i
			}
			sort.SliceStable(order, func(i, j int) bool {
				if tunnelsSnapshot[order[i]].Security != tunnelsSnapshot[order[j]].Security {
					return tunnelsSnapshot[order[i]].Security > tunnelsSnapshot[order[j]].Security
				}
				return tunnelsSnapshot[order[i]].ID < tunnelsSnapshot[order[j]].ID
			})

			results := make(map[int]MethodResult, 30)
			var bestCandidate *TunnelConfig
			var bestResult MethodResult

			for _, idx := range order {
				select {
				case <-stopCh:
					return
				default:
				}
				tc := tunnelsSnapshot[idx]
				res := probeSingleMethod(peerSnapshot, tc)
				results[tc.ID] = res

				if res.Success && bestCandidate == nil {
					chosen := tc
					bestCandidate = &chosen
					bestResult = res
				}
				// Silent micro-delay between probes to prevent port-scan burst signature
				if tc.Implemented {
					time.Sleep(time.Duration(90+rand.IntN(140)) * time.Millisecond)
				}
			}

			stateMu.Lock()
			var updatedPeer *ServerPeer
			for i := range appCfg.Servers {
				if appCfg.Servers[i].ID == peerID {
					updatedPeer = &appCfg.Servers[i]
					break
				}
			}
			if updatedPeer == nil || !updatedPeer.Running {
				stateMu.Unlock()
				return
			}

			for i := range updatedPeer.Tunnels {
				if r, ok := results[updatedPeer.Tunnels[i].ID]; ok {
					updatedPeer.Tunnels[i].LastDiscovery = r
				}
			}

			if bestCandidate != nil {
				updatedPeer.Status = "CONNECTED"
				updatedPeer.ActiveMethodID = bestCandidate.ID
				updatedPeer.ActiveMethod = bestCandidate.Name
				updatedPeer.ActiveSecurity = bestCandidate.Security
				updatedPeer.ActiveLatencyMS = bestResult.LatencyMS
				updatedPeer.NextRetryAt = ""
				recordLifelineEvent(updatedPeer, bestCandidate.ID, bestCandidate.Name, bestCandidate.Security, bestResult.LatencyMS, "outbound")
				peerCopy := *updatedPeer
				_ = saveConfig(configPath(), appCfg)
				stateMu.Unlock()

				// Push automatic parity check & config sync over winning lifeline
				_ = pushParitySyncOverMethod(peerCopy, *bestCandidate)
				go syncServerListeners(peerCopy)
				return
			}

			// Random retry delay between 10 and 30 minutes per spec
			retryMins := 10 + rand.IntN(21)
			retryDuration := time.Duration(retryMins) * time.Minute
			nextRetry := time.Now().UTC().Add(retryDuration)
			updatedPeer.Status = "RETRY SCHEDULED"
			updatedPeer.ActiveMethodID = 0
			updatedPeer.ActiveMethod = ""
			updatedPeer.NextRetryAt = nextRetry.Format("15:04 UTC")
			_ = saveConfig(configPath(), appCfg)
			stateMu.Unlock()

			timer := time.NewTimer(retryDuration)
			select {
			case <-stopCh:
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func stopDiscoveryLoop(peerID string) {
	discoveryMu.Lock()
	if ch, ok := discoveryCancel[peerID]; ok {
		close(ch)
		delete(discoveryCancel, peerID)
	}
	discoveryMu.Unlock()
}

// ============================================================================
// LOCAL OS ANALYTICS (/proc/net/dev)
// ============================================================================

func readPhysicalNetCounters() (uint64, uint64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return atomic.LoadUint64(&appRxBytes), atomic.LoadUint64(&appTxBytes)
	}
	var totalRx, totalTx uint64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[2:] {
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colon])
		if iface == "lo" ||
			strings.HasPrefix(iface, "tun") ||
			strings.HasPrefix(iface, "tap") ||
			strings.HasPrefix(iface, "wg") ||
			strings.HasPrefix(iface, "docker") ||
			strings.HasPrefix(iface, "veth") ||
			strings.HasPrefix(iface, "br-") {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 == nil && err2 == nil {
			totalRx += rx
			totalTx += tx
		}
	}
	return totalRx, totalTx
}

func loadAnalytics() {
	analyticsMu.Lock()
	defer analyticsMu.Unlock()

	raw, err := os.ReadFile(analyticsPath())
	if err == nil {
		_ = json.Unmarshal(raw, &analyticsData)
	}
	curRx, curTx := readPhysicalNetCounters()
	analyticsData.LastRawRx = curRx
	analyticsData.LastRawTx = curTx
	ensure30DaysLocked()
}

func ensure30DaysLocked() {
	now := time.Now().UTC()
	byDate := make(map[string]DailyUsage, len(analyticsData.Days))
	for _, d := range analyticsData.Days {
		byDate[d.Date] = d
	}
	days := make([]DailyUsage, 0, 30)
	for i := 29; i >= 0; i-- {
		dateStr := now.AddDate(0, 0, -i).Format("2006-01-02")
		if existing, ok := byDate[dateStr]; ok {
			days = append(days, existing)
		} else {
			days = append(days, DailyUsage{Date: dateStr, RxBytes: 0, TxBytes: 0})
		}
	}
	analyticsData.Days = days
}

func sampleAnalyticsTick() {
	analyticsMu.Lock()
	defer analyticsMu.Unlock()

	ensure30DaysLocked()
	curRx, curTx := readPhysicalNetCounters()
	var deltaRx, deltaTx uint64
	if curRx >= analyticsData.LastRawRx && analyticsData.LastRawRx > 0 {
		deltaRx = curRx - analyticsData.LastRawRx
	}
	if curTx >= analyticsData.LastRawTx && analyticsData.LastRawTx > 0 {
		deltaTx = curTx - analyticsData.LastRawTx
	}
	analyticsData.LastRawRx = curRx
	analyticsData.LastRawTx = curTx

	today := time.Now().UTC().Format("2006-01-02")
	for i := range analyticsData.Days {
		if analyticsData.Days[i].Date == today {
			analyticsData.Days[i].RxBytes += deltaRx
			analyticsData.Days[i].TxBytes += deltaTx
			break
		}
	}

	if raw, err := json.MarshalIndent(analyticsData, "", "  "); err == nil {
		_ = os.WriteFile(analyticsPath(), raw, 0600)
	}
}

// ============================================================================
// HTTP SERVER & REST API
// ============================================================================

func runServer() error {
	cfg, exists, err := loadExistingConfig(configPath())
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("configuration file does not exist; run the installer first")
	}
	if cfg.Role != "master" && cfg.Role != "agent" {
		return errors.New("invalid role in configuration")
	}
	if cfg.NodeID == "" {
		return errors.New("node ID is missing from configuration")
	}
	if cfg.PanelPort < 1024 || cfg.PanelPort > 65535 {
		return errors.New("invalid panel port in configuration")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = fmt.Sprintf(":%d", cfg.PanelPort)
	}
	if cfg.AdminUsername == "" || cfg.AdminSalt == "" || cfg.AdminHash == "" {
		return errors.New("administrator credentials are missing")
	}

	if changed, err := ensureCryptoMaterial(&cfg); err != nil {
		return err
	} else if changed {
		_ = saveConfig(configPath(), cfg)
	}

	stateMu.Lock()
	appCfg = cfg
	stateMu.Unlock()

	loadAnalytics()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			sampleAnalyticsTick()
		}
	}()

	for _, srv := range cfg.Servers {
		syncServerListeners(srv)
		if srv.Running {
			startDiscoveryLoop(srv.ID)
		}
	}

	distFS, err := fs.Sub(webAssets, "web/dist")
	if err != nil {
		return fmt.Errorf("frontend assets are missing: %w", err)
	}
	assetFS, err := fs.Sub(distFS, "assets")
	if err != nil {
		return fmt.Errorf("frontend assets directory is missing: %w", err)
	}
	assetServer := http.FileServer(http.FS(assetFS))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", handleHealth)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logout", requireAuth(handleLogout))
	mux.HandleFunc("/api/v1/node", requireAuth(handleNode))
	mux.HandleFunc("/api/v1/state", requireAuth(handleState))
	mux.HandleFunc("/api/v1/servers", requireAuth(handleServers))
	mux.HandleFunc("/api/v1/servers/action", requireAuth(handleServerAction))
	mux.HandleFunc("/api/v1/tunnels", requireAuth(handleTunnelsUpdate))
	mux.HandleFunc("/api/v1/analytics", requireAuth(handleAnalytics))

	mux.HandleFunc("/assets/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.StripPrefix("/assets/", assetServer).ServeHTTP(w, r)
	}))
	mux.HandleFunc("/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleDashboard(w, r, distFS)
	}))

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("%s %s starting on %s", AppName, AppVersion, cfg.ListenAddr)
	if cfg.PanelURL != "" {
		log.Printf("Public panel: %s", cfg.PanelURL)
	} else {
		log.Printf("Panel is available on port %d (HTTP mode)", cfg.PanelPort)
	}
	return server.ListenAndServe()
}

func handleNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stateMu.RLock()
	info := NodeInfo{
		AppVersion: AppVersion,
		Role:       appCfg.Role,
		NodeID:     appCfg.NodeID,
		Status:     "online",
		PanelURL:   appCfg.PanelURL,
	}
	stateMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stateMu.RLock()
	payload := struct {
		AppVersion string                `json:"app_version"`
		Role       string                `json:"role"`
		NodeID     string                `json:"node_id"`
		Servers    []ServerPeer          `json:"servers"`
		Catalogue  []MethodCatalogueItem `json:"catalogue"`
	}{
		AppVersion: AppVersion,
		Role:       appCfg.Role,
		NodeID:     appCfg.NodeID,
		Servers:    appCfg.Servers,
		Catalogue:  methodCatalogue,
	}
	stateMu.RUnlock()

	if payload.Servers == nil {
		payload.Servers = []ServerPeer{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func handleServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name  string `json:"name"`
		IP    string `json:"ip"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	stateMu.Lock()
	role := appCfg.Role
	if role == "master" {
		name := strings.TrimSpace(req.Name)
		ip := strings.TrimSpace(req.IP)
		if name == "" || ip == "" {
			stateMu.Unlock()
			http.Error(w, "server name and agent IP are required", http.StatusBadRequest)
			return
		}
		peerID, _ := randomHex(8)
		peer := ServerPeer{
			ID:              peerID,
			Name:            name,
			IP:              ip,
			ConfigVersion:   1,
			SyncState:       "synced",
			Status:          "WAITING",
			Running:         false,
			RecentLifelines: []LifelineEvent{},
			Tunnels:         defaultTunnelsForServer(),
		}
		tok, err := generatePeerToken(appCfg, peer)
		if err != nil {
			stateMu.Unlock()
			http.Error(w, "could not generate token", http.StatusInternalServerError)
			return
		}
		peer.Token = tok
		appCfg.Servers = append(appCfg.Servers, peer)
		_ = saveConfig(configPath(), appCfg)
		stateMu.Unlock()

		syncServerListeners(peer)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(peer)
		return
	}

	// Agent role: validate Master IP and Connection Token, extract ports, and auto-start discovery
	ip := strings.TrimSpace(req.IP)
	rawToken := strings.TrimSpace(req.Token)
	if ip == "" || rawToken == "" {
		stateMu.Unlock()
		http.Error(w, "master IP and connection token are required", http.StatusBadRequest)
		return
	}
	tp, err := parseAndValidateToken(rawToken)
	if err != nil {
		stateMu.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tunnels := defaultTunnelsForServer()
	for i := range tunnels {
		if i < len(tp.Ports) && tp.Ports[i] >= 1024 && tp.Ports[i] <= 65535 {
			tunnels[i].ListenPort = tp.Ports[i]
		}
	}

	peer := ServerPeer{
		ID:              tp.AID,
		Name:            "Master (" + ip + ")",
		IP:              ip,
		Token:           rawToken,
		ConfigVersion:   tp.V,
		SyncState:       "synced",
		Status:          "TESTING",
		Running:         true,
		RemoteCertPin:   tp.Pin,
		RecentLifelines: []LifelineEvent{},
		Tunnels:         tunnels,
	}

	// Replace existing Master record or append
	if len(appCfg.Servers) > 0 {
		stopDiscoveryLoop(appCfg.Servers[0].ID)
		stopAllServerListeners(appCfg.Servers[0].ID)
		appCfg.Servers = []ServerPeer{peer}
	} else {
		appCfg.Servers = append(appCfg.Servers, peer)
	}
	_ = saveConfig(configPath(), appCfg)
	stateMu.Unlock()

	syncServerListeners(peer)
	startDiscoveryLoop(peer.ID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(peer)
}

func handleServerAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ServerID string `json:"server_id"`
		Action   string `json:"action"` // "play" | "pause" | "delete" | "regen_token"
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	stateMu.Lock()
	idx := -1
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == req.ServerID {
			idx = i
			break
		}
	}
	if idx < 0 {
		stateMu.Unlock()
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}

	switch req.Action {
	case "play":
		appCfg.Servers[idx].Running = true
		appCfg.Servers[idx].Status = "TESTING"
		appCfg.Servers[idx].NextRetryAt = ""
		peer := appCfg.Servers[idx]
		_ = saveConfig(configPath(), appCfg)
		stateMu.Unlock()
		syncServerListeners(peer)
		startDiscoveryLoop(peer.ID)

	case "pause":
		appCfg.Servers[idx].Running = false
		appCfg.Servers[idx].Status = "PAUSED"
		appCfg.Servers[idx].NextRetryAt = ""
		peerID := appCfg.Servers[idx].ID
		_ = saveConfig(configPath(), appCfg)
		stateMu.Unlock()
		stopDiscoveryLoop(peerID)

	case "regen_token":
		if appCfg.Role != "master" {
			stateMu.Unlock()
			http.Error(w, "only master can generate tokens", http.StatusForbidden)
			return
		}
		appCfg.Servers[idx].ConfigVersion++
		tok, err := generatePeerToken(appCfg, appCfg.Servers[idx])
		if err != nil {
			stateMu.Unlock()
			http.Error(w, "failed to generate token", http.StatusInternalServerError)
			return
		}
		appCfg.Servers[idx].Token = tok
		_ = saveConfig(configPath(), appCfg)
		stateMu.Unlock()

	case "delete":
		peerID := appCfg.Servers[idx].ID
		appCfg.Servers = append(appCfg.Servers[:idx], appCfg.Servers[idx+1:]...)
		_ = saveConfig(configPath(), appCfg)
		stateMu.Unlock()
		stopDiscoveryLoop(peerID)
		stopAllServerListeners(peerID)

	default:
		stateMu.Unlock()
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func handleTunnelsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ServerID string       `json:"server_id"`
		Tunnel   TunnelConfig `json:"tunnel"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	stateMu.Lock()
	if appCfg.Role != "master" {
		stateMu.Unlock()
		http.Error(w, "tunnels are read-only on agent nodes", http.StatusForbidden)
		return
	}

	sIdx := -1
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == req.ServerID {
			sIdx = i
			break
		}
	}
	if sIdx < 0 {
		stateMu.Unlock()
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}

	srv := &appCfg.Servers[sIdx]
	for i := range srv.Tunnels {
		if srv.Tunnels[i].ID == req.Tunnel.ID {
			prevDiscovery := srv.Tunnels[i].LastDiscovery
			updated := req.Tunnel
			if updated.ListenPort < 1024 || updated.ListenPort > 65535 {
				updated.ListenPort = srv.Tunnels[i].ListenPort
			}
			updated.Name = srv.Tunnels[i].Name
			updated.Security = srv.Tunnels[i].Security
			updated.TrafficType = srv.Tunnels[i].TrafficType
			updated.Implemented = srv.Tunnels[i].Implemented
			updated.LastDiscovery = prevDiscovery
			srv.Tunnels[i] = updated
			break
		}
	}

	srv.ConfigVersion++
	srv.SyncState = "pending_sync"
	if tok, err := generatePeerToken(appCfg, *srv); err == nil {
		srv.Token = tok
	}
	peerCopy := *srv
	_ = saveConfig(configPath(), appCfg)
	stateMu.Unlock()

	// Make-Before-Break listener update & automatic live push to Agent
	syncServerListeners(peerCopy)
	go func() {
		for _, tc := range peerCopy.Tunnels {
			if tc.Implemented {
				if pushParitySyncOverMethod(peerCopy, tc) {
					return
				}
			}
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sampleAnalyticsTick()
	analyticsMu.Lock()
	days := make([]DailyUsage, len(analyticsData.Days))
	copy(days, analyticsData.Days)
	analyticsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Days []DailyUsage `json:"days"`
	}{Days: days})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	peerIP := net.ParseIP(host)
	if peerIP == nil {
		return "unknown"
	}
	if peerIP.IsLoopback() {
		forwarded := r.Header.Get("X-Forwarded-For")
		if forwarded != "" {
			candidate := strings.TrimSpace(strings.Split(forwarded, ",")[0])
			if ip := net.ParseIP(candidate); ip != nil {
				return ip.String()
			}
		}
	}
	return peerIP.String()
}

func allowLogin(ip string) bool {
	loginMu.Lock()
	defer loginMu.Unlock()

	now := time.Now()
	recent := make([]time.Time, 0)
	for _, t := range loginAttempts[ip] {
		if now.Sub(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 5 {
		loginAttempts[ip] = recent
		return false
	}
	recent = append(recent, now)
	loginAttempts[ip] = recent

	for key, attempts := range loginAttempts {
		if key == ip {
			continue
		}
		active := false
		for _, attempt := range attempts {
			if now.Sub(attempt) < 10*time.Minute {
				active = true
				break
			}
		}
		if !active {
			delete(loginAttempts, key)
		}
	}
	return true
}

func createSession() (string, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	now := time.Now()
	for key, session := range sessions {
		if now.After(session.ExpiresAt) {
			delete(sessions, key)
		}
	}
	sessions[token] = Session{ExpiresAt: now.Add(sessionTTL)}
	return token, nil
}

func validSession(r *http.Request) bool {
	cookie, err := r.Cookie("sahand_session")
	if err != nil {
		return false
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	session, ok := sessions[cookie.Value]
	if !ok {
		return false
	}
	if time.Now().After(session.ExpiresAt) {
		delete(sessions, cookie.Value)
		return false
	}
	return true
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validSession(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if validSession(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, loginHTML)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r)
	if !allowLogin(ip) {
		http.Error(w, "too many login attempts; try again later", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	cfg, _, err := loadExistingConfig(configPath())
	if err != nil {
		http.Error(w, "configuration error", http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(cfg.AdminUsername)) == 1
	passOK := verifyPassword(password, cfg.AdminSalt, cfg.AdminHash)
	if !userOK || !passOK {
		time.Sleep(500 * time.Millisecond)
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := createSession()
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	secure := isHTTPS(r)
	http.SetCookie(w, &http.Cookie{
		Name: "sahand_session", Value: token, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
		Expires: time.Now().Add(sessionTTL), MaxAge: int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if cookie, err := r.Cookie("sahand_session"); err == nil {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: "sahand_session", Value: "", Path: "/",
		HttpOnly: true, Secure: isHTTPS(r),
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleDashboard(w http.ResponseWriter, r *http.Request, dist fs.FS) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		http.Error(w, "dashboard frontend is unavailable", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(index)
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sahand Tunnel - Login</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#eef2ff;font-family:Arial,sans-serif}
.card{width:min(420px,92%);padding:34px;background:#151d32;border:1px solid #293653;border-radius:18px}
h1{margin:0 0 8px;font-size:25px}
p{color:#aab6ce;margin-bottom:26px}
label{display:block;margin:16px 0 7px;color:#cbd5e1;font-size:14px}
input{width:100%;padding:13px;border-radius:9px;border:1px solid #34435f;background:#0c1427;color:white;font-size:15px}
button{width:100%;margin-top:24px;padding:13px;border:0;border-radius:9px;background:#3977f6;color:white;font-weight:bold;font-size:15px;cursor:pointer}
.small{margin-top:20px;text-align:center;font-size:12px;color:#7787a6}
</style>
</head>
<body>
<div class="card">
<h1>Sahand Tunnel</h1>
<p>Sign in to your server dashboard.</p>
<form method="post" action="/login">
<label>Username</label>
<input name="username" autocomplete="username" required>
<label>Password</label>
<input name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
<div class="small">Server management</div>
</div>
</body>
</html>`

func runMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println()
		fmt.Println("================================")
		fmt.Println("       SAHAND TUNNEL")
		fmt.Println("================================")
		fmt.Println("1. Configure Domain & SSL")
		fmt.Println("2. Start Service")
		fmt.Println("3. Restart Service")
		fmt.Println("4. Stop Service")
		fmt.Println("5. Service Status")
		fmt.Println("6. View Logs")
		fmt.Println("7. Update")
		fmt.Println("0. Exit")
		fmt.Print("\nSelect an option: ")

		choice, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Println("Input error:", err)
			return
		}
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			cmd := exec.Command("sahand-tunnel-domain")
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Println("Domain/SSL configuration failed:", err)
			}
		case "2":
			runSystemctl("enable", "--now", "sahand-tunnel")
		case "3":
			runSystemctl("restart", "sahand-tunnel")
		case "4":
			runSystemctl("stop", "sahand-tunnel")
		case "5":
			runSystemctl("status", "sahand-tunnel", "--no-pager")
		case "6":
			cmd := exec.Command("journalctl", "-u", "sahand-tunnel", "-n", "50", "--no-pager")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			_ = cmd.Run()
		case "7":
			cmd := exec.Command("sahand-tunnel-update")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Println("Update failed:", err)
			}
		case "0":
			return
		case "":
			if errors.Is(err, io.EOF) {
				return
			}
		default:
			fmt.Println("Invalid option.")
		}

		if errors.Is(err, io.EOF) {
			return
		}
		fmt.Print("\nPress Enter to continue...")
		_, _ = reader.ReadString('\n')
	}
}

func runSystemctl(args ...string) {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("Command failed:", err)
	}
}
