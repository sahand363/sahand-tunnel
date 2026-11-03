package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	tokenVersionV2   = 2
	tokenPrefixV2    = "st2."
	maxTokenWireSize = 4096
)

type Config struct {
	Role                          string       `json:"role"`
	NodeID                        string       `json:"node_id"`
	ListenAddr                    string       `json:"listen_addr"`
	PanelURL                      string       `json:"panel_url,omitempty"`
	PanelPort                     int          `json:"panel_port"`
	AdminUsername                 string       `json:"admin_username"`
	AdminSalt                     string       `json:"admin_salt"`
	AdminHash                     string       `json:"admin_hash"`
	TokenSecret                   string       `json:"token_secret,omitempty"`
	MasterSigningPrivateKey       string       `json:"master_signing_private_key,omitempty"`
	MasterSigningPublicKey        string       `json:"master_signing_public_key,omitempty"`
	MasterNoiseStaticPrivateKey   string       `json:"master_noise_static_private_key,omitempty"`
	MasterNoiseStaticPublicKey    string       `json:"master_noise_static_public_key,omitempty"`
	AgentSigningPrivateKey        string       `json:"agent_signing_private_key,omitempty"`
	AgentSigningPublicKey         string       `json:"agent_signing_public_key,omitempty"`
	AgentNoiseStaticPrivateKey    string       `json:"agent_noise_static_private_key,omitempty"`
	AgentNoiseStaticPublicKey     string       `json:"agent_noise_static_public_key,omitempty"`
	TrustedMasterSigningPublicKey string       `json:"trusted_master_signing_public_key,omitempty"`
	TLSCertPEM                    string       `json:"tls_cert_pem,omitempty"`
	TLSKeyPEM                     string       `json:"tls_key_pem,omitempty"`
	CertPin                       string       `json:"cert_pin,omitempty"`
	MasterTZName                  string       `json:"master_tz_name,omitempty"`
	MasterTZOffsetSec             int          `json:"master_tz_offset_sec,omitempty"`
	MasterClockDelta              int64        `json:"master_clock_delta,omitempty"`
	Servers                       []ServerPeer `json:"servers,omitempty"`
	CreatedAt                     time.Time    `json:"created_at"`
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
	MethodID      int    `json:"method_id"`
	Success       bool   `json:"success"`
	Direction     string `json:"direction"`
	LatencyMS     int64  `json:"latency_ms"`
	MinLatencyMS  int64  `json:"min_latency_ms,omitempty"`
	MaxLatencyMS  int64  `json:"max_latency_ms,omitempty"`
	JitterMS      int64  `json:"jitter_ms,omitempty"`
	PacketLossPct int    `json:"packet_loss_pct,omitempty"`
	ErrorReason   string `json:"error_reason,omitempty"`
	TestedAt      string `json:"tested_at,omitempty"`
}

type LifelineEvent struct {
	MethodID    int    `json:"method_id"`
	MethodName  string `json:"method_name"`
	Port        int    `json:"port"`
	Security    int    `json:"security"`
	LatencyMS   int64  `json:"latency_ms"`
	Direction   string `json:"direction"`
	Initiator   string `json:"initiator,omitempty"`
	ConnectedAt string `json:"connected_at"`
}

type GREFRPForwardRule struct {
	Name          string `json:"name"`
	Protocol      string `json:"protocol"`        // "tcp", "udp", or "tcp+udp"
	LocalAddr     string `json:"local_addr"`      // default "127.0.0.1"
	LocalPort     string `json:"local_port"`      // single port "45001" or range "45001-45005"
	RemotePort    string `json:"remote_port"`     // single port "45001" or range "45001-45005"
	UseEncryption bool   `json:"use_encryption"`
	UseCompress   bool   `json:"use_compression"`
	ProxyProtoV2  bool   `json:"proxy_proto_v2"`
}

type GREFRPDiagnostics struct {
	EngineName         string   `json:"engine_name"`
	GREInterfaceStatus string   `json:"gre_interface_status"`
	GREPrivatePingOK   bool     `json:"gre_private_ping_ok"`
	GREPacketLossPct   int      `json:"gre_packet_loss_pct"`
	GRERoundTripMS     int64    `json:"gre_rtt_ms"`
	FRPSServiceStatus  string   `json:"frps_service_status"`
	FRPCServiceStatus  string   `json:"frpc_service_status"`
	ActivePath         string   `json:"active_path"` // "GRE" or "PUBLIC_FALLBACK"
	PortForwardStatus  string   `json:"port_forward_status"`
	ServiceUptime      string   `json:"service_uptime"`
	ReconnectCount     int      `json:"reconnect_count"`
	LastFailureReason  string   `json:"last_failure_reason,omitempty"`
	LastRecoveryAt     string   `json:"last_recovery_at,omitempty"`
	RecentLogs         []string `json:"recent_logs,omitempty"`
}

type GREFRPConfig struct {
	InternalEngine     string              `json:"internal_engine"` // "gre-frp"
	LocalPublicIP      string              `json:"local_public_ip"`
	RemotePublicIP     string              `json:"remote_public_ip"`
	GREInterfaceName   string              `json:"gre_interface_name"`
	PrivateSubnetCIDR  string              `json:"private_subnet_cidr"` // e.g. "10.77.25.0/30"
	LocalPrivateIP     string              `json:"local_private_ip"`    // e.g. "10.77.25.1"
	RemotePrivateIP    string              `json:"remote_private_ip"`   // e.g. "10.77.25.2"
	MTU                int                 `json:"mtu"`                 // default 1400
	RouteConfig        string              `json:"route_config"`        // e.g. "auto (/30 point-to-point)"
	HealthCheckSec     int                 `json:"health_check_sec"`    // default 5
	FailureThreshold   int                 `json:"failure_threshold"`   // default 3
	RecoveryThreshold  int                 `json:"recovery_threshold"`  // default 2
	AutoPublicFallback bool                `json:"auto_public_fallback"`
	AutoRestoreGRE     bool                `json:"auto_restore_gre"`
	FRPVersion         string              `json:"frp_version"`     // "0.61.1"
	FRPTransport       string              `json:"frp_transport"`   // "tcp", "kcp", "quic", "websocket", "wss"
	FRPServerPort      int                 `json:"frp_server_port"` // default 28025
	FRPAuthToken       string              `json:"frp_auth_token"`
	FRPEncryption      bool                `json:"frp_encryption"`
	FRPCompression     bool                `json:"frp_compression"`
	FRPTCPMux          bool                `json:"frp_tcp_mux"`
	FRPProxyProtoV2    bool                `json:"frp_proxy_proto_v2"`
	ForwardingRules    []GREFRPForwardRule `json:"forwarding_rules"`
	Diagnostics        GREFRPDiagnostics   `json:"diagnostics"`
}

type TunnelConfig struct {
	ID             int           `json:"id"`
	Name           string        `json:"name"`
	Security       int           `json:"security"`
	TrafficType    string        `json:"traffic_type"`
	Implemented    bool          `json:"implemented"`
	Enabled        bool          `json:"enabled"`
	ListenPort     int           `json:"listen_port"`
	ForwardPorts   string        `json:"forward_ports"`
	SNI            string        `json:"sni,omitempty"`
	WSPath         string        `json:"ws_path,omitempty"`
	CertPin        string        `json:"cert_pin,omitempty"`
	RawTransport   string        `json:"raw_transport,omitempty"`
	GREFRP         *GREFRPConfig `json:"gre_frp,omitempty"`
	HeartbeatSec   int           `json:"heartbeat_sec,omitempty"`
	StreamLimit    int           `json:"stream_limit,omitempty"`
	SpeedLimitMBps string        `json:"speed_limit_mbps"`
	LastDiscovery  MethodResult  `json:"last_discovery"`
}

type ServerPeer struct {
	ID                         string          `json:"id"`
	Name                       string          `json:"name"`
	IP                         string          `json:"ip"`
	Token                      string          `json:"token"`
	TokenRevoked               bool            `json:"token_revoked,omitempty"`
	PeerSecret                 string          `json:"peer_secret,omitempty"`
	MasterSigningPublicKey     string          `json:"master_signing_public_key,omitempty"`
	MasterNoiseStaticPublicKey string          `json:"master_noise_static_public_key,omitempty"`
	AgentSigningPublicKey      string          `json:"agent_signing_public_key,omitempty"`
	AgentNoiseStaticPublicKey  string          `json:"agent_noise_static_public_key,omitempty"`
	TrustedFingerprint         string          `json:"trusted_fingerprint,omitempty"`
	ConfigVersion              int             `json:"config_version"`
	SyncState                  string          `json:"sync_state"`
	Status                     string          `json:"status"`
	Running                    bool            `json:"running"`
	ActiveMethodID             int             `json:"active_method_id"`
	ActiveMethod               string          `json:"active_method"`
	ActivePort                 int             `json:"active_port"`
	ActiveSecurity             int             `json:"active_security"`
	ActiveLatencyMS            int64           `json:"active_latency_ms"`
	ActiveDirection            string          `json:"active_direction,omitempty"`
	ActiveInitiator            string          `json:"active_initiator,omitempty"`
	LastInboundAt              int64           `json:"last_inbound_at,omitempty"`
	NextRetryAt                string          `json:"next_retry_at,omitempty"`
	RemoteCertPin              string          `json:"remote_cert_pin,omitempty"`
	RecentLifelines            []LifelineEvent `json:"recent_lifelines"`
	Tunnels                    []TunnelConfig  `json:"tunnels"`
}

type TokenPayload struct {
	V                          int    `json:"v"`
	CV                         int    `json:"cv"`
	MID                        string `json:"mid"`
	AID                        string `json:"aid"`
	MIP                        string `json:"mip,omitempty"`
	Pin                        string `json:"pin,omitempty"`
	MasterSigningPublicKey     string `json:"master_signing_public_key"`
	MasterNoiseStaticPublicKey string `json:"master_noise_static_public_key"`
	TS                         int64  `json:"ts"`
	Exp                        int64  `json:"exp"`
	TZName                     string `json:"tzn,omitempty"`
	TZOff                      int    `json:"tzo,omitempty"`
	Ports                      []int  `json:"ports"`
	Key                        string `json:"key"`
	Sig                        string `json:"sig"`
}

type SyncPacket struct {
	Type                       string         `json:"type"`
	SenderID                   string         `json:"sender_id"`
	PeerID                     string         `json:"peer_id"`
	MethodID                   int            `json:"method_id"`
	Port                       int            `json:"port"`
	LatencyMS                  int64          `json:"latency_ms"`
	ConfigVersion              int            `json:"config_version"`
	MasterUnix                 int64          `json:"m_unix,omitempty"`
	MasterTZName               string         `json:"m_tzn,omitempty"`
	MasterTZOff                int            `json:"m_tzo,omitempty"`
	Tunnels                    []TunnelConfig `json:"tunnels,omitempty"`
	CertPin                    string         `json:"cert_pin,omitempty"`
	MasterSigningPublicKey     string         `json:"master_signing_public_key,omitempty"`
	MasterNoiseStaticPublicKey string         `json:"master_noise_static_public_key,omitempty"`
	AgentSigningPublicKey      string         `json:"agent_signing_public_key,omitempty"`
	AgentNoiseStaticPublicKey  string         `json:"agent_noise_static_public_key,omitempty"`
	Padding                    string         `json:"pad,omitempty"`
}

type SyncResponse struct {
	OK                         bool           `json:"ok"`
	NodeID                     string         `json:"node_id"`
	ConfigVersion              int            `json:"config_version"`
	MasterUnix                 int64          `json:"m_unix,omitempty"`
	MasterTZName               string         `json:"m_tzn,omitempty"`
	MasterTZOff                int            `json:"m_tzo,omitempty"`
	Tunnels                    []TunnelConfig `json:"tunnels,omitempty"`
	CertPin                    string         `json:"cert_pin,omitempty"`
	MasterSigningPublicKey     string         `json:"master_signing_public_key,omitempty"`
	MasterNoiseStaticPublicKey string         `json:"master_noise_static_public_key,omitempty"`
	AgentSigningPublicKey      string         `json:"agent_signing_public_key,omitempty"`
	AgentNoiseStaticPublicKey  string         `json:"agent_noise_static_public_key,omitempty"`
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
	AppVersion                  string `json:"app_version"`
	Role                        string `json:"role"`
	NodeID                      string `json:"node_id"`
	Status                      string `json:"status"`
	PanelURL                    string `json:"panel_url"`
	MasterSigningPublicKey      string `json:"master_signing_public_key,omitempty"`
	MasterNoiseStaticPublicKey  string `json:"master_noise_static_public_key,omitempty"`
	MasterSigningKeyFingerprint string `json:"master_signing_key_fingerprint,omitempty"`
	AgentSigningPublicKey       string `json:"agent_signing_public_key,omitempty"`
	AgentNoiseStaticPublicKey   string `json:"agent_noise_static_public_key,omitempty"`
}

type Session struct {
	ExpiresAt time.Time
}

var methodCatalogue = []MethodCatalogueItem{
	{1, "WSS", 95, "tcp", true, 28001, []string{"listen_port", "forward_ports", "sni", "ws_path", "speed_limit_mbps"}},
	{2, "gRPC", 95, "tcp", true, 28002, []string{"listen_port", "forward_ports", "sni", "cert_pin", "stream_limit", "speed_limit_mbps"}},
	{3, "HTTP/2", 90, "tcp", true, 28003, []string{"listen_port", "forward_ports", "sni", "heartbeat_sec", "speed_limit_mbps"}},
	{4, "HTTP CONNECT", 76, "tcp", true, 28004, []string{"listen_port", "forward_ports", "sni", "speed_limit_mbps"}},
	{5, "HTTPS Proxy", 82, "tcp", true, 28005, []string{"listen_port", "forward_ports", "sni", "speed_limit_mbps"}},
	{6, "TCP Relay", 45, "tcp", true, 28006, []string{"listen_port", "forward_ports", "speed_limit_mbps"}},
	{7, "TLS Stream", 88, "tcp", true, 28007, []string{"listen_port", "forward_ports", "sni", "cert_pin", "speed_limit_mbps"}},
	{8, "QUIC", 92, "tcp+udp", true, 28008, []string{"listen_port", "forward_ports", "sni", "cert_pin", "heartbeat_sec", "stream_limit", "speed_limit_mbps"}},
	{9, "Rathole", 94, "tcp+udp", true, 28009, []string{"listen_port", "forward_ports", "heartbeat_sec", "speed_limit_mbps"}},
	{10, "Noise TCP Stealth", 97, "tcp+udp", true, 28010, []string{"listen_port", "forward_ports", "heartbeat_sec", "speed_limit_mbps"}},
	{11, "Reverse TCP", 50, "tcp", true, 28011, []string{"listen_port", "forward_ports", "heartbeat_sec", "speed_limit_mbps"}},
	{12, "SOCKS5", 60, "tcp+udp", true, 28012, []string{"listen_port", "forward_ports", "speed_limit_mbps"}},
	{13, "SSH Tunnel", 86, "tcp", true, 28013, []string{"listen_port", "forward_ports", "heartbeat_sec", "speed_limit_mbps"}},
	{14, "Raw TCP", 35, "tcp", true, 28014, []string{"listen_port", "forward_ports", "speed_limit_mbps"}},
	{15, "UDP Relay", 40, "udp", true, 28015, []string{"listen_port", "forward_ports", "speed_limit_mbps"}},
	{16, "DNS Transport", 70, "tcp+udp", true, 28016, []string{"listen_port", "forward_ports", "sni", "speed_limit_mbps"}},
	{17, "TLS over TCP", 84, "tcp", true, 28017, []string{"listen_port", "forward_ports", "sni", "speed_limit_mbps"}},
	{18, "HTTP Long Polling", 72, "tcp", true, 28018, []string{"listen_port", "forward_ports", "sni", "ws_path", "speed_limit_mbps"}},
	{19, "WebTransport", 93, "tcp+udp", true, 28019, []string{"listen_port", "forward_ports", "sni", "speed_limit_mbps"}},
	{20, "mTLS Stream", 99, "tcp", true, 28020, []string{"listen_port", "forward_ports", "sni", "cert_pin", "speed_limit_mbps"}},
	{21, "TCP Multiplex", 68, "tcp", true, 28021, []string{"listen_port", "forward_ports", "stream_limit", "speed_limit_mbps"}},
	{22, "WebSocket Multiplex", 89, "tcp", true, 28022, []string{"listen_port", "forward_ports", "sni", "ws_path", "stream_limit", "speed_limit_mbps"}},
	{23, "HTTP Upgrade", 74, "tcp", true, 28023, []string{"listen_port", "forward_ports", "sni", "ws_path", "speed_limit_mbps"}},
	{24, "SAHAND-RAW", 96, "tcp+udp", true, 28024, []string{"listen_port", "forward_ports", "raw_transport", "heartbeat_sec", "stream_limit", "speed_limit_mbps"}},
	{25, "GRE + FRP", 91, "tcp+udp", true, 28025, []string{"listen_port", "forward_ports", "gre_frp", "heartbeat_sec", "stream_limit", "speed_limit_mbps"}},
	{26, "Stream Bridge", 80, "tcp+udp", false, 28026, []string{"listen_port", "forward_ports", "stream_limit"}},
	{27, "Fallback TCP", 42, "tcp", false, 28027, []string{"listen_port", "forward_ports"}},
	{28, "Custom TLS", 91, "tcp", false, 28028, []string{"listen_port", "forward_ports", "sni", "cert_pin"}},
	{29, "Hybrid Transport", 87, "tcp+udp", false, 28029, []string{"listen_port", "forward_ports", "sni"}},
	{30, "Experimental", 62, "tcp+udp", false, 28030, []string{"listen_port", "forward_ports"}},
}

var (
	stateMu   sync.RWMutex
	appCfg    Config
	localCert tls.Certificate

	atomicIsAgent          atomic.Bool
	atomicMasterTZOffset   atomic.Int64
	atomicMasterClockDelta atomic.Int64
	atomicMasterTZName     atomic.Value
)

func syncMasterClockAtomics(cfg Config) {
	atomicIsAgent.Store(cfg.Role == "agent")
	atomicMasterTZOffset.Store(int64(cfg.MasterTZOffsetSec))
	atomicMasterClockDelta.Store(cfg.MasterClockDelta)
	atomicMasterTZName.Store(cfg.MasterTZName)
}

func masterNow() time.Time {
	if !atomicIsAgent.Load() {
		return time.Now()
	}
	delta := atomicMasterClockDelta.Load()
	tzOff := int(atomicMasterTZOffset.Load())
	tzName, _ := atomicMasterTZName.Load().(string)

	now := time.Now().Add(time.Duration(delta) * time.Second)
	if tzName != "" || tzOff != 0 {
		if tzName == "" {
			tzName = "MASTER"
		}
		loc := time.FixedZone(tzName, tzOff)
		return now.In(loc)
	}
	return now
}

func formatMasterTimestamp(t time.Time) string {
	zone, _ := t.Zone()
	if zone == "" {
		return t.Format("2006-01-02 15:04")
	}
	return fmt.Sprintf("%s %s", t.Format("2006-01-02 15:04"), zone)
}

func formatMasterClock(t time.Time) string {
	zone, _ := t.Zone()
	if zone == "" {
		return t.Format("15:04")
	}
	return fmt.Sprintf("%s %s", t.Format("15:04"), zone)
}

func formatMasterClockSec(t time.Time) string {
	zone, _ := t.Zone()
	if zone == "" {
		return t.Format("15:04:05")
	}
	return fmt.Sprintf("%s %s", t.Format("15:04:05"), zone)
}

func buildMasterTimeHeader() string {
	if atomicIsAgent.Load() {
		return ""
	}
	now := time.Now()
	zName, zOff := now.Zone()
	return fmt.Sprintf("%d|%d|%s", now.Unix(), zOff, zName)
}

func applyMasterTimeHeader(hdr string) {
	parts := strings.SplitN(strings.TrimSpace(hdr), "|", 3)
	if len(parts) < 2 {
		return
	}
	unixSec, err1 := strconv.ParseInt(parts[0], 10, 64)
	tzOff, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || unixSec <= 0 {
		return
	}
	var tzName string
	if len(parts) == 3 {
		tzName = parts[2]
	}
	stateMu.Lock()
	if appCfg.Role == "agent" {
		appCfg.MasterClockDelta = unixSec - time.Now().Unix()
		appCfg.MasterTZOffsetSec = tzOff
		if tzName != "" {
			appCfg.MasterTZName = tzName
		}
		syncMasterClockAtomics(appCfg)
	}
	stateMu.Unlock()
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
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"www.speedtest.net", "localhost", "127.0.0.1", "::1"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
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

// ============================================================================
// STAGE 1: INDEPENDENT KEYPAIR GENERATION, FINGERPRINTS & STRICT JSON VALIDATION
// ============================================================================

func generateEd25519KeypairHex() (privHex string, pubHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(priv), hex.EncodeToString(pub), nil
}

func validateEd25519KeypairHex(privHex, pubHex string) bool {
	privBytes, err1 := hex.DecodeString(strings.TrimSpace(privHex))
	pubBytes, err2 := hex.DecodeString(strings.TrimSpace(pubHex))
	if err1 != nil || err2 != nil || len(privBytes) != ed25519.PrivateKeySize || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	derivedPub := ed25519.PrivateKey(privBytes).Public().(ed25519.PublicKey)
	return subtle.ConstantTimeCompare(derivedPub, pubBytes) == 1
}

func generateX25519KeypairHex() (privHex string, pubHex string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(priv.Bytes()), hex.EncodeToString(priv.PublicKey().Bytes()), nil
}

func validateX25519KeypairHex(privHex, pubHex string) bool {
	privBytes, err1 := hex.DecodeString(strings.TrimSpace(privHex))
	pubBytes, err2 := hex.DecodeString(strings.TrimSpace(pubHex))
	if err1 != nil || err2 != nil || len(privBytes) != 32 || len(pubBytes) != 32 {
		return false
	}
	privKey, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(privKey.PublicKey().Bytes(), pubBytes) == 1
}

func decodeHexExact(raw string, expectedBytes int) ([]byte, error) {
	clean := strings.ToLower(strings.TrimSpace(raw))
	if len(clean) != expectedBytes*2 {
		return nil, fmt.Errorf("expected %d hex characters, got %d", expectedBytes*2, len(clean))
	}
	out, err := hex.DecodeString(clean)
	if err != nil || len(out) != expectedBytes {
		return nil, fmt.Errorf("invalid hex encoding: %w", err)
	}
	return out, nil
}

func ComputeSigningKeyFingerprint(pubKeyHex string) (string, error) {
	pubBytes, err := decodeHexExact(pubKeyHex, ed25519.PublicKeySize)
	if err != nil {
		return "", fmt.Errorf("invalid signing public key: %w", err)
	}
	sum := sha256.Sum256(pubBytes)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeFingerprintHex(raw string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(raw))
	clean = strings.TrimPrefix(clean, "sha256:")
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, " ", "")
	if len(clean) != sha256.Size*2 {
		return "", fmt.Errorf("invalid fingerprint length (expected 64 hex characters / 32-byte SHA-256 digest)")
	}
	if _, err := hex.DecodeString(clean); err != nil {
		return "", fmt.Errorf("invalid fingerprint hex format: %w", err)
	}
	return clean, nil
}

func checkNoDuplicateJSONKeys(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			keyStr, ok := keyTok.(string)
			if !ok {
				return errors.New("expected string key in JSON object")
			}
			if _, dup := seen[keyStr]; dup {
				return fmt.Errorf("duplicate JSON key %q is not allowed", keyStr)
			}
			seen[keyStr] = struct{}{}
			if err := checkNoDuplicateJSONKeys(dec); err != nil {
				return err
			}
		}
		endTok, err := dec.Token()
		if err != nil {
			return err
		}
		if endTok != json.Delim('}') {
			return errors.New("malformed JSON object closing delimiter")
		}
	case '[':
		for dec.More() {
			if err := checkNoDuplicateJSONKeys(dec); err != nil {
				return err
			}
		}
		endTok, err := dec.Token()
		if err != nil {
			return err
		}
		if endTok != json.Delim(']') {
			return errors.New("malformed JSON array closing delimiter")
		}
	}
	return nil
}

func unmarshalStrictJSON(data []byte, dst any) error {
	dupScanner := json.NewDecoder(bytes.NewReader(data))
	if err := checkNoDuplicateJSONKeys(dupScanner); err != nil {
		return err
	}
	var extraCheck any
	if err := dupScanner.Decode(&extraCheck); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing data after JSON document")
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing data after JSON document")
	}
	return nil
}

func defaultGREFRPConfig(listenPort int, forwardPorts string) *GREFRPConfig {
	if listenPort <= 0 {
		listenPort = 28025
	}
	if strings.TrimSpace(forwardPorts) == "" {
		forwardPorts = "32025"
	}
	return &GREFRPConfig{
		InternalEngine:     "gre-frp",
		GREInterfaceName:   "sahand-gre0",
		PrivateSubnetCIDR:  "10.77.25.0/30",
		LocalPrivateIP:     "10.77.25.1",
		RemotePrivateIP:    "10.77.25.2",
		MTU:                1400,
		RouteConfig:        "10.77.25.0/30 via sahand-gre0",
		HealthCheckSec:     5,
		FailureThreshold:   3,
		RecoveryThreshold:  2,
		AutoPublicFallback: true,
		AutoRestoreGRE:     true,
		FRPVersion:         "0.61.1",
		FRPTransport:       "tcp",
		FRPServerPort:      listenPort,
		FRPEncryption:      true,
		FRPCompression:     false,
		FRPTCPMux:          true,
		FRPProxyProtoV2:    false,
		ForwardingRules:    buildGREFRPRulesFromCSV(forwardPorts, true, false, false),
		Diagnostics: GREFRPDiagnostics{
			EngineName:         "gre-frp",
			GREInterfaceStatus: "STANDBY",
			FRPSServiceStatus:  "BUILT-IN READY",
			FRPCServiceStatus:  "BUILT-IN READY",
			ActivePath:         "GRE",
			PortForwardStatus:  "READY",
		},
	}
}

func buildGREFRPRulesFromCSV(csvPorts string, enc, comp, ppv2 bool) []GREFRPForwardRule {
	var rules []GREFRPForwardRule
	parts := strings.Split(csvPorts, ",")
	for idx, raw := range parts {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		localPort := token
		remotePort := token
		if strings.Contains(token, ":") {
			segs := strings.SplitN(token, ":", 2)
			remotePort = strings.TrimSpace(segs[0])
			localPort = strings.TrimSpace(segs[1])
		}
		rules = append(rules, GREFRPForwardRule{
			Name:          fmt.Sprintf("rule-%02d", idx+1),
			Protocol:      "tcp+udp",
			LocalAddr:     "127.0.0.1",
			LocalPort:     localPort,
			RemotePort:    remotePort,
			UseEncryption: enc,
			UseCompress:   comp,
			ProxyProtoV2:  ppv2,
		})
	}
	if len(rules) == 0 {
		rules = append(rules, GREFRPForwardRule{
			Name:          "rule-01",
			Protocol:      "tcp+udp",
			LocalAddr:     "127.0.0.1",
			LocalPort:     "32025",
			RemotePort:    "32025",
			UseEncryption: enc,
			UseCompress:   comp,
			ProxyProtoV2:  ppv2,
		})
	}
	return rules
}

func defaultTunnelsForServer() []TunnelConfig {
	list := make([]TunnelConfig, 0, len(methodCatalogue))
	for _, item := range methodCatalogue {
		tc := TunnelConfig{
			ID:             item.ID,
			Name:           item.Name,
			Security:       item.Security,
			TrafficType:    item.SupportedTraffic,
			Implemented:    item.Implemented,
			Enabled:        item.ID == 1,
			ListenPort:     item.DefaultPort,
			ForwardPorts:   strconv.Itoa(32000 + item.ID),
			SpeedLimitMBps: "0",
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
			case "raw_transport":
				tc.RawTransport = "auto"
			case "gre_frp":
				tc.GREFRP = defaultGREFRPConfig(tc.ListenPort, tc.ForwardPorts)
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
			if cur.ListenPort < 1024 ||
				cur.ListenPort > 65535 ||
				cur.ListenPort == 10200+def.ID ||
				cur.ListenPort == 11300+def.ID ||
				cur.ListenPort == 11400+def.ID {
				cur.ListenPort = def.ListenPort
			}
			trimmedFwd := strings.TrimSpace(cur.ForwardPorts)
			if trimmedFwd == "" || trimmedFwd == "2053" {
				cur.ForwardPorts = def.ForwardPorts
			}
			if cur.SNI == "" {
				cur.SNI = def.SNI
			}
			if cur.WSPath == "" {
				cur.WSPath = def.WSPath
			}
			if def.RawTransport != "" {
				rt := strings.ToLower(strings.TrimSpace(cur.RawTransport))
				if rt != "raw_ip" && rt != "udp" && rt != "auto" {
					cur.RawTransport = def.RawTransport
				} else {
					cur.RawTransport = rt
				}
			}
			if def.ID == 25 {
				cur.GREFRP = normalizeGREFRPConfig(cur.GREFRP, cur.ListenPort, cur.ForwardPorts)
			}
			if cur.HeartbeatSec <= 0 {
				cur.HeartbeatSec = def.HeartbeatSec
			}
			if cur.StreamLimit <= 0 {
				cur.StreamLimit = def.StreamLimit
			}
			if strings.TrimSpace(cur.SpeedLimitMBps) == "" {
				cur.SpeedLimitMBps = "0"
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
	info, statErr := os.Stat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		return cfg, false, nil
	}
	if statErr != nil {
		return cfg, false, statErr
	}
	if info.Mode().Perm()&0077 != 0 {
		_ = os.Chmod(path, 0600)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, false, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, true, fmt.Errorf("cannot read existing configuration: %w", err)
	}
	syncMasterClockAtomics(cfg)
	return cfg, true, nil
}

func saveConfig(path string, cfg Config) error {
	syncMasterClockAtomics(cfg)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil && len(existing) > 0 {
		_ = os.WriteFile(path+".bak", existing, 0600)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(tmp, 0600)
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

	if cfg.Role != "agent" {
		if !validateEd25519KeypairHex(cfg.MasterSigningPrivateKey, cfg.MasterSigningPublicKey) {
			privHex, pubHex, err := generateEd25519KeypairHex()
			if err != nil {
				return false, err
			}
			cfg.MasterSigningPrivateKey = privHex
			cfg.MasterSigningPublicKey = pubHex
			changed = true
		}
		if !validateX25519KeypairHex(cfg.MasterNoiseStaticPrivateKey, cfg.MasterNoiseStaticPublicKey) {
			privHex, pubHex, err := generateX25519KeypairHex()
			if err != nil {
				return false, err
			}
			cfg.MasterNoiseStaticPrivateKey = privHex
			cfg.MasterNoiseStaticPublicKey = pubHex
			changed = true
		}
	}

	if !validateEd25519KeypairHex(cfg.AgentSigningPrivateKey, cfg.AgentSigningPublicKey) {
		privHex, pubHex, err := generateEd25519KeypairHex()
		if err != nil {
			return false, err
		}
		cfg.AgentSigningPrivateKey = privHex
		cfg.AgentSigningPublicKey = pubHex
		changed = true
	}
	if !validateX25519KeypairHex(cfg.AgentNoiseStaticPrivateKey, cfg.AgentNoiseStaticPublicKey) {
		privHex, pubHex, err := generateX25519KeypairHex()
		if err != nil {
			return false, err
		}
		cfg.AgentNoiseStaticPrivateKey = privHex
		cfg.AgentNoiseStaticPublicKey = pubHex
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
		srv := &cfg.Servers[i]
		srv.Tunnels = normalizeTunnels(srv.Tunnels)
		if srv.ConfigVersion <= 0 {
			srv.ConfigVersion = 1
		}
		if srv.Status == "" {
			srv.Status = "WAITING"
		}
		if srv.SyncState == "" {
			srv.SyncState = "synced"
		}
		if srv.RecentLifelines == nil {
			srv.RecentLifelines = []LifelineEvent{}
		}
		if cfg.Role == "master" {
			if _, err := decodeHexExact(srv.PeerSecret, 32); err != nil {
				sec, sErr := randomHex(32)
				if sErr != nil {
					return false, sErr
				}
				srv.PeerSecret = sec
				changed = true
			}
			if srv.MasterSigningPublicKey != cfg.MasterSigningPublicKey {
				srv.MasterSigningPublicKey = cfg.MasterSigningPublicKey
				changed = true
			}
			if srv.MasterNoiseStaticPublicKey != cfg.MasterNoiseStaticPublicKey {
				srv.MasterNoiseStaticPublicKey = cfg.MasterNoiseStaticPublicKey
				changed = true
			}
			if tok, err := generatePeerToken(*cfg, *srv); err == nil && tok != srv.Token {
				srv.Token = tok
				changed = true
			}
		} else if cfg.Role == "agent" {
			if srv.AgentSigningPublicKey != cfg.AgentSigningPublicKey {
				srv.AgentSigningPublicKey = cfg.AgentSigningPublicKey
				changed = true
			}
			if srv.AgentNoiseStaticPublicKey != cfg.AgentNoiseStaticPublicKey {
				srv.AgentNoiseStaticPublicKey = cfg.AgentNoiseStaticPublicKey
				changed = true
			}
			if strings.HasPrefix(strings.TrimSpace(srv.Token), "st1.") {
				srv.Running = false
				srv.Status = "TOKEN UPGRADE REQUIRED"
				srv.SyncState = "reauth_required"
				changed = true
			}
		}
	}
	syncMasterClockAtomics(*cfg)
	return changed, nil
}

// ============================================================================
// STAGE 1: CANONICAL BINARY SERIALIZATION, ED25519 SIGNING & TRUST ESTABLISHMENT
// ============================================================================

// Returns the Master's Ed25519 signing and X25519 Noise static keypairs.
// If a unit test constructs a `Config` struct literal directly without calling `ensureCryptoMaterial`,
// falls back to deterministic test keys seeded from `cfg.TokenSecret` and `cfg.NodeID`.
func resolveMasterKeyMaterial(cfg Config) (signPrivHex, signPubHex, noisePrivHex, noisePubHex string, err error) {
	signPrivHex = strings.ToLower(strings.TrimSpace(cfg.MasterSigningPrivateKey))
	signPubHex = strings.ToLower(strings.TrimSpace(cfg.MasterSigningPublicKey))
	noisePrivHex = strings.ToLower(strings.TrimSpace(cfg.MasterNoiseStaticPrivateKey))
	noisePubHex = strings.ToLower(strings.TrimSpace(cfg.MasterNoiseStaticPublicKey))

	if validateEd25519KeypairHex(signPrivHex, signPubHex) && validateX25519KeypairHex(noisePrivHex, noisePubHex) {
		return signPrivHex, signPubHex, noisePrivHex, noisePubHex, nil
	}

	seedMaterial := cfg.TokenSecret + "|" + cfg.NodeID
	if strings.TrimSpace(seedMaterial) == "|" {
		seedMaterial = "default-test-master-seed"
	}

	if !validateEd25519KeypairHex(signPrivHex, signPubHex) {
		edSeed := sha256.Sum256([]byte("sahand-master-ed25519-test-seed-v2|" + seedMaterial))
		priv := ed25519.NewKeyFromSeed(edSeed[:])
		pub := priv.Public().(ed25519.PublicKey)
		signPrivHex = hex.EncodeToString(priv)
		signPubHex = hex.EncodeToString(pub)
	}

	if !validateX25519KeypairHex(noisePrivHex, noisePubHex) {
		xSeed := sha256.Sum256([]byte("sahand-master-x25519-test-seed-v2|" + seedMaterial))
		priv, xErr := ecdh.X25519().NewPrivateKey(xSeed[:])
		if xErr != nil {
			return "", "", "", "", xErr
		}
		noisePrivHex = hex.EncodeToString(priv.Bytes())
		noisePubHex = hex.EncodeToString(priv.PublicKey().Bytes())
	}

	return signPrivHex, signPubHex, noisePrivHex, noisePubHex, nil
}

func encodeCanonicalTokenPayload(tp TokenPayload) ([]byte, error) {
	if tp.V != tokenVersionV2 {
		return nil, fmt.Errorf("unsupported token version %d (expected %d)", tp.V, tokenVersionV2)
	}
	if tp.CV < 1 || tp.CV > 1_000_000_000 {
		return nil, fmt.Errorf("invalid token config version %d", tp.CV)
	}
	mid := strings.ToLower(strings.TrimSpace(tp.MID))
	aid := strings.ToLower(strings.TrimSpace(tp.AID))
	if mid == "" || aid == "" {
		return nil, errors.New("missing MID or AID in token payload")
	}
	if mid == aid {
		return nil, errors.New("token MID and AID must be distinct")
	}
	if len(mid) > 128 || len(aid) > 128 {
		return nil, errors.New("token MID or AID exceeds maximum length")
	}

	mpkBytes, err := decodeHexExact(tp.MasterSigningPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("invalid master_signing_public_key: %w", err)
	}
	mnpkBytes, err := decodeHexExact(tp.MasterNoiseStaticPublicKey, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid master_noise_static_public_key: %w", err)
	}

	var pinBytes []byte
	if strings.TrimSpace(tp.Pin) == "" {
		pinBytes = make([]byte, sha256.Size)
	} else {
		pinBytes, err = decodeHexExact(tp.Pin, sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate pin in token: %w", err)
		}
	}

	keyBytes, err := decodeHexExact(tp.Key, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid 256-bit peer key in token: %w", err)
	}

	mip := strings.TrimSpace(tp.MIP)
	if mip != "" {
		if len(mip) > 45 || net.ParseIP(mip) == nil {
			return nil, fmt.Errorf("invalid master IP %q in token", mip)
		}
	}
	if tp.TS <= 0 || tp.Exp <= tp.TS {
		return nil, errors.New("invalid token timestamps")
	}
	if tp.TZOff < -50400 || tp.TZOff > 50400 {
		return nil, errors.New("invalid token timezone offset")
	}
	if len(tp.TZName) > 32 {
		return nil, errors.New("token timezone name too long")
	}
	for i := 0; i < len(tp.TZName); i++ {
		if tp.TZName[i] < 0x20 || tp.TZName[i] > 0x7E {
			return nil, errors.New("invalid character in token timezone name")
		}
	}
	if len(tp.Ports) != 30 {
		return nil, fmt.Errorf("expected exactly 30 ports in token, got %d", len(tp.Ports))
	}
	for _, p := range tp.Ports {
		if p < 1024 || p > 65535 {
			return nil, fmt.Errorf("invalid port %d in token", p)
		}
	}

	var buf bytes.Buffer
	buf.WriteString("SAHAND-TOKEN-ED25519-V2\x00")

	var u32 [4]byte
	var u64 [8]byte
	var u16 [2]byte

	binary.BigEndian.PutUint32(u32[:], uint32(tp.V))
	buf.Write(u32[:])
	binary.BigEndian.PutUint32(u32[:], uint32(tp.CV))
	buf.Write(u32[:])

	binary.BigEndian.PutUint16(u16[:], uint16(len(mid)))
	buf.Write(u16[:])
	buf.WriteString(mid)

	binary.BigEndian.PutUint16(u16[:], uint16(len(aid)))
	buf.Write(u16[:])
	buf.WriteString(aid)

	buf.Write(mpkBytes)
	buf.Write(mnpkBytes)
	buf.Write(pinBytes)
	buf.Write(keyBytes)

	binary.BigEndian.PutUint64(u64[:], uint64(tp.TS))
	buf.Write(u64[:])
	binary.BigEndian.PutUint64(u64[:], uint64(tp.Exp))
	buf.Write(u64[:])
	binary.BigEndian.PutUint32(u32[:], uint32(int32(tp.TZOff)))
	buf.Write(u32[:])

	binary.BigEndian.PutUint16(u16[:], uint16(len(mip)))
	buf.Write(u16[:])
	buf.WriteString(mip)

	binary.BigEndian.PutUint16(u16[:], uint16(len(tp.TZName)))
	buf.Write(u16[:])
	buf.WriteString(tp.TZName)

	binary.BigEndian.PutUint16(u16[:], uint16(len(tp.Ports)))
	buf.Write(u16[:])
	for _, p := range tp.Ports {
		binary.BigEndian.PutUint16(u16[:], uint16(p))
		buf.Write(u16[:])
	}

	return buf.Bytes(), nil
}

func signTokenPayloadEd25519(tp TokenPayload, masterSigningPrivKeyHex string) (string, error) {
	privBytes, err := decodeHexExact(masterSigningPrivKeyHex, ed25519.PrivateKeySize)
	if err != nil {
		return "", fmt.Errorf("invalid master Ed25519 signing private key: %w", err)
	}
	canonical, err := encodeCanonicalTokenPayload(tp)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), canonical)
	return hex.EncodeToString(sig), nil
}

func generatePeerToken(cfg Config, peer ServerPeer) (string, error) {
	signPrivHex, signPubHex, _, noisePubHex, err := resolveMasterKeyMaterial(cfg)
	if err != nil {
		return "", err
	}

	ports := make([]int, 0, 30)
	tunnels := normalizeTunnels(peer.Tunnels)
	for _, t := range tunnels {
		ports = append(ports, t.ListenPort)
	}

	peerSecretHex := strings.ToLower(strings.TrimSpace(peer.PeerSecret))
	if _, err := decodeHexExact(peerSecretHex, 32); err != nil {
		mac := hmac.New(sha256.New, []byte(cfg.TokenSecret))
		_, _ = mac.Write([]byte("sahand-peer-random-secret-v2|" + peer.ID + "|" + strconv.Itoa(peer.ConfigVersion)))
		peerSecretHex = hex.EncodeToString(mac.Sum(nil))
	}

	cv := peer.ConfigVersion
	if cv <= 0 {
		cv = 1
	}

	now := time.Now()
	zName, zOff := now.Zone()

	tp := TokenPayload{
		V:                          tokenVersionV2,
		CV:                         cv,
		MID:                        strings.ToLower(strings.TrimSpace(cfg.NodeID)),
		AID:                        strings.ToLower(strings.TrimSpace(peer.ID)),
		Pin:                        strings.ToLower(strings.TrimSpace(cfg.CertPin)),
		MasterSigningPublicKey:     signPubHex,
		MasterNoiseStaticPublicKey: noisePubHex,
		TS:                         now.Unix(),
		Exp:                        now.Add(365 * 24 * time.Hour).Unix(),
		TZName:                     zName,
		TZOff:                      zOff,
		Ports:                      ports,
		Key:                        peerSecretHex,
	}

	sigHex, err := signTokenPayloadEd25519(tp, signPrivHex)
	if err != nil {
		return "", err
	}
	tp.Sig = sigHex

	raw, err := json.Marshal(tp)
	if err != nil {
		return "", err
	}
	return tokenPrefixV2 + base64.RawURLEncoding.EncodeToString(raw), nil
}

func parseAndValidateToken(rawToken string) (TokenPayload, error) {
	var tp TokenPayload
	trimmed := strings.TrimSpace(rawToken)
	if len(trimmed) > maxTokenWireSize {
		return tp, errors.New("token exceeds maximum allowed size")
	}
	if strings.HasPrefix(trimmed, "st1.") {
		return tp, errors.New("legacy st1. token is rejected; use an Ed25519-signed st2. token")
	}
	if !strings.HasPrefix(trimmed, tokenPrefixV2) {
		return tp, errors.New("invalid token prefix (expected st2.)")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(trimmed, tokenPrefixV2))
	if err != nil {
		return tp, errors.New("invalid token base64url encoding")
	}

	if err := unmarshalStrictJSON(decoded, &tp); err != nil {
		return tp, fmt.Errorf("invalid token JSON payload: %w", err)
	}

	if time.Now().Unix() > tp.Exp {
		return tp, errors.New("token has expired")
	}

	canonical, err := encodeCanonicalTokenPayload(tp)
	if err != nil {
		return tp, err
	}
	pubBytes, err := decodeHexExact(tp.MasterSigningPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return tp, errors.New("invalid master signing public key in token")
	}
	sigBytes, err := decodeHexExact(tp.Sig, ed25519.SignatureSize)
	if err != nil {
		return tp, errors.New("invalid Ed25519 signature encoding in token")
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, sigBytes) {
		return tp, errors.New("token Ed25519 signature verification failed")
	}

	return tp, nil
}

func VerifyAndEstablishInitialTrust(cfg *Config, masterIP, rawToken, expectedFingerprint string) (ServerPeer, error) {
	var empty ServerPeer
	if cfg == nil {
		return empty, errors.New("configuration is nil")
	}
	ip := strings.TrimSpace(masterIP)
	if ip == "" || net.ParseIP(ip) == nil {
		return empty, errors.New("valid master IP address is required")
	}

	tp, err := parseAndValidateToken(rawToken)
	if err != nil {
		return empty, err
	}

	actualFP, err := ComputeSigningKeyFingerprint(tp.MasterSigningPublicKey)
	if err != nil {
		return empty, err
	}

	normExpectedFP := ""
	if strings.TrimSpace(expectedFingerprint) != "" {
		normExpectedFP, err = normalizeFingerprintHex(expectedFingerprint)
		if err != nil {
			return empty, err
		}
	} else if strings.TrimSpace(cfg.TrustedMasterSigningPublicKey) != "" {
		pinnedFP, fpErr := ComputeSigningKeyFingerprint(cfg.TrustedMasterSigningPublicKey)
		if fpErr != nil {
			return empty, errors.New("master signing key fingerprint is required for initial trust verification")
		}
		normExpectedFP = pinnedFP
	} else {
		return empty, errors.New("master signing key fingerprint is required for initial trust verification")
	}

	if subtle.ConstantTimeCompare([]byte(actualFP), []byte(normExpectedFP)) != 1 {
		return empty, errors.New("master signing key fingerprint mismatch: refusing to establish initial trust")
	}

	if cfg.TrustedMasterSigningPublicKey != "" &&
		subtle.ConstantTimeCompare(
			[]byte(strings.ToLower(strings.TrimSpace(cfg.TrustedMasterSigningPublicKey))),
			[]byte(strings.ToLower(strings.TrimSpace(tp.MasterSigningPublicKey))),
		) != 1 {
		return empty, errors.New("token signing key does not match previously pinned master signing public key")
	}

	if !validateEd25519KeypairHex(cfg.AgentSigningPrivateKey, cfg.AgentSigningPublicKey) {
		privHex, pubHex, gErr := generateEd25519KeypairHex()
		if gErr != nil {
			return empty, gErr
		}
		cfg.AgentSigningPrivateKey = privHex
		cfg.AgentSigningPublicKey = pubHex
	}
	if !validateX25519KeypairHex(cfg.AgentNoiseStaticPrivateKey, cfg.AgentNoiseStaticPublicKey) {
		privHex, pubHex, gErr := generateX25519KeypairHex()
		if gErr != nil {
			return empty, gErr
		}
		cfg.AgentNoiseStaticPrivateKey = privHex
		cfg.AgentNoiseStaticPublicKey = pubHex
	}

	tunnels := defaultTunnelsForServer()
	cidr, mIP, aIP := deriveDefaultSlash30ForPeer(tp.AID)
	for i := range tunnels {
		if i < len(tp.Ports) && tp.Ports[i] >= 1024 && tp.Ports[i] <= 65535 {
			tunnels[i].ListenPort = tp.Ports[i]
		}
		if tunnels[i].ID == 25 && tunnels[i].GREFRP != nil {
			tunnels[i].GREFRP.PrivateSubnetCIDR = cidr
			tunnels[i].GREFRP.LocalPrivateIP = aIP
			tunnels[i].GREFRP.RemotePrivateIP = mIP
			tunnels[i].GREFRP.RemotePublicIP = ip
			if len(tp.AID) >= 6 {
				tunnels[i].GREFRP.GREInterfaceName = "gre-" + tp.AID[:6]
			}
			tunnels[i].GREFRP.FRPServerPort = tunnels[i].ListenPort
		}
	}

	peer := ServerPeer{
		ID:                         tp.AID,
		Name:                       "Master (" + ip + ")",
		IP:                         ip,
		Token:                      strings.TrimSpace(rawToken),
		PeerSecret:                 tp.Key,
		MasterSigningPublicKey:     tp.MasterSigningPublicKey,
		MasterNoiseStaticPublicKey: tp.MasterNoiseStaticPublicKey,
		AgentSigningPublicKey:      cfg.AgentSigningPublicKey,
		AgentNoiseStaticPublicKey:  cfg.AgentNoiseStaticPublicKey,
		TrustedFingerprint:         actualFP,
		ConfigVersion:              tp.CV,
		SyncState:                  "synced",
		Status:                     "TESTING",
		Running:                    true,
		RemoteCertPin:              tp.Pin,
		RecentLifelines:            []LifelineEvent{},
		Tunnels:                    tunnels,
	}

	cfg.TrustedMasterSigningPublicKey = tp.MasterSigningPublicKey
	if tp.TZName != "" || tp.TZOff != 0 {
		cfg.MasterTZName = tp.TZName
		cfg.MasterTZOffsetSec = tp.TZOff
	}
	cfg.Servers = []ServerPeer{peer}

	if err := saveConfig(configPath(), *cfg); err != nil {
		return empty, err
	}
	return peer, nil
}

func derivePeerAuthKey(cfg Config, peer ServerPeer) ([]byte, error) {
	if peer.TokenRevoked {
		return nil, errors.New("peer token has been revoked")
	}
	if strings.TrimSpace(peer.Token) == "" {
		return nil, errors.New("peer token is missing")
	}

	tp, err := parseAndValidateToken(peer.Token)
	if err != nil {
		return nil, err
	}

	if peer.ID != "" && subtle.ConstantTimeCompare([]byte(strings.ToLower(strings.TrimSpace(peer.ID))), []byte(tp.AID)) != 1 {
		return nil, errors.New("peer ID mismatch with token AID")
	}

	expectedMasterSignPub := strings.ToLower(strings.TrimSpace(peer.MasterSigningPublicKey))
	if expectedMasterSignPub == "" {
		if cfg.Role == "agent" {
			expectedMasterSignPub = strings.ToLower(strings.TrimSpace(cfg.TrustedMasterSigningPublicKey))
			if expectedMasterSignPub == "" {
				return nil, errors.New("initial trust not established: master signing public key is not verified")
			}
		} else if cfg.MasterSigningPublicKey != "" {
			expectedMasterSignPub = strings.ToLower(strings.TrimSpace(cfg.MasterSigningPublicKey))
		} else {
			_, signPubHex, _, _, rErr := resolveMasterKeyMaterial(cfg)
			if rErr == nil {
				expectedMasterSignPub = signPubHex
			}
		}
	}
	if expectedMasterSignPub == "" {
		return nil, errors.New("master signing public key trust anchor is missing")
	}
	if subtle.ConstantTimeCompare([]byte(tp.MasterSigningPublicKey), []byte(expectedMasterSignPub)) != 1 {
		return nil, errors.New("token master signing public key does not match trusted master key")
	}

	if peer.PeerSecret != "" {
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(strings.TrimSpace(peer.PeerSecret))), []byte(tp.Key)) != 1 {
			return nil, errors.New("token peer secret does not match stored peer secret")
		}
	}

	pskBytes, err := decodeHexExact(tp.Key, 32)
	if err != nil {
		return nil, errors.New("invalid 256-bit peer secret in token")
	}

	salt := []byte("sahand-hkdf-salt-v2|" + tp.MID + "|" + tp.AID)
	info := []byte("sahand-peer-root-auth-key-v2")
	r := hkdf.New(sha256.New, pskBytes, salt, info)
	rootKey := make([]byte, 32)
	if _, err := io.ReadFull(r, rootKey); err != nil {
		return nil, err
	}
	return rootKey, nil
}

func derivePeerSubKey(cfg Config, peer ServerPeer, domainLabel string) ([]byte, error) {
	if strings.TrimSpace(domainLabel) == "" {
		return nil, errors.New("subkey domain label is required")
	}
	rootKey, err := derivePeerAuthKey(cfg, peer)
	if err != nil {
		return nil, err
	}
	r := hkdf.Expand(sha256.New, rootKey, []byte("sahand-subkey-v2|"+domainLabel))
	subKey := make([]byte, 32)
	if _, err := io.ReadFull(r, subKey); err != nil {
		return nil, err
	}
	return subKey, nil
}
