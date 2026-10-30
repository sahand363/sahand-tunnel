
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The frontend is built by GitHub Actions before Go compilation.
//go:embed web/dist
var webAssets embed.FS

const (
	AppName        = "sahand-tunnel"
	AppVersion     = "0.3.0"
	defaultPort    = 18080
	passwordRounds = 310000
	sessionTTL     = 12 * time.Hour
)

type Config struct {
	Role          string    `json:"role"`
	NodeID        string    `json:"node_id"`
	ListenAddr    string    `json:"listen_addr"`
	PanelURL      string    `json:"panel_url,omitempty"`
	PanelPort     int       `json:"panel_port"`
	AdminUsername string    `json:"admin_username"`
	AdminSalt     string    `json:"admin_salt"`
	AdminHash     string    `json:"admin_hash"`
	CreatedAt     time.Time `json:"created_at"`
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

var (
	sessionsMu sync.Mutex
	sessions   = make(map[string]Session)

	loginMu       sync.Mutex
	loginAttempts = make(map[string][]time.Time)
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
	mux.HandleFunc("/api/v1/node", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleNode(w, r, cfg)
	}))
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

func handleNode(w http.ResponseWriter, r *http.Request, cfg Config) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	info := NodeInfo{
		AppVersion: AppVersion, Role: cfg.Role, NodeID: cfg.NodeID,
		Status: "online", PanelURL: cfg.PanelURL,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
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
