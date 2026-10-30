
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
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

const (
	AppName       = "sahand-tunnel"
	AppVersion    = "0.2.1"
	defaultListen = "127.0.0.1:18080"
	passwordRounds = 310000
	sessionTTL     = 12 * time.Hour
)

type Config struct {
    Role          string    `json:"role"`
    NodeID        string    `json:"node_id"`
    ListenAddr    string    `json:"listen_addr"`
    PanelURL      string    `json:"panel_url,omitempty"`
    PanelPort     int       `json:"panel_port,omitempty"`
    AdminUsername string    `json:"admin_username,omitempty"`
    AdminSalt     string    `json:"admin_salt,omitempty"`
    AdminHash     string    `json:"admin_hash,omitempty"`
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

	loginMu sync.Mutex
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
		if err := runServer(); err != nil {
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

func randomHex(bytesCount int) (string, error) {
	b := make([]byte, bytesCount)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// PBKDF2-HMAC-SHA256 implementation.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	const hashLen = 32
	blocks := (keyLen + hashLen - 1) / hashLen
	result := make([]byte, 0, blocks*hashLen)

	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{
			byte(block >> 24),
			byte(block >> 16),
			byte(block >> 8),
			byte(block),
		})
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
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

	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return "", "", err
	}

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
		return cfg, false, fmt.Errorf("cannot read existing configuration: %w", err)
	}

	return cfg, true, nil
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)

	role := fs.String("role", "", "master or agent")
	listen := fs.String("listen", defaultListen, "local application listen address")
	panelURL := fs.String("panel-url", "", "public HTTPS panel URL")
	adminUser := fs.String("admin-user", "", "administrator username")
	passwordStdin := fs.Bool("admin-password-stdin", false, "read administrator password from stdin")

	if err := fs.Parse(args); err != nil {
		return err
	}

	path := configPath()
	cfg, exists, err := loadExistingConfig(path)
	if err != nil {
		return err
	}

	// Preserve the identity of an existing installation.
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
	if cfg.Role == "" {
		return errors.New("role is required: use --role master or --role agent")
	}

	if *listen != "" {
		cfg.ListenAddr = *listen
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultListen
	}

	if *panelURL != "" {
		cfg.PanelURL = strings.TrimRight(*panelURL, "/")
	}
	if !strings.HasPrefix(cfg.PanelURL, "https://") {
		return errors.New("a public HTTPS panel URL is required")
	}

	if *adminUser != "" {
		cfg.AdminUsername = *adminUser
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

	fmt.Println("Installation configured successfully.")
	fmt.Printf("Role: %s\n", cfg.Role)
	fmt.Printf("Node ID: %s\n", cfg.NodeID)
	fmt.Printf("Panel URL: %s\n", cfg.PanelURL)
	fmt.Printf("Config: %s\n", path)

	return nil
}

func runServer() error {
	cfg, _, err := loadExistingConfig(configPath())
	if err != nil {
		return err
	}

	if cfg.Role != "master" && cfg.Role != "agent" {
		return errors.New("invalid role in configuration")
	}
	if cfg.NodeID == "" {
		return errors.New("node ID is missing from configuration")
	}
	if cfg.AdminUsername == "" || cfg.AdminSalt == "" || cfg.AdminHash == "" {
		return errors.New("administrator credentials are missing; run the installer to configure the panel")
	}
	if !strings.HasPrefix(cfg.PanelURL, "https://") {
		return errors.New("valid HTTPS panel URL is missing; run the installer again")
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", handleHealth)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logout", requireAuth(handleLogout))
	mux.HandleFunc("/api/v1/node", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleNode(w, r, cfg)
	}))
	mux.HandleFunc("/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleDashboard(w, r, cfg)
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
	log.Printf("Public panel: %s", cfg.PanelURL)

	return server.ListenAndServe()
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
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
	if err == nil {
		return host
	}
	return r.RemoteAddr
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

	sessions[token] = Session{
		ExpiresAt: now.Add(sessionTTL),
	}
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

	http.SetCookie(w, &http.Cookie{
		Name:     "sahand_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(sessionTTL),
		MaxAge:   int(sessionTTL.Seconds()),
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
		Name:     "sahand_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleNode(w http.ResponseWriter, r *http.Request, cfg Config) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	info := NodeInfo{
		AppVersion: AppVersion,
		Role:       cfg.Role,
		NodeID:     cfg.NodeID,
		Status:     "online",
		PanelURL:   cfg.PanelURL,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func handleDashboard(w http.ResponseWriter, r *http.Request, cfg Config) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	page := strings.ReplaceAll(dashboardHTML, "{{PANEL_URL}}", html.EscapeString(cfg.PanelURL))
	page = strings.ReplaceAll(page, "{{ROLE}}", html.EscapeString(strings.ToUpper(cfg.Role)))
	page = strings.ReplaceAll(page, "{{NODE_ID}}", html.EscapeString(cfg.NodeID))
	page = strings.ReplaceAll(page, "{{VERSION}}", html.EscapeString(AppVersion))

	_, _ = io.WriteString(w, page)
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
<div class="small">Secure server management</div>
</div>
</body>
</html>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sahand Tunnel</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1020;color:#eef2ff;font-family:Arial,sans-serif}
header{padding:22px 5%;background:#111a2e;border-bottom:1px solid #293653;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.brand{font-size:21px;font-weight:bold}
.address{color:#8fa4c8;font-size:13px;margin-top:7px}
.address a{color:#72a4ff;text-decoration:none}
button{background:#263653;color:#eaf0ff;border:1px solid #3b4d6c;border-radius:8px;padding:10px 15px;cursor:pointer}
main{max-width:1100px;margin:35px auto;padding:0 22px}
h1{font-size:27px;margin-bottom:8px}
.subtitle{color:#91a1bd;margin-bottom:28px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:17px}
.card{background:#151f35;border:1px solid #293956;border-radius:14px;padding:22px}
.label{color:#91a1bd;font-size:13px;margin-bottom:12px}
.value{font-size:20px;font-weight:bold;overflow-wrap:anywhere}
.online{color:#55d69a}
.footer{color:#657795;text-align:center;margin:40px 0;font-size:12px}
</style>
</head>
<body>
<header>
<div>
<div class="brand">SAHAND TUNNEL</div>
<div class="address">Panel address: <a href="{{PANEL_URL}}">{{PANEL_URL}}</a></div>
</div>
<form method="post" action="/logout">
<button type="submit">Sign out</button>
</form>
</header>
<main>
<h1>Dashboard</h1>
<div class="subtitle">Server overview and installation information</div>
<div class="grid">
<div class="card"><div class="label">Server status</div><div class="value online">● Online</div></div>
<div class="card"><div class="label">Server role</div><div class="value">{{ROLE}}</div></div>
<div class="card"><div class="label">Application version</div><div class="value">{{VERSION}}</div></div>
<div class="card"><div class="label">Node ID</div><div class="value">{{NODE_ID}}</div></div>
</div>
<div class="footer">Sahand Tunnel · Secure server management</div>
</main>
</body>
</html>`

func runMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println()
		fmt.Println("================================")
		fmt.Println("       SAHAND TUNNEL")
		fmt.Println("================================")
		fmt.Println("1. Configure Installation")
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
			fmt.Println("Use the installer to configure or upgrade this installation.")
		case "2":
			runSystemctl("enable", "--now", "sahand-tunnel")
		case "3":
			runSystemctl("restart", "sahand-tunnel")
		case "4":
			runSystemctl("stop", "sahand-tunnel")
		case "5":
			runSystemctl("status", "sahand-tunnel", "--no-pager")
		case "6":
			runSystemctl("status", "sahand-tunnel", "--no-pager", "-l")
			fmt.Println("\nRecent logs:")
			runSystemctl("show", "-p", "ExecMainStatus", "sahand-tunnel")
			cmd := exec.Command("journalctl", "-u", "sahand-tunnel", "-n", "40", "--no-pager")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()
		case "7":
			cmd := exec.Command("sahand-tunnel-update")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
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
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("Command failed:", err)
	}
}
