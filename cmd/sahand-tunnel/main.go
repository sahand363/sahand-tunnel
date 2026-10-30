
package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const AppName = "sahand-tunnel"

var AppVersion = "0.2.0"

const (
	sessionCookie = "sahand_session"
	sessionTTL    = 12 * time.Hour
	passwordRounds = 200000
)

type Config struct {
	Role           string    `json:"role"`
	NodeID         string    `json:"node_id"`
	ListenAddr     string    `json:"listen_addr"`
	PanelURL       string    `json:"panel_url,omitempty"`
	AdminUsername  string    `json:"admin_username,omitempty"`
	AdminSalt      string    `json:"admin_salt,omitempty"`
	AdminHash      string    `json:"admin_hash,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type NodeInfo struct {
	AppVersion string `json:"app_version"`
	Role       string `json:"role"`
	NodeID     string `json:"node_id"`
	Status     string `json:"status"`
}

type Session struct {
	ExpiresAt time.Time
}

var sessions = struct {
	sync.Mutex
	items map[string]Session
}{items: make(map[string]Session)}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "menu":
		runMenu()
	case "init":
		runInit(os.Args[2:])
	case "serve":
		runServer()
	case "version":
		fmt.Println(AppName, AppVersion)
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println(AppName, AppVersion)
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  init --role master|agent")
	fmt.Println("  serve")
	fmt.Println("  menu")
	fmt.Println("  version")
}

func configPath() string {
	path := os.Getenv("SAHAND_CONFIG")
	if path == "" {
		path = "./data/config.json"
	}
	return path
}

func randomHex(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func generateNodeID() (string, error) {
	return randomHex(16)
}

// Password hashing using an iterated HMAC-SHA256 construction.
func passwordHash(password, salt string) string {
	key := []byte(password)
	saltBytes := []byte(salt)

	mac := hmac.New(sha256.New, key)
	mac.Write(saltBytes)
	result := mac.Sum(nil)

	for i := 1; i < passwordRounds; i++ {
		mac = hmac.New(sha256.New, key)
		mac.Write(result)
		result = mac.Sum(nil)
	}

	return hex.EncodeToString(result)
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)

	role := fs.String("role", "", "master or agent")
	addr := fs.String("listen", "127.0.0.1:18080", "Internal listen address")
	panelURL := fs.String("panel-url", "", "Public panel URL")
	adminUser := fs.String("admin-user", "", "Administrator username")
	adminPassword := fs.String("admin-password", "", "Administrator password")

	_ = fs.Parse(args)

	*role = strings.ToLower(strings.TrimSpace(*role))
	*adminUser = strings.TrimSpace(*adminUser)

	if *role != "master" && *role != "agent" {
		log.Fatal("Invalid role. Use master or agent.")
	}

	if *adminUser == "" || len(*adminPassword) < 12 {
		log.Fatal("Administrator username and a password of at least 12 characters are required.")
	}

	if strings.TrimSpace(*panelURL) == "" {
		log.Fatal("Panel URL is required.")
	}

	path := configPath()

	if _, err := os.Stat(path); err == nil {
		log.Fatal("Configuration already exists. Refusing to overwrite.")
	}

	nodeID, err := generateNodeID()
	if err != nil {
		log.Fatal(err)
	}

	salt, err := randomHex(16)
	if err != nil {
		log.Fatal(err)
	}

	cfg := Config{
		Role:          *role,
		NodeID:        nodeID,
		ListenAddr:    *addr,
		PanelURL:      strings.TrimRight(*panelURL, "/"),
		AdminUsername: *adminUser,
		AdminSalt:     salt,
		AdminHash:     passwordHash(*adminPassword, salt),
		CreatedAt:     time.Now().UTC(),
	}

	if err := saveConfig(path, cfg); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Installation initialized successfully.")
	fmt.Println("Role:", cfg.Role)
	fmt.Println("Node ID:", cfg.NodeID)
	fmt.Println("Panel:", cfg.PanelURL)
	fmt.Println("Config:", path)
}

func saveConfig(path string, cfg Config) error {
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
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

func loadConfig(path string) (Config, error) {
	var cfg Config

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	if cfg.Role != "master" && cfg.Role != "agent" {
		return cfg, fmt.Errorf("invalid configured role")
	}

	if cfg.NodeID == "" || cfg.ListenAddr == "" {
		return cfg, fmt.Errorf("incomplete configuration")
	}

	if cfg.AdminUsername == "" || cfg.AdminSalt == "" || cfg.AdminHash == "" {
		return cfg, fmt.Errorf("administrator credentials are missing; run the secure configuration migration")
	}

	if cfg.PanelURL == "" {
		return cfg, fmt.Errorf("panel URL is missing")
	}

	return cfg, nil
}

func runServer() {
	cfg, err := loadConfig(configPath())
	if err != nil {
		log.Fatal("Cannot load configuration: ", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/login", handleLogin(cfg))
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/api/v1/health", handleHealth)
	mux.Handle("/api/v1/node", requireAuth(cfg, http.HandlerFunc(handleNode(cfg))))
	mux.Handle("/", requireAuth(cfg, handleDashboard(cfg)))

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cancel()

		_ = server.Shutdown(shutdownCtx)
	}()

	log.Println(AppName, AppVersion)
	log.Println("Role:", cfg.Role)
	log.Println("Node ID:", cfg.NodeID)
	log.Println("Internal listener:", cfg.ListenAddr)
	log.Println("Panel URL:", cfg.PanelURL)

	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleNode(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		writeJSON(w, http.StatusOK, NodeInfo{
			AppVersion: AppVersion,
			Role:       cfg.Role,
			NodeID:     cfg.NodeID,
			Status:     "online",
		})
	}
}

func requireAuth(cfg Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(sessionCookie)
		if err != nil || !validSession(cookie.Value) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func validSession(token string) bool {
	sessions.Lock()
	defer sessions.Unlock()

	session, ok := sessions.items[token]
	if !ok {
		return false
	}

	if time.Now().After(session.ExpiresAt) {
		delete(sessions.items, token)
		return false
	}

	return true
}

func createSession() (string, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}

	sessions.Lock()
	sessions.items[token] = Session{
		ExpiresAt: time.Now().Add(sessionTTL),
	}
	sessions.Unlock()

	return token, nil
}

func handleLogin(cfg Config) http.HandlerFunc {
	tmpl := template.Must(template.New("login").Parse(loginHTML))

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if cookie, err := r.Cookie(sessionCookie); err == nil && validSession(cookie.Value) {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = tmpl.Execute(w, nil)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		userOK := subtle.ConstantTimeCompare(
			[]byte(username),
			[]byte(cfg.AdminUsername),
		) == 1

		calculated := passwordHash(password, cfg.AdminSalt)
		passwordOK := subtle.ConstantTimeCompare(
			[]byte(calculated),
			[]byte(cfg.AdminHash),
		) == 1

		if !userOK || !passwordOK {
			time.Sleep(700 * time.Millisecond)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = tmpl.Execute(w, "Invalid username or password.")
			return
		}

		token, err := createSession()
		if err != nil {
			http.Error(w, "Could not create session", http.StatusInternalServerError)
			return
		}

		secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")

		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(sessionTTL.Seconds()),
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cookie, err := r.Cookie(sessionCookie); err == nil {
		sessions.Lock()
		delete(sessions.items, cookie.Value)
		sessions.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleDashboard(cfg Config) http.Handler {
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		data := map[string]string{
			"Role":    strings.ToUpper(cfg.Role),
			"NodeID":  cfg.NodeID,
			"Version": AppVersion,
			"PanelURL": cfg.PanelURL,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if err := tmpl.Execute(w, data); err != nil {
			log.Println("Dashboard error:", err)
		}
	})
}

func runMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println()
		fmt.Println("================================")
		fmt.Println("       SAHAND TUNNEL")
		fmt.Println("================================")

		cfg, err := loadConfig(configPath())
		if err != nil {
			fmt.Println("Installation: NOT CONFIGURED")
		} else {
			fmt.Println("Role:", strings.ToUpper(cfg.Role))
			fmt.Println("Node ID:", cfg.NodeID)
			fmt.Println("Panel:", cfg.PanelURL)
		}

		fmt.Println("Version:", AppVersion)
		fmt.Println("--------------------------------")
		fmt.Println("1. Configure Installation")
		fmt.Println("2. Start Service")
		fmt.Println("3. Restart Service")
		fmt.Println("4. Stop Service")
		fmt.Println("5. Service Status")
		fmt.Println("6. View Logs")
		fmt.Println("7. Update")
		fmt.Println("0. Exit")
		fmt.Println("--------------------------------")
		fmt.Print("Select option: ")

		choice, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println("\nInput closed. Exiting menu.")
			} else {
				fmt.Println("\nInput error:", err)
			}
			return
		}

		switch strings.TrimSpace(choice) {
		case "1":
			fmt.Println("Use the installer to configure a secure installation.")
		case "2":
			runSystemctl("enable", "--now", "sahand-tunnel")
		case "3":
			runSystemctl("restart", "sahand-tunnel")
		case "4":
			runSystemctl("stop", "sahand-tunnel")
		case "5":
			runSystemctl("status", "sahand-tunnel")
		case "6":
			cmd := exec.Command("journalctl", "-u", "sahand-tunnel", "-n", "50", "--no-pager")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()
		case "7":
			cmd := exec.Command("/usr/local/bin/sahand-tunnel-update")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Println("Update failed:", err)
			}
		case "0":
			fmt.Println("Goodbye.")
			return
		default:
			fmt.Println("Invalid option.")
		}

		fmt.Println()
		fmt.Print("Press Enter to continue...")
		_, err = reader.ReadString('\n')
		if err != nil {
			return
		}
	}
}

func runSystemctl(args ...string) {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println("Service command failed:", err)
	}
}

const loginHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sahand Tunnel Login</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#e5e7eb;font-family:Arial,sans-serif}
.box{width:min(92%,400px);padding:32px;background:#151c2e;border:1px solid #273449;border-radius:16px}
h1{font-size:23px;margin-top:0}
p{color:#94a3b8;font-size:14px}
input{width:100%;padding:13px;margin:8px 0 16px;background:#0b1020;border:1px solid #334155;border-radius:8px;color:white}
button{width:100%;padding:13px;border:0;border-radius:8px;background:#2563eb;color:white;font-weight:bold;cursor:pointer}
.error{color:#f87171}
</style>
</head>
<body>
<div class="box">
<h1>SAHAND TUNNEL</h1>
<p>Administrator sign in</p>
{{if .}}<p class="error">{{.}}</p>{{end}}
<form method="POST" action="/login">
<label>Username</label>
<input name="username" autocomplete="username" required>
<label>Password</label>
<input name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
</div>
</body>
</html>
`

const dashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sahand Tunnel</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1020;color:#e5e7eb;font-family:Arial,sans-serif}
.container{max-width:1100px;margin:auto;padding:24px}
.header{display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap;margin-bottom:20px}
.logo{font-size:23px;font-weight:bold}
.role{background:#172554;color:#93c5fd;padding:8px 14px;border-radius:8px;font-size:12px}
.address{background:#151c2e;border:1px solid #273449;border-radius:12px;padding:16px;margin-bottom:24px;overflow-wrap:anywhere}
.address a{color:#60a5fa;text-decoration:none}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.card{background:#151c2e;border:1px solid #273449;border-radius:14px;padding:22px;min-height:135px}
.card h3{margin-top:0;font-size:14px;color:#94a3b8}
.value{font-size:20px;font-weight:bold}
.status{color:#4ade80}
.info{margin-top:22px;background:#151c2e;border-radius:14px;padding:22px;overflow-wrap:anywhere}
.muted{color:#94a3b8;font-size:13px}
button{padding:10px 16px;background:#273449;color:white;border:0;border-radius:8px;cursor:pointer}
@media(max-width:700px){.grid{grid-template-columns:1fr}.container{padding:16px}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<div class="logo">SAHAND TUNNEL</div>
<div class="role">{{.Role}} PANEL</div>
</div>

<div class="address">
<div class="muted">PANEL ADDRESS</div>
<a href="{{.PanelURL}}">{{.PanelURL}}</a>
</div>

<div class="grid">
<div class="card">
<h3>Server Status</h3>
<div class="value status">ONLINE</div>
</div>
<div class="card">
<h3>Installation Role</h3>
<div class="value">{{.Role}}</div>
</div>
<div class="card">
<h3>Application Version</h3>
<div class="value">{{.Version}}</div>
</div>
</div>

<div class="info">
<h3>Node Information</h3>
<p class="muted">Unique Node ID</p>
<div>{{.NodeID}}</div>
<p class="muted">Sahand Tunnel is running successfully.</p>
<form method="POST" action="/logout">
<button type="submit">Sign out</button>
</form>
</div>
</div>
</body>
</html>
`
