

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"bufio"
    "os/exec"
	"io"
)

const AppName = "sahand-tunnel"

var AppVersion = "0.1.0"

type Config struct {
	Role       string    `json:"role"`
	NodeID     string    `json:"node_id"`
	ListenAddr string    `json:"listen_addr"`
	CreatedAt  time.Time `json:"created_at"`
}

type NodeInfo struct {
	AppVersion string `json:"app_version"`
	Role       string `json:"role"`
	NodeID     string `json:"node_id"`
	Status     string `json:"status"`
}

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
	fmt.Println("  init --role master")
	fmt.Println("  init --role agent")
	fmt.Println("  serve")
	fmt.Println("  version")
}

func configPath() string {
	path := os.Getenv("SAHAND_CONFIG")

	if path == "" {
		path = "./data/config.json"
	}

	return path
}

func generateNodeID() (string, error) {
	data := make([]byte, 16)

	if _, err := rand.Read(data); err != nil {
		return "", err
	}

	return hex.EncodeToString(data), nil
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)

	role := fs.String("role", "", "Installation role: master or agent")
	addr := fs.String("listen", "127.0.0.1:8080", "Panel listen address")

	_ = fs.Parse(args)

	*role = strings.ToLower(strings.TrimSpace(*role))

	if *role != "master" && *role != "agent" {
		log.Fatal("Invalid role. Use master or agent.")
	}

	path := configPath()

	if _, err := os.Stat(path); err == nil {
		log.Fatal("Configuration already exists. Refusing to overwrite.")
	}

	nodeID, err := generateNodeID()
	if err != nil {
		log.Fatal(err)
	}

	cfg := Config{
		Role:       *role,
		NodeID:     nodeID,
		ListenAddr: *addr,
		CreatedAt:  time.Now().UTC(),
	}

	if err := saveConfig(path, cfg); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Installation initialized successfully.")
	fmt.Println("Role:", cfg.Role)
	fmt.Println("Node ID:", cfg.NodeID)
	fmt.Println("Config:", path)
	fmt.Println()
	fmt.Println("Run the application with:")
	fmt.Println("  sahand-tunnel serve")
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

	return cfg, nil
}

func runServer() {
	cfg, err := loadConfig(configPath())
	if err != nil {
		log.Fatal("Cannot load configuration:", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", handleDashboard(cfg))
	mux.HandleFunc("/api/v1/health", handleHealth)
	mux.HandleFunc("/api/v1/node", handleNode(cfg))

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
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
	log.Println("Listening on:", cfg.ListenAddr)

	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
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

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func handleNode(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		info := NodeInfo{
			AppVersion: AppVersion,
			Role:       cfg.Role,
			NodeID:     cfg.NodeID,
			Status:     "online",
		}

		writeJSON(w, http.StatusOK, info)
	}
}

func handleDashboard(cfg Config) http.HandlerFunc {
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))

	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		data := map[string]string{
			"Role":    strings.ToUpper(cfg.Role),
			"NodeID":  cfg.NodeID,
			"Version": AppVersion,
		}

		if err := tmpl.Execute(w, data); err != nil {
			log.Println("Dashboard error:", err)
		}
	}
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

choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			if _, err := os.Stat(configPath()); err == nil {
				fmt.Println("Configuration already exists.")
				fmt.Println("Role changes are not supported from this menu.")
				break
			}

			fmt.Println()
			fmt.Println("Select installation role:")
			fmt.Println("1. Master")
			fmt.Println("2. Agent")
			fmt.Print("Role: ")

			role, err := reader.ReadString('\n')
if err != nil {
    fmt.Println("Could not read installation role:", err)
    return
}
role = strings.TrimSpace(role)

			switch role {
			case "1":
				runInit([]string{"--role", "master"})
			case "2":
				runInit([]string{"--role", "agent"})
			default:
				fmt.Println("Invalid role.")
			}

		case "2":
			runSystemctl("enable", "--now", "sahand-tunnel")

		case "3":
			runSystemctl("restart", "sahand-tunnel")

		case "4":
			runSystemctl("stop", "sahand-tunnel")

		case "5":
			runSystemctl("status", "sahand-tunnel")

		case "6":
			cmd := exec.Command(
				"journalctl",
				"-u", "sahand-tunnel",
				"-n", "50",
				"--no-pager",
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()

		case "7":
			cmd := exec.Command(
				"/usr/local/bin/sahand-tunnel-update",
			)
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
		_, _ = reader.ReadString('\n')
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


const dashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sahand Tunnel</title>

<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #0b1020;
    color: #e5e7eb;
    font-family: Arial, sans-serif;
}

.container {
    max-width: 1100px;
    margin: auto;
    padding: 24px;
}

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 35px;
}

.logo {
    font-size: 22px;
    font-weight: bold;
}

.role {
    background: #172554;
    color: #93c5fd;
    padding: 8px 14px;
    border-radius: 8px;
    font-size: 12px;
}

.grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
}

.card {
    background: #151c2e;
    border: 1px solid #273449;
    border-radius: 14px;
    padding: 22px;
    min-height: 140px;
}

.card h3 {
    margin-top: 0;
    font-size: 15px;
    color: #94a3b8;
}

.value {
    font-size: 20px;
    font-weight: bold;
}

.status {
    color: #4ade80;
}

.info {
    margin-top: 30px;
    background: #151c2e;
    border-radius: 14px;
    padding: 22px;
    overflow-wrap: anywhere;
}

.muted {
    color: #94a3b8;
    font-size: 13px;
}

@media(max-width: 700px) {
    .grid {
        grid-template-columns: 1fr;
    }

    .container {
        padding: 16px;
    }
}
</style>
</head>

<body>
<div class="container">

    <div class="header">
        <div class="logo">SAHAND TUNNEL</div>
        <div class="role">{{.Role}} PANEL</div>
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
        <br>
        <p class="muted">
            Sahand Tunnel is running successfully.
            Dashboard modules will be added in upcoming versions.
        </p>
    </div>

</div>
</body>
</html>
`
