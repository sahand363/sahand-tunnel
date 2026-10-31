package main

import (
	"bufio"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// The frontend is built by GitHub Actions before Go compilation.
//
//go:embed web/dist
var webAssets embed.FS

const (
	AppName        = "sahand-tunnel"
	AppVersion     = "0.4.2"
	defaultPort    = 18080
	passwordRounds = 310000
	sessionTTL     = 12 * time.Hour
	wsGUID         = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
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
		fmt.Println("8. Uninstall")
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
		case "8":
			if runUninstall(reader) {
				return
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

func runUninstall(reader *bufio.Reader) bool {
	fmt.Println()
	fmt.Print("Are you sure you want to completely uninstall Sahand Tunnel? [y/N]: ")
	confirm, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Println("Input error:", err)
		return false
	}
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Uninstall cancelled.")
		return false
	}

	fmt.Println("\nStopping and disabling Sahand Tunnel service...")
	_ = exec.Command("systemctl", "stop", "sahand-tunnel").Run()
	_ = exec.Command("systemctl", "disable", "sahand-tunnel").Run()

	pathsToRemove := []string{
		"/etc/systemd/system/sahand-tunnel.service",
		"/usr/local/bin/sahand-tunnel-domain",
		"/usr/local/bin/sahand-tunnel-update",
		"/etc/sahand-tunnel",
		"/var/lib/sahand-tunnel",
		"/usr/local/bin/sahand-tunnel",
	}

	for _, p := range pathsToRemove {
		_ = os.RemoveAll(p)
	}

	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("Sahand Tunnel has been completely uninstalled.")
	return true
}

func runSystemctl(args ...string) {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("Command failed:", err)
	}
}
