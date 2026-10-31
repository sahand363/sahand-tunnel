package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	sessionsMu sync.Mutex
	sessions   = make(map[string]Session)

	loginMu       sync.Mutex
	loginAttempts = make(map[string][]time.Time)

	analyticsMu   sync.Mutex
	analyticsData AnalyticsStore
)

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
		Action   string `json:"action"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Action == "next_method" {
		stateMu.RLock()
		role := appCfg.Role
		stateMu.RUnlock()
		if role != "master" {
			http.Error(w, "only master can switch methods", http.StatusForbidden)
			return
		}
		switched, msg, err := switchNextMethod(req.ServerID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			OK       bool   `json:"ok"`
			Switched bool   `json:"switched"`
			Message  string `json:"message"`
		}{
			OK:       true,
			Switched: switched,
			Message:  msg,
		})
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
		appCfg.Servers[idx].ActiveMethodID = 0
		appCfg.Servers[idx].ActiveMethod = ""
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
			if srv.ActiveMethodID == updated.ID {
				srv.ActivePort = updated.ListenPort
			}
			break
		}
	}

	srv.ConfigVersion++
	srv.SyncState = "pending_sync"
	if tok, err := generatePeerToken(appCfg, *srv); err == nil {
		srv.Token = tok
	}
	newVer := srv.ConfigVersion
	newToken := srv.Token
	peerCopy := *srv
	_ = saveConfig(configPath(), appCfg)
	stateMu.Unlock()

	syncServerListeners(peerCopy)
	go func() {
		for _, tc := range peerCopy.Tunnels {
			if tc.Implemented {
				if pushParitySyncOverMethod(peerCopy, tc, peerCopy.ActiveLatencyMS) {
					return
				}
			}
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK            bool   `json:"ok"`
		ConfigVersion int    `json:"config_version"`
		Token         string `json:"token"`
	}{
		OK:            true,
		ConfigVersion: newVer,
		Token:         newToken,
	})
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
