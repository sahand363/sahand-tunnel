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
			strings.HasPrefix(iface, "sahand-gre") ||
			strings.HasPrefix(iface, "gre") ||
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
	now := masterNow()
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

	today := masterNow().Format("2006-01-02")
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

func allocateNonCollidingTunnelsForNewPeer(existing []ServerPeer, peerID, remoteIP string) []TunnelConfig {
	usedListenPorts := make(map[int]bool)
	usedForwardPorts := make(map[int]bool)
	for _, srv := range existing {
		for _, t := range srv.Tunnels {
			if t.ListenPort > 0 {
				usedListenPorts[t.ListenPort] = true
			}
			for _, fpStr := range parsePortList(t.ForwardPorts) {
				if p, err := strconv.Atoi(fpStr); err == nil && p > 0 {
					usedForwardPorts[p] = true
				}
			}
		}
	}

	slot := 0
	for slot < 25 {
		e1Base := 28000 + slot*1000
		e2Base := 32000 + slot*1000
		if e2Base+30 > 65000 {
			break
		}
		conflict := false
		for id := 1; id <= 30; id++ {
			if usedListenPorts[e1Base+id] || usedForwardPorts[e2Base+id] {
				conflict = true
				break
			}
		}
		if !conflict {
			break
		}
		slot++
	}

	e1Base := 28000 + slot*1000
	e2Base := 32000 + slot*1000
	tunnels := defaultTunnelsForServer()
	cidr, mIP, aIP := deriveDefaultSlash30ForPeer(peerID)

	for i := range tunnels {
		id := tunnels[i].ID
		tunnels[i].ListenPort = e1Base + id
		tunnels[i].ForwardPorts = strconv.Itoa(e2Base + id)

		if id == 25 && tunnels[i].GREFRP != nil {
			tunnels[i].GREFRP.PrivateSubnetCIDR = cidr
			tunnels[i].GREFRP.LocalPrivateIP = mIP
			tunnels[i].GREFRP.RemotePrivateIP = aIP
			tunnels[i].GREFRP.RemotePublicIP = remoteIP
			if len(peerID) >= 6 {
				tunnels[i].GREFRP.GREInterfaceName = "gre-" + peerID[:6]
			}
			tunnels[i].GREFRP.RouteConfig = fmt.Sprintf("%s via %s", cidr, tunnels[i].GREFRP.GREInterfaceName)
			tunnels[i].GREFRP.FRPServerPort = tunnels[i].ListenPort
			tunnels[i].GREFRP.ForwardingRules = buildGREFRPRulesFromCSV(
				tunnels[i].ForwardPorts,
				tunnels[i].GREFRP.FRPEncryption,
				tunnels[i].GREFRP.FRPCompression,
				tunnels[i].GREFRP.FRPProxyProtoV2,
			)
		}

		if id == 26 && tunnels[i].SpoofWG != nil {
			tunnels[i].SpoofWG.Role = "local"
			tunnels[i].SpoofWG.PeerPublicIP = remoteIP
			if slot > 0 {
				subnetOctet := (20 + slot) % 250
				if subnetOctet <= 0 {
					subnetOctet = 21
				}
				tunnels[i].SpoofWG.WGLocalIP = fmt.Sprintf("10.%d.0.1", subnetOctet)
				tunnels[i].SpoofWG.WGPeerIP = fmt.Sprintf("10.%d.0.2", subnetOctet)
				tunnels[i].SpoofWG.SpoofListenPort = defaultSpoofPort + slot
				tunnels[i].SpoofWG.RecvPort = defaultRecvPort + slot
				tunnels[i].SpoofWG.CorePort = defaultCorePort + slot
				tunnels[i].SpoofWG.WGListen = defaultWGListen + slot
			}
			tunnels[i].SpoofWG = normalizeSpoofWGConfig(tunnels[i].SpoofWG)
		}

		if id == 27 && tunnels[i].SpoofNative != nil {
			tunnels[i].SpoofNative.Role = "local"
			tunnels[i].SpoofNative.PeerPublicIP = remoteIP
			if slot > 0 {
				subnetOctet := (27 + slot) % 250
				if subnetOctet <= 0 || subnetOctet == 20 {
					subnetOctet = 28
				}
				tunnels[i].SpoofNative.WGLocalIP = fmt.Sprintf("10.%d.0.1", subnetOctet)
				tunnels[i].SpoofNative.WGPeerIP = fmt.Sprintf("10.%d.0.2", subnetOctet)
				tunnels[i].SpoofNative.SpoofListenPort = defaultM27SpoofPort + slot
				tunnels[i].SpoofNative.RecvPort = defaultM27RecvPort + slot
				tunnels[i].SpoofNative.CorePort = defaultM27CorePort + slot
				tunnels[i].SpoofNative.AdapterPort = defaultM27AdaptPort + slot
			}
			tunnels[i].SpoofNative = normalizeSpoofNativeConfig(tunnels[i].SpoofNative)
		}
	}

	return tunnels
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
	mux.HandleFunc("/api/v1/tunnels/ports", requireAuth(handleBatchPortsUpdate))
	mux.HandleFunc("/api/v1/tunnels/ping", requireAuth(handleTunnelPing))
	mux.HandleFunc("/api/v1/tunnels/gre-frp", requireAuth(handleGREFRPAction))
	mux.HandleFunc("/api/v1/tunnels/spoof-wg", requireAuth(handleSpoofWGAction))
	mux.HandleFunc("/api/v1/tunnels/spoof-native", requireAuth(handleSpoofNativeAction))
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
	fp, _ := ComputeSigningKeyFingerprint(appCfg.MasterSigningPublicKey)
	info := NodeInfo{
		AppVersion:                  AppVersion,
		Role:                        appCfg.Role,
		NodeID:                      appCfg.NodeID,
		Status:                      "online",
		PanelURL:                    appCfg.PanelURL,
		MasterSigningPublicKey:      appCfg.MasterSigningPublicKey,
		MasterNoiseStaticPublicKey:  appCfg.MasterNoiseStaticPublicKey,
		MasterSigningKeyFingerprint: fp,
		AgentSigningPublicKey:       appCfg.AgentSigningPublicKey,
		AgentNoiseStaticPublicKey:   appCfg.AgentNoiseStaticPublicKey,
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
	mTime := formatMasterClock(masterNow())
	testerView := getSpoofTesterStatusView()
	m27TesterView := getSpoofM27TesterStatusView()

	stateMu.RLock()
	serversCopy := make([]ServerPeer, len(appCfg.Servers))
	for i, srv := range appCfg.Servers {
		srvCopy := srv
		tunnelsCopy := make([]TunnelConfig, len(srv.Tunnels))
		copy(tunnelsCopy, srv.Tunnels)
		for j := range tunnelsCopy {
			if tunnelsCopy[j].ID == 25 {
				gf := normalizeGREFRPConfig(tunnelsCopy[j].GREFRP, tunnelsCopy[j].ListenPort, tunnelsCopy[j].ForwardPorts)
				if diag, ok := GetGREFRPDiagnostics(srv.ID); ok {
					gf.Diagnostics = diag
				}
				tunnelsCopy[j].GREFRP = gf
			}
			if tunnelsCopy[j].ID == 26 {
				swg := normalizeSpoofWGConfig(tunnelsCopy[j].SpoofWG)
				if swg.PeerPublicIP == "" && isValidIPv4String(srv.IP) {
					swg.PeerPublicIP = srv.IP
				}
				swg.Health = querySpoofWGRuntimeHealth(swg)
				swg.Tester = testerView
				tunnelsCopy[j].SpoofWG = swg
			}
			if tunnelsCopy[j].ID == 27 {
				sn := normalizeSpoofNativeConfig(tunnelsCopy[j].SpoofNative)
				if sn.PeerPublicIP == "" && isValidIPv4String(srv.IP) {
					sn.PeerPublicIP = srv.IP
				}
				sn.Health = querySpoofNativeRuntimeHealth(srv.ID, sn)
				sn.Tester = m27TesterView
				tunnelsCopy[j].SpoofNative = sn
			}
		}
		srvCopy.Tunnels = tunnelsCopy
		serversCopy[i] = srvCopy
	}
	role := appCfg.Role
	nodeID := appCfg.NodeID
	mSignPub := appCfg.MasterSigningPublicKey
	mNoisePub := appCfg.MasterNoiseStaticPublicKey
	aSignPub := appCfg.AgentSigningPublicKey
	aNoisePub := appCfg.AgentNoiseStaticPublicKey
	trustedMasterSignPub := appCfg.TrustedMasterSigningPublicKey
	stateMu.RUnlock()

	mFP, _ := ComputeSigningKeyFingerprint(mSignPub)
	if mFP == "" && trustedMasterSignPub != "" {
		mFP, _ = ComputeSigningKeyFingerprint(trustedMasterSignPub)
	}

	payload := struct {
		AppVersion                  string                `json:"app_version"`
		Role                        string                `json:"role"`
		NodeID                      string                `json:"node_id"`
		ServerTime                  string                `json:"server_time"`
		MasterSigningPublicKey      string                `json:"master_signing_public_key,omitempty"`
		MasterNoiseStaticPublicKey  string                `json:"master_noise_static_public_key,omitempty"`
		MasterSigningKeyFingerprint string                `json:"master_signing_key_fingerprint,omitempty"`
		AgentSigningPublicKey       string                `json:"agent_signing_public_key,omitempty"`
		AgentNoiseStaticPublicKey   string                `json:"agent_noise_static_public_key,omitempty"`
		Servers                     []ServerPeer          `json:"servers"`
		Catalogue                   []MethodCatalogueItem `json:"catalogue"`
	}{
		AppVersion:                  AppVersion,
		Role:                        role,
		NodeID:                      nodeID,
		ServerTime:                  mTime,
		MasterSigningPublicKey:      mSignPub,
		MasterNoiseStaticPublicKey:  mNoisePub,
		MasterSigningKeyFingerprint: mFP,
		AgentSigningPublicKey:       aSignPub,
		AgentNoiseStaticPublicKey:   aNoisePub,
		Servers:                     serversCopy,
		Catalogue:                   methodCatalogue,
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
		Name                 string `json:"name"`
		IP                   string `json:"ip"`
		Token                string `json:"token"`
		MasterKeyFingerprint string `json:"master_key_fingerprint"`
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
		peerSecret, err := randomHex(32)
		if err != nil {
			stateMu.Unlock()
			http.Error(w, "could not generate peer secret", http.StatusInternalServerError)
			return
		}
		tunnels := allocateNonCollidingTunnelsForNewPeer(appCfg.Servers, peerID, ip)

		peer := ServerPeer{
			ID:                         peerID,
			Name:                       name,
			IP:                         ip,
			PeerSecret:                 peerSecret,
			MasterSigningPublicKey:     appCfg.MasterSigningPublicKey,
			MasterNoiseStaticPublicKey: appCfg.MasterNoiseStaticPublicKey,
			ConfigVersion:              1,
			SyncState:                  "synced",
			Status:                     "WAITING",
			Running:                    false,
			RecentLifelines:            []LifelineEvent{},
			Tunnels:                    tunnels,
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

	var prevPeerID string
	if len(appCfg.Servers) > 0 {
		prevPeerID = appCfg.Servers[0].ID
	}

	fpToVerify := strings.TrimSpace(req.MasterKeyFingerprint)
	if fpToVerify == "" {
		if appCfg.TrustedMasterSigningPublicKey != "" {
			fpToVerify, _ = ComputeSigningKeyFingerprint(appCfg.TrustedMasterSigningPublicKey)
		} else if tp, pErr := parseAndValidateToken(rawToken); pErr == nil {
			fpToVerify, _ = ComputeSigningKeyFingerprint(tp.MasterSigningPublicKey)
		}
	}

	peer, err := VerifyAndEstablishInitialTrust(&appCfg, ip, rawToken, fpToVerify)
	if err != nil {
		stateMu.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stateMu.Unlock()

	if prevPeerID != "" && prevPeerID != peer.ID {
		stopDiscoveryLoop(prevPeerID)
		stopAllServerListeners(prevPeerID)
	}
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
		newSecret, sErr := randomHex(32)
		if sErr != nil {
			stateMu.Unlock()
			http.Error(w, "failed to generate peer secret", http.StatusInternalServerError)
			return
		}
		appCfg.Servers[idx].PeerSecret = newSecret
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

func handleTunnelPing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ServerID string `json:"server_id"`
		MethodID int    `json:"method_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	stateMu.RLock()
	var peerSnapshot *ServerPeer
	var tcSnapshot *TunnelConfig
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == req.ServerID {
			cp := appCfg.Servers[i]
			peerSnapshot = &cp
			for j := range cp.Tunnels {
				if cp.Tunnels[j].ID == req.MethodID {
					tc := cp.Tunnels[j]
					tcSnapshot = &tc
					break
				}
			}
			break
		}
	}
	stateMu.RUnlock()

	if peerSnapshot == nil || tcSnapshot == nil {
		http.Error(w, "server or tunnel method not found", http.StatusNotFound)
		return
	}

	res := probeSingleMethod(*peerSnapshot, *tcSnapshot)

	stateMu.Lock()
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == req.ServerID {
			for j := range appCfg.Servers[i].Tunnels {
				if appCfg.Servers[i].Tunnels[j].ID == req.MethodID {
					appCfg.Servers[i].Tunnels[j].LastDiscovery = res
					break
				}
			}
			if res.Success && appCfg.Servers[i].ActiveMethodID == req.MethodID {
				appCfg.Servers[i].ActiveLatencyMS = res.LatencyMS
			}
			_ = saveConfig(configPath(), appCfg)
			break
		}
	}
	stateMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK     bool         `json:"ok"`
		Result MethodResult `json:"result"`
	}{
		OK:     true,
		Result: res,
	})
}

func handleGREFRPAction(w http.ResponseWriter, r *http.Request) {
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

	msg, err := ExecuteGREFRPServiceAction(req.ServerID, req.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	diag, _ := GetGREFRPDiagnostics(req.ServerID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK          bool              `json:"ok"`
		Message     string            `json:"message"`
		Diagnostics GREFRPDiagnostics `json:"diagnostics"`
	}{
		OK:          true,
		Message:     msg,
		Diagnostics: diag,
	})
}

func handleSpoofWGAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ServerID  string              `json:"server_id"`
		Action    string              `json:"action"` // "bundle" | "import" | "up" | "down" | "restart" | "install_binary" | "tester_start" | "tester_stop" | "tester_clear"
		Bundle    string              `json:"bundle,omitempty"`
		SpoofWG   *SpoofWGConfig      `json:"spoof_wg,omitempty"`
		TesterReq *SpoofTesterRequest `json:"tester_req,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))

	var installedMsg string
	if action == "install_binary" {
		m, err := installOfficialSpoofBinary()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		installedMsg = m
	}

	stateMu.Lock()
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
	tIdx := -1
	for i := range srv.Tunnels {
		if srv.Tunnels[i].ID == 26 {
			tIdx = i
			break
		}
	}
	if tIdx < 0 {
		stateMu.Unlock()
		http.Error(w, "Method 26 (Spoof + WireGuard) not found", http.StatusNotFound)
		return
	}

	cur := normalizeSpoofWGConfig(srv.Tunnels[tIdx].SpoofWG)
	if req.SpoofWG != nil {
		edited := *req.SpoofWG
		if edited.WGPrivKey == "" {
			edited.WGPrivKey = cur.WGPrivKey
		}
		if edited.WGPubKey == "" {
			edited.WGPubKey = cur.WGPubKey
		}
		if edited.WGPeerPriv == "" {
			edited.WGPeerPriv = cur.WGPeerPriv
		}
		if edited.WGPeerPub == "" {
			edited.WGPeerPub = cur.WGPeerPub
		}
		cur = normalizeSpoofWGConfig(&edited)
	}
	if cur.PeerPublicIP == "" && isValidIPv4String(srv.IP) {
		cur.PeerPublicIP = srv.IP
	}

	var msg string
	var bundleOut string

	switch action {
	case "install_binary":
		msg = installedMsg

	case "bundle":
		bStr, err := makeSpoofWGBundle(cur, "")
		if err != nil {
			stateMu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		bundleOut = bStr
		msg = "Generated spf1_ bundle for foreign server"

	case "import":
		imported, err := importSpoofWGBundle(req.Bundle, cur)
		if err != nil {
			stateMu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cur = imported
		bundleOut = cur.LastBundle
		msg = fmt.Sprintf("Imported bundle (%s/%s, %s ↔ %s)",
			cur.SendTransport, cur.RecvTransport, cur.WGLocalIP, cur.WGPeerIP)

	case "up", "apply":
		outMsg, err := applyLinuxSpoofAndWGServices(cur)
		if err != nil {
			cur.LastError = err.Error()
			srv.Tunnels[tIdx].SpoofWG = cur
			_ = saveConfig(configPath(), appCfg)
			stateMu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cur.LastError = ""
		msg = outMsg

	case "down", "stop":
		stopLinuxSpoofAndWGServices(cur)
		cur.LastError = ""
		msg = "Spoof + WireGuard services stopped"

	case "restart":
		msg = "Spoof + WireGuard carrier listener restarted"

	case "tester_start":
		if req.TesterReq == nil {
			stateMu.Unlock()
			http.Error(w, "tester_req is required", http.StatusBadRequest)
			return
		}
		tReq := *req.TesterReq
		if tReq.DstIP == "" {
			tReq.DstIP = cur.PeerPublicIP
		}
		if err := startSpoofTesterProcess(tReq); err != nil {
			stateMu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg = fmt.Sprintf("Spoof IP Tester started in %s mode (%s)", tReq.Mode, strings.ToUpper(tReq.Protocol))

	case "tester_stop":
		stopSpoofTesterProcess()
		msg = "Spoof IP Tester stopped"

	case "tester_clear":
		clearSpoofTesterStatus()
		msg = "Spoof IP Tester results cleared"

	default:
		stateMu.Unlock()
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	cur.Health = querySpoofWGRuntimeHealth(cur)
	cur.Tester = getSpoofTesterStatusView()
	srv.Tunnels[tIdx].SpoofWG = cur
	peerCopy := *srv
	_ = saveConfig(configPath(), appCfg)
	stateMu.Unlock()

	if action == "up" || action == "apply" || action == "import" || action == "restart" {
		syncServerListeners(peerCopy)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK      bool              `json:"ok"`
		Message string            `json:"message"`
		Bundle  string            `json:"bundle,omitempty"`
		SpoofWG *SpoofWGConfig    `json:"spoof_wg"`
		Health  SpoofWGHealth     `json:"health"`
		Tester  SpoofTesterStatus `json:"tester"`
	}{
		OK:      true,
		Message: msg,
		Bundle:  bundleOut,
		SpoofWG: cur,
		Health:  cur.Health,
		Tester:  cur.Tester,
	})
}

func handleSpoofNativeAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ServerID    string              `json:"server_id"`
		Action      string              `json:"action"` // "save" | "bundle" | "import" | "up" | "down" | "restart" | "verify_pipe" | "install_binary" | "tester_start" | "tester_stop" | "tester_clear"
		Bundle      string              `json:"bundle,omitempty"`
		SpoofNative *SpoofNativeConfig  `json:"spoof_native,omitempty"`
		TesterReq   *SpoofTesterRequest `json:"tester_req,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))

	var installedMsg string
	if action == "install_binary" {
		m, err := installOfficialSpoofBinary()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		installedMsg = m
	}

	stateMu.Lock()
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
	tIdx := -1
	for i := range srv.Tunnels {
		if srv.Tunnels[i].ID == 27 {
			tIdx = i
			break
		}
	}
	if tIdx < 0 {
		stateMu.Unlock()
		http.Error(w, "Method 27 (Native Spoof Engine) not found", http.StatusNotFound)
		return
	}

	cur := normalizeSpoofNativeConfig(srv.Tunnels[tIdx].SpoofNative)
	if req.SpoofNative != nil {
		edited := *req.SpoofNative
		if edited.WGPrivKey == "" {
			edited.WGPrivKey = cur.WGPrivKey
		}
		if edited.WGPubKey == "" {
			edited.WGPubKey = cur.WGPubKey
		}
		if edited.WGPeerPriv == "" {
			edited.WGPeerPriv = cur.WGPeerPriv
		}
		if edited.WGPeerPub == "" {
			edited.WGPeerPub = cur.WGPeerPub
		}
		if edited.NoisePrivKey == "" {
			edited.NoisePrivKey = cur.NoisePrivKey
		}
		if edited.NoisePubKey == "" {
			edited.NoisePubKey = cur.NoisePubKey
		}
		if edited.NoisePeerPriv == "" {
			edited.NoisePeerPriv = cur.NoisePeerPriv
		}
		if edited.NoisePeerPub == "" {
			edited.NoisePeerPub = cur.NoisePeerPub
		}
		cur = normalizeSpoofNativeConfig(&edited)
	}
	if cur.PeerPublicIP == "" && isValidIPv4String(srv.IP) {
		cur.PeerPublicIP = srv.IP
	}

	var msg string
	var bundleOut string
	needVerifyProbe := false

	switch action {
	case "save":
		msg = fmt.Sprintf("Method 27 (%s) settings saved", strings.ToUpper(cur.Mode))

	case "install_binary":
		msg = installedMsg

	case "bundle":
		bStr, err := makeSpoofNativeBundle(cur, "")
		if err != nil {
			stateMu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		bundleOut = bStr
		msg = fmt.Sprintf("Generated Method 27 (%s) m27spf1_ bundle", strings.ToUpper(cur.Mode))

	case "import":
		imported, err := importSpoofNativeBundle(req.Bundle, cur)
		if err != nil {
			stateMu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.SpoofNative != nil && len(req.SpoofNative.SpoofIPs) > 0 {
			imported.SpoofIPs = cleanSpoofIPs(req.SpoofNative.SpoofIPs)
		}
		cur = imported
		bundleOut = cur.LastBundle
		msg = fmt.Sprintf("Imported Method 27 bundle (Mode: %s, %s/%s)",
			strings.ToUpper(cur.Mode), cur.SendTransport, cur.RecvTransport)

	case "up", "apply":
		outMsg, err := applyLinuxSpoofNativeServices(cur)
		if err != nil {
			cur.LastError = err.Error()
			srv.Tunnels[tIdx].SpoofNative = cur
			_ = saveConfig(configPath(), appCfg)
			stateMu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cur.LastError = ""
		msg = outMsg
		needVerifyProbe = true

	case "down", "stop":
		stopLinuxSpoofNativeServices(cur)
		cur.LastError = ""
		recordSpoofNativeVerification(srv.ID, cur.Mode, "", 0, 100, "Stopped by user")
		msg = "Method 27 (spoof-core-m27) services stopped"

	case "restart":
		msg = "Method 27 adapter listener restarted"
		needVerifyProbe = true

	case "verify_pipe":
		needVerifyProbe = true
		msg = "Running end-to-end Spoof Pipe verification..."

	case "tester_start":
		if req.TesterReq == nil {
			stateMu.Unlock()
			http.Error(w, "tester_req is required", http.StatusBadRequest)
			return
		}
		tReq := *req.TesterReq
		if tReq.DstIP == "" {
			tReq.DstIP = cur.PeerPublicIP
		}
		if err := startSpoofM27TesterProcess(tReq); err != nil {
			stateMu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg = fmt.Sprintf("Method 27 Spoof IP Tester started in %s mode (%s)", tReq.Mode, strings.ToUpper(tReq.Protocol))

	case "tester_stop":
		stopSpoofM27TesterProcess()
		msg = "Method 27 Spoof IP Tester stopped"

	case "tester_clear":
		clearSpoofM27TesterStatus()
		msg = "Method 27 Spoof IP Tester results cleared"

	default:
		stateMu.Unlock()
		http.Error(w, "unknown Method 27 action", http.StatusBadRequest)
		return
	}

	srv.Tunnels[tIdx].SpoofNative = cur
	peerCopy := *srv
	tcCopy := srv.Tunnels[tIdx]
	_ = saveConfig(configPath(), appCfg)
	stateMu.Unlock()

	if action == "up" || action == "apply" || action == "import" || action == "restart" || action == "save" {
		syncServerListeners(peerCopy)
	}

	if needVerifyProbe {
		res := probeSpoofNative(peerCopy, tcCopy, appCfg.NodeID)
		stateMu.Lock()
		for i := range appCfg.Servers {
			if appCfg.Servers[i].ID == peerCopy.ID {
				for j := range appCfg.Servers[i].Tunnels {
					if appCfg.Servers[i].Tunnels[j].ID == 27 {
						appCfg.Servers[i].Tunnels[j].LastDiscovery = res
						break
					}
				}
				_ = saveConfig(configPath(), appCfg)
				break
			}
		}
		stateMu.Unlock()
		if action == "verify_pipe" {
			if res.Success {
				msg = fmt.Sprintf("End-to-End Spoof Pipe Verified (%dms RTT)", res.LatencyMS)
			} else {
				msg = fmt.Sprintf("Spoof Pipe Verification Failed: %s", res.ErrorReason)
			}
		}
	}

	cur.Health = querySpoofNativeRuntimeHealth(peerCopy.ID, cur)
	cur.Tester = getSpoofM27TesterStatusView()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK          bool               `json:"ok"`
		Message     string             `json:"message"`
		Bundle      string             `json:"bundle,omitempty"`
		SpoofNative *SpoofNativeConfig `json:"spoof_native"`
		Health      SpoofNativeHealth  `json:"health"`
		Tester      SpoofTesterStatus  `json:"tester"`
	}{
		OK:          true,
		Message:     msg,
		Bundle:      bundleOut,
		SpoofNative: cur,
		Health:      cur.Health,
		Tester:      cur.Tester,
	})
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
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
			if updated.ID == 25 && updated.GREFRP != nil {
				if updated.GREFRP.FRPServerPort >= 1024 && updated.GREFRP.FRPServerPort <= 65535 {
					updated.ListenPort = updated.GREFRP.FRPServerPort
				} else {
					updated.GREFRP.FRPServerPort = updated.ListenPort
				}
				if err := validateGREFRPConfiguration(updated.GREFRP, updated.ListenPort); err != nil {
					stateMu.Unlock()
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				updated.ForwardPorts = syncForwardPortsCSVFromRules(updated.GREFRP)
				updated.GREFRP = normalizeGREFRPConfig(updated.GREFRP, updated.ListenPort, updated.ForwardPorts)
			}
			if updated.ID == 26 {
				prevSpoof := normalizeSpoofWGConfig(srv.Tunnels[i].SpoofWG)
				if updated.SpoofWG != nil {
					if updated.SpoofWG.WGPrivKey == "" {
						updated.SpoofWG.WGPrivKey = prevSpoof.WGPrivKey
					}
					if updated.SpoofWG.WGPeerPriv == "" {
						updated.SpoofWG.WGPeerPriv = prevSpoof.WGPeerPriv
					}
				}
				updated.SpoofWG = normalizeSpoofWGConfig(updated.SpoofWG)
				if updated.SpoofWG.PeerPublicIP == "" && isValidIPv4String(srv.IP) {
					updated.SpoofWG.PeerPublicIP = srv.IP
				}
				updated.SpoofWG.Health = querySpoofWGRuntimeHealth(updated.SpoofWG)
				updated.SpoofWG.Tester = getSpoofTesterStatusView()
			}
			if updated.ID == 27 {
				prevNat := normalizeSpoofNativeConfig(srv.Tunnels[i].SpoofNative)
				if updated.SpoofNative != nil {
					if updated.SpoofNative.WGPrivKey == "" {
						updated.SpoofNative.WGPrivKey = prevNat.WGPrivKey
					}
					if updated.SpoofNative.WGPeerPriv == "" {
						updated.SpoofNative.WGPeerPriv = prevNat.WGPeerPriv
					}
					if updated.SpoofNative.NoisePrivKey == "" {
						updated.SpoofNative.NoisePrivKey = prevNat.NoisePrivKey
					}
					if updated.SpoofNative.NoisePeerPriv == "" {
						updated.SpoofNative.NoisePeerPriv = prevNat.NoisePeerPriv
					}
				}
				updated.SpoofNative = normalizeSpoofNativeConfig(updated.SpoofNative)
				if updated.SpoofNative.PeerPublicIP == "" && isValidIPv4String(srv.IP) {
					updated.SpoofNative.PeerPublicIP = srv.IP
				}
				updated.SpoofNative.Health = querySpoofNativeRuntimeHealth(srv.ID, updated.SpoofNative)
				updated.SpoofNative.Tester = getSpoofM27TesterStatusView()
			}
			if strings.TrimSpace(updated.SpeedLimitMBps) == "" {
				updated.SpeedLimitMBps = "0"
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

type batchPortItem struct {
	ID           int    `json:"id"`
	ListenPort   int    `json:"listen_port"`
	ForwardPorts string `json:"forward_ports,omitempty"`
}

func handleBatchPortsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ServerID string          `json:"server_id"`
		Items    []batchPortItem `json:"items"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	stateMu.Lock()
	if appCfg.Role != "master" {
		stateMu.Unlock()
		http.Error(w, "ports can only be edited on the master node", http.StatusForbidden)
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

	byID := make(map[int]batchPortItem, len(req.Items))
	for _, item := range req.Items {
		byID[item.ID] = item
	}

	srv := &appCfg.Servers[sIdx]
	for i := range srv.Tunnels {
		tid := srv.Tunnels[i].ID
		if upd, ok := byID[tid]; ok {
			if upd.ListenPort >= 1024 && upd.ListenPort <= 65535 {
				srv.Tunnels[i].ListenPort = upd.ListenPort
				if srv.Tunnels[i].ID == 25 && srv.Tunnels[i].GREFRP != nil {
					srv.Tunnels[i].GREFRP.FRPServerPort = upd.ListenPort
				}
				if srv.ActiveMethodID == tid {
					srv.ActivePort = upd.ListenPort
				}
			}
			if strings.TrimSpace(upd.ForwardPorts) != "" {
				srv.Tunnels[i].ForwardPorts = strings.TrimSpace(upd.ForwardPorts)
			}
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
