package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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
	discoveryMu     sync.Mutex
	discoveryCancel = make(map[string]chan struct{})

	engineMu        sync.Mutex
	activeListeners = make(map[string][]net.Listener)

	sharedBuckets   = make(map[int64]*sharedThrottleBucket)
	sharedBucketsMu sync.Mutex

	appRxBytes uint64
	appTxBytes uint64
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

func syncServerListeners(peer ServerPeer) {
	stopAllServerListeners(peer.ID)

	var bound []net.Listener
	tunnels := normalizeTunnels(peer.Tunnels)

	for _, tun := range tunnels {
		tc := tun
		if !tc.Implemented {
			continue
		}
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

	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	br := bufio.NewReader(conn)
	firstLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return
	}

	var wsKey, targetPort, syncPayloadB64, grpcMode, peerHeader string
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
		} else if strings.HasPrefix(low, "x-sahand-peer:") {
			peerHeader = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}

	effectivePeerID := peerID
	if peerHeader != "" {
		effectivePeerID = peerHeader
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
		resp := processIncomingSync(effectivePeerID, remoteHost, pkt)
		respBytes, _ := json.Marshal(resp)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"))
		_, _ = conn.Write(respBytes)
		return
	}

	// Engine 1: Discovery Probe (always responds regardless of Traffic Tunnel toggle, and marks peer CONNECTED)
	if strings.HasPrefix(targetPort, "probe:") {
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)
		if tc.ID == 2 || grpcMode == "grpc" {
			handleGRPCProbeReply(conn)
			return
		}
		handleWSSProbeReply(conn, wsKey)
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

	if tc.ID == 2 || grpcMode == "grpc" {
		handleGRPCIncomingTraffic(conn, br, tc, targetPort)
	} else {
		handleWSSIncomingTraffic(conn, br, tc, wsKey, targetPort)
	}
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
	if tc.ID == 2 {
		forwardGRPCTraffic(client, peer, tc, targetPort)
	} else {
		forwardWSSTraffic(client, peer, tc, targetPort)
	}
}

func recordLifelineEvent(peer *ServerPeer, mID int, mName string, port int, sec int, lat int64, dir string) {
	nowStr := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	if len(peer.RecentLifelines) > 0 {
		top := &peer.RecentLifelines[0]
		if top.MethodID == mID && top.Port == port && top.ConnectedAt == nowStr {
			if lat > 1 {
				top.LatencyMS = lat
			}
			return
		}
	}
	ev := LifelineEvent{
		MethodID:    mID,
		MethodName:  mName,
		Port:        port,
		Security:    sec,
		LatencyMS:   lat,
		Direction:   dir,
		ConnectedAt: nowStr,
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

func markPeerConnectedInbound(peerID, remoteIP string, methodID, port int, latencyMS int64) {
	stateMu.Lock()
	defer stateMu.Unlock()

	for i := range appCfg.Servers {
		srv := &appCfg.Servers[i]
		if srv.ID == peerID || srv.IP == remoteIP || len(appCfg.Servers) == 1 {
			srv.Status = "CONNECTED"
			srv.Running = true
			srv.NextRetryAt = ""
			for _, m := range methodCatalogue {
				if m.ID == methodID {
					srv.ActiveMethodID = m.ID
					srv.ActiveMethod = m.Name
					srv.ActivePort = port
					srv.ActiveSecurity = m.Security
					if latencyMS > 1 || srv.ActiveLatencyMS == 0 {
						srv.ActiveLatencyMS = latencyMS
					}
					recordLifelineEvent(srv, m.ID, m.Name, port, m.Security, srv.ActiveLatencyMS, "inbound")
					break
				}
			}
			for j := range srv.Tunnels {
				if srv.Tunnels[j].ID == methodID {
					srv.Tunnels[j].LastDiscovery = MethodResult{
						MethodID:  methodID,
						Success:   true,
						Direction: "inbound",
						LatencyMS: srv.ActiveLatencyMS,
						TestedAt:  time.Now().UTC().Format("15:04:05 UTC"),
					}
					break
				}
			}
			_ = saveConfig(configPath(), appCfg)
			break
		}
	}
}

func processIncomingSync(localPeerID, remoteIP string, pkt SyncPacket) SyncResponse {
	stateMu.Lock()
	defer stateMu.Unlock()

	var resp SyncResponse
	resp.OK = true
	resp.NodeID = appCfg.NodeID
	resp.CertPin = appCfg.CertPin

	for i := range appCfg.Servers {
		srv := &appCfg.Servers[i]
		if srv.ID == localPeerID || srv.ID == pkt.PeerID || srv.ID == pkt.SenderID || srv.IP == remoteIP || len(appCfg.Servers) == 1 {
			if appCfg.Role == "agent" && len(pkt.Tunnels) == 30 && pkt.ConfigVersion >= srv.ConfigVersion {
				srv.Tunnels = normalizeTunnels(pkt.Tunnels)
				srv.ConfigVersion = pkt.ConfigVersion
				srv.SyncState = "synced"
				go syncServerListeners(*srv)
			}
			srv.Status = "CONNECTED"
			srv.Running = true
			srv.SyncState = "synced"
			srv.NextRetryAt = ""
			if pkt.LatencyMS > 0 {
				srv.ActiveLatencyMS = pkt.LatencyMS
			}
			for _, m := range methodCatalogue {
				if m.ID == pkt.MethodID {
					srv.ActiveMethodID = m.ID
					srv.ActiveMethod = m.Name
					if pkt.Port > 0 {
						srv.ActivePort = pkt.Port
					} else {
						srv.ActivePort = m.DefaultPort
					}
					srv.ActiveSecurity = m.Security
					recordLifelineEvent(srv, m.ID, m.Name, srv.ActivePort, m.Security, srv.ActiveLatencyMS, "inbound")
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

	stateMu.RLock()
	localNodeID := appCfg.NodeID
	stateMu.RUnlock()

	if tc.ID == 2 {
		return probeGRPC(peer, tc, localNodeID)
	}
	return probeWSS(peer, tc, localNodeID)
}

func pushParitySyncOverMethod(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
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

	padLen := 32 + randomIntN(128)
	padHex, _ := randomHex(padLen)

	pkt := SyncPacket{
		Type:          "parity_sync",
		SenderID:      senderID,
		PeerID:        peer.ID,
		MethodID:      tc.ID,
		Port:          tc.ListenPort,
		LatencyMS:     latencyMS,
		ConfigVersion: peer.ConfigVersion,
		CertPin:       certPin,
		Padding:       padHex,
	}
	if role == "master" {
		pkt.Tunnels = peer.Tunnels
	}
	rawPkt, _ := json.Marshal(pkt)
	b64 := base64.StdEncoding.EncodeToString(rawPkt)

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nX-Sahand-Peer: %s\r\nX-Sahand-Sync: %s\r\n\r\n", sni, peer.ID, b64)
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

			// Sort methods by highest Security % first
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

				if res.Success {
					chosen := tc
					bestCandidate = &chosen
					bestResult = res
					// Stop trying remaining methods once the most secure working method connects
					break
				}
				if tc.Implemented {
					time.Sleep(time.Duration(90+randomIntN(140)) * time.Millisecond)
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
				updatedPeer.ActivePort = bestCandidate.ListenPort
				updatedPeer.ActiveSecurity = bestCandidate.Security
				updatedPeer.ActiveLatencyMS = bestResult.LatencyMS
				updatedPeer.NextRetryAt = ""
				recordLifelineEvent(updatedPeer, bestCandidate.ID, bestCandidate.Name, bestCandidate.ListenPort, bestCandidate.Security, bestResult.LatencyMS, "outbound")
				peerCopy := *updatedPeer
				_ = saveConfig(configPath(), appCfg)
				stateMu.Unlock()

				_ = pushParitySyncOverMethod(peerCopy, *bestCandidate, bestResult.LatencyMS)
				go syncServerListeners(peerCopy)

				// Silent jittered liveness monitor: only re-runs 30-method sweep if active connection drops
				for {
					jitterWait := time.Duration(90+randomIntN(90)) * time.Second
					timer := time.NewTimer(jitterWait)
					select {
					case <-stopCh:
						timer.Stop()
						return
					case <-timer.C:
					}

					stateMu.RLock()
					var curPeer *ServerPeer
					for i := range appCfg.Servers {
						if appCfg.Servers[i].ID == peerID {
							cp := appCfg.Servers[i]
							curPeer = &cp
							break
						}
					}
					stateMu.RUnlock()

					if curPeer == nil || !curPeer.Running {
						return
					}
					var activeTun *TunnelConfig
					for i := range curPeer.Tunnels {
						if curPeer.Tunnels[i].ID == curPeer.ActiveMethodID {
							t := curPeer.Tunnels[i]
							activeTun = &t
							break
						}
					}
					if activeTun == nil {
						break
					}
					chk := probeSingleMethod(*curPeer, *activeTun)
					if !chk.Success {
						break // Connection broke -> restart 30-method sweep
					}
				}
				continue
			}

			// Random retry delay between 10 and 30 minutes per spec
			retryMins := 10 + randomIntN(21)
			retryDuration := time.Duration(retryMins) * time.Minute
			nextRetry := time.Now().UTC().Add(retryDuration)
			updatedPeer.Status = "RETRY SCHEDULED"
			updatedPeer.ActiveMethodID = 0
			updatedPeer.ActiveMethod = ""
			updatedPeer.ActivePort = 0
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
