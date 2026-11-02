package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
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

	engineMu          sync.Mutex
	activeListeners   = make(map[string][]net.Listener)
	activePacketConns = make(map[string][]net.PacketConn)

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
		_ = tcp.SetKeepAlivePeriod(20 * time.Second)
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

func formatConnectionInitiator(localRole, direction string) string {
	if localRole == "master" {
		if direction == "outbound" {
			return "Master → Agent"
		}
		return "Agent → Master"
	}
	if direction == "outbound" {
		return "Agent → Master"
	}
	return "Master → Agent"
}

func shouldBindEntryPorts() bool {
	stateMu.RLock()
	role := appCfg.Role
	stateMu.RUnlock()
	return role != "agent"
}

func stopAllServerListeners(peerID string) {
	stopWSSPeerResources(peerID)
	stopQUICPeerResources(peerID)
	stopRatholePeerResources(peerID)
	stopNoiseStealthPeerResources(peerID)
	stopReverseTCPPeerResources(peerID)
	stopSOCKS5PeerResources(peerID)
	stopSSHTunnelPeerResources(peerID)
	stopUDPRelayPeerResources(peerID)
	stopDNSTransportPeerResources(peerID)
	stopWebTransportPeerResources(peerID)
	stopTCPMultiplexPeerResources(peerID)
	stopWSMultiplexPeerResources(peerID)
	stopSahandRawPeerResources(peerID)
	stopGREFRPPeerResources(peerID)

	engineMu.Lock()
	defer engineMu.Unlock()
	if list, ok := activeListeners[peerID]; ok {
		for _, ln := range list {
			_ = ln.Close()
		}
		delete(activeListeners, peerID)
	}
	if pList, ok := activePacketConns[peerID]; ok {
		for _, pc := range pList {
			_ = pc.Close()
		}
		delete(activePacketConns, peerID)
	}
}

func syncServerListeners(peer ServerPeer) {
	stopAllServerListeners(peer.ID)

	var bound []net.Listener
	var boundUDP []net.PacketConn
	tunnels := normalizeTunnels(peer.Tunnels)
	bindEntries := shouldBindEntryPorts()

	for _, tun := range tunnels {
		tc := tun
		if !tc.Implemented {
			continue
		}

		// Method 25 (GRE + FRP): Point-to-Point GRE Tunnel + FRP v0.61.1 Port Forwarding Engine
		if tc.ID == 25 {
			cLn, eLns, uConns, err := startGREFRPServer(peer, tc)
			if err == nil {
				if cLn != nil {
					bound = append(bound, cLn)
				}
				bound = append(bound, eLns...)
				boundUDP = append(boundUDP, uConns...)
			}
			continue
		}

		// Method 24 (SAHAND-RAW): Raw Packet Tunnel Engine (RFC 793 Framing + X25519/ChaCha20-Poly1305 + ARQ + Mux)
		if tc.ID == 24 {
			if pConn, err := startSahandRawServer(peer, tc); err == nil && pConn != nil {
				boundUDP = append(boundUDP, pConn)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
						if udpEntry := startSahandRawUDPEntryForwarder(peer, tc, targetPort); udpEntry != nil {
							boundUDP = append(boundUDP, udpEntry)
						}
					}
				}
			}
			continue
		}

		// Method 01 (WSS): Standards-compliant RFC 6455 WebSocket Secure Server & Upgrader
		if tc.ID == 1 {
			if ln, err := startWSSServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
					}
				}
			}
			continue
		}

		// Method 23 (HTTP Upgrade): Genuine RFC 9110 Section 7.8 / Xray httpupgrade (101 Switching Protocols + Raw Stream)
		if tc.ID == 23 {
			if ln, err := startHTTPUpgradeServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
					}
				}
			}
			continue
		}

		// Method 22 (WebSocket Multiplex): Genuine RFC 6455 Binary WebSocket Stream Multiplexer
		if tc.ID == 22 {
			if ln, err := startWSMultiplexServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
					}
				}
			}
			continue
		}

		// Method 21 (TCP Multiplex): Genuine Yamux-style Binary Stream Multiplexer
		if tc.ID == 21 {
			if ln, err := startTCPMultiplexServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
					}
				}
			}
			continue
		}

		// Method 20 (mTLS Stream): Genuine TLS 1.3 Mutual X.509 Certificate Authentication
		if tc.ID == 20 {
			if ln, err := startMTLSStreamServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
					}
				}
			}
			continue
		}

		// Method 19 (WebTransport): Genuine QUIC H3 Extended CONNECT + TLS 1.3 Fallback
		if tc.ID == 19 {
			uConn, tLn := startWebTransportServer(peer, tc)
			if uConn != nil {
				boundUDP = append(boundUDP, uConn)
			}
			if tLn != nil {
				bound = append(bound, tLn)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
						if udpEntry := startWebTransportUDPEntryForwarder(peer, tc, targetPort); udpEntry != nil {
							boundUDP = append(boundUDP, udpEntry)
						}
					}
				}
			}
			continue
		}

		// Method 18 (HTTP Long Polling): Streaming HTTP/1.1 Event-Stream Carrier
		if tc.ID == 18 {
			if ln, err := startHTTPLongPollingServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
					}
				}
			}
			continue
		}

		// Method 17 (TLS over TCP): Record-Layer Authenticated TLS over TCP
		if tc.ID == 17 {
			if ln, err := startTLSOverTCPServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
					}
				}
			}
			continue
		}

		// Method 16 (DNS Transport): Genuine RFC 1035 UDP DNS + TCP DNS (Section 4.2.2)
		if tc.ID == 16 {
			uConn, tLn := startDNSTransportServer(peer, tc)
			if uConn != nil {
				boundUDP = append(boundUDP, uConn)
			}
			if tLn != nil {
				bound = append(bound, tLn)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
						if udpEntry := startDNSTransportUDPEntryForwarder(peer, tc, targetPort); udpEntry != nil {
							boundUDP = append(boundUDP, udpEntry)
						}
					}
				}
			}
			continue
		}

		// Method 15 (UDP Relay): Authenticated Binary UDP Datagram Relay + Companion Stream Carrier
		if tc.ID == 15 {
			uConn, tLn := startUDPRelayServer(peer, tc)
			if uConn != nil {
				boundUDP = append(boundUDP, uConn)
			}
			if tLn != nil {
				bound = append(bound, tLn)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
						if udpEntry := startUDPRelayEntryForwarder(peer, tc, targetPort); udpEntry != nil {
							boundUDP = append(boundUDP, udpEntry)
						}
					}
				}
			}
			continue
		}

		// Method 14 (Raw TCP): Zero-ASCII Binary Preamble + Unframed Raw TCP Splicing
		if tc.ID == 14 {
			if ln, err := startRawTCPServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
					}
				}
			}
			continue
		}

		// Method 13 (SSH Tunnel): Genuine RFC 4251-4254 SSH-2 Server & direct-tcpip Channels
		if tc.ID == 13 {
			if ln, err := startSSHTunnelServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
					}
				}
			}
			continue
		}

		// Method 12 (SOCKS5): Genuine RFC 1928 + RFC 1929 SOCKS5 Server (TCP CONNECT + UDP ASSOCIATE)
		if tc.ID == 12 {
			if ln, err := startSOCKS5ServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
						if udpEntry := startSOCKS5UDPEntryForwarder(peer, tc, targetPort); udpEntry != nil {
							boundUDP = append(boundUDP, udpEntry)
						}
					}
				}
			}
			continue
		}

		// Method 11 (Reverse TCP): Warm Reverse Socket Pool + Control Channel
		if tc.ID == 11 {
			if ln, err := startReverseTCPServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" {
				startReverseTCPClientWorker(peer, tc)
				if bindEntries {
					forwardPorts := parsePortList(tc.ForwardPorts)
					for _, fp := range forwardPorts {
						targetPort := fp
						entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
						if err == nil {
							bound = append(bound, entryLn)
							go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
						}
					}
				}
			}
			continue
		}

		// Method 10 (Noise TCP Stealth): Noise_IK_25519_ChaChaPoly_BLAKE2s with obfuscated length headers
		if tc.ID == 10 {
			if ln, err := startNoiseStealthServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" && bindEntries {
				forwardPorts := parsePortList(tc.ForwardPorts)
				for _, fp := range forwardPorts {
					targetPort := fp
					entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
					if err == nil {
						bound = append(bound, entryLn)
						go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
						if udpEntry := startNoiseStealthUDPEntryForwarder(peer, tc, targetPort); udpEntry != nil {
							boundUDP = append(boundUDP, udpEntry)
						}
					}
				}
			}
			continue
		}

		// Method 09 (Rathole): Genuine Noise_NK_25519_ChaChaPoly_BLAKE2s listener + Reverse Control Channel
		if tc.ID == 9 {
			if ln, err := startRatholeServerListener(peer, tc); err == nil {
				bound = append(bound, ln)
			}
			if tc.Enabled && peer.IP != "" {
				startRatholeReverseClient(peer, tc)
				if bindEntries {
					forwardPorts := parsePortList(tc.ForwardPorts)
					for _, fp := range forwardPorts {
						targetPort := fp
						entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
						if err == nil {
							bound = append(bound, entryLn)
							go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
							if udpEntry := startRatholeUDPEntryForwarder(peer, tc, targetPort); udpEntry != nil {
								boundUDP = append(boundUDP, udpEntry)
							}
						}
					}
				}
			}
			continue
		}

		if tc.ID == 8 {
			_ = registerQUICPeerListener(peer, tc)
		}

		listenAddr := fmt.Sprintf("0.0.0.0:%d", tc.ListenPort)
		var ln net.Listener
		var err error
		if tc.ID == 6 {
			ln, err = net.Listen("tcp", listenAddr)
		} else {
			nextProtos := []string{"http/1.1"}
			if tc.ID == 2 || tc.ID == 3 || tc.ID == 7 {
				nextProtos = []string{"h2", "http/1.1"}
			} else if tc.ID == 8 {
				nextProtos = []string{quicALPN, "h3", "quic", "h2"}
			}
			tlsCfg := &tls.Config{
				Certificates: []tls.Certificate{localCert},
				MinVersion:   tls.VersionTLS12,
				NextProtos:   nextProtos,
			}
			ln, err = tls.Listen("tcp", listenAddr, tlsCfg)
		}

		if err == nil {
			bound = append(bound, ln)
			go acceptTunnelServerLoop(ln, peer.ID, tc)
		}

		// Engine 2: Bind local forwarding entry ports ONLY on the Entry Server (Master) when Traffic Tunnel toggle is ON
		if tc.Enabled && peer.IP != "" && bindEntries {
			forwardPorts := parsePortList(tc.ForwardPorts)
			for _, fp := range forwardPorts {
				targetPort := fp
				entryLn, err := net.Listen("tcp", "0.0.0.0:"+targetPort)
				if err == nil {
					bound = append(bound, entryLn)
					go acceptTrafficEntryLoop(entryLn, peer, tc, targetPort)
					if tc.ID == 8 {
						if udpEntry := startQUICUDPEntryForwarder(peer, tc, targetPort); udpEntry != nil {
							boundUDP = append(boundUDP, udpEntry)
						}
					}
				}
			}
		}
	}

	engineMu.Lock()
	activeListeners[peer.ID] = bound
	activePacketConns[peer.ID] = boundUDP
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

	// Method 03: Binary HTTP/2 connection preface
	if strings.HasPrefix(firstLine, "PRI * HTTP/2.0") {
		handleH2IncomingConn(conn, br, peerID, remoteHost, tc)
		return
	}

	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return
	}

	var targetPort, syncPayloadB64, tunnelMode, peerHeader, timeHeader string
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "x-target-port:") {
			targetPort = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(low, "x-sahand-sync:") {
			syncPayloadB64 = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(low, "x-tunnel-mode:") {
			tunnelMode = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(low, "x-sahand-peer:") {
			peerHeader = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(low, "x-sahand-time:") {
			timeHeader = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}

	if timeHeader != "" {
		applyMasterTimeHeader(timeHeader)
	}

	if (parts[0] == "CONNECT" || parts[0] == "RELAY" || parts[0] == "STREAM" || parts[0] == "QUIC") && targetPort == "" {
		if strings.HasPrefix(parts[1], "probe:") {
			targetPort = parts[1]
		} else if idx := strings.LastIndex(parts[1], ":"); idx >= 0 {
			targetPort = parts[1][idx+1:]
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

	// Engine 1: Discovery Probe (Methods 02–08)
	if strings.HasPrefix(targetPort, "probe:") {
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)
		switch {
		case tc.ID == 2 || tunnelMode == "grpc":
			handleGRPCProbeReply(conn)
		case tc.ID == 4 || parts[0] == "CONNECT":
			handleHTTPConnectProbeReply(conn)
		case tc.ID == 5 || tunnelMode == "https-proxy":
			handleHTTPSProxyProbeReply(conn)
		case tc.ID == 6 || parts[0] == "RELAY" || tunnelMode == "tcp-relay":
			handleTCPRelayProbeReply(conn)
		case tc.ID == 7 || parts[0] == "STREAM" || tunnelMode == "tls-stream":
			handleTLSStreamProbeReply(conn)
		case tc.ID == 8 || parts[0] == "QUIC" || tunnelMode == "quic":
			handleQUICStreamProbeReply(conn)
		}
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
			targetPort = strconv.Itoa(32000 + tc.ID)
		}
	}

	switch {
	case tc.ID == 2 || tunnelMode == "grpc":
		handleGRPCIncomingTraffic(conn, br, tc, targetPort)
	case tc.ID == 4 || parts[0] == "CONNECT":
		handleHTTPConnectIncomingTraffic(conn, br, tc, targetPort)
	case tc.ID == 5 || tunnelMode == "https-proxy":
		handleHTTPSProxyIncomingTraffic(conn, br, tc, targetPort)
	case tc.ID == 6 || parts[0] == "RELAY" || tunnelMode == "tcp-relay":
		handleTCPRelayIncomingTraffic(conn, br, tc, targetPort)
	case tc.ID == 7 || parts[0] == "STREAM" || tunnelMode == "tls-stream":
		handleTLSStreamIncomingTraffic(conn, br, tc, targetPort)
	case tc.ID == 8 || parts[0] == "QUIC" || tunnelMode == "quic":
		handleQUICStreamIncomingTraffic(conn, br, tc, targetPort)
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
	switch tc.ID {
	case 2:
		forwardGRPCTraffic(client, peer, tc, targetPort)
	case 3:
		forwardHTTP2Traffic(client, peer, tc, targetPort)
	case 4:
		forwardHTTPConnectTraffic(client, peer, tc, targetPort)
	case 5:
		forwardHTTPSProxyTraffic(client, peer, tc, targetPort)
	case 6:
		forwardTCPRelayTraffic(client, peer, tc, targetPort)
	case 7:
		forwardTLSStreamTraffic(client, peer, tc, targetPort)
	case 8:
		forwardQUICTraffic(client, peer, tc, targetPort)
	case 9:
		forwardRatholeTraffic(client, peer, tc, targetPort)
	case 10:
		forwardNoiseStealthTraffic(client, peer, tc, targetPort)
	case 11:
		forwardReverseTCPTraffic(client, peer, tc, targetPort)
	case 12:
		forwardSOCKS5Traffic(client, peer, tc, targetPort)
	case 13:
		forwardSSHTunnelTraffic(client, peer, tc, targetPort)
	case 14, 15:
		forwardRawTCPTraffic(client, peer, tc, targetPort)
	case 16:
		forwardDNSTransportTraffic(client, peer, tc, targetPort)
	case 17:
		forwardTLSOverTCPTraffic(client, peer, tc, targetPort)
	case 18:
		forwardHTTPLongPollingTraffic(client, peer, tc, targetPort)
	case 19:
		forwardWebTransportTraffic(client, peer, tc, targetPort)
	case 20:
		forwardMTLSStreamTraffic(client, peer, tc, targetPort)
	case 21:
		forwardTCPMultiplexTraffic(client, peer, tc, targetPort)
	case 22:
		forwardWSMultiplexTraffic(client, peer, tc, targetPort)
	case 23:
		forwardHTTPUpgradeTraffic(client, peer, tc, targetPort)
	case 24:
		forwardSahandRawTraffic(client, peer, tc, targetPort)
	case 25:
		forwardGREFRPTraffic(client, peer, tc, targetPort)
	default:
		forwardWSSTraffic(client, peer, tc, targetPort)
	}
}

func recordLifelineEvent(peer *ServerPeer, mID int, mName string, port int, sec int, lat int64, dir, initiator string) {
	nowStr := formatMasterTimestamp(masterNow())
	if len(peer.RecentLifelines) > 0 {
		top := &peer.RecentLifelines[0]
		if top.MethodID == mID && top.Port == port && top.Direction == dir {
			if lat > 1 {
				top.LatencyMS = lat
			}
			top.Initiator = initiator
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
		Initiator:   initiator,
		ConnectedAt: nowStr,
	}
	history := []LifelineEvent{ev}
	for _, old := range peer.RecentLifelines {
		if len(history) >= 20 {
			break
		}
		history = append(history, old)
	}
	peer.RecentLifelines = history
}

func markPeerConnectedInbound(peerID, remoteIP string, methodID, port int, latencyMS int64) {
	stateMu.Lock()
	defer stateMu.Unlock()

	initiator := formatConnectionInitiator(appCfg.Role, "inbound")
	testedStr := formatMasterClockSec(masterNow())

	for i := range appCfg.Servers {
		srv := &appCfg.Servers[i]
		if srv.ID == peerID || srv.IP == remoteIP || len(appCfg.Servers) == 1 {
			srv.Status = "CONNECTED"
			srv.Running = true
			srv.NextRetryAt = ""
			srv.ActiveDirection = "inbound"
			srv.ActiveInitiator = initiator
			srv.LastInboundAt = time.Now().Unix()
			for _, m := range methodCatalogue {
				if m.ID == methodID {
					srv.ActiveMethodID = m.ID
					srv.ActiveMethod = m.Name
					srv.ActivePort = port
					srv.ActiveSecurity = m.Security
					if latencyMS > 1 || srv.ActiveLatencyMS == 0 {
						srv.ActiveLatencyMS = latencyMS
					}
					recordLifelineEvent(srv, m.ID, m.Name, port, m.Security, srv.ActiveLatencyMS, "inbound", initiator)
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
						TestedAt:  testedStr,
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

	if appCfg.Role == "agent" && pkt.MasterUnix > 0 {
		appCfg.MasterClockDelta = pkt.MasterUnix - time.Now().Unix()
		appCfg.MasterTZOffsetSec = pkt.MasterTZOff
		if pkt.MasterTZName != "" {
			appCfg.MasterTZName = pkt.MasterTZName
		}
	}

	var resp SyncResponse
	resp.OK = true
	resp.NodeID = appCfg.NodeID
	resp.CertPin = appCfg.CertPin
	resp.MasterSigningPublicKey = appCfg.MasterSigningPublicKey
	resp.MasterNoiseStaticPublicKey = appCfg.MasterNoiseStaticPublicKey
	resp.AgentSigningPublicKey = appCfg.AgentSigningPublicKey
	resp.AgentNoiseStaticPublicKey = appCfg.AgentNoiseStaticPublicKey
	if appCfg.Role == "master" {
		now := time.Now()
		zName, zOff := now.Zone()
		resp.MasterUnix = now.Unix()
		resp.MasterTZName = zName
		resp.MasterTZOff = zOff
	}

	initiator := formatConnectionInitiator(appCfg.Role, "inbound")

	for i := range appCfg.Servers {
		srv := &appCfg.Servers[i]
		if srv.ID == localPeerID || srv.ID == pkt.PeerID || srv.ID == pkt.SenderID || srv.IP == remoteIP || len(appCfg.Servers) == 1 {
			if pkt.CertPin != "" {
				srv.RemoteCertPin = pkt.CertPin
			}
			if _, err := decodeHexExact(pkt.AgentNoiseStaticPublicKey, 32); err == nil {
				srv.AgentNoiseStaticPublicKey = strings.ToLower(strings.TrimSpace(pkt.AgentNoiseStaticPublicKey))
			}
			if _, err := decodeHexExact(pkt.AgentSigningPublicKey, 32); err == nil {
				srv.AgentSigningPublicKey = strings.ToLower(strings.TrimSpace(pkt.AgentSigningPublicKey))
			}
			if _, err := decodeHexExact(pkt.MasterNoiseStaticPublicKey, 32); err == nil && srv.MasterNoiseStaticPublicKey == "" {
				srv.MasterNoiseStaticPublicKey = strings.ToLower(strings.TrimSpace(pkt.MasterNoiseStaticPublicKey))
			}
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
			srv.ActiveDirection = "inbound"
			srv.ActiveInitiator = initiator
			srv.LastInboundAt = time.Now().Unix()
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
					recordLifelineEvent(srv, m.ID, m.Name, srv.ActivePort, m.Security, srv.ActiveLatencyMS, "inbound", initiator)
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
		TestedAt:  formatMasterClockSec(masterNow()),
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

	switch tc.ID {
	case 1:
		res = probeWSS(peer, tc, localNodeID)
	case 2:
		res = probeGRPC(peer, tc, localNodeID)
	case 3:
		res = probeHTTP2(peer, tc, localNodeID)
	case 4:
		res = probeHTTPConnect(peer, tc, localNodeID)
	case 5:
		res = probeHTTPSProxy(peer, tc, localNodeID)
	case 6:
		res = probeTCPRelay(peer, tc, localNodeID)
	case 7:
		res = probeTLSStream(peer, tc, localNodeID)
	case 8:
		res = probeQUIC(peer, tc, localNodeID)
	case 9:
		res = probeRathole(peer, tc, localNodeID)
	case 10:
		res = probeNoiseStealth(peer, tc, localNodeID)
	case 11:
		res = probeReverseTCP(peer, tc, localNodeID)
	case 12:
		res = probeSOCKS5(peer, tc, localNodeID)
	case 13:
		res = probeSSHTunnel(peer, tc, localNodeID)
	case 14:
		res = probeRawTCP(peer, tc, localNodeID)
	case 15:
		res = probeUDPRelay(peer, tc, localNodeID)
	case 16:
		res = probeDNSTransport(peer, tc, localNodeID)
	case 17:
		res = probeTLSOverTCP(peer, tc, localNodeID)
	case 18:
		res = probeHTTPLongPolling(peer, tc, localNodeID)
	case 19:
		res = probeWebTransport(peer, tc, localNodeID)
	case 20:
		res = probeMTLSStream(peer, tc, localNodeID)
	case 21:
		res = probeTCPMultiplex(peer, tc, localNodeID)
	case 22:
		res = probeWSMultiplex(peer, tc, localNodeID)
	case 23:
		res = probeHTTPUpgrade(peer, tc, localNodeID)
	case 24:
		res = probeSahandRaw(peer, tc, localNodeID)
	case 25:
		res = probeGREFRP(peer, tc, localNodeID)
	default:
		res.Success = false
		res.ErrorReason = "Driver not implemented"
	}
	res.TestedAt = formatMasterClockSec(masterNow())
	return res
}

func pushParitySyncOverMethod(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	switch tc.ID {
	case 25:
		return pushGREFRPParitySync(peer, tc, latencyMS)
	case 24:
		return pushSahandRawParitySync(peer, tc, latencyMS)
	case 1:
		return pushWSSParitySync(peer, tc, latencyMS)
	case 23:
		return pushHTTPUpgradeParitySync(peer, tc, latencyMS)
	case 22:
		return pushWSMultiplexParitySync(peer, tc, latencyMS)
	case 21:
		return pushTCPMultiplexParitySync(peer, tc, latencyMS)
	case 20:
		return pushMTLSStreamParitySync(peer, tc, latencyMS)
	case 19:
		return pushWebTransportParitySync(peer, tc, latencyMS)
	case 18:
		return pushHTTPLongPollingParitySync(peer, tc, latencyMS)
	case 17:
		return pushTLSOverTCPParitySync(peer, tc, latencyMS)
	case 16:
		return pushDNSTransportParitySync(peer, tc, latencyMS)
	case 15:
		return pushUDPRelayParitySync(peer, tc, latencyMS)
	case 14:
		return pushRawTCPParitySync(peer, tc, latencyMS)
	case 13:
		return pushSSHTunnelParitySync(peer, tc, latencyMS)
	case 12:
		return pushSOCKS5ParitySync(peer, tc, latencyMS)
	case 11:
		return pushReverseTCPParitySync(peer, tc, latencyMS)
	case 10:
		return pushNoiseStealthParitySync(peer, tc, latencyMS)
	case 9:
		return pushRatholeParitySync(peer, tc, latencyMS)
	case 8:
		if pushQUICParitySync(peer, tc, latencyMS) {
			return true
		}
	}

	stateMu.RLock()
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	mSignPub := appCfg.MasterSigningPublicKey
	mNoisePub := appCfg.MasterNoiseStaticPublicKey
	aSignPub := appCfg.AgentSigningPublicKey
	aNoisePub := appCfg.AgentNoiseStaticPublicKey
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

	var conn net.Conn = rawConn
	if tc.ID != 6 {
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			return false
		}
		defer tlsConn.Close()
		conn = tlsConn
	}

	padLen := 32 + randomIntN(128)
	padHex, _ := randomHex(padLen)

	pkt := SyncPacket{
		Type:                       "parity_sync",
		SenderID:                   senderID,
		PeerID:                     peer.ID,
		MethodID:                   tc.ID,
		Port:                       tc.ListenPort,
		LatencyMS:                  latencyMS,
		ConfigVersion:              peer.ConfigVersion,
		CertPin:                    certPin,
		MasterSigningPublicKey:     mSignPub,
		MasterNoiseStaticPublicKey: mNoisePub,
		AgentSigningPublicKey:      aSignPub,
		AgentNoiseStaticPublicKey:  aNoisePub,
		Padding:                    padHex,
	}
	if role == "master" {
		now := time.Now()
		zName, zOff := now.Zone()
		pkt.MasterUnix = now.Unix()
		pkt.MasterTZName = zName
		pkt.MasterTZOff = zOff
		pkt.Tunnels = peer.Tunnels
	}
	rawPkt, _ := json.Marshal(pkt)
	b64 := base64.StdEncoding.EncodeToString(rawPkt)

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nX-Sahand-Peer: %s\r\nX-Sahand-Time: %s\r\nX-Sahand-Sync: %s\r\n\r\n",
		sni, peer.ID, buildMasterTimeHeader(), b64)
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}

	br := bufio.NewReader(conn)
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

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func applySyncResponseToPeer(peerID string, resp SyncResponse) {
	stateMu.Lock()
	if appCfg.Role == "agent" && resp.MasterUnix > 0 {
		appCfg.MasterClockDelta = resp.MasterUnix - time.Now().Unix()
		appCfg.MasterTZOffsetSec = resp.MasterTZOff
		if resp.MasterTZName != "" {
			appCfg.MasterTZName = resp.MasterTZName
		}
	}
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peerID {
			if appCfg.Role == "agent" && len(resp.Tunnels) == 30 && resp.ConfigVersion >= appCfg.Servers[i].ConfigVersion {
				appCfg.Servers[i].Tunnels = normalizeTunnels(resp.Tunnels)
				appCfg.Servers[i].ConfigVersion = resp.ConfigVersion
				go syncServerListeners(appCfg.Servers[i])
			}
			if resp.CertPin != "" {
				appCfg.Servers[i].RemoteCertPin = resp.CertPin
			}
			if _, err := decodeHexExact(resp.AgentNoiseStaticPublicKey, 32); err == nil {
				appCfg.Servers[i].AgentNoiseStaticPublicKey = strings.ToLower(strings.TrimSpace(resp.AgentNoiseStaticPublicKey))
			}
			if _, err := decodeHexExact(resp.AgentSigningPublicKey, 32); err == nil {
				appCfg.Servers[i].AgentSigningPublicKey = strings.ToLower(strings.TrimSpace(resp.AgentSigningPublicKey))
			}
			if _, err := decodeHexExact(resp.MasterNoiseStaticPublicKey, 32); err == nil && appCfg.Servers[i].MasterNoiseStaticPublicKey == "" {
				appCfg.Servers[i].MasterNoiseStaticPublicKey = strings.ToLower(strings.TrimSpace(resp.MasterNoiseStaticPublicKey))
			}
			appCfg.Servers[i].SyncState = "synced"
			_ = saveConfig(configPath(), appCfg)
			break
		}
	}
	stateMu.Unlock()
}

func sortedTunnelIndices(tunnels []TunnelConfig) []int {
	order := make([]int, len(tunnels))
	for i := range tunnels {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		if tunnels[order[i]].Security != tunnels[order[j]].Security {
			return tunnels[order[i]].Security > tunnels[order[j]].Security
		}
		return tunnels[order[i]].ID < tunnels[order[j]].ID
	})
	return order
}

func switchNextMethod(peerID string) (bool, string, error) {
	stateMu.RLock()
	localRole := appCfg.Role
	var peerSnapshot *ServerPeer
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peerID {
			cp := appCfg.Servers[i]
			peerSnapshot = &cp
			break
		}
	}
	stateMu.RUnlock()

	if peerSnapshot == nil {
		return false, "", errors.New("server not found")
	}

	tunnelsSnapshot := make([]TunnelConfig, len(peerSnapshot.Tunnels))
	copy(tunnelsSnapshot, peerSnapshot.Tunnels)
	order := sortedTunnelIndices(tunnelsSnapshot)

	startPos := 0
	if peerSnapshot.ActiveMethodID > 0 {
		for pos, idx := range order {
			if tunnelsSnapshot[idx].ID == peerSnapshot.ActiveMethodID {
				startPos = (pos + 1) % len(order)
				break
			}
		}
	}

	testedResults := make(map[int]MethodResult)
	var chosenCandidate *TunnelConfig
	var chosenResult MethodResult

	for step := 0; step < len(order); step++ {
		pos := (startPos + step) % len(order)
		tc := tunnelsSnapshot[order[pos]]

		if peerSnapshot.ActiveMethodID > 0 && tc.ID == peerSnapshot.ActiveMethodID {
			continue
		}
		if !tc.Implemented {
			continue
		}

		res := probeSingleMethod(*peerSnapshot, tc)
		testedResults[tc.ID] = res

		if res.Success {
			if pushParitySyncOverMethod(*peerSnapshot, tc, res.LatencyMS) {
				chosen := tc
				chosenCandidate = &chosen
				chosenResult = res
				break
			}
		}
		time.Sleep(time.Duration(70+randomIntN(90)) * time.Millisecond)
	}

	stateMu.Lock()
	var updatedPeer *ServerPeer
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peerID {
			updatedPeer = &appCfg.Servers[i]
			break
		}
	}
	if updatedPeer == nil {
		stateMu.Unlock()
		return false, "", errors.New("server not found")
	}

	for i := range updatedPeer.Tunnels {
		if r, ok := testedResults[updatedPeer.Tunnels[i].ID]; ok {
			updatedPeer.Tunnels[i].LastDiscovery = r
		}
	}

	if chosenCandidate != nil {
		initiator := formatConnectionInitiator(localRole, "outbound")
		updatedPeer.Running = true
		updatedPeer.Status = "CONNECTED"
		updatedPeer.ActiveMethodID = chosenCandidate.ID
		updatedPeer.ActiveMethod = chosenCandidate.Name
		updatedPeer.ActivePort = chosenCandidate.ListenPort
		updatedPeer.ActiveSecurity = chosenCandidate.Security
		updatedPeer.ActiveLatencyMS = chosenResult.LatencyMS
		updatedPeer.ActiveDirection = "outbound"
		updatedPeer.ActiveInitiator = initiator
		updatedPeer.NextRetryAt = ""
		updatedPeer.SyncState = "synced"
		recordLifelineEvent(updatedPeer, chosenCandidate.ID, chosenCandidate.Name, chosenCandidate.ListenPort, chosenCandidate.Security, chosenResult.LatencyMS, "outbound", initiator)
		_ = saveConfig(configPath(), appCfg)
		stateMu.Unlock()

		ensureLivenessMonitorRunning(peerID)
		msg := fmt.Sprintf("Switched to Method %02d (%s %d%%) on port %d",
			chosenCandidate.ID, chosenCandidate.Name, chosenCandidate.Security, chosenCandidate.ListenPort)
		return true, msg, nil
	}

	_ = saveConfig(configPath(), appCfg)
	curName := updatedPeer.ActiveMethod
	stateMu.Unlock()

	if curName != "" {
		return false, fmt.Sprintf("No other method responded; stayed on %s", curName), nil
	}
	return false, "No working method responded", nil
}

func ensureLivenessMonitorRunning(peerID string) {
	discoveryMu.Lock()
	_, exists := discoveryCancel[peerID]
	discoveryMu.Unlock()
	if !exists {
		startDiscoveryLoop(peerID)
	}
}

func isPeerAlreadyConnected(peerID string) bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peerID {
			return appCfg.Servers[i].Status == "CONNECTED" && appCfg.Servers[i].ActiveMethodID > 0
		}
	}
	return false
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
			localRole := appCfg.Role
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

			alreadyConnected := peer.Status == "CONNECTED" && peer.ActiveMethodID > 0
			if !alreadyConnected {
				peer.Status = "TESTING"
				peer.NextRetryAt = ""
			}
			peerSnapshot := *peer
			tunnelsSnapshot := make([]TunnelConfig, len(peer.Tunnels))
			copy(tunnelsSnapshot, peer.Tunnels)
			stateMu.Unlock()

			if !alreadyConnected {
				order := sortedTunnelIndices(tunnelsSnapshot)
				results := make(map[int]MethodResult, 30)
				var bestCandidate *TunnelConfig
				var bestResult MethodResult

				for _, idx := range order {
					select {
					case <-stopCh:
						return
					default:
					}
					if isPeerAlreadyConnected(peerID) {
						break
					}
					tc := tunnelsSnapshot[idx]
					res := probeSingleMethod(peerSnapshot, tc)
					results[tc.ID] = res

					if res.Success {
						chosen := tc
						bestCandidate = &chosen
						bestResult = res
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

				if updatedPeer.Status == "CONNECTED" && updatedPeer.ActiveMethodID > 0 && bestCandidate == nil {
					_ = saveConfig(configPath(), appCfg)
					stateMu.Unlock()
				} else if bestCandidate == nil {
					retryMins := 10 + randomIntN(21)
					retryDuration := time.Duration(retryMins) * time.Minute
					nextRetry := masterNow().Add(retryDuration)
					updatedPeer.Status = "RETRY SCHEDULED"
					updatedPeer.ActiveMethodID = 0
					updatedPeer.ActiveMethod = ""
					updatedPeer.ActivePort = 0
					updatedPeer.NextRetryAt = formatMasterClock(nextRetry)
					_ = saveConfig(configPath(), appCfg)
					stateMu.Unlock()

					retryTicker := time.NewTicker(5 * time.Second)
					deadline := time.Now().Add(retryDuration)
					for time.Now().Before(deadline) {
						select {
						case <-stopCh:
							retryTicker.Stop()
							return
						case <-retryTicker.C:
							if isPeerAlreadyConnected(peerID) {
								deadline = time.Now()
							}
						}
					}
					retryTicker.Stop()
					continue
				} else {
					initiator := formatConnectionInitiator(localRole, "outbound")
					updatedPeer.Status = "CONNECTED"
					updatedPeer.ActiveMethodID = bestCandidate.ID
					updatedPeer.ActiveMethod = bestCandidate.Name
					updatedPeer.ActivePort = bestCandidate.ListenPort
					updatedPeer.ActiveSecurity = bestCandidate.Security
					updatedPeer.ActiveLatencyMS = bestResult.LatencyMS
					updatedPeer.ActiveDirection = "outbound"
					updatedPeer.ActiveInitiator = initiator
					updatedPeer.NextRetryAt = ""
					recordLifelineEvent(updatedPeer, bestCandidate.ID, bestCandidate.Name, bestCandidate.ListenPort, bestCandidate.Security, bestResult.LatencyMS, "outbound", initiator)
					peerCopy := *updatedPeer
					_ = saveConfig(configPath(), appCfg)
					stateMu.Unlock()

					_ = pushParitySyncOverMethod(peerCopy, *bestCandidate, bestResult.LatencyMS)
					go syncServerListeners(peerCopy)
				}
			}

			// Silent jittered liveness monitor: keeps the active method locked as long as it works
			for {
				jitterWait := time.Duration(65+randomIntN(45)) * time.Second
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

				if curPeer.ActiveDirection == "inbound" && time.Now().Unix()-curPeer.LastInboundAt < 240 {
					continue
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
				if chk.Success {
					stateMu.Lock()
					for i := range appCfg.Servers {
						if appCfg.Servers[i].ID == peerID {
							appCfg.Servers[i].ActiveLatencyMS = chk.LatencyMS
							break
						}
					}
					stateMu.Unlock()
					continue
				}

				stateMu.Lock()
				stillInboundAlive := false
				for i := range appCfg.Servers {
					if appCfg.Servers[i].ID == peerID {
						if time.Now().Unix()-appCfg.Servers[i].LastInboundAt < 240 {
							stillInboundAlive = true
						} else {
							appCfg.Servers[i].Status = "TESTING"
							appCfg.Servers[i].ActiveMethodID = 0
							appCfg.Servers[i].ActiveMethod = ""
						}
						break
					}
				}
				stateMu.Unlock()
				if !stillInboundAlive {
					break
				}
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
