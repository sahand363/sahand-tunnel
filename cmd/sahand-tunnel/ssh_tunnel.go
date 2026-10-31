package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	sshServerVersionString = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
	sshClientVersionString = "SSH-2.0-OpenSSH_9.6p1"

	sshChannelDirectTCPIP = "direct-tcpip"
	sshChannelParitySync  = "sahand-parity-sync"
	sshReqProbe           = "sahand-probe@sahand.tunnel"
	sshReqKeepalive       = "keepalive@openssh.com"
)

// RFC 4254 Section 7.2 direct-tcpip channel open payload
type sshDirectTCPIPMsg struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type sshProbePayload struct {
	PeerID  string `json:"pid"`
	NodeID  string `json:"nid"`
	TimeHdr string `json:"tm,omitempty"`
	Seq     uint32 `json:"seq"`
	SentAt  int64  `json:"ts"`
}

func deriveSSHSigner(authKey []byte, roleDomain string) (ssh.Signer, error) {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("sahand-ssh-ed25519-v1:" + roleDomain))
	seed := mac.Sum(nil)[:ed25519.SeedSize]
	privKey := ed25519.NewKeyFromSeed(seed)
	return ssh.NewSignerFromKey(privKey)
}

// ============================================================================
// 1. PERSISTENT MULTIPLEXED SSH CLIENT POOL (ControlMaster Style)
// ============================================================================

type sshManagedClient struct {
	mu         sync.Mutex
	peerID     string
	endpoint   string
	configHash string
	rawConn    net.Conn
	client     *ssh.Client
	stopCh     chan struct{}
	closed     bool
}

var (
	sshPoolMu     sync.Mutex
	sshClientPool = make(map[string]*sshManagedClient)
)

func stopSSHTunnelPeerResources(peerID string) {
	sshPoolMu.Lock()
	if mc, ok := sshClientPool[peerID]; ok {
		mc.close()
		delete(sshClientPool, peerID)
	}
	sshPoolMu.Unlock()
}

func (mc *sshManagedClient) close() {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.closeLocked()
}

func (mc *sshManagedClient) closeLocked() {
	if mc.closed {
		return
	}
	mc.closed = true
	if mc.stopCh != nil {
		close(mc.stopCh)
		mc.stopCh = nil
	}
	if mc.client != nil {
		_ = mc.client.Close()
		mc.client = nil
	}
	if mc.rawConn != nil {
		_ = mc.rawConn.Close()
		mc.rawConn = nil
	}
}

func getOrDialSSHClient(peer ServerPeer, tc TunnelConfig, timeout time.Duration) (*ssh.Client, *sshManagedClient, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return nil, nil, err
	}

	endpoint := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))
	cfgHash := fmt.Sprintf("%s|hb:%d", endpoint, tc.HeartbeatSec)

	sshPoolMu.Lock()
	mc, exists := sshClientPool[peer.ID]
	if !exists || mc.configHash != cfgHash {
		if exists {
			mc.close()
		}
		mc = &sshManagedClient{
			peerID:     peer.ID,
			endpoint:   endpoint,
			configHash: cfgHash,
		}
		sshClientPool[peer.ID] = mc
	}
	sshPoolMu.Unlock()

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.client != nil && !mc.closed {
		return mc.client, mc, nil
	}

	mc.closeLocked()
	mc.closed = false

	clientSigner, err := deriveSSHSigner(authKey, "ssh-client-key")
	if err != nil {
		return nil, nil, err
	}
	hostSigner, err := deriveSSHSigner(authKey, "ssh-host-key")
	if err != nil {
		return nil, nil, err
	}

	sshCfg := &ssh.ClientConfig{
		User:          peer.ID,
		ClientVersion: sshClientVersionString,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientSigner),
		},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
		Timeout:         timeout,
	}

	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.Dial("tcp", endpoint)
	if err != nil {
		return nil, nil, err
	}
	enableKeepAlive(rawConn)
	_ = rawConn.SetDeadline(time.Now().Add(timeout + 2*time.Second))

	c, chans, reqs, err := ssh.NewClientConn(rawConn, endpoint, sshCfg)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	_ = rawConn.SetDeadline(time.Time{})

	client := ssh.NewClient(c, chans, reqs)
	stopCh := make(chan struct{})
	mc.rawConn = rawConn
	mc.client = client
	mc.stopCh = stopCh

	hbSec := tc.HeartbeatSec
	if hbSec <= 0 {
		hbSec = 25
	}
	go func(cli *ssh.Client, done <-chan struct{}, wrapper *sshManagedClient) {
		ticker := time.NewTicker(time.Duration(hbSec) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				_, _, kErr := cli.SendRequest(sshReqKeepalive, true, nil)
				if kErr != nil {
					wrapper.close()
					return
				}
			}
		}
	}(client, stopCh, mc)

	return client, mc, nil
}

// ============================================================================
// 2. SSH SERVER LISTENER (:11313) & RFC 4254 CHANNEL HANDLERS
// ============================================================================

func startSSHTunnelServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			enableKeepAlive(rawConn)
			go handleIncomingSSHTunnelConn(rawConn, peer, tc)
		}
	}()
	return ln, nil
}

func handleIncomingSSHTunnelConn(rawConn net.Conn, peer ServerPeer, tc TunnelConfig) {
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(12 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return
	}

	hostSigner, err := deriveSSHSigner(authKey, "ssh-host-key")
	if err != nil {
		return
	}
	expectedClientSigner, err := deriveSSHSigner(authKey, "ssh-client-key")
	if err != nil {
		return
	}
	expectedPubBytes := expectedClientSigner.PublicKey().Marshal()

	srvCfg := &ssh.ServerConfig{
		ServerVersion: sshServerVersionString,
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if subtle.ConstantTimeCompare(pubKey.Marshal(), expectedPubBytes) != 1 {
				return nil, errors.New("ssh client public key mismatch")
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"peer_id": conn.User(),
				},
			}, nil
		},
	}
	srvCfg.AddHostKey(hostSigner)

	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, srvCfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	_ = rawConn.SetDeadline(time.Time{})

	remoteHost, _, _ := net.SplitHostPort(rawConn.RemoteAddr().String())
	effectivePeerID := peer.ID
	if sshConn.Permissions != nil && sshConn.Permissions.Extensions["peer_id"] != "" {
		effectivePeerID = sshConn.Permissions.Extensions["peer_id"]
	}

	// Handle Global Requests (Engine 1 Probes & OpenSSH Keepalives)
	go func() {
		for req := range reqs {
			switch req.Type {
			case sshReqKeepalive:
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			case sshReqProbe:
				var probePkt sshProbePayload
				if json.Unmarshal(req.Payload, &probePkt) == nil {
					if probePkt.TimeHdr != "" {
						applyMasterTimeHeader(probePkt.TimeHdr)
					}
					if probePkt.PeerID != "" {
						effectivePeerID = probePkt.PeerID
					}
				}
				markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)
				if req.WantReply {
					_ = req.Reply(true, req.Payload)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()

	// Handle Multiplexed Channels (Engine 1 Parity Sync & Engine 2 direct-tcpip)
	for newChan := range chans {
		switch newChan.ChannelType() {
		case sshChannelParitySync:
			ch, chanReqs, err := newChan.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(chanReqs)
			go handleSSHTunnelParitySyncChannel(ch, effectivePeerID, remoteHost)

		case sshChannelDirectTCPIP:
			if !tc.Enabled {
				_ = newChan.Reject(ssh.Prohibited, "traffic tunnel disabled")
				continue
			}
			var msg sshDirectTCPIPMsg
			if err := ssh.Unmarshal(newChan.ExtraData(), &msg); err != nil {
				_ = newChan.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
				continue
			}
			go handleSSHDirectTCPIPChannel(newChan, tc, msg.DestPort)

		default:
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

func handleSSHDirectTCPIPChannel(newChan ssh.NewChannel, tc TunnelConfig, destPort uint32) {
	targetPortStr := strconv.Itoa(int(destPort))
	if destPort == 0 {
		ports := parsePortList(tc.ForwardPorts)
		if len(ports) > 0 {
			targetPortStr = ports[0]
		} else {
			targetPortStr = "2053"
		}
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", targetPortStr), 5*time.Second)
	if err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "target port unreachable")
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	ch, chanReqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(chanReqs)

	pipeSSHChannelAndTCP(ch, target, tc.SpeedLimitMBps)
}

// ============================================================================
// 3. ENGINE 1: PROBE & PARITY SYNC OVER SSH-2
// ============================================================================

func probeSSHTunnel(peer ServerPeer, tc TunnelConfig, localNodeID string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	client, mc, err := getOrDialSSHClient(peer, tc, 4*time.Second)
	if err != nil {
		res.Success = false
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(msg, "unable to authenticate") || strings.Contains(msg, "key") {
			res.ErrorReason = "Authentication failure"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}

	probePkt := sshProbePayload{
		PeerID:  peer.ID,
		NodeID:  localNodeID,
		TimeHdr: buildMasterTimeHeader(),
		Seq:     1,
		SentAt:  time.Now().UnixNano(),
	}
	rawProbe, _ := json.Marshal(probePkt)

	pingStart := time.Now()
	ok, replyBytes, err := client.SendRequest(sshReqProbe, true, rawProbe)
	if err != nil || !ok || !bytes.Equal(replyBytes, rawProbe) {
		mc.close()
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	rtt := time.Since(pingStart).Milliseconds()
	if rtt <= 0 {
		rtt = time.Since(start).Milliseconds()
	}
	if rtt <= 0 {
		rtt = 1
	}
	res.Success = true
	res.LatencyMS = rtt
	res.MinLatencyMS = rtt
	res.MaxLatencyMS = rtt
	return res
}

func pushSSHTunnelParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	client, mc, err := getOrDialSSHClient(peer, tc, 4*time.Second)
	if err != nil {
		return false
	}

	ch, reqs, err := client.OpenChannel(sshChannelParitySync, nil)
	if err != nil {
		mc.close()
		return false
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	stateMu.RLock()
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	stateMu.RUnlock()

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
		now := time.Now()
		zName, zOff := now.Zone()
		pkt.MasterUnix = now.Unix()
		pkt.MasterTZName = zName
		pkt.MasterTZOff = zOff
		pkt.Tunnels = peer.Tunnels
	}

	rawPkt, err := json.Marshal(pkt)
	if err != nil {
		return false
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(rawPkt)))
	if _, err := ch.Write(lenBuf[:]); err != nil {
		mc.close()
		return false
	}
	if _, err := ch.Write(rawPkt); err != nil {
		mc.close()
		return false
	}

	if _, err := io.ReadFull(ch, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(ch, respBytes); err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func handleSSHTunnelParitySyncChannel(ch ssh.Channel, effectivePeerID, remoteHost string) {
	defer ch.Close()

	var lenBuf [4]byte
	if _, err := io.ReadFull(ch, lenBuf[:]); err != nil {
		return
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen == 0 || pktLen > 256*1024 {
		return
	}
	rawPkt := make([]byte, pktLen)
	if _, err := io.ReadFull(ch, rawPkt); err != nil {
		return
	}
	var pkt SyncPacket
	if json.Unmarshal(rawPkt, &pkt) != nil {
		return
	}

	resp := processIncomingSync(effectivePeerID, remoteHost, pkt)
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return
	}
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(respBytes)))
	_, _ = ch.Write(lenBuf[:])
	_, _ = ch.Write(respBytes)
}

// ============================================================================
// 4. ENGINE 2: BIDIRECTIONAL TCP FORWARDING VIA SSH direct-tcpip CHANNELS
// ============================================================================

func forwardSSHTunnelTraffic(clientConn net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer clientConn.Close()

	portNum, _ := strconv.Atoi(strings.TrimSpace(targetPort))
	if portNum <= 0 {
		portNum = 2053
	}

	sshClient, mc, err := getOrDialSSHClient(peer, tc, 5*time.Second)
	if err != nil {
		return
	}

	origHost, origPortStr, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
	origPort, _ := strconv.Atoi(origPortStr)
	if origHost == "" {
		origHost = "127.0.0.1"
	}

	openMsg := sshDirectTCPIPMsg{
		DestAddr:   "127.0.0.1",
		DestPort:   uint32(portNum),
		OriginAddr: origHost,
		OriginPort: uint32(origPort),
	}

	ch, reqs, err := sshClient.OpenChannel(sshChannelDirectTCPIP, ssh.Marshal(&openMsg))
	if err != nil {
		mc.close()
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	pipeSSHChannelAndTCP(ch, clientConn, tc.SpeedLimitMBps)
}

func pipeSSHChannelAndTCP(sshChan ssh.Channel, tcpConn net.Conn, speedLimitMBps string) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	toSSH := newThrottledWriter(sshChan, &appTxBytes, mbLimit)
	toTCP := newThrottledWriter(tcpConn, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toSSH, tcpConn, buf)
		_ = sshChan.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toTCP, sshChan, buf)
		if tc, ok := tcpConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}
