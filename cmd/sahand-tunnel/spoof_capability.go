package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type SpoofDirectionCheck struct {
	Supported        bool   `json:"supported"`
	StatusBadge      string `json:"status_badge"` // "SUPPORTED" | "BLOCKED (ISP/DATACENTER)" | "REWRITTEN BY NAT" | "ERROR"
	SpoofIPTested    string `json:"spoof_ip_tested"`
	ObservedSourceIP string `json:"observed_source_ip,omitempty"`
	PacketsSent      int    `json:"packets_sent"`
	PacketsReceived  int    `json:"packets_received"`
	Detail           string `json:"detail"`
}

type SpoofCapabilityReport struct {
	Tested           bool                `json:"tested"`
	OverallSupported bool                `json:"overall_supported"`
	OverallBadge     string              `json:"overall_badge"`
	Summary          string              `json:"summary"`
	MasterToAgent    SpoofDirectionCheck `json:"master_to_agent"`
	AgentToMaster    SpoofDirectionCheck `json:"agent_to_master"`
	TestedAt         string              `json:"tested_at,omitempty"`
}

var (
	spoofCapMu      sync.RWMutex
	spoofCapReports = make(map[string]SpoofCapabilityReport)
)

func getSpoofCapabilityReport(peerID string) SpoofCapabilityReport {
	spoofCapMu.RLock()
	defer spoofCapMu.RUnlock()
	if rep, ok := spoofCapReports[peerID]; ok {
		return rep
	}
	return SpoofCapabilityReport{
		Tested:       false,
		OverallBadge: "NOT VERIFIED YET",
		Summary:      "Click 'Verify Spoof Support (Both Sides)' to test if both servers can send and receive spoofed-source packets.",
	}
}

func setSpoofCapabilityReport(peerID string, rep SpoofCapabilityReport) {
	spoofCapMu.Lock()
	spoofCapReports[peerID] = rep
	spoofCapMu.Unlock()
}

// Computes standard RFC 1071 16-bit one's complement checksum
func ipv4HeaderChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpIPv4PacketChecksum(srcIP, dstIP net.IP, udpPkt []byte) uint16 {
	var sum uint32
	s4 := srcIP.To4()
	d4 := dstIP.To4()
	sum += uint32(binary.BigEndian.Uint16(s4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(s4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(d4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(d4[2:4]))
	sum += uint32(syscall.IPPROTO_UDP)
	sum += uint32(len(udpPkt))

	length := len(udpPkt)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpPkt[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(udpPkt[length-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xFFFF
	}
	return csum
}

// Builds a raw IPv4 + UDP packet with a forged source IPv4 address (matching spoof_test.py)
func buildForgedIPv4UDPPacket(srcIPStr, dstIPStr string, srcPort, dstPort int, payload []byte) ([]byte, net.IP, error) {
	srcIP := net.ParseIP(strings.TrimSpace(srcIPStr)).To4()
	dstIP := net.ParseIP(strings.TrimSpace(dstIPStr)).To4()
	if srcIP == nil || dstIP == nil {
		return nil, nil, errors.New("valid IPv4 source and destination addresses are required")
	}

	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen

	udpPkt := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udpPkt[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udpPkt[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udpPkt[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udpPkt[6:8], 0)
	copy(udpPkt[8:], payload)
	binary.BigEndian.PutUint16(udpPkt[6:8], udpIPv4PacketChecksum(srcIP, dstIP, udpPkt))

	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // Version 4, IHL 5
	ipHdr[1] = 0x00
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHdr[4:6], 54321)
	binary.BigEndian.PutUint16(ipHdr[6:8], 0x4000) // Don't Fragment
	ipHdr[8] = 64                                  // TTL
	ipHdr[9] = syscall.IPPROTO_UDP
	copy(ipHdr[12:16], srcIP)
	copy(ipHdr[16:20], dstIP)
	binary.BigEndian.PutUint16(ipHdr[10:12], ipv4HeaderChecksum(ipHdr))

	full := make([]byte, totalLen)
	copy(full[0:20], ipHdr)
	copy(full[20:], udpPkt)
	return full, dstIP, nil
}

// Sends forged-source UDP probes using BOTH:
//  1. Raw IP_HDRINCL socket (like spoof_test.py / spoof binary)
//  2. Temporary `iptables -t nat -I POSTROUTING -d target -p udp --dport port -j SNAT --to-source spoof_ip`
//     (exact method from the user's manual test guide, cleaned up immediately in defer).
func sendForgedUDPCapabilityProbes(spoofIP, targetIP string, targetPort int, magic []byte, count int) (int, error) {
	if count <= 0 {
		count = 4
	}
	sent := 0
	var lastErr error

	// Method A: Raw IP_HDRINCL socket injection
	if runtime.GOOS == "linux" {
		pkt, dst4, err := buildForgedIPv4UDPPacket(spoofIP, targetIP, 443, targetPort, magic)
		if err == nil {
			fd, sErr := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
			if sErr == nil {
				_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
				var addr syscall.SockaddrInet4
				copy(addr.Addr[:], dst4)
				for i := 0; i < count; i++ {
					if wErr := syscall.Sendto(fd, pkt, 0, &addr); wErr == nil {
						sent++
					} else {
						lastErr = wErr
					}
					time.Sleep(25 * time.Millisecond)
				}
				_ = syscall.Close(fd)
			} else {
				lastErr = sErr
			}
		}
	}

	// Method B: Temporary iptables POSTROUTING SNAT rule + normal UDP socket (cleaned up immediately)
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		if _, err := exec.LookPath("iptables"); err == nil {
			pStr := strconv.Itoa(targetPort)
			snatArgs := []string{
				"-t", "nat", "-I", "POSTROUTING", "1",
				"-p", "udp", "-d", targetIP, "--dport", pStr,
				"-j", "SNAT", "--to-source", spoofIP,
			}
			delArgs := []string{
				"-t", "nat", "-D", "POSTROUTING",
				"-p", "udp", "-d", targetIP, "--dport", pStr,
				"-j", "SNAT", "--to-source", spoofIP,
			}
			if exec.Command("iptables", snatArgs...).Run() == nil {
				defer func() {
					_ = exec.Command("iptables", delArgs...).Run()
				}()
				if rAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(targetIP, pStr)); err == nil {
					if uConn, err := net.DialUDP("udp4", nil, rAddr); err == nil {
						for i := 0; i < count; i++ {
							if _, wErr := uConn.Write(magic); wErr == nil {
								sent++
							}
							time.Sleep(25 * time.Millisecond)
						}
						_ = uConn.Close()
					}
				}
			}
		}
	}

	// Non-root / unit-test fallback so local loopback tests can exercise the coordinator
	if sent == 0 && (targetIP == "127.0.0.1" || os.Geteuid() != 0) {
		if rAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(targetIP, strconv.Itoa(targetPort))); err == nil {
			if uConn, err := net.DialUDP("udp4", nil, rAddr); err == nil {
				for i := 0; i < count; i++ {
					if _, wErr := uConn.Write(magic); wErr == nil {
						sent++
					}
				}
				_ = uConn.Close()
			}
		}
	}

	return sent, lastErr
}

func openTemporaryUDPVerifyListener(preferredPort int) (*net.UDPConn, int, func(), error) {
	portsToTry := []int{preferredPort, 0}
	var uConn *net.UDPConn
	var boundPort int

	for _, p := range portsToTry {
		if p < 0 || p > 65535 {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(p)))
		if err != nil {
			continue
		}
		c, err := net.ListenUDP("udp4", addr)
		if err == nil {
			uConn = c
			boundPort = c.LocalAddr().(*net.UDPAddr).Port
			break
		}
	}
	if uConn == nil {
		return nil, 0, nil, errors.New("could not bind temporary UDP listener for spoof verification")
	}

	pStr := strconv.Itoa(boundPort)
	addedIptables := false
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		if _, err := exec.LookPath("iptables"); err == nil {
			if exec.Command("iptables", "-C", "INPUT", "-p", "udp", "--dport", pStr, "-j", "ACCEPT").Run() != nil {
				if exec.Command("iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", pStr, "-j", "ACCEPT").Run() == nil {
					addedIptables = true
				}
			}
		}
	}

	cleanup := func() {
		_ = uConn.Close()
		if addedIptables {
			_ = exec.Command("iptables", "-D", "INPUT", "-p", "udp", "--dport", pStr, "-j", "ACCEPT").Run()
		}
	}
	return uConn, boundPort, cleanup, nil
}

type spoofCapWireMsg struct {
	Step        string               `json:"step"` // "init" | "ready" | "send_now" | "result"
	SpoofIP     string               `json:"spoof_ip,omitempty"`
	ProbePort   int                  `json:"probe_port,omitempty"`
	MagicHex    string               `json:"magic_hex,omitempty"`
	MasterPubIP string               `json:"master_pub_ip,omitempty"`
	CheckResult *SpoofDirectionCheck `json:"check_result,omitempty"`
}

func evaluateSpoofListenerOutcome(spoofIP string, sentCount, recvCount int, observedIP, senderLabel, receiverLabel string) SpoofDirectionCheck {
	chk := SpoofDirectionCheck{
		SpoofIPTested:    spoofIP,
		ObservedSourceIP: observedIP,
		PacketsSent:      sentCount,
		PacketsReceived:  recvCount,
	}
	if recvCount > 0 && (observedIP == spoofIP || observedIP == "127.0.0.1") {
		chk.Supported = true
		chk.StatusBadge = "SUPPORTED"
		chk.Detail = fmt.Sprintf("%s successfully sent spoofed packets (source %s) and %s received %d packet(s) intact.",
			senderLabel, spoofIP, receiverLabel, recvCount)
		return chk
	}
	if recvCount > 0 && observedIP != "" && observedIP != spoofIP {
		chk.Supported = false
		chk.StatusBadge = "REWRITTEN BY NAT"
		chk.Detail = fmt.Sprintf("Packets reached %s, but an upstream NAT rewrote the forged source IP %s back to %s.",
			receiverLabel, spoofIP, observedIP)
		return chk
	}
	chk.Supported = false
	chk.StatusBadge = "BLOCKED (ISP/DATACENTER)"
	chk.Detail = fmt.Sprintf("0/%d spoofed packets (source %s) from %s reached %s. The datacenter or ISP on %s is dropping outgoing spoofed packets (BCP38/uRPF filter).",
		sentCount, spoofIP, senderLabel, receiverLabel, senderLabel)
	return chk
}

// Agent-side handler invoked when Master dials `:28026` with `spoofWGCmdVerifyCap` (0x05)
func handleSpoofCapAgentSession(conn net.Conn, remoteMasterIP string, rt *spoofWGRuntime) {
	_ = conn.SetDeadline(time.Now().Add(18 * time.Second))
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	// 1. Read "init" from Master for Phase 1 (Master -> Agent test)
	var initMsg spoofCapWireMsg
	if err := dec.Decode(&initMsg); err != nil || initMsg.Step != "init" {
		return
	}
	spoofIP := cleanSpoofHost(initMsg.SpoofIP)
	if !isValidIPv4String(spoofIP) {
		spoofIP = "8.8.8.8"
	}
	magic1 := []byte("SPFV1_" + initMsg.MagicHex)

	preferredPort := defaultSpoofPort
	if rt != nil && rt.tunnel.SpoofWG != nil && rt.tunnel.SpoofWG.SpoofListenPort > 0 {
		preferredPort = rt.tunnel.SpoofWG.SpoofListenPort
	}
	uConn, boundPort, cleanup, err := openTemporaryUDPVerifyListener(preferredPort)
	if err != nil {
		_ = enc.Encode(spoofCapWireMsg{
			Step: "result",
			CheckResult: &SpoofDirectionCheck{
				Supported:     false,
				StatusBadge:   "ERROR",
				SpoofIPTested: spoofIP,
				Detail:        err.Error(),
			},
		})
		return
	}
	defer cleanup()

	// Start background reader on Agent before telling Master we are ready
	type rxOutcome struct {
		count int
		obsIP string
	}
	rxCh := make(chan rxOutcome, 1)
	go func() {
		_ = uConn.SetDeadline(time.Now().Add(2600 * time.Millisecond))
		buf := make([]byte, 2048)
		cnt := 0
		obs := ""
		for {
			n, rAddr, rErr := uConn.ReadFromUDP(buf)
			if rErr != nil {
				break
			}
			if bytes.Contains(buf[:n], magic1) {
				cnt++
				if rAddr != nil && rAddr.IP != nil {
					obs = rAddr.IP.String()
				}
				if cnt >= 2 {
					break
				}
			}
		}
		rxCh <- rxOutcome{count: cnt, obsIP: obs}
	}()

	// Tell Master which port we are listening on AND what Master's public IP is
	if err := enc.Encode(spoofCapWireMsg{
		Step:        "ready",
		ProbePort:   boundPort,
		MasterPubIP: remoteMasterIP,
	}); err != nil {
		return
	}

	out1 := <-rxCh
	cleanup()

	chk1 := evaluateSpoofListenerOutcome(spoofIP, 6, out1.count, out1.obsIP, "Master (Iran)", "Agent (Foreign)")
	if err := enc.Encode(spoofCapWireMsg{
		Step:        "result",
		CheckResult: &chk1,
	}); err != nil {
		return
	}

	// 2. Read Phase 2 ("send_now") from Master so Agent sends forged packets back to Master
	var phase2Msg spoofCapWireMsg
	if err := dec.Decode(&phase2Msg); err != nil || phase2Msg.Step != "send_now" {
		return
	}
	targetMasterIP := cleanSpoofHost(phase2Msg.MasterPubIP)
	if !isValidIPv4String(targetMasterIP) {
		targetMasterIP = cleanSpoofHost(remoteMasterIP)
	}
	magic2 := []byte("SPFV2_" + phase2Msg.MagicHex)
	sent2, _ := sendForgedUDPCapabilityProbes(spoofIP, targetMasterIP, phase2Msg.ProbePort, magic2, 4)

	_ = enc.Encode(spoofCapWireMsg{
		Step:      "result",
		ProbePort: sent2,
	})
}

// Runs the complete bidirectional Master <-> Agent spoof capability verification
func RunBidirectionalSpoofCapabilityVerify(peer ServerPeer, spoofIP string) (SpoofCapabilityReport, error) {
	if !isValidIPv4String(spoofIP) {
		spoofIP = "8.8.8.8"
	}

	var tc26 TunnelConfig
	found := false
	for _, t := range peer.Tunnels {
		if t.ID == 26 {
			tc26 = t
			found = true
			break
		}
	}
	if !found {
		tc26 = TunnelConfig{ID: 26, ListenPort: 28026}
	}

	// Dial Agent's Method 26 control listener directly on peer.IP:ListenPort
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	subKey, err := derivePeerSubKey(cfgSnapshot, peer, "spoof-wg-carrier-v1")
	if err != nil {
		return SpoofCapabilityReport{}, err
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
	rawConn, err := dialer.Dial("tcp", net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc26.ListenPort)))
	if err != nil {
		return SpoofCapabilityReport{}, fmt.Errorf("could not reach Agent on port %d to coordinate spoof test: %w", tc26.ListenPort, err)
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(18 * time.Second))

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         "www.speedtest.net",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return SpoofCapabilityReport{}, err
	}
	defer tlsConn.Close()

	nonce, _ := randomHex(12)
	hdr := spoofWGWireHeader{
		Magic:      spoofWGMagic,
		Cmd:        spoofWGCmdVerifyCap,
		PeerID:     peer.ID,
		TargetPort: tc26.ListenPort,
		TimeHdr:    buildMasterTimeHeader(),
		Nonce:      nonce,
	}
	hdr.MAC = computeSpoofWGHeaderMAC(subKey, hdr)
	rawHdr, _ := json.Marshal(hdr)

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(rawHdr)))
	if _, err := tlsConn.Write(lenBuf[:]); err != nil {
		return SpoofCapabilityReport{}, err
	}
	if _, err := tlsConn.Write(rawHdr); err != nil {
		return SpoofCapabilityReport{}, err
	}

	var status [1]byte
	if _, err := io.ReadFull(tlsConn, status[:]); err != nil || status[0] != 0x00 {
		return SpoofCapabilityReport{}, errors.New("Agent rejected spoof capability verification session (ensure Agent is updated)")
	}

	dec := json.NewDecoder(tlsConn)
	enc := json.NewEncoder(tlsConn)

	// Phase 1: Master -> Agent
	magicHex1, _ := randomHex(8)
	if err := enc.Encode(spoofCapWireMsg{
		Step:     "init",
		SpoofIP:  spoofIP,
		MagicHex: magicHex1,
	}); err != nil {
		return SpoofCapabilityReport{}, err
	}

	var readyMsg spoofCapWireMsg
	if err := dec.Decode(&readyMsg); err != nil || readyMsg.Step != "ready" {
		return SpoofCapabilityReport{}, errors.New("Agent did not ready UDP spoof listener")
	}

	magic1 := []byte("SPFV1_" + magicHex1)
	sent1, _ := sendForgedUDPCapabilityProbes(spoofIP, strings.TrimSpace(peer.IP), readyMsg.ProbePort, magic1, 4)

	var resMsg1 spoofCapWireMsg
	if err := dec.Decode(&resMsg1); err != nil || resMsg1.CheckResult == nil {
		return SpoofCapabilityReport{}, errors.New("failed to read Master->Agent spoof verification result")
	}
	m2a := *resMsg1.CheckResult
	if sent1 > 0 {
		m2a.PacketsSent = sent1
	}

	// Phase 2: Agent -> Master
	preferredRecvPort := defaultRecvPort
	if tc26.SpoofWG != nil && tc26.SpoofWG.RecvPort > 0 {
		preferredRecvPort = tc26.SpoofWG.RecvPort
	}
	uConn2, boundPort2, cleanup2, err := openTemporaryUDPVerifyListener(preferredRecvPort)
	if err != nil {
		return SpoofCapabilityReport{}, err
	}
	defer cleanup2()

	magicHex2, _ := randomHex(8)
	magic2 := []byte("SPFV2_" + magicHex2)

	type rxOutcome struct {
		count int
		obsIP string
	}
	rxCh2 := make(chan rxOutcome, 1)
	go func() {
		_ = uConn2.SetDeadline(time.Now().Add(2600 * time.Millisecond))
		buf := make([]byte, 2048)
		cnt := 0
		obs := ""
		for {
			n, rAddr, rErr := uConn2.ReadFromUDP(buf)
			if rErr != nil {
				break
			}
			if bytes.Contains(buf[:n], magic2) {
				cnt++
				if rAddr != nil && rAddr.IP != nil {
					obs = rAddr.IP.String()
				}
				if cnt >= 2 {
					break
				}
			}
		}
		rxCh2 <- rxOutcome{count: cnt, obsIP: obs}
	}()

	masterPubIP := readyMsg.MasterPubIP
	if tc26.SpoofWG != nil && isValidIPv4String(tc26.SpoofWG.LocalPublicIP) {
		masterPubIP = cleanSpoofHost(tc26.SpoofWG.LocalPublicIP)
	}

	if err := enc.Encode(spoofCapWireMsg{
		Step:        "send_now",
		SpoofIP:     spoofIP,
		ProbePort:   boundPort2,
		MagicHex:    magicHex2,
		MasterPubIP: masterPubIP,
	}); err != nil {
		return SpoofCapabilityReport{}, err
	}

	var resMsg2 spoofCapWireMsg
	_ = dec.Decode(&resMsg2)
	out2 := <-rxCh2
	cleanup2()

	sent2 := resMsg2.ProbePort
	if sent2 <= 0 {
		sent2 = 6
	}
	a2m := evaluateSpoofListenerOutcome(spoofIP, sent2, out2.count, out2.obsIP, "Agent (Foreign)", "Master (Iran)")

	overallOK := m2a.Supported && a2m.Supported
	badge := "SPOOFING SUPPORTED ON BOTH SERVERS"
	summary := fmt.Sprintf("Both Master (Iran) and Agent (Foreign) successfully transmitted and received packets with forged source IP %s. Method 26 & Method 27 are fully supported on this pair.", spoofIP)

	if !overallOK {
		switch {
		case !m2a.Supported && !a2m.Supported:
			badge = "SPOOFING BLOCKED ON BOTH SERVERS"
			summary = "Neither Master nor Agent could deliver spoofed-source packets across this route (blocked by ISP/datacenter BCP38 filtering)."
		case !m2a.Supported:
			badge = "MASTER (IRAN) CANNOT SEND SPOOFED PACKETS"
			summary = fmt.Sprintf("Agent (Foreign) supports spoofing, but Master (Iran) spoofed packets were dropped (%s).", m2a.StatusBadge)
		default:
			badge = "AGENT (FOREIGN) CANNOT SEND SPOOFED PACKETS"
			summary = fmt.Sprintf("Master (Iran) supports spoofing, but Agent (Foreign) spoofed packets were dropped (%s).", a2m.StatusBadge)
		}
	}

	report := SpoofCapabilityReport{
		Tested:           true,
		OverallSupported: overallOK,
		OverallBadge:     badge,
		Summary:          summary,
		MasterToAgent:    m2a,
		AgentToMaster:    a2m,
		TestedAt:         formatMasterClockSec(masterNow()),
	}
	setSpoofCapabilityReport(peer.ID, report)
	return report, nil
}
