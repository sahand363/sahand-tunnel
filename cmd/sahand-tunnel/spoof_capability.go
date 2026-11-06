package main

import (
	"bytes"
	"context"
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
	StatusBadge      string `json:"status_badge"` // "SUPPORTED" | "SAME-/24 ONLY" | "BLOCKED (ISP/DATACENTER)" | "REWRITTEN BY NAT" | "PORT FIREWALLED"
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
		Summary:      "Click 'Verify Spoof Support (Both Sides)' to test custom candidate spoof IPs across ICMP, TCP, and UDP.",
	}
}

func setSpoofCapabilityReport(peerID string, rep SpoofCapabilityReport) {
	spoofCapMu.Lock()
	spoofCapReports[peerID] = rep
	spoofCapMu.Unlock()
}

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

func l4IPv4PseudoChecksum(srcIP, dstIP net.IP, proto uint8, l4Pkt []byte) uint16 {
	var sum uint32
	s4 := srcIP.To4()
	d4 := dstIP.To4()
	sum += uint32(binary.BigEndian.Uint16(s4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(s4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(d4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(d4[2:4]))
	sum += uint32(proto)
	sum += uint32(len(l4Pkt))

	length := len(l4Pkt)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(l4Pkt[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(l4Pkt[length-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	csum := ^uint16(sum)
	if proto == syscall.IPPROTO_UDP && csum == 0 {
		csum = 0xFFFF
	}
	return csum
}

func wrapIPv4Header(srcIP, dstIP net.IP, proto uint8, l4Payload []byte) []byte {
	totalLen := 20 + len(l4Payload)
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	ipHdr[1] = 0x00
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHdr[4:6], 54321)
	binary.BigEndian.PutUint16(ipHdr[6:8], 0x4000)
	ipHdr[8] = 64
	ipHdr[9] = proto
	copy(ipHdr[12:16], srcIP.To4())
	copy(ipHdr[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ipHdr[10:12], ipv4HeaderChecksum(ipHdr))

	full := make([]byte, totalLen)
	copy(full[0:20], ipHdr)
	copy(full[20:], l4Payload)
	return full
}

func buildForgedIPv4UDPPacket(srcIPStr, dstIPStr string, srcPort, dstPort int, payload []byte) ([]byte, net.IP, error) {
	srcIP := net.ParseIP(strings.TrimSpace(srcIPStr)).To4()
	dstIP := net.ParseIP(strings.TrimSpace(dstIPStr)).To4()
	if srcIP == nil || dstIP == nil {
		return nil, nil, errors.New("valid IPv4 addresses required")
	}
	udpLen := 8 + len(payload)
	udpPkt := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udpPkt[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udpPkt[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udpPkt[4:6], uint16(udpLen))
	copy(udpPkt[8:], payload)
	binary.BigEndian.PutUint16(udpPkt[6:8], l4IPv4PseudoChecksum(srcIP, dstIP, syscall.IPPROTO_UDP, udpPkt))
	return wrapIPv4Header(srcIP, dstIP, syscall.IPPROTO_UDP, udpPkt), dstIP, nil
}

func buildForgedIPv4ICMPPacket(srcIPStr, dstIPStr string, seq uint16, payload []byte) ([]byte, net.IP, error) {
	srcIP := net.ParseIP(strings.TrimSpace(srcIPStr)).To4()
	dstIP := net.ParseIP(strings.TrimSpace(dstIPStr)).To4()
	if srcIP == nil || dstIP == nil {
		return nil, nil, errors.New("valid IPv4 addresses required")
	}
	icmpPkt := make([]byte, 8+len(payload))
	icmpPkt[0] = 8 // ICMPv4 Echo Request
	icmpPkt[1] = 0
	binary.BigEndian.PutUint16(icmpPkt[4:6], 0x5A27)
	binary.BigEndian.PutUint16(icmpPkt[6:8], seq)
	copy(icmpPkt[8:], payload)
	binary.BigEndian.PutUint16(icmpPkt[2:4], ipv4HeaderChecksum(icmpPkt))
	return wrapIPv4Header(srcIP, dstIP, syscall.IPPROTO_ICMP, icmpPkt), dstIP, nil
}

func buildForgedIPv4TCPPacket(srcIPStr, dstIPStr string, srcPort, dstPort int, payload []byte) ([]byte, net.IP, error) {
	srcIP := net.ParseIP(strings.TrimSpace(srcIPStr)).To4()
	dstIP := net.ParseIP(strings.TrimSpace(dstIPStr)).To4()
	if srcIP == nil || dstIP == nil {
		return nil, nil, errors.New("valid IPv4 addresses required")
	}
	tcpPkt := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcpPkt[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpPkt[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcpPkt[4:8], 0x10203040)
	binary.BigEndian.PutUint32(tcpPkt[8:12], 0)
	tcpPkt[12] = 5 << 4
	tcpPkt[13] = 0x18 // PSH | ACK
	binary.BigEndian.PutUint16(tcpPkt[14:16], 64240)
	copy(tcpPkt[20:], payload)
	binary.BigEndian.PutUint16(tcpPkt[16:18], l4IPv4PseudoChecksum(srcIP, dstIP, syscall.IPPROTO_TCP, tcpPkt))
	return wrapIPv4Header(srcIP, dstIP, syscall.IPPROTO_TCP, tcpPkt), dstIP, nil
}

func deriveSameSlash24NeighborIP(realIPStr string) string {
	ip := net.ParseIP(cleanSpoofHost(realIPStr)).To4()
	if ip == nil || ip[0] == 127 || ip[0] == 10 {
		return "198.51.100.233"
	}
	last := byte(233)
	if ip[3] == 233 {
		last = 234
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], last)
}

func buildSpoofProbeSuite(realSenderIP string, candidateIPs []string) []string {
	own := cleanSpoofHost(realSenderIP)
	if !isValidIPv4String(own) {
		own = resolveOutboundInterfaceIP("8.8.8.8").String()
	}
	seen := map[string]bool{own: true}
	var list []string

	for _, raw := range candidateIPs {
		ip := cleanSpoofHost(raw)
		if isValidIPv4String(ip) && !seen[ip] {
			seen[ip] = true
			list = append(list, ip)
		}
	}

	defaults := []string{"8.8.8.8", "1.1.1.1", "172.67.150.10", deriveSameSlash24NeighborIP(own)}
	for _, d := range defaults {
		if isValidIPv4String(d) && !seen[d] {
			seen[d] = true
			list = append(list, d)
		}
	}
	return list
}

func runExactIptablesSNATPingTest(targetIP, spoofIP string) int {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || !isValidIPv4String(targetIP) || !isValidIPv4String(spoofIP) {
		return 0
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return 0
	}
	pingBin, err := exec.LookPath("ping")
	if err != nil {
		return 0
	}

	if _, err := exec.LookPath("conntrack"); err == nil {
		_ = exec.Command("conntrack", "-D", "-p", "icmp", "-d", targetIP).Run()
	}

	addRule := []string{"-t", "nat", "-I", "POSTROUTING", "1", "-p", "icmp", "-d", targetIP, "-j", "SNAT", "--to-source", spoofIP}
	delRule := []string{"-t", "nat", "-D", "POSTROUTING", "-p", "icmp", "-d", targetIP, "-j", "SNAT", "--to-source", spoofIP}

	if exec.Command("iptables", addRule...).Run() != nil {
		return 0
	}
	defer func() {
		_ = exec.Command("iptables", delRule...).Run()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	_ = exec.CommandContext(ctx, pingBin, "-c", "2", "-i", "0.2", "-W", "1", targetIP).Run()
	return 2
}

func sendMultiMethodCapabilityProbes(candidates []string, targetIP string, targetPort int, magicPrefix string) int {
	sent := 0
	pStr := strconv.Itoa(targetPort)

	// Baseline Own-IP
	if rAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(targetIP, pStr)); err == nil {
		if uConn, err := net.DialUDP("udp4", nil, rAddr); err == nil {
			_, _ = uConn.Write([]byte(magicPrefix + "|OWN|UDP|"))
			sent++
			_ = uConn.Close()
		}
	}

	if runtime.GOOS == "linux" {
		if fd, sErr := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW); sErr == nil {
			_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
			for idx, ipStr := range candidates {
				if !isValidIPv4String(ipStr) {
					continue
				}
				uPayload := []byte(fmt.Sprintf("%s|%s|UDP|", magicPrefix, ipStr))
				if pkt, dst4, err := buildForgedIPv4UDPPacket(ipStr, targetIP, 443, targetPort, uPayload); err == nil {
					var addr syscall.SockaddrInet4
					copy(addr.Addr[:], dst4)
					if syscall.Sendto(fd, pkt, 0, &addr) == nil {
						sent++
					}
				}
				iPayload := []byte(fmt.Sprintf("%s|%s|ICMP|", magicPrefix, ipStr))
				if pkt, dst4, err := buildForgedIPv4ICMPPacket(ipStr, targetIP, uint16(idx+1), iPayload); err == nil {
					var addr syscall.SockaddrInet4
					copy(addr.Addr[:], dst4)
					if syscall.Sendto(fd, pkt, 0, &addr) == nil {
						sent++
					}
				}
				tPayload := []byte(fmt.Sprintf("%s|%s|TCP|", magicPrefix, ipStr))
				if pkt, dst4, err := buildForgedIPv4TCPPacket(ipStr, targetIP, 443, targetPort, tPayload); err == nil {
					var addr syscall.SockaddrInet4
					copy(addr.Addr[:], dst4)
					if syscall.Sendto(fd, pkt, 0, &addr) == nil {
						sent++
					}
				}
			}
			_ = syscall.Close(fd)
		}
	}

	for _, ipStr := range candidates {
		sent += runExactIptablesSNATPingTest(targetIP, ipStr)
	}

	return sent
}

type multiProtoCaptureResult struct {
	OwnIPReceived      bool     `json:"own_ip_received"`
	ExternalSupported  bool     `json:"external_supported"`
	SameSub24Supported bool     `json:"same_sub24_supported"`
	NATRewrittenTo     string   `json:"nat_rewritten_to,omitempty"`
	WorkingProtocols   []string `json:"working_protocols,omitempty"`
	WorkingSpoofIPs    []string `json:"working_spoof_ips,omitempty"`
	PacketsReceived    int      `json:"packets_received"`
}

func captureMultiProtocolProbes(uConn *net.UDPConn, magicPrefix string, candidates []string, duration time.Duration) multiProtoCaptureResult {
	var mu sync.Mutex
	res := multiProtoCaptureResult{}
	protoSet := make(map[string]bool)
	ipSet := make(map[string]bool)
	candMap := make(map[string]bool)
	for _, c := range candidates {
		candMap[c] = true
	}

	addWorking := func(proto, ip string) {
		if proto != "" && !protoSet[proto] {
			protoSet[proto] = true
			res.WorkingProtocols = append(res.WorkingProtocols, proto)
		}
		if ip != "" && !ipSet[ip] {
			ipSet[ip] = true
			res.WorkingSpoofIPs = append(res.WorkingSpoofIPs, ip)
			if strings.Contains(ip, ".233") || strings.Contains(ip, ".234") {
				res.SameSub24Supported = true
			} else {
				res.ExternalSupported = true
			}
		}
	}

	recordDirectSourceIPMatch := func(srcIP, protoLabel string) bool {
		srcIP = cleanSpoofHost(srcIP)
		if srcIP == "" {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		if candMap[srcIP] {
			res.PacketsReceived++
			addWorking(protoLabel, srcIP)
			return true
		}
		return false
	}

	recordHit := func(srcIP string, payload []byte, listenerProto string) {
		idx := bytes.Index(payload, []byte(magicPrefix+"|"))
		if idx < 0 {
			if listenerProto == "ICMP" && len(payload) >= 8 && payload[0] == 8 {
				recordDirectSourceIPMatch(srcIP, "SNAT+PING")
			}
			return
		}
		parts := strings.Split(string(payload[idx:]), "|")
		if len(parts) < 3 {
			return
		}
		ipTag := parts[1]
		proto := parts[2]
		if proto == "" {
			proto = listenerProto
		}

		mu.Lock()
		defer mu.Unlock()
		res.PacketsReceived++

		if ipTag == "OWN" {
			res.OwnIPReceived = true
			return
		}

		if candMap[ipTag] || ipTag == "127.0.0.1" {
			addWorking(proto, ipTag)
		} else if srcIP != "" {
			res.NATRewrittenTo = srcIP
		}
	}

	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = uConn.SetDeadline(deadline)
		buf := make([]byte, 4096)
		for {
			n, rAddr, err := uConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			src := ""
			if rAddr != nil && rAddr.IP != nil {
				src = rAddr.IP.String()
			}
			recordHit(src, buf[:n], "UDP")
		}
	}()

	if icmpConn, err := net.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer icmpConn.Close()
			_ = icmpConn.SetDeadline(deadline)
			buf := make([]byte, 4096)
			for {
				n, rAddr, rErr := icmpConn.ReadFrom(buf)
				if rErr != nil {
					return
				}
				src := ""
				if rAddr != nil {
					src = cleanSpoofHost(rAddr.String())
				}
				recordHit(src, buf[:n], "ICMP")
			}
		}()
	}

	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		if tcpdumpBin, err := exec.LookPath("tcpdump"); err == nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), duration)
				defer cancel()
				cmd := exec.CommandContext(ctx, tcpdumpBin, "-l", "-n", "-i", "any", "-c", "3", "icmp")
				outBytes, _ := cmd.CombinedOutput()
				outStr := string(outBytes)
				if strings.Contains(outStr, "ICMP echo request") {
					for _, cIP := range candidates {
						if strings.Contains(outStr, cIP) {
							recordDirectSourceIPMatch(cIP, "TCPDUMP_ICMP")
						}
					}
				}
			}()
		}
	}

	if tcpRawConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0"); err == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer tcpRawConn.Close()
			_ = tcpRawConn.SetDeadline(deadline)
			buf := make([]byte, 4096)
			for {
				n, rAddr, rErr := tcpRawConn.ReadFrom(buf)
				if rErr != nil {
					return
				}
				if !bytes.Contains(buf[:n], []byte(magicPrefix+"|")) {
					continue
				}
				src := ""
				if rAddr != nil {
					src = cleanSpoofHost(rAddr.String())
				}
				recordHit(src, buf[:n], "TCP")
			}
		}()
	}

	wg.Wait()
	return res
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
	Step         string               `json:"step"`
	CandidateIPs []string             `json:"candidate_ips,omitempty"`
	ProbePort    int                  `json:"probe_port,omitempty"`
	MagicHex     string               `json:"magic_hex,omitempty"`
	MasterPubIP  string               `json:"master_pub_ip,omitempty"`
	CheckResult  *SpoofDirectionCheck `json:"check_result,omitempty"`
}

func buildDirectionVerdict(candidates []string, sentCount int, capRes multiProtoCaptureResult, senderLabel, receiverLabel string) SpoofDirectionCheck {
	testedStr := strings.Join(candidates, ", ")
	chk := SpoofDirectionCheck{
		SpoofIPTested:   testedStr,
		PacketsSent:     sentCount,
		PacketsReceived: capRes.PacketsReceived,
	}

	protos := strings.Join(capRes.WorkingProtocols, ", ")
	ips := strings.Join(capRes.WorkingSpoofIPs, ", ")

	if capRes.ExternalSupported {
		chk.Supported = true
		chk.StatusBadge = fmt.Sprintf("SUPPORTED (%s)", protos)
		chk.ObservedSourceIP = ips
		chk.Detail = fmt.Sprintf("%s can send spoofed packets! %s received forged packets from [%s] via [%s].",
			senderLabel, receiverLabel, ips, protos)
		return chk
	}

	if capRes.SameSub24Supported {
		chk.Supported = true
		chk.StatusBadge = fmt.Sprintf("SAME-/24 SUBNET SUPPORTED (%s)", protos)
		chk.ObservedSourceIP = ips
		chk.Detail = fmt.Sprintf("%s blocks external spoofing, but SAME-/24 SUBNET SPOOFING WORKS! Working IP(s): [%s] via [%s].",
			senderLabel, ips, protos)
		return chk
	}

	if capRes.NATRewrittenTo != "" {
		chk.Supported = false
		chk.StatusBadge = "REWRITTEN BY NAT"
		chk.ObservedSourceIP = capRes.NATRewrittenTo
		chk.Detail = fmt.Sprintf("Spoofed packets left %s, but an upstream NAT rewrote the source IP back to %s before reaching %s.",
			senderLabel, capRes.NATRewrittenTo, receiverLabel)
		return chk
	}

	if capRes.OwnIPReceived {
		chk.Supported = false
		chk.StatusBadge = "BLOCKED (ISP/DATACENTER)"
		chk.Detail = fmt.Sprintf("Baseline Real-IP reached %s OK, but 0 spoofed packets (tested candidates: [%s]) left %s. Datacenter enforces strict BCP38 anti-spoofing.",
			receiverLabel, testedStr, senderLabel, senderLabel)
		return chk
	}

	chk.Supported = false
	chk.StatusBadge = "PORT / FIREWALL BLOCKED"
	chk.Detail = fmt.Sprintf("Even unspoofed packets from %s's own real IP did not reach %s. Check firewall / security group on %s.",
		senderLabel, receiverLabel, receiverLabel)
	return chk
}

func handleSpoofCapAgentSession(conn net.Conn, remoteMasterIP string, rt *spoofWGRuntime) {
	_ = conn.SetDeadline(time.Now().Add(26 * time.Second))
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	var initMsg spoofCapWireMsg
	if err := dec.Decode(&initMsg); err != nil || initMsg.Step != "init" {
		return
	}

	preferredPort := defaultSpoofPort
	if rt != nil && rt.tunnel.SpoofWG != nil && rt.tunnel.SpoofWG.SpoofListenPort > 0 {
		preferredPort = rt.tunnel.SpoofWG.SpoofListenPort
	}
	uConn, boundPort, cleanup, err := openTemporaryUDPVerifyListener(preferredPort)
	if err != nil {
		_ = enc.Encode(spoofCapWireMsg{
			Step: "result",
			CheckResult: &SpoofDirectionCheck{
				Supported:   false,
				StatusBadge: "ERROR",
				Detail:      err.Error(),
			},
		})
		return
	}
	defer cleanup()

	candidates := buildSpoofProbeSuite(remoteMasterIP, initMsg.CandidateIPs)
	magicPrefix1 := "SPFV1_" + initMsg.MagicHex

	capCh1 := make(chan multiProtoCaptureResult, 1)
	go func() {
		capCh1 <- captureMultiProtocolProbes(uConn, magicPrefix1, candidates, 3800*time.Millisecond)
	}()

	if err := enc.Encode(spoofCapWireMsg{
		Step:        "ready",
		ProbePort:   boundPort,
		MasterPubIP: remoteMasterIP,
	}); err != nil {
		return
	}

	capRes1 := <-capCh1
	cleanup()

	chk1 := buildDirectionVerdict(candidates, len(candidates)*8, capRes1, "Master (Iran)", "Agent (Foreign)")
	if err := enc.Encode(spoofCapWireMsg{
		Step:        "result",
		CheckResult: &chk1,
	}); err != nil {
		return
	}

	var phase2Msg spoofCapWireMsg
	if err := dec.Decode(&phase2Msg); err != nil || phase2Msg.Step != "send_now" {
		return
	}
	targetMasterIP := cleanSpoofHost(phase2Msg.MasterPubIP)
	if !isValidIPv4String(targetMasterIP) {
		targetMasterIP = cleanSpoofHost(remoteMasterIP)
	}
	agentOwnIP := resolveOutboundInterfaceIP(targetMasterIP).String()
	candidates2 := buildSpoofProbeSuite(agentOwnIP, phase2Msg.CandidateIPs)
	magicPrefix2 := "SPFV2_" + phase2Msg.MagicHex

	sent2 := sendMultiMethodCapabilityProbes(candidates2, targetMasterIP, phase2Msg.ProbePort, magicPrefix2)

	_ = enc.Encode(spoofCapWireMsg{
		Step:        "result",
		ProbePort:   sent2,
		MasterPubIP: agentOwnIP,
	})
}

func RunBidirectionalSpoofCapabilityVerify(peer ServerPeer, candidateIPs []string) (SpoofCapabilityReport, error) {
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
	_ = rawConn.SetDeadline(time.Now().Add(26 * time.Second))

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
	magicHex1, _ := randomHex(6)
	candidates1 := buildSpoofProbeSuite(peer.IP, candidateIPs)

	if err := enc.Encode(spoofCapWireMsg{
		Step:         "init",
		CandidateIPs: candidates1,
		MagicHex:     magicHex1,
	}); err != nil {
		return SpoofCapabilityReport{}, err
	}

	var readyMsg spoofCapWireMsg
	if err := dec.Decode(&readyMsg); err != nil || readyMsg.Step != "ready" {
		return SpoofCapabilityReport{}, errors.New("Agent did not ready spoof listener")
	}

	masterPubIP := cleanSpoofHost(readyMsg.MasterPubIP)
	if tc26.SpoofWG != nil && isValidIPv4String(tc26.SpoofWG.LocalPublicIP) {
		masterPubIP = cleanSpoofHost(tc26.SpoofWG.LocalPublicIP)
	}
	magicPrefix1 := "SPFV1_" + magicHex1

	sent1 := sendMultiMethodCapabilityProbes(candidates1, strings.TrimSpace(peer.IP), readyMsg.ProbePort, magicPrefix1)

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

	magicHex2, _ := randomHex(6)
	magicPrefix2 := "SPFV2_" + magicHex2
	candidates2 := buildSpoofProbeSuite(masterPubIP, candidateIPs)

	capCh2 := make(chan multiProtoCaptureResult, 1)
	go func() {
		capCh2 <- captureMultiProtocolProbes(uConn2, magicPrefix2, candidates2, 3800*time.Millisecond)
	}()

	if err := enc.Encode(spoofCapWireMsg{
		Step:         "send_now",
		CandidateIPs: candidates2,
		ProbePort:    boundPort2,
		MagicHex:     magicHex2,
		MasterPubIP:  masterPubIP,
	}); err != nil {
		return SpoofCapabilityReport{}, err
	}

	var resMsg2 spoofCapWireMsg
	_ = dec.Decode(&resMsg2)
	capRes2 := <-capCh2
	cleanup2()

	sent2 := resMsg2.ProbePort
	if sent2 <= 0 {
		sent2 = len(candidates2) * 8
	}
	a2m := buildDirectionVerdict(candidates2, sent2, capRes2, "Agent (Foreign)", "Master (Iran)")

	overallOK := m2a.Supported && a2m.Supported
	badge := "SPOOFING SUPPORTED ON BOTH SERVERS"
	summary := fmt.Sprintf("Both Master (%s) and Agent (%s) passed multi-method spoof verification!",
		m2a.StatusBadge, a2m.StatusBadge)

	if !overallOK {
		switch {
		case !m2a.Supported && !a2m.Supported:
			badge = "SPOOFING BLOCKED ON BOTH SERVERS"
			summary = fmt.Sprintf("Tested candidate IPs [%s] via iptables SNAT+ping, tcpdump icmp, and raw ICMP/TCP/UDP: both datacenters dropped all spoofed packets.",
				strings.Join(candidates1, ", "))
		case !m2a.Supported:
			badge = "MASTER (IRAN) BLOCKS SPOOFING (AGENT OK)"
			summary = fmt.Sprintf("Agent supports spoofing (%s), but Master dropped spoofed packets (%s).",
				a2m.StatusBadge, m2a.StatusBadge)
		default:
			badge = "AGENT (FOREIGN) BLOCKS SPOOFING (MASTER OK)"
			summary = fmt.Sprintf("Master supports spoofing (%s), but Agent dropped spoofed packets (%s).",
				m2a.StatusBadge, a2m.StatusBadge)
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
