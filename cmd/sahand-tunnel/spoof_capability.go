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
		Summary:      "Click 'Verify Spoof Support (Both Sides)' to test Own-IP baseline, Same-/24 subnet spoofing, and External IP spoofing across ICMP, TCP, and UDP.",
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

// Builds a raw IPv4 + ICMP Echo Request (Type 8, Code 0) packet with forged source IP
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

// Builds a raw IPv4 + TCP ACK/PSH probe packet with forged source IP (sport=443 -> dport=targetPort)
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
	tcpPkt[12] = 5 << 4 // Data offset: 20 bytes
	tcpPkt[13] = 0x18   // PSH | ACK (passes stateless firewalls better than bare SYN)
	binary.BigEndian.PutUint16(tcpPkt[14:16], 64240)
	copy(tcpPkt[20:], payload)
	binary.BigEndian.PutUint16(tcpPkt[16:18], l4IPv4PseudoChecksum(srcIP, dstIP, syscall.IPPROTO_TCP, tcpPkt))
	return wrapIPv4Header(srcIP, dstIP, syscall.IPPROTO_TCP, tcpPkt), dstIP, nil
}

// Derives a neighbor IP in the same /24 subnet as realIP (e.g., x.y.z.233)
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

type spoofProbeSuite struct {
	OwnIP        string `json:"own_ip"`
	SameSubnetIP string `json:"same_subnet_ip"`
	ExternalIP   string `json:"external_ip"`
	GoogleDNSIP  string `json:"google_dns_ip"`
}

func buildSpoofProbeSuite(realSenderIP, requestedSpoofIP string) spoofProbeSuite {
	own := cleanSpoofHost(realSenderIP)
	if !isValidIPv4String(own) {
		own = resolveOutboundInterfaceIP("8.8.8.8").String()
	}
	ext := cleanSpoofHost(requestedSpoofIP)
	if !isValidIPv4String(ext) || ext == "8.8.8.8" || ext == own {
		ext = "172.67.150.10" // Non-DNS Cloudflare edge IP (not blocked by Google DNS amplification ACLs)
	}
	return spoofProbeSuite{
		OwnIP:        own,
		SameSubnetIP: deriveSameSlash24NeighborIP(own),
		ExternalIP:   ext,
		GoogleDNSIP:  "8.8.8.8",
	}
}

// Sends multi-protocol probes:
// 1. Baseline control probe from OwnIP (normal UDP + raw socket)
// 2. Spoofed probes from SameSubnetIP, ExternalIP, and GoogleDNSIP across UDP, ICMP, and TCP
// 3. Temporary `iptables -t nat -I POSTROUTING -d target -p icmp -j SNAT --to-source <extIP>` + `ping`
//    (exact match for the manual test in the user's screenshot!)
func sendMultiMethodCapabilityProbes(suite spoofProbeSuite, targetIP string, targetPort int, magicPrefix string) int {
	sent := 0
	pStr := strconv.Itoa(targetPort)

	// 1. Baseline Own-IP Control Probe over normal UDP socket (proves port is open)
	ownToken := []byte(magicPrefix + "|OWN|UDP|")
	if rAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(targetIP, pStr)); err == nil {
		if uConn, err := net.DialUDP("udp4", nil, rAddr); err == nil {
			for i := 0; i < 2; i++ {
				if _, wErr := uConn.Write(ownToken); wErr == nil {
					sent++
				}
			}
			_ = uConn.Close()
		}
	}

	candidates := []struct {
		tag string
		ip  string
	}{
		{"OWN", suite.OwnIP},
		{"SUB24", suite.SameSubnetIP},
		{"EXT", suite.ExternalIP},
		{"DNS8", suite.GoogleDNSIP},
	}

	// 2. Raw IP_HDRINCL Socket Injection across UDP, ICMP, and TCP
	if runtime.GOOS == "linux" {
		if fd, sErr := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW); sErr == nil {
			_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
			for idx, c := range candidates {
				if !isValidIPv4String(c.ip) {
					continue
				}
				// 2a. Raw UDP
				uPayload := []byte(fmt.Sprintf("%s|%s|UDP|", magicPrefix, c.tag))
				if pkt, dst4, err := buildForgedIPv4UDPPacket(c.ip, targetIP, 443, targetPort, uPayload); err == nil {
					var addr syscall.SockaddrInet4
					copy(addr.Addr[:], dst4)
					for i := 0; i < 2; i++ {
						if syscall.Sendto(fd, pkt, 0, &addr) == nil {
							sent++
						}
					}
				}
				// 2b. Raw ICMP Echo Request
				iPayload := []byte(fmt.Sprintf("%s|%s|ICMP|", magicPrefix, c.tag))
				if pkt, dst4, err := buildForgedIPv4ICMPPacket(c.ip, targetIP, uint16(idx+1), iPayload); err == nil {
					var addr syscall.SockaddrInet4
					copy(addr.Addr[:], dst4)
					for i := 0; i < 2; i++ {
						if syscall.Sendto(fd, pkt, 0, &addr) == nil {
							sent++
						}
					}
				}
				// 2c. Raw TCP (sport 443 -> dport targetPort)
				tPayload := []byte(fmt.Sprintf("%s|%s|TCP|", magicPrefix, c.tag))
				if pkt, dst4, err := buildForgedIPv4TCPPacket(c.ip, targetIP, 443, targetPort, tPayload); err == nil {
					var addr syscall.SockaddrInet4
					copy(addr.Addr[:], dst4)
					for i := 0; i < 2; i++ {
						if syscall.Sendto(fd, pkt, 0, &addr) == nil {
							sent++
						}
					}
				}
				time.Sleep(15 * time.Millisecond)
			}
			_ = syscall.Close(fd)
		}
	}

	// 3. Exact Manual Test from Screenshot: Temporary `iptables -t nat POSTROUTING SNAT` + `ping -p <hex>` & fresh UDP
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		if _, err := exec.LookPath("iptables"); err == nil {
			for _, c := range []struct {
				tag string
				ip  string
			}{
				{"EXT", suite.ExternalIP},
				{"SUB24", suite.SameSubnetIP},
			} {
				if !isValidIPv4String(c.ip) {
					continue
				}
				// Temporary SNAT rule for UDP with random source port (bypasses existing conntrack state)
				snatUDP := []string{"-t", "nat", "-I", "POSTROUTING", "1", "-p", "udp", "-d", targetIP, "--dport", pStr, "-j", "SNAT", "--to-source", c.ip}
				delUDP := []string{"-t", "nat", "-D", "POSTROUTING", "-p", "udp", "-d", targetIP, "--dport", pStr, "-j", "SNAT", "--to-source", c.ip}
				if exec.Command("iptables", snatUDP...).Run() == nil {
					if rAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(targetIP, pStr)); err == nil {
						if uConn, err := net.DialUDP("udp4", nil, rAddr); err == nil {
							_, _ = uConn.Write([]byte(fmt.Sprintf("%s|%s|SNAT_UDP|", magicPrefix, c.tag)))
							sent++
							_ = uConn.Close()
						}
					}
					_ = exec.Command("iptables", delUDP...).Run()
				}
			}
		}
	}

	return sent
}

type multiProtoCaptureResult struct {
	OwnIPReceived      bool     `json:"own_ip_received"`
	ExternalSupported  bool     `json:"external_supported"`
	SameSub24Supported bool     `json:"same_sub24_supported"`
	DNS8Supported      bool     `json:"dns8_supported"`
	NATRewrittenTo     string   `json:"nat_rewritten_to,omitempty"`
	WorkingProtocols   []string `json:"working_protocols,omitempty"`
	WorkingSpoofIPs    []string `json:"working_spoof_ips,omitempty"`
	PacketsReceived    int      `json:"packets_received"`
}

// Listens simultaneously on UDP (`0.0.0.0:port`), Raw ICMP (`ip4:icmp`), and Raw TCP (`ip4:tcp`)
// for 2.8 seconds to catch any probe carrying `magicPrefix`.
func captureMultiProtocolProbes(uConn *net.UDPConn, magicPrefix string, suite spoofProbeSuite, duration time.Duration) multiProtoCaptureResult {
	var mu sync.Mutex
	res := multiProtoCaptureResult{}
	protoSet := make(map[string]bool)
	ipSet := make(map[string]bool)

	recordHit := func(srcIP string, payload []byte, listenerProto string) {
		idx := bytes.Index(payload, []byte(magicPrefix+"|"))
		if idx < 0 {
			return
		}
		parts := strings.Split(string(payload[idx:]), "|")
		if len(parts) < 3 {
			return
		}
		tag := parts[1]   // "OWN" | "SUB24" | "EXT" | "DNS8"
		proto := parts[2] // "UDP" | "ICMP" | "TCP" | "SNAT_UDP"
		if proto == "" {
			proto = listenerProto
		}

		mu.Lock()
		defer mu.Unlock()
		res.PacketsReceived++

		if tag == "OWN" {
			res.OwnIPReceived = true
			return
		}

		expectedIP := ""
		switch tag {
		case "SUB24":
			expectedIP = suite.SameSubnetIP
		case "EXT":
			expectedIP = suite.ExternalIP
		case "DNS8":
			expectedIP = suite.GoogleDNSIP
		}

		if srcIP == expectedIP || srcIP == "127.0.0.1" {
			switch tag {
			case "SUB24":
				res.SameSub24Supported = true
			case "EXT":
				res.ExternalSupported = true
			case "DNS8":
				res.DNS8Supported = true
			}
			if !protoSet[proto] {
				protoSet[proto] = true
				res.WorkingProtocols = append(res.WorkingProtocols, proto)
			}
			if expectedIP != "" && !ipSet[expectedIP] {
				ipSet[expectedIP] = true
				res.WorkingSpoofIPs = append(res.WorkingSpoofIPs, expectedIP)
			}
		} else if srcIP != "" {
			res.NATRewrittenTo = srcIP
		}
	}

	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup

	// 1. UDP Listener
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

	// 2. Raw ICMP Listener (`ip4:icmp` — catches spoofed ICMP Echo Requests just like `tcpdump icmp`)
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

	// 3. Raw TCP Listener (`ip4:tcp` — catches spoofed TCP packets even when UDP/ICMP is filtered)
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
	Step        string               `json:"step"` // "init" | "ready" | "send_now" | "result"
	SpoofIP     string               `json:"spoof_ip,omitempty"`
	ProbePort   int                  `json:"probe_port,omitempty"`
	MagicHex    string               `json:"magic_hex,omitempty"`
	MasterPubIP string               `json:"master_pub_ip,omitempty"`
	CheckResult *SpoofDirectionCheck `json:"check_result,omitempty"`
}

func buildDirectionVerdict(suite spoofProbeSuite, sentCount int, capRes multiProtoCaptureResult, senderLabel, receiverLabel string) SpoofDirectionCheck {
	chk := SpoofDirectionCheck{
		SpoofIPTested:   fmt.Sprintf("%s, %s (/24), 8.8.8.8", suite.ExternalIP, suite.SameSubnetIP),
		PacketsSent:     sentCount,
		PacketsReceived: capRes.PacketsReceived,
	}

	protos := strings.Join(capRes.WorkingProtocols, ", ")
	ips := strings.Join(capRes.WorkingSpoofIPs, ", ")

	// Case 1: Full External Spoofing Supported (e.g. 172.67.150.10 or 8.8.8.8 arrived intact)
	if capRes.ExternalSupported || capRes.DNS8Supported {
		chk.Supported = true
		chk.StatusBadge = fmt.Sprintf("SUPPORTED (%s)", protos)
		chk.ObservedSourceIP = ips
		chk.Detail = fmt.Sprintf("%s can send spoofed packets! %s received forged packets from [%s] over [%s].",
			senderLabel, receiverLabel, ips, protos)
		return chk
	}

	// Case 2: Only Same-/24 Subnet Spoofing Supported (e.g. 8.8.8.8 dropped, but x.y.z.233 passed!)
	if capRes.SameSub24Supported {
		chk.Supported = true
		chk.StatusBadge = fmt.Sprintf("SAME-/24 SUBNET SUPPORTED (%s)", protos)
		chk.ObservedSourceIP = suite.SameSubnetIP
		chk.Detail = fmt.Sprintf("%s blocks external IPs like 8.8.8.8, Beat-Filter: SAME-/24 SPOOFING WORKS! Use %s as your Spoof IP on %s (verified over %s).",
			senderLabel, suite.SameSubnetIP, senderLabel, protos)
		return chk
	}

	// Case 3: Upstream NAT rewrote the forged IP back to the server's real IP
	if capRes.NATRewrittenTo != "" {
		chk.Supported = false
		chk.StatusBadge = "REWRITTEN BY NAT"
		chk.ObservedSourceIP = capRes.NATRewrittenTo
		chk.Detail = fmt.Sprintf("Spoofed packets left %s, but an upstream NAT rewrote the source IP back to %s before reaching %s.",
			senderLabel, capRes.NATRewrittenTo, receiverLabel)
		return chk
	}

	// Case 4: Baseline Own-IP arrived, but ALL spoofed IPs (External + Same /24) across UDP, ICMP, and TCP were dropped
	if capRes.OwnIPReceived {
		chk.Supported = false
		chk.StatusBadge = "BLOCKED (ISP/DATACENTER)"
		chk.Detail = fmt.Sprintf("Baseline Real-IP (%s) reached %s OK (port is open), but 0 spoofed packets (tested %s, %s, 8.8.8.8 across ICMP/TCP/UDP) left %s. %s's hypervisor/router strictly enforces BCP38 anti-spoofing.",
			suite.OwnIP, receiverLabel, suite.ExternalIP, suite.SameSubnetIP, senderLabel, senderLabel)
		return chk
	}

	// Case 5: Even the server's OWN real IP did not arrive -> Firewall/Port block, NOT necessarily spoofing!
	chk.Supported = false
	chk.StatusBadge = "PORT / FIREWALL BLOCKED"
	chk.Detail = fmt.Sprintf("Even unspoofed packets from %s's own real IP (%s) did not reach %s on UDP/ICMP/TCP. Check firewall / security group on %s.",
		senderLabel, suite.OwnIP, receiverLabel, receiverLabel)
	return chk
}

// Agent-side handler invoked when Master dials `:28026` with `spoofWGCmdVerifyCap` (0x05)
func handleSpoofCapAgentSession(conn net.Conn, remoteMasterIP string, rt *spoofWGRuntime) {
	_ = conn.SetDeadline(time.Now().Add(22 * time.Second))
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

	suite1 := buildSpoofProbeSuite(remoteMasterIP, initMsg.SpoofIP)
	magicPrefix1 := "SPFV1_" + initMsg.MagicHex

	capCh1 := make(chan multiProtoCaptureResult, 1)
	go func() {
		capCh1 <- captureMultiProtocolProbes(uConn, magicPrefix1, suite1, 2800*time.Millisecond)
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

	chk1 := buildDirectionVerdict(suite1, 26, capRes1, "Master (Iran)", "Agent (Foreign)")
	if err := enc.Encode(spoofCapWireMsg{
		Step:        "result",
		CheckResult: &chk1,
	}); err != nil {
		return
	}

	// Phase 2: Agent sends multi-method probes back to Master
	var phase2Msg spoofCapWireMsg
	if err := dec.Decode(&phase2Msg); err != nil || phase2Msg.Step != "send_now" {
		return
	}
	targetMasterIP := cleanSpoofHost(phase2Msg.MasterPubIP)
	if !isValidIPv4String(targetMasterIP) {
		targetMasterIP = cleanSpoofHost(remoteMasterIP)
	}
	agentOwnIP := resolveOutboundInterfaceIP(targetMasterIP).String()
	suite2 := buildSpoofProbeSuite(agentOwnIP, phase2Msg.SpoofIP)
	magicPrefix2 := "SPFV2_" + phase2Msg.MagicHex

	sent2 := sendMultiMethodCapabilityProbes(suite2, targetMasterIP, phase2Msg.ProbePort, magicPrefix2)

	_ = enc.Encode(spoofCapWireMsg{
		Step:        "result",
		ProbePort:   sent2,
		MasterPubIP: agentOwnIP,
	})
}

func RunBidirectionalSpoofCapabilityVerify(peer ServerPeer, spoofIP string) (SpoofCapabilityReport, error) {
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
	_ = rawConn.SetDeadline(time.Now().Add(22 * time.Second))

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
	if err := enc.Encode(spoofCapWireMsg{
		Step:     "init",
		SpoofIP:  spoofIP,
		MagicHex: magicHex1,
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
	suite1 := buildSpoofProbeSuite(masterPubIP, spoofIP)
	magicPrefix1 := "SPFV1_" + magicHex1

	sent1 := sendMultiMethodCapabilityProbes(suite1, strings.TrimSpace(peer.IP), readyMsg.ProbePort, magicPrefix1)

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
	suite2 := buildSpoofProbeSuite(strings.TrimSpace(peer.IP), spoofIP)

	capCh2 := make(chan multiProtoCaptureResult, 1)
	go func() {
		capCh2 <- captureMultiProtocolProbes(uConn2, magicPrefix2, suite2, 2800*time.Millisecond)
	}()

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
	capRes2 := <-capCh2
	cleanup2()

	sent2 := resMsg2.ProbePort
	if sent2 <= 0 {
		sent2 = 26
	}
	a2m := buildDirectionVerdict(suite2, sent2, capRes2, "Agent (Foreign)", "Master (Iran)")

	overallOK := m2a.Supported && a2m.Supported
	badge := "SPOOFING SUPPORTED ON BOTH SERVERS"
	summary := fmt.Sprintf("Both Master (%s) and Agent (%s) passed multi-protocol spoof verification! You can now activate Method 26 or Method 27 using the working Spoof IP(s) and transport shown below.",
		m2a.StatusBadge, a2m.StatusBadge)

	if !overallOK {
		switch {
		case !m2a.Supported && !a2m.Supported:
			badge = "SPOOFING BLOCKED ON BOTH SERVERS"
			summary = "Tested Own-IP Baseline, Same-/24 Neighbor IP, External IP (172.67.150.10), and 8.8.8.8 across ICMP, TCP, and UDP: both datacenters dropped all spoofed packets."
		case !m2a.Supported:
			badge = "MASTER (IRAN) BLOCKS SPOOFING (AGENT OK)"
			summary = fmt.Sprintf("Agent (Foreign) supports spoofing (%s), but Master (Iran) dropped outgoing spoofed packets (%s).",
				a2m.StatusBadge, m2a.StatusBadge)
		default:
			badge = "AGENT (FOREIGN) BLOCKS SPOOFING (MASTER OK)"
			summary = fmt.Sprintf("Master (Iran) supports spoofing (%s), but Agent (Foreign) dropped outgoing spoofed packets (%s).",
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
