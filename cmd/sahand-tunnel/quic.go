package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	quicHeaderByte    = 0xC3 // RFC 9000 Long Header (Fixed bit + Initial type)
	quicVersionNumber = 0x00000001
	quicTypeProbe     = 0x01
	quicTypeProbeAck  = 0x02
	quicTypeUDPData   = 0x03
)

func quicAEAD() (cipher.AEAD, error) {
	sum := sha256.Sum256([]byte("SAHAND-QUIC-V1-AEAD-KEY-2026"))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Builds an RFC 9000 QUIC Long Header packet with an AES-256-GCM encrypted payload
func packQUICDatagram(pktType byte, peerID, targetPort, timeHdr string, data []byte) ([]byte, error) {
	aead, err := quicAEAD()
	if err != nil {
		return nil, err
	}

	dcid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	scid := make([]byte, 8)
	_, _ = rand.Read(scid)

	hdr := make([]byte, 0, 24)
	hdr = append(hdr, quicHeaderByte)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], quicVersionNumber)
	hdr = append(hdr, ver[:]...)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)

	meta := fmt.Sprintf("%s|%s|%s", peerID, targetPort, timeHdr)
	metaBytes := []byte(meta)
	plain := make([]byte, 3+len(metaBytes)+len(data))
	plain[0] = pktType
	binary.BigEndian.PutUint16(plain[1:3], uint16(len(metaBytes)))
	copy(plain[3:3+len(metaBytes)], metaBytes)
	copy(plain[3+len(metaBytes):], data)

	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)

	sealed := aead.Seal(nil, nonce, plain, hdr)
	out := make([]byte, 0, len(hdr)+len(nonce)+len(sealed))
	out = append(out, hdr...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

func unpackQUICDatagram(raw []byte) (byte, string, string, string, []byte, error) {
	if len(raw) < 35 || raw[0] != quicHeaderByte {
		return 0, "", "", "", nil, errors.New("invalid quic header")
	}
	idx := 5
	dcidLen := int(raw[idx])
	idx++
	if len(raw) < idx+dcidLen+1 {
		return 0, "", "", "", nil, errors.New("truncated dcid")
	}
	idx += dcidLen
	scidLen := int(raw[idx])
	idx++
	if len(raw) < idx+scidLen {
		return 0, "", "", "", nil, errors.New("truncated scid")
	}
	idx += scidLen

	hdr := raw[:idx]
	aead, err := quicAEAD()
	if err != nil {
		return 0, "", "", "", nil, err
	}
	nonceSize := aead.NonceSize()
	if len(raw) < idx+nonceSize+aead.Overhead() {
		return 0, "", "", "", nil, errors.New("truncated quic payload")
	}
	nonce := raw[idx : idx+nonceSize]
	ciphertext := raw[idx+nonceSize:]

	plain, err := aead.Open(nil, nonce, ciphertext, hdr)
	if err != nil || len(plain) < 3 {
		return 0, "", "", "", nil, errors.New("quic aead verification failed")
	}

	pktType := plain[0]
	metaLen := int(binary.BigEndian.Uint16(plain[1:3]))
	if len(plain) < 3+metaLen {
		return 0, "", "", "", nil, errors.New("corrupted quic metadata")
	}
	metaParts := strings.SplitN(string(plain[3:3+metaLen]), "|", 3)
	var peerID, targetPort, timeHdr string
	if len(metaParts) > 0 {
		peerID = metaParts[0]
	}
	if len(metaParts) > 1 {
		targetPort = metaParts[1]
	}
	if len(metaParts) > 2 {
		timeHdr = metaParts[2]
	}
	payload := plain[3+metaLen:]
	return pktType, peerID, targetPort, timeHdr, payload, nil
}

func startQUICUDPServer(peerID string, tc TunnelConfig) net.PacketConn {
	listenAddr := fmt.Sprintf("0.0.0.0:%d", tc.ListenPort)
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pktCopy := make([]byte, n)
			copy(pktCopy, buf[:n])
			go handleIncomingQUICDatagram(conn, clientAddr, peerID, tc, pktCopy)
		}
	}()
	return conn
}

func handleIncomingQUICDatagram(conn *net.UDPConn, clientAddr *net.UDPAddr, defaultPeerID string, tc TunnelConfig, raw []byte) {
	pktType, peerHeader, targetPort, timeHdr, payload, err := unpackQUICDatagram(raw)
	if err != nil {
		return
	}
	if timeHdr != "" {
		applyMasterTimeHeader(timeHdr)
	}
	effectivePeerID := defaultPeerID
	if peerHeader != "" {
		effectivePeerID = peerHeader
	}

	switch pktType {
	case quicTypeProbe:
		markPeerConnectedInbound(effectivePeerID, clientAddr.IP.String(), tc.ID, tc.ListenPort, 1)
		ack, err := packQUICDatagram(quicTypeProbeAck, effectivePeerID, targetPort, buildMasterTimeHeader(), []byte("QUIC-OK"))
		if err == nil {
			_, _ = conn.WriteToUDP(ack, clientAddr)
		}

	case quicTypeUDPData:
		if !tc.Enabled || len(payload) == 0 {
			return
		}
		if targetPort == "" {
			ports := parsePortList(tc.ForwardPorts)
			if len(ports) > 0 {
				targetPort = ports[0]
			} else {
				targetPort = "2053"
			}
		}
		atomic.AddUint64(&appRxBytes, uint64(len(payload)))
		dstAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+targetPort)
		if err != nil {
			return
		}
		localUDP, err := net.DialUDP("udp", nil, dstAddr)
		if err != nil {
			return
		}
		defer localUDP.Close()
		_ = localUDP.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := localUDP.Write(payload); err != nil {
			return
		}
		replyBuf := make([]byte, 65535)
		rn, err := localUDP.Read(replyBuf)
		if err == nil && rn > 0 {
			atomic.AddUint64(&appTxBytes, uint64(rn))
			respPkt, err := packQUICDatagram(quicTypeUDPData, effectivePeerID, targetPort, "", replyBuf[:rn])
			if err == nil {
				_, _ = conn.WriteToUDP(respPkt, clientAddr)
			}
		}
	}
}

func startQUICUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:"+targetPort)
	if err != nil {
		return nil
	}
	entryConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := entryConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			go func(cAddr *net.UDPAddr, chunk []byte) {
				remoteUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peer.IP, tc.ListenPort))
				if err != nil {
					return
				}
				remConn, err := net.DialUDP("udp", nil, remoteUDPAddr)
				if err != nil {
					return
				}
				defer remConn.Close()
				_ = remConn.SetDeadline(time.Now().Add(4 * time.Second))

				pkt, err := packQUICDatagram(quicTypeUDPData, peer.ID, targetPort, "", chunk)
				if err != nil {
					return
				}
				atomic.AddUint64(&appTxBytes, uint64(len(chunk)))
				if _, err := remConn.Write(pkt); err != nil {
					return
				}
				repBuf := make([]byte, 65535)
				rn, err := remConn.Read(repBuf)
				if err != nil || rn == 0 {
					return
				}
				rType, _, _, _, rPayload, err := unpackQUICDatagram(repBuf[:rn])
				if err == nil && rType == quicTypeUDPData && len(rPayload) > 0 {
					atomic.AddUint64(&appRxBytes, uint64(len(rPayload)))
					_, _ = entryConn.WriteToUDP(rPayload, cAddr)
				}
			}(clientAddr, data)
		}
	}()
	return entryConn
}

func probeQUIC(peer ServerPeer, tc TunnelConfig, localNodeID string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	targetAddr := fmt.Sprintf("%s:%d", peer.IP, tc.ListenPort)

	// 1. Primary RFC 9000 UDP QUIC Encrypted Probe
	if udpAddr, err := net.ResolveUDPAddr("udp", targetAddr); err == nil {
		if udpConn, err := net.DialUDP("udp", nil, udpAddr); err == nil {
			start := time.Now()
			_ = udpConn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
			pkt, packErr := packQUICDatagram(quicTypeProbe, peer.ID, fmt.Sprintf("probe:%d", tc.ListenPort), buildMasterTimeHeader(), []byte("PING"))
			if packErr == nil {
				if _, wErr := udpConn.Write(pkt); wErr == nil {
					rep := make([]byte, 2048)
					if n, rErr := udpConn.Read(rep); rErr == nil && n > 0 {
						rType, _, _, rTime, _, uErr := unpackQUICDatagram(rep[:n])
						if uErr == nil && rType == quicTypeProbeAck {
							if rTime != "" {
								applyMasterTimeHeader(rTime)
							}
							_ = udpConn.Close()
							res.Success = true
							res.LatencyMS = time.Since(start).Milliseconds()
							if res.LatencyMS <= 0 {
								res.LatencyMS = 1
							}
							return res
						}
					}
				}
			}
			_ = udpConn.Close()
		}
	}

	// 2. Fallback QUIC-ALPN h3 Stream Probe (when UDP datagrams are filtered by middleboxes)
	start := time.Now()
	dialer := &net.Dialer{Timeout: 3500 * time.Millisecond}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		res.Success = false
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}
	defer rawConn.Close()
	enableKeepAlive(rawConn)
	_ = rawConn.SetDeadline(time.Now().Add(4 * time.Second))

	sni := strings.TrimSpace(tc.SNI)
	if sni == "" {
		sni = "www.speedtest.net"
	}
	pin := strings.TrimSpace(tc.CertPin)
	if pin == "" {
		pin = peer.RemoteCertPin
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3", "quic", "h2"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		res.Success = false
		res.ErrorReason = "TLS/QUIC failure"
		return res
	}
	defer tlsConn.Close()

	req := fmt.Sprintf("QUIC probe:%d SAHAND-QUIC/1.0\r\nX-Tunnel-Mode: quic\r\nX-Sahand-Peer: %s\r\nX-Sahand-Node: %s\r\nX-Sahand-Time: %s\r\nX-Target-Port: probe:%d\r\n\r\n",
		tc.ListenPort, peer.ID, localNodeID, buildMasterTimeHeader(), tc.ListenPort)

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	br := bufio.NewReader(tlsConn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	res.Success = true
	res.LatencyMS = time.Since(start).Milliseconds()
	if res.LatencyMS <= 0 {
		res.LatencyMS = 1
	}
	return res
}

func handleQUICStreamProbeReply(conn net.Conn) {
	_, _ = conn.Write([]byte("SAHAND-QUIC/1.0 200 QUIC-OK\r\n\r\n"))
}

func handleQUICStreamIncomingTraffic(conn net.Conn, br *bufio.Reader, tc TunnelConfig, targetPort string) {
	target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte("SAHAND-QUIC/1.0 502 UNREACHABLE\r\n\r\n"))
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	_, _ = conn.Write([]byte("SAHAND-QUIC/1.0 200 QUIC-STREAM\r\n\r\n"))

	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		n, _ := br.Read(buf)
		if n > 0 {
			_, _ = target.Write(buf[:n])
		}
	}

	mbLimit := parseSpeedLimit(tc.SpeedLimitMBps)
	txW := newThrottledWriter(target, &appRxBytes, mbLimit)
	rxW := newThrottledWriter(conn, &appTxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(txW, conn) }()
	go func() { defer wg.Done(); _, _ = io.Copy(rxW, target) }()
	wg.Wait()
}

func forwardQUICTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	remoteAddr := fmt.Sprintf("%s:%d", peer.IP, tc.ListenPort)
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	rawConn, err := dialer.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer rawConn.Close()
	enableKeepAlive(rawConn)

	sni := strings.TrimSpace(tc.SNI)
	if sni == "" {
		sni = "www.speedtest.net"
	}
	pin := strings.TrimSpace(tc.CertPin)
	if pin == "" {
		pin = peer.RemoteCertPin
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3", "quic", "h2"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	req := fmt.Sprintf("QUIC 127.0.0.1:%s SAHAND-QUIC/1.0\r\nX-Tunnel-Mode: quic\r\nX-Sahand-Peer: %s\r\nX-Target-Port: %s\r\n\r\n",
		targetPort, peer.ID, targetPort)

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return
	}

	br := bufio.NewReader(tlsConn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		return
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		n, _ := br.Read(buf)
		if n > 0 {
			_, _ = client.Write(buf[:n])
		}
	}

	mbLimit := parseSpeedLimit(tc.SpeedLimitMBps)
	txW := newThrottledWriter(tlsConn, &appTxBytes, mbLimit)
	rxW := newThrottledWriter(client, &appRxBytes, mbLimit)

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(txW, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(rxW, tlsConn); done <- struct{}{} }()
	<-done
}
