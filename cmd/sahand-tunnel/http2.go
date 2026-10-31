package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	h2ClientPreface  = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	h2PrefaceTail    = "\r\nSM\r\n\r\n"
	h2FrameData      = 0x0
	h2FrameHeaders   = 0x1
	h2FrameSettings  = 0x4
	h2FramePing      = 0x6
	h2FlagEndStream  = 0x1
	h2FlagAck        = 0x1
	h2FlagEndHeaders = 0x4
)

type h2ConnWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (hw *h2ConnWriter) writeFrame(frameType, flags byte, streamID uint32, payload []byte) error {
	hw.mu.Lock()
	defer hw.mu.Unlock()

	length := len(payload)
	var hdr [9]byte
	hdr[0] = byte(length >> 16)
	hdr[1] = byte(length >> 8)
	hdr[2] = byte(length)
	hdr[3] = frameType
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:9], streamID&0x7fffffff)

	if _, err := hw.w.Write(hdr[:]); err != nil {
		return err
	}
	if length > 0 {
		if _, err := hw.w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readH2Frame(r io.Reader) (byte, byte, uint32, []byte, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	length := (int(hdr[0]) << 16) | (int(hdr[1]) << 8) | int(hdr[2])
	if length > 65536 {
		return 0, 0, 0, nil, errors.New("http2 frame exceeds max size")
	}
	frameType := hdr[3]
	flags := hdr[4]
	streamID := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, 0, 0, nil, err
		}
	}
	return frameType, flags, streamID, payload, nil
}

func encodeH2MetaBlock(kv map[string]string) []byte {
	var sb strings.Builder
	for k, v := range kv {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(v)
		sb.WriteString("\n")
	}
	return []byte(sb.String())
}

func decodeH2MetaBlock(b []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}

func probeHTTP2(peer ServerPeer, tc TunnelConfig, localNodeID string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  time.Now().UTC().Format("15:04:05 UTC"),
	}

	targetAddr := fmt.Sprintf("%s:%d", peer.IP, tc.ListenPort)
	start := time.Now()
	dialer := &net.Dialer{Timeout: 4 * time.Second}
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
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

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
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		res.Success = false
		res.ErrorReason = "TLS failure"
		return res
	}
	defer tlsConn.Close()

	if _, err := tlsConn.Write([]byte(h2ClientPreface)); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	hw := &h2ConnWriter{w: tlsConn}
	if err := hw.writeFrame(h2FrameSettings, 0, 0, nil); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	meta := encodeH2MetaBlock(map[string]string{
		":method":       "POST",
		":path":         "/api/v1/stream",
		":authority":    sni,
		"x-sahand-peer": peer.ID,
		"x-sahand-node": localNodeID,
		"x-target-port": fmt.Sprintf("probe:%d", tc.ListenPort),
	})
	if err := hw.writeFrame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, meta); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	for i := 0; i < 6; i++ {
		fType, flags, streamID, payload, err := readH2Frame(tlsConn)
		if err != nil {
			res.Success = false
			res.ErrorReason = "Timeout"
			return res
		}
		if fType == h2FrameSettings && (flags&h2FlagAck) == 0 {
			_ = hw.writeFrame(h2FrameSettings, h2FlagAck, 0, nil)
			continue
		}
		if fType == h2FrameHeaders && streamID == 1 {
			headers := decodeH2MetaBlock(payload)
			if headers[":status"] == "200" {
				res.Success = true
				res.LatencyMS = time.Since(start).Milliseconds()
				if res.LatencyMS <= 0 {
					res.LatencyMS = 1
				}
				return res
			}
			res.Success = false
			res.ErrorReason = "Protocol mismatch"
			return res
		}
	}

	res.Success = false
	res.ErrorReason = "Protocol mismatch"
	return res
}

func handleH2IncomingConn(conn net.Conn, br *bufio.Reader, peerID, remoteHost string, tc TunnelConfig) {
	tail := make([]byte, len(h2PrefaceTail))
	if _, err := io.ReadFull(br, tail); err != nil || string(tail) != h2PrefaceTail {
		return
	}

	hw := &h2ConnWriter{w: conn}
	if err := hw.writeFrame(h2FrameSettings, 0, 0, nil); err != nil {
		return
	}

	var reqHeaders map[string]string
	for i := 0; i < 6; i++ {
		fType, flags, streamID, payload, err := readH2Frame(br)
		if err != nil {
			return
		}
		if fType == h2FrameSettings && (flags&h2FlagAck) == 0 {
			_ = hw.writeFrame(h2FrameSettings, h2FlagAck, 0, nil)
			continue
		}
		if fType == h2FrameHeaders && streamID == 1 {
			reqHeaders = decodeH2MetaBlock(payload)
			break
		}
	}
	if reqHeaders == nil {
		return
	}

	effectivePeerID := peerID
	if p := reqHeaders["x-sahand-peer"]; p != "" {
		effectivePeerID = p
	}
	targetPort := reqHeaders["x-target-port"]

	if strings.HasPrefix(targetPort, "probe:") {
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)
		respMeta := encodeH2MetaBlock(map[string]string{
			":status":      "200",
			"content-type": "application/octet-stream",
		})
		_ = hw.writeFrame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, respMeta)
		return
	}

	if !tc.Enabled {
		respMeta := encodeH2MetaBlock(map[string]string{":status": "403"})
		_ = hw.writeFrame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, respMeta)
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

	target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		respMeta := encodeH2MetaBlock(map[string]string{":status": "502"})
		_ = hw.writeFrame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, respMeta)
		return
	}
	defer target.Close()
	enableKeepAlive(target)

	respMeta := encodeH2MetaBlock(map[string]string{
		":status":      "200",
		"content-type": "application/octet-stream",
	})
	if err := hw.writeFrame(h2FrameHeaders, h2FlagEndHeaders, 1, respMeta); err != nil {
		return
	}

	pumpH2Stream(br, hw, target, tc.SpeedLimitMBps, true)
}

func forwardHTTP2Traffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
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
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	if _, err := tlsConn.Write([]byte(h2ClientPreface)); err != nil {
		return
	}

	hw := &h2ConnWriter{w: tlsConn}
	if err := hw.writeFrame(h2FrameSettings, 0, 0, nil); err != nil {
		return
	}

	meta := encodeH2MetaBlock(map[string]string{
		":method":       "POST",
		":path":         "/api/v1/stream",
		":authority":    sni,
		"x-sahand-peer": peer.ID,
		"x-target-port": targetPort,
	})
	if err := hw.writeFrame(h2FrameHeaders, h2FlagEndHeaders, 1, meta); err != nil {
		return
	}

	br := bufio.NewReader(tlsConn)
	established := false
	for i := 0; i < 6; i++ {
		fType, flags, streamID, payload, err := readH2Frame(br)
		if err != nil {
			return
		}
		if fType == h2FrameSettings && (flags&h2FlagAck) == 0 {
			_ = hw.writeFrame(h2FrameSettings, h2FlagAck, 0, nil)
			continue
		}
		if fType == h2FrameHeaders && streamID == 1 {
			headers := decodeH2MetaBlock(payload)
			if headers[":status"] == "200" {
				established = true
			}
			break
		}
	}
	if !established {
		return
	}

	pumpH2Stream(br, hw, client, tc.SpeedLimitMBps, false)
}

func pumpH2Stream(h2Reader io.Reader, hw *h2ConnWriter, rawPeer net.Conn, speedLimitMBps string, isServer bool) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	var rxCounter, txCounter *uint64
	if isServer {
		rxCounter = &appRxBytes
		txCounter = &appTxBytes
	} else {
		rxCounter = &appRxBytes
		txCounter = &appTxBytes
	}
	rawPeerWriter := newThrottledWriter(rawPeer, rxCounter, mbLimit)
	throttledH2Counter := newThrottledWriter(io.Discard, txCounter, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	// H2 DATA Frames -> Raw TCP Socket
	go func() {
		defer wg.Done()
		for {
			fType, flags, streamID, payload, err := readH2Frame(h2Reader)
			if err != nil {
				if tcp, ok := rawPeer.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
				return
			}
			switch fType {
			case h2FrameData:
				if streamID == 1 && len(payload) > 0 {
					if _, wErr := rawPeerWriter.Write(payload); wErr != nil {
						return
					}
				}
				if streamID == 1 && (flags&h2FlagEndStream) != 0 {
					if tcp, ok := rawPeer.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
					return
				}
			case h2FramePing:
				if (flags & h2FlagAck) == 0 {
					_ = hw.writeFrame(h2FramePing, h2FlagAck, 0, payload)
				}
			case h2FrameSettings:
				if (flags & h2FlagAck) == 0 {
					_ = hw.writeFrame(h2FrameSettings, h2FlagAck, 0, nil)
				}
			}
		}
	}()

	// Raw TCP Socket -> H2 DATA Frames
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := rawPeer.Read(buf)
			if n > 0 {
				_, _ = throttledH2Counter.Write(buf[:n])
				if wErr := hw.writeFrame(h2FrameData, 0, 1, buf[:n]); wErr != nil {
					_ = rawPeer.Close()
					return
				}
			}
			if err != nil {
				_ = hw.writeFrame(h2FrameData, h2FlagEndStream, 1, nil)
				return
			}
		}
	}()

	wg.Wait()
}
