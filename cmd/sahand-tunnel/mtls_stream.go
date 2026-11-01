package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	mtlsALPN = "sahand-mtls-v1"

	mtlsModeProbe      byte = 0x01
	mtlsModeParitySync byte = 0x02
	mtlsModeForward    byte = 0x03

	mtlsStatusOK          byte = 0x00
	mtlsStatusForbidden   byte = 0x01
	mtlsStatusUnreachable byte = 0x02
)

type mtlsPKIMaterial struct {
	rootPool   *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

// Deterministically derives a peer-specific Ed25519 Root CA, Server X.509 Certificate,
// and Client X.509 Certificate from the shared authKey so both Master and Agent can perform
// strict TLS 1.3 Mutual Authentication (tls.RequireAndVerifyClientCert).
func buildPeerMTLSPKI(authKey []byte, sni string) (*mtlsPKIMaterial, error) {
	if strings.TrimSpace(sni) == "" {
		sni = "www.speedtest.net"
	}

	deriveKey := func(label string) (ed25519.PublicKey, ed25519.PrivateKey) {
		mac := hmac.New(sha256.New, authKey)
		_, _ = mac.Write([]byte("sahand-mtls-pki-v1:" + label))
		seed := mac.Sum(nil)[:ed25519.SeedSize]
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		return pub, priv
	}

	caPub, caPriv := deriveKey("root-ca")
	srvPub, srvPriv := deriveKey("server-leaf")
	cliPub, cliPriv := deriveKey("client-leaf")

	notBefore := time.Unix(1700000000, 0).UTC()
	notAfter := time.Unix(2100000000, 0).UTC()
	caKeyID := sha256.Sum256(caPub)
	srvKeyID := sha256.Sum256(srvPub)
	cliKeyID := sha256.Sum256(cliPub)

	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Sahand mTLS Root Authority"},
			CommonName:   "Sahand-mTLS-CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          caKeyID[:20],
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Sahand mTLS Server"},
			CommonName:   sni,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          srvKeyID[:20],
		AuthorityKeyId:        caKeyID[:20],
		DNSNames:              []string{sni, "mtls.sahand.internal", "localhost"},
	}

	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, srvPub, caPriv)
	if err != nil {
		return nil, err
	}

	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Sahand mTLS Client"},
			CommonName:   "sahand-mtls-authenticated-client",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          cliKeyID[:20],
		AuthorityKeyId:        caKeyID[:20],
	}

	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, cliPub, caPriv)
	if err != nil {
		return nil, err
	}

	return &mtlsPKIMaterial{
		rootPool: rootPool,
		serverCert: tls.Certificate{
			Certificate: [][]byte{srvDER, caDER},
			PrivateKey:  srvPriv,
		},
		clientCert: tls.Certificate{
			Certificate: [][]byte{cliDER, caDER},
			PrivateKey:  cliPriv,
		},
	}, nil
}

func dialMTLSStreamSession(
	peer ServerPeer,
	tc TunnelConfig,
	mode byte,
	targetPort uint16,
	timeout time.Duration,
) (net.Conn, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return nil, err
	}

	sni := strings.TrimSpace(tc.SNI)
	if sni == "" {
		sni = "www.speedtest.net"
	}
	pki, err := buildPeerMTLSPKI(authKey, sni)
	if err != nil {
		return nil, err
	}

	pin := strings.TrimSpace(tc.CertPin)

	tlsCfg := &tls.Config{
		ServerName:         sni,
		Certificates:       []tls.Certificate{pki.clientCert},
		RootCAs:            pki.rootPool,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{mtlsALPN},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCertPin(rawCerts, pin)
		},
	}

	targetAddr := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, err
	}
	enableKeepAlive(rawConn)
	_ = rawConn.SetDeadline(time.Now().Add(timeout + 2*time.Second))

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	timeHdr := []byte(buildMasterTimeHeader())
	hdr := make([]byte, 4+len(timeHdr))
	hdr[0] = mode
	binary.BigEndian.PutUint16(hdr[1:3], targetPort)
	hdr[3] = byte(len(timeHdr))
	copy(hdr[4:], timeHdr)

	if _, err := tlsConn.Write(hdr); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	var status [1]byte
	if _, err := io.ReadFull(tlsConn, status[:]); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if status[0] != mtlsStatusOK {
		_ = tlsConn.Close()
		return nil, errors.New("mtls stream session rejected")
	}

	return tlsConn, nil
}

func startMTLSStreamServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
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
			go handleIncomingMTLSStreamConn(rawConn, peer, tc)
		}
	}()
	return ln, nil
}

func handleIncomingMTLSStreamConn(rawConn net.Conn, peer ServerPeer, tc TunnelConfig) {
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(12 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return
	}

	sni := strings.TrimSpace(tc.SNI)
	if sni == "" {
		sni = "www.speedtest.net"
	}
	pki, err := buildPeerMTLSPKI(authKey, sni)
	if err != nil {
		return
	}

	srvTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.rootPool,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{mtlsALPN},
	}

	tlsConn := tls.Server(rawConn, srvTLSCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	st := tlsConn.ConnectionState()
	if len(st.PeerCertificates) == 0 || st.PeerCertificates[0].Subject.CommonName != "sahand-mtls-authenticated-client" {
		return
	}

	var hdr [4]byte
	if _, err := io.ReadFull(tlsConn, hdr[:]); err != nil {
		return
	}
	mode := hdr[0]
	targetPort := binary.BigEndian.Uint16(hdr[1:3])
	tLen := int(hdr[3])
	if tLen > 0 {
		tBuf := make([]byte, tLen)
		if _, err := io.ReadFull(tlsConn, tBuf); err != nil {
			return
		}
		applyMasterTimeHeader(string(tBuf))
	}

	remoteHost, _, _ := net.SplitHostPort(rawConn.RemoteAddr().String())

	switch mode {
	case mtlsModeProbe:
		if _, err := tlsConn.Write([]byte{mtlsStatusOK}); err != nil {
			return
		}
		var ping [12]byte
		if _, err := io.ReadFull(tlsConn, ping[:]); err != nil {
			return
		}
		_, _ = tlsConn.Write(ping[:])
		markPeerConnectedInbound(peer.ID, remoteHost, tc.ID, tc.ListenPort, 1)

	case mtlsModeParitySync:
		if _, err := tlsConn.Write([]byte{mtlsStatusOK}); err != nil {
			return
		}
		handleRawTCPParitySyncServer(tlsConn, peer.ID, remoteHost)

	case mtlsModeForward:
		if !tc.Enabled {
			_, _ = tlsConn.Write([]byte{mtlsStatusForbidden})
			return
		}
		portStr := strconv.Itoa(int(targetPort))
		if targetPort == 0 {
			ports := parsePortList(tc.ForwardPorts)
			if len(ports) > 0 {
				portStr = ports[0]
			} else {
				portStr = strconv.Itoa(32000 + tc.ID)
			}
		}
		target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", portStr), 5*time.Second)
		if err != nil {
			_, _ = tlsConn.Write([]byte{mtlsStatusUnreachable})
			return
		}
		defer target.Close()
		enableKeepAlive(target)

		if _, err := tlsConn.Write([]byte{mtlsStatusOK}); err != nil {
			return
		}
		_ = tlsConn.SetDeadline(time.Time{})

		pipeRawTCPStreams(tlsConn, target, tc.SpeedLimitMBps)
	}
}

func probeMTLSStream(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	conn, err := dialMTLSStreamSession(peer, tc, mtlsModeProbe, uint16(tc.ListenPort), 4*time.Second)
	if err != nil {
		res.Success = false
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(msg, "certificate") || strings.Contains(msg, "tls") || strings.Contains(msg, "pin") {
			res.ErrorReason = "TLS failure"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}
	defer conn.Close()

	var ping [12]byte
	var pong [12]byte
	binary.BigEndian.PutUint32(ping[0:4], 1)
	binary.BigEndian.PutUint64(ping[4:12], uint64(time.Now().UnixNano()))

	if _, err := conn.Write(ping[:]); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}
	if _, err := io.ReadFull(conn, pong[:]); err != nil || !bytes.Equal(ping[:], pong[:]) {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}

	rtt := time.Since(start).Milliseconds()
	if rtt <= 0 {
		rtt = 1
	}
	res.Success = true
	res.LatencyMS = rtt
	res.MinLatencyMS = rtt
	res.MaxLatencyMS = rtt
	return res
}

func pushMTLSStreamParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	conn, err := dialMTLSStreamSession(peer, tc, mtlsModeParitySync, uint16(tc.ListenPort), 4*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

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
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := conn.Write(rawPkt); err != nil {
		return false
	}

	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBytes); err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func forwardMTLSStreamTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	portNum, _ := strconv.Atoi(strings.TrimSpace(targetPort))
	if portNum <= 0 {
		portNum = 32000 + tc.ID
	}

	conn, err := dialMTLSStreamSession(peer, tc, mtlsModeForward, uint16(portNum), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})

	pipeRawTCPStreams(conn, client, tc.SpeedLimitMBps)
}
