package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	noiseStealthProtocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	noiseStealthProtoVersion = 0x01

	noiseStealthModeProbe      byte = 0x01
	noiseStealthModeParitySync byte = 0x02
	noiseStealthModeTCPForward byte = 0x03
	noiseStealthModeUDPForward byte = 0x04

	noiseStealthStatusOK          byte = 0x00
	noiseStealthStatusForbidden   byte = 0x01
	noiseStealthStatusUnreachable byte = 0x02

	noiseStealthMaxPayload = 32 * 1024
	noiseStealthUDPIdleTTL = 60 * time.Second
)

// ============================================================================
// 1. NOISE_IK_25519_CHACHAPOLY_BLAKE2S WITH OBFUSCATED LENGTH HEADERS
// ============================================================================

type noiseStealthCipher struct {
	mu      sync.Mutex
	aead    cipher.AEAD
	n       uint64
	lenSalt [32]byte
}

func newNoiseStealthCipher(key [32]byte) (*noiseStealthCipher, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	salt := blake2s.Sum256(append([]byte("sahand-stealth-len-mask:"), key[:]...))
	return &noiseStealthCipher{
		aead:    aead,
		n:       0,
		lenSalt: salt,
	}, nil
}

func (sc *noiseStealthCipher) nextLenMask(seq uint64) [2]byte {
	var buf [40]byte
	copy(buf[0:32], sc.lenSalt[:])
	binary.LittleEndian.PutUint64(buf[32:40], seq)
	sum := blake2s.Sum256(buf[:])
	return [2]byte{sum[0], sum[1]}
}

func (sc *noiseStealthCipher) encrypt(ad, plaintext []byte) ([]byte, [2]byte, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.n == ^uint64(0) {
		return nil, [2]byte{}, errors.New("noise stealth nonce exhausted")
	}
	seq := sc.n
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:12], seq)
	sc.n++

	mask := sc.nextLenMask(seq)
	ct := sc.aead.Seal(nil, nonce[:], plaintext, ad)
	return ct, mask, nil
}

func (sc *noiseStealthCipher) decrypt(ad, ciphertext []byte) ([]byte, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.n == ^uint64(0) {
		return nil, errors.New("noise stealth nonce exhausted")
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:12], sc.n)
	sc.n++

	return sc.aead.Open(nil, nonce[:], ciphertext, ad)
}

func (sc *noiseStealthCipher) peekNextLenMask() [2]byte {
	sc.mu.Lock()
	seq := sc.n
	sc.mu.Unlock()
	return sc.nextLenMask(seq)
}

type noiseStealthSymmetricState struct {
	ck [32]byte
	h  [32]byte
	cs *noiseStealthCipher
}

func newNoiseStealthSymmetricState() *noiseStealthSymmetricState {
	ss := &noiseStealthSymmetricState{}
	nameBytes := []byte(noiseStealthProtocolName)
	if len(nameBytes) <= 32 {
		copy(ss.h[:], nameBytes)
	} else {
		ss.h = blake2s.Sum256(nameBytes)
	}
	ss.ck = ss.h
	ss.mixHash([]byte("sahand-noise-ik-stealth-v1"))
	return ss
}

func (ss *noiseStealthSymmetricState) mixHash(data []byte) {
	h, _ := blake2s.New256(nil)
	_, _ = h.Write(ss.h[:])
	_, _ = h.Write(data)
	copy(ss.h[:], h.Sum(nil))
}

func noiseStealthHMAC(key, data []byte) [32]byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	_, _ = mac.Write(data)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func noiseStealthHKDF2(ck [32]byte, ikm []byte) ([32]byte, [32]byte) {
	tempKey := noiseStealthHMAC(ck[:], ikm)
	out1 := noiseStealthHMAC(tempKey[:], []byte{0x01})
	in2 := append(out1[:], 0x02)
	out2 := noiseStealthHMAC(tempKey[:], in2)
	return out1, out2
}

func (ss *noiseStealthSymmetricState) mixKey(ikm []byte) error {
	var k [32]byte
	ss.ck, k = noiseStealthHKDF2(ss.ck, ikm)
	cs, err := newNoiseStealthCipher(k)
	if err != nil {
		return err
	}
	ss.cs = cs
	return nil
}

func (ss *noiseStealthSymmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	if ss.cs == nil {
		ss.mixHash(plaintext)
		return plaintext, nil
	}
	ct, _, err := ss.cs.encrypt(ss.h[:], plaintext)
	if err != nil {
		return nil, err
	}
	ss.mixHash(ct)
	return ct, nil
}

func (ss *noiseStealthSymmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if ss.cs == nil {
		ss.mixHash(ciphertext)
		return ciphertext, nil
	}
	pt, err := ss.cs.decrypt(ss.h[:], ciphertext)
	if err != nil {
		return nil, err
	}
	ss.mixHash(ciphertext)
	return pt, nil
}

func (ss *noiseStealthSymmetricState) split() (*noiseStealthCipher, *noiseStealthCipher, error) {
	k1, k2 := noiseStealthHKDF2(ss.ck, nil)
	c1, err := newNoiseStealthCipher(k1)
	if err != nil {
		return nil, nil, err
	}
	c2, err := newNoiseStealthCipher(k2)
	if err != nil {
		return nil, nil, err
	}
	return c1, c2, nil
}

func deriveNoiseStealthStaticKeypair(authKey []byte, domain string) (priv [32]byte, pub [32]byte, err error) {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte("noise-ik-static:" + domain))
	sum := mac.Sum(nil)
	copy(priv[:], sum[:32])
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pubSlice, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, err
	}
	copy(pub[:], pubSlice)
	return priv, pub, nil
}

func computeHandshakeLenMask(authKey []byte, ephemPub [32]byte) [2]byte {
	h, _ := blake2s.New256(nil)
	_, _ = h.Write([]byte("stealth-hs-mask:"))
	_, _ = h.Write(authKey)
	_, _ = h.Write(ephemPub[:])
	sum := h.Sum(nil)
	return [2]byte{sum[0], sum[1]}
}

type noiseStealthHandshakePayload struct {
	Version    int    `json:"v"`
	Mode       byte   `json:"m"`
	PeerID     string `json:"pid"`
	NodeID     string `json:"nid"`
	TargetPort string `json:"port,omitempty"`
	TimeHdr    string `json:"tm,omitempty"`
	Timestamp  int64  `json:"ts"`
	Padding    string `json:"pad"`
}

// noiseStealthConn wraps a net.Conn with Noise_IK and obfuscated 2-byte frame lengths.
type noiseStealthConn struct {
	net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
	rx      *noiseStealthCipher
	tx      *noiseStealthCipher
	readBuf bytes.Buffer
}

func (sc *noiseStealthConn) Write(p []byte) (int, error) {
	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > noiseStealthMaxPayload {
			chunk = p[:noiseStealthMaxPayload]
		}
		ct, mask, err := sc.tx.encrypt(nil, chunk)
		if err != nil {
			return total, err
		}
		frameLen := uint16(len(ct))
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], frameLen)
		hdr[0] ^= mask[0]
		hdr[1] ^= mask[1]

		if _, err := sc.Conn.Write(hdr[:]); err != nil {
			return total, err
		}
		if _, err := sc.Conn.Write(ct); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (sc *noiseStealthConn) Read(p []byte) (int, error) {
	sc.readMu.Lock()
	defer sc.readMu.Unlock()

	if sc.readBuf.Len() > 0 {
		return sc.readBuf.Read(p)
	}
	var hdr [2]byte
	if _, err := io.ReadFull(sc.Conn, hdr[:]); err != nil {
		return 0, err
	}
	mask := sc.rx.peekNextLenMask()
	hdr[0] ^= mask[0]
	hdr[1] ^= mask[1]
	frameLen := int(binary.BigEndian.Uint16(hdr[:]))
	if frameLen <= 0 || frameLen > noiseStealthMaxPayload+chacha20poly1305.Overhead {
		return 0, errors.New("invalid stealth frame length")
	}

	ct := make([]byte, frameLen)
	if _, err := io.ReadFull(sc.Conn, ct); err != nil {
		return 0, err
	}
	pt, err := sc.rx.decrypt(nil, ct)
	if err != nil {
		return 0, err
	}
	sc.readBuf.Write(pt)
	return sc.readBuf.Read(p)
}

// Client Handshake: Noise_IK_25519_ChaChaPoly_BLAKE2s
// Pre-message: <- s
// Message 1:   -> e, es, s, ss + encrypted payload (with random padding)
// Message 2:   <- e, ee, se + encrypted ack (with random padding)
func dialNoiseStealthSession(
	peer ServerPeer,
	tc TunnelConfig,
	mode byte,
	targetPort string,
	timeout time.Duration,
) (*noiseStealthConn, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return nil, err
	}

	// Responder static keypair & Initiator static keypair
	_, rsPub, err := deriveNoiseStealthStaticKeypair(authKey, "responder")
	if err != nil {
		return nil, err
	}
	isPriv, isPub, err := deriveNoiseStealthStaticKeypair(authKey, "initiator")
	if err != nil {
		return nil, err
	}

	targetAddr := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, err
	}
	enableKeepAlive(rawConn)
	_ = rawConn.SetDeadline(time.Now().Add(timeout + 2*time.Second))

	ss := newNoiseStealthSymmetricState()
	// Pre-message: <- s
	ss.mixHash(rsPub[:])

	// -> e
	ePriv, ePub, err := generateEphemeralX25519()
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	ss.mixHash(ePub[:])

	// -> es
	es, err := curve25519.X25519(ePriv[:], rsPub[:])
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if err := ss.mixKey(es); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	// -> s
	encS, err := ss.encryptAndHash(isPub[:])
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	// -> ss
	ssDH, err := curve25519.X25519(isPriv[:], rsPub[:])
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if err := ss.mixKey(ssDH); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	padHex, _ := randomHex(16 + randomIntN(64))
	hsPayload := noiseStealthHandshakePayload{
		Version:    noiseStealthProtoVersion,
		Mode:       mode,
		PeerID:     peer.ID,
		NodeID:     cfgSnapshot.NodeID,
		TargetPort: targetPort,
		TimeHdr:    buildMasterTimeHeader(),
		Timestamp:  time.Now().Unix(),
		Padding:    padHex,
	}
	rawPayload, err := json.Marshal(hsPayload)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	encPayload, err := ss.encryptAndHash(rawPayload)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	bodyLen := len(encS) + len(encPayload)
	mask1 := computeHandshakeLenMask(authKey, ePub)
	var lenHdr1 [2]byte
	binary.BigEndian.PutUint16(lenHdr1[:], uint16(bodyLen))
	lenHdr1[0] ^= mask1[0]
	lenHdr1[1] ^= mask1[1]

	msg1 := make([]byte, 0, 32+2+bodyLen)
	msg1 = append(msg1, ePub[:]...)
	msg1 = append(msg1, lenHdr1[:]...)
	msg1 = append(msg1, encS...)
	msg1 = append(msg1, encPayload...)

	if _, err := rawConn.Write(msg1); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	// Read Message 2: [rePub:32][obfLen:2][encAck]
	var reHdr [34]byte
	if _, err := io.ReadFull(rawConn, reHdr[:]); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	var rePub [32]byte
	copy(rePub[:], reHdr[0:32])
	mask2 := computeHandshakeLenMask(authKey, rePub)
	reHdr[32] ^= mask2[0]
	reHdr[33] ^= mask2[1]
	ackLen := int(binary.BigEndian.Uint16(reHdr[32:34]))
	if ackLen < chacha20poly1305.Overhead || ackLen > 2048 {
		_ = rawConn.Close()
		return nil, errors.New("invalid stealth handshake response length")
	}
	encAck := make([]byte, ackLen)
	if _, err := io.ReadFull(rawConn, encAck); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	// <- e
	ss.mixHash(rePub[:])
	// <- ee
	ee, err := curve25519.X25519(ePriv[:], rePub[:])
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if err := ss.mixKey(ee); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	// <- se
	se, err := curve25519.X25519(isPriv[:], rePub[:])
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if err := ss.mixKey(se); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	ackPlain, err := ss.decryptAndHash(encAck)
	if err != nil || len(ackPlain) == 0 || ackPlain[0] != noiseStealthStatusOK {
		_ = rawConn.Close()
		return nil, errors.New("stealth handshake rejected")
	}

	txCS, rxCS, err := ss.split()
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return &noiseStealthConn{
		Conn: rawConn,
		tx:   txCS,
		rx:   rxCS,
	}, nil
}

// Active-probing resistant silent tarpit: absorbs probe and closes without writing a single byte.
func silentDropProber(rawConn net.Conn) {
	jitter := time.Duration(60+randomIntN(160)) * time.Millisecond
	time.Sleep(jitter)
	_ = rawConn.Close()
}

func acceptNoiseStealthSession(
	rawConn net.Conn,
	peer ServerPeer,
) (*noiseStealthConn, noiseStealthHandshakePayload, error) {
	var hsPayload noiseStealthHandshakePayload

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		silentDropProber(rawConn)
		return nil, hsPayload, err
	}

	rsPriv, rsPub, err := deriveNoiseStealthStaticKeypair(authKey, "responder")
	if err != nil {
		silentDropProber(rawConn)
		return nil, hsPayload, err
	}
	_, expectedInitPub, err := deriveNoiseStealthStaticKeypair(authKey, "initiator")
	if err != nil {
		silentDropProber(rawConn)
		return nil, hsPayload, err
	}

	var initHdr [34]byte
	if _, err := io.ReadFull(rawConn, initHdr[:]); err != nil {
		silentDropProber(rawConn)
		return nil, hsPayload, err
	}
	var ePub [32]byte
	copy(ePub[:], initHdr[0:32])
	mask1 := computeHandshakeLenMask(authKey, ePub)
	initHdr[32] ^= mask1[0]
	initHdr[33] ^= mask1[1]
	bodyLen := int(binary.BigEndian.Uint16(initHdr[32:34]))

	// encS is 32 + 16 = 48 bytes; payload is at least 16 bytes
	if bodyLen < 64 || bodyLen > 4096 {
		silentDropProber(rawConn)
		return nil, hsPayload, errors.New("invalid stealth body length")
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(rawConn, body); err != nil {
		silentDropProber(rawConn)
		return nil, hsPayload, err
	}

	ss := newNoiseStealthSymmetricState()
	ss.mixHash(rsPub[:])
	ss.mixHash(ePub[:])

	es, err := curve25519.X25519(rsPriv[:], ePub[:])
	if err != nil {
		silentDropProber(rawConn)
		return nil, hsPayload, err
	}
	if err := ss.mixKey(es); err != nil {
		silentDropProber(rawConn)
		return nil, hsPayload, err
	}

	// Decrypt Initiator's static public key s (first 48 bytes of body)
	clientStaticPub, err := ss.decryptAndHash(body[0:48])
	if err != nil || !bytes.Equal(clientStaticPub, expectedInitPub[:]) {
		silentDropProber(rawConn)
		return nil, hsPayload, errors.New("stealth static key authentication failed")
	}

	var isPub [32]byte
	copy(isPub[:], clientStaticPub)
	ssDH, err := curve25519.X25519(rsPriv[:], isPub[:])
	if err != nil {
		silentDropProber(rawConn)
		return nil, hsPayload, err
	}
	if err := ss.mixKey(ssDH); err != nil {
		silentDropProber(rawConn)
		return nil, hsPayload, err
	}

	plainPayload, err := ss.decryptAndHash(body[48:])
	if err != nil {
		silentDropProber(rawConn)
		return nil, hsPayload, err
	}
	if err := json.Unmarshal(plainPayload, &hsPayload); err != nil || hsPayload.Version != noiseStealthProtoVersion {
		silentDropProber(rawConn)
		return nil, hsPayload, errors.New("invalid stealth handshake payload")
	}

	if hsPayload.TimeHdr != "" {
		applyMasterTimeHeader(hsPayload.TimeHdr)
	}

	// Build Message 2: <- e, ee, se
	rePriv, rePub, err := generateEphemeralX25519()
	if err != nil {
		_ = rawConn.Close()
		return nil, hsPayload, err
	}
	ss.mixHash(rePub[:])

	ee, err := curve25519.X25519(rePriv[:], ePub[:])
	if err != nil {
		_ = rawConn.Close()
		return nil, hsPayload, err
	}
	if err := ss.mixKey(ee); err != nil {
		_ = rawConn.Close()
		return nil, hsPayload, err
	}

	se, err := curve25519.X25519(rePriv[:], isPub[:])
	if err != nil {
		_ = rawConn.Close()
		return nil, hsPayload, err
	}
	if err := ss.mixKey(se); err != nil {
		_ = rawConn.Close()
		return nil, hsPayload, err
	}

	ackPadLen := 16 + randomIntN(48)
	ackPlain := make([]byte, 1+ackPadLen)
	ackPlain[0] = noiseStealthStatusOK
	_, _ = io.ReadFull(rand.Reader, ackPlain[1:])

	encAck, err := ss.encryptAndHash(ackPlain)
	if err != nil {
		_ = rawConn.Close()
		return nil, hsPayload, err
	}

	mask2 := computeHandshakeLenMask(authKey, rePub)
	var lenHdr2 [2]byte
	binary.BigEndian.PutUint16(lenHdr2[:], uint16(len(encAck)))
	lenHdr2[0] ^= mask2[0]
	lenHdr2[1] ^= mask2[1]

	msg2 := make([]byte, 0, 32+2+len(encAck))
	msg2 = append(msg2, rePub[:]...)
	msg2 = append(msg2, lenHdr2[:]...)
	msg2 = append(msg2, encAck...)

	if _, err := rawConn.Write(msg2); err != nil {
		_ = rawConn.Close()
		return nil, hsPayload, err
	}

	rxCS, txCS, err := ss.split()
	if err != nil {
		_ = rawConn.Close()
		return nil, hsPayload, err
	}
	return &noiseStealthConn{
		Conn: rawConn,
		tx:   txCS,
		rx:   rxCS,
	}, hsPayload, nil
}

// ============================================================================
// 2. SERVER LISTENER & ENGINE 1 / ENGINE 2 DISPATCH
// ============================================================================

var (
	noiseStealthMu          sync.RWMutex
	noiseStealthExitUDPMux  = make(map[string]*noiseStealthUDPExitManager)
	noiseStealthEntryUDPMux = make(map[string]*noiseStealthUDPEntryManager)
)

func stopNoiseStealthPeerResources(peerID string) {
	noiseStealthMu.Lock()
	if exitMux, ok := noiseStealthExitUDPMux[peerID]; ok {
		exitMux.closeAll()
		delete(noiseStealthExitUDPMux, peerID)
	}
	for k, entryMux := range noiseStealthEntryUDPMux {
		if strings.HasPrefix(k, peerID+"|") {
			entryMux.closeAll()
			delete(noiseStealthEntryUDPMux, k)
		}
	}
	noiseStealthMu.Unlock()
}

func startNoiseStealthServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}

	noiseStealthMu.Lock()
	if old, ok := noiseStealthExitUDPMux[peer.ID]; ok {
		old.closeAll()
	}
	exitMux := newNoiseStealthUDPExitManager(tc.SpeedLimitMBps)
	noiseStealthExitUDPMux[peer.ID] = exitMux
	noiseStealthMu.Unlock()

	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			enableKeepAlive(rawConn)
			go handleIncomingNoiseStealthConn(rawConn, peer, tc, exitMux)
		}
	}()
	return ln, nil
}

func handleIncomingNoiseStealthConn(
	rawConn net.Conn,
	peer ServerPeer,
	tc TunnelConfig,
	exitMux *noiseStealthUDPExitManager,
) {
	_ = rawConn.SetDeadline(time.Now().Add(12 * time.Second))

	sc, hs, err := acceptNoiseStealthSession(rawConn, peer)
	if err != nil {
		return
	}
	defer sc.Close()

	remoteHost, _, _ := net.SplitHostPort(rawConn.RemoteAddr().String())
	effectivePeerID := peer.ID
	if hs.PeerID != "" {
		effectivePeerID = hs.PeerID
	}

	switch hs.Mode {
	case noiseStealthModeProbe:
		var ping [12]byte
		if _, err := io.ReadFull(sc, ping[:]); err != nil {
			return
		}
		_, _ = sc.Write(ping[:])
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)

	case noiseStealthModeParitySync:
		handleNoiseStealthParitySyncServer(sc, effectivePeerID, remoteHost)

	case noiseStealthModeTCPForward:
		if !tc.Enabled {
			_, _ = sc.Write([]byte{noiseStealthStatusForbidden})
			return
		}
		_ = sc.SetDeadline(time.Time{})
		targetPort := strings.TrimSpace(hs.TargetPort)
		if targetPort == "" {
			ports := parsePortList(tc.ForwardPorts)
			if len(ports) > 0 {
				targetPort = ports[0]
			} else {
				targetPort = "2053"
			}
		}
		target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", targetPort), 5*time.Second)
		if err != nil {
			_, _ = sc.Write([]byte{noiseStealthStatusUnreachable})
			return
		}
		defer target.Close()
		enableKeepAlive(target)

		if _, err := sc.Write([]byte{noiseStealthStatusOK}); err != nil {
			return
		}
		pipeNoiseStealthAndTCP(sc, target, tc.SpeedLimitMBps)

	case noiseStealthModeUDPForward:
		if !tc.Enabled || exitMux == nil {
			return
		}
		_ = sc.SetDeadline(time.Time{})
		portNum, _ := strconv.Atoi(strings.TrimSpace(hs.TargetPort))
		if portNum <= 0 {
			portNum = 2053
		}
		exitMux.serveUDPChannel(sc, uint16(portNum))
	}
}

// ============================================================================
// 3. ENGINE 1: PROBE & PARITY SYNC
// ============================================================================

func probeNoiseStealth(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	sc, err := dialNoiseStealthSession(peer, tc, noiseStealthModeProbe, fmt.Sprintf("probe:%d", tc.ListenPort), 4*time.Second)
	if err != nil {
		res.Success = false
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else if strings.Contains(err.Error(), "stealth") || strings.Contains(err.Error(), "auth") {
			res.ErrorReason = "Authentication failure"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}
	defer sc.Close()

	var ping [12]byte
	var pong [12]byte
	binary.BigEndian.PutUint32(ping[0:4], 1)
	binary.BigEndian.PutUint64(ping[4:12], uint64(time.Now().UnixNano()))

	if _, err := sc.Write(ping[:]); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}
	if _, err := io.ReadFull(sc, pong[:]); err != nil || !bytes.Equal(ping[:], pong[:]) {
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

func pushNoiseStealthParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	sc, err := dialNoiseStealthSession(peer, tc, noiseStealthModeParitySync, strconv.Itoa(tc.ListenPort), 4*time.Second)
	if err != nil {
		return false
	}
	defer sc.Close()

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
	if _, err := sc.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := sc.Write(rawPkt); err != nil {
		return false
	}

	if _, err := io.ReadFull(sc, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(sc, respBytes); err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func handleNoiseStealthParitySyncServer(sc *noiseStealthConn, effectivePeerID, remoteHost string) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(sc, lenBuf[:]); err != nil {
		return
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen == 0 || pktLen > 256*1024 {
		return
	}
	rawPkt := make([]byte, pktLen)
	if _, err := io.ReadFull(sc, rawPkt); err != nil {
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
	_, _ = sc.Write(lenBuf[:])
	_, _ = sc.Write(respBytes)
}

// ============================================================================
// 4. ENGINE 2: BIDIRECTIONAL TCP & UDP FORWARDING
// ============================================================================

func forwardNoiseStealthTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	sc, err := dialNoiseStealthSession(peer, tc, noiseStealthModeTCPForward, targetPort, 5*time.Second)
	if err != nil {
		return
	}
	defer sc.Close()

	var status [1]byte
	if _, err := io.ReadFull(sc, status[:]); err != nil || status[0] != noiseStealthStatusOK {
		return
	}
	_ = sc.SetDeadline(time.Time{})

	pipeNoiseStealthAndTCP(sc, client, tc.SpeedLimitMBps)
}

func pipeNoiseStealthAndTCP(sc *noiseStealthConn, tcpConn net.Conn, speedLimitMBps string) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	toStealth := newThrottledWriter(sc, &appTxBytes, mbLimit)
	toTCP := newThrottledWriter(tcpConn, &appRxBytes, mbLimit)

	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toStealth, tcpConn, buf)
		_ = sc.Close()
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toTCP, sc, buf)
		if tc, ok := tcpConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}

type noiseStealthUDPEntrySession struct {
	sessionID    uint32
	clientAddr   *net.UDPAddr
	entryConn    *net.UDPConn
	lastActivity atomic.Int64
}

type noiseStealthUDPEntryManager struct {
	mu          sync.RWMutex
	peer        ServerPeer
	tunnel      TunnelConfig
	targetPort  uint16
	byAddr      map[string]*noiseStealthUDPEntrySession
	bySessionID map[uint32]*noiseStealthUDPEntrySession
	nextID      atomic.Uint32
	scMu        sync.Mutex
	sc          *noiseStealthConn
	limiter     io.Writer
	stopCh      chan struct{}
	closed      atomic.Bool
}

func newNoiseStealthUDPEntryManager(peer ServerPeer, tc TunnelConfig, targetPort uint16) *noiseStealthUDPEntryManager {
	m := &noiseStealthUDPEntryManager{
		peer:        peer,
		tunnel:      tc,
		targetPort:  targetPort,
		byAddr:      make(map[string]*noiseStealthUDPEntrySession),
		bySessionID: make(map[uint32]*noiseStealthUDPEntrySession),
		limiter:     newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(tc.SpeedLimitMBps)),
		stopCh:      make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *noiseStealthUDPEntryManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Unix() - int64(noiseStealthUDPIdleTTL.Seconds())
			m.mu.Lock()
			for k, s := range m.byAddr {
				if s.lastActivity.Load() < cutoff {
					delete(m.byAddr, k)
					delete(m.bySessionID, s.sessionID)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *noiseStealthUDPEntryManager) closeAll() {
	if m.closed.Swap(true) {
		return
	}
	close(m.stopCh)
	m.scMu.Lock()
	if m.sc != nil {
		_ = m.sc.Close()
		m.sc = nil
	}
	m.scMu.Unlock()
}

func (m *noiseStealthUDPEntryManager) getOrCreateSession(entryConn *net.UDPConn, clientAddr *net.UDPAddr) *noiseStealthUDPEntrySession {
	key := clientAddr.String()
	now := time.Now().Unix()

	m.mu.RLock()
	if s, ok := m.byAddr[key]; ok {
		s.lastActivity.Store(now)
		m.mu.RUnlock()
		return s
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.byAddr[key]; ok {
		s.lastActivity.Store(now)
		return s
	}
	sid := m.nextID.Add(1)
	if sid == 0 {
		sid = m.nextID.Add(1)
	}
	addrCopy := &net.UDPAddr{
		IP:   append([]byte(nil), clientAddr.IP...),
		Port: clientAddr.Port,
		Zone: clientAddr.Zone,
	}
	s := &noiseStealthUDPEntrySession{
		sessionID:  sid,
		clientAddr: addrCopy,
		entryConn:  entryConn,
	}
	s.lastActivity.Store(now)
	m.byAddr[key] = s
	m.bySessionID[sid] = s
	return s
}

func (m *noiseStealthUDPEntryManager) getOrOpenChannel() (*noiseStealthConn, error) {
	m.scMu.Lock()
	defer m.scMu.Unlock()

	if m.sc != nil {
		return m.sc, nil
	}
	sc, err := dialNoiseStealthSession(m.peer, m.tunnel, noiseStealthModeUDPForward, strconv.Itoa(int(m.targetPort)), 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = sc.SetDeadline(time.Time{})
	m.sc = sc
	go m.readRepliesLoop(sc)
	return sc, nil
}

func (m *noiseStealthUDPEntryManager) readRepliesLoop(sc *noiseStealthConn) {
	defer func() {
		_ = sc.Close()
		m.scMu.Lock()
		if m.sc == sc {
			m.sc = nil
		}
		m.scMu.Unlock()
	}()

	var hdr [8]byte
	for {
		if _, err := io.ReadFull(sc, hdr[:]); err != nil {
			return
		}
		sid := binary.BigEndian.Uint32(hdr[0:4])
		pktLen := int(binary.BigEndian.Uint16(hdr[6:8]))
		if pktLen <= 0 || pktLen > 65507 {
			return
		}
		payload := make([]byte, pktLen)
		if _, err := io.ReadFull(sc, payload); err != nil {
			return
		}
		m.mu.RLock()
		sess, ok := m.bySessionID[sid]
		m.mu.RUnlock()
		if ok {
			sess.lastActivity.Store(time.Now().Unix())
			atomic.AddUint64(&appRxBytes, uint64(len(payload)))
			_, _ = sess.entryConn.WriteToUDP(payload, sess.clientAddr)
		}
	}
}

func (m *noiseStealthUDPEntryManager) handleClientPacket(entryConn *net.UDPConn, clientAddr *net.UDPAddr, payload []byte) {
	if len(payload) == 0 || len(payload) > 16384 {
		return
	}
	sess := m.getOrCreateSession(entryConn, clientAddr)
	sc, err := m.getOrOpenChannel()
	if err != nil {
		return
	}
	_, _ = m.limiter.Write(payload)

	frame := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], sess.sessionID)
	binary.BigEndian.PutUint16(frame[4:6], m.targetPort)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[8:], payload)

	if _, err := sc.Write(frame); err != nil {
		_ = sc.Close()
	}
}

type noiseStealthUDPExitSession struct {
	sessionID    uint32
	targetPort   uint16
	localConn    *net.UDPConn
	lastActivity atomic.Int64
	closed       atomic.Bool
}

type noiseStealthUDPExitManager struct {
	mu       sync.RWMutex
	sessions map[uint32]*noiseStealthUDPExitSession
	limiter  io.Writer
	stopCh   chan struct{}
	closed   atomic.Bool
}

func newNoiseStealthUDPExitManager(speedLimitMBps string) *noiseStealthUDPExitManager {
	m := &noiseStealthUDPExitManager{
		sessions: make(map[uint32]*noiseStealthUDPExitSession),
		limiter:  newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(speedLimitMBps)),
		stopCh:   make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *noiseStealthUDPExitManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Unix() - int64(noiseStealthUDPIdleTTL.Seconds())
			m.mu.Lock()
			for sid, s := range m.sessions {
				if s.lastActivity.Load() < cutoff {
					if s.closed.CompareAndSwap(false, true) {
						_ = s.localConn.Close()
					}
					delete(m.sessions, sid)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *noiseStealthUDPExitManager) closeAll() {
	if m.closed.Swap(true) {
		return
	}
	close(m.stopCh)
	m.mu.Lock()
	for sid, s := range m.sessions {
		if s.closed.CompareAndSwap(false, true) {
			_ = s.localConn.Close()
		}
		delete(m.sessions, sid)
	}
	m.mu.Unlock()
}

func (m *noiseStealthUDPExitManager) serveUDPChannel(sc *noiseStealthConn, defaultPort uint16) {
	defer sc.Close()
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(sc, hdr[:]); err != nil {
			return
		}
		sid := binary.BigEndian.Uint32(hdr[0:4])
		tPort := binary.BigEndian.Uint16(hdr[4:6])
		pktLen := int(binary.BigEndian.Uint16(hdr[6:8]))
		if pktLen <= 0 || pktLen > 65507 {
			return
		}
		if tPort == 0 {
			tPort = defaultPort
		}
		payload := make([]byte, pktLen)
		if _, err := io.ReadFull(sc, payload); err != nil {
			return
		}

		sess, err := m.getOrCreateExitSession(sc, sid, tPort)
		if err != nil {
			continue
		}
		sess.lastActivity.Store(time.Now().Unix())
		atomic.AddUint64(&appRxBytes, uint64(len(payload)))
		_, _ = sess.localConn.Write(payload)
	}
}

func (m *noiseStealthUDPExitManager) getOrCreateExitSession(
	sc *noiseStealthConn,
	sid uint32,
	targetPort uint16,
) (*noiseStealthUDPExitSession, error) {
	now := time.Now().Unix()
	m.mu.RLock()
	if s, ok := m.sessions[sid]; ok && !s.closed.Load() {
		s.lastActivity.Store(now)
		m.mu.RUnlock()
		return s, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sid]; ok && !s.closed.Load() {
		s.lastActivity.Store(now)
		return s, nil
	}
	dstAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(targetPort)}
	localUDP, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		return nil, err
	}
	s := &noiseStealthUDPExitSession{
		sessionID:  sid,
		targetPort: targetPort,
		localConn:  localUDP,
	}
	s.lastActivity.Store(now)
	m.sessions[sid] = s

	go func(sess *noiseStealthUDPExitSession) {
		defer func() {
			if sess.closed.CompareAndSwap(false, true) {
				_ = sess.localConn.Close()
			}
			m.mu.Lock()
			if cur, ok := m.sessions[sess.sessionID]; ok && cur == sess {
				delete(m.sessions, sess.sessionID)
			}
			m.mu.Unlock()
		}()
		buf := make([]byte, 16384)
		for {
			_ = sess.localConn.SetReadDeadline(time.Now().Add(noiseStealthUDPIdleTTL))
			n, err := sess.localConn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				sess.lastActivity.Store(time.Now().Unix())
				_, _ = m.limiter.Write(buf[:n])
				frame := make([]byte, 8+n)
				binary.BigEndian.PutUint32(frame[0:4], sess.sessionID)
				binary.BigEndian.PutUint16(frame[4:6], sess.targetPort)
				binary.BigEndian.PutUint16(frame[6:8], uint16(n))
				copy(frame[8:], buf[:n])
				if _, wErr := sc.Write(frame); wErr != nil {
					return
				}
			}
		}
	}(s)

	return s, nil
}

func startNoiseStealthUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
	portNum, err := strconv.Atoi(strings.TrimSpace(targetPort))
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(portNum)))
	if err != nil {
		return nil
	}
	entryConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil
	}

	muxKey := fmt.Sprintf("%s|%d", peer.ID, portNum)
	noiseStealthMu.Lock()
	if old, ok := noiseStealthEntryUDPMux[muxKey]; ok {
		old.closeAll()
	}
	mgr := newNoiseStealthUDPEntryManager(peer, tc, uint16(portNum))
	noiseStealthEntryUDPMux[muxKey] = mgr
	noiseStealthMu.Unlock()

	go func() {
		defer mgr.closeAll()
		buf := make([]byte, 16384)
		for {
			n, clientAddr, err := entryConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				mgr.handleClientPacket(entryConn, clientAddr, pkt)
			}
		}
	}()
	return entryConn
}
