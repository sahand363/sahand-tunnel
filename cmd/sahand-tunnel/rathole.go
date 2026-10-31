package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	ratholeNoiseProtocolName = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
	ratholeProtoVersion      = 0x01

	// Rathole Hello Types
	ratholeHelloControlChannel byte = 0x00
	ratholeHelloDataChannel    byte = 0x01
	ratholeHelloProbe          byte = 0x02
	ratholeHelloParitySync     byte = 0x03
	ratholeHelloDirectForward  byte = 0x04

	// Rathole Ack Statuses
	ratholeAckOK              byte = 0x00
	ratholeAckAuthFailed      byte = 0x01
	ratholeAckServiceNotExist byte = 0x02

	// Rathole Control Channel Commands (Server -> Client)
	ratholeCmdCreateDataChannel byte = 0x00
	ratholeCmdHeartBeat         byte = 0x01
	ratholeCmdHeartBeatAck      byte = 0x02

	// Rathole Data Channel Commands
	ratholeDataCmdStartForwardTCP byte = 0x00
	ratholeDataCmdStartForwardUDP byte = 0x01

	ratholeMaxFramePayload     = 32 * 1024
	ratholeMaxWireFrame        = 65535
	ratholePendingHandoverWait = 6 * time.Second
	ratholeUDPIdleTTL          = 60 * time.Second
)

// ============================================================================
// 1. GENUINE NOISE_NK_25519_CHACHAPOLY_BLAKE2S CRYPTO TRANSPORT
// ============================================================================

type ratholeCipherState struct {
	mu   sync.Mutex
	aead cipher.AEAD
	n    uint64
}

func newRatholeCipherState(key [32]byte) (*ratholeCipherState, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &ratholeCipherState{aead: aead, n: 0}, nil
}

func (cs *ratholeCipherState) encrypt(ad, plaintext []byte) ([]byte, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.n == ^uint64(0) {
		return nil, errors.New("noise nonce counter exhausted")
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:12], cs.n)
	cs.n++

	return cs.aead.Seal(nil, nonce[:], plaintext, ad), nil
}

func (cs *ratholeCipherState) decrypt(ad, ciphertext []byte) ([]byte, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.n == ^uint64(0) {
		return nil, errors.New("noise nonce counter exhausted")
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:12], cs.n)
	cs.n++

	return cs.aead.Open(nil, nonce[:], ciphertext, ad)
}

type ratholeSymmetricState struct {
	ck [32]byte
	h  [32]byte
	cs *ratholeCipherState
}

func newRatholeSymmetricState() *ratholeSymmetricState {
	ss := &ratholeSymmetricState{}
	nameBytes := []byte(ratholeNoiseProtocolName)
	if len(nameBytes) <= 32 {
		copy(ss.h[:], nameBytes)
	} else {
		ss.h = blake2s.Sum256(nameBytes)
	}
	ss.ck = ss.h
	// Empty prologue
	ss.mixHash(nil)
	return ss
}

func (ss *ratholeSymmetricState) mixHash(data []byte) {
	h, _ := blake2s.New256(nil)
	_, _ = h.Write(ss.h[:])
	_, _ = h.Write(data)
	copy(ss.h[:], h.Sum(nil))
}

func ratholeHMACBlake2s(key, data []byte) [32]byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	_, _ = mac.Write(data)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func ratholeHKDF2(ck [32]byte, ikm []byte) ([32]byte, [32]byte) {
	tempKey := ratholeHMACBlake2s(ck[:], ikm)
	out1 := ratholeHMACBlake2s(tempKey[:], []byte{0x01})
	in2 := append(out1[:], 0x02)
	out2 := ratholeHMACBlake2s(tempKey[:], in2)
	return out1, out2
}

func (ss *ratholeSymmetricState) mixKey(ikm []byte) error {
	var k [32]byte
	ss.ck, k = ratholeHKDF2(ss.ck, ikm)
	cs, err := newRatholeCipherState(k)
	if err != nil {
		return err
	}
	ss.cs = cs
	return nil
}

func (ss *ratholeSymmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	if ss.cs == nil {
		ss.mixHash(plaintext)
		return plaintext, nil
	}
	ct, err := ss.cs.encrypt(ss.h[:], plaintext)
	if err != nil {
		return nil, err
	}
	ss.mixHash(ct)
	return ct, nil
}

func (ss *ratholeSymmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
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

func (ss *ratholeSymmetricState) split() (*ratholeCipherState, *ratholeCipherState, error) {
	k1, k2 := ratholeHKDF2(ss.ck, nil)
	c1, err := newRatholeCipherState(k1)
	if err != nil {
		return nil, nil, err
	}
	c2, err := newRatholeCipherState(k2)
	if err != nil {
		return nil, nil, err
	}
	return c1, c2, nil
}

// Deterministically derives the peer's static X25519 keypair for the Noise_NK pre-message (<- s)
func deriveRatholeStaticKeypair(authKey []byte) (priv [32]byte, pub [32]byte, err error) {
	h := hmac.New(sha256.New, authKey)
	_, _ = h.Write([]byte("rathole-noise-nk-static-x25519-v1"))
	sum := h.Sum(nil)
	copy(priv[:], sum[:32])
	// Clamp X25519 private scalar per RFC 7748
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

func generateEphemeralX25519() (priv [32]byte, pub [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return priv, pub, err
	}
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

// ratholeNoiseConn wraps a raw TCP net.Conn with Noise_NK_25519_ChaChaPoly_BLAKE2s framing.
type ratholeNoiseConn struct {
	 net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
	rx      *ratholeCipherState
	tx      *ratholeCipherState
	readBuf bytes.Buffer
}

func writeNoiseWireFrame(w io.Writer, payload []byte) error {
	if len(payload) > ratholeMaxWireFrame {
		return errors.New("noise frame exceeds max uint16 size")
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readNoiseWireFrame(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if frameLen == 0 {
		return nil, errors.New("empty noise frame")
	}
	buf := make([]byte, frameLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Initiator handshake: Noise_NK_25519_ChaChaPoly_BLAKE2s
// Pre-message: <- s
// Message 1:   -> e, es
// Message 2:   <- e, ee
func performRatholeClientNoiseHandshake(rawConn net.Conn, serverStaticPub [32]byte) (*ratholeNoiseConn, error) {
	ss := newRatholeSymmetricState()
	// Pre-message: <- s
	ss.mixHash(serverStaticPub[:])

	// -> e, es
	ePriv, ePub, err := generateEphemeralX25519()
	if err != nil {
		return nil, err
	}
	ss.mixHash(ePub[:])

	es, err := curve25519.X25519(ePriv[:], serverStaticPub[:])
	if err != nil {
		return nil, err
	}
	if err := ss.mixKey(es); err != nil {
		return nil, err
	}
	tag1, err := ss.encryptAndHash(nil)
	if err != nil {
		return nil, err
	}

	msg1 := make([]byte, 0, 32+len(tag1))
	msg1 = append(msg1, ePub[:]...)
	msg1 = append(msg1, tag1...)
	if err := writeNoiseWireFrame(rawConn, msg1); err != nil {
		return nil, err
	}

	// <- e, ee
	msg2, err := readNoiseWireFrame(rawConn)
	if err != nil {
		return nil, err
	}
	if len(msg2) < 32+chacha20poly1305.Overhead {
		return nil, errors.New("invalid noise handshake response length")
	}
	var rePub [32]byte
	copy(rePub[:], msg2[:32])
	ss.mixHash(rePub[:])

	ee, err := curve25519.X25519(ePriv[:], rePub[:])
	if err != nil {
		return nil, err
	}
	if err := ss.mixKey(ee); err != nil {
		return nil, err
	}
	if _, err := ss.decryptAndHash(msg2[32:]); err != nil {
		return nil, errors.New("noise handshake authentication failed")
	}

	txCS, rxCS, err := ss.split()
	if err != nil {
		return nil, err
	}
	return &ratholeNoiseConn{
		Conn: rawConn,
		tx:   txCS,
		rx:   rxCS,
	}, nil
}

// Responder handshake: Noise_NK_25519_ChaChaPoly_BLAKE2s
func performRatholeServerNoiseHandshake(rawConn net.Conn, serverStaticPriv, serverStaticPub [32]byte) (*ratholeNoiseConn, error) {
	ss := newRatholeSymmetricState()
	// Pre-message: <- s
	ss.mixHash(serverStaticPub[:])

	// -> e, es
	msg1, err := readNoiseWireFrame(rawConn)
	if err != nil {
		return nil, err
	}
	if len(msg1) < 32+chacha20poly1305.Overhead {
		return nil, errors.New("invalid noise client hello length")
	}
	var ePub [32]byte
	copy(ePub[:], msg1[:32])
	ss.mixHash(ePub[:])

	es, err := curve25519.X25519(serverStaticPriv[:], ePub[:])
	if err != nil {
		return nil, err
	}
	if err := ss.mixKey(es); err != nil {
		return nil, err
	}
	if _, err := ss.decryptAndHash(msg1[32:]); err != nil {
		return nil, errors.New("noise client hello authentication failed")
	}

	// <- e, ee
	rePriv, rePub, err := generateEphemeralX25519()
	if err != nil {
		return nil, err
	}
	ss.mixHash(rePub[:])

	ee, err := curve25519.X25519(rePriv[:], ePub[:])
	if err != nil {
		return nil, err
	}
	if err := ss.mixKey(ee); err != nil {
		return nil, err
	}
	tag2, err := ss.encryptAndHash(nil)
	if err != nil {
		return nil, err
	}

	msg2 := make([]byte, 0, 32+len(tag2))
	msg2 = append(msg2, rePub[:]...)
	msg2 = append(msg2, tag2...)
	if err := writeNoiseWireFrame(rawConn, msg2); err != nil {
		return nil, err
	}

	rxCS, txCS, err := ss.split()
	if err != nil {
		return nil, err
	}
	return &ratholeNoiseConn{
		Conn: rawConn,
		tx:   txCS,
		rx:   rxCS,
	}, nil
}

func (nc *ratholeNoiseConn) Write(p []byte) (int, error) {
	nc.writeMu.Lock()
	defer nc.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > ratholeMaxFramePayload {
			chunk = p[:ratholeMaxFramePayload]
		}
		ct, err := nc.tx.encrypt(nil, chunk)
		if err != nil {
			return total, err
		}
		if err := writeNoiseWireFrame(nc.Conn, ct); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (nc *ratholeNoiseConn) Read(p []byte) (int, error) {
	nc.readMu.Lock()
	defer nc.readMu.Unlock()

	if nc.readBuf.Len() > 0 {
		return nc.readBuf.Read(p)
	}
	ct, err := readNoiseWireFrame(nc.Conn)
	if err != nil {
		return 0, err
	}
	pt, err := nc.rx.decrypt(nil, ct)
	if err != nil {
		return 0, err
	}
	nc.readBuf.Write(pt)
	return nc.readBuf.Read(p)
}

// ============================================================================
// 2. RATHOLE 4-STEP CHALLENGE-RESPONSE AUTHENTICATION & STATE MANAGERS
// ============================================================================

type ratholeAuthMetadata struct {
	PeerID     string `json:"pid"`
	NodeID     string `json:"nid"`
	TargetPort string `json:"port,omitempty"`
	TimeHdr    string `json:"tm,omitempty"`
}

func computeRatholeServiceDigest(peerID string) [32]byte {
	return sha256.Sum256([]byte("sahand-rathole-svc:" + peerID))
}

func computeRatholeAuthDigest(authKey []byte, nonce [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write(authKey)
	_, _ = h.Write(nonce[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func clientRatholeChallengeAuth(
	nc *ratholeNoiseConn,
	helloType byte,
	peer ServerPeer,
	authKey []byte,
	targetPort string,
) ([32]byte, error) {
	var sessionKey [32]byte
	svcDigest := computeRatholeServiceDigest(peer.ID)

	// Step 1: Send ControlChannelHello ([Version:1][HelloType:1][ServiceDigest:32])
	var hello [34]byte
	hello[0] = ratholeProtoVersion
	hello[1] = helloType
	copy(hello[2:34], svcDigest[:])
	if _, err := nc.Write(hello[:]); err != nil {
		return sessionKey, err
	}

	// Step 2: Read Server Nonce Challenge ([Version:1][Nonce:32])
	var challenge [33]byte
	if _, err := io.ReadFull(nc, challenge[:]); err != nil {
		return sessionKey, err
	}
	if challenge[0] != ratholeProtoVersion {
		return sessionKey, errors.New("rathole protocol version mismatch")
	}
	copy(sessionKey[:], challenge[1:33])

	// Step 3: Send Salted Auth Digest + Metadata
	stateMu.RLock()
	localNodeID := appCfg.NodeID
	stateMu.RUnlock()

	authDigest := computeRatholeAuthDigest(authKey, sessionKey)
	meta := ratholeAuthMetadata{
		PeerID:     peer.ID,
		NodeID:     localNodeID,
		TargetPort: targetPort,
		TimeHdr:    buildMasterTimeHeader(),
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return sessionKey, err
	}

	authPkt := make([]byte, 34+len(metaBytes))
	copy(authPkt[0:32], authDigest[:])
	binary.BigEndian.PutUint16(authPkt[32:34], uint16(len(metaBytes)))
	copy(authPkt[34:], metaBytes)
	if _, err := nc.Write(authPkt); err != nil {
		return sessionKey, err
	}

	// Step 4: Read Server Ack (0x00 = Ok)
	var ack [1]byte
	if _, err := io.ReadFull(nc, ack[:]); err != nil {
		return sessionKey, err
	}
	if ack[0] != ratholeAckOK {
		return sessionKey, errors.New("rathole authentication rejected")
	}
	return sessionKey, nil
}

// ============================================================================
// 3. RATHOLE REVERSE CONTROL CHANNEL & DATA CHANNEL MULTIPLEXER
// ============================================================================

type ratholeControlSession struct {
	mu         sync.Mutex
	peerID     string
	sessionKey [32]byte
	conn       *ratholeNoiseConn
	pendingCh  chan *ratholeNoiseConn
	closed     atomic.Bool
}

func (cs *ratholeControlSession) requestReverseDataChannel(proto byte, portNum uint16) (*ratholeNoiseConn, error) {
	if cs.closed.Load() {
		return nil, errors.New("rathole control channel closed")
	}
	cs.mu.Lock()
	var cmd [4]byte
	cmd[0] = ratholeCmdCreateDataChannel
	cmd[1] = proto
	binary.BigEndian.PutUint16(cmd[2:4], portNum)
	_, err := cs.conn.Write(cmd[:])
	cs.mu.Unlock()
	if err != nil {
		cs.close()
		return nil, err
	}

	timer := time.NewTimer(ratholePendingHandoverWait)
	defer timer.Stop()
	select {
	case dc := <-cs.pendingCh:
		if dc == nil {
			return nil, errors.New("rathole reverse data channel closed")
		}
		return dc, nil
	case <-timer.C:
		return nil, errors.New("rathole reverse data channel timeout")
	}
}

func (cs *ratholeControlSession) close() {
	if cs.closed.Swap(true) {
		return
	}
	_ = cs.conn.Close()
}

var (
	ratholeMu               sync.RWMutex
	ratholeControlByPeer    = make(map[string]*ratholeControlSession)
	ratholeControlBySessKey = make(map[[32]byte]*ratholeControlSession)
	ratholeClientCancel     = make(map[string]chan struct{})
	ratholeExitUDPMuxes     = make(map[string]*ratholeUDPExitManager)
	ratholeEntryUDPMuxes    = make(map[string]*ratholeUDPEntryManager)
)

func registerRatholeControlSession(peerID string, sessionKey [32]byte, nc *ratholeNoiseConn) *ratholeControlSession {
	cs := &ratholeControlSession{
		peerID:     peerID,
		sessionKey: sessionKey,
		conn:       nc,
		pendingCh:  make(chan *ratholeNoiseConn, 64),
	}
	ratholeMu.Lock()
	if old, ok := ratholeControlByPeer[peerID]; ok {
		delete(ratholeControlBySessKey, old.sessionKey)
		old.close()
	}
	ratholeControlByPeer[peerID] = cs
	ratholeControlBySessKey[sessionKey] = cs
	ratholeMu.Unlock()
	return cs
}

func unregisterRatholeControlSession(cs *ratholeControlSession) {
	ratholeMu.Lock()
	if cur, ok := ratholeControlByPeer[cs.peerID]; ok && cur == cs {
		delete(ratholeControlByPeer, cs.peerID)
	}
	delete(ratholeControlBySessKey, cs.sessionKey)
	ratholeMu.Unlock()
	cs.close()
}

func stopRatholePeerResources(peerID string) {
	ratholeMu.Lock()
	if ch, ok := ratholeClientCancel[peerID]; ok {
		close(ch)
		delete(ratholeClientCancel, peerID)
	}
	if cs, ok := ratholeControlByPeer[peerID]; ok {
		delete(ratholeControlBySessKey, cs.sessionKey)
		delete(ratholeControlByPeer, peerID)
		cs.close()
	}
	if exitMux, ok := ratholeExitUDPMuxes[peerID]; ok {
		exitMux.closeAll()
		delete(ratholeExitUDPMuxes, peerID)
	}
	for k, entryMux := range ratholeEntryUDPMuxes {
		if strings.HasPrefix(k, peerID+"|") {
			entryMux.closeAll()
			delete(ratholeEntryUDPMuxes, k)
		}
	}
	ratholeMu.Unlock()
}

// ============================================================================
// 4. RATHOLE SERVER LISTENER & HANDLERS (ENGINE 1 + ENGINE 2)
// ============================================================================

func startRatholeServerListener(peer ServerPeer, tc TunnelConfig) (net.Listener, error) {
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(tc.ListenPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}

	ratholeMu.Lock()
	if oldMux, ok := ratholeExitUDPMuxes[peer.ID]; ok {
		oldMux.closeAll()
	}
	exitMux := newRatholeUDPExitManager(tc.SpeedLimitMBps)
	ratholeExitUDPMuxes[peer.ID] = exitMux
	ratholeMu.Unlock()

	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			enableKeepAlive(rawConn)
			go handleIncomingRatholeConn(rawConn, peer, tc, exitMux)
		}
	}()
	return ln, nil
}

func handleIncomingRatholeConn(rawConn net.Conn, peer ServerPeer, tc TunnelConfig, exitMux *ratholeUDPExitManager) {
	_ = rawConn.SetDeadline(time.Now().Add(12 * time.Second))

	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		_ = rawConn.Close()
		return
	}
	sPriv, sPub, err := deriveRatholeStaticKeypair(authKey)
	if err != nil {
		_ = rawConn.Close()
		return
	}

	nc, err := performRatholeServerNoiseHandshake(rawConn, sPriv, sPub)
	if err != nil {
		_ = rawConn.Close()
		return
	}

	// Read 34-byte Rathole Hello ([Version:1][HelloType:1][DigestOrSessionKey:32])
	var hello [34]byte
	if _, err := io.ReadFull(nc, hello[:]); err != nil || hello[0] != ratholeProtoVersion {
		_ = nc.Close()
		return
	}
	helloType := hello[1]
	var keyOrDigest [32]byte
	copy(keyOrDigest[:], hello[2:34])

	// DataChannelHello: match SessionKey to active ControlChannel and hand over connection
	if helloType == ratholeHelloDataChannel {
		ratholeMu.RLock()
		cs, ok := ratholeControlBySessKey[keyOrDigest]
		ratholeMu.RUnlock()
		if !ok || cs.closed.Load() {
			_ = nc.Close()
			return
		}
		_ = nc.SetDeadline(time.Time{})
		select {
		case cs.pendingCh <- nc:
			return
		default:
			_ = nc.Close()
			return
		}
	}

	// Verify ServiceDigest for ControlChannel / Probe / ParitySync / DirectForward
	expectedSvc := computeRatholeServiceDigest(peer.ID)
	if subtle.ConstantTimeCompare(keyOrDigest[:], expectedSvc[:]) != 1 {
		_, _ = nc.Write([]byte{ratholeAckServiceNotExist})
		_ = nc.Close()
		return
	}

	// Send 32-byte random Nonce Challenge
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		_ = nc.Close()
		return
	}
	var challenge [33]byte
	challenge[0] = ratholeProtoVersion
	copy(challenge[1:33], nonce[:])
	if _, err := nc.Write(challenge[:]); err != nil {
		_ = nc.Close()
		return
	}

	// Read client AuthDigest + Metadata
	var authHdr [34]byte
	if _, err := io.ReadFull(nc, authHdr[:]); err != nil {
		_ = nc.Close()
		return
	}
	expectedAuth := computeRatholeAuthDigest(authKey, nonce)
	if subtle.ConstantTimeCompare(authHdr[0:32], expectedAuth[:]) != 1 {
		_, _ = nc.Write([]byte{ratholeAckAuthFailed})
		_ = nc.Close()
		return
	}
	metaLen := int(binary.BigEndian.Uint16(authHdr[32:34]))
	if metaLen <= 0 || metaLen > 4096 {
		_ = nc.Close()
		return
	}
	metaBuf := make([]byte, metaLen)
	if _, err := io.ReadFull(nc, metaBuf); err != nil {
		_ = nc.Close()
		return
	}
	var meta ratholeAuthMetadata
	if json.Unmarshal(metaBuf, &meta) != nil {
		_ = nc.Close()
		return
	}
	if meta.TimeHdr != "" {
		applyMasterTimeHeader(meta.TimeHdr)
	}

	remoteHost, _, _ := net.SplitHostPort(rawConn.RemoteAddr().String())
	effectivePeerID := peer.ID
	if meta.PeerID != "" {
		effectivePeerID = meta.PeerID
	}

	// Send Ack::Ok
	if _, err := nc.Write([]byte{ratholeAckOK}); err != nil {
		_ = nc.Close()
		return
	}

	switch helloType {
	case ratholeHelloProbe:
		defer nc.Close()
		var pingBuf [12]byte
		if _, err := io.ReadFull(nc, pingBuf[:]); err != nil {
			return
		}
		_, _ = nc.Write(pingBuf[:])
		markPeerConnectedInbound(effectivePeerID, remoteHost, tc.ID, tc.ListenPort, 1)

	case ratholeHelloParitySync:
		defer nc.Close()
		handleRatholeParitySyncServer(nc, effectivePeerID, remoteHost)

	case ratholeHelloControlChannel:
		if !tc.Enabled {
			_ = nc.Close()
			return
		}
		_ = nc.SetDeadline(time.Time{})
		serveRatholeControlChannel(nc, effectivePeerID, nonce, tc)

	case ratholeHelloDirectForward:
		defer nc.Close()
		if !tc.Enabled {
			return
		}
		_ = nc.SetDeadline(time.Time{})
		handleRatholeDirectDataChannel(nc, tc, exitMux)

	default:
		_ = nc.Close()
	}
}

func serveRatholeControlChannel(nc *ratholeNoiseConn, peerID string, sessionKey [32]byte, tc TunnelConfig) {
	cs := registerRatholeControlSession(peerID, sessionKey, nc)
	defer unregisterRatholeControlSession(cs)

	hbSec := tc.HeartbeatSec
	if hbSec <= 0 {
		hbSec = 25
	}
	ticker := time.NewTicker(time.Duration(hbSec) * time.Second)
	defer ticker.Stop()

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		var buf [1]byte
		for {
			_ = nc.SetReadDeadline(time.Now().Add(time.Duration(hbSec*2+15) * time.Second))
			if _, err := io.ReadFull(nc, buf[:]); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-doneCh:
			return
		case <-ticker.C:
			cs.mu.Lock()
			_, err := cs.conn.Write([]byte{ratholeCmdHeartBeat})
			cs.mu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

// ============================================================================
// 5. RATHOLE REVERSE CLIENT WORKER (SPAWNS REVERSE DATA CHANNELS ON DEMAND)
// ============================================================================

func startRatholeReverseClient(peer ServerPeer, tc TunnelConfig) {
	ratholeMu.Lock()
	if ch, ok := ratholeClientCancel[peer.ID]; ok {
		close(ch)
	}
	stopCh := make(chan struct{})
	ratholeClientCancel[peer.ID] = stopCh
	ratholeMu.Unlock()

	go func() {
		for {
			select {
			case <-stopCh:
				return
			default:
			}

			runRatholeReverseControlSession(peer, tc, stopCh)

			timer := time.NewTimer(5 * time.Second)
			select {
			case <-stopCh:
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func dialRatholeNoise(peer ServerPeer, tc TunnelConfig, timeout time.Duration) (*ratholeNoiseConn, []byte, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	authKey, err := derivePeerAuthKey(cfgSnapshot, peer)
	if err != nil {
		return nil, nil, err
	}
	_, sPub, err := deriveRatholeStaticKeypair(authKey)
	if err != nil {
		return nil, nil, err
	}

	targetAddr := net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort))
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, nil, err
	}
	enableKeepAlive(rawConn)
	_ = rawConn.SetDeadline(time.Now().Add(timeout + 2*time.Second))

	nc, err := performRatholeClientNoiseHandshake(rawConn, sPub)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	return nc, authKey, nil
}

func runRatholeReverseControlSession(peer ServerPeer, tc TunnelConfig, stopCh <-chan struct{}) {
	nc, authKey, err := dialRatholeNoise(peer, tc, 5*time.Second)
	if err != nil {
		return
	}
	defer nc.Close()

	sessionKey, err := clientRatholeChallengeAuth(nc, ratholeHelloControlChannel, peer, authKey, "control")
	if err != nil {
		return
	}
	_ = nc.SetDeadline(time.Time{})

	go func() {
		<-stopCh
		_ = nc.Close()
	}()

	ratholeMu.RLock()
	exitMux := ratholeExitUDPMuxes[peer.ID]
	ratholeMu.RUnlock()
	if exitMux == nil {
		exitMux = newRatholeUDPExitManager(tc.SpeedLimitMBps)
	}

	var cmdBuf [1]byte
	for {
		_ = nc.SetReadDeadline(time.Now().Add(90 * time.Second))
		if _, err := io.ReadFull(nc, cmdBuf[:]); err != nil {
			return
		}
		switch cmdBuf[0] {
		case ratholeCmdHeartBeat:
			_, _ = nc.Write([]byte{ratholeCmdHeartBeatAck})

		case ratholeCmdCreateDataChannel:
			var args [3]byte
			if _, err := io.ReadFull(nc, args[:]); err != nil {
				return
			}
			go spawnRatholeReverseDataChannel(peer, tc, sessionKey, exitMux)
		}
	}
}

func spawnRatholeReverseDataChannel(
	peer ServerPeer,
	tc TunnelConfig,
	sessionKey [32]byte,
	exitMux *ratholeUDPExitManager,
) {
	nc, _, err := dialRatholeNoise(peer, tc, 5*time.Second)
	if err != nil {
		return
	}
	defer nc.Close()

	// Send DataChannelHello ([Version:1][HelloType=0x01][SessionKey:32])
	var hello [34]byte
	hello[0] = ratholeProtoVersion
	hello[1] = ratholeHelloDataChannel
	copy(hello[2:34], sessionKey[:])
	if _, err := nc.Write(hello[:]); err != nil {
		return
	}
	_ = nc.SetDeadline(time.Time{})

	handleRatholeDirectDataChannel(nc, tc, exitMux)
}

func handleRatholeDirectDataChannel(nc *ratholeNoiseConn, tc TunnelConfig, exitMux *ratholeUDPExitManager) {
	// Read 3-byte DataChannelCmd ([Cmd:1][TargetPort:2])
	_ = nc.SetReadDeadline(time.Now().Add(10 * time.Second))
	var dcmd [3]byte
	if _, err := io.ReadFull(nc, dcmd[:]); err != nil {
		return
	}
	_ = nc.SetReadDeadline(time.Time{})

	portNum := int(binary.BigEndian.Uint16(dcmd[1:3]))
	targetPort := strconv.Itoa(portNum)
	if portNum <= 0 {
		ports := parsePortList(tc.ForwardPorts)
		if len(ports) > 0 {
			targetPort = ports[0]
		} else {
			targetPort = "2053"
		}
	}

	switch dcmd[0] {
	case ratholeDataCmdStartForwardTCP:
		target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", targetPort), 5*time.Second)
		if err != nil {
			_, _ = nc.Write([]byte{0x01})
			return
		}
		defer target.Close()
		enableKeepAlive(target)

		if _, err := nc.Write([]byte{0x00}); err != nil {
			return
		}
		pipeRatholeStreamAndTCP(nc, target, tc.SpeedLimitMBps)

	case ratholeDataCmdStartForwardUDP:
		if exitMux != nil {
			exitMux.serveUDPDataChannel(nc, uint16(portNum))
		}
	}
}

// ============================================================================
// 6. ENGINE 1: PROBE & PARITY SYNC OVER RATHOLE NOISE_NK
// ============================================================================

func probeRathole(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	nc, authKey, err := dialRatholeNoise(peer, tc, 4*time.Second)
	if err != nil {
		res.Success = false
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			res.ErrorReason = "Timeout"
		} else {
			res.ErrorReason = "Port unreachable"
		}
		return res
	}
	defer nc.Close()

	if _, err := clientRatholeChallengeAuth(nc, ratholeHelloProbe, peer, authKey, fmt.Sprintf("probe:%d", tc.ListenPort)); err != nil {
		res.Success = false
		res.ErrorReason = "Authentication failure"
		return res
	}

	var ping [12]byte
	var pong [12]byte
	binary.BigEndian.PutUint32(ping[0:4], 1)
	binary.BigEndian.PutUint64(ping[4:12], uint64(time.Now().UnixNano()))
	if _, err := nc.Write(ping[:]); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}
	if _, err := io.ReadFull(nc, pong[:]); err != nil || !bytes.Equal(ping[:], pong[:]) {
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

func pushRatholeParitySync(peer ServerPeer, tc TunnelConfig, latencyMS int64) bool {
	nc, authKey, err := dialRatholeNoise(peer, tc, 4*time.Second)
	if err != nil {
		return false
	}
	defer nc.Close()

	if _, err := clientRatholeChallengeAuth(nc, ratholeHelloParitySync, peer, authKey, strconv.Itoa(tc.ListenPort)); err != nil {
		return false
	}

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
	if _, err := nc.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := nc.Write(rawPkt); err != nil {
		return false
	}

	if _, err := io.ReadFull(nc, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(nc, respBytes); err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func handleRatholeParitySyncServer(nc *ratholeNoiseConn, effectivePeerID, remoteHost string) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(nc, lenBuf[:]); err != nil {
		return
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen == 0 || pktLen > 256*1024 {
		return
	}
	rawPkt := make([]byte, pktLen)
	if _, err := io.ReadFull(nc, rawPkt); err != nil {
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
	_, _ = nc.Write(lenBuf[:])
	_, _ = nc.Write(respBytes)
}

// ============================================================================
// 7. ENGINE 2: TCP & UDP FORWARDING OVER RATHOLE (REVERSE + DIRECT)
// ============================================================================

func openRatholeDataChannel(peer ServerPeer, tc TunnelConfig, proto byte, portNum uint16) (*ratholeNoiseConn, error) {
	// 1. Try Reverse Control Channel first (True Rathole: works even when outbound is blocked)
	ratholeMu.RLock()
	cs := ratholeControlByPeer[peer.ID]
	ratholeMu.RUnlock()

	if cs != nil && !cs.closed.Load() {
		if dc, err := cs.requestReverseDataChannel(proto, portNum); err == nil {
			return dc, nil
		}
	}

	// 2. Direct Noise DataChannel fallback (when Entry Server can dial Exit Server directly)
	nc, authKey, err := dialRatholeNoise(peer, tc, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err := clientRatholeChallengeAuth(nc, ratholeHelloDirectForward, peer, authKey, strconv.Itoa(int(portNum))); err != nil {
		_ = nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return nc, nil
}

func forwardRatholeTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	portNum, _ := strconv.Atoi(strings.TrimSpace(targetPort))
	if portNum <= 0 {
		portNum = 2053
	}

	dc, err := openRatholeDataChannel(peer, tc, ratholeDataCmdStartForwardTCP, uint16(portNum))
	if err != nil {
		return
	}
	defer dc.Close()

	// Send DataChannelCmd: [StartForwardTCP (0x00)][TargetPort:2]
	var dcmd [3]byte
	dcmd[0] = ratholeDataCmdStartForwardTCP
	binary.BigEndian.PutUint16(dcmd[1:3], uint16(portNum))
	_ = dc.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := dc.Write(dcmd[:]); err != nil {
		return
	}

	var status [1]byte
	if _, err := io.ReadFull(dc, status[:]); err != nil || status[0] != 0x00 {
		return
	}
	_ = dc.SetDeadline(time.Time{})

	pipeRatholeStreamAndTCP(dc, client, tc.SpeedLimitMBps)
}

func pipeRatholeStreamAndTCP(nc *ratholeNoiseConn, tcpConn net.Conn, speedLimitMBps string) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	toNoise := newThrottledWriter(nc, &appTxBytes, mbLimit)
	toTCP := newThrottledWriter(tcpConn, &appRxBytes, mbLimit)

	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toNoise, tcpConn, buf)
		_ = nc.Close()
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(toTCP, nc, buf)
		if tc, ok := tcpConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}

// ============================================================================
// 8. RATHOLE UDP FORWARDING (`StartForwardUdp`)
// ============================================================================

type ratholeUDPEntrySession struct {
	sessionID    uint32
	clientAddr   *net.UDPAddr
	entryConn    *net.UDPConn
	lastActivity atomic.Int64
}

type ratholeUDPEntryManager struct {
	mu          sync.RWMutex
	peer        ServerPeer
	tunnel      TunnelConfig
	targetPort  uint16
	byAddr      map[string]*ratholeUDPEntrySession
	bySessionID map[uint32]*ratholeUDPEntrySession
	nextID      atomic.Uint32
	dcMu        sync.Mutex
	dc          *ratholeNoiseConn
	limiter     io.Writer
	stopCh      chan struct{}
	closed      atomic.Bool
}

func newRatholeUDPEntryManager(peer ServerPeer, tc TunnelConfig, targetPort uint16) *ratholeUDPEntryManager {
	m := &ratholeUDPEntryManager{
		peer:        peer,
		tunnel:      tc,
		targetPort:  targetPort,
		byAddr:      make(map[string]*ratholeUDPEntrySession),
		bySessionID: make(map[uint32]*ratholeUDPEntrySession),
		limiter:     newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(tc.SpeedLimitMBps)),
		stopCh:      make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *ratholeUDPEntryManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Unix() - int64(ratholeUDPIdleTTL.Seconds())
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

func (m *ratholeUDPEntryManager) closeAll() {
	if m.closed.Swap(true) {
		return
	}
	close(m.stopCh)
	m.dcMu.Lock()
	if m.dc != nil {
		_ = m.dc.Close()
		m.dc = nil
	}
	m.dcMu.Unlock()
}

func (m *ratholeUDPEntryManager) getOrCreateSession(entryConn *net.UDPConn, clientAddr *net.UDPAddr) *ratholeUDPEntrySession {
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
	s := &ratholeUDPEntrySession{
		sessionID:  sid,
		clientAddr: addrCopy,
		entryConn:  entryConn,
	}
	s.lastActivity.Store(now)
	m.byAddr[key] = s
	m.bySessionID[sid] = s
	return s
}

func (m *ratholeUDPEntryManager) getOrOpenUDPDataChannel() (*ratholeNoiseConn, error) {
	m.dcMu.Lock()
	defer m.dcMu.Unlock()

	if m.dc != nil {
		return m.dc, nil
	}
	dc, err := openRatholeDataChannel(m.peer, m.tunnel, ratholeDataCmdStartForwardUDP, m.targetPort)
	if err != nil {
		return nil, err
	}
	var dcmd [3]byte
	dcmd[0] = ratholeDataCmdStartForwardUDP
	binary.BigEndian.PutUint16(dcmd[1:3], m.targetPort)
	if _, err := dc.Write(dcmd[:]); err != nil {
		_ = dc.Close()
		return nil, err
	}
	m.dc = dc
	go m.readUDPRepliesLoop(dc)
	return dc, nil
}

func (m *ratholeUDPEntryManager) readUDPRepliesLoop(dc *ratholeNoiseConn) {
	defer func() {
		_ = dc.Close()
		m.dcMu.Lock()
		if m.dc == dc {
			m.dc = nil
		}
		m.dcMu.Unlock()
	}()

	var hdr [8]byte
	for {
		if _, err := io.ReadFull(dc, hdr[:]); err != nil {
			return
		}
		sid := binary.BigEndian.Uint32(hdr[0:4])
		pktLen := int(binary.BigEndian.Uint16(hdr[6:8]))
		if pktLen <= 0 || pktLen > 65507 {
			return
		}
		payload := make([]byte, pktLen)
		if _, err := io.ReadFull(dc, payload); err != nil {
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

func (m *ratholeUDPEntryManager) handleClientPacket(entryConn *net.UDPConn, clientAddr *net.UDPAddr, payload []byte) {
	if len(payload) == 0 || len(payload) > 16384 {
		return
	}
	sess := m.getOrCreateSession(entryConn, clientAddr)
	dc, err := m.getOrOpenUDPDataChannel()
	if err != nil {
		return
	}
	_, _ = m.limiter.Write(payload)

	frame := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], sess.sessionID)
	binary.BigEndian.PutUint16(frame[4:6], m.targetPort)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[8:], payload)

	if _, err := dc.Write(frame); err != nil {
		_ = dc.Close()
	}
}

type ratholeUDPExitSession struct {
	sessionID    uint32
	targetPort   uint16
	localConn    *net.UDPConn
	lastActivity atomic.Int64
	closed       atomic.Bool
}

type ratholeUDPExitManager struct {
	mu       sync.RWMutex
	sessions map[uint32]*ratholeUDPExitSession
	limiter  io.Writer
	stopCh   chan struct{}
	closed   atomic.Bool
}

func newRatholeUDPExitManager(speedLimitMBps string) *ratholeUDPExitManager {
	m := &ratholeUDPExitManager{
		sessions: make(map[uint32]*ratholeUDPExitSession),
		limiter:  newThrottledWriter(io.Discard, &appTxBytes, parseSpeedLimit(speedLimitMBps)),
		stopCh:   make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *ratholeUDPExitManager) janitorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Unix() - int64(ratholeUDPIdleTTL.Seconds())
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

func (m *ratholeUDPExitManager) closeAll() {
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

func (m *ratholeUDPExitManager) serveUDPDataChannel(dc *ratholeNoiseConn, defaultPort uint16) {
	defer dc.Close()
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(dc, hdr[:]); err != nil {
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
		if _, err := io.ReadFull(dc, payload); err != nil {
			return
		}

		sess, err := m.getOrCreateExitSession(dc, sid, tPort)
		if err != nil {
			continue
		}
		sess.lastActivity.Store(time.Now().Unix())
		atomic.AddUint64(&appRxBytes, uint64(len(payload)))
		_, _ = sess.localConn.Write(payload)
	}
}

func (m *ratholeUDPExitManager) getOrCreateExitSession(dc *ratholeNoiseConn, sid uint32, targetPort uint16) (*ratholeUDPExitSession, error) {
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
	s := &ratholeUDPExitSession{
		sessionID:  sid,
		targetPort: targetPort,
		localConn:  localUDP,
	}
	s.lastActivity.Store(now)
	m.sessions[sid] = s

	go func(sess *ratholeUDPExitSession) {
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
			_ = sess.localConn.SetReadDeadline(time.Now().Add(ratholeUDPIdleTTL))
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
				if _, wErr := dc.Write(frame); wErr != nil {
					return
				}
			}
		}
	}(s)

	return s, nil
}

func startRatholeUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
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
	ratholeMu.Lock()
	if old, ok := ratholeEntryUDPMuxes[muxKey]; ok {
		old.closeAll()
	}
	mgr := newRatholeUDPEntryManager(peer, tc, uint16(portNum))
	ratholeEntryUDPMuxes[muxKey] = mgr
	ratholeMu.Unlock()

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
