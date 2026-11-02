package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Official Noise Protocol Framework (Revision 34) pattern name
	noiseIKpsk2ProtocolName = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

	// Wire packet types prior to transport split
	noiseWireTypeBootstrapReq  byte = 0xB1
	noiseWireTypeBootstrapResp byte = 0xB2
	noiseWireTypeHandshakeMsg1 byte = 0x10
	noiseWireTypeHandshakeMsg2 byte = 0x20

	// Post-handshake transport frame types (authenticated inside 3-byte AAD header)
	noiseFrameTypeData        byte = 0x01
	noiseFrameTypeRekeyInit   byte = 0x02
	noiseFrameTypeRekeyAck    byte = 0x03
	noiseFrameTypeRekeyCommit byte = 0x04
	noiseFrameTypeClose       byte = 0x05

	// Application commands carried inside Message 3 (first post-split transport frame)
	noiseAppCmdProbe      byte = 0x01
	noiseAppCmdParitySync byte = 0x02
	noiseAppCmdTCPForward byte = 0x03
	noiseAppCmdUDPForward byte = 0x04

	// Frame sizing constants (Plaintext, AEAD Tag, Ciphertext, and Header)
	noiseFrameHeaderLen   = 3
	noiseMaxPlaintextLen  = 32 * 1024
	noiseAEADTagLen       = chacha20poly1305.Overhead // 16 bytes
	noiseMaxCiphertextLen = noiseMaxPlaintextLen + noiseAEADTagLen
	noiseMaxHandshakeLen  = 2048

	noiseHandshakeTimeout = 6 * time.Second
)

// ============================================================================
// 1. NOISE REVISION 34 STATE MACHINE (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s)
// ============================================================================

type noiseDHKey struct {
	Private []byte
	Public  []byte
}

// Implements Noise Specification Section 5.1 CipherState for ChaChaPoly.
type noiseCipherState struct {
	mu      sync.Mutex
	key     [32]byte
	maskKey [32]byte
	hasKey  bool
	n       uint64
}

func newNoiseCipherState(key [32]byte, maskKey [32]byte) *noiseCipherState {
	return &noiseCipherState{
		key:     key,
		maskKey: maskKey,
		hasKey:  true,
		n:       0,
	}
}

// Encodes the 64-bit sequence number `n` into the 96-bit ChaChaPoly nonce per
// Noise Specification Revision 34 Section 7.3: 32 bits of zeros followed by
// little-endian encoding of `n`.
func encodeNoiseChaChaPolyNonce(n uint64) [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:12], n)
	return nonce
}

func (cs *noiseCipherState) nextFrameMaskLocked() uint16 {
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], cs.n)
	mac := hmac.New(newUnkeyedBLAKE2s, cs.maskKey[:])
	_, _ = mac.Write([]byte("sahand-noise-len-mask-v2:"))
	_, _ = mac.Write(seqBuf[:])
	sum := mac.Sum(nil)
	return binary.BigEndian.Uint16(sum[0:2])
}

func (cs *noiseCipherState) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if !cs.hasKey {
		out := make([]byte, len(plaintext))
		copy(out, plaintext)
		return out, nil
	}
	if cs.n == math.MaxUint64 {
		return nil, errors.New("noise cipherstate nonce exhausted")
	}
	aead, err := chacha20poly1305.New(cs.key[:])
	if err != nil {
		return nil, err
	}
	nonce := encodeNoiseChaChaPolyNonce(cs.n)
	cs.n++
	return aead.Seal(nil, nonce[:], plaintext, ad), nil
}

func (cs *noiseCipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if !cs.hasKey {
		out := make([]byte, len(ciphertext))
		copy(out, ciphertext)
		return out, nil
	}
	if cs.n == math.MaxUint64 {
		return nil, errors.New("noise cipherstate nonce exhausted")
	}
	if len(ciphertext) < noiseAEADTagLen {
		return nil, errors.New("noise ciphertext shorter than 16-byte Poly1305 tag")
	}
	aead, err := chacha20poly1305.New(cs.key[:])
	if err != nil {
		return nil, err
	}
	nonce := encodeNoiseChaChaPolyNonce(cs.n)
	plain, err := aead.Open(nil, nonce[:], ciphertext, ad)
	if err != nil {
		return nil, errors.New("noise AEAD authentication failed")
	}
	cs.n++
	return plain, nil
}

func (cs *noiseCipherState) Zeroize() {
	cs.mu.Lock()
	clear(cs.key[:])
	clear(cs.maskKey[:])
	cs.hasKey = false
	cs.n = math.MaxUint64
	cs.mu.Unlock()
}

func newUnkeyedBLAKE2s() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

func noiseHMACBLAKE2s(key, data []byte) [32]byte {
	mac := hmac.New(newUnkeyedBLAKE2s, key)
	_, _ = mac.Write(data)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func noiseHKDF2(chainingKey, ikm []byte) ([32]byte, [32]byte) {
	tempKey := noiseHMACBLAKE2s(chainingKey, ikm)
	out1 := noiseHMACBLAKE2s(tempKey[:], []byte{0x01})
	buf2 := make([]byte, 33)
	copy(buf2[0:32], out1[:])
	buf2[32] = 0x02
	out2 := noiseHMACBLAKE2s(tempKey[:], buf2)
	clear(tempKey[:])
	return out1, out2
}

func noiseHKDF3(chainingKey, ikm []byte) ([32]byte, [32]byte, [32]byte) {
	tempKey := noiseHMACBLAKE2s(chainingKey, ikm)
	out1 := noiseHMACBLAKE2s(tempKey[:], []byte{0x01})
	buf2 := make([]byte, 33)
	copy(buf2[0:32], out1[:])
	buf2[32] = 0x02
	out2 := noiseHMACBLAKE2s(tempKey[:], buf2)
	buf3 := make([]byte, 33)
	copy(buf3[0:32], out2[:])
	buf3[32] = 0x03
	out3 := noiseHMACBLAKE2s(tempKey[:], buf3)
	clear(tempKey[:])
	return out1, out2, out3
}

type noiseIKpsk2HandshakeState struct {
	initiator bool
	s         noiseDHKey
	e         noiseDHKey
	rs        []byte
	re        []byte
	psk       [32]byte
	ck        [32]byte
	h         [32]byte
	cs        *noiseCipherState
	msgIdx    int
}

type noiseIKpsk2Config struct {
	Initiator     bool
	Prologue      []byte
	StaticKeypair noiseDHKey
	PeerStatic    []byte
	PresharedKey  []byte
}

func newNoiseIKpsk2HandshakeState(cfg noiseIKpsk2Config) (*noiseIKpsk2HandshakeState, error) {
	if len(cfg.StaticKeypair.Private) != 32 || len(cfg.StaticKeypair.Public) != 32 {
		return nil, errors.New("noise static keypair must be 32 bytes")
	}
	if len(cfg.PresharedKey) != 32 {
		return nil, errors.New("noise PSK must be 32 bytes")
	}
	if cfg.Initiator && len(cfg.PeerStatic) != 32 {
		return nil, errors.New("noise IK initiator requires 32-byte PeerStatic public key")
	}

	st := &noiseIKpsk2HandshakeState{
		initiator: cfg.Initiator,
		s: noiseDHKey{
			Private: append([]byte(nil), cfg.StaticKeypair.Private...),
			Public:  append([]byte(nil), cfg.StaticKeypair.Public...),
		},
		cs: &noiseCipherState{},
	}
	copy(st.psk[:], cfg.PresharedKey)

	if len(noiseIKpsk2ProtocolName) <= 32 {
		copy(st.h[:], noiseIKpsk2ProtocolName)
	} else {
		st.h = blake2s.Sum256([]byte(noiseIKpsk2ProtocolName))
	}
	st.ck = st.h

	st.mixHash(cfg.Prologue)

	if cfg.Initiator {
		st.rs = append([]byte(nil), cfg.PeerStatic...)
		st.mixHash(st.rs)
	} else {
		st.mixHash(st.s.Public)
	}

	return st, nil
}

func (st *noiseIKpsk2HandshakeState) mixHash(data []byte) {
	h := newUnkeyedBLAKE2s()
	_, _ = h.Write(st.h[:])
	_, _ = h.Write(data)
	copy(st.h[:], h.Sum(nil))
}

func (st *noiseIKpsk2HandshakeState) mixKey(ikm []byte) {
	ck, k := noiseHKDF2(st.ck[:], ikm)
	st.ck = ck
	st.cs = newNoiseCipherState(k, [32]byte{})
}

func (st *noiseIKpsk2HandshakeState) mixKeyAndHash(ikm []byte) {
	ck, tempH, k := noiseHKDF3(st.ck[:], ikm)
	st.ck = ck
	st.mixHash(tempH[:])
	st.cs = newNoiseCipherState(k, [32]byte{})
}

func (st *noiseIKpsk2HandshakeState) encryptAndHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := st.cs.EncryptWithAd(st.h[:], plaintext)
	if err != nil {
		return nil, err
	}
	st.mixHash(ciphertext)
	return ciphertext, nil
}

func (st *noiseIKpsk2HandshakeState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := st.cs.DecryptWithAd(st.h[:], ciphertext)
	if err != nil {
		return nil, err
	}
	st.mixHash(ciphertext)
	return plaintext, nil
}

func performX25519DH(privBytes, pubBytes []byte) ([]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	pub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

func (st *noiseIKpsk2HandshakeState) PeerStatic() []byte {
	if len(st.rs) == 0 {
		return nil
	}
	cp := make([]byte, len(st.rs))
	copy(cp, st.rs)
	return cp
}

func (st *noiseIKpsk2HandshakeState) PeerEphemeral() []byte {
	if len(st.re) == 0 {
		return nil
	}
	cp := make([]byte, len(st.re))
	copy(cp, st.re)
	return cp
}

func (st *noiseIKpsk2HandshakeState) ChannelBinding() [32]byte {
	return st.h
}

func (st *noiseIKpsk2HandshakeState) WriteMessage(payload []byte) ([]byte, *noiseCipherState, *noiseCipherState, error) {
	if st.msgIdx == 0 && st.initiator {
		ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		st.e = noiseDHKey{
			Private: ephPriv.Bytes(),
			Public:  ephPriv.PublicKey().Bytes(),
		}

		var out bytes.Buffer
		out.Write(st.e.Public)
		st.mixHash(st.e.Public)
		st.mixKey(st.e.Public)

		esDH, err := performX25519DH(st.e.Private, st.rs)
		if err != nil {
			return nil, nil, nil, err
		}
		st.mixKey(esDH)
		clear(esDH)

		encS, err := st.encryptAndHash(st.s.Public)
		if err != nil {
			return nil, nil, nil, err
		}
		out.Write(encS)

		ssDH, err := performX25519DH(st.s.Private, st.rs)
		if err != nil {
			return nil, nil, nil, err
		}
		st.mixKey(ssDH)
		clear(ssDH)

		encPayload, err := st.encryptAndHash(payload)
		if err != nil {
			return nil, nil, nil, err
		}
		out.Write(encPayload)

		st.msgIdx = 1
		return out.Bytes(), nil, nil, nil
	}

	if st.msgIdx == 1 && !st.initiator {
		ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		st.e = noiseDHKey{
			Private: ephPriv.Bytes(),
			Public:  ephPriv.PublicKey().Bytes(),
		}

		var out bytes.Buffer
		out.Write(st.e.Public)
		st.mixHash(st.e.Public)
		st.mixKey(st.e.Public)

		eeDH, err := performX25519DH(st.e.Private, st.re)
		if err != nil {
			return nil, nil, nil, err
		}
		st.mixKey(eeDH)
		clear(eeDH)

		seDH, err := performX25519DH(st.e.Private, st.rs)
		if err != nil {
			return nil, nil, nil, err
		}
		st.mixKey(seDH)
		clear(seDH)

		st.mixKeyAndHash(st.psk[:])

		encPayload, err := st.encryptAndHash(payload)
		if err != nil {
			return nil, nil, nil, err
		}
		out.Write(encPayload)

		st.msgIdx = 2
		csI2R, csR2I := st.splitTransportKeys()
		return out.Bytes(), csI2R, csR2I, nil
	}

	return nil, nil, nil, errors.New("invalid noise handshake WriteMessage state")
}

func (st *noiseIKpsk2HandshakeState) ReadMessage(message []byte) ([]byte, *noiseCipherState, *noiseCipherState, error) {
	if st.msgIdx == 0 && !st.initiator {
		if len(message) < 96 {
			return nil, nil, nil, errors.New("noise handshake message 1 too short")
		}
		st.re = append([]byte(nil), message[0:32]...)
		st.mixHash(st.re)
		st.mixKey(st.re)

		esDH, err := performX25519DH(st.s.Private, st.re)
		if err != nil {
			return nil, nil, nil, err
		}
		st.mixKey(esDH)
		clear(esDH)

		rsPlain, err := st.decryptAndHash(message[32:80])
		if err != nil || len(rsPlain) != 32 {
			return nil, nil, nil, errors.New("noise handshake failed to authenticate initiator static key")
		}
		st.rs = rsPlain

		ssDH, err := performX25519DH(st.s.Private, st.rs)
		if err != nil {
			return nil, nil, nil, err
		}
		st.mixKey(ssDH)
		clear(ssDH)

		payload, err := st.decryptAndHash(message[80:])
		if err != nil {
			return nil, nil, nil, errors.New("noise handshake failed to authenticate message 1 payload")
		}

		st.msgIdx = 1
		return payload, nil, nil, nil
	}

	if st.msgIdx == 1 && st.initiator {
		if len(message) < 48 {
			return nil, nil, nil, errors.New("noise handshake message 2 too short")
		}
		st.re = append([]byte(nil), message[0:32]...)
		st.mixHash(st.re)
		st.mixKey(st.re)

		eeDH, err := performX25519DH(st.e.Private, st.re)
		if err != nil {
			return nil, nil, nil, err
		}
		st.mixKey(eeDH)
		clear(eeDH)

		seDH, err := performX25519DH(st.s.Private, st.re)
		if err != nil {
			return nil, nil, nil, err
		}
		st.mixKey(seDH)
		clear(seDH)

		st.mixKeyAndHash(st.psk[:])

		payload, err := st.decryptAndHash(message[32:])
		if err != nil {
			return nil, nil, nil, errors.New("noise handshake failed to authenticate message 2 payload")
		}

		st.msgIdx = 2
		csI2R, csR2I := st.splitTransportKeys()
		return payload, csI2R, csR2I, nil
	}

	return nil, nil, nil, errors.New("invalid noise handshake ReadMessage state")
}

func (st *noiseIKpsk2HandshakeState) splitTransportKeys() (*noiseCipherState, *noiseCipherState) {
	k1, k2 := noiseHKDF2(st.ck[:], nil)
	maskI2R, maskR2I := noiseHKDF2(st.ck[:], []byte("sahand-noise-len-masks-v2"))

	clear(st.ck[:])
	clear(st.psk[:])
	clear(st.e.Private)
	clear(st.s.Private)
	if st.cs != nil {
		st.cs.Zeroize()
	}

	return newNoiseCipherState(k1, maskI2R), newNoiseCipherState(k2, maskR2I)
}

// ============================================================================
// 2. STATIC KEY MANAGEMENT & AUTHENTICATED BOOTSTRAP EXCHANGE
// ============================================================================

type noiseHandshakeMsg1Payload struct {
	TimestampUnix int64  `json:"ts"`
	ClientNonce   string `json:"n"`
	SenderNodeID  string `json:"nid"`
	PeerID        string `json:"pid"`
	SigningPubKey string `json:"spk,omitempty"`
	IdentitySig   string `json:"sig,omitempty"`
}

type noiseHandshakeMsg2Payload struct {
	ServerUnix  int64  `json:"ts"`
	ClientNonce string `json:"n"`
}

type noiseBootstrapRequest struct {
	PeerID      string `json:"pid"`
	MasterID    string `json:"mid"`
	Challenge   string `json:"ch"`
	Timestamp   int64  `json:"ts"`
	MasterSig   string `json:"msig"`
	RequestHMAC string `json:"hmac"`
}

type noiseBootstrapResponse struct {
	PeerID                    string `json:"pid"`
	AgentSigningPublicKey     string `json:"agent_signing_public_key"`
	AgentNoiseStaticPublicKey string `json:"agent_noise_static_public_key"`
	AgentSig                  string `json:"asig"`
	ResponseHMAC              string `json:"hmac"`
}

func loadLocalNoiseKeyMaterial(cfg Config, peer ServerPeer) (localStatic noiseDHKey, localSignPriv ed25519.PrivateKey, localSignPubHex string, psk [32]byte, err error) {
	pskSlice, err := derivePeerSubKey(cfg, peer, "noise-ikpsk2-key-v2")
	if err != nil {
		return localStatic, nil, "", psk, err
	}
	copy(psk[:], pskSlice)

	var privHex, pubHex, signPrivHex, signPubHex string
	if cfg.Role == "agent" {
		privHex = cfg.AgentNoiseStaticPrivateKey
		pubHex = cfg.AgentNoiseStaticPublicKey
		signPrivHex = cfg.AgentSigningPrivateKey
		signPubHex = cfg.AgentSigningPublicKey
	} else {
		privHex = cfg.MasterNoiseStaticPrivateKey
		pubHex = cfg.MasterNoiseStaticPublicKey
		signPrivHex = cfg.MasterSigningPrivateKey
		signPubHex = cfg.MasterSigningPublicKey
	}

	sPriv, err1 := decodeHexExact(privHex, 32)
	sPub, err2 := decodeHexExact(pubHex, 32)
	if err1 != nil || err2 != nil {
		return localStatic, nil, "", psk, errors.New("local X25519 static keypair is not initialized")
	}
	edPriv, err3 := decodeHexExact(signPrivHex, ed25519.PrivateKeySize)
	if err3 != nil {
		return localStatic, nil, "", psk, errors.New("local Ed25519 signing key is not initialized")
	}

	localStatic = noiseDHKey{Private: sPriv, Public: sPub}
	return localStatic, ed25519.PrivateKey(edPriv), strings.ToLower(strings.TrimSpace(signPubHex)), psk, nil
}

func resolveExpectedRemoteStaticPublicKey(cfg Config, peer ServerPeer) ([]byte, error) {
	if cfg.Role == "agent" {
		pubHex := strings.TrimSpace(peer.MasterNoiseStaticPublicKey)
		if pubHex == "" {
			if tp, err := parseAndValidateToken(peer.Token); err == nil {
				pubHex = tp.MasterNoiseStaticPublicKey
			}
		}
		return decodeHexExact(pubHex, 32)
	}

	pubHex := strings.TrimSpace(peer.AgentNoiseStaticPublicKey)
	if pubHex != "" {
		return decodeHexExact(pubHex, 32)
	}

	stateMu.RLock()
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peer.ID && appCfg.Servers[i].AgentNoiseStaticPublicKey != "" {
			pubHex = appCfg.Servers[i].AgentNoiseStaticPublicKey
			break
		}
	}
	stateMu.RUnlock()

	if pubHex == "" {
		return nil, nil
	}
	return decodeHexExact(pubHex, 32)
}

func registerVerifiedAgentPublicKeys(peerID, agentNoisePubHex, agentSignPubHex string) {
	normNoise := strings.ToLower(strings.TrimSpace(agentNoisePubHex))
	normSign := strings.ToLower(strings.TrimSpace(agentSignPubHex))
	if _, err := decodeHexExact(normNoise, 32); err != nil {
		return
	}

	stateMu.Lock()
	defer stateMu.Unlock()
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peerID {
			changed := false
			if appCfg.Servers[i].AgentNoiseStaticPublicKey != normNoise {
				appCfg.Servers[i].AgentNoiseStaticPublicKey = normNoise
				changed = true
			}
			if normSign != "" && appCfg.Servers[i].AgentSigningPublicKey != normSign {
				appCfg.Servers[i].AgentSigningPublicKey = normSign
				changed = true
			}
			if changed {
				_ = saveConfig(configPath(), appCfg)
			}
			break
		}
	}
}

func bootstrapFetchAgentStaticKey(peer ServerPeer, tc TunnelConfig, timeout time.Duration) ([]byte, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	reqSubKey, err := derivePeerSubKey(cfgSnapshot, peer, "noise-bootstrap-req-v2")
	if err != nil {
		return nil, err
	}
	respSubKey, err := derivePeerSubKey(cfgSnapshot, peer, "noise-bootstrap-resp-v2")
	if err != nil {
		return nil, err
	}
	mSignPrivBytes, err := decodeHexExact(cfgSnapshot.MasterSigningPrivateKey, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}

	challenge, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	ts := time.Now().Unix()
	sigMsg := []byte(fmt.Sprintf("SAHAND-NOISE-BOOTSTRAP-REQ-V2|%s|%s|%s|%d",
		strings.ToLower(cfgSnapshot.NodeID), strings.ToLower(peer.ID), challenge, ts))
	mSig := ed25519.Sign(ed25519.PrivateKey(mSignPrivBytes), sigMsg)

	reqPkt := noiseBootstrapRequest{
		PeerID:    strings.ToLower(peer.ID),
		MasterID:  strings.ToLower(cfgSnapshot.NodeID),
		Challenge: challenge,
		Timestamp: ts,
		MasterSig: hex.EncodeToString(mSig),
	}
	macReq := hmac.New(sha256.New, reqSubKey)
	_, _ = macReq.Write(sigMsg)
	_, _ = macReq.Write(mSig)
	reqPkt.RequestHMAC = hex.EncodeToString(macReq.Sum(nil))

	rawReq, err := json.Marshal(reqPkt)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort)), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var wireHdr [3]byte
	wireHdr[0] = noiseWireTypeBootstrapReq
	binary.BigEndian.PutUint16(wireHdr[1:3], uint16(len(rawReq)))
	if _, err := conn.Write(wireHdr[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(rawReq); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, wireHdr[:]); err != nil {
		return nil, err
	}
	if wireHdr[0] != noiseWireTypeBootstrapResp {
		return nil, errors.New("unexpected bootstrap response wire type")
	}
	respLen := int(binary.BigEndian.Uint16(wireHdr[1:3]))
	if respLen <= 0 || respLen > noiseMaxHandshakeLen {
		return nil, errors.New("invalid bootstrap response length")
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBytes); err != nil {
		return nil, err
	}

	var respPkt noiseBootstrapResponse
	if err := unmarshalStrictJSON(respBytes, &respPkt); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(respPkt.PeerID)), []byte(strings.ToLower(peer.ID))) != 1 {
		return nil, errors.New("bootstrap response peer ID mismatch")
	}

	agentNoisePub, err := decodeHexExact(respPkt.AgentNoiseStaticPublicKey, 32)
	if err != nil {
		return nil, err
	}
	agentSignPub, err := decodeHexExact(respPkt.AgentSigningPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	agentSigBytes, err := decodeHexExact(respPkt.AgentSig, ed25519.SignatureSize)
	if err != nil {
		return nil, err
	}
	respHMACBytes, err := decodeHexExact(respPkt.ResponseHMAC, sha256.Size)
	if err != nil {
		return nil, err
	}

	respTranscript := []byte(fmt.Sprintf("SAHAND-NOISE-BOOTSTRAP-RESP-V2|%s|%s|%s|%s|%s",
		challenge,
		strings.ToLower(cfgSnapshot.NodeID),
		strings.ToLower(peer.ID),
		strings.ToLower(respPkt.AgentSigningPublicKey),
		strings.ToLower(respPkt.AgentNoiseStaticPublicKey)))

	macResp := hmac.New(sha256.New, respSubKey)
	_, _ = macResp.Write(respTranscript)
	_, _ = macResp.Write(agentSigBytes)
	if subtle.ConstantTimeCompare(respHMACBytes, macResp.Sum(nil)) != 1 {
		return nil, errors.New("bootstrap response HMAC verification failed")
	}
	if !ed25519.Verify(ed25519.PublicKey(agentSignPub), respTranscript, agentSigBytes) {
		return nil, errors.New("bootstrap response Ed25519 signature verification failed")
	}

	registerVerifiedAgentPublicKeys(peer.ID, respPkt.AgentNoiseStaticPublicKey, respPkt.AgentSigningPublicKey)
	return agentNoisePub, nil
}

func handleNoiseBootstrapRequest(conn net.Conn, peer ServerPeer, rawReq []byte) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	var reqPkt noiseBootstrapRequest
	if err := unmarshalStrictJSON(rawReq, &reqPkt); err != nil {
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(reqPkt.PeerID)), []byte(strings.ToLower(peer.ID))) != 1 {
		return
	}
	diff := time.Now().Unix() - reqPkt.Timestamp
	if diff < -300 || diff > 300 {
		return
	}

	reqSubKey, err := derivePeerSubKey(cfgSnapshot, peer, "noise-bootstrap-req-v2")
	if err != nil {
		return
	}
	respSubKey, err := derivePeerSubKey(cfgSnapshot, peer, "noise-bootstrap-resp-v2")
	if err != nil {
		return
	}

	masterSignPubHex := strings.TrimSpace(peer.MasterSigningPublicKey)
	if masterSignPubHex == "" {
		masterSignPubHex = strings.TrimSpace(cfgSnapshot.TrustedMasterSigningPublicKey)
	}
	if masterSignPubHex == "" {
		if tp, tErr := parseAndValidateToken(peer.Token); tErr == nil {
			masterSignPubHex = tp.MasterSigningPublicKey
		}
	}
	masterSignPub, err := decodeHexExact(masterSignPubHex, ed25519.PublicKeySize)
	if err != nil {
		return
	}
	mSigBytes, err := decodeHexExact(reqPkt.MasterSig, ed25519.SignatureSize)
	if err != nil {
		return
	}
	reqHMACBytes, err := decodeHexExact(reqPkt.RequestHMAC, sha256.Size)
	if err != nil {
		return
	}

	sigMsg := []byte(fmt.Sprintf("SAHAND-NOISE-BOOTSTRAP-REQ-V2|%s|%s|%s|%d",
		strings.ToLower(reqPkt.MasterID), strings.ToLower(peer.ID), reqPkt.Challenge, reqPkt.Timestamp))
	macReq := hmac.New(sha256.New, reqSubKey)
	_, _ = macReq.Write(sigMsg)
	_, _ = macReq.Write(mSigBytes)
	if subtle.ConstantTimeCompare(reqHMACBytes, macReq.Sum(nil)) != 1 {
		return
	}
	if !ed25519.Verify(ed25519.PublicKey(masterSignPub), sigMsg, mSigBytes) {
		return
	}

	agentSignPrivHex := cfgSnapshot.AgentSigningPrivateKey
	agentSignPubHex := cfgSnapshot.AgentSigningPublicKey
	agentNoisePubHex := cfgSnapshot.AgentNoiseStaticPublicKey
	agentSignPriv, err := decodeHexExact(agentSignPrivHex, ed25519.PrivateKeySize)
	if err != nil || agentNoisePubHex == "" || agentSignPubHex == "" {
		return
	}

	respTranscript := []byte(fmt.Sprintf("SAHAND-NOISE-BOOTSTRAP-RESP-V2|%s|%s|%s|%s|%s",
		reqPkt.Challenge,
		strings.ToLower(reqPkt.MasterID),
		strings.ToLower(peer.ID),
		strings.ToLower(agentSignPubHex),
		strings.ToLower(agentNoisePubHex)))

	aSig := ed25519.Sign(ed25519.PrivateKey(agentSignPriv), respTranscript)
	macResp := hmac.New(sha256.New, respSubKey)
	_, _ = macResp.Write(respTranscript)
	_, _ = macResp.Write(aSig)

	respPkt := noiseBootstrapResponse{
		PeerID:                    strings.ToLower(peer.ID),
		AgentSigningPublicKey:     strings.ToLower(agentSignPubHex),
		AgentNoiseStaticPublicKey: strings.ToLower(agentNoisePubHex),
		AgentSig:                  hex.EncodeToString(aSig),
		ResponseHMAC:              hex.EncodeToString(macResp.Sum(nil)),
	}
	rawResp, err := json.Marshal(respPkt)
	if err != nil {
		return
	}

	var wireHdr [3]byte
	wireHdr[0] = noiseWireTypeBootstrapResp
	binary.BigEndian.PutUint16(wireHdr[1:3], uint16(len(rawResp)))
	_, _ = conn.Write(wireHdr[:])
	_, _ = conn.Write(rawResp)
}

// ============================================================================
// 3. TRANSPORT STREAM FRAMING, 3-BYTE AAD & REKEY STATE (noiseTransportConn)
// ============================================================================

type noiseTransportConn struct {
	raw            net.Conn
	initiator      bool
	transcriptHash [32]byte
	peerStatic     []byte

	readMu          sync.Mutex
	writeMu         sync.Mutex
	bufMu           sync.Mutex
	csRx            *noiseCipherState
	csTx            *noiseCipherState
	txFramesInEpoch uint64
	autoRekeyEvery  uint64
	readBuf         bytes.Buffer
	closed          atomic.Bool

	rekeyMu             sync.Mutex
	epoch               uint32
	rekeyInProgress     bool
	rekeyWaitCommit     bool
	rekeyPendingEpoch   uint32
	rekeyEphPriv        []byte
	rekeyEphPub         []byte
	rekeyNextRx         *noiseCipherState
	rekeyNextTranscript [32]byte
	rekeyDoneCh         chan error
}

func newNoiseTransportConn(raw net.Conn, initiator bool, csI2R, csR2I *noiseCipherState, h [32]byte, peerStatic []byte) *noiseTransportConn {
	tc := &noiseTransportConn{
		raw:            raw,
		initiator:      initiator,
		transcriptHash: h,
		peerStatic:     append([]byte(nil), peerStatic...),
		autoRekeyEvery: noiseDefaultAutoRekeyCount,
	}
	if initiator {
		tc.csTx = csI2R
		tc.csRx = csR2I
	} else {
		tc.csTx = csR2I
		tc.csRx = csI2R
	}
	return tc
}

func (ntc *noiseTransportConn) PeerStatic() []byte {
	cp := make([]byte, len(ntc.peerStatic))
	copy(cp, ntc.peerStatic)
	return cp
}

func (ntc *noiseTransportConn) CurrentEpoch() uint32 {
	ntc.rekeyMu.Lock()
	defer ntc.rekeyMu.Unlock()
	return ntc.epoch
}

func (ntc *noiseTransportConn) SetAutoRekeyInterval(frames uint64) {
	ntc.writeMu.Lock()
	ntc.autoRekeyEvery = frames
	ntc.writeMu.Unlock()
}

func (ntc *noiseTransportConn) writeFrameLocked(frameType byte, plaintext []byte) error {
	if ntc.closed.Load() {
		return net.ErrClosed
	}
	if len(plaintext) > noiseMaxPlaintextLen {
		return fmt.Errorf("noise frame plaintext length %d exceeds maximum %d", len(plaintext), noiseMaxPlaintextLen)
	}

	ntc.csTx.mu.Lock()
	mask := ntc.csTx.nextFrameMaskLocked()
	ntc.csTx.mu.Unlock()

	var hdr [noiseFrameHeaderLen]byte
	hdr[0] = frameType
	obfLen := uint16(len(plaintext)) ^ mask
	binary.BigEndian.PutUint16(hdr[1:3], obfLen)

	ciphertext, err := ntc.csTx.EncryptWithAd(hdr[:], plaintext)
	if err != nil {
		return err
	}

	wire := make([]byte, noiseFrameHeaderLen+len(ciphertext))
	copy(wire[0:noiseFrameHeaderLen], hdr[:])
	copy(wire[noiseFrameHeaderLen:], ciphertext)

	if _, err := ntc.raw.Write(wire); err != nil {
		return err
	}
	if frameType == noiseFrameTypeData {
		ntc.txFramesInEpoch++
	}
	return nil
}

func (ntc *noiseTransportConn) WriteFrame(frameType byte, plaintext []byte) error {
	if ntc.closed.Load() {
		return net.ErrClosed
	}
	if len(plaintext) > noiseMaxPlaintextLen {
		return fmt.Errorf("noise frame plaintext length %d exceeds maximum %d", len(plaintext), noiseMaxPlaintextLen)
	}

	ntc.writeMu.Lock()
	err := ntc.writeFrameLocked(frameType, plaintext)
	shouldAutoRekey := err == nil &&
		frameType == noiseFrameTypeData &&
		ntc.initiator &&
		ntc.autoRekeyEvery > 0 &&
		ntc.txFramesInEpoch >= ntc.autoRekeyEvery
	ntc.writeMu.Unlock()

	if shouldAutoRekey {
		if _, payload, rErr := ntc.beginRekeyInit(); rErr == nil {
			_ = ntc.WriteFrame(noiseFrameTypeRekeyInit, payload)
		}
	}
	return err
}

func (ntc *noiseTransportConn) ReadFrame() (byte, []byte, error) {
	if ntc.closed.Load() {
		return 0, nil, net.ErrClosed
	}

	ntc.readMu.Lock()
	defer ntc.readMu.Unlock()

	for {
		if ntc.closed.Load() {
			return 0, nil, net.ErrClosed
		}

		var hdr [noiseFrameHeaderLen]byte
		if _, err := io.ReadFull(ntc.raw, hdr[:]); err != nil {
			return 0, nil, err
		}

		frameType := hdr[0]
		switch frameType {
		case noiseFrameTypeData, noiseFrameTypeRekeyInit, noiseFrameTypeRekeyAck, noiseFrameTypeRekeyCommit, noiseFrameTypeClose:
		default:
			_ = ntc.Close()
			return 0, nil, fmt.Errorf("invalid noise transport frame type 0x%02x", frameType)
		}

		ntc.csRx.mu.Lock()
		mask := ntc.csRx.nextFrameMaskLocked()
		ntc.csRx.mu.Unlock()

		plaintextLen := int(binary.BigEndian.Uint16(hdr[1:3]) ^ mask)
		if plaintextLen < 0 || plaintextLen > noiseMaxPlaintextLen {
			_ = ntc.Close()
			return 0, nil, fmt.Errorf("noise frame length %d exceeds maximum %d", plaintextLen, noiseMaxPlaintextLen)
		}

		ciphertextLen := plaintextLen + noiseAEADTagLen
		cipherBuf := make([]byte, ciphertextLen)
		if _, err := io.ReadFull(ntc.raw, cipherBuf); err != nil {
			_ = ntc.Close()
			if errors.Is(err, io.EOF) {
				return 0, nil, io.ErrUnexpectedEOF
			}
			return 0, nil, err
		}

		plaintext, err := ntc.csRx.DecryptWithAd(hdr[:], cipherBuf)
		if err != nil {
			_ = ntc.Close()
			return 0, nil, err
		}

		switch frameType {
		case noiseFrameTypeRekeyInit:
			if err := ntc.handleIncomingRekeyInitLocked(plaintext); err != nil {
				_ = ntc.Close()
				return 0, nil, err
			}
			continue

		case noiseFrameTypeRekeyAck:
			if err := ntc.handleIncomingRekeyAckLocked(plaintext); err != nil {
				_ = ntc.Close()
				return 0, nil, err
			}
			continue

		case noiseFrameTypeRekeyCommit:
			if err := ntc.handleIncomingRekeyCommitLocked(plaintext); err != nil {
				_ = ntc.Close()
				return 0, nil, err
			}
			continue

		default:
			return frameType, plaintext, nil
		}
	}
}

func (ntc *noiseTransportConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > noiseMaxPlaintextLen {
			chunk = p[:noiseMaxPlaintextLen]
		}
		if err := ntc.WriteFrame(noiseFrameTypeData, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (ntc *noiseTransportConn) Read(p []byte) (int, error) {
	ntc.bufMu.Lock()
	if ntc.readBuf.Len() > 0 {
		n, err := ntc.readBuf.Read(p)
		ntc.bufMu.Unlock()
		return n, err
	}
	ntc.bufMu.Unlock()

	for {
		fType, plain, err := ntc.ReadFrame()
		if err != nil {
			return 0, err
		}
		if fType == noiseFrameTypeClose {
			return 0, io.EOF
		}
		if fType == noiseFrameTypeData {
			if len(plain) == 0 {
				continue
			}
			ntc.bufMu.Lock()
			ntc.readBuf.Write(plain)
			n, rErr := ntc.readBuf.Read(p)
			ntc.bufMu.Unlock()
			return n, rErr
		}
	}
}

func (ntc *noiseTransportConn) CloseWrite() error {
	_ = ntc.WriteFrame(noiseFrameTypeClose, nil)
	closeWriteTCP(ntc.raw)
	return nil
}

func (ntc *noiseTransportConn) Close() error {
	if ntc.closed.Swap(true) {
		return nil
	}
	ntc.rekeyMu.Lock()
	clear(ntc.rekeyEphPriv)
	clear(ntc.rekeyEphPub)
	if ntc.rekeyNextRx != nil {
		ntc.rekeyNextRx.Zeroize()
		ntc.rekeyNextRx = nil
	}
	if ntc.rekeyDoneCh != nil {
		select {
		case ntc.rekeyDoneCh <- net.ErrClosed:
		default:
		}
		ntc.rekeyDoneCh = nil
	}
	ntc.rekeyInProgress = false
	ntc.rekeyWaitCommit = false
	ntc.rekeyMu.Unlock()

	if ntc.csTx != nil {
		ntc.csTx.Zeroize()
	}
	if ntc.csRx != nil {
		ntc.csRx.Zeroize()
	}
	return ntc.raw.Close()
}

// ============================================================================
// 4. BIDIRECTIONAL HANDSHAKE ESTABLISHMENT & 1.5-RTT MESSAGE 3 GATE
// ============================================================================

func encodeNoiseMessage3Header(appCmd byte, targetPort uint16, timeHdr string) []byte {
	if len(timeHdr) > 120 {
		timeHdr = timeHdr[:120]
	}
	out := make([]byte, 4+len(timeHdr))
	out[0] = appCmd
	binary.BigEndian.PutUint16(out[1:3], targetPort)
	out[3] = byte(len(timeHdr))
	copy(out[4:], []byte(timeHdr))
	return out
}

func decodeNoiseMessage3Header(plain []byte) (appCmd byte, targetPort uint16, timeHdr string, err error) {
	if len(plain) < 4 {
		return 0, 0, "", errors.New("noise message 3 header too short")
	}
	appCmd = plain[0]
	targetPort = binary.BigEndian.Uint16(plain[1:3])
	thLen := int(plain[3])
	if 4+thLen > len(plain) {
		return 0, 0, "", errors.New("noise message 3 time header length mismatch")
	}
	timeHdr = string(plain[4 : 4+thLen])
	return appCmd, targetPort, timeHdr, nil
}

func dialNoiseStealthSession(
	peer ServerPeer,
	tc TunnelConfig,
	appCmd byte,
	targetPort uint16,
	timeout time.Duration,
) (*noiseTransportConn, error) {
	stateMu.RLock()
	cfgSnapshot := appCfg
	stateMu.RUnlock()

	localStatic, localSignPriv, localSignPubHex, psk, err := loadLocalNoiseKeyMaterial(cfgSnapshot, peer)
	if err != nil {
		return nil, err
	}

	remoteStaticPub, err := resolveExpectedRemoteStaticPublicKey(cfgSnapshot, peer)
	if err != nil {
		return nil, err
	}
	if len(remoteStaticPub) != 32 {
		remoteStaticPub, err = bootstrapFetchAgentStaticKey(peer, tc, timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to bootstrap remote static public key: %w", err)
		}
	}

	prologue := []byte("SAHAND-NOISE-IKPSK2-V2|" + strings.ToLower(peer.ID))
	hs, err := newNoiseIKpsk2HandshakeState(noiseIKpsk2Config{
		Initiator:     true,
		Prologue:      prologue,
		StaticKeypair: localStatic,
		PeerStatic:    remoteStaticPub,
		PresharedKey:  psk[:],
	})
	if err != nil {
		return nil, err
	}

	nonceHex, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	nowUnix := time.Now().Unix()

	idTranscript := []byte(fmt.Sprintf("SAHAND-NOISE-ID-V2|%s|%s|%s|%d|%s",
		strings.ToLower(cfgSnapshot.NodeID),
		strings.ToLower(peer.ID),
		hex.EncodeToString(localStatic.Public),
		nowUnix,
		nonceHex))
	idSig := ed25519.Sign(localSignPriv, idTranscript)

	msg1PayloadStruct := noiseHandshakeMsg1Payload{
		TimestampUnix: nowUnix,
		ClientNonce:   nonceHex,
		SenderNodeID:  strings.ToLower(cfgSnapshot.NodeID),
		PeerID:        strings.ToLower(peer.ID),
		SigningPubKey: localSignPubHex,
		IdentitySig:   hex.EncodeToString(idSig),
	}
	msg1PayloadBytes, err := json.Marshal(msg1PayloadStruct)
	if err != nil {
		return nil, err
	}

	msg1Wire, _, _, err := hs.WriteMessage(msg1PayloadBytes)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	rawConn, err := dialer.Dial("tcp", net.JoinHostPort(strings.TrimSpace(peer.IP), strconv.Itoa(tc.ListenPort)))
	if err != nil {
		return nil, err
	}
	enableKeepAlive(rawConn)
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	var wireHdr [3]byte
	wireHdr[0] = noiseWireTypeHandshakeMsg1
	binary.BigEndian.PutUint16(wireHdr[1:3], uint16(len(msg1Wire)))
	if _, err := rawConn.Write(wireHdr[:]); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if _, err := rawConn.Write(msg1Wire); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	if _, err := io.ReadFull(rawConn, wireHdr[:]); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if wireHdr[0] != noiseWireTypeHandshakeMsg2 {
		_ = rawConn.Close()
		return nil, errors.New("unexpected noise handshake message 2 wire type")
	}
	msg2Len := int(binary.BigEndian.Uint16(wireHdr[1:3]))
	if msg2Len <= 0 || msg2Len > noiseMaxHandshakeLen {
		_ = rawConn.Close()
		return nil, errors.New("invalid noise handshake message 2 length")
	}
	msg2Wire := make([]byte, msg2Len)
	if _, err := io.ReadFull(rawConn, msg2Wire); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	msg2Plain, csI2R, csR2I, err := hs.ReadMessage(msg2Wire)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	var msg2Payload noiseHandshakeMsg2Payload
	if err := unmarshalStrictJSON(msg2Plain, &msg2Payload); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(msg2Payload.ClientNonce), []byte(nonceHex)) != 1 {
		_ = rawConn.Close()
		return nil, errors.New("noise handshake message 2 nonce echo mismatch")
	}

	if subtle.ConstantTimeCompare(hs.PeerStatic(), remoteStaticPub) != 1 {
		_ = rawConn.Close()
		return nil, errors.New("noise PeerStatic() mismatch on initiator")
	}

	ntc := newNoiseTransportConn(rawConn, true, csI2R, csR2I, hs.ChannelBinding(), hs.PeerStatic())

	msg3Plain := encodeNoiseMessage3Header(appCmd, targetPort, buildMasterTimeHeader())
	if err := ntc.WriteFrame(noiseFrameTypeData, msg3Plain); err != nil {
		_ = ntc.Close()
		return nil, err
	}

	return ntc, nil
}

// ============================================================================
// 5. SERVER LISTENER, RATE LIMITERS, REPLAY GUARD & FORWARDING (:28010)
// ============================================================================

var (
	noiseStealthMu            sync.RWMutex
	noiseStealthUDPEntryByKey = make(map[string]*net.UDPConn)
)

func stopNoiseStealthPeerResources(peerID string) {
	noiseStealthMu.Lock()
	for k, uConn := range noiseStealthUDPEntryByKey {
		if strings.HasPrefix(k, peerID+"|") {
			_ = uConn.Close()
			delete(noiseStealthUDPEntryByKey, k)
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

	go func() {
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			enableKeepAlive(conn)
			go handleNoiseStealthServerConn(conn, peer, tc)
		}
	}()

	return ln, nil
}

func handleNoiseStealthServerConn(conn net.Conn, peer ServerPeer, tc TunnelConfig) {
	defer conn.Close()

	remoteIP := extractRemoteHostIP(conn.RemoteAddr())
	if !defaultNoisePreAuthIPLimiter.Allow(remoteIP, time.Now()) {
		return
	}

	_ = conn.SetDeadline(time.Now().Add(noiseHandshakeTimeout))

	var wireHdr [3]byte
	if _, err := io.ReadFull(conn, wireHdr[:]); err != nil {
		return
	}
	pktType := wireHdr[0]
	pktLen := int(binary.BigEndian.Uint16(wireHdr[1:3]))
	if pktLen <= 0 || pktLen > noiseMaxHandshakeLen {
		return
	}
	pktBytes := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, pktBytes); err != nil {
		return
	}

	if pktType == noiseWireTypeBootstrapReq {
		handleNoiseBootstrapRequest(conn, peer, pktBytes)
		return
	}
	if pktType != noiseWireTypeHandshakeMsg1 {
		return
	}

	stateMu.RLock()
	cfgSnapshot := appCfg
	for i := range appCfg.Servers {
		if appCfg.Servers[i].ID == peer.ID {
			peer = appCfg.Servers[i]
			break
		}
	}
	stateMu.RUnlock()

	localStatic, _, _, psk, err := loadLocalNoiseKeyMaterial(cfgSnapshot, peer)
	if err != nil {
		return
	}

	prologue := []byte("SAHAND-NOISE-IKPSK2-V2|" + strings.ToLower(peer.ID))
	hs, err := newNoiseIKpsk2HandshakeState(noiseIKpsk2Config{
		Initiator:     false,
		Prologue:      prologue,
		StaticKeypair: localStatic,
		PresharedKey:  psk[:],
	})
	if err != nil {
		return
	}

	msg1Plain, _, _, err := hs.ReadMessage(pktBytes)
	if err != nil {
		return
	}

	var msg1Payload noiseHandshakeMsg1Payload
	if err := unmarshalStrictJSON(msg1Plain, &msg1Payload); err != nil {
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(msg1Payload.PeerID)), []byte(strings.ToLower(peer.ID))) != 1 {
		return
	}

	if err := defaultNoiseReplayGuard.CheckAndAccept(
		peer.ID,
		msg1Payload.ClientNonce,
		hs.PeerEphemeral(),
		msg1Payload.TimestampUnix,
		time.Now(),
	); err != nil {
		return
	}

	peerStaticBytes := hs.PeerStatic()
	if len(peerStaticBytes) != 32 || subtle.ConstantTimeCompare(peerStaticBytes, localStatic.Public) == 1 {
		return
	}

	expectedRemoteStatic, _ := resolveExpectedRemoteStaticPublicKey(cfgSnapshot, peer)
	if len(expectedRemoteStatic) == 32 {
		if subtle.ConstantTimeCompare(peerStaticBytes, expectedRemoteStatic) != 1 {
			return
		}
	} else {
		agentSignPub, err1 := decodeHexExact(msg1Payload.SigningPubKey, ed25519.PublicKeySize)
		agentIdSig, err2 := decodeHexExact(msg1Payload.IdentitySig, ed25519.SignatureSize)
		if err1 != nil || err2 != nil {
			return
		}
		idTranscript := []byte(fmt.Sprintf("SAHAND-NOISE-ID-V2|%s|%s|%s|%d|%s",
			msg1Payload.SenderNodeID,
			msg1Payload.PeerID,
			hex.EncodeToString(peerStaticBytes),
			msg1Payload.TimestampUnix,
			msg1Payload.ClientNonce))
		if !ed25519.Verify(ed25519.PublicKey(agentSignPub), idTranscript, agentIdSig) {
			return
		}
	}

	if !defaultNoisePostAuthPeerLimiter.Allow(peer.ID, time.Now()) {
		return
	}

	msg2PayloadBytes, err := json.Marshal(noiseHandshakeMsg2Payload{
		ServerUnix:  time.Now().Unix(),
		ClientNonce: msg1Payload.ClientNonce,
	})
	if err != nil {
		return
	}

	msg2Wire, csI2R, csR2I, err := hs.WriteMessage(msg2PayloadBytes)
	if err != nil {
		return
	}

	wireHdr[0] = noiseWireTypeHandshakeMsg2
	binary.BigEndian.PutUint16(wireHdr[1:3], uint16(len(msg2Wire)))
	if _, err := conn.Write(wireHdr[:]); err != nil {
		return
	}
	if _, err := conn.Write(msg2Wire); err != nil {
		return
	}

	ntc := newNoiseTransportConn(conn, false, csI2R, csR2I, hs.ChannelBinding(), peerStaticBytes)
	defer ntc.Close()

	fType, msg3Plain, err := ntc.ReadFrame()
	if err != nil || fType != noiseFrameTypeData {
		return
	}

	appCmd, targetPort, timeHdr, err := decodeNoiseMessage3Header(msg3Plain)
	if err != nil {
		return
	}
	if timeHdr != "" {
		applyMasterTimeHeader(timeHdr)
	}

	if cfgSnapshot.Role == "master" && len(expectedRemoteStatic) == 0 {
		registerVerifiedAgentPublicKeys(peer.ID, hex.EncodeToString(peerStaticBytes), msg1Payload.SigningPubKey)
	}

	switch appCmd {
	case noiseAppCmdProbe:
		var ping [16]byte
		if _, err := io.ReadFull(ntc, ping[:]); err != nil {
			return
		}
		if _, err := ntc.Write(ping[:]); err != nil {
			return
		}
		markPeerConnectedInbound(peer.ID, remoteIP, tc.ID, tc.ListenPort, 1)

	case noiseAppCmdParitySync:
		handleWebTransportParitySyncStream(ntc, peer.ID, remoteIP)

	case noiseAppCmdTCPForward:
		if !tc.Enabled {
			return
		}
		authorizedPort, err := authorizeWSSTargetPort(tc, strconv.Itoa(int(targetPort)))
		if err != nil {
			return
		}
		targetConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", authorizedPort), 5*time.Second)
		if err != nil {
			return
		}
		defer targetConn.Close()
		enableKeepAlive(targetConn)

		_ = conn.SetDeadline(time.Time{})
		markPeerConnectedInbound(peer.ID, remoteIP, tc.ID, tc.ListenPort, 1)
		pipeNoiseTransportAndTCP(ntc, targetConn, tc.SpeedLimitMBps)

	case noiseAppCmdUDPForward:
		if !tc.Enabled {
			return
		}
		authorizedPort, err := authorizeWSSTargetPort(tc, strconv.Itoa(int(targetPort)))
		if err != nil {
			return
		}
		_, dgram, err := ntc.ReadFrame()
		if err != nil || len(dgram) == 0 {
			return
		}
		atomic.AddUint64(&appRxBytes, uint64(len(dgram)))

		uConn, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", authorizedPort), 3*time.Second)
		if err != nil {
			return
		}
		defer uConn.Close()
		_ = uConn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := uConn.Write(dgram); err != nil {
			return
		}
		rep := make([]byte, noiseMaxPlaintextLen)
		n, err := uConn.Read(rep)
		if err == nil && n > 0 {
			atomic.AddUint64(&appTxBytes, uint64(n))
			_ = ntc.WriteFrame(noiseFrameTypeData, rep[:n])
		}
	}
}

func pipeNoiseTransportAndTCP(ntc *noiseTransportConn, tcpConn net.Conn, speedLimitMBps string) {
	mbLimit := parseSpeedLimit(speedLimitMBps)
	toNoise := newThrottledWriter(ntc, &appTxBytes, mbLimit)
	toTCP := newThrottledWriter(tcpConn, &appRxBytes, mbLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 16*1024)
		_, _ = io.CopyBuffer(toNoise, tcpConn, buf)
		_ = ntc.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 16*1024)
		_, _ = io.CopyBuffer(toTCP, ntc, buf)
		closeWriteTCP(tcpConn)
	}()

	wg.Wait()
}

// ============================================================================
// 6. ENGINE 1 & ENGINE 2 ENTRY POINTS (probe, parity sync, TCP & UDP forward)
// ============================================================================

func probeNoiseStealth(peer ServerPeer, tc TunnelConfig, _ string) MethodResult {
	res := MethodResult{
		MethodID:  tc.ID,
		Direction: "outbound",
		TestedAt:  formatMasterClockSec(masterNow()),
	}

	start := time.Now()
	ntc, err := dialNoiseStealthSession(peer, tc, noiseAppCmdProbe, uint16(tc.ListenPort), 4*time.Second)
	if err != nil {
		res.Success = false
		msg := strings.ToLower(err.Error())
		switch {
		case strings.Contains(msg, "timeout"):
			res.ErrorReason = "Timeout"
		case strings.Contains(msg, "auth") || strings.Contains(msg, "static") || strings.Contains(msg, "token"):
			res.ErrorReason = "Authentication failure"
		default:
			res.ErrorReason = "Port unreachable"
		}
		return res
	}
	defer ntc.Close()

	var ping [16]byte
	var pong [16]byte
	_, _ = io.ReadFull(rand.Reader, ping[:])
	if _, err := ntc.Write(ping[:]); err != nil {
		res.Success = false
		res.ErrorReason = "Protocol mismatch"
		return res
	}
	if _, err := io.ReadFull(ntc, pong[:]); err != nil || !bytes.Equal(ping[:], pong[:]) {
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
	ntc, err := dialNoiseStealthSession(peer, tc, noiseAppCmdParitySync, uint16(tc.ListenPort), 4*time.Second)
	if err != nil {
		return false
	}
	defer ntc.Close()

	stateMu.RLock()
	senderID := appCfg.NodeID
	role := appCfg.Role
	certPin := appCfg.CertPin
	mSignPub := appCfg.MasterSigningPublicKey
	mNoisePub := appCfg.MasterNoiseStaticPublicKey
	aSignPub := appCfg.AgentSigningPublicKey
	aNoisePub := appCfg.AgentNoiseStaticPublicKey
	stateMu.RUnlock()

	padLen := 24 + randomIntN(64)
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

	rawPkt, err := json.Marshal(pkt)
	if err != nil {
		return false
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(rawPkt)))
	if _, err := ntc.Write(lenBuf[:]); err != nil {
		return false
	}
	if _, err := ntc.Write(rawPkt); err != nil {
		return false
	}

	if _, err := io.ReadFull(ntc, lenBuf[:]); err != nil {
		return false
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	if respLen == 0 || respLen > 256*1024 {
		return false
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(ntc, respBytes); err != nil {
		return false
	}
	var resp SyncResponse
	if json.Unmarshal(respBytes, &resp) != nil || !resp.OK {
		return false
	}

	applySyncResponseToPeer(peer.ID, resp)
	return true
}

func forwardNoiseStealthTraffic(client net.Conn, peer ServerPeer, tc TunnelConfig, targetPort string) {
	defer client.Close()

	authorizedPort, err := authorizeWSSTargetPort(tc, targetPort)
	if err != nil {
		return
	}
	portNum, _ := strconv.Atoi(authorizedPort)

	ntc, err := dialNoiseStealthSession(peer, tc, noiseAppCmdTCPForward, uint16(portNum), 5*time.Second)
	if err != nil {
		return
	}
	defer ntc.Close()
	_ = ntc.raw.SetDeadline(time.Time{})

	pipeNoiseTransportAndTCP(ntc, client, tc.SpeedLimitMBps)
}

func startNoiseStealthUDPEntryForwarder(peer ServerPeer, tc TunnelConfig, targetPort string) net.PacketConn {
	authorizedPort, err := authorizeWSSTargetPort(tc, targetPort)
	if err != nil {
		return nil
	}
	portNum, _ := strconv.Atoi(authorizedPort)

	uAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(portNum)))
	if err != nil {
		return nil
	}
	entryConn, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		return nil
	}
	configureUDPSocketBuffers(entryConn)

	muxKey := fmt.Sprintf("%s|%d", peer.ID, portNum)
	noiseStealthMu.Lock()
	if old, ok := noiseStealthUDPEntryByKey[muxKey]; ok {
		_ = old.Close()
	}
	noiseStealthUDPEntryByKey[muxKey] = entryConn
	noiseStealthMu.Unlock()

	go func() {
		buf := make([]byte, noiseMaxPlaintextLen)
		for {
			n, cliAddr, rErr := entryConn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			if n <= 0 {
				continue
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			cliCopy := cloneUDPAddr(cliAddr)

			go func(dgram []byte, cAddr *net.UDPAddr) {
				ntc, dErr := dialNoiseStealthSession(peer, tc, noiseAppCmdUDPForward, uint16(portNum), 4*time.Second)
				if dErr != nil {
					return
				}
				defer ntc.Close()

				atomic.AddUint64(&appTxBytes, uint64(len(dgram)))
				if err := ntc.WriteFrame(noiseFrameTypeData, dgram); err != nil {
					return
				}
				fType, rep, err := ntc.ReadFrame()
				if err == nil && fType == noiseFrameTypeData && len(rep) > 0 {
					atomic.AddUint64(&appRxBytes, uint64(len(rep)))
					_, _ = entryConn.WriteToUDP(rep, cAddr)
				}
			}(payload, cliCopy)
		}
	}()

	return entryConn
}
