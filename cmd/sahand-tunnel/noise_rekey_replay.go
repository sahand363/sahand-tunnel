package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	noiseRekeyPayloadLen       = 36 // [NextEpoch:4B][EphemeralPub:32B]
	noiseRekeyCommitPayloadLen = 4  // [NextEpoch:4B]
	noiseDefaultRekeyWait      = 8 * time.Second
	noiseDefaultAutoRekeyCount = 32768

	noiseReplayWindowSec     = 300
	noiseReplayMaxPerGen     = 8192
	noiseReplayRotatePeriod  = 150 * time.Second
	noiseMaxRateTrackedHosts = 4096
)

// ============================================================================
// 1. REPLAY PROTECTION (TWO-GENERATION ROTATING DEDUPLICATOR)
// ============================================================================

type noiseHandshakeReplayGuard struct {
	mu         sync.Mutex
	curGen     map[string]int64
	prevGen    map[string]int64
	lastRotate time.Time
	maxPerGen  int
}

func newNoiseHandshakeReplayGuard(maxPerGen int) *noiseHandshakeReplayGuard {
	if maxPerGen <= 0 {
		maxPerGen = noiseReplayMaxPerGen
	}
	return &noiseHandshakeReplayGuard{
		curGen:     make(map[string]int64),
		prevGen:    make(map[string]int64),
		lastRotate: time.Now(),
		maxPerGen:  maxPerGen,
	}
}

var defaultNoiseReplayGuard = newNoiseHandshakeReplayGuard(noiseReplayMaxPerGen)

func (rg *noiseHandshakeReplayGuard) CheckAndAccept(peerID, clientNonce string, ephemeralPub []byte, timestampUnix int64, now time.Time) error {
	if strings.TrimSpace(peerID) == "" || strings.TrimSpace(clientNonce) == "" || len(ephemeralPub) != 32 {
		return errors.New("incomplete handshake replay parameters")
	}
	diff := now.Unix() - timestampUnix
	if diff < -noiseReplayWindowSec || diff > noiseReplayWindowSec {
		return errors.New("handshake timestamp outside acceptable skew window")
	}

	key := strings.ToLower(strings.TrimSpace(peerID)) + "|" +
		strings.ToLower(strings.TrimSpace(clientNonce)) + "|" +
		hex.EncodeToString(ephemeralPub)

	rg.mu.Lock()
	defer rg.mu.Unlock()

	if now.Sub(rg.lastRotate) >= noiseReplayRotatePeriod || len(rg.curGen) >= rg.maxPerGen {
		rg.prevGen = rg.curGen
		rg.curGen = make(map[string]int64)
		rg.lastRotate = now
	}

	if _, exists := rg.curGen[key]; exists {
		return errors.New("replayed handshake message rejected")
	}
	if ts, exists := rg.prevGen[key]; exists {
		if now.Unix()-ts <= noiseReplayWindowSec {
			return errors.New("replayed handshake message rejected")
		}
		delete(rg.prevGen, key)
	}

	rg.curGen[key] = timestampUnix
	return nil
}

func (rg *noiseHandshakeReplayGuard) Reset() {
	rg.mu.Lock()
	rg.curGen = make(map[string]int64)
	rg.prevGen = make(map[string]int64)
	rg.lastRotate = time.Now()
	rg.mu.Unlock()
}

// ============================================================================
// 2. PRE-AUTH IP RATE LIMITER & POST-AUTH PEER RATE LIMITER
// ============================================================================

type noiseTokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

type noiseKeyedRateLimiter struct {
	mu           sync.Mutex
	buckets      map[string]*noiseTokenBucket
	burst        float64
	refillPerSec float64
	maxKeys      int
}

func newNoiseKeyedRateLimiter(burst, refillPerSec float64, maxKeys int) *noiseKeyedRateLimiter {
	if burst < 1 {
		burst = 1
	}
	if refillPerSec <= 0 {
		refillPerSec = 1
	}
	if maxKeys <= 0 {
		maxKeys = noiseMaxRateTrackedHosts
	}
	return &noiseKeyedRateLimiter{
		buckets:      make(map[string]*noiseTokenBucket),
		burst:        burst,
		refillPerSec: refillPerSec,
		maxKeys:      maxKeys,
	}
}

func (rl *noiseKeyedRateLimiter) Allow(key string, now time.Time) bool {
	k := strings.TrimSpace(key)
	if k == "" {
		k = "unknown"
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if len(rl.buckets) >= rl.maxKeys {
		for id, b := range rl.buckets {
			if now.Sub(b.lastRefill) > 60*time.Second {
				delete(rl.buckets, id)
			}
		}
		if len(rl.buckets) >= rl.maxKeys {
			for id := range rl.buckets {
				delete(rl.buckets, id)
				break
			}
		}
	}

	b, exists := rl.buckets[k]
	if !exists {
		rl.buckets[k] = &noiseTokenBucket{
			tokens:     rl.burst - 1,
			lastRefill: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.refillPerSec
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
		b.lastRefill = now
	}

	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

func extractRemoteHostIP(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

var (
	defaultNoisePreAuthIPLimiter    = newNoiseKeyedRateLimiter(128, 64, noiseMaxRateTrackedHosts)
	defaultNoisePostAuthPeerLimiter = newNoiseKeyedRateLimiter(256, 128, noiseMaxRateTrackedHosts)
)

// ============================================================================
// 3. EPHEMERAL X25519 + HKDF-HMAC-SHA256 TRANSPORT REKEY ENGINE
// ============================================================================

func deriveNoiseRekeyEpochKeys(
	prevTranscript [32]byte,
	nextEpoch uint32,
	initEphPub []byte,
	respEphPub []byte,
	dhSecret []byte,
) (csI2R *noiseCipherState, csR2I *noiseCipherState, newTranscript [32]byte, err error) {
	if len(initEphPub) != 32 || len(respEphPub) != 32 || len(dhSecret) != 32 {
		return nil, nil, newTranscript, errors.New("invalid ephemeral key material for noise rekey")
	}

	var epochBytes [4]byte
	binary.BigEndian.PutUint32(epochBytes[:], nextEpoch)

	h := newUnkeyedBLAKE2s()
	_, _ = h.Write(prevTranscript[:])
	_, _ = h.Write([]byte("SAHAND-NOISE-REKEY-TRANSCRIPT-V2|"))
	_, _ = h.Write(epochBytes[:])
	_, _ = h.Write(initEphPub)
	_, _ = h.Write(respEphPub)
	copy(newTranscript[:], h.Sum(nil))

	prk := hkdf.Extract(sha256.New, dhSecret, newTranscript[:])
	defer clear(prk)

	derive32 := func(label string) ([32]byte, error) {
		var out [32]byte
		info := make([]byte, 0, len(label)+4)
		info = append(info, []byte(label)...)
		info = append(info, epochBytes[:]...)
		r := hkdf.Expand(sha256.New, prk, info)
		if _, rErr := io.ReadFull(r, out[:]); rErr != nil {
			return out, rErr
		}
		return out, nil
	}

	kI2R, err := derive32("sahand-noise-rekey-v2|i2r-key|")
	if err != nil {
		return nil, nil, newTranscript, err
	}
	kR2I, err := derive32("sahand-noise-rekey-v2|r2i-key|")
	if err != nil {
		return nil, nil, newTranscript, err
	}
	maskI2R, err := derive32("sahand-noise-rekey-v2|i2r-mask|")
	if err != nil {
		return nil, nil, newTranscript, err
	}
	maskR2I, err := derive32("sahand-noise-rekey-v2|r2i-mask|")
	if err != nil {
		return nil, nil, newTranscript, err
	}

	cs1 := newNoiseCipherState(kI2R, maskI2R)
	cs2 := newNoiseCipherState(kR2I, maskR2I)
	clear(kI2R[:])
	clear(kR2I[:])
	clear(maskI2R[:])
	clear(maskR2I[:])

	return cs1, cs2, newTranscript, nil
}

func (ntc *noiseTransportConn) Rekey(timeout time.Duration) error {
	if ntc.closed.Load() {
		return net.ErrClosed
	}
	if timeout <= 0 {
		timeout = noiseDefaultRekeyWait
	}

	doneCh, payload, err := ntc.beginRekeyInit()
	if err != nil {
		return err
	}

	if err := ntc.WriteFrame(noiseFrameTypeRekeyInit, payload); err != nil {
		_ = ntc.Close()
		return err
	}

	deadline := time.Now().Add(timeout)
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	go func() {
		for time.Now().Before(deadline) {
			ntc.rekeyMu.Lock()
			inProg := ntc.rekeyInProgress
			ntc.rekeyMu.Unlock()
			if !inProg {
				return
			}
			fType, plain, rErr := ntc.ReadFrame()
			if rErr != nil {
				return
			}
			if fType == noiseFrameTypeData && len(plain) > 0 {
				ntc.bufMu.Lock()
				ntc.readBuf.Write(plain)
				ntc.bufMu.Unlock()
			}
		}
	}()

	select {
	case rErr := <-doneCh:
		if rErr != nil {
			_ = ntc.Close()
			return rErr
		}
		return nil
	case <-timer.C:
		_ = ntc.Close()
		return errors.New("noise transport rekey timed out")
	}
}

func (ntc *noiseTransportConn) beginRekeyInit() (chan error, []byte, error) {
	ntc.rekeyMu.Lock()
	defer ntc.rekeyMu.Unlock()

	if ntc.closed.Load() {
		return nil, nil, net.ErrClosed
	}
	if ntc.rekeyInProgress || ntc.rekeyWaitCommit {
		return nil, nil, errors.New("noise transport rekey already in progress")
	}

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	nextEpoch := ntc.epoch + 1
	ephPubBytes := ephPriv.PublicKey().Bytes()

	ntc.rekeyInProgress = true
	ntc.rekeyPendingEpoch = nextEpoch
	ntc.rekeyEphPriv = append([]byte(nil), ephPriv.Bytes()...)
	ntc.rekeyEphPub = append([]byte(nil), ephPubBytes...)
	doneCh := make(chan error, 1)
	ntc.rekeyDoneCh = doneCh

	payload := make([]byte, noiseRekeyPayloadLen)
	binary.BigEndian.PutUint32(payload[0:4], nextEpoch)
	copy(payload[4:36], ephPubBytes)

	return doneCh, payload, nil
}

func (ntc *noiseTransportConn) handleIncomingRekeyInitLocked(plain []byte) error {
	if len(plain) != noiseRekeyPayloadLen {
		return errors.New("invalid REKEY_INIT payload length")
	}
	nextEpoch := binary.BigEndian.Uint32(plain[0:4])
	peerEphPub := plain[4:36]

	ntc.rekeyMu.Lock()
	if ntc.rekeyInProgress || ntc.rekeyWaitCommit || nextEpoch != ntc.epoch+1 {
		ntc.rekeyMu.Unlock()
		return fmt.Errorf("unexpected REKEY_INIT epoch %d (current %d)", nextEpoch, ntc.epoch)
	}

	respEphPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		ntc.rekeyMu.Unlock()
		return err
	}
	respEphPub := respEphPriv.PublicKey().Bytes()

	dhSecret, err := performX25519DH(respEphPriv.Bytes(), peerEphPub)
	if err != nil {
		ntc.rekeyMu.Unlock()
		return err
	}

	csI2R, csR2I, newTranscript, err := deriveNoiseRekeyEpochKeys(
		ntc.transcriptHash,
		nextEpoch,
		peerEphPub,
		respEphPub,
		dhSecret,
	)
	clear(dhSecret)
	if err != nil {
		ntc.rekeyMu.Unlock()
		return err
	}

	var newTx, newRx *noiseCipherState
	if ntc.initiator {
		newTx = csI2R
		newRx = csR2I
	} else {
		newTx = csR2I
		newRx = csI2R
	}

	ackPayload := make([]byte, noiseRekeyPayloadLen)
	binary.BigEndian.PutUint32(ackPayload[0:4], nextEpoch)
	copy(ackPayload[4:36], respEphPub)

	ntc.writeMu.Lock()
	wErr := ntc.writeFrameLocked(noiseFrameTypeRekeyAck, ackPayload)
	if wErr != nil {
		ntc.writeMu.Unlock()
		ntc.rekeyMu.Unlock()
		return wErr
	}
	oldTx := ntc.csTx
	ntc.csTx = newTx
	ntc.txFramesInEpoch = 0
	ntc.writeMu.Unlock()
	if oldTx != nil {
		oldTx.Zeroize()
	}

	ntc.rekeyPendingEpoch = nextEpoch
	ntc.rekeyNextRx = newRx
	ntc.rekeyNextTranscript = newTranscript
	ntc.rekeyWaitCommit = true
	ntc.rekeyMu.Unlock()

	return nil
}

func (ntc *noiseTransportConn) handleIncomingRekeyAckLocked(plain []byte) error {
	if len(plain) != noiseRekeyPayloadLen {
		return errors.New("invalid REKEY_ACK payload length")
	}
	nextEpoch := binary.BigEndian.Uint32(plain[0:4])
	respEphPub := plain[4:36]

	ntc.rekeyMu.Lock()
	if !ntc.rekeyInProgress || nextEpoch != ntc.rekeyPendingEpoch || len(ntc.rekeyEphPriv) != 32 {
		ntc.rekeyMu.Unlock()
		return fmt.Errorf("unexpected REKEY_ACK for epoch %d", nextEpoch)
	}

	dhSecret, err := performX25519DH(ntc.rekeyEphPriv, respEphPub)
	clear(ntc.rekeyEphPriv)
	ntc.rekeyEphPriv = nil
	if err != nil {
		doneCh := ntc.rekeyDoneCh
		ntc.rekeyInProgress = false
		ntc.rekeyMu.Unlock()
		if doneCh != nil {
			doneCh <- err
		}
		return err
	}

	csI2R, csR2I, newTranscript, err := deriveNoiseRekeyEpochKeys(
		ntc.transcriptHash,
		nextEpoch,
		ntc.rekeyEphPub,
		respEphPub,
		dhSecret,
	)
	clear(dhSecret)
	clear(ntc.rekeyEphPub)
	ntc.rekeyEphPub = nil
	if err != nil {
		doneCh := ntc.rekeyDoneCh
		ntc.rekeyInProgress = false
		ntc.rekeyMu.Unlock()
		if doneCh != nil {
			doneCh <- err
		}
		return err
	}

	var newTx, newRx *noiseCipherState
	if ntc.initiator {
		newTx = csI2R
		newRx = csR2I
	} else {
		newTx = csR2I
		newRx = csI2R
	}

	oldRx := ntc.csRx
	ntc.csRx = newRx
	if oldRx != nil {
		oldRx.Zeroize()
	}

	commitPayload := make([]byte, noiseRekeyCommitPayloadLen)
	binary.BigEndian.PutUint32(commitPayload[0:4], nextEpoch)

	ntc.writeMu.Lock()
	wErr := ntc.writeFrameLocked(noiseFrameTypeRekeyCommit, commitPayload)
	if wErr == nil {
		oldTx := ntc.csTx
		ntc.csTx = newTx
		ntc.txFramesInEpoch = 0
		if oldTx != nil {
			oldTx.Zeroize()
		}
	}
	ntc.writeMu.Unlock()

	doneCh := ntc.rekeyDoneCh
	ntc.rekeyDoneCh = nil
	ntc.rekeyInProgress = false
	if wErr == nil {
		ntc.epoch = nextEpoch
		ntc.transcriptHash = newTranscript
	}
	ntc.rekeyMu.Unlock()

	if doneCh != nil {
		doneCh <- wErr
	}
	return wErr
}

func (ntc *noiseTransportConn) handleIncomingRekeyCommitLocked(plain []byte) error {
	if len(plain) != noiseRekeyCommitPayloadLen {
		return errors.New("invalid REKEY_COMMIT payload length")
	}
	nextEpoch := binary.BigEndian.Uint32(plain[0:4])

	ntc.rekeyMu.Lock()
	defer ntc.rekeyMu.Unlock()

	if !ntc.rekeyWaitCommit || nextEpoch != ntc.rekeyPendingEpoch || ntc.rekeyNextRx == nil {
		return fmt.Errorf("unexpected REKEY_COMMIT for epoch %d", nextEpoch)
	}

	oldRx := ntc.csRx
	ntc.csRx = ntc.rekeyNextRx
	ntc.rekeyNextRx = nil
	ntc.rekeyWaitCommit = false
	ntc.epoch = nextEpoch
	ntc.transcriptHash = ntc.rekeyNextTranscript
	if oldRx != nil {
		oldRx.Zeroize()
	}
	return nil
}
