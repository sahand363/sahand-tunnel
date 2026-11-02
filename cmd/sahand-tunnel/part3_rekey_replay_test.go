package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func createNoiseConnectedPair(t *testing.T) (*noiseTransportConn, *noiseTransportConn, func()) {
	t.Helper()
	var k1, k2, m1, m2, h [32]byte
	_, _ = io.ReadFull(rand.Reader, k1[:])
	_, _ = io.ReadFull(rand.Reader, k2[:])
	_, _ = io.ReadFull(rand.Reader, m1[:])
	_, _ = io.ReadFull(rand.Reader, m2[:])
	_, _ = io.ReadFull(rand.Reader, h[:])

	c1, c2 := net.Pipe()
	clientTC := newNoiseTransportConn(
		c1,
		true,
		newNoiseCipherState(k1, m1),
		newNoiseCipherState(k2, m2),
		h,
		nil,
	)
	serverTC := newNoiseTransportConn(
		c2,
		false,
		newNoiseCipherState(k1, m1),
		newNoiseCipherState(k2, m2),
		h,
		nil,
	)
	cleanup := func() {
		_ = clientTC.Close()
		_ = serverTC.Close()
	}
	return clientTC, serverTC, cleanup
}

func TestPart3ExplicitAndAutoTransportRekeyAcrossEpochs(t *testing.T) {
	clientTC, serverTC, cleanup := createNoiseConnectedPair(t)
	defer cleanup()

	initialTranscript := clientTC.transcriptHash

	echoDone := make(chan error, 1)
	go func() {
		defer close(echoDone)
		buf := make([]byte, 8192)
		for {
			n, err := serverTC.Read(buf)
			if err != nil {
				if err == io.EOF {
					return
				}
				echoDone <- err
				return
			}
			if _, wErr := serverTC.Write(buf[:n]); wErr != nil {
				echoDone <- wErr
				return
			}
		}
	}()

	for targetEpoch := uint32(1); targetEpoch <= 3; targetEpoch++ {
		msgBefore := []byte("payload-before-rekey-epoch-" + strconv.Itoa(int(targetEpoch)))
		if _, err := clientTC.Write(msgBefore); err != nil {
			t.Fatalf("clientTC.Write before epoch %d failed: %v", targetEpoch, err)
		}
		replyBefore := make([]byte, len(msgBefore))
		if _, err := io.ReadFull(clientTC, replyBefore); err != nil || !bytes.Equal(replyBefore, msgBefore) {
			t.Fatalf("echo mismatch before rekey to epoch %d: err=%v", targetEpoch, err)
		}

		if err := clientTC.Rekey(4 * time.Second); err != nil {
			t.Fatalf("explicit Rekey(%d) failed: %v", targetEpoch, err)
		}
	}

	_ = clientTC.CloseWrite()
	if err := <-echoDone; err != nil {
		t.Fatalf("server echo loop failed: %v", err)
	}
	if clientTC.CurrentEpoch() != 3 {
		t.Fatalf("expected client epoch 3, got %d", clientTC.CurrentEpoch())
	}
	if clientTC.transcriptHash == initialTranscript {
		t.Fatalf("expected transcriptHash to evolve across rekey epochs")
	}
}

func TestPart3AutomaticRekeyUnderConcurrentBidirectionalTraffic(t *testing.T) {
	clientTC, serverTC, cleanup := createNoiseConnectedPair(t)
	defer cleanup()

	clientTC.SetAutoRekeyInterval(4)

	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		buf := make([]byte, 4096)
		for {
			n, err := serverTC.Read(buf)
			if err != nil {
				if err == io.EOF {
					return
				}
				serverDone <- err
				return
			}
			if _, wErr := serverTC.Write(buf[:n]); wErr != nil {
				serverDone <- wErr
				return
			}
		}
	}()

	const frameCount = 16
	const chunkSize = 1024
	totalSent := make([]byte, frameCount*chunkSize)
	_, _ = io.ReadFull(rand.Reader, totalSent)

	writeErrCh := make(chan error, 1)
	go func() {
		for i := 0; i < frameCount; i++ {
			chunk := totalSent[i*chunkSize : (i+1)*chunkSize]
			if _, err := clientTC.Write(chunk); err != nil {
				writeErrCh <- err
				return
			}
		}
		writeErrCh <- nil
	}()

	totalRecv := make([]byte, len(totalSent))
	if _, err := io.ReadFull(clientTC, totalRecv); err != nil {
		t.Fatalf("io.ReadFull during automatic rekey streaming failed: %v", err)
	}
	if wErr := <-writeErrCh; wErr != nil {
		t.Fatalf("clientTC.Write during automatic rekey streaming failed: %v", wErr)
	}
	if !bytes.Equal(totalSent, totalRecv) {
		t.Fatalf("streamed data corrupted across automatic rekey epochs")
	}
	if clientTC.CurrentEpoch() < 1 || serverTC.CurrentEpoch() < 1 {
		t.Fatalf("expected automatic rekey to advance epochs, got client=%d server=%d",
			clientTC.CurrentEpoch(), serverTC.CurrentEpoch())
	}

	_ = clientTC.CloseWrite()
	if err := <-serverDone; err != nil {
		t.Fatalf("server echo loop error: %v", err)
	}
}

func TestPart3InvalidAndInterruptedRekeyHandling(t *testing.T) {
	clientTC, serverTC, cleanup := createNoiseConnectedPair(t)
	defer cleanup()

	go func() {
		badInit := make([]byte, noiseRekeyPayloadLen)
		binary.BigEndian.PutUint32(badInit[0:4], 99)
		_ = clientTC.WriteFrame(noiseFrameTypeRekeyInit, badInit)
	}()

	if _, _, err := serverTC.ReadFrame(); err == nil {
		t.Fatalf("expected out-of-sequence REKEY_INIT epoch 99 to be rejected")
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	var k1, k2, m1, m2, h [32]byte
	_, _ = io.ReadFull(rand.Reader, k1[:])
	_, _ = io.ReadFull(rand.Reader, k2[:])
	stallClient := newNoiseTransportConn(c1, true, newNoiseCipherState(k1, m1), newNoiseCipherState(k2, m2), h, nil)
	go func() {
		_, _ = io.Copy(io.Discard, c2)
	}()

	if err := stallClient.Rekey(120 * time.Millisecond); err == nil {
		t.Fatalf("expected stalled Rekey to fail with timeout")
	}
}

func TestPart3ReplayProtectionAndRateLimiting(t *testing.T) {
	rg := newNoiseHandshakeReplayGuard(8)
	now := time.Now()
	var ephPub [32]byte
	_, _ = io.ReadFull(rand.Reader, ephPub[:])

	if err := rg.CheckAndAccept("peer-01", "nonce-abc", ephPub[:], now.Unix(), now); err != nil {
		t.Fatalf("expected fresh handshake nonce to be accepted: %v", err)
	}

	var wg sync.WaitGroup
	var acceptedReplays int32
	var mu sync.Mutex
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := rg.CheckAndAccept("peer-01", "nonce-abc", ephPub[:], now.Unix(), now); err == nil {
				mu.Lock()
				acceptedReplays++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if acceptedReplays != 0 {
		t.Fatalf("expected 0 concurrent replays to be accepted, got %d", acceptedReplays)
	}

	if err := rg.CheckAndAccept("peer-01", "nonce-old", ephPub[:], now.Unix()-600, now); err == nil {
		t.Fatalf("expected expired handshake timestamp to be rejected")
	}

	for i := 0; i < 25; i++ {
		var ep [32]byte
		_, _ = io.ReadFull(rand.Reader, ep[:])
		if err := rg.CheckAndAccept("peer-01", "nonce-"+strconv.Itoa(i), ep[:], now.Unix(), now); err != nil {
			t.Fatalf("legitimate handshake #%d rejected during cache rotation: %v", i, err)
		}
	}

	peer, tc := setupNoiseStealthTestEnv(t)
	tc.ListenPort = allocateFreeTCPPort(t)
	tc.Enabled = true

	stateMu.Lock()
	appCfg.Servers[0].AgentNoiseStaticPublicKey = appCfg.AgentNoiseStaticPublicKey
	appCfg.Servers[0].Tunnels[9] = tc
	peer = appCfg.Servers[0]
	cfgSnap := appCfg
	stateMu.Unlock()

	ln, err := startNoiseStealthServerListener(peer, tc)
	if err != nil {
		t.Fatalf("startNoiseStealthServerListener failed: %v", err)
	}
	defer ln.Close()

	localStatic, localSignPriv, localSignPubHex, psk, err := loadLocalNoiseKeyMaterial(cfgSnap, peer)
	if err != nil {
		t.Fatalf("loadLocalNoiseKeyMaterial failed: %v", err)
	}
	remoteStatic, _ := decodeHexExact(cfgSnap.AgentNoiseStaticPublicKey, 32)
	hs, err := newNoiseIKpsk2HandshakeState(noiseIKpsk2Config{
		Initiator:     true,
		Prologue:      []byte("SAHAND-NOISE-IKPSK2-V2|" + strings.ToLower(peer.ID)),
		StaticKeypair: localStatic,
		PeerStatic:    remoteStatic,
		PresharedKey:  psk[:],
	})
	if err != nil {
		t.Fatalf("newNoiseIKpsk2HandshakeState failed: %v", err)
	}

	nowUnix := time.Now().Unix()
	nonceHex, _ := randomHex(16)
	idTranscript := []byte("SAHAND-NOISE-ID-V2|" + strings.ToLower(cfgSnap.NodeID) + "|" + strings.ToLower(peer.ID) + "|" + hex.EncodeToString(localStatic.Public) + "|" + strconv.FormatInt(nowUnix, 10) + "|" + nonceHex)
	idSig := hex.EncodeToString(ed25519.Sign(localSignPriv, idTranscript))

	msg1Payload, _ := json.Marshal(noiseHandshakeMsg1Payload{
		TimestampUnix: nowUnix,
		ClientNonce:   nonceHex,
		SenderNodeID:  strings.ToLower(cfgSnap.NodeID),
		PeerID:        strings.ToLower(peer.ID),
		SigningPubKey: localSignPubHex,
		IdentitySig:   idSig,
	})
	msg1Wire, _, _, err := hs.WriteMessage(msg1Payload)
	if err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	sendCapturedMsg1 := func() error {
		c, dErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tc.ListenPort)), 2*time.Second)
		if dErr != nil {
			return dErr
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		var hdr [3]byte
		hdr[0] = noiseWireTypeHandshakeMsg1
		binary.BigEndian.PutUint16(hdr[1:3], uint16(len(msg1Wire)))
		_, _ = c.Write(hdr[:])
		_, _ = c.Write(msg1Wire)
		_, rErr := io.ReadFull(c, hdr[:])
		return rErr
	}

	if err := sendCapturedMsg1(); err != nil {
		t.Fatalf("expected initial Message 1 delivery to receive Message 2: %v", err)
	}
	if err := sendCapturedMsg1(); err == nil {
		t.Fatalf("expected replayed Message 1 wire packet to be rejected by server")
	}

	limiter := newNoiseKeyedRateLimiter(3, 1, 16)
	t0 := time.Now()
	if !limiter.Allow("198.51.100.77", t0) || !limiter.Allow("198.51.100.77", t0) || !limiter.Allow("198.51.100.77", t0) {
		t.Fatalf("expected first 3 burst requests to be allowed")
	}
	if limiter.Allow("198.51.100.77", t0) {
		t.Fatalf("expected 4th immediate request to be rate-limited")
	}
	if !limiter.Allow("198.51.100.77", t0.Add(1100*time.Millisecond)) {
		t.Fatalf("expected request after 1.1s token refill to be allowed")
	}
}
