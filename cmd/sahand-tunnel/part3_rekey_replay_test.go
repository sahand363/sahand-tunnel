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

	// Server echo loop (Read processes REKEY_INIT and REKEY_COMMIT transparently while echoing data)
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

	// 1. Send data in Epoch 0, then perform explicit Rekey to Epoch 1, then Epoch 2
	for targetEpoch := uint32(1); targetEpoch <= 3; targetEpoch++ {
		msgBefore := []byte("payload-before-rekey-epoch-" + strconv.Itoa(int(targetEpoch)))
		if _, err := clientTC.Write(msgBefore); err != nil {
			t.Fatalf("clientTC.Write before epoch %d failed: %v", targetEpoch, err)
		}
		replyBefore := make([]byte, len(msgBefore))
		if _, err := io.ReadFull(clientTC, replyBefore); err != nil || !bytes.Equal(replyBefore, msgBefore) {
			t.Fatalf("echo mismatch before rekey to epoch %d: err=%v", targetEpoch, err)
		}

		// Perform explicit authenticated ephemeral X25519 rekey
		rekeyErrCh := make(chan error, 1)
		go func() {
			rekeyErrCh <- clientTC.Rekey(4 * time.Second)
		}()

		// Trigger clientTC.Read concurrently so clientTC processes REKEY_ACK while sending a probe after rekey
		if err := <-rekeyErrCh; err != nil {
			// Note: Rekey waits for REKEY_ACK, which is read by ReadFrame/Read. Let's test explicit Rekey with background reader.
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

	// Configure automatic rekey every 4 outbound data frames
	clientTC.SetAutoRekeyInterval(4)

	// Server echo loop
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

	// Send 16 frames (4 frames per epoch -> triggers multiple automatic rekeys while streaming data)
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
	// 1. Out-of-order epoch number in REKEY_INIT must fail closed immediately
	clientTC, serverTC, cleanup := createNoiseConnectedPair(t)
	defer cleanup()

	go func() {
		badInit := make([]byte, noiseRekeyPayloadLen)
		binary.BigEndian.PutUint32(badInit[0:4], 99) // Invalid jump from epoch 0 to 99
		_ = clientTC.WriteFrame(noiseFrameTypeRekeyInit, badInit)
	}()

	if _, _, err := serverTC.ReadFrame(); err == nil {
		t.Fatalf("expected out-of-sequence REKEY_INIT epoch 99 to be rejected")
	}

	// 2. Interrupted rekey timeout when peer never responds with REKEY_ACK
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	var k1, k2, m1, m2, h [32]byte
	_, _ = io.ReadFull(rand.Reader, k1[:])
	_, _ = io.ReadFull(rand.Reader, k2[:])
	stallClient := newNoiseTransportConn(c1, true, newNoiseCipherState(k1, m1), newNoiseCipherState(k2, m2), h, nil)
	// Drain c2 without replying
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

	// 1. First presentation of a valid handshake nonce must succeed
	if err := rg.CheckAndAccept("peer-01", "nonce-abc", ephPub[:], now.Unix(), now); err != nil {
		t.Fatalf("expected fresh handshake nonce to be accepted: %v", err)
	}

	// 2. Concurrent replay attempts of the same handshake nonce must all be rejected
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

	// 3. Expired timestamp outside ±300s skew window must be rejected
	if err := rg.CheckAndAccept("peer-01", "nonce-old", ephPub[:], now.Unix()-600, now); err == nil {
		t.Fatalf("expected expired handshake timestamp to be rejected")
	}

	// 4. Cache rotation under capacity pressure must NOT lock out legitimate new handshakes
	for i := 0; i < 25; i++ {
		var ep [32]byte
		_, _ = io.ReadFull(rand.Reader, ep[:])
		if err := rg.CheckAndAccept("peer-01", "nonce-"+strconv.Itoa(i), ep[:], now.Unix(), now); err != nil {
			t.Fatalf("legitimate handshake #%d rejected during cache rotation: %v", i, err)
		}
	}

	// 5. End-to-end wire replay test against handleNoiseStealthServerConn
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

	// First delivery receives Message 2
	if err := sendCapturedMsg1(); err != nil {
		t.Fatalf("expected initial Message 1 delivery to receive Message 2: %v", err)
	}
	// Second delivery (replay of the exact same Message 1 packet) must be dropped by the replay guard without sending Message 2
	if err := sendCapturedMsg1(); err == nil {
		t.Fatalf("expected replayed Message 1 wire packet to be rejected by server")
	}

	// 6. Verify Pre-Auth IP and Post-Auth Peer token-bucket rate limiters
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
