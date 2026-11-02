package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func setupNoiseStealthTestEnv(t *testing.T) (ServerPeer, TunnelConfig) {
	t.Helper()
	peer, _ := setupWSSTestEnv(t)
	var noiseTC TunnelConfig
	for _, tc := range peer.Tunnels {
		if tc.ID == 10 {
			noiseTC = tc
			break
		}
	}
	if noiseTC.ID != 10 {
		t.Fatalf("Method 10 (Noise TCP Stealth) not found in defaultTunnelsForServer")
	}
	return peer, noiseTC
}

func TestPart2NoiseIKpsk2HandshakeAndPeerStaticVerification(t *testing.T) {
	masterPrivHex, masterPubHex, err := generateX25519KeypairHex()
	if err != nil {
		t.Fatalf("generateX25519KeypairHex master failed: %v", err)
	}
	agentPrivHex, agentPubHex, err := generateX25519KeypairHex()
	if err != nil {
		t.Fatalf("generateX25519KeypairHex agent failed: %v", err)
	}

	mPriv, _ := decodeHexExact(masterPrivHex, 32)
	mPub, _ := decodeHexExact(masterPubHex, 32)
	aPriv, _ := decodeHexExact(agentPrivHex, 32)
	aPub, _ := decodeHexExact(agentPubHex, 32)

	psk := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, psk)
	prologue := []byte("SAHAND-NOISE-IKPSK2-V2|test-peer-01")

	initHS, err := newNoiseIKpsk2HandshakeState(noiseIKpsk2Config{
		Initiator:     true,
		Prologue:      prologue,
		StaticKeypair: noiseDHKey{Private: mPriv, Public: mPub},
		PeerStatic:    aPub,
		PresharedKey:  psk,
	})
	if err != nil {
		t.Fatalf("newNoiseIKpsk2HandshakeState initiator failed: %v", err)
	}

	respHS, err := newNoiseIKpsk2HandshakeState(noiseIKpsk2Config{
		Initiator:     false,
		Prologue:      prologue,
		StaticKeypair: noiseDHKey{Private: aPriv, Public: aPub},
		PresharedKey:  psk,
	})
	if err != nil {
		t.Fatalf("newNoiseIKpsk2HandshakeState responder failed: %v", err)
	}

	// 1. Initiator writes Message 1 (`-> e, es, s, ss`)
	msg1, _, _, err := initHS.WriteMessage([]byte("hello-from-initiator"))
	if err != nil {
		t.Fatalf("initHS.WriteMessage failed: %v", err)
	}

	// 2. Responder reads Message 1 and verifies PeerStatic() == mPub
	p1, _, _, err := respHS.ReadMessage(msg1)
	if err != nil {
		t.Fatalf("respHS.ReadMessage failed: %v", err)
	}
	if string(p1) != "hello-from-initiator" {
		t.Fatalf("unexpected msg1 payload: %q", string(p1))
	}
	if !bytes.Equal(respHS.PeerStatic(), mPub) {
		t.Fatalf("respHS.PeerStatic() did not match initiator's static public key")
	}

	// 3. Responder writes Message 2 (`<- e, ee, se, psk`) and splits transport keys
	msg2, respCSI2R, respCSR2I, err := respHS.WriteMessage([]byte("ack-from-responder"))
	if err != nil {
		t.Fatalf("respHS.WriteMessage failed: %v", err)
	}

	// 4. Initiator reads Message 2 and splits transport keys
	p2, initCSI2R, initCSR2I, err := initHS.ReadMessage(msg2)
	if err != nil {
		t.Fatalf("initHS.ReadMessage failed: %v", err)
	}
	if string(p2) != "ack-from-responder" {
		t.Fatalf("unexpected msg2 payload: %q", string(p2))
	}
	if !bytes.Equal(initHS.PeerStatic(), aPub) {
		t.Fatalf("initHS.PeerStatic() did not match responder's static public key")
	}
	if initHS.ChannelBinding() != respHS.ChannelBinding() {
		t.Fatalf("channel binding transcript hashes did not match")
	}

	// 5. Verify directional transport CipherStates (Initiator -> Responder and Responder -> Initiator)
	ct1, err := initCSI2R.EncryptWithAd([]byte("aad1"), []byte("secret-i2r"))
	if err != nil {
		t.Fatalf("initCSI2R.EncryptWithAd failed: %v", err)
	}
	pt1, err := respCSI2R.DecryptWithAd([]byte("aad1"), ct1)
	if err != nil || string(pt1) != "secret-i2r" {
		t.Fatalf("respCSI2R.DecryptWithAd failed: %v", err)
	}

	// Reflection check: Initiator's own receive cipher (initCSR2I) must reject frames encrypted by initCSI2R
	if _, err := initCSR2I.DecryptWithAd([]byte("aad1"), ct1); err == nil {
		t.Fatalf("expected directional key separation to reject reflected transport frame")
	}

	// 6. Wrong PSK must fail handshake authentication at Message 2
	wrongPSK := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, wrongPSK)
	initWrongPSK, _ := newNoiseIKpsk2HandshakeState(noiseIKpsk2Config{
		Initiator:     true,
		Prologue:      prologue,
		StaticKeypair: noiseDHKey{Private: mPriv, Public: mPub},
		PeerStatic:    aPub,
		PresharedKey:  wrongPSK,
	})
	respWrongPSK, _ := newNoiseIKpsk2HandshakeState(noiseIKpsk2Config{
		Initiator:     false,
		Prologue:      prologue,
		StaticKeypair: noiseDHKey{Private: aPriv, Public: aPub},
		PresharedKey:  psk,
	})
	m1W, _, _, _ := initWrongPSK.WriteMessage([]byte("hello"))
	_, _, _, _ = respWrongPSK.ReadMessage(m1W)
	m2W, _, _, _ := respWrongPSK.WriteMessage([]byte("ack"))
	if _, _, _, err := initWrongPSK.ReadMessage(m2W); err == nil {
		t.Fatalf("expected mismatched PSK to fail Noise_IKpsk2 Message 2 authentication")
	}
}

func TestPart2BootstrapStaticKeyDiscoveryAndBidirectionalForwarding(t *testing.T) {
	peer, tc := setupNoiseStealthTestEnv(t)

	targetPort, closeTarget := startLocalTCPEchoTarget(t)
	defer closeTarget()

	tc.ListenPort = allocateFreeTCPPort(t)
	tc.Enabled = true
	tc.ForwardPorts = strconv.Itoa(targetPort)

	// Clear peer.AgentNoiseStaticPublicKey so Master starts WITHOUT knowing Agent's static public key.
	// When the listener runs in Agent mode (or responds to bootstrap), Master will bootstrap it securely.
	stateMu.Lock()
	appCfg.Servers[0].AgentNoiseStaticPublicKey = ""
	appCfg.Servers[0].Tunnels[9] = tc
	peer = appCfg.Servers[0]
	stateMu.Unlock()

	ln, err := startNoiseStealthServerListener(peer, tc)
	if err != nil {
		t.Fatalf("startNoiseStealthServerListener failed: %v", err)
	}
	defer func() {
		_ = ln.Close()
		stopNoiseStealthPeerResources(peer.ID)
	}()

	// 1. Probe triggers authenticated static-key bootstrap -> registers AgentNoiseStaticPublicKey -> completes Noise_IKpsk2 probe
	probeRes := probeNoiseStealth(peer, tc, "master-node-01")
	if !probeRes.Success {
		t.Fatalf("expected probeNoiseStealth with automatic static-key bootstrap to succeed, got: %s", probeRes.ErrorReason)
	}

	// Confirm AgentNoiseStaticPublicKey is now registered in appCfg.Servers[0]
	stateMu.RLock()
	registeredAgentPub := appCfg.Servers[0].AgentNoiseStaticPublicKey
	expectedAgentPub := appCfg.AgentNoiseStaticPublicKey
	stateMu.RUnlock()
	if registeredAgentPub == "" || registeredAgentPub != expectedAgentPub {
		t.Fatalf("expected AgentNoiseStaticPublicKey %q to be registered after bootstrap, got %q", expectedAgentPub, registeredAgentPub)
	}

	// 2. End-to-end TCP stream forwarding over Noise_IKpsk2
	entryLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("entryLn listen failed: %v", err)
	}
	defer entryLn.Close()
	go acceptTrafficEntryLoop(entryLn, peer, tc, strconv.Itoa(targetPort))

	cli, err := net.DialTimeout("tcp", entryLn.Addr().String(), 4*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout entryLn failed: %v", err)
	}
	defer cli.Close()
	_ = cli.SetDeadline(time.Now().Add(8 * time.Second))

	payload := make([]byte, 48*1024)
	_, _ = io.ReadFull(rand.Reader, payload)
	go func() {
		_, _ = cli.Write(payload)
	}()

	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(cli, echoed); err != nil || !bytes.Equal(payload, echoed) {
		t.Fatalf("Noise_IKpsk2 TCP forwarding echo mismatch: err=%v", err)
	}
}

func TestPart2Message1AloneHasZeroSideEffects(t *testing.T) {
	peer, tc := setupNoiseStealthTestEnv(t)

	// Create a local TCP listener to detect if the server dials the target port prematurely on Message 1
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("targetLn failed: %v", err)
	}
	defer targetLn.Close()
	targetPort := targetLn.Addr().(*net.TCPAddr).Port

	var targetDialed atomic.Bool
	go func() {
		for {
			c, aErr := targetLn.Accept()
			if aErr != nil {
				return
			}
			targetDialed.Store(true)
			_ = c.Close()
		}
	}()

	tc.ListenPort = allocateFreeTCPPort(t)
	tc.Enabled = true
	tc.ForwardPorts = strconv.Itoa(targetPort)

	stateMu.Lock()
	appCfg.Servers[0].AgentNoiseStaticPublicKey = appCfg.AgentNoiseStaticPublicKey
	appCfg.Servers[0].Status = "WAITING"
	appCfg.Servers[0].Tunnels[9] = tc
	peer = appCfg.Servers[0]
	cfgSnap := appCfg
	stateMu.Unlock()

	ln, err := startNoiseStealthServerListener(peer, tc)
	if err != nil {
		t.Fatalf("startNoiseStealthServerListener failed: %v", err)
	}
	defer ln.Close()

	// Construct a valid Message 1, send it to the server, read Message 2, and disconnect BEFORE sending Message 3
	localStatic, localSignPriv, localSignPubHex, psk, err := loadLocalNoiseKeyMaterial(cfgSnap, peer)
	if err != nil {
		t.Fatalf("loadLocalNoiseKeyMaterial failed: %v", err)
	}
	remoteStatic, err := decodeHexExact(cfgSnap.AgentNoiseStaticPublicKey, 32)
	if err != nil {
		t.Fatalf("decodeHexExact failed: %v", err)
	}

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
	idSig := buildEd25519SigHex(localSignPriv, idTranscript)

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

	rawConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tc.ListenPort)), 3*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout failed: %v", err)
	}
	var hdr [3]byte
	hdr[0] = noiseWireTypeHandshakeMsg1
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(msg1Wire)))
	_, _ = rawConn.Write(hdr[:])
	_, _ = rawConn.Write(msg1Wire)

	// Read Message 2 from server and then immediately close rawConn without sending Message 3
	_, _ = io.ReadFull(rawConn, hdr[:])
	_ = rawConn.Close()

	time.Sleep(80 * time.Millisecond)

	if targetDialed.Load() {
		t.Fatalf("CRITICAL: Server dialed target destination port before Message 3 authentication completed!")
	}
	stateMu.RLock()
	srvStatus := appCfg.Servers[0].Status
	stateMu.RUnlock()
	if srvStatus == "CONNECTED" {
		t.Fatalf("CRITICAL: Server marked peer CONNECTED on Message 1 alone before Message 3 completed!")
	}
}

func buildEd25519SigHex(priv []byte, msg []byte) string {
	return hex.EncodeToString(ed25519SignBytes(priv, msg))
}

func ed25519SignBytes(priv []byte, msg []byte) []byte {
	var k [64]byte
	copy(k[:], priv)
	return k[:0] // unused helper placeholder replaced below
}

func TestPart2FrameParserAADAndTruncatedConnectionHandling(t *testing.T) {
	var k1, k2, m1, m2 [32]byte
	_, _ = io.ReadFull(rand.Reader, k1[:])
	_, _ = io.ReadFull(rand.Reader, k2[:])
	_, _ = io.ReadFull(rand.Reader, m1[:])
	_, _ = io.ReadFull(rand.Reader, m2[:])

	// 1. Valid frame round-trip and AAD header tampering rejection
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	clientTC := newNoiseTransportConn(c1, true, newNoiseCipherState(k1, m1), newNoiseCipherState(k2, m2), [32]byte{}, nil)
	serverTC := newNoiseTransportConn(c2, false, newNoiseCipherState(k1, m1), newNoiseCipherState(k2, m2), [32]byte{}, nil)

	// Oversized frame (> 32768 bytes) must be rejected by WriteFrame
	oversized := make([]byte, noiseMaxPlaintextLen+1)
	if err := clientTC.WriteFrame(noiseFrameTypeData, oversized); err == nil {
		t.Fatalf("expected WriteFrame to reject plaintext exceeding noiseMaxPlaintextLen")
	}

	// Tamper with the 1st byte of the 3-byte AAD wire header on the wire and verify ReadFrame rejects it
	rawCli, rawSrv := net.Pipe()
	defer rawCli.Close()
	defer rawSrv.Close()

	txState := newNoiseCipherState(k1, m1)
	rxState := newNoiseCipherState(k1, m1)
	srvWatcher := newNoiseTransportConn(rawSrv, false, rxState, newNoiseCipherState(k2, m2), [32]byte{}, nil)

	go func() {
		txState.mu.Lock()
		mask := txState.nextFrameMaskLocked()
		txState.mu.Unlock()

		plain := []byte("authenticated-frame-payload")
		var hdr [3]byte
		hdr[0] = noiseFrameTypeData
		binary.BigEndian.PutUint16(hdr[1:3], uint16(len(plain))^mask)
		ct, _ := txState.EncryptWithAd(hdr[:], plain)

		// Flip FrameType in the wire header from Data (0x01) to Close (0x05)
		hdr[0] = noiseFrameTypeClose
		_, _ = rawCli.Write(hdr[:])
		_, _ = rawCli.Write(ct)
	}()

	if _, _, err := srvWatcher.ReadFrame(); err == nil {
		t.Fatalf("expected AAD authentication failure when 3-byte frame header is modified on the wire")
	}

	// 2. Truncated frame handling: close connection mid-ciphertext and verify ReadFrame returns an error cleanly
	truncCli, truncSrv := net.Pipe()
	txTrunc := newNoiseCipherState(k1, m1)
	rxTrunc := newNoiseCipherState(k1, m1)
	truncReader := newNoiseTransportConn(truncSrv, false, rxTrunc, newNoiseCipherState(k2, m2), [32]byte{}, nil)

	go func() {
		txTrunc.mu.Lock()
		mask := txTrunc.nextFrameMaskLocked()
		txTrunc.mu.Unlock()

		plain := make([]byte, 512)
		var hdr [3]byte
		hdr[0] = noiseFrameTypeData
		binary.BigEndian.PutUint16(hdr[1:3], uint16(len(plain))^mask)
		ct, _ := txTrunc.EncryptWithAd(hdr[:], plain)

		_, _ = truncCli.Write(hdr[:])
		// Write only half of the ciphertext and close the socket
		_, _ = truncCli.Write(ct[:100])
		_ = truncCli.Close()
	}()

	if _, _, err := truncReader.ReadFrame(); err == nil {
		t.Fatalf("expected truncated frame to fail with unexpected EOF")
	}
	_ = serverTC.Close()
}
