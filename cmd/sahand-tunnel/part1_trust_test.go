package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPart1IndependentKeyGenerationAndStorageIsolation(t *testing.T) {
	tmpDir := t.TempDir()
	masterCfgPath := filepath.Join(tmpDir, "master_config.json")
	agentCfgPath := filepath.Join(tmpDir, "agent_config.json")

	masterCfg := Config{
		Role:          "master",
		NodeID:        "0102030405060708090a0b0c0d0e0f10",
		PanelPort:     18080,
		ListenAddr:    ":18080",
		AdminUsername: "admin",
	}
	if _, err := ensureCryptoMaterial(&masterCfg); err != nil {
		t.Fatalf("ensureCryptoMaterial master failed: %v", err)
	}
	if err := saveConfig(masterCfgPath, masterCfg); err != nil {
		t.Fatalf("saveConfig master failed: %v", err)
	}

	// Verify file permissions are 0600
	st, err := os.Stat(masterCfgPath)
	if err != nil {
		t.Fatalf("os.Stat master config failed: %v", err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on config.json, got %o", st.Mode().Perm())
	}

	agentCfg := Config{
		Role:          "agent",
		NodeID:        "a1a2a3a4a5a6a7a8a9aaabacadaeafb0",
		PanelPort:     18081,
		ListenAddr:    ":18081",
		AdminUsername: "admin",
	}
	if _, err := ensureCryptoMaterial(&agentCfg); err != nil {
		t.Fatalf("ensureCryptoMaterial agent failed: %v", err)
	}
	if err := saveConfig(agentCfgPath, agentCfg); err != nil {
		t.Fatalf("saveConfig agent failed: %v", err)
	}

	// Verify Master and Agent generated independent keypairs and Agent has no Master private keys
	if !validateEd25519KeypairHex(masterCfg.MasterSigningPrivateKey, masterCfg.MasterSigningPublicKey) {
		t.Fatalf("master Ed25519 signing keypair is invalid")
	}
	if !validateX25519KeypairHex(masterCfg.MasterNoiseStaticPrivateKey, masterCfg.MasterNoiseStaticPublicKey) {
		t.Fatalf("master X25519 static keypair is invalid")
	}
	if !validateEd25519KeypairHex(agentCfg.AgentSigningPrivateKey, agentCfg.AgentSigningPublicKey) {
		t.Fatalf("agent Ed25519 signing keypair is invalid")
	}
	if !validateX25519KeypairHex(agentCfg.AgentNoiseStaticPrivateKey, agentCfg.AgentNoiseStaticPublicKey) {
		t.Fatalf("agent X25519 static keypair is invalid")
	}
	if agentCfg.MasterSigningPrivateKey != "" || agentCfg.MasterNoiseStaticPrivateKey != "" {
		t.Fatalf("agent config must never contain master private keys")
	}
	if masterCfg.MasterNoiseStaticPublicKey == agentCfg.AgentNoiseStaticPublicKey {
		t.Fatalf("master and agent X25519 static public keys collided")
	}
}

func TestPart1TokenSigningStrictJSONAndMutationRejection(t *testing.T) {
	peer, _ := setupWSSTestEnv(t)
	stateMu.RLock()
	masterCfg := appCfg
	stateMu.RUnlock()

	rawToken, err := generatePeerToken(masterCfg, peer)
	if err != nil {
		t.Fatalf("generatePeerToken failed: %v", err)
	}
	if !strings.HasPrefix(rawToken, "st2.") {
		t.Fatalf("expected st2. token prefix, got %q", rawToken)
	}

	// Verify private keys are never present in the token payload
	decodedBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(rawToken, "st2."))
	if err != nil {
		t.Fatalf("DecodeString failed: %v", err)
	}
	if bytes.Contains(decodedBytes, []byte(masterCfg.MasterSigningPrivateKey)) ||
		bytes.Contains(decodedBytes, []byte(masterCfg.MasterNoiseStaticPrivateKey)) {
		t.Fatalf("token payload leaked a private key!")
	}

	tp, err := parseAndValidateToken(rawToken)
	if err != nil {
		t.Fatalf("parseAndValidateToken failed on valid token: %v", err)
	}
	if tp.MasterSigningPublicKey != masterCfg.MasterSigningPublicKey ||
		tp.MasterNoiseStaticPublicKey != masterCfg.MasterNoiseStaticPublicKey {
		t.Fatalf("token public keys did not match master public keys")
	}

	// 1. Legacy st1. token must be rejected
	if _, err := parseAndValidateToken("st1." + base64.RawURLEncoding.EncodeToString(decodedBytes)); err == nil {
		t.Fatalf("expected legacy st1. token to be rejected")
	}

	// 2. Modifying any field in TokenPayload must invalidate the Ed25519 signature
	mutations := []func(*TokenPayload){
		func(p *TokenPayload) { p.CV++ },
		func(p *TokenPayload) { p.MID = "ffffffffffffffffffffffffffffffff" },
		func(p *TokenPayload) { p.AID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" },
		func(p *TokenPayload) { p.Ports[0] = 29999 },
		func(p *TokenPayload) { p.Exp += 3600 },
		func(p *TokenPayload) { p.TZOff += 60 },
		func(p *TokenPayload) {
			_, otherPub, _ := generateX25519KeypairHex()
			p.MasterNoiseStaticPublicKey = otherPub
		},
	}

	for idx, mutate := range mutations {
		tampered := tp
		tampered.Ports = append([]int(nil), tp.Ports...)
		mutate(&tampered)
		rawTampered, _ := json.Marshal(tampered)
		tamperedTok := "st2." + base64.RawURLEncoding.EncodeToString(rawTampered)
		if _, err := parseAndValidateToken(tamperedTok); err == nil {
			t.Fatalf("mutation #%d was not rejected by parseAndValidateToken", idx)
		}
	}

	// 3. Forged token signed by an attacker's Ed25519 private key must fail against Master's pinned public key
	attackerPriv, attackerPub, err := generateEd25519KeypairHex()
	if err != nil {
		t.Fatalf("generateEd25519KeypairHex failed: %v", err)
	}
	forgedTP := tp
	forgedTP.MasterSigningPublicKey = attackerPub
	forgedSig, err := signTokenPayloadEd25519(forgedTP, attackerPriv)
	if err != nil {
		t.Fatalf("signTokenPayloadEd25519 failed: %v", err)
	}
	forgedTP.Sig = forgedSig
	rawForged, _ := json.Marshal(forgedTP)
	forgedToken := "st2." + base64.RawURLEncoding.EncodeToString(rawForged)

	forgedPeer := peer
	forgedPeer.Token = forgedToken
	if _, err := derivePeerAuthKey(masterCfg, forgedPeer); err == nil {
		t.Fatalf("expected derivePeerAuthKey to reject token signed by untrusted Ed25519 key")
	}

	// 4. Strict JSON validation: reject duplicate keys, unknown fields, and trailing data after EOF
	dupKeyJSON := []byte(`{"v":2,"v":2,"cv":1}`)
	var dummy TokenPayload
	if err := unmarshalStrictJSON(dupKeyJSON, &dummy); err == nil {
		t.Fatalf("expected duplicate JSON key to be rejected")
	}

	unknownFieldJSON := append(bytes.TrimSuffix(decodedBytes, []byte("}")), []byte(`,"unknown_field":123}`)...)
	if err := unmarshalStrictJSON(unknownFieldJSON, &dummy); err == nil {
		t.Fatalf("expected unknown JSON field to be rejected")
	}

	trailingGarbageJSON := append(append([]byte(nil), decodedBytes...), []byte(`{"extra":true}`)...)
	if err := unmarshalStrictJSON(trailingGarbageJSON, &dummy); err == nil {
		t.Fatalf("expected trailing JSON document after main document to be rejected")
	}
}

func TestPart1InitialPairingFingerprintVerification(t *testing.T) {
	peer, _ := setupWSSTestEnv(t)
	stateMu.RLock()
	masterCfg := appCfg
	stateMu.RUnlock()

	rawToken, err := generatePeerToken(masterCfg, peer)
	if err != nil {
		t.Fatalf("generatePeerToken failed: %v", err)
	}
	validFP, err := ComputeSigningKeyFingerprint(masterCfg.MasterSigningPublicKey)
	if err != nil {
		t.Fatalf("ComputeSigningKeyFingerprint failed: %v", err)
	}

	tmpDir := t.TempDir()
	t.Setenv("SAHAND_CONFIG", filepath.Join(tmpDir, "agent_config.json"))

	agentCfg := Config{
		Role:          "agent",
		NodeID:        peer.ID,
		PanelPort:     18081,
		ListenAddr:    ":18081",
		AdminUsername: "admin",
	}
	if _, err := ensureCryptoMaterial(&agentCfg); err != nil {
		t.Fatalf("ensureCryptoMaterial agent failed: %v", err)
	}

	// 1. Missing fingerprint during initial pairing must be rejected and must NOT persist trust
	if _, err := VerifyAndEstablishInitialTrust(&agentCfg, "127.0.0.1", rawToken, ""); err == nil {
		t.Fatalf("expected initial pairing without fingerprint to be rejected")
	}
	if agentCfg.TrustedMasterSigningPublicKey != "" || len(agentCfg.Servers) != 0 {
		t.Fatalf("trust state was modified despite missing fingerprint")
	}

	// 2. Mismatched fingerprint must be rejected and must NOT persist trust
	wrongFP := "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := VerifyAndEstablishInitialTrust(&agentCfg, "127.0.0.1", rawToken, wrongFP); err == nil {
		t.Fatalf("expected initial pairing with wrong fingerprint to be rejected")
	}
	if agentCfg.TrustedMasterSigningPublicKey != "" || len(agentCfg.Servers) != 0 {
		t.Fatalf("trust state was modified despite mismatched fingerprint")
	}

	// 3. Valid fingerprint must succeed, pin MasterSigningPublicKey & MasterNoiseStaticPublicKey, and allow derivePeerAuthKey
	pairedPeer, err := VerifyAndEstablishInitialTrust(&agentCfg, "127.0.0.1", rawToken, validFP)
	if err != nil {
		t.Fatalf("VerifyAndEstablishInitialTrust with valid fingerprint failed: %v", err)
	}
	if agentCfg.TrustedMasterSigningPublicKey != masterCfg.MasterSigningPublicKey {
		t.Fatalf("expected TrustedMasterSigningPublicKey to be pinned")
	}
	if pairedPeer.MasterNoiseStaticPublicKey != masterCfg.MasterNoiseStaticPublicKey {
		t.Fatalf("expected MasterNoiseStaticPublicKey to be pinned on peer")
	}
	if pairedPeer.AgentNoiseStaticPublicKey != agentCfg.AgentNoiseStaticPublicKey {
		t.Fatalf("expected AgentNoiseStaticPublicKey to be populated on peer")
	}

	masterAuthKey, err := derivePeerAuthKey(masterCfg, peer)
	if err != nil {
		t.Fatalf("derivePeerAuthKey on Master failed: %v", err)
	}
	agentAuthKey, err := derivePeerAuthKey(agentCfg, pairedPeer)
	if err != nil {
		t.Fatalf("derivePeerAuthKey on Agent failed: %v", err)
	}
	if len(masterAuthKey) != 32 || !bytes.Equal(masterAuthKey, agentAuthKey) {
		t.Fatalf("Master and Agent derived mismatched 32-byte HKDF root keys")
	}
}
