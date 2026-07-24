package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func generateKeyPair(t *testing.T) (privatePath, publicPath string) {
	t.Helper()
	directory := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privatePath = filepath.Join(directory, "signer.key")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privateDER,
	}), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicPath = filepath.Join(directory, "signer.pub")
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: publicDER,
	}), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return privatePath, publicPath
}

func TestSignAndVerifyBundle(t *testing.T) {
	bundle := writeTestBundle(t)
	privateKey, publicKey := generateKeyPair(t)

	if err := SignBundle(bundle, privateKey, "release-signer@example.com"); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	state, signer, err := VerifySignedBundle(bundle, publicKey)
	if err != nil {
		t.Fatalf("VerifySignedBundle: %v", err)
	}
	if state != StateSignatureVerified || signer != "release-signer@example.com" {
		t.Fatalf("state = %s, signer = %s", state, signer)
	}
}

func TestUnsignedBundleIsIntegrityOnly(t *testing.T) {
	bundle := writeTestBundle(t)
	state, _, err := VerifySignedBundle(bundle, "")
	if err != nil {
		t.Fatalf("VerifySignedBundle: %v", err)
	}
	if state != StateIntegrityVerified {
		t.Fatalf("state = %s, want integrity_verified", state)
	}
}

func TestSignedBundleWithoutPinnedKeyIsIntegrityOnly(t *testing.T) {
	bundle := writeTestBundle(t)
	privateKey, _ := generateKeyPair(t)
	if err := SignBundle(bundle, privateKey, "signer"); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	state, signer, err := VerifySignedBundle(bundle, "")
	if err != nil {
		t.Fatalf("VerifySignedBundle: %v", err)
	}
	if state != StateIntegrityVerified || signer != "signer" {
		t.Fatalf("state = %s; a self-embedded key must not prove authenticity", state)
	}
}

func TestVerifyRejectsWrongSigner(t *testing.T) {
	bundle := writeTestBundle(t)
	privateKey, _ := generateKeyPair(t)
	_, otherPublic := generateKeyPair(t)
	if err := SignBundle(bundle, privateKey, "signer"); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	state, _, err := VerifySignedBundle(bundle, otherPublic)
	if err == nil || state != StateUnverified {
		t.Fatalf("wrong signer accepted: state=%s err=%v", state, err)
	}
	if !strings.Contains(err.Error(), "different key") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	bundle := writeTestBundle(t)
	privateKey, publicKey := generateKeyPair(t)
	if err := SignBundle(bundle, privateKey, "signer"); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	// Tamper with a bundle file after signing: integrity fails first.
	if err := os.WriteFile(filepath.Join(bundle, "scan.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	state, _, err := VerifySignedBundle(bundle, publicKey)
	if err == nil || state != StateUnverified {
		t.Fatalf("tampered bundle accepted: state=%s err=%v", state, err)
	}
}

func TestVerifyRequestedSignatureMissingFails(t *testing.T) {
	bundle := writeTestBundle(t)
	_, publicKey := generateKeyPair(t)
	state, _, err := VerifySignedBundle(bundle, publicKey)
	if err == nil || state != StateUnverified {
		t.Fatalf("missing signature accepted: state=%s err=%v", state, err)
	}
}

func TestSignRefusesInvalidBundleAndBadKeys(t *testing.T) {
	privateKey, _ := generateKeyPair(t)
	if err := SignBundle(t.TempDir(), privateKey, "signer"); err == nil {
		t.Fatal("signing an invalid bundle succeeded")
	}

	bundle := writeTestBundle(t)
	if err := SignBundle(bundle, privateKey, ""); err == nil {
		t.Fatal("empty signer identity accepted")
	}
	_, publicKey := generateKeyPair(t)
	if err := SignBundle(bundle, publicKey, "signer"); err == nil {
		t.Fatal("public key accepted as a private key")
	}
}

func TestSignatureFileDoesNotBreakLegacyVerify(t *testing.T) {
	bundle := writeTestBundle(t)
	privateKey, _ := generateKeyPair(t)
	if err := SignBundle(bundle, privateKey, "signer"); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	// Plain VerifyBundle treats the signature as an untracked file, which
	// keeps the strict legacy behavior for verifiers that do not know
	// about signatures.
	if err := VerifyBundle(bundle); err == nil {
		t.Fatal("legacy verify unexpectedly tolerated the signature file")
	}
	// The signature-aware path accepts it.
	if state, _, err := VerifySignedBundle(bundle, ""); err != nil || state != StateIntegrityVerified {
		t.Fatalf("signature-aware verify failed: state=%s err=%v", state, err)
	}
}
