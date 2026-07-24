package evidence

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// signatureFileName stores the detached manifest signature in the bundle.
const signatureFileName = "bundle-manifest.sig.json"

// maxSignatureFileBytes bounds the signature envelope file.
const maxSignatureFileBytes = 64 << 10

// maxKeyFileBytes bounds PEM key files supplied by the caller.
const maxKeyFileBytes = 64 << 10

// signatureEnvelope is the detached signature over bundle-manifest.json.
// Signing covers the exact manifest bytes, which in turn pin the size and
// SHA-256 of every other bundle file.
type signatureEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	// SignerID is a caller-supplied identity label recorded for evidence.
	SignerID string `json:"signer_id"`
	// PublicKeyPEM embeds the signer public key for offline verification.
	// Embedding supports integrity chains; authenticity still requires the
	// verifier to pin the expected key or signer out of band.
	PublicKeyPEM string `json:"public_key_pem"`
	// Signature is the base64-free hex Ed25519 signature of the manifest.
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
}

// VerificationState describes how far a bundle could be verified.
type VerificationState string

const (
	// StateIntegrityVerified means file sizes and hashes match the manifest
	// but no signature was present or requested.
	StateIntegrityVerified VerificationState = "integrity_verified"
	// StateSignatureVerified means integrity passed and the manifest
	// signature verified against the expected signer key.
	StateSignatureVerified VerificationState = "signature_verified"
	// StateUnverified means verification failed.
	StateUnverified VerificationState = "unverified"
)

// SignBundle signs an existing bundle's manifest with a caller-provided
// Ed25519 private key file. ClusterProof never generates or stores keys:
// the key file is read, used, and left untouched.
func SignBundle(directory, privateKeyPath, signerID string) error {
	if strings.TrimSpace(signerID) == "" {
		return errors.New("signer identity is required")
	}
	if len(signerID) > 500 || strings.ContainsAny(signerID, "\x00\n\r") {
		return errors.New("signer identity must be short single-line text")
	}
	if err := VerifyBundle(directory); err != nil {
		return fmt.Errorf("refuse to sign an invalid bundle: %w", err)
	}

	privateKey, err := loadEd25519PrivateKey(privateKeyPath)
	if err != nil {
		return err
	}

	manifestData, err := readRegularBounded(
		filepath.Join(directory, "bundle-manifest.json"), defaultVerifyLimits().MaxManifestBytes)
	if err != nil {
		return fmt.Errorf("read bundle manifest: %w", err)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	envelope := signatureEnvelope{
		SchemaVersion: "1",
		Algorithm:     "Ed25519",
		SignerID:      signerID,
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{
			Type: "PUBLIC KEY", Bytes: publicDER,
		})),
		Signature: fmt.Sprintf("%x", ed25519.Sign(privateKey, manifestData)),
		SignedAt:  time.Now().UTC(),
	}
	data, err := marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode signature envelope: %w", err)
	}
	return writePrivate(filepath.Join(directory, signatureFileName), data)
}

// VerifySignedBundle verifies bundle integrity and, when expectedKeyPath is
// provided, the manifest signature against that exact public key. It
// returns the reached verification state; the state distinguishes file
// integrity from signer authenticity.
func VerifySignedBundle(directory, expectedKeyPath string) (VerificationState, string, error) {
	signaturePath := filepath.Join(directory, signatureFileName)
	_, statErr := os.Lstat(signaturePath)
	signaturePresent := statErr == nil

	if err := verifyBundleAllowingSignature(directory, signaturePresent); err != nil {
		return StateUnverified, "", err
	}
	if !signaturePresent {
		if expectedKeyPath != "" {
			return StateUnverified, "", errors.New(
				"signature verification requested but the bundle has no signature file")
		}
		return StateIntegrityVerified, "", nil
	}

	envelope, err := loadSignatureEnvelope(signaturePath)
	if err != nil {
		return StateUnverified, "", err
	}
	if expectedKeyPath == "" {
		// A signature exists but the caller did not pin a key. Integrity
		// holds; authenticity is unknown, and saying otherwise would let an
		// attacker self-sign a tampered bundle.
		return StateIntegrityVerified, envelope.SignerID, nil
	}

	expectedKey, err := loadEd25519PublicKey(expectedKeyPath)
	if err != nil {
		return StateUnverified, "", err
	}
	embeddedKey, err := parsePublicKeyPEM(envelope.PublicKeyPEM)
	if err != nil {
		return StateUnverified, "", fmt.Errorf("parse embedded public key: %w", err)
	}
	if !expectedKey.Equal(embeddedKey) {
		return StateUnverified, "", errors.New(
			"bundle was signed by a different key than expected; signer authenticity failed")
	}

	manifestData, err := readRegularBounded(
		filepath.Join(directory, "bundle-manifest.json"), defaultVerifyLimits().MaxManifestBytes)
	if err != nil {
		return StateUnverified, "", fmt.Errorf("read bundle manifest: %w", err)
	}
	var signature []byte
	if _, err := fmt.Sscanf(envelope.Signature, "%x", &signature); err != nil {
		return StateUnverified, "", errors.New("signature envelope contains a malformed signature")
	}
	if len(signature) != ed25519.SignatureSize {
		return StateUnverified, "", errors.New("signature has the wrong size")
	}
	if !ed25519.Verify(expectedKey, manifestData, signature) {
		return StateUnverified, "", errors.New("manifest signature verification failed")
	}
	return StateSignatureVerified, envelope.SignerID, nil
}

// verifyBundleAllowingSignature verifies integrity while tolerating the
// signature file, which is intentionally outside the hashed manifest (it
// cannot contain its own hash).
func verifyBundleAllowingSignature(directory string, signaturePresent bool) error {
	if !signaturePresent {
		return VerifyBundle(directory)
	}
	limits := defaultVerifyLimits()
	return verifyBundleExtra(directory, limits, map[string]struct{}{signatureFileName: {}})
}

func loadSignatureEnvelope(path string) (signatureEnvelope, error) {
	data, err := readRegularBounded(path, maxSignatureFileBytes)
	if err != nil {
		return signatureEnvelope{}, fmt.Errorf("read signature envelope: %w", err)
	}
	var envelope signatureEnvelope
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return signatureEnvelope{}, fmt.Errorf("decode signature envelope: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return signatureEnvelope{}, errors.New("signature envelope has trailing content")
	}
	if envelope.SchemaVersion != "1" || envelope.Algorithm != "Ed25519" {
		return signatureEnvelope{}, fmt.Errorf(
			"unsupported signature envelope (schema %q, algorithm %q)",
			envelope.SchemaVersion, envelope.Algorithm)
	}
	return envelope, nil
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	block, err := readPEMBlock(path)
	if err != nil {
		return nil, err
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("key %q is %q; a PKCS#8 PRIVATE KEY is required", path, block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key %q: %w", path, err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key %q is not an Ed25519 key", path)
	}
	return privateKey, nil
}

func loadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	block, err := readPEMBlock(path)
	if err != nil {
		return nil, err
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("key %q is %q; a PUBLIC KEY is required", path, block.Type)
	}
	return parsePublicKeyDER(block.Bytes)
}

func parsePublicKeyPEM(content string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(content))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("content is not a PEM public key")
	}
	return parsePublicKeyDER(block.Bytes)
}

func parsePublicKeyDER(der []byte) (ed25519.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("key is not an Ed25519 public key")
	}
	return publicKey, nil
}

func readPEMBlock(path string) (*pem.Block, error) {
	data, err := readRegularBounded(path, maxKeyFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read key %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key %q contains no PEM block", path)
	}
	return block, nil
}
