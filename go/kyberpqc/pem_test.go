package kyberpqc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPEMRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ct, err := Encapsulate(kp.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	publicPEM, err := EncodePEM(PEMPublicKey, kp.PublicKey)
	if err != nil {
		t.Fatalf("EncodePEM public: %v", err)
	}
	decodedPublic, err := DecodePEM(PEMPublicKey, publicPEM)
	if err != nil {
		t.Fatalf("DecodePEM public: %v", err)
	}
	if string(decodedPublic) != string(kp.PublicKey) {
		t.Fatal("public key round-trip mismatch")
	}

	privatePEM, err := EncodePEM(PEMPrivateKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("EncodePEM private: %v", err)
	}
	decodedPrivate, err := DecodePEM(PEMPrivateKey, privatePEM)
	if err != nil {
		t.Fatalf("DecodePEM private: %v", err)
	}
	if string(decodedPrivate) != string(kp.PrivateKey) {
		t.Fatal("private key round-trip mismatch")
	}

	cipherPEM, err := EncodePEM(PEMCiphertext, ct.Data)
	if err != nil {
		t.Fatalf("EncodePEM ciphertext: %v", err)
	}
	decodedCipher, err := DecodePEM(PEMCiphertext, cipherPEM)
	if err != nil {
		t.Fatalf("DecodePEM ciphertext: %v", err)
	}
	if string(decodedCipher) != string(ct.Data) {
		t.Fatal("ciphertext round-trip mismatch")
	}

	secretPEM, err := EncodePEM(PEMSharedSecret, ct.SharedSecret)
	if err != nil {
		t.Fatalf("EncodePEM shared secret: %v", err)
	}
	decodedSecret, err := DecodePEM(PEMSharedSecret, secretPEM)
	if err != nil {
		t.Fatalf("DecodePEM shared secret: %v", err)
	}
	if string(decodedSecret) != string(ct.SharedSecret) {
		t.Fatal("shared secret round-trip mismatch")
	}
}

func TestPEMFileRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	path := filepath.Join(t.TempDir(), "private.hex.pem")
	if err := WritePEMFile(path, PEMPrivateKey, kp.PrivateKey); err != nil {
		t.Fatalf("WritePEMFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}

	decoded, err := ReadPEMFile(path, PEMPrivateKey)
	if err != nil {
		t.Fatalf("ReadPEMFile: %v", err)
	}
	if string(decoded) != string(kp.PrivateKey) {
		t.Fatal("private key file round-trip mismatch")
	}
}
