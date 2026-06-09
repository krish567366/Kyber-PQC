package kyberpqc

import "testing"

func TestKyber512Exchange(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ct, err := Encapsulate(kp.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	ss, err := Decapsulate(ct.Data, kp.PrivateKey)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if string(ss) != string(ct.SharedSecret) {
		t.Fatal("shared secrets do not match")
	}
}

func TestInvalidLengths(t *testing.T) {
	if _, err := Encapsulate([]byte("short")); err == nil {
		t.Fatal("expected invalid public key error")
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ct, err := Encapsulate(kp.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if _, err := Decapsulate(ct.Data[:10], kp.PrivateKey); err == nil {
		t.Fatal("expected invalid ciphertext error")
	}
}
