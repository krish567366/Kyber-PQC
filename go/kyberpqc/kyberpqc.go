// Package kyberpqc provides a native Kyber-512 implementation via cgo.
package kyberpqc

const (
	PublicKeyBytes    = 800
	PrivateKeyBytes   = 1632
	CiphertextBytes   = 768
	SharedSecretBytes = 32
)

type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

type Ciphertext struct {
	Data         []byte
	SharedSecret []byte
}

func GenerateKeyPair() (KeyPair, error) {
	return nativeKeyPair()
}

func Encapsulate(publicKey []byte) (Ciphertext, error) {
	return nativeEncapsulate(publicKey)
}

func Decapsulate(ciphertext, privateKey []byte) ([]byte, error) {
	return nativeDecapsulate(ciphertext, privateKey)
}
