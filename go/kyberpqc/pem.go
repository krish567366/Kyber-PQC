package kyberpqc

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const pemLineWidth = 64

type PEMKind int

const (
	PEMPublicKey PEMKind = iota
	PEMPrivateKey
	PEMCiphertext
	PEMSharedSecret
)

var pemLabels = map[PEMKind]string{
	PEMPublicKey:   "PUBLIC KEY",
	PEMPrivateKey:  "PRIVATE KEY",
	PEMCiphertext:  "CIPHERTEXT",
	PEMSharedSecret: "SHARED SECRET",
}

var pemExpectedBytes = map[PEMKind]int{
	PEMPublicKey:   PublicKeyBytes,
	PEMPrivateKey:  PrivateKeyBytes,
	PEMCiphertext:  CiphertextBytes,
	PEMSharedSecret: SharedSecretBytes,
}

func PEMLabel(kind PEMKind) (string, error) {
	label, ok := pemLabels[kind]
	if !ok {
		return "", fmt.Errorf("unknown pem kind: %d", kind)
	}
	return label, nil
}

func EncodePEM(kind PEMKind, data []byte) (string, error) {
	expected, ok := pemExpectedBytes[kind]
	if !ok {
		return "", fmt.Errorf("unknown pem kind: %d", kind)
	}
	if len(data) != expected {
		return "", fmt.Errorf("invalid data length: expected %d, got %d", expected, len(data))
	}

	label, err := PEMLabel(kind)
	if err != nil {
		return "", err
	}

	encoded := hex.EncodeToString(data)
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("-----BEGIN KYBER512 %s-----\n", label))
	for i := 0; i < len(encoded); i += pemLineWidth {
		end := i + pemLineWidth
		if end > len(encoded) {
			end = len(encoded)
		}
		builder.WriteString(encoded[i:end])
		builder.WriteByte('\n')
	}
	builder.WriteString(fmt.Sprintf("-----END KYBER512 %s-----\n", label))
	return builder.String(), nil
}

func DecodePEM(kind PEMKind, pem string) ([]byte, error) {
	label, err := PEMLabel(kind)
	if err != nil {
		return nil, err
	}
	expected, ok := pemExpectedBytes[kind]
	if !ok {
		return nil, fmt.Errorf("unknown pem kind: %d", kind)
	}

	begin := fmt.Sprintf("-----BEGIN KYBER512 %s-----", label)
	end := fmt.Sprintf("-----END KYBER512 %s-----", label)

	start := strings.Index(pem, begin)
	if start < 0 {
		return nil, fmt.Errorf("missing pem header for %s", label)
	}
	start += len(begin)
	stop := strings.Index(pem[start:], end)
	if stop < 0 {
		return nil, fmt.Errorf("missing pem footer for %s", label)
	}

	body := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', ' ':
			return -1
		default:
			return r
		}
	}, pem[start:start+stop])

	decoded, err := hex.DecodeString(body)
	if err != nil {
		return nil, err
	}
	if len(decoded) != expected {
		return nil, fmt.Errorf("invalid decoded length: expected %d, got %d", expected, len(decoded))
	}
	return decoded, nil
}

func WritePEMFile(path string, kind PEMKind, data []byte) error {
	pem, err := EncodePEM(kind, data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(pem), 0o600)
}

func ReadPEMFile(path string, kind PEMKind) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodePEM(kind, string(content))
}
