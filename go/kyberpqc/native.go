package kyberpqc

/*
#cgo CFLAGS: -O3 -Wall -I${SRCDIR}/../../c/include -I${SRCDIR}/../../c/vendor/kyber512 -DKYBER_K=2
#cgo LDFLAGS: ${SRCDIR}/../../c/build/libkyber_pqc.a
#include "kyber_pqc.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

func nativeKeyPair() (KeyPair, error) {
	pk := make([]byte, PublicKeyBytes)
	sk := make([]byte, PrivateKeyBytes)

	rc := C.kyber_pqc_keypair(
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
	)
	if rc != 0 {
		return KeyPair{}, errors.New("native keypair failed")
	}

	return KeyPair{PublicKey: pk, PrivateKey: sk}, nil
}

func nativeEncapsulate(publicKey []byte) (Ciphertext, error) {
	if len(publicKey) != PublicKeyBytes {
		return Ciphertext{}, fmt.Errorf(
			"invalid public key length: expected %d, got %d",
			PublicKeyBytes,
			len(publicKey),
		)
	}

	ct := make([]byte, CiphertextBytes)
	ss := make([]byte, SharedSecretBytes)

	rc := C.kyber_pqc_encapsulate(
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&ss[0])),
	)
	if rc != 0 {
		return Ciphertext{}, errors.New("native encapsulation failed")
	}

	return Ciphertext{Data: ct, SharedSecret: ss}, nil
}

func nativeDecapsulate(ciphertext, privateKey []byte) ([]byte, error) {
	if len(ciphertext) != CiphertextBytes {
		return nil, fmt.Errorf(
			"invalid ciphertext length: expected %d, got %d",
			CiphertextBytes,
			len(ciphertext),
		)
	}
	if len(privateKey) != PrivateKeyBytes {
		return nil, fmt.Errorf(
			"invalid private key length: expected %d, got %d",
			PrivateKeyBytes,
			len(privateKey),
		)
	}

	ss := make([]byte, SharedSecretBytes)
	rc := C.kyber_pqc_decapsulate(
		(*C.uint8_t)(unsafe.Pointer(&privateKey[0])),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&ss[0])),
	)
	if rc != 0 {
		return nil, errors.New("native decapsulation failed")
	}

	return ss, nil
}
