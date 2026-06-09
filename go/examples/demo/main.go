package main

import (
	"fmt"
	"os"

	"github.com/krish567366/Kyber-PQC/go/kyberpqc"
)

func main() {
	kp, err := kyberpqc.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keypair failed: %v\n", err)
		os.Exit(1)
	}

	publicPEM, err := kyberpqc.EncodePEM(kyberpqc.PEMPublicKey, kp.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode public key failed: %v\n", err)
		os.Exit(1)
	}
	privatePEM, err := kyberpqc.EncodePEM(kyberpqc.PEMPrivateKey, kp.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode private key failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(publicPEM)
	fmt.Print(privatePEM)

	ct, err := kyberpqc.Encapsulate(kp.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encapsulate failed: %v\n", err)
		os.Exit(1)
	}
	ss, err := kyberpqc.Decapsulate(ct.Data, kp.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decapsulate failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("demo complete: shared secret recovered")
	fmt.Printf("shared secret bytes: %d\n", len(ss))
}
