#include <stdio.h>

#include "kyber_pem.h"
#include "kyber_pqc.h"

int main(void)
{
    uint8_t pk[KYBER_PQC_PUBLIC_KEY_BYTES];
    uint8_t sk[KYBER_PQC_PRIVATE_KEY_BYTES];
    uint8_t ct[KYBER_PQC_CIPHERTEXT_BYTES];
    uint8_t ss_enc[KYBER_PQC_SHARED_SECRET_BYTES];
    uint8_t ss_dec[KYBER_PQC_SHARED_SECRET_BYTES];
    char *public_pem = NULL;
    char *secret_pem = NULL;

    if (kyber_pqc_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }
    if (kyber_pem_encode(KYBER_PEM_PUBLIC_KEY, pk, sizeof(pk), &public_pem) != 0) {
        fprintf(stderr, "encode public key failed\n");
        return 1;
    }
    if (kyber_pem_encode(KYBER_PEM_PRIVATE_KEY, sk, sizeof(sk), &secret_pem) != 0) {
        fprintf(stderr, "encode private key failed\n");
        return 1;
    }

    printf("%s", public_pem);
    printf("%s", secret_pem);

    if (kyber_pqc_encapsulate(pk, ct, ss_enc) != 0) {
        fprintf(stderr, "encapsulate failed\n");
        return 1;
    }
    if (kyber_pqc_decapsulate(sk, ct, ss_dec) != 0) {
        fprintf(stderr, "decapsulate failed\n");
        return 1;
    }

    kyber_pem_free(public_pem);
    kyber_pem_free(secret_pem);
    printf("demo complete: shared secret recovered\n");
    return 0;
}
