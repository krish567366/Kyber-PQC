#include <stdio.h>
#include <string.h>

#include "kyber_pqc.h"

int main(void)
{
    uint8_t pk[KYBER_PQC_PUBLIC_KEY_BYTES];
    uint8_t sk[KYBER_PQC_PRIVATE_KEY_BYTES];
    uint8_t ct[KYBER_PQC_CIPHERTEXT_BYTES];
    uint8_t ss1[KYBER_PQC_SHARED_SECRET_BYTES];
    uint8_t ss2[KYBER_PQC_SHARED_SECRET_BYTES];

    if (kyber_pqc_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }
    if (kyber_pqc_encapsulate(pk, ct, ss1) != 0) {
        fprintf(stderr, "encapsulate failed\n");
        return 1;
    }
    if (kyber_pqc_decapsulate(sk, ct, ss2) != 0) {
        fprintf(stderr, "decapsulate failed\n");
        return 1;
    }
    if (memcmp(ss1, ss2, KYBER_PQC_SHARED_SECRET_BYTES) != 0) {
        fprintf(stderr, "shared secrets do not match\n");
        return 1;
    }

    printf("kyber-pqc conan test ok\n");
    return 0;
}
