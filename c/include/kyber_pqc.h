#ifndef KYBER_PQC_H
#define KYBER_PQC_H

#include <stddef.h>
#include <stdint.h>

#define KYBER_PQC_PUBLIC_KEY_BYTES 800
#define KYBER_PQC_PRIVATE_KEY_BYTES 1632
#define KYBER_PQC_CIPHERTEXT_BYTES 768
#define KYBER_PQC_SHARED_SECRET_BYTES 32

int kyber_pqc_keypair(uint8_t *public_key, uint8_t *private_key);
int kyber_pqc_encapsulate(
    const uint8_t *public_key,
    uint8_t *ciphertext,
    uint8_t *shared_secret
);
int kyber_pqc_decapsulate(
    const uint8_t *private_key,
    const uint8_t *ciphertext,
    uint8_t *shared_secret
);

#endif
