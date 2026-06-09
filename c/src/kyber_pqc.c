#include "kyber_pqc.h"
#include "secure.h"

#include "kem.h"

int kyber_pqc_keypair(uint8_t *public_key, uint8_t *private_key)
{
    if (public_key == NULL || private_key == NULL) {
        return -1;
    }
    return crypto_kem_keypair(public_key, private_key);
}

int kyber_pqc_encapsulate(
    const uint8_t *public_key,
    uint8_t *ciphertext,
    uint8_t *shared_secret
)
{
    if (public_key == NULL || ciphertext == NULL || shared_secret == NULL) {
        return -1;
    }
    return crypto_kem_enc(ciphertext, shared_secret, public_key);
}

int kyber_pqc_decapsulate(
    const uint8_t *private_key,
    const uint8_t *ciphertext,
    uint8_t *shared_secret
)
{
    int rc;

    if (private_key == NULL || ciphertext == NULL || shared_secret == NULL) {
        return -1;
    }

    rc = crypto_kem_dec(shared_secret, ciphertext, private_key);
    if (rc != 0) {
        kyber_pqc_secure_zero(shared_secret, KYBER_PQC_SHARED_SECRET_BYTES);
        return rc;
    }

    return 0;
}
