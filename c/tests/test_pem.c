#include <stdio.h>
#include <string.h>

#include "kyber_pem.h"
#include "kyber_pqc.h"

int main(void)
{
    uint8_t pk[KYBER_PQC_PUBLIC_KEY_BYTES];
    uint8_t sk[KYBER_PQC_PRIVATE_KEY_BYTES];
    uint8_t ct[KYBER_PQC_CIPHERTEXT_BYTES];
    uint8_t ss[KYBER_PQC_SHARED_SECRET_BYTES];
    uint8_t decoded_pk[KYBER_PQC_PUBLIC_KEY_BYTES];
    uint8_t decoded_sk[KYBER_PQC_PRIVATE_KEY_BYTES];
    uint8_t decoded_ct[KYBER_PQC_CIPHERTEXT_BYTES];
    uint8_t decoded_ss[KYBER_PQC_SHARED_SECRET_BYTES];
    size_t decoded_len;
    char *pem = NULL;
    const char *path = "build/test_key.hex.pem";

    if (kyber_pqc_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }
    if (kyber_pqc_encapsulate(pk, ct, ss) != 0) {
        fprintf(stderr, "encapsulate failed\n");
        return 1;
    }

    if (kyber_pem_encode(KYBER_PEM_PUBLIC_KEY, pk, sizeof(pk), &pem) != 0) {
        fprintf(stderr, "encode public key failed\n");
        return 1;
    }
    decoded_len = sizeof(decoded_pk);
    if (kyber_pem_decode(KYBER_PEM_PUBLIC_KEY, pem, decoded_pk, &decoded_len) != 0) {
        fprintf(stderr, "decode public key failed\n");
        return 1;
    }
    if (memcmp(pk, decoded_pk, sizeof(pk)) != 0) {
        fprintf(stderr, "public key round-trip mismatch\n");
        return 1;
    }
    kyber_pem_free(pem);
    pem = NULL;

    if (kyber_pem_write_file(path, KYBER_PEM_PRIVATE_KEY, sk, sizeof(sk)) != 0) {
        fprintf(stderr, "write pem file failed\n");
        return 1;
    }
    decoded_len = sizeof(decoded_sk);
    if (kyber_pem_read_file(path, KYBER_PEM_PRIVATE_KEY, decoded_sk, &decoded_len) != 0) {
        fprintf(stderr, "read pem file failed\n");
        return 1;
    }
    if (memcmp(sk, decoded_sk, sizeof(sk)) != 0) {
        fprintf(stderr, "private key file round-trip mismatch\n");
        return 1;
    }

    if (kyber_pem_encode(KYBER_PEM_CIPHERTEXT, ct, sizeof(ct), &pem) != 0) {
        fprintf(stderr, "encode ciphertext failed\n");
        return 1;
    }
    decoded_len = sizeof(decoded_ct);
    if (kyber_pem_decode(KYBER_PEM_CIPHERTEXT, pem, decoded_ct, &decoded_len) != 0) {
        fprintf(stderr, "decode ciphertext failed\n");
        return 1;
    }
    kyber_pem_free(pem);
    pem = NULL;

    if (kyber_pem_encode(KYBER_PEM_SHARED_SECRET, ss, sizeof(ss), &pem) != 0) {
        fprintf(stderr, "encode shared secret failed\n");
        return 1;
    }
    decoded_len = sizeof(decoded_ss);
    if (kyber_pem_decode(KYBER_PEM_SHARED_SECRET, pem, decoded_ss, &decoded_len) != 0) {
        fprintf(stderr, "decode shared secret failed\n");
        return 1;
    }
    kyber_pem_free(pem);

    printf("c hex pem ok\n");
    return 0;
}
