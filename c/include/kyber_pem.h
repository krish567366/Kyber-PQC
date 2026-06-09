#ifndef KYBER_PEM_H
#define KYBER_PEM_H

#include <stddef.h>
#include <stdint.h>

#define KYBER_PEM_LINE_WIDTH 64

typedef enum {
    KYBER_PEM_PUBLIC_KEY = 0,
    KYBER_PEM_PRIVATE_KEY = 1,
    KYBER_PEM_CIPHERTEXT = 2,
    KYBER_PEM_SHARED_SECRET = 3
} kyber_pem_kind_t;

const char *kyber_pem_label(kyber_pem_kind_t kind);
size_t kyber_pem_expected_bytes(kyber_pem_kind_t kind);

int kyber_pem_encode(
    kyber_pem_kind_t kind,
    const uint8_t *data,
    size_t data_len,
    char **out_pem
);
int kyber_pem_decode(
    kyber_pem_kind_t kind,
    const char *pem,
    uint8_t *out,
    size_t *out_len
);

int kyber_pem_write_file(
    const char *path,
    kyber_pem_kind_t kind,
    const uint8_t *data,
    size_t data_len
);
int kyber_pem_read_file(
    const char *path,
    kyber_pem_kind_t kind,
    uint8_t *out,
    size_t *out_len
);

void kyber_pem_free(char *pem);

#endif
