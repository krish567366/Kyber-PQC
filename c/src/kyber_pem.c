#include "kyber_pem.h"
#include "kyber_pqc.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *LABELS[] = {
    "PUBLIC KEY",
    "PRIVATE KEY",
    "CIPHERTEXT",
    "SHARED SECRET",
};

static const size_t EXPECTED_BYTES[] = {
    KYBER_PQC_PUBLIC_KEY_BYTES,
    KYBER_PQC_PRIVATE_KEY_BYTES,
    KYBER_PQC_CIPHERTEXT_BYTES,
    KYBER_PQC_SHARED_SECRET_BYTES,
};

const char *kyber_pem_label(kyber_pem_kind_t kind)
{
    if (kind < 0 || kind > KYBER_PEM_SHARED_SECRET) {
        return NULL;
    }
    return LABELS[kind];
}

size_t kyber_pem_expected_bytes(kyber_pem_kind_t kind)
{
    if (kind < 0 || kind > KYBER_PEM_SHARED_SECRET) {
        return 0;
    }
    return EXPECTED_BYTES[kind];
}

void kyber_pem_free(char *pem)
{
    free(pem);
}

static int hex_encode(const uint8_t *data, size_t data_len, char **out_hex)
{
    static const char HEX[] = "0123456789abcdef";
    char *hex;
    size_t i;

    hex = (char *)malloc((data_len * 2U) + 1U);
    if (hex == NULL) {
        return -1;
    }

    for (i = 0; i < data_len; i++) {
        hex[i * 2U] = HEX[data[i] >> 4];
        hex[(i * 2U) + 1U] = HEX[data[i] & 0x0f];
    }
    hex[data_len * 2U] = '\0';
    *out_hex = hex;
    return 0;
}

static int hex_decode(const char *hex, uint8_t *out, size_t expected_len)
{
    size_t hex_len;
    size_t i;

    if (hex == NULL || out == NULL) {
        return -1;
    }

    hex_len = strlen(hex);
    if (hex_len != expected_len * 2U) {
        return -1;
    }

    for (i = 0; i < expected_len; i++) {
        char hi = (char)tolower((unsigned char)hex[i * 2U]);
        char lo = (char)tolower((unsigned char)hex[(i * 2U) + 1U]);
        int hi_val;
        int lo_val;

        if (!isxdigit((unsigned char)hi) || !isxdigit((unsigned char)lo)) {
            return -1;
        }

        hi_val = (hi >= 'a') ? (hi - 'a' + 10) : (hi - '0');
        lo_val = (lo >= 'a') ? (lo - 'a' + 10) : (lo - '0');
        out[i] = (uint8_t)((hi_val << 4) | lo_val);
    }

    return 0;
}

static int build_header(kyber_pem_kind_t kind, char *buf, size_t buf_len)
{
    int written = snprintf(
        buf,
        buf_len,
        "-----BEGIN KYBER512 %s-----\n",
        LABELS[kind]
    );
    return (written < 0 || (size_t)written >= buf_len) ? -1 : 0;
}

static int build_footer(kyber_pem_kind_t kind, char *buf, size_t buf_len)
{
    int written = snprintf(
        buf,
        buf_len,
        "-----END KYBER512 %s-----\n",
        LABELS[kind]
    );
    return (written < 0 || (size_t)written >= buf_len) ? -1 : 0;
}

int kyber_pem_encode(
    kyber_pem_kind_t kind,
    const uint8_t *data,
    size_t data_len,
    char **out_pem
)
{
    char *hex = NULL;
    char *pem = NULL;
    size_t pem_len;
    size_t hex_len;
    size_t offset = 0;
    size_t i;

    if (out_pem == NULL || data == NULL) {
        return -1;
    }
    if (kind < 0 || kind > KYBER_PEM_SHARED_SECRET) {
        return -1;
    }
    if (data_len != EXPECTED_BYTES[kind]) {
        return -1;
    }
    if (hex_encode(data, data_len, &hex) != 0) {
        return -1;
    }

    hex_len = strlen(hex);
    pem_len = hex_len + (hex_len / KYBER_PEM_LINE_WIDTH) + 128U;
    pem = (char *)malloc(pem_len);
    if (pem == NULL) {
        free(hex);
        return -1;
    }

    if (build_header(kind, pem, pem_len) != 0) {
        free(hex);
        free(pem);
        return -1;
    }
    offset = strlen(pem);

    for (i = 0; i < hex_len; i += KYBER_PEM_LINE_WIDTH) {
        size_t chunk = hex_len - i;
        if (chunk > KYBER_PEM_LINE_WIDTH) {
            chunk = KYBER_PEM_LINE_WIDTH;
        }
        if (offset + chunk + 2U >= pem_len) {
            free(hex);
            free(pem);
            return -1;
        }
        memcpy(pem + offset, hex + i, chunk);
        offset += chunk;
        pem[offset++] = '\n';
    }
    pem[offset] = '\0';

    if (build_footer(kind, pem + offset, pem_len - offset) != 0) {
        free(hex);
        free(pem);
        return -1;
    }

    free(hex);
    *out_pem = pem;
    return 0;
}

static int extract_body(const char *pem, kyber_pem_kind_t kind, char **out_hex)
{
    char begin[128];
    char end[128];
    const char *start;
    const char *stop;
    size_t body_len;
    char *body;
    size_t i;
    size_t j = 0;

    snprintf(begin, sizeof(begin), "-----BEGIN KYBER512 %s-----", LABELS[kind]);
    snprintf(end, sizeof(end), "-----END KYBER512 %s-----", LABELS[kind]);

    start = strstr(pem, begin);
    if (start == NULL) {
        return -1;
    }
    start += strlen(begin);
    while (*start == '\n' || *start == '\r') {
        start++;
    }

    stop = strstr(start, end);
    if (stop == NULL) {
        return -1;
    }

    body_len = (size_t)(stop - start);
    body = (char *)malloc(body_len + 1U);
    if (body == NULL) {
        return -1;
    }

    for (i = 0; i < body_len; i++) {
        char c = start[i];
        if (c == '\n' || c == '\r' || c == ' ') {
            continue;
        }
        body[j++] = c;
    }
    body[j] = '\0';
    *out_hex = body;
    return 0;
}

int kyber_pem_decode(
    kyber_pem_kind_t kind,
    const char *pem,
    uint8_t *out,
    size_t *out_len
)
{
    char *hex = NULL;
    size_t expected;

    if (pem == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if (kind < 0 || kind > KYBER_PEM_SHARED_SECRET) {
        return -1;
    }

    expected = EXPECTED_BYTES[kind];
    if (*out_len < expected) {
        return -1;
    }
    if (extract_body(pem, kind, &hex) != 0) {
        return -1;
    }
    if (hex_decode(hex, out, expected) != 0) {
        free(hex);
        return -1;
    }

    *out_len = expected;
    free(hex);
    return 0;
}

int kyber_pem_write_file(
    const char *path,
    kyber_pem_kind_t kind,
    const uint8_t *data,
    size_t data_len
)
{
    char *pem = NULL;
    FILE *file;
    int rc = -1;

    if (path == NULL || data == NULL) {
        return -1;
    }
    if (kyber_pem_encode(kind, data, data_len, &pem) != 0) {
        return -1;
    }

    file = fopen(path, "w");
    if (file == NULL) {
        kyber_pem_free(pem);
        return -1;
    }

    if (fputs(pem, file) >= 0) {
        rc = 0;
    }

    fclose(file);
    kyber_pem_free(pem);
    return rc;
}

int kyber_pem_read_file(
    const char *path,
    kyber_pem_kind_t kind,
    uint8_t *out,
    size_t *out_len
)
{
    FILE *file;
    long size;
    char *pem = NULL;
    int rc = -1;

    if (path == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    file = fopen(path, "r");
    if (file == NULL) {
        return -1;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    size = ftell(file);
    if (size < 0) {
        fclose(file);
        return -1;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }

    pem = (char *)malloc((size_t)size + 1U);
    if (pem == NULL) {
        fclose(file);
        return -1;
    }
    if (fread(pem, 1, (size_t)size, file) != (size_t)size) {
        free(pem);
        fclose(file);
        return -1;
    }
    pem[size] = '\0';
    fclose(file);

    if (kyber_pem_decode(kind, pem, out, out_len) == 0) {
        rc = 0;
    }

    free(pem);
    return rc;
}
