#include <stdio.h>
#include <string.h>

#include "kyber_pem.h"
#include "kyber_pqc.h"

#ifndef KYBER_PQC_VERSION
#define KYBER_PQC_VERSION "2.0.0"
#endif

static void print_usage(const char *program)
{
    fprintf(
        stderr,
        "usage:\n"
        "  %s version\n"
        "  %s keygen <public.hex.pem> <private.hex.pem>\n",
        program,
        program
    );
}

int main(int argc, char **argv)
{
    uint8_t public_key[KYBER_PQC_PUBLIC_KEY_BYTES];
    uint8_t private_key[KYBER_PQC_PRIVATE_KEY_BYTES];

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "version") == 0) {
        printf("kyber-pqc %s (ML-KEM-512)\n", KYBER_PQC_VERSION);
        return 0;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        if (argc != 4) {
            print_usage(argv[0]);
            return 1;
        }
        if (kyber_pqc_keypair(public_key, private_key) != 0) {
            fprintf(stderr, "key generation failed\n");
            return 1;
        }
        if (kyber_pem_write_file(
                argv[2],
                KYBER_PEM_PUBLIC_KEY,
                public_key,
                sizeof(public_key)
            ) != 0) {
            fprintf(stderr, "failed to write public key\n");
            return 1;
        }
        if (kyber_pem_write_file(
                argv[3],
                KYBER_PEM_PRIVATE_KEY,
                private_key,
                sizeof(private_key)
            ) != 0) {
            fprintf(stderr, "failed to write private key\n");
            return 1;
        }
        printf("wrote %s and %s\n", argv[2], argv[3]);
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
