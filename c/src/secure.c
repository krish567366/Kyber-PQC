#include "secure.h"

#include <string.h>

#if defined(__linux__)
#include <strings.h>
#endif

void kyber_pqc_secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *cursor;

    if (ptr == NULL || len == 0) {
        return;
    }

#if defined(__linux__)
    explicit_bzero(ptr, len);
    return;
#endif

    cursor = (volatile unsigned char *)ptr;
    while (len-- > 0) {
        *cursor++ = 0;
    }
}
