#include <stddef.h>
#include <string.h>
#include "mbedtls/platform.h"

void explicit_bzero(void *s, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)s;

    while (n--) {
        *p++ = 0;
    }
}

void * __attribute__((weak)) calloc(size_t nmemb, size_t size) {
    return mbedtls_calloc(nmemb, size);
}

void __attribute__((weak)) free(void *ptr) {
    mbedtls_free(ptr);
}

void exit(int status) {
    (void)status;
    __asm__ volatile("cli; hlt");

    __builtin_unreachable();
}

int inet_pton(int af, const char *src, void *dst) {
    (void)af;
    (void)src;
    (void)dst;

    return 0;
}