#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

extern void serial_print(const char* str);

__attribute__((weak))
void *memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;

    while (n--) {
        *p++ = (unsigned char)c;
    }

    return s;
}

__attribute__((weak))
void *memcpy(void *dest, const void *src, size_t n) {
    char *d = (char *)dest; //unsigned char
    const char *s = (const char *)src;
    
    while (n--) {
        *d++ = *s++;
    }

    return dest;
}

void *memmove(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    
    if (d == s) {
        return dest;
    }

    if (d < s) {
        while (n--) {
            *d++ = *s++;
        }
    }
    else {
        d += n;
        s += n;
        
        while (n--) {
            *--d = *--s;
        }
    }

    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;

    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }

        p1++;
        p2++;
    }

    return 0;
}

void *memchr(const void *s, int c, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    
    while (n--) {
        if (*p == (unsigned char)c) {
            return (void *)p;
        }
        
        p++;
    }
    
    return NULL;
}

size_t strlen(const char *str) {
    const char *s = str;

    while (*s) {
        s++;
    }

    return s - str;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    while (n > 0) {
        if (*s1 != *s2) {
            return (unsigned char)*s1 - (unsigned char)*s2;
        }

        if (*s1 == '\0') {
            return 0;
        }

        s1++;
        s2++;
        n--;
    }

    return 0;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }

    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;

    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }

    for (; i < n; i++) {
        dest[i] = '\0';
    }

    return dest;
}

char *strstr(const char *haystack, const char *needle) {
    if (!*needle) {
        return (char *)haystack;
    }

    for (; *haystack; haystack++) {
        if (*haystack != *needle) {
            continue;
        }

        const char *h = haystack;
        const char *n = needle;

        while (*h && *n && *h == *n) {
            h++;
            n++;
        }

        if (!*n) {
            return (char *)haystack;
        }
    }

    return NULL;
}

char *strcpy(char *dest, const char *src) {
    char *save = dest;

    while ((*dest++ = *src++));

    return save;
}

char *strchr(const char *s, int c) {
    while (*s != (char)c) {
        if (!*s++) {
            return NULL;
        }
    }

    return (char *)s;
}

char *strrchr(const char *s, int c) {
    const char *last = NULL;

    do {
        if (*s == (char)c) {
            last = s;
        }
    } while (*s++);
    
    return (char *)last;
}

char *strncat(char *dest, const char *src, size_t n) {
    char *d = dest;
    
    while (*d != '\0') {
        d++;
    }
    
    while (n-- > 0 && *src != '\0') {
        *d++ = *src++;
    }
    
    *d = '\0';
    
    return dest;
}

char *strcat(char *dest, const char *src) {
    char *d = dest;

    while (*d != '\0') {
        d++;
    }

    while (*src != '\0') {
        *d++ = *src++;
    }

    *d = '\0';

    return dest;
}

int atoi(const char *str) {
    int res = 0;
    int sign = 1;
    
    while (*str == ' ' || *str == '\t' || *str == '\n') {
        str++;
    }

    if (*str == '-') { 
        sign = -1;
        str++;
    }
    else if (*str == '+') { 
        str++; 
    }

    while (*str >= '0' && *str <= '9') {
        res = res * 10 + (*str - '0'); // '0' is 48 in ASCII
        str++;
    }

    return res * sign;
}

int putchar(int c) {
    char str[2] = {(char)c, '\0'};
    serial_print(str);
    return c;
}

static void simple_append_int(char **buf, size_t *limit, unsigned long n) {
    if (n >= 10) {
        simple_append_int(buf, limit, n / 10);
    }

    if (*limit > 1) {
        **buf = (n % 10) + '0';
        (*buf)++;
        (*limit)--;
    }
}

static void simple_append_hex(char **buf, size_t *limit, unsigned long n) {
    char hex_digits[] = "0123456789ABCDEF";

    if (n >= 16) {
        simple_append_hex(buf, limit, n / 16);
    }

    if (*limit > 1) {
        **buf = hex_digits[n % 16];
        (*buf)++;
        (*limit)--;
    }
}

static void print_int(long n) {
    char buffer[21];
    int i = 0;
    int is_neg = 0;

    if (n == 0) {
        putchar('0');
        return;
    }

    if (n < 0) {
        is_neg = 1;
        n = -n; 
    }

    while (n > 0) {
        buffer[i++] = (n % 10) + '0';
        n /= 10;
    }

    if (is_neg) {
        putchar('-');
    }

    while (i > 0) {
        putchar(buffer[--i]);
    }
}

static void print_hex(unsigned long n) {
    char buffer[16];
    int i = 0;
    char hex_digits[] = "0123456789ABCDEF";

    if (n == 0) {
        putchar('0');
        return;
    }

    while (n > 0) {
        buffer[i++] = hex_digits[n % 16];
        n /= 16;
    }

    while (i > 0) {
        putchar(buffer[--i]);
    }
}

static void print_str(const char *s) {
    if (!s) s = "(null)";
    while (*s) putchar(*s++);
}

//review
int vprintf(const char *format, va_list args) {
    int count = 0;

    while (*format) {
        if (*format == '%') {
            format++;
            switch (*format) {
                case 'd':
                    print_int(va_arg(args, int));
                    break;
                case 'u':
                    print_int(va_arg(args, unsigned int));
                    break;
                case 'x':
                case 'p':
                    print_str("0x");
                    print_hex(va_arg(args, unsigned long));
                    break;
                case 's':
                    print_str(va_arg(args, char*));
                    break;
                case 'c':
                    putchar(va_arg(args, int));
                    break;
                case '%':
                    putchar('%');
                    break;
                default:
                    putchar('%');
                    putchar(*format);
            }
        } else {
            putchar(*format);
        }
        format++;
        count++;
    }
    return count;
}

int printf(const char *format, ...) {
    va_list args;

    va_start(args, format);

    int ret = vprintf(format, args);

    va_end(args);
    
    return ret;
}

//review
int vsnprintf(char *str, size_t size, const char *format, va_list args) {
    char *out = str;
    size_t remaining = size;

    while (*format && remaining > 1) {
        if (*format == '%') {
            format++;
            
            if (*format == 'd') {
                int val = va_arg(args, int);
                
                if (val < 0) {
                    if (remaining > 1) {
                        *out++ = '-'; remaining--;
                    }

                    val = -val;
                }

                simple_append_int(&out, &remaining, (unsigned long)(unsigned int)val);
            }
            else if (*format == 'u') {
                /* Must read as unsigned int, not int — reading a value
                 * with the high bit set as int then casting to unsigned long
                 * sign-extends it to 64 bits, producing a 20-digit decimal.
                 * This was causing stream IDs like 18446744073707137098
                 * instead of the correct 32-bit value. */
                unsigned int uval = va_arg(args, unsigned int);

                simple_append_int(&out, &remaining, (unsigned long)uval);
            }
            else if (*format == 's') {
                char *s = va_arg(args, char*);
                
                while (s && *s && remaining > 1) {
                    *out++ = *s++;
                    remaining--;
                }
            }
            else if (*format == 'x' || *format == 'p') {
                if (remaining > 2) {
                    *out++ = '0'; *out++ = 'x'; remaining -= 2; 
                }
                
                simple_append_hex(&out, &remaining, va_arg(args, unsigned long)); 
            }
        }
        else {
            *out++ = *format;
            remaining--;
        }

        format++;
    }

    *out = '\0';
    
    return out - str;
}

//review
int snprintf(char *str, size_t size, const char *format, ...) {
    va_list args;

    va_start(args, format);

    int ret = vsnprintf(str, size, format, args);
    
    va_end(args);
    
    return ret;
}

//review
// int printf(const char *format, ...) {
//     char buf[256];
//     va_list args;

//     va_start(args, format);
    
//     int ret = vsnprintf(buf, sizeof(buf), format, args);
    
//     va_end(args);
    
//     serial_print(buf);
    
//     return ret;
// }

/* ------------------------------------------------------------------
 * Hardware TRNG hook
 *
 * Platforms MUST override this weak stub with a real implementation
 * that reads one 32-bit word from the MCU's hardware True Random
 * Number Generator (TRNG) peripheral.
 *
 * Return value:
 *   1  — *out has been filled with a hardware-entropy word.
 *   0  — TRNG unavailable; caller will fall back to the software CSPRNG.
 *
 * Example (Cortex-M4 with STM32 RNG peripheral):
 *
 *   int hw_trng_read(uint32_t *out) {
 *       while (!(RNG->SR & RNG_SR_DRDY));   // wait for data ready
 *       *out = RNG->DR;
 *       return 1;
 *   }
 *
 * RFC 6120 §4.7.3 — stream IDs MUST be hard to predict.
 * RFC 6120 §7.7.1 — server-generated resource IDs (we treat the same).
 * ------------------------------------------------------------------ */
__attribute__((weak))
int hw_trng_read(uint32_t *out) {
    (void)out;
    /* Weak stub -- signals no hardware TRNG so secure_random_u32()
     * activates its xorshift64* CSPRNG fallback (with a seed warning).
     *
     * To provide real entropy, define a non-weak hw_trng_read() in your
     * BSP that reads from the MCU TRNG peripheral, e.g. (STM32 RNG):
     *
     *   int hw_trng_read(uint32_t *out) {
     *       while (!(RNG->SR & RNG_SR_DRDY));
     *       *out = RNG->DR;
     *       return 1;
     *   }
     *
     * On x86-64 / QEMU, rdrand is available:
     *   int hw_trng_read(uint32_t *out) {
     *       return __builtin_ia32_rdrand32_step(out);
     *   }
     */
    return 0;
}

/* ------------------------------------------------------------------
 * secure_random_u32
 *
 * Returns a cryptographically unpredictable 32-bit value suitable for
 * use in stream IDs and resource IDs per RFC 6120 §4.7.3.
 *
 * Algorithm:
 *   1. Try hw_trng_read().  If it succeeds, return the hardware word
 *      directly — this is the preferred path.
 *   2. Otherwise, run an xorshift64* CSPRNG whose 64-bit state is
 *      (re-)seeded from hw_trng_read() on the very first call.  If
 *      the TRNG is still unavailable at seeding time the state is
 *      initialised from a compile-time constant, which degrades to a
 *      PRNG that is at least harder to predict than the old LCG but
 *      is NOT cryptographically secure.  The serial console will print
 *      a warning in that case so the condition is visible.
 *
 * xorshift64* reference:
 *   Vigna, S. "An experimental exploration of Marsaglia's xorshift
 *   generators, scrambled" (2016).  The * scrambler (multiply by a
 *   Weyl-sequence constant) gives good statistical quality; the period
 *   is 2^64-1.
 *
 * NOTE: the LCG rand() below is kept for any third-party code that
 * calls the standard rand() symbol, but it must NOT be used for
 * security-sensitive IDs.  See the SECURITY WARNING comment there.
 * ------------------------------------------------------------------ */
unsigned int secure_random_u32(void) {
    uint32_t hw;

    /* Fast path: real hardware entropy */
    if (hw_trng_read(&hw)) {
        return (unsigned int)hw;
    }

    /* Software fallback: xorshift64* seeded from hardware entropy
     * (or a compile-time constant if TRNG is not yet available). */
    static uint64_t state = 0;
    static int seeded = 0;

    if (!seeded) {
        uint32_t seed_hi = 0, seed_lo = 0;
        int got_hi = hw_trng_read(&seed_hi);
        int got_lo = hw_trng_read(&seed_lo);

        if (got_hi && got_lo) {
            state = ((uint64_t)seed_hi << 32) | seed_lo;
        } else {
            /* TRNG unavailable at seed time — degrade gracefully but
             * warn loudly so the integrator notices. */
            serial_print("[SECURITY WARNING] hw_trng_read() unavailable; "
                         "secure_random_u32() is seeded from a constant. "
                         "Override hw_trng_read() in your BSP.\n");
            /* Mix in the address of the state variable as a tiny bit
             * of environmental entropy so different builds differ. */
            state = 0xDEADBEEFCAFEBABEULL ^ (uint64_t)(uintptr_t)&state;
        }

        /* xorshift64 must never have an all-zero state */
        if (state == 0) {
            state = 0x123456789ABCDEF0ULL;
        }

        seeded = 1;
    }

    /* xorshift64* step */
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;

    return (unsigned int)((state * 0x2545F4914F6CDD1DULL) >> 32);
}

/* ------------------------------------------------------------------
 * rand() — kept for ABI compatibility ONLY.
 *
 * SECURITY WARNING: This is a plain LCG.  It MUST NOT be used for
 * stream IDs, resource IDs, nonces, or any other security-sensitive
 * value.  Use secure_random_u32() instead.
 * ------------------------------------------------------------------ */
int rand(void) {
    static unsigned long next = 123456789;
    next = next * 1103515245 + 12345;

    return (unsigned int)(next / 65536) % 32768;
}

void abort(void) {
    serial_print("[FATAL] ABORT CALLED\n");

    __asm__ volatile("cli; hlt");
    
    while(1);
}

// public implemantations of libc functions
// Glibc
// (https://www.gnu.org/savannah-checkouts/gnu/libc/index.html | https://www.gnu.org/software/libc/) -> https://sourceware.org/glibc/ -> https://sourceware.org/git/?p=glibc.git
// https://elixir.bootlin.com/glibc/glibc-2.42.9000/source
// https://github.com/lattera/glibc

// Musl
// https://musl.libc.org/
// https://git.musl-libc.org/cgit/musl/tree/src
// https://github.com/esmil/musl

// Newlib
// https://sourceware.org/newlib/
// https://sourceware.org/git/gitweb.cgi?p=newlib-cygwin.git
// https://github.com/eblot/newlib/tree/master/newlib/libc

// PDCLib
// https://rootdirectory.de/doku.php?id=pdclib:start

// uClibc
// https://www.uclibc.org/

// Diet Libc
// http://www.fefe.de/dietlibc/
// https://github.com/ensc/dietlibc

// Google's Bionic
// https://android.googlesource.com/platform/bionic/

// Sortix Libc
// https://gitlab.com/sortix/sortix/-/tree/main/libc

// Libc11
// https://github.com/dryc/libc11
// https://github.com/public-domain/libc11/tree/master/libc11-master

// mlibc
// https://github.com/managarm/mlibc

// PDPCLIB
// https://www.pdos.org/

// https://github.com/openbsd/src/tree/master/lib/libc
// https://github.com/libressl/openbsd/tree/master/src/lib/libc
// https://github.com/freebsd/freebsd-src/tree/main/lib/libc
// https://github.com/bminor/glibc


// The freestanding headers are: <float.h>, <iso646.h>, <limits.h>, <stdalign.h>, 
//                               <stdarg.h>, <stdbool.h>, <stddef.h>, <stdint.h>, and <stdnoreturn.h>
// https://www.etalabs.net/compare_libcs.html
// https://wiki.osdev.org/C_Library