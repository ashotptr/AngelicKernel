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
    if (!s) {
        s = "(null)";
    }

    while (*s) {
        putchar(*s++);
    }
}

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
                    print_int((long)(unsigned long)(unsigned int)va_arg(args, unsigned int));
                    
                    break;

                case 'x':
                    print_hex(va_arg(args, unsigned long));
                    
                    break;

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
        }
        else {
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

int vsnprintf(char *str, size_t size, const char *format, va_list args) {
    char *out = str;
    size_t remaining = size;

    while (*format && remaining > 1) {
        if (*format != '%') {
            *out++ = *format++;
            remaining--;

            continue;
        }

        format++;
        
        int is_long = 0;
        int is_size = 0;

        if (*format == 'l') { 
            is_long = 1; 
            format++; 
        }
        else if (*format == 'z') { 
            is_size = 1;
            format++;
        }

        switch (*format) {
            case 'd':
            case 'i': {
                long val = is_long ? va_arg(args, long) : (long)va_arg(args, int);
                
                if (val < 0 && remaining > 1) { 
                    *out++ = '-'; 
                    remaining--; 
                    val = -val; 
                }
                
                simple_append_int(&out, &remaining, (unsigned long)val);
                
                break;
            }
            case 'u': {
                unsigned long val = (is_long || is_size) ? va_arg(args, unsigned long) : (unsigned long)va_arg(args, unsigned int);

                simple_append_int(&out, &remaining, val);

                break;
            }
            case 'x':
            case 'X': {
                unsigned long val = (is_long || is_size) ? va_arg(args, unsigned long) : (unsigned long)va_arg(args, unsigned int);
                
                simple_append_hex(&out, &remaining, val);
                
                break;
            }
            case 'p': {
                if (remaining > 2) { 
                    *out++ = '0'; 
                    *out++ = 'x'; 
                    remaining -= 2; 
                }

                simple_append_hex(&out, &remaining, va_arg(args, unsigned long));
                
                break;
            }
            case 's': {
                const char *s = va_arg(args, const char *);

                if (!s) {
                    s = "(null)";
                }

                while (*s && remaining > 1) { 
                    *out++ = *s++;
                    remaining--; 
                }

                break;
            }
            case 'c': {
                int c = va_arg(args, int);

                if (remaining > 1) { 
                    *out++ = (char)c; 
                    remaining--; 
                }

                break;
            }
            case '%': {
                if (remaining > 1) { 
                    *out++ = '%'; 
                    remaining--; 
                }

                break;
            }
            default: {
                if (remaining > 1) { 
                    *out++ = '%';
                    remaining--;
                }

                if (remaining > 1) { 
                    *out++ = *format;
                    remaining--; 
                }

                break;
            }
        }

        format++;
    }

    *out = '\0';

    return (int)(out - str);
}

int snprintf(char *str, size_t size, const char *format, ...) {
    va_list args;

    va_start(args, format);

    int ret = vsnprintf(str, size, format, args);
    
    va_end(args);
    
    return ret;
}

int hw_trng_read(uint32_t *out) {
    for (int attempt = 0; attempt < 10; attempt++) {
        unsigned int val = 0;
        unsigned char cf = 0;

        __asm__ volatile(
            "rdrand %0\n"
            "setc   %1\n"
            : "=r"(val), "=qm"(cf)
            :
            : "cc"
        );

        if (cf) {
            *out = (uint32_t)val;

            return 1;
        }
    }

    return 0;
}

unsigned int secure_random_u32(void) {
    uint32_t hw;

    if (hw_trng_read(&hw)) {
        return (unsigned int)hw;
    }

    static uint64_t state = 0;
    static int seeded = 0;

    if (!seeded) {
        uint32_t seed_hi = 0, seed_lo = 0;
        int got_hi = hw_trng_read(&seed_hi);
        int got_lo = hw_trng_read(&seed_lo);

        if (got_hi && got_lo) {
            state = ((uint64_t)seed_hi << 32) | seed_lo;
        }
        else {
            serial_print("[security warning] hw_trng_read() unavailable\n");

            state = 0xDEADBEEFCAFEBABEULL ^ (uint64_t)(uintptr_t)&state;
        }

        if (state == 0) {
            state = 0x123456789ABCDEF0ULL;
        }

        seeded = 1;
    }

    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;

    return (unsigned int)((state * 0x2545F4914F6CDD1DULL) >> 32);
}

int rand(void) {
    static unsigned long next = 123456789;
    next = next * 1103515245 + 12345;

    return (unsigned int)(next / 65536) % 32768;
}

void abort(void) {
    serial_print("[fatal] abort called\n");

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