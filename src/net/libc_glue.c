#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

extern void serial_print(const char* str);

void *memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

void *memcpy(void *dest, const void *src, size_t n) {
    char *d = (char *)dest;
    const char *s = (const char *)src;
    while (n--) *d++ = *s++;
    return dest;
}

void *memmove(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    
    if (d == s) return dest;

    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++; p2++;
    }
    return 0;
}

size_t strlen(const char *str) {
    size_t len = 0;
    while (str[len]) len++;
    return len;
}

// size_t strlen(const char *str) {
//     const char *s = str;
//     while (*s) s++;
//     return s - str;
// }

int strncmp(const char *s1, const char *s2, size_t n) {
    while (n > 0) {
        if (*s1 != *s2) return (unsigned char)*s1 - (unsigned char)*s2;
        if (*s1 == '\0') return 0;
        s1++;
        s2++;
        n--;
    }
    return 0;
}

// int strncmp(const char *s1, const char *s2, size_t n) {
//     while (n && *s1 && (*s1 == *s2)) {
//         s1++;
//         s2++;
//         n--;
//     }
//     if (n == 0) return 0;
//     return *(const unsigned char *)s1 - *(const unsigned char *)s2;
// }

int atoi(const char *str) {
    int res = 0;
    int sign = 1;
    
    while (*str == ' ' || *str == '\t' || *str == '\n') str++;

    if (*str == '-') { sign = -1; str++; }
    else if (*str == '+') { str++; }

    while (*str >= '0' && *str <= '9') {
        res = res * 10 + (*str - '0');
        str++;
    }
    return res * sign;
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

int vsnprintf(char *str, size_t size, const char *format, va_list args) {
    char *out = str;
    size_t remaining = size;

    while (*format && remaining > 1) {
        if (*format == '%') {
            format++;
            if (*format == 'd' || *format == 'u') {
                int val = va_arg(args, int);
                if (val < 0 && *format == 'd') {
                    if (remaining > 1) { *out++ = '-'; remaining--; }
                    val = -val;
                }
                simple_append_int(&out, &remaining, (unsigned long)val);
            } else if (*format == 's') {
                char *s = va_arg(args, char*);
                while (s && *s && remaining > 1) {
                    *out++ = *s++;
                    remaining--;
                }
            } else if (*format == 'x' || *format == 'p') {
                if (remaining > 2) { *out++ = '0'; *out++ = 'x'; remaining -= 2; }
                simple_append_int(&out, &remaining, va_arg(args, unsigned long)); 
            }
        } else {
            *out++ = *format;
            remaining--;
        }
        format++;
    }
    *out = '\0';
    return out - str;
}

int snprintf(char *str, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(str, size, format, args);
    va_end(args);
    return ret;
}

int printf(const char *format, ...) {
    char buf[256];
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    serial_print(buf);
    return ret;
}

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

char *strstr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    for (; *haystack; haystack++) {
        if (*haystack != *needle) continue;
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            h++;
            n++;
        }
        if (!*n) return (char *)haystack;
    }
    return NULL;
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
    for (i = 0; i < n && src[i] != '\0'; i++)
        dest[i] = src[i];
    for ( ; i < n; i++)
        dest[i] = '\0';
    return dest;
}