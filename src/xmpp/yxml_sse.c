#ifdef __SSE4_2__

#include <nmmintrin.h>
#include <stdint.h>
#include <string.h>

static int cpu_has_sse42(void) {
    uint32_t ecx = 0;

    __asm__ volatile(
        "cpuid"
        : "=c"(ecx)
        : "a"(1)
        : "ebx", "edx"
    );

    return (ecx >> 20) & 1;
}

static const char XML_NEEDLE[16] = {
    '<', '>', '/', '!', '?',
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define NEEDLE_LEN 5
#define PCMPISTRI_FLAGS (_SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_LEAST_SIGNIFICANT)

int find_stanza_end_sse(const char *xml, int len) {
    const char *p = xml;
    const char *end = xml + len;
    int depth = 0;

    __m128i needle = _mm_loadu_si128((const __m128i *)XML_NEEDLE);

    while (p < end) {
        int remaining = (int)(end - p);

        if (remaining >= 16) {
            __m128i chunk = _mm_loadu_si128((const __m128i *)p);
            int idx = _mm_cmpistri(needle, chunk, PCMPISTRI_FLAGS);

            if (idx == 16) {
                p += 16;

                continue;
            }

            p += idx;
        }

        char c = *p;

        if (c != '<') {
            p++;

            continue;
        }

        if (p + 1 >= end) {
            return -1;
        }

        char next = *(p + 1);

        if (next == '?' || next == '!') {
            const char *gt = (const char *)memchr(p, '>', end - p);

            if (!gt) {
                return -1;
            }

            p = gt + 1;

            continue;
        }

        if (next == '/') {
            const char *gt = (const char *)memchr(p, '>', end - p);

            if (!gt) {
                return -1;
            }

            depth--;

            if (depth == 0) {
                return (int)((gt + 1) - xml);
            }

            p = gt + 1;

            continue;
        }

        const char *gt = (const char *)memchr(p, '>', end - p);
        
        if (!gt) {
            return -1;
        }

        if (*(gt - 1) == '/') {
            if (depth == 0) {
                return (int)((gt + 1) - xml);
            }
        }
        else {
            depth++;
        }

        p = gt + 1;
    }

    return -1;
}

static int find_stanza_end_scalar(const char *xml, int len) {
    const char *p = xml;
    const char *end = xml + len;
    int depth = 0;

    while (p < end) {
        if (*p != '<') { 
            p++; 

            continue; 
        }

        if (p + 1 < end && (*(p+1) == '?' || *(p+1) == '!')) {
            const char *gt = (const char *)memchr(p, '>', end - p);

            if (!gt) {
                return -1;
            }

            p = gt + 1;

            continue;
        }

        if (p + 1 < end && *(p+1) == '/') {
            const char *gt = (const char *)memchr(p, '>', end - p);

            if (!gt) {
                return -1;
            }

            depth--;

            if (depth == 0) {
                return (int)((gt + 1) - xml);
            }

            p = gt + 1;

            continue;
        }

        const char *gt = (const char *)memchr(p, '>', end - p);

        if (!gt) {
            return -1;
        }

        if (*(gt-1) == '/') {
            if (depth == 0) {
                return (int)((gt + 1) - xml);
            }
        }
        else {
            depth++;
        }

        p = gt + 1;
    }

    return -1;
}

int find_stanza_end_dispatch(const char *xml, int len) {
    typedef int (*impl_t)(const char *, int);
    static impl_t impl = NULL;

    if (__builtin_expect(impl == NULL, 0)) {
        impl = cpu_has_sse42() ? find_stanza_end_sse : find_stanza_end_scalar;

        extern void serial_print(const char *);

        serial_print(impl == find_stanza_end_sse ? "[parser] sse4.2 vectorised stanza scan active\n" : "[parser] scalar stanza scan, no sse4.2)\n");
    }

    return impl(xml, len);
}

#else

int find_stanza_end_dispatch(const char *xml, int len) {
    const char *p = xml;
    const char *end = xml + len;
    int depth = 0;

    while (p < end) {
        if (*p != '<') { 
            p++; 
            
            continue; 
        }

        if (p + 1 < end && (*(p+1) == '?' || *(p+1) == '!')) {
            const char *gt = (const char *)(p + 1);

            while (gt < end && *gt != '>') {
                gt++;
            }

            if (gt >= end) {
                return -1;
            }

            p = gt + 1;

            continue;
        }

        if (p + 1 < end && *(p+1) == '/') {
            const char *gt = (const char *)(p + 1);

            while (gt < end && *gt != '>') {
                gt++;
            }

            if (gt >= end) {
                return -1;
            }

            depth--;

            if (depth == 0) {
                return (int)((gt + 1) - xml);
            }

            p = gt + 1;

            continue;
        }

        const char *gt = (const char *)(p + 1);

        while (gt < end && *gt != '>') {
            gt++;
        }

        if (gt >= end) {
            return -1;
        }

        if (*(gt-1) == '/') {
            if (depth == 0) {
                return (int)((gt + 1) - xml);
            }
        }
        else {
            depth++;
        }

        p = gt + 1;
    }

    return -1;
}

#endif