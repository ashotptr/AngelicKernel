#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>

/* 1. Basic Types */
typedef uint8_t   u8_t;
typedef int8_t    s8_t;
typedef uint16_t  u16_t;
typedef int16_t   s16_t;
typedef uint32_t  u32_t;
typedef int32_t   s32_t;
//typedef uint64_t u64_t;
typedef uintptr_t mem_ptr_t;

/* 2. Endianness (CRITICAL for x86_64) */
#ifndef BYTE_ORDER
#define BYTE_ORDER  LITTLE_ENDIAN
#endif

/* 3. Printf Formatters */
#define U16_F "u" //hu
#define S16_F "d" //hd
#define X16_F "x" //hx
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "u"

/* 4. Compiler Hints for Packing Structures */
/* This ensures network headers fit exactly into bytes without padding */
#define PACK_STRUCT_FIELD(x)    x
#define PACK_STRUCT_STRUCT      __attribute__((packed))
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

/* 5. Random Number Generator */
/* TCP needs this for sequence numbers. 
   If you have a timer, use it: #define LWIP_RAND() ((u32_t)get_timer_ticks()) 
   For now, a simple counter or constant allows compilation, but is not secure. */
extern u32_t get_ticks(void); // Ensure this exists in your kernel or use a dummy for now
#define LWIP_RAND() ((u32_t)get_ticks())

/* 6. Diagnostics & Logging */
/* Map to your serial output function */
extern void serial_print(const char *str); // Ensure this matches your kernel API

// Optional: If you implement a full printf, use this:
// #define LWIP_PLATFORM_DIAG(x) do { kprintf x; } while(0)
// For now, valid to leave empty if you don't want debug spam:
#define LWIP_PLATFORM_DIAG(x) do { } while(0)

/* Fatal Error Handler - Hangs the kernel so you can see the error */
#define LWIP_PLATFORM_ASSERT(x) do { \
    serial_print("\n[LWIP FATAL]: "); \
    serial_print(x); \
    while(1); \
} while(0)

#endif /* LWIP_ARCH_CC_H */