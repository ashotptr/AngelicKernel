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

/* 2. Endianness */
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
extern u32_t sys_now(void); 
#define LWIP_RAND() sys_now()

/* 6. Diagnostics & Logging */
extern int printf(const char *fmt, ...);

#define LWIP_PLATFORM_DIAG(x) do { printf x; } while(0)

extern void serial_print(const char *str);

#define LWIP_PLATFORM_ASSERT(x) do { \
    serial_print("\n[LWIP ASSERT]: "); \
    serial_print(x); \
    serial_print("\n"); \
    while(1); \
} while(0)

#endif /* LWIP_ARCH_CC_H */