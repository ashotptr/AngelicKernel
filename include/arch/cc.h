#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>

// 1. Define Basic Types
typedef uint8_t     u8_t;
typedef int8_t      s8_t;
typedef uint16_t    u16_t;
typedef int16_t     s16_t;
typedef uint32_t    u32_t;
typedef int32_t     s32_t;
typedef uintptr_t   mem_ptr_t;

// 2. Define Print Formatters
#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"

// 3. Define Compiler Hints
#define PACK_STRUCT_FIELD(x) x
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

// 4. Debugging Macros (Map these to your UEFI Print function later)
// #define LWIP_PLATFORM_DIAG(x) do { /* TODO: Add UEFI Print here */ } while(0)
#define LWIP_PLATFORM_ASSERT(x) do { /* TODO: Add Panic loop */ } while(0)

#endif /* LWIP_ARCH_CC_H */