#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>

// 1. Define Basic Types
typedef uint8_t     u8_t;
typedef int8_t      s8_t;
typedef uint16_t    u16_t;
typedef int16_t     s16_t;
typedef uint32_t    u32_t;
typedef int32_t     s32_t;
//typedef uint64_t    u64_t;
typedef uintptr_t   mem_ptr_t;

//#define BYTE_ORDER  LITTLE_ENDIAN

#define U16_F "u" //hu
#define S16_F "d" //hd
#define X16_F "x" //hx
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "u" 

#define PACK_STRUCT_FIELD(x) x
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

// extern void* memcpy(void* dest, const void* src, size_t n);
// extern void* memset(void* s, int c, size_t n);
// extern void serial_print(const char* str);

// #define MEMCPY(dst,src,len) memcpy(dst,src,len)
// #define SMEMCPY(dst,src,len) memcpy(dst,src,len)
// #define MEMSET(dst,val,len) memset(dst,val,len)

// #define LWIP_PLATFORM_DIAG(x) do { /*serial_printf x; */ } while(0) 

#define LWIP_PLATFORM_ASSERT(x) do { serial_print("\n[LWIP FATAL]: "); serial_print(x); while(1); } while(0)

#endif /* LWIP_ARCH_CC_H */