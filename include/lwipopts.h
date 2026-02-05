#ifndef LWIP_CUSTOM_LWIPOPTS_H
#define LWIP_CUSTOM_LWIPOPTS_H

// --- 1. System Settings ---
#define NO_SYS                  1  // Bare metal (no OS threads)
#define SYS_LIGHTWEIGHT_PROT    0  // No mutexes needed for single core
#define MEM_ALIGNMENT           4

// --- 2. Memory Settings ---
#define MEM_SIZE                (128 * 1024) // 128KB Heap
#define MEMP_NUM_PBUF           16
#define MEMP_NUM_TCP_PCB        16
#define PBUF_POOL_SIZE          32

#define MEMP_NUM_TCP_SEG        32

// --- 3. Protocol Settings ---
#define LWIP_ARP                1
#define LWIP_ETHERNET           1
#define LWIP_IPV4               1  // Explicitly enable IPv4
#define LWIP_TCP                1
#define LWIP_UDP                1
#define LWIP_ICMP               1
#define LWIP_DHCP               0  // Static IP

// --- 4. Tuning ---
#define TCP_MSS                 1460
#define TCP_WND                 (8 * TCP_MSS) // Increased to ~11KB for better speed
#define TCP_SND_BUF             (8 * TCP_MSS)

// #define LWIP_DEBUG LWIP_DBG_ON

// #define LWIP_DEBUG              0 
// #define LWIP_PLATFORM_DIAG(x)   do { } while(0)
// #define LWIP_PLATFORM_ASSERT(x) do { } while(0)

// --- 5. Checksums ---
// By default, lwIP calculates checksums in software. 
// Since we are debugging a new driver, keep software checksums ON to avoid hardware bugs.
#define CHECKSUM_GEN_IP         1
#define CHECKSUM_GEN_UDP        1
#define CHECKSUM_GEN_TCP        1
#define CHECKSUM_CHECK_IP       1
#define CHECKSUM_CHECK_UDP      1
#define CHECKSUM_CHECK_TCP      1

// --- 6. CRITICAL FIX: Disable OS-dependent APIs ---
// These require threads/mutexes, which we don't have.
#define LWIP_NETCONN            0
#define LWIP_SOCKET             0
#define LWIP_DNS                0 

// Note: LWIP_PLATFORM_DIAG and ASSERT are handled in cc.h
// Do NOT define them here, or you will hide error messages.

#endif

// consider for some options
// https://lwip.fandom.com/wiki/LwIP_code_size 
// https://lwip.fandom.com/wiki/Maximizing_throughput
// https://lwip.fandom.com/wiki/Tuning_TCP
// https://lwip.fandom.com/wiki/LwIP_Application_Developers_Manual
// https://lwip.fandom.com/wiki/Custom_memory_pools
// https://lwip.fandom.com/wiki/Lwipopts.h