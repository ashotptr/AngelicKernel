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
// MEMP_NUM_TCP_PCB_LISTEN
// PBUF_POOL_BUFSIZE

// --- 4. Tuning ---
#define TCP_MSS                 1460
#define TCP_WND                 (8 * TCP_MSS) // Increased to ~11KB for better speed
#define TCP_SND_BUF             (8 * TCP_MSS)

// TCP_SND_QUEUELEN

// --- 3. Protocol Settings ---
#define LWIP_ARP                1
#define LWIP_ETHERNET           1
#define LWIP_IPV4               1  // Explicitly enable IPv4
#define LWIP_TCP                1
#define LWIP_UDP                1
#define LWIP_ICMP               1
#define LWIP_DHCP               0  // Static IP

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

// Disable OS-dependent APIs ---
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

// Table 7. LwIP memory configuration
// LwIP memory option Definition
// MEM_SIZE LwIP heap memory size: used for all LwIP dynamic memory
// allocations.
// MEMP_NUM_PBUF Total number of MEM_REF and MEM_ROM pbufs.
// MEMP_NUM_UDP_PCB Total number of UDP PCB structures.
// MEMP_NUM_TCP_PCB Total number of TCP PCB structures.
// MEMP_NUM_TCP_PCB_LISTEN Total number of listening TCP PCBs.
// MEMP_NUM_TCP_SEG Maximum number of simultaneously queued TCP segments.
// PBUF_POOL_SIZE Total number of PBUF_POOL type pbufs.
// PBUF_POOL_BUFSIZE Size of a PBUF_POOL type pbufs.
// TCP_MSS TCP maximum segment size.
// TCP_SND_BUF TCP send buffer space for a connection.
// TCP_SND_QUEUELEN Maximum number of pbufs in the TCP send queue.
// TCP_WND Advertised TCP receive window size.