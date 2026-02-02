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

// --- 3. Protocol Settings ---
#define LWIP_ARP                1
#define LWIP_ETHERNET           1
#define LWIP_IP                 1
#define LWIP_TCP                1
#define LWIP_UDP                1
#define LWIP_ICMP               1
#define LWIP_DHCP               0  // We use static IP

// --- 4. Tuning ---
#define TCP_MSS                 1460
#define TCP_WND                 (4 * TCP_MSS)

// --- 5. Debugging (Disabled for Bare Metal stability) ---
#define LWIP_DEBUG              0 
#define LWIP_PLATFORM_DIAG(x)   do { } while(0)
#define LWIP_PLATFORM_ASSERT(x) do { } while(0)

// --- 6. CRITICAL FIX: Disable OS-dependent APIs ---
// These require threads/mutexes, which we don't have.
#define LWIP_NETCONN            0
#define LWIP_SOCKET             0
#define LWIP_DNS                0  // DNS often relies on sockets, safer to disable for now

#endif

// consider for some options
// https://lwip.fandom.com/wiki/LwIP_code_size 
// https://lwip.fandom.com/wiki/Maximizing_throughput
// https://lwip.fandom.com/wiki/Tuning_TCP
// https://lwip.fandom.com/wiki/LwIP_Application_Developers_Manual