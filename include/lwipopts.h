#ifndef LWIP_HDR_LWIPOPTS_H
#define LWIP_HDR_LWIPOPTS_H

// 1. CRITICAL: Tell lwIP we are a Unikernel (No OS threads)
#define NO_SYS                      1
#define SYS_LIGHTWEIGHT_PROT        0 
#define LWIP_NETCONN                0 
#define LWIP_SOCKET                 0 

// 2. Memory Settings (Allocate 128KB for network buffer)
#define MEM_ALIGNMENT               4
#define MEM_SIZE                    (128 * 1024) 
#define PBUF_POOL_SIZE              16
#define MEMP_NUM_PBUF               16
#define MEMP_NUM_TCP_SEG            16

// 3. Protocol Settings
#define LWIP_IPV4                   1
#define LWIP_TCP                    1
#define LWIP_UDP                    1
#define TCP_MSS                     1460
#define TCP_WND                     (4 * TCP_MSS)

// 4. Debugging (Enable this to see why it hangs if it fails again)
#define LWIP_DEBUG                  1
#define LWIP_PLATFORM_DIAG(x)       do { Print(L"%a", x); } while(0)

#endif