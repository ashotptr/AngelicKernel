#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

// CRITICAL: Tell lwIP we have no OS (no threads, no semaphores)
#define NO_SYS                  1
#define LWIP_TIMERS             1  // We still need timers for TCP timeouts

// Memory Management (Static allocation for Unikernel speed)
#define MEM_LIBC_MALLOC         0
#define MEMP_MEM_MALLOC         0
#define MEM_ALIGNMENT           4
#define MEM_SIZE                (16 * 1024) // Give it 16KB of RAM initially

// Disable high-level APIs (We use raw callbacks for max performance)
#define LWIP_SOCKET             0
#define LWIP_NETCONN            0

// Protocol Support
#define LWIP_TCP                1
#define LWIP_UDP                1
#define LWIP_ICMP               1  // Allow "ping"

// Debugging (Turn these off later for speed)
#define LWIP_DEBUG              1
#define TCP_DEBUG               LWIP_DBG_ON

#endif /* LWIP_LWIPOPTS_H */