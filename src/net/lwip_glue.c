#include <efi.h>
#include <efilib.h>
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "netif/ethernet.h"
#include "drivers/e1000.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h> // Add this to fix implicit memcpy

// Defined in libefi (gnu-efi)
//void *memcpy(void *dest, const void *src, size_t n);
// rename these to avoid conflicts with libefi/compiler builtins
// void *memcpy(void *dest, const void *src, size_t n) {
//     char *d = (char *)dest;
//     const char *s = (const char *)src;
//     while (n--) {
//         *d++ = *s++;
//     }
//     return dest;
// }

// void *memset(void *s, int c, size_t n) {
//     unsigned char *p = (unsigned char *)s;
//     while (n--) {
//         *p++ = (unsigned char)c;
//     }
//     return s;
// }

void serial_print(const char* str);

// 1. Implementation of abort()
// This prevents the "Invalid Opcode" crash by giving the CPU a valid loop to sit in.
// void abort(void) {
//     serial_print("\n[FATAL] lwIP called abort()! System Halted.\n");
//     while (1) {
//         __asm__ volatile("hlt");
//     }
// }

// // 2. Implementation of printf()
// // lwIP uses this to tell you WHY it is aborting (e.g., "pbuf_alloc failed").
// // We map it to your kernel's serial output.
// int printf(const char *fmt, ...) {
//     // Note: For a proper implementation, you would use vsnprintf.
//     // For now, we just print the format string to catch the error message.
//     serial_print("[LWIP MSG] ");
//     serial_print(fmt); 
//     // If your serial_print doesn't handle newlines automatically:
//     serial_print("\n");
//     return 0;
// }
// // 1. The missing function implementation
// int rand(void) {
//     static unsigned long next = 1;
//     next = next * 1103515245 + 12345;
//     return (unsigned int)(next / 65536) % 32768;
// }

// // 2. Sometimes lwIP expects 'srand' too, just in case:
// void srand(unsigned int seed) {
//     (void)seed; // We don't have storage for seed yet, or use a static variable if needed
// }
// this function must be defined for lwIP
uint32_t sys_now(void) {
    uint32_t a, d;
    // Read Time-Stamp Counter
    __asm__ volatile("rdtsc" : "=a" (a), "=d" (d));
    
    // 2GHz = 2,000,000 cycles per millisecond
    // Divide by 2,000,000 (approximate)
    return a / 2000000; 
}

int mpk_trampoline_3(void* func, uint64_t arg1, uint64_t arg2, uint64_t arg3);
static struct netif angelic_netif;
static uint64_t global_mmio_base;

static char rx_buffer[1514]; 
static char tx_buffer[1514];

static err_t low_level_output(struct netif *netif, struct pbuf *p) {
    (void)netif;
    struct pbuf *q;
    int len = 0;

    // Flatten pbuf chain into contiguous memory for the driver
    for(q = p; q != NULL; q = q->next) {
        if (len + q->len > 1514) {
            break;
        }

        memcpy(tx_buffer + len, q->payload, q->len);

        len += q->len;
    }

    #ifdef USE_MPK
        mpk_trampoline_3((void*)e1000_send_raw, global_mmio_base, (uint64_t)tx_buffer, (uint64_t)len);
    #else
        e1000_send_raw(global_mmio_base, (uint8_t*)tx_buffer, len);
    #endif

    return ERR_OK;
}

err_t angelic_netif_init(struct netif *netif) {
    netif->name[0] = 'e';
    netif->name[1] = '0';
    netif->output = etharp_output;
    netif->linkoutput = low_level_output;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

    return ERR_OK;
}

void angelic_netif_poll() {
    int len;

    #ifdef USE_MPK
        len = mpk_trampoline_3((void*)e1000_poll_receive, global_mmio_base, (uint64_t)rx_buffer, 1514);
    #else
        len = e1000_poll_receive(global_mmio_base, (uint8_t*)rx_buffer, 1514);
    #endif

    if (len > 0) {
        struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        if (p) {
            memcpy(p->payload, rx_buffer, len);
            
            if (angelic_netif.input(p, &angelic_netif) != ERR_OK) {
                pbuf_free(p);
            }
        }
    }
}

void init_network_stack(uint64_t mmio_base, uint8_t *mac) {
    global_mmio_base = mmio_base;
    
    ip4_addr_t ip, netmask, gw;
    
    IP4_ADDR(&ip, 10, 0, 2, 15);
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gw, 10, 0, 2, 2);
    
    serial_print("[DEBUG] Calling lwip_init()...\n");
    lwip_init();
    serial_print("[DEBUG] lwip_init() done.\n");

    //tcpip_init(tcpip_init_done, tcpip_init_done_param); 
    
    angelic_netif.hwaddr_len = 6;
    for(int i = 0; i < 6; i++) {
        angelic_netif.hwaddr[i] = mac[i];
    }

    serial_print("[DEBUG] Adding netif...\n");
    netif_add(&angelic_netif, &ip, &netmask, &gw, NULL, angelic_netif_init, ethernet_input);
    
    serial_print("[DEBUG] Setting default...\n");
    netif_set_default(&angelic_netif);
    
    serial_print("[DEBUG] Bringing interface up...\n");
    netif_set_up(&angelic_netif);

    // for(int i = 0; i < 6; i++) {
    //     angelic_netif.hwaddr[i] = mac[i];
    // }

    // angelic_netif.hwaddr_len = 6;
    
    serial_print("[DEBUG] Network Stack Initialized.\n");
}

// https://lwip.fandom.com/wiki/Writing_a_device_driver
// https://lwip.fandom.com/wiki/Guide:_integrating_baremetal_lwip_2.2_on_a_Cortex_M
// https://lwip.fandom.com/wiki/LwIP_Wiki

// 4.1.2 Example of TCP echo server demonstration