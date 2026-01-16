#include <efi.h>
#include <efilib.h>
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "netif/ethernet.h"
#include "drivers/e1000.h"

// --- FIX 1: Add Prototypes so the compiler is happy ---
#include <stddef.h> // for size_t

// Defined in libefi (gnu-efi)
void *memcpy(void *dest, const void *src, size_t n);

// Defined in kernel.c
void serial_print(const char* str);
// -----------------------------------------------------

// ---------------------------------------------------------
// RUNTIME IMPLEMENTATION
// ---------------------------------------------------------

// lwIP needs a time source (in milliseconds)
uint32_t sys_now(void) {
    uint32_t a, d;
    // Read Time-Stamp Counter
    __asm__ volatile("rdtsc" : "=a" (a), "=d" (d));
    // Approximate conversion to ms (assuming ~2GHz CPU freq for QEMU)
    return a / 2000;
}

// ---------------------------------------------------------
// NETWORK GLUE
// ---------------------------------------------------------

static struct netif angelic_netif;
static uint64_t global_mmio_base;

static err_t low_level_output(struct netif *netif, struct pbuf *p) {
    (void)netif;
    struct pbuf *q;
    char buffer[1514];
    int len = 0;

    for(q = p; q != NULL; q = q->next) {
        // memcpy is now properly declared above
        memcpy(buffer + len, q->payload, q->len);
        len += q->len;
    }

    e1000_send_raw(global_mmio_base, buffer, len);
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
    char buffer[1514];
    int len = e1000_poll_receive(global_mmio_base, buffer, 1514);
    
    if (len > 0) {
        struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        if (p) {
            memcpy(p->payload, buffer, len);
            if (angelic_netif.input(p, &angelic_netif) != ERR_OK) {
                pbuf_free(p);
            }
        }
    }
}

void init_network_stack(uint64_t mmio_base, uint8_t *mac) {
    global_mmio_base = mmio_base;
    
    // --- FIX 2: Removed 'L' prefix. Use standard ASCII strings for bare metal. ---
    serial_print("[DEBUG] Calling lwip_init()...\n");
    lwip_init();
    serial_print("[DEBUG] lwip_init() done.\n");
    
    ip4_addr_t ip, netmask, gw;
    
    // QEMU Default User Network Settings
    IP4_ADDR(&ip, 10, 0, 2, 15);        // Standard Guest IP
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gw, 10, 0, 2, 2);         // Standard Gateway

    serial_print("[DEBUG] Adding netif...\n");
    netif_add(&angelic_netif, &ip, &netmask, &gw, NULL, angelic_netif_init, ethernet_input);
    
    serial_print("[DEBUG] Setting default...\n");
    netif_set_default(&angelic_netif);
    
    serial_print("[DEBUG] Bringing interface up...\n");
    netif_set_up(&angelic_netif);
    
    for(int i=0; i<6; i++) angelic_netif.hwaddr[i] = mac[i];
    angelic_netif.hwaddr_len = 6;
    
    serial_print("[DEBUG] Network Stack Initialized.\n");
}