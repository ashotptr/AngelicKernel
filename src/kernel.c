#include <efi.h>
#include <efilib.h>
#include "drivers/e1000.h"
#include "drivers/pci.h"
#include "net/lwip_glue.h"
#include "lwip/init.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "drivers/framebuffer.h" 
#include "mm/pmm.h" 
#include "mm/vmm.h"

// Add externs
extern void mpk_enable();
extern void vmm_protect_driver();
// --- NEW PROTOTYPE ---
void init_idt(); 

// --- SERIAL PORT DRIVER ---
static inline void outb(UINT16 port, UINT8 val) {
    __asm__ volatile ( "outb %0, %1" : : "a"(val), "Nd"(port) );
}

static inline UINT8 inb(UINT16 port) {
    UINT8 ret;
    __asm__ volatile ( "inb %1, %0" : "=a"(ret) : "Nd"(port) );
    return ret;
}

void serial_putc(char c) {
    while ((inb(0x3F8 + 5) & 0x20) == 0); 
    outb(0x3F8, c);
}

void serial_print(const char* str) {
    for (int i = 0; str[i] != '\0'; i++) {
        serial_putc(str[i]);
    }
}

// --- NETWORK CALLBACKS ---
const char RESPONSE[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                        "<html><body><h1>Hello from AngelicKernel!</h1>"
                        "<p>Phase 3 Complete: Drivers & Interrupts Active.</p></body></html>";

err_t http_sent_callback(void *arg, struct tcp_pcb *pcb, u16_t len) {
    (void)arg; (void)len;
    tcp_close(pcb);
    return ERR_OK;
}

err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg; (void)err; 
    if (!p) {
        tcp_close(pcb);
        return ERR_OK;
    }
    tcp_recved(pcb, p->tot_len);
    tcp_write(pcb, RESPONSE, sizeof(RESPONSE) - 1, TCP_WRITE_FLAG_COPY);
    tcp_sent(pcb, http_sent_callback);
    tcp_output(pcb);
    pbuf_free(p);
    return ERR_OK;
}

static err_t http_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg; (void)err;
    tcp_recv(newpcb, http_recv);
    return ERR_OK;
}

void start_http_server() {
    struct tcp_pcb *pcb = tcp_new();
    if (!pcb) {
        serial_print("[ERROR] Failed to create TCP PCB\n");
        return;
    }

    // Bind to 0.0.0.0 (All interfaces) on Port 80
    err_t err = tcp_bind(pcb, IP_ADDR_ANY, 80);
    if (err != ERR_OK) {
        serial_print("[ERROR] Failed to bind to Port 80\n");
        return;
    }

    // Put into listening mode
    pcb = tcp_listen(pcb);
    
    // Register the callback we wrote earlier
    tcp_accept(pcb, http_accept_callback);
    
    serial_print("[INFO] HTTP Server started on Port 80\n");
}

// --- UTILS ---
void serial_print_hex(uint64_t n) {
    char hex[] = "0123456789ABCDEF";
    char buf[19];
    buf[18] = 0;
    for (int i = 17; i >= 0; i--) { 
        buf[i] = hex[n % 16];
        n /= 16;
    }
    serial_print("0x"); 
    serial_print(buf);
}

void serial_init() {
    outb(0x3F8 + 1, 0x00);    
    outb(0x3F8 + 3, 0x80);    
    outb(0x3F8 + 0, 0x03);    
    outb(0x3F8 + 1, 0x00);    
    outb(0x3F8 + 3, 0x03);    
    outb(0x3F8 + 2, 0xC7);    
    outb(0x3F8 + 4, 0x0B);    
}

// --- MAIN KERNEL ---
EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);
    
    Print(L"AngelicKernel Phase 1: Preparing for Exodus...\n");
    
    uint64_t mmio_base = pci_get_bar(0x8086, 0x100E);
    if (mmio_base == 0) {
        Print(L"[WARNING] e1000 Card not found (Check QEMU flags)\n");
    } else {
        Print(L"[SUCCESS] e1000 MMIO found at 0x%lx\n", mmio_base);
    }

    Print(L"Exiting Firmware in 1s...\n");
    SystemTable->BootServices->Stall(1000000); 

    UINTN MapSize = 0, MapKey, DescriptorSize;
    UINT32 DescriptorVersion;
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    
    SystemTable->BootServices->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    MapSize += 2 * DescriptorSize;
    SystemTable->BootServices->AllocatePool(EfiLoaderData, MapSize, (void**)&MemoryMap);
    SystemTable->BootServices->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);

    SystemTable->BootServices->ExitBootServices(ImageHandle, MapKey);

    // =========================================================
    //   BARE METAL ZONE
    // =========================================================

    serial_init();
    serial_print("\n\n=== ANGELIC KERNEL (BARE METAL) ===\n");

    // Phase 2: Memory
    pmm_init(MemoryMap, MapSize, DescriptorSize);
    vmm_init(); 

    // Phase 3 Part 2: Interrupts (NEW)
    init_idt();

    /* TEST CRASH (Uncomment to verify IDT works)
       int* bad = (int*)0xDEADBEEF;
       *bad = 10;
    */

    // Phase 3 Part 1: Network
    uint8_t mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56}; 
    init_network_stack(mmio_base, mac);
    mpk_enable();           // Turn on the hardware feature
    vmm_protect_driver();   // Tag the pages
    // <--- ADD THIS LINE --->
    start_http_server();

    serial_print("[KERNEL] Network Online. Listening on Port 80...\n");

    while (1) {
        angelic_netif_poll();
        sys_check_timeouts();
    }

    return EFI_SUCCESS;
}