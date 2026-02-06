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

// address is arbitrary, but safe in QEMU
// #define GDB_MAGIC_ADDR  0x10000 
// #define GDB_INFO_ADDR   0x10008
// #define MAGIC_SIGNATURE 0xDEADBEEF

uint64_t global_mmio_base = 0;

extern void mpk_enable();
extern void vmm_protect_driver();

void init_idt();

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

// Put this helper function at the top of src/kernel.c
static void enable_sse(void) {
    uint64_t cr0, cr4;

    // 1. Read CR0
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    
    // 2. Clear EM (Bit 2) - Emulation
    cr0 &= ~(1UL << 2); 
    // 3. Set MP (Bit 1) - Monitor Coprocessor
    cr0 |= (1UL << 1);  
    
    // 4. Write back CR0
    __asm__ volatile("mov %0, %%cr0" :: "r"(cr0));

    // 5. Read CR4
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    
    // 6. Set OSFXSR (Bit 9) - OS Support for FXSAVE/FXRSTOR
    cr4 |= (1UL << 9);  
    // 7. Set OSXMMEXCPT (Bit 10) - OS Support for Unmasked SIMD Float Exceptions
    cr4 |= (1UL << 10); 
    
    // 8. Write back CR4
    __asm__ volatile("mov %0, %%cr4" :: "r"(cr4));
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
    outb(0x3F8 + 1, 0x00);    //0x3F8 for COM1, might need to check if correct address
    outb(0x3F8 + 3, 0x80);
    outb(0x3F8 + 0, 0x03);
    outb(0x3F8 + 1, 0x00);
    outb(0x3F8 + 3, 0x03);
    outb(0x3F8 + 2, 0xC7);
    outb(0x3F8 + 4, 0x0B);
}

//EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) { //Microsoft ABI
EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    //SystemTable->BootServices->SetWatchdogTimer(0, 0, 0, NULL);

    InitializeLib(ImageHandle, SystemTable);
    
    // gdb marker for debugging
    // EFI_LOADED_IMAGE *loaded_image = NULL;
    // EFI_GUID loaded_image_protocol = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    
    // SystemTable->BootServices->HandleProtocol(ImageHandle, &loaded_image_protocol, (void**)&loaded_image);

    // volatile uint64_t *marker = (uint64_t*)GDB_MAGIC_ADDR;
    // volatile uint64_t *base   = (uint64_t*)GDB_INFO_ADDR;
    
    // *base = (uint64_t)loaded_image->ImageBase; 
    // *marker = MAGIC_SIGNATURE; 

    // Print(L"[DEBUG] GDB Marker Set. Base: 0x%lx\n", (uint64_t)loaded_image->ImageBase);
    
    // 2. ENABLE SSE IMMEDIATELY (Before PMM, VMM, or LwIP)
    enable_sse();

    Print(L"AngelicKernel Phase 1: Preparing for Exodus...\n");
    
    global_mmio_base = pci_get_bar(0x8086, 0x100E);
    
    if (global_mmio_base == 0) {
        Print(L"[WARNING] e1000 Card not found\n");
    }
    else {
        Print(L"[SUCCESS] e1000 MMIO found at 0x%lx\n", global_mmio_base);
    }

    uint8_t mac[6] = {0, 0, 0, 0, 0, 0};

    Print(L"Exiting Firmware in 1s...\n");

    SystemTable->BootServices->Stall(1000000); //uefi_call_wrapper not needed

    EFI_STATUS Status;
    UINTN MapSize = 0, MapKey, DescriptorSize;
    UINT32 DescriptorVersion;
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;

    Status = SystemTable->BootServices->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    
    MapSize += 2 * DescriptorSize;
    
    Status = SystemTable->BootServices->AllocatePool(EfiLoaderData, MapSize, (void**)&MemoryMap);
    
    if (EFI_ERROR(Status)) {
        return Status;
    }

    Status = SystemTable->BootServices->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    
    if (EFI_ERROR(Status)) {
        return Status;
    }

    Status = SystemTable->BootServices->ExitBootServices(ImageHandle, MapKey);
    
    if (EFI_ERROR(Status)) {
        Status = SystemTable->BootServices->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
        
        if (!EFI_ERROR(Status)) {
            Status = SystemTable->BootServices->ExitBootServices(ImageHandle, MapKey);
        }
    }

    if (EFI_ERROR(Status)) {
        while(1); 
    }

    serial_init();
    serial_print("\n\n=== ANGELIC KERNEL (BARE METAL) ===\n");

    pmm_init(MemoryMap, MapSize, DescriptorSize);
    vmm_init(); 

    init_idt();
    
    e1000_init(global_mmio_base, mac);
    
    serial_print("MAC Address: ");

    for (int i = 0; i < 6; i++) {
        serial_print_hex(mac[i]);

        if (i < 5) {
            serial_print(":");
        }
    }
    
    serial_print("\n");

    // --- NEW DEBUG INFO ---
    serial_print("--- DEBUG INFO ---\n");
    serial_print("Function 'init_network_stack' is at: ");
    serial_print_hex((uint64_t)&init_network_stack); 
    serial_print("\n------------------\n");
    // ----------------------

    // ==========================================================
    // [DEBUG TRAP] Pauses execution so you can attach GDB safely
    // ==========================================================
    serial_print("[DEBUG] Waiting for GDB... Attach now!\n");
    volatile int debug_wait = 0;
    while (debug_wait) {
        __asm__ volatile("pause");
    }
    // ==========================================================

    init_network_stack(global_mmio_base, mac);
    
    // Phase 4 Preparation (MPK)
    // Only enable these if you are 100% sure the VMM setup is perfect
    // mpk_enable();           
    // vmm_protect_driver();   
    
    // Enable Interrupts globally
    __asm__ volatile("sti");
    serial_print("[KERNEL] Interrupts Enabled.\n");

    start_http_server();

    serial_print("[KERNEL] Network Online. Listening on Port 80...\n");

    // Flag to track if we should sleep
    // Set this to 0 if you don't have a PIT/LAPIC timer yet!
    int use_interrupt_sleeping = 0; 

    while (1) {
        angelic_netif_poll();
        
        sys_check_timeouts();
        
        if (use_interrupt_sleeping) {
             // ONLY enable this if you have a PIT/LAPIC timer firing every ~10ms.
             // Otherwise, TCP timers will freeze until a packet arrives.
             __asm__ volatile("hlt");
        }
        else {
             // Busy wait (High CPU usage, but guarantees TCP timers work)
             __asm__ volatile("pause"); 
        }
    }

    return EFI_SUCCESS;
}