#include <efi.h>
#include <efilib.h>
#include "drivers/e1000.h"
#include "drivers/pci.h"
#include "drivers/disk.h"
#include "net/lwip_glue.h"
#include "lwip/init.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "mm/pmm.h" 
#include "mm/vmm.h"
#include "sys/mpk_gate.h"
#include "xmpp/xmpp_core.h"

// address is arbitrary, but safe in QEMU
// #define GDB_MAGIC_ADDR  0x10000 
// #define GDB_INFO_ADDR   0x10008
// #define MAGIC_SIGNATURE 0xDEADBEEF

extern volatile int packet_pending;

uint64_t global_mmio_base = 0;

extern void mpk_enable();
extern void vmm_protect_driver();
extern void mpk_set_pkru(uint32_t pkru_val);
extern void mpk_diagnostic(void);
extern void mpk_benchmark(void);

void xmpp_init_server();

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

static int cpu_has_pku(void) {
    uint32_t ecx = 0;

    __asm__ volatile(
        "cpuid"
        : "=c"(ecx)
        : "a"(7), "c"(0)
        : "ebx", "edx"
    );

    return (ecx >> 3) & 1;  /* CPUID.(EAX=7,ECX=0):ECX.PKU = bit 3 */
}

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

void serial_print_mac(uint8_t *mac) {
    const char hex[] = "0123456789ABCDEF";

    for (int i = 0; i < 6; i++) {
        char buf[3] = { hex[(mac[i] >> 4) & 0xF], hex[mac[i] & 0xF], '\0' };
        
        serial_print(buf);
        
        if (i < 5) {
            serial_print(":");
        } 
    }

    serial_print("\n");
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

    // if (!cpu_has_pku()) {
    //     serial_print("[FATAL] CPU does not support Intel MPK (PKU). Halting.\n");

    //     while(1) __asm__ volatile("hlt");
    // }
    
    uint64_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    if (cr4 & (1UL << 20)) {
        serial_print("[MPK] WARNING: SMEP active — code pages cannot be user-mode\n");
    }
    else {
        serial_print("[MPK] INFO: SMEP is disabled. Safe to mark code as user-mode.\n");
    }

    mpk_enable();           /* CR4.PKE = 1 */
    
    init_idt();
    
    //e1000_init(global_mmio_base, mac);
    mpk_e1000_init(global_mmio_base, mac);
    
    /* Initialise the storage backend.
     * disk_init() tries AHCI first (PCI scan), then falls back to ATA PIO
     * on the primary IDE channel (0x1F0).  Either way it prints the drive
     * model / backend choice to the serial console.  The selected backend
     * is then used transparently by xmpp_persist_load_all(). */
    disk_init();
    
    serial_print("MAC Address: ");

    for (int i = 0; i < 6; i++) {
        serial_print_hex(mac[i]);

        if (i < 5) {
            serial_print(":");
        }
    }

    serial_print("\n");
    
    serial_print_mac(mac);

    serial_print("\n");

    serial_print("--- DEBUG INFO ---\n");
    serial_print("Function 'init_network_stack' is at: ");
    serial_print_hex((uint64_t)&init_network_stack); 
    serial_print("\n------------------\n");

    serial_print("[DEBUG] Waiting for GDB... Attach now!\n");
    volatile int debug_wait = 0;
    while (debug_wait) {
        __asm__ volatile("pause");
    }

    init_network_stack(global_mmio_base, mac);
    
    /*
     * ── MPK Isolation Activation ──────────────────────────────────────
     *
     * Order matters:
     *   (a) mpk_enable()        — set CR4.PKE so WRPKRU/RDPKRU are legal
     *   (b) vmm_protect_driver() — tag Key 1 onto driver code+data PTEs
     *   (c) mpk_set_pkru(0x0C)  — activate restriction in the CPU
     *
     * Why (c) must come AFTER (b):
     *   If we set PKRU = 0x0C before the PTEs carry Key 1, the kernel
     *   tries to read/write pages that have key 0 in their PTEs — those
     *   are NOT restricted, so PKRU = 0x0C has no effect yet.  Setting
     *   PKRU before tagging means there is a window where the driver code
     *   is callable without the trampoline.  The reverse (tag first, then
     *   restrict) is always safe because tagging with no PKRU restriction
     *   is a no-op.
     *
     * Why (c) must come BEFORE any direct driver calls:
     *   After mpk_set_pkru(0x0C), any direct call to an e1000 function
     *   (without the trampoline) will fault.  All call sites in kernel.c
     *   and lwip_glue.c must have been converted to mpk_e1000_*() before
     *   this line is reached.
     *
     * PKRU value 0x0000000C:
     *   bits [3:2] = 0b11 → Key 1: AD=1 (Access Disable), WD=1 (Write Disable)
     *   bits [1:0] = 0b00 → Key 0: AD=0, WD=0  (kernel has full access)
     *   All other keys default to 0 (accessible).
     *
     * Intel SDM Vol. 3A §4.6.2 — Protection Keys
     * Intel SDM Vol. 2B — WRPKRU, RDPKRU
     */
    vmm_protect_driver();   /* PTE bits [62:59] = 1 for all driver pages */
    mpk_set_pkru(0x0000000C); /* PKRU: Key 1 inaccessible to kernel      */

    serial_print("[MPK] Isolation ACTIVE. Driver domain locked to Key 1.\n");
    mpk_diagnostic();   // prints verification report to serial
    mpk_benchmark(); 
    // Enable Interrupts globally
    __asm__ volatile("sti");

    serial_print("[KERNEL] Interrupts Enabled.\n");
    
    serial_print("[XMPP] Starting MUC Server on Port 5222...\n");

    xmpp_init_server();

    // Flag to track if we should sleep
    // Set this to 0 if don't have a PIT/LAPIC timer yet!
    int use_interrupt_sleeping = 0; 
    (void)use_interrupt_sleeping;

    while (1) {
        /* Clear packet_pending BEFORE polling the NIC.
         * Because e1000 interrupts can fire
         * at any point during the burst (interrupts are enabled), the IRQ
         * handler could set packet_pending = 1 again mid-burst.  The main
         * loop would then immediately start another burst, feeding the same
         * partially-processed TCP segment to lwIP a second time.  lwIP's
         * tcp_input() detected this as a corrupt PCB list and asserted:
         *
         *   LWIP ASSERT: tcp_input: pcb->next != pcb (before cache)
         *
         * (snapshot-and-drain pattern):
         *   1. Atomically clear packet_pending first.
         *   2. Then poll the NIC.
         *
         * If a new interrupt fires AFTER the clear but BEFORE the first
         * poll, packet_pending becomes 1 again and the next loop iteration
         * handles it — this is safe.  If it fires DURING polling, the same
         * applies: we pick it up next iteration.  No data is lost and no
         * double-processing occurs.
         */
        if (packet_pending) {
            packet_pending = 0;  /* clear FIRST — then drain */

            // Loop this a few times to drain the hardware buffer.
            // Since angelic_netif_poll() returns void, we blindly call it 
            // a few times. 4 is usually enough to clear a burst.
            for(int i = 0; i < 4; i++) {
                angelic_netif_poll();
            }
        }

        /* Retry any TLS handshakes that stalled on WANT_WRITE */
        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb != NULL &&
                client_registry[i].state == STATE_STARTTLS &&
                client_registry[i].tls_want_write) {
                xmpp_tls_handshake_step(&client_registry[i], NULL, 0);
            }
        }

        /* Flush deferred SM ack requests (Bug fix #4 — anti-recursion).
         * xmpp_sm_on_stanza_sent sets sm_want_ack instead of calling
         * xmpp_sm_request_ack directly (which would re-enter send_raw).
         * We drain those here, safely outside any send_raw call stack. */
        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb != NULL &&
                client_registry[i].sm_want_ack) {
                client_registry[i].sm_want_ack = 0;
                xmpp_sm_request_ack(&client_registry[i]);
            }
        }

        sys_check_timeouts();
    }

    return EFI_SUCCESS;
}