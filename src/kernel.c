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

    return (ecx >> 3) & 1;
}

static void enable_sse(void) {
    uint64_t cr0, cr4;

    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    
    cr0 &= ~(1UL << 2);

    cr0 |= (1UL << 1);  
    
    __asm__ volatile("mov %0, %%cr0" :: "r"(cr0));

    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    
    cr4 |= (1UL << 9);
    
    cr4 |= (1UL << 10); 
    
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
    outb(0x3F8 + 1, 0x00);
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
    
    enable_sse();
    
    Print(L"preparing for exit from firmware\n");

    uint16_t nic_did = 0;
    global_mmio_base = pci_find_nic(&nic_did);

    if (global_mmio_base == 0) {
        Print(L"[warning] no supported nic found\n");
    }
    else {
        Print(L"[success] nic 8086:%04x mmio at 0x%lx\n", (UINTN)nic_did, global_mmio_base);
    }

    uint8_t mac[6] = {0, 0, 0, 0, 0, 0};

    Print(L"exiting firmware\n");

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

    serial_print("\n\n angelic kernel \n");

    pmm_init(MemoryMap, MapSize, DescriptorSize);
    vmm_init();

    // if (!cpu_has_pku()) {
    //     serial_print("[FATAL] CPU does not support Intel MPK (PKU). Halting.\n");

    //     while(1) __asm__ volatile("hlt");
    // }
    
    uint64_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));

    if (cr4 & (1UL << 20)) {
        serial_print("[mpk] warning: smep is active\n");
    }
    else {
        serial_print("[mpk] info: smep is disabled\n");
    }

    mpk_enable();
    
    init_idt();
    
    mpk_e1000_init(global_mmio_base, mac);
    
    disk_init();
    
    serial_print("mac address: ");

    for (int i = 0; i < 6; i++) {
        serial_print_hex(mac[i]);

        if (i < 5) {
            serial_print(":");
        }
    }

    serial_print("\n");
    
    serial_print_mac(mac);

    serial_print("\n");

    volatile int debug_wait = 0;

    while (debug_wait) {
        __asm__ volatile("pause");
    }

    init_network_stack(global_mmio_base, mac);

    vmm_protect_driver();
    mpk_set_pkru(0x0000000C);

    serial_print("[mpk] isolation active\n");

    mpk_diagnostic();
    mpk_benchmark();
    
    __asm__ volatile("sti");

    serial_print("[kernel] interrupts enabled\n");
    
    serial_print("[xmpp] starting server on port 5222\n");

    xmpp_init_server();

    int use_interrupt_sleeping = 0; 
    (void)use_interrupt_sleeping;

    while (1) {
        if (packet_pending) {
            packet_pending = 0;

            for(int i = 0; i < 4; i++) {
                angelic_netif_poll();
            }
        }

        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb != NULL && client_registry[i].state == STATE_STARTTLS && client_registry[i].tls_want_write) {
                xmpp_tls_handshake_step(&client_registry[i], NULL, 0);
            }
        }

        for (int i = 0; i < MAX_USERS; i++) {
            if (client_registry[i].pcb != NULL && client_registry[i].sm_want_ack) {
                client_registry[i].sm_want_ack = 0;

                xmpp_sm_request_ack(&client_registry[i]);
            }
        }

        sys_check_timeouts();
    }

    return EFI_SUCCESS;
}