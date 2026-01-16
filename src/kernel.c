#include <efi.h>
#include <efilib.h>
#include "drivers/e1000.h"
#include "drivers/pci.h"
#include "net/lwip_glue.h"
#include "lwip/init.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "drivers/framebuffer.h" // <--- ADD THIS
#include "mm/pmm.h" // Add this
#include "mm/vmm.h"

// --- SERIAL PORT DRIVER (The "Server" way) ---
static inline void outb(UINT16 port, UINT8 val) {
    __asm__ volatile ( "outb %0, %1" : : "a"(val), "Nd"(port) );
}

static inline UINT8 inb(UINT16 port) {
    UINT8 ret;
    __asm__ volatile ( "inb %1, %0" : "=a"(ret) : "Nd"(port) );
    return ret;
}

void serial_putc(char c) {
    while ((inb(0x3F8 + 5) & 0x20) == 0); // Wait for transmit empty
    outb(0x3F8, c);
}

void serial_print(const char* str) {
    for (int i = 0; str[i] != '\0'; i++) {
        serial_putc(str[i]);
    }
}

// Calculate length automatically to avoid buffer errors
const char RESPONSE[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                        "<html><body><h1>Hello from AngelicKernel!</h1>"
                        "<p>Phase 1 Complete: Networking is Live.</p></body></html>";

// ---------------------------------------------------------
// CALLBACK: Called when data has been successfully sent (ACKed)
// ---------------------------------------------------------
err_t http_sent_callback(void *arg, struct tcp_pcb *pcb, u16_t len) {
    (void)arg; (void)len;
    // The client got the data. NOW we can close.
    tcp_close(pcb);
    return ERR_OK;
}

// ---------------------------------------------------------
// CALLBACK: Called when data arrives
// ---------------------------------------------------------
err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg; (void)err; // Silence unused parameter warnings

    if (!p) {
        // Client closed connection
        tcp_close(pcb);
        return ERR_OK;
    }

    // 1. Notify lwIP we received the bytes
    tcp_recved(pcb, p->tot_len);
    
    // 2. Queue the response
    // Use sizeof(RESPONSE)-1 to exclude the null terminator
    tcp_write(pcb, RESPONSE, sizeof(RESPONSE) - 1, TCP_WRITE_FLAG_COPY);
    
    // 3. Register the close callback (The Fix)
    tcp_sent(pcb, http_sent_callback);
    
    // 4. Flush output
    tcp_output(pcb);
    
    pbuf_free(p);
    return ERR_OK;
}

static err_t http_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg; (void)err;
    // Set up the receive callback for this new connection
    tcp_recv(newpcb, http_recv);
    return ERR_OK;
}

// ---------------------------------------------------------
// UTILS
// ---------------------------------------------------------
void print_memory_map(EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS Status;
    UINTN MemoryMapSize = 0;
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    UINTN MapKey;
    UINTN DescriptorSize;
    UINT32 DescriptorVersion;

    SystemTable->BootServices->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    MemoryMapSize += 2 * DescriptorSize;
    SystemTable->BootServices->AllocatePool(EfiLoaderData, MemoryMapSize, (void**)&MemoryMap);
    Status = SystemTable->BootServices->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    
    if (EFI_ERROR(Status)) return;

    Print(L"\n--- UEFI MEMORY MAP ---\n");
    EFI_MEMORY_DESCRIPTOR *Desc = MemoryMap;
    int count = 0;
    while ((UINT8*)Desc < (UINT8*)MemoryMap + MemoryMapSize) {
        if (Desc->Type == EfiConventionalMemory) {
             Print(L"FREE RAM    %016lx - %016lx  (%ld pages)\n", 
                  Desc->PhysicalStart, 
                  Desc->PhysicalStart + (Desc->NumberOfPages * 4096),
                  Desc->NumberOfPages);
            count++;
        }
        Desc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)Desc + DescriptorSize);
    }
    Print(L"Total Free Regions: %d\n-----------------------\n\n", count);
}
// ADD THIS HELPER FUNCTION
void serial_print_hex(uint64_t n) {
    char hex[] = "0123456789ABCDEF";
    char buf[19];
    // Remove the "0x" prefix here because you likely print it manually in the caller
    // Or keep it here and don't print "0x" in the caller. 
    // Let's keep it simple: Just the numbers.
    buf[18] = 0;
    for (int i = 17; i >= 0; i--) { // Fill full 64-bit width
        buf[i] = hex[n % 16];
        n /= 16;
    }
    serial_print("0x"); // Print prefix once
    serial_print(buf);
}

void serial_init() {
    outb(0x3F8 + 1, 0x00);    // Disable all interrupts
    outb(0x3F8 + 3, 0x80);    // Enable DLAB (set baud rate divisor)
    outb(0x3F8 + 0, 0x03);    // Set divisor to 3 (lo byte) 38400 baud
    outb(0x3F8 + 1, 0x00);    //                  (hi byte)
    outb(0x3F8 + 3, 0x03);    // 8 bits, no parity, one stop bit
    outb(0x3F8 + 2, 0xC7);    // Enable FIFO, clear them, with 14-byte threshold
    outb(0x3F8 + 4, 0x0B);    // IRQs enabled, RTS/DSR set
}
// --- MAIN KERNEL ---
EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);
    
    Print(L"AngelicKernel Phase 1: Preparing for Exodus...\n");
    
    // Debug: Check if hardware is found (before we kill UEFI)
    uint64_t mmio_base = pci_get_bar(0x8086, 0x100E);
    if (mmio_base == 0) {
        Print(L"[WARNING] e1000 Card not found (Check QEMU flags)\n");
    } else {
        Print(L"[SUCCESS] e1000 MMIO found at 0x%lx\n", mmio_base);
    }

    Print(L"Exiting Firmware in 1s...\n");
    SystemTable->BootServices->Stall(1000000); 

    // --- EXIT BOOT SERVICES ---
    UINTN MapSize = 0, MapKey, DescriptorSize;
    UINT32 DescriptorVersion;
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    
    // Get Memory Map (Needed for PMM Phase 2)
    SystemTable->BootServices->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    MapSize += 2 * DescriptorSize;
    SystemTable->BootServices->AllocatePool(EfiLoaderData, MapSize, (void**)&MemoryMap);
    SystemTable->BootServices->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);

    SystemTable->BootServices->ExitBootServices(ImageHandle, MapKey);

    // =========================================================
    //   BARE METAL ZONE
    // =========================================================

    // 1. Initialize Serial Port
    serial_init();

    serial_print("\n\n");
    serial_print("========================================\n");
    serial_print("   WELCOME TO ANGELIC KERNEL (BARE METAL)   \n");
    serial_print("========================================\n");
    serial_print("Phase 1 Complete. UEFI is dead.\n");

    // 2. Initialize Physical Memory Manager (Phase 2 Part 1)
    pmm_init(MemoryMap, MapSize, DescriptorSize);

    // 3. Test Allocation
    void* p = pmm_alloc_page();
    serial_print("Test Alloc: ");
    serial_print_hex((uint64_t)p);
    serial_print("\n");

    // 4. Initialize Virtual Memory Manager (Phase 2 Part 2)
    // Uncomment this only AFTER you have created src/mm/vmm.c
    vmm_init(); 

    while (1) {
        // Spin forever
    }

    return EFI_SUCCESS;
}