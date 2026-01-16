#include <efi.h>
#include <efilib.h>
#include "drivers/e1000.h"
#include "drivers/pci.h"
#include "net/lwip_glue.h"
#include "lwip/init.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"

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

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);
    
    Print(L"AngelicKernel Starting...\n");
    
    // Initialize Hardware
    uint64_t mmio_base = pci_get_bar(0x8086, 0x100E);
    uint8_t mac[6];
    e1000_init(mmio_base, mac);
    init_network_stack(mmio_base, mac);

    // Setup HTTP Server
    struct tcp_pcb *pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, 80);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, http_accept_callback);

    // Show Memory for Phase 2 Planning
    print_memory_map(SystemTable);

    Print(L"System Ready. Try: curl http://localhost:8080\n");

    while (1) {
        angelic_netif_poll();
        sys_check_timeouts();
    }
    return EFI_SUCCESS;
}