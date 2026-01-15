#include <efi.h>
#include <efilib.h>

// ---------------------------------------------------------
// 1. Data Structures
// ---------------------------------------------------------

// TX Descriptor (What we use to SEND)
struct e1000_tx_desc {
    uint64_t addr;      
    uint16_t length;    
    uint8_t  cso;       
    uint8_t  cmd;       
    uint8_t  status;    
    uint8_t  css;       
    uint16_t special;   
} __attribute__((packed));

// RX Descriptor (What the card uses to give us DATA)
struct e1000_rx_desc {
    uint64_t addr;      // Address of the buffer
    uint16_t length;    // Length of data received
    uint16_t checksum;  
    uint8_t  status;    // Status (Bit 0 = DD = Descriptor Done)
    uint8_t  errors;    
    uint16_t special;   
} __attribute__((packed));

typedef struct {
    uint16_t VendorID;
    uint16_t DeviceID;
    uint16_t Command;
    uint16_t Status;
    uint8_t  RevisionID;
    uint8_t  ProgIF;
    uint8_t  SubClass;
    uint8_t  ClassCode;
    uint8_t  CacheLineSize;
    uint8_t  LatencyTimer;
    uint8_t  HeaderType;
    uint8_t  BIST;
    uint32_t BAR0;      
} __attribute__((packed)) PCI_HEADER;

// GLOBALS
// Note: Changed to uint64_t to fix compiler warnings on x86_64
uint64_t mmio_base_global = 0; 

struct e1000_tx_desc *tx_ring_base;
struct e1000_rx_desc *rx_ring_base;
uint8_t  *rx_buffer_pool; // Big chunk of memory for packets

uint32_t tx_tail_index = 0;
uint32_t rx_tail_index = 0; // We read from here

// ---------------------------------------------------------
// 2. Helper Functions
// ---------------------------------------------------------
void print_byte(EFI_SYSTEM_TABLE *SystemTable, uint8_t n) {
    CHAR16 hex[] = L"0123456789ABCDEF";
    CHAR16 buf[3];
    buf[0] = hex[(n >> 4) & 0xF];
    buf[1] = hex[n & 0xF];
    buf[2] = L'\0';
    SystemTable->ConOut->OutputString(SystemTable->ConOut, buf);
}

void print_hex(EFI_SYSTEM_TABLE *SystemTable, uint64_t n) {
    CHAR16 hex[] = L"0123456789ABCDEF";
    CHAR16 buf[19]; 
    int i;
    buf[0] = L'0'; buf[1] = L'x';
    for (i = 17; i >= 2; i--) {
        buf[i] = hex[n & 0xF];
        n >>= 4;
    }
    buf[18] = L'\0';
    SystemTable->ConOut->OutputString(SystemTable->ConOut, buf);
}

// ---------------------------------------------------------
// 3. Driver Logic - TX (Transmit)
// ---------------------------------------------------------
void init_tx(EFI_SYSTEM_TABLE *SystemTable) {
    SystemTable->BootServices->AllocatePool(EfiLoaderData, 4096, (void **)&tx_ring_base);
    SystemTable->BootServices->SetMem(tx_ring_base, 4096, 0);

    volatile uint32_t *tdbal = (volatile uint32_t *)(mmio_base_global + 0x3800); 
    volatile uint32_t *tdbah = (volatile uint32_t *)(mmio_base_global + 0x3804); 
    volatile uint32_t *tdlen = (volatile uint32_t *)(mmio_base_global + 0x3808); 
    volatile uint32_t *tdh   = (volatile uint32_t *)(mmio_base_global + 0x3810); 
    volatile uint32_t *tdt   = (volatile uint32_t *)(mmio_base_global + 0x3818); 
    volatile uint32_t *tctl  = (volatile uint32_t *)(mmio_base_global + 0x0400); 

    *tdbal = (uint32_t)(uint64_t)tx_ring_base;
    *tdbah = 0; 
    *tdlen = 512; // 32 descriptors * 16 bytes
    *tdh = 0;
    *tdt = 0;
    *tctl = 0xA; // Enable + Pad Short Packets
}

void send_raw_packet(EFI_SYSTEM_TABLE *SystemTable, void *data, uint16_t len) {
    struct e1000_tx_desc *desc = &tx_ring_base[tx_tail_index];

    desc->addr = (uint64_t)data;
    desc->length = len;
    desc->cmd = 0x0B; // EOP | IFCS | RS
    desc->status = 0;

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [NET]     Sending Packet...\r\n");

    tx_tail_index = (tx_tail_index + 1) % 32;

    volatile uint32_t *tdt = (volatile uint32_t *)(mmio_base_global + 0x3818);
    *tdt = tx_tail_index;
}

// ---------------------------------------------------------
// 4. Driver Logic - RX (Receive)
// ---------------------------------------------------------
void init_rx(EFI_SYSTEM_TABLE *SystemTable) {
    int i;
    
    // 1. Allocate RX Ring (Descriptor Array)
    SystemTable->BootServices->AllocatePool(EfiLoaderData, 4096, (void **)&rx_ring_base);
    SystemTable->BootServices->SetMem(rx_ring_base, 4096, 0);

    // 2. Allocate Buffers (Where the actual data goes)
    // We need 32 buffers x 2048 bytes (standard packet size room)
    SystemTable->BootServices->AllocatePool(EfiLoaderData, 32 * 2048, (void **)&rx_buffer_pool);

    // 3. Link Descriptors to Buffers
    for(i=0; i<32; i++) {
        rx_ring_base[i].addr = (uint64_t)(rx_buffer_pool + (i * 2048));
        rx_ring_base[i].status = 0; // Clear status so we know when it updates
    }

    // 4. Configure Registers
    // RDBAL (0x2800), RDLEN (0x2808), RDH (0x2810), RDT (0x2818), RCTL (0x0100)
    volatile uint32_t *rdbal = (volatile uint32_t *)(mmio_base_global + 0x2800);
    volatile uint32_t *rdbah = (volatile uint32_t *)(mmio_base_global + 0x2804);
    volatile uint32_t *rdlen = (volatile uint32_t *)(mmio_base_global + 0x2808);
    volatile uint32_t *rdh   = (volatile uint32_t *)(mmio_base_global + 0x2810);
    volatile uint32_t *rdt   = (volatile uint32_t *)(mmio_base_global + 0x2818);
    volatile uint32_t *rctl  = (volatile uint32_t *)(mmio_base_global + 0x0100);

    *rdbal = (uint32_t)(uint64_t)rx_ring_base;
    *rdbah = 0;
    *rdlen = 512; // 32 * 16 bytes
    *rdh   = 0;
    *rdt   = 31;  // IMPORTANT: Tail must be 1 less than Head initially to indicate "All buffers available"

    // 5. Enable Receiver (RCTL)
    // Bit 1 (EN) = 1
    // Bit 4 (MPE) = 1 (Multicast Promiscuous) - useful for testing
    // Bit 15 (BAM) = 1 (Broadcast Accept Mode) - receive Broadcasts
    // Bit 26 (SECRC) = 1 (Strip Ethernet CRC)
    *rctl = (1 << 1) | (1 << 4) | (1 << 15) | (1 << 26);

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [SUCCESS] RX Engine Configured & Listening.\r\n");
}

void check_for_packets(EFI_SYSTEM_TABLE *SystemTable) {
    // Check the descriptor at our current index
    // Note: Use 'volatile' so the compiler doesn't cache the value
    volatile struct e1000_rx_desc *desc = &rx_ring_base[rx_tail_index];

    // Check Bit 0 of Status (DD - Descriptor Done). 
    // If it is 1, the hardware has put a packet here.
    if ((desc->status & 0x1)) {
        SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [RX]      PACKET RECEIVED! Size: ");
        print_hex(SystemTable, desc->length);
        SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");

        // Reset status to 0 so we can reuse this descriptor later
        desc->status = 0;

        // Move our pointer
        rx_tail_index = (rx_tail_index + 1) % 32;

        // Tell hardware we are done with this descriptor (Move Tail)
        volatile uint32_t *rdt = (volatile uint32_t *)(mmio_base_global + 0x2818);
        *rdt = rx_tail_index; 
    }
}

// ---------------------------------------------------------
// 5. Main Entry
// ---------------------------------------------------------
EFI_STATUS efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    (void)ImageHandle;

    SystemTable->ConOut->Reset(SystemTable->ConOut, 1);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [KERNEL]  XMPP Unikernel Booting... \r\n");

    // 1. Scan PCI
    EFI_GUID PciIoProtocolGuid = EFI_PCI_IO_PROTOCOL_GUID;
    EFI_PCI_IO_PROTOCOL *PciIo;
    UINTN HandleCount;
    EFI_HANDLE *HandleBuffer;
    UINTN i;
    PCI_HEADER PciHeader;
    EFI_STATUS Status;

    Status = SystemTable->BootServices->LocateHandleBuffer(
        ByProtocol, &PciIoProtocolGuid, NULL, &HandleCount, &HandleBuffer
    );

    if (EFI_ERROR(Status)) return EFI_SUCCESS;

    for (i = 0; i < HandleCount; i++) {
        Status = SystemTable->BootServices->HandleProtocol(
            HandleBuffer[i], &PciIoProtocolGuid, (void **)&PciIo
        );
        PciIo->Pci.Read(PciIo, EfiPciIoWidthUint32, 0, sizeof(PCI_HEADER)/4, &PciHeader);

        if (PciHeader.VendorID == 0x8086 && PciHeader.DeviceID == 0x100E) {
            SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [FOUND]   Intel e1000 Network Card!\r\n");
            
            // Capture the Bar0 and clean it
            mmio_base_global = (uint64_t)(PciHeader.BAR0 & 0xFFFFFFF0);
            
            // Initialize Both Engines
            init_tx(SystemTable);
            init_rx(SystemTable);
            
            // Send one packet
            uint8_t packet[64];
            for(int k=0; k<64; k++) packet[k] = 0xFF; // Broadcast junk
            send_raw_packet(SystemTable, packet, 64);
        }
    }

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [KERNEL]  Entering Main Loop (Polling)... \r\n");

    // 2. Main Loop
    while(1) { 
        check_for_packets(SystemTable);
        // Small pause to stop CPU burning 100% (optional)
        for(volatile int k=0; k<10000; k++); 
    }

    return EFI_SUCCESS;
}