#include <efi.h>
#include <efilib.h>

// ---------------------------------------------------------
// 1. Data Structures
// ---------------------------------------------------------
struct e1000_tx_desc {
    uint64_t addr;      
    uint16_t length;    
    uint8_t  cso;       
    uint8_t  cmd;       
    uint8_t  status;    
    uint8_t  css;       
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
struct e1000_tx_desc *tx_ring_base;
uint32_t mmio_base_global = 0;
uint32_t tx_tail_index = 0;

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
// 3. Driver Logic
// ---------------------------------------------------------
void init_e1000(EFI_SYSTEM_TABLE *SystemTable, uint32_t bar0) {
    mmio_base_global = bar0 & 0xFFFFFFF0;
    
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
    *tdlen = 512; 
    *tdh = 0;
    *tdt = 0;
    *tctl = 0xA; // Enable + Pad Short Packets

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [SUCCESS] TX Engine Ready.\r\n");
}

void send_raw_packet(EFI_SYSTEM_TABLE *SystemTable, void *data, uint16_t len) {
    // 1. Get the current descriptor (where Tail points)
    struct e1000_tx_desc *desc = &tx_ring_base[tx_tail_index];

    // 2. Fill it
    desc->addr = (uint64_t)data;
    desc->length = len;
    // CMD: EOP (End of Packet) | IFCS (Insert Frame Checksum/CRC)
    // EOP = Bit 0, IFCS = Bit 1 -> 0x3
    // RS (Report Status) = Bit 3 -> 0x8 (Optional, helps debug)
    desc->cmd = 0x0B; 
    desc->status = 0;

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [NET]     Sending Packet (Size: ");
    print_hex(SystemTable, len);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L")...\r\n");

    // 3. Increment Tail (Wrap at 32)
    tx_tail_index = (tx_tail_index + 1) % 32;

    // 4. Write new Tail to Hardware
    volatile uint32_t *tdt = (volatile uint32_t *)(mmio_base_global + 0x3818);
    *tdt = tx_tail_index;

    // 5. Verification: Check Head Pointer
    // If Head catches up to Tail, the card has sent the data.
    // We do a simple busy wait check for demo purposes.
    volatile uint32_t *tdh = (volatile uint32_t *)(mmio_base_global + 0x3810);
    
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [DEBUG]   Tail: ");
    print_hex(SystemTable, tx_tail_index);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L" Head: ");
    print_hex(SystemTable, *tdh); // Should be old value
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");

    // Simple delay to let QEMU process
    for(volatile int k=0; k<1000000; k++);

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [DEBUG]   Tail: ");
    print_hex(SystemTable, tx_tail_index);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L" Head: ");
    print_hex(SystemTable, *tdh); // Should be NEW value
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");
}

// ---------------------------------------------------------
// 4. PCI Scanner
// ---------------------------------------------------------
void scan_pci(EFI_SYSTEM_TABLE *SystemTable) {
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

    if (EFI_ERROR(Status)) return;

    for (i = 0; i < HandleCount; i++) {
        Status = SystemTable->BootServices->HandleProtocol(
            HandleBuffer[i], &PciIoProtocolGuid, (void **)&PciIo
        );
        PciIo->Pci.Read(PciIo, EfiPciIoWidthUint32, 0, sizeof(PCI_HEADER)/4, &PciHeader);

        if (PciHeader.VendorID == 0x8086 && PciHeader.DeviceID == 0x100E) {
            SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [FOUND]   Intel e1000 Network Card!\r\n");
            init_e1000(SystemTable, PciHeader.BAR0);
            return;
        }
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

    scan_pci(SystemTable); 

    // -- CONSTRUCT A RAW PACKET --
    // Destination: Broadcast (FF:FF:FF:FF:FF:FF)
    // Source:      52:54:00:12:34:56
    // Type:        0x0800 (IP) or just bogus data
    // Payload:     "Hello Unikernel"
    uint8_t packet[64];
    
    // Dest
    for(int i=0; i<6; i++) packet[i] = 0xFF;
    // Source
    packet[6] = 0x52; packet[7] = 0x54; packet[8] = 0x00;
    packet[9] = 0x12; packet[10]= 0x34; packet[11]= 0x56;
    // Type
    packet[12] = 0xDE; packet[13] = 0xAD;
    // Data
    packet[14] = 'H'; packet[15] = 'e'; packet[16] = 'l'; packet[17] = 'l'; packet[18] = 'o';

    send_raw_packet(SystemTable, packet, 64);

    while(1) { __asm__ __volatile__("hlt"); }
    return EFI_SUCCESS;
}