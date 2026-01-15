#include <efi.h>
#include <efilib.h>

// ---------------------------------------------------------
// 1. Data Structures
// ---------------------------------------------------------

// The Hardware Descriptor (What the card reads)
// The card expects exactly 16 bytes per entry.
struct e1000_tx_desc {
    uint64_t addr;      // Address of the packet data
    uint16_t length;    // Length of the packet
    uint8_t  cso;       // Checksum Offset
    uint8_t  cmd;       // Command Field
    uint8_t  status;    // Status Field
    uint8_t  css;       // Checksum Start
    uint16_t special;   // VLAN / Special
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

// Global Pointer to the Ring (so we can use it later)
struct e1000_tx_desc *tx_ring_base;

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
    uint64_t mem_base = bar0 & 0xFFFFFFF0;
    EFI_STATUS Status;

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [DRIVER]  Initializing e1000...\r\n");

    // 1. Allocate Memory for the TX Ring (32 Descriptors * 16 bytes = 512 bytes)
    //    We align it to 4KB (Page) just to be safe and clean.
    Status = SystemTable->BootServices->AllocatePool(
        EfiLoaderData, 
        4096, 
        (void **)&tx_ring_base
    );

    if (EFI_ERROR(Status)) {
        SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [ERROR]   Memory Allocation Failed!\r\n");
        return;
    }

    // Zero out the memory
    SystemTable->BootServices->SetMem(tx_ring_base, 4096, 0);

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [DRIVER]  TX Ring Allocated at: ");
    print_hex(SystemTable, (uint64_t)tx_ring_base);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");

    // 2. Configure the Transmit Registers
    volatile uint32_t *tdbal = (volatile uint32_t *)(mem_base + 0x3800); // Low Address
    volatile uint32_t *tdbah = (volatile uint32_t *)(mem_base + 0x3804); // High Address
    volatile uint32_t *tdlen = (volatile uint32_t *)(mem_base + 0x3808); // Length
    volatile uint32_t *tdh   = (volatile uint32_t *)(mem_base + 0x3810); // Head
    volatile uint32_t *tdt   = (volatile uint32_t *)(mem_base + 0x3818); // Tail
    volatile uint32_t *tctl  = (volatile uint32_t *)(mem_base + 0x0400); // Control

    // A. Tell hardware WHERE the ring is
    //    Note: In UEFI identity mapping, Virtual Pointer == Physical Address.
    *tdbal = (uint32_t)(uint64_t)tx_ring_base;
    *tdbah = 0; // We are in 32-bit address space usually for QEMU RAM, but safe to 0.
    
    // B. Tell hardware HOW BIG the ring is (Length in Bytes)
    //    32 descriptors * 16 bytes = 512 bytes
    *tdlen = 512; 

    // C. Reset Head and Tail to 0
    *tdh = 0;
    *tdt = 0;

    // D. Enable the Transmitter (TCTL)
    //    Bit 1 (EN) = 1 (Enable)
    //    Bit 3 (PSP) = 1 (Pad Short Packets)
    //    Val = 0b1010 = 0xA (plus some collision threshold defaults usually)
    //    A safe standard value is (1 << 1) | (1 << 3) = 0xA.
    *tctl = 0xA;

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [SUCCESS] TX Engine Configured & Enabled!\r\n");
}

// ---------------------------------------------------------
// 4. PCI Scanner (Same as before)
// ---------------------------------------------------------
void scan_pci(EFI_SYSTEM_TABLE *SystemTable) {
    EFI_GUID PciIoProtocolGuid = EFI_PCI_IO_PROTOCOL_GUID;
    EFI_PCI_IO_PROTOCOL *PciIo;
    UINTN HandleCount;
    EFI_HANDLE *HandleBuffer;
    UINTN i;
    PCI_HEADER PciHeader;
    EFI_STATUS Status;

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [SCAN]    Scanning PCI Bus...\r\n");

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

    while(1) { __asm__ __volatile__("hlt"); }
    return EFI_SUCCESS;
}