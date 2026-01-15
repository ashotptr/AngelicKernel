#include <efi.h>
#include <efilib.h>

// 1. Data Structures
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

// 2. Helper: Print a single byte as Hex (e.g., "A5")
void print_byte(EFI_SYSTEM_TABLE *SystemTable, uint8_t n) {
    CHAR16 hex[] = L"0123456789ABCDEF";
    CHAR16 buf[3];
    buf[0] = hex[(n >> 4) & 0xF];
    buf[1] = hex[n & 0xF];
    buf[2] = L'\0';
    SystemTable->ConOut->OutputString(SystemTable->ConOut, buf);
}

// 3. Helper: Print 32-bit Integer
void print_hex32(EFI_SYSTEM_TABLE *SystemTable, uint32_t n) {
    CHAR16 hex[] = L"0123456789ABCDEF";
    CHAR16 buf[11];
    int i;
    buf[0] = L'0'; buf[1] = L'x';
    for (i = 9; i >= 2; i--) {
        buf[i] = hex[n & 0xF];
        n >>= 4;
    }
    buf[10] = L'\0';
    SystemTable->ConOut->OutputString(SystemTable->ConOut, buf);
}

// 4. The Driver Logic
void init_e1000(EFI_SYSTEM_TABLE *SystemTable, uint32_t bar0) {
    uint64_t mem_base = bar0 & 0xFFFFFFF0; // Clean the flags
    uint8_t mac[6];

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [DRIVER]  Initializing e1000...\r\n");

    // -- READ MAC ADDRESS --
    // The MAC is stored in two registers:
    // RAL0 (0x5400) = Lower 4 bytes
    // RAH0 (0x5404) = Upper 2 bytes
    volatile uint32_t *ral = (volatile uint32_t *)(mem_base + 0x5400);
    volatile uint32_t *rah = (volatile uint32_t *)(mem_base + 0x5404);

    uint32_t mac_low = *ral;
    uint32_t mac_high = *rah;

    // Extract the bytes (Little Endian)
    mac[0] = (uint8_t)(mac_low & 0xFF);
    mac[1] = (uint8_t)((mac_low >> 8) & 0xFF);
    mac[2] = (uint8_t)((mac_low >> 16) & 0xFF);
    mac[3] = (uint8_t)((mac_low >> 24) & 0xFF);
    mac[4] = (uint8_t)(mac_high & 0xFF);
    mac[5] = (uint8_t)((mac_high >> 8) & 0xFF);

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [NETWORK] MAC Address: ");
    
    // Print formatted XX:XX:XX...
    for(int i=0; i<6; i++) {
        print_byte(SystemTable, mac[i]);
        if(i < 5) SystemTable->ConOut->OutputString(SystemTable->ConOut, L":");
    }
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [SUCCESS] Driver Loaded & Identified!\r\n");
}

// 5. PCI Scanner
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

// 6. Main Entry
EFI_STATUS efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    (void)ImageHandle;

    SystemTable->ConOut->Reset(SystemTable->ConOut, 1);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [KERNEL]  XMPP Unikernel Booting... \r\n");

    scan_pci(SystemTable); 

    while(1) { __asm__ __volatile__("hlt"); }
    return EFI_SUCCESS;
}