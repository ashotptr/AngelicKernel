#include <efi.h>
#include <efilib.h>

// ---------------------------------------------------------
// 1. Data Structures
// ---------------------------------------------------------
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

// ---------------------------------------------------------
// 2. Helper Functions
// ---------------------------------------------------------
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
    // 1. Clean the address (The last 4 bits are flags, not address)
    //    Mask: 0xFFFFFFF0 (Keeps top bits, clears bottom 4)
    uint64_t mem_base = bar0 & 0xFFFFFFF0;

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [DRIVER]  Initializing e1000 Driver...\r\n");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [DRIVER]  Mem Base (Cleaned): ");
    print_hex(SystemTable, mem_base);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");

    // 2. Read the STATUS Register (Offset 0x8)
    //    We cast the address to a "volatile uint32_t pointer" so the compiler knows 
    //    this is a hardware register, not RAM.
    volatile uint32_t *status_reg = (volatile uint32_t *)(mem_base + 0x8);
    uint32_t status_value = *status_reg;

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [HARDWARE] Status Register Value: ");
    print_hex(SystemTable, status_value);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");

    // 3. Interpret the result
    //    If we see 0x80080 or similar, it means "Full Duplex" + "1000mbps"
    if (status_value == 0xFFFFFFFF) {
         SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [ERROR]   Read All-Ones. Device invalid?\r\n");
    } else if (status_value == 0) {
         SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [ERROR]   Read Zero. Device sleeping?\r\n");
    } else {
         SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [SUCCESS] Device is ONLINE and responding!\r\n");
    }
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
            
            // PASS THE ADDRESS TO THE DRIVER
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