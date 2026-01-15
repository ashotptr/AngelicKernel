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
    uint32_t BAR0;      // Base Address Register 0 (The Memory Address)
} __attribute__((packed)) PCI_HEADER;

// ---------------------------------------------------------
// 2. Helper Functions
// ---------------------------------------------------------
// Simple helper to print 64-bit Hex values (since we don't have printf)
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
// 3. The PCI Scanner
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

    // Ask UEFI for the list of PCI devices
    Status = SystemTable->BootServices->LocateHandleBuffer(
        ByProtocol, &PciIoProtocolGuid, NULL, &HandleCount, &HandleBuffer
    );

    if (EFI_ERROR(Status)) {
        SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [ERROR]   PCI Bus Not Found!\r\n");
        return;
    }

    for (i = 0; i < HandleCount; i++) {
        Status = SystemTable->BootServices->HandleProtocol(
            HandleBuffer[i], &PciIoProtocolGuid, (void **)&PciIo
        );

        // Read the config space
        PciIo->Pci.Read(PciIo, EfiPciIoWidthUint32, 0, sizeof(PCI_HEADER)/4, &PciHeader);

        // Check for Intel (0x8086) and e1000 (0x100E)
        if (PciHeader.VendorID == 0x8086 && PciHeader.DeviceID == 0x100E) {
            SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [FOUND]   Intel e1000 Network Card!\r\n");
            
            // Print the physical memory address where the card lives
            SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [INFO]    MMIO Base Address: ");
            print_hex(SystemTable, PciHeader.BAR0); 
            SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");
            
            // Save this address! We will need it to make the card do things.
            return;
        }
    }

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [WARNING] No Network Card Found.\r\n");
}

// ---------------------------------------------------------
// 4. Main Entry Point
// ---------------------------------------------------------
EFI_STATUS efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    (void)ImageHandle;

    SystemTable->ConOut->Reset(SystemTable->ConOut, 1);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [SUCCESS] Kernel Booted Successfully! \r\n");

    // CRITICAL: Actually call the function this time!
    scan_pci(SystemTable); 

    while(1) { __asm__ __volatile__("hlt"); }
    return EFI_SUCCESS;
}