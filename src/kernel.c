#include <efi.h>
#include <efilib.h>

// CRITICAL CHANGE: 
// We removed "EFIAPI" and "__attribute__((ms_abi))" from this function definition.
// The "crt0" wrapper calls us using the standard System V (Linux) convention.
EFI_STATUS efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    
    (void)ImageHandle; // Ignore unused argument warning

    // 1. Reset Console
    // Because of the Makefile flag, this call will correctly switch 
    // to MS ABI just for this instruction.
    SystemTable->ConOut->Reset(SystemTable->ConOut, 1);

    // 2. Print Success
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"\r\n");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [SUCCESS] Kernel Booted Successfully! \r\n");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [INFO]    Ready for Driver Init...    \r\n");

    // 3. Halt Loop
    while(1) {
        __asm__ __volatile__("hlt");
    }

    return EFI_SUCCESS;
}

// 
// The PCI bus is like a giant Excel sheet. 
// Rows = Devices. Columns = Configuration Registers.
// We are looking for Vendor ID 8086 (Intel) and Device ID 100E (e1000).

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
    uint32_t BAR0;  // Base Address Register 0 (The Memory Address of the Card)
    // ... rest omitted for brevity
} __attribute__((packed)) PCI_HEADER;

// We use the UEFI PCI I/O Protocol to scan safely
void scan_pci(EFI_SYSTEM_TABLE *SystemTable) {
    EFI_GUID PciIoProtocolGuid = EFI_PCI_IO_PROTOCOL_GUID;
    EFI_PCI_IO_PROTOCOL *PciIo;
    EFI_HANDLE *HandleBuffer;
    UINTN HandleCount;
    UINTN i;
    PCI_HEADER PciHeader;

    // 1. Locate all PCI devices
    // Note: In a real OS we scan manually, but UEFI gives us a shortcut
    EFI_STATUS Status = SystemTable->BootServices->LocateHandleBuffer(
        ByProtocol, 
        &PciIoProtocolGuid, 
        NULL, 
        &HandleCount, 
        &HandleBuffer
    );

    if (EFI_ERROR(Status)) {
        SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [ERROR] PCI Scan Failed \r\n");
        return;
    }

    // 2. Iterate through them
    for (i = 0; i < HandleCount; i++) {
        Status = SystemTable->BootServices->HandleProtocol(
            HandleBuffer[i], 
            &PciIoProtocolGuid, 
            (void **)&PciIo
        );

        // Read the first 64 bytes of config space
        PciIo->Pci.Read(PciIo, EfiPciIoWidthUint32, 0, sizeof(PCI_HEADER)/4, &PciHeader);

        // Check for Intel e1000 (Vendor 0x8086, Device 0x100E or 0x1000)
        if (PciHeader.VendorID == 0x8086 && (PciHeader.DeviceID == 0x100E || PciHeader.DeviceID == 0x1000)) {
             SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  [FOUND] Intel e1000 NIC Detected! \r\n");
             
             // TODO: Save PciHeader.BAR0 -- this is your MMIO address!
             return;
        }
    }
}