#include <efi.h>
#include <efilib.h>

// We define the function type specifically for the compiler to handle the ABI correctly
EFI_STATUS EFIAPI efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    
    // 1. Reset the Console (Clears screen)
    // We call the function pointer directly: SystemTable->ConOut->Reset(...)
    SystemTable->ConOut->Reset(SystemTable->ConOut, 1);

    // 2. Print "Hello World" directly
    // Note: We must use L"..." for Wide Strings (UEFI requirement)
    // Note: We must use \r\n for a new line
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"----------------------------------\r\n");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  XMPP Unikernel: Boot Successful \r\n");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"----------------------------------\r\n");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"  Phase 1: Raw UEFI Mode Active   \r\n");

    // 3. Infinite Loop (So the VM doesn't close)
    while(1) {
        __asm__ __volatile__("hlt");
    }

    return EFI_SUCCESS;
}