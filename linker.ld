/* 1. CRITICAL: The Entry Point must be _start (from crt0), not efi_main */
ENTRY(_start)

SECTIONS
{
    /* 2. UEFI Image starts at 0 */
    . = 0;
    ImageBase = .;

    /* --- CODE SECTION (Read + Execute) --- */
    .text : {
        *(.text)
        *(.text.*)
        
        /* MPK SECURE CODE: Aligned to 4K page */
        . = ALIGN(4096);
        __secure_driver_code_start = .;
        *(.secure_driver_code)
        . = ALIGN(4096);
        __secure_driver_code_end = .;
    }

    /* --- DATA SECTION (Read + Write) --- */
    /* 3. CRITICAL: Force a gap between Code and Data to avoid RWX Warning */
    . = ALIGN(4096);
    
    .data : {
        *(.data)
        *(.data.*)
        *(.sdata)
        *(.rodata)
        *(.rodata.*)

        /* MPK SECURE DATA: Aligned to 4K page */
        . = ALIGN(4096);
        __secure_driver_data_start = .;
        *(.secure_driver_data)
        . = ALIGN(4096);
        __secure_driver_data_end = .;
    }

    /* --- UEFI RELOCATIONS (Required for booting) --- */
    .rel : { *(.rel .rel.*) }
    .rela : { *(.rela .rela.*) }
    .reloc : { *(.reloc) }
    
    /* Discard strict stack notes to silence warnings */
    /DISCARD/ : {
        *(.note.GNU-stack)
        *(.eh_frame)
    }
}