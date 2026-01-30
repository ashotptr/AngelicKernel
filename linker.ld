ENTRY(_start)

SECTIONS
{
    . = 0;
    ImageBase = .;

    .text : {
        *(.text)
        *(.text.*)
        
        . = ALIGN(4096);
        __secure_driver_code_start = .;
        *(.secure_driver_code)
        . = ALIGN(4096);
        __secure_driver_code_end = .;
    }

    . = ALIGN(4096);
    
    .data : {
        *(.data)
        *(.data.*)
        *(.sdata)
        *(.rodata)
        *(.rodata.*)

        . = ALIGN(4096);
        __secure_driver_data_start = .;
        *(.secure_driver_data)
        . = ALIGN(4096);
        __secure_driver_data_end = .;
    }

    .rel : { *(.rel .rel.*) }
    .rela : { *(.rela .rela.*) }
    .reloc : { *(.reloc) }
    
    /DISCARD/ : {
        *(.note.GNU-stack)
        *(.eh_frame)
    }
}