ENTRY(_start)

SECTIONS
{
    . = 0;
    ImageBase = .;
    
    .hash : { *(.hash) }
    .gnu.hash : { *(.gnu.hash) }

    . = ALIGN(4096);
    .eh_frame : { 
        *(.eh_frame)
    }

    . = ALIGN(4096);
    .text : {
        *(.text)
        *(.text.*)
        *(.gnu.linkonce.t.*)
        
        . = ALIGN(4096);
        __secure_driver_code_start = .;
        *(.secure_driver_code)
        . = ALIGN(4096);
        __secure_driver_code_end = .;
    }

    . = ALIGN(4096);
    .reloc : {
        *(.reloc)
    }

    . = ALIGN(4096);
    .data : {
        *(.rodata*)
        *(.got.plt)
        *(.got)
        *(.data*)
        *(.sdata)
        *(.sbss)
        *(.scommon)
        *(.dynbss)
        *(.bss)
        *(COMMON)
        *(.rel.local)
        
        . = ALIGN(4096);
        __secure_driver_data_start = .;
        *(.secure_driver_data)
        . = ALIGN(4096);
        __secure_driver_data_end = .;
    }

    . = ALIGN(4096);
    .dynamic : {
        *(.dynamic)
    }

    . = ALIGN(4096);
    .rela : {
        *(.rela*)
    }

    . = ALIGN(4096);
    .rel : {
        *(.rel*)
    }

    . = ALIGN(4096);
    .dynsym : {
        *(.dynsym)
    }

    . = ALIGN(4096);
    .dynstr : {
        *(.dynstr)
    }
    
    /DISCARD/ : {
        *(.note.GNU-stack)
    }
}