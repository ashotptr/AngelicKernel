CC = gcc
NASM = nasm

# Compiler Flags
# Added -mno-mmx -mno-sse to prevent interrupt crashes
CFLAGS = -I. -Iinclude -Isrc/lwip/src/include \
         -I/usr/include/efi -I/usr/include/efi/x86_64 -I/usr/include/efi/protocol \
         -fno-stack-protector -fpic -fshort-wchar -mno-red-zone \
         -mno-mmx -mno-sse \
         -Wall -Wextra -DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI

LWIP_SRCS = $(wildcard src/lwip/src/core/*.c) \
            $(wildcard src/lwip/src/core/ipv4/*.c) \
            $(wildcard src/lwip/src/netif/*.c)

OBJS = src/kernel.o \
       src/drivers/e1000.o \
       src/drivers/pci.o \
       src/net/lwip_glue.o \
       $(LWIP_SRCS:.c=.o) \
       src/mm/pmm.o \
       src/mm/vmm.o \
       src/arch/interrupts.o \
       src/arch/idt.o \
       src/arch/mpk.o

all: unikernel.efi

unikernel.efi: unikernel.so
	# FIXED: Added '-j .rodata' to keep strings and read-only constants
	objcopy -j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym -j .rel \
	    -j .rela -j .reloc --target=efi-app-x86_64 $< $@

unikernel.so: $(OBJS)
	ld -shared -Bsymbolic -L/usr/lib -L/usr/lib64 -T linker.ld \
	    $(OBJS) /usr/lib/crt0-efi-x86_64.o -o $@ -lefi -lgnuefi

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.asm
	$(NASM) -f elf64 $< -o $@

clean:
	rm -f $(OBJS) *.so *.efi