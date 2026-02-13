CC = gcc
NASM = nasm

# maybe add but are for c++: -fno-exceptions -fno-rtti, also reviwew fno-stack-protector, -mcmodel=large
CFLAGS = -I. -Iinclude -Isrc/lwip/src/include \
	-I/usr/include/efi -I/usr/include/efi/x86_64 -I/usr/include/efi/protocol \
	-fno-stack-protector -ffreestanding -fpic -fshort-wchar -mno-red-zone \
	-mno-mmx -mno-sse -mno-avx \
	-Wall -Wextra -DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI -g \
	-DNO_SYS=1

LWIP_CORE = src/lwip/src/core/init.c \
	src/lwip/src/core/def.c \
	src/lwip/src/core/dns.c \
	src/lwip/src/core/inet_chksum.c \
	src/lwip/src/core/ip.c \
	src/lwip/src/core/mem.c \
	src/lwip/src/core/memp.c \
	src/lwip/src/core/netif.c \
	src/lwip/src/core/pbuf.c \
	src/lwip/src/core/raw.c \
	src/lwip/src/core/stats.c \
	src/lwip/src/core/tcp.c \
	src/lwip/src/core/tcp_in.c \
	src/lwip/src/core/tcp_out.c \
	src/lwip/src/core/timeouts.c \
	src/lwip/src/core/udp.c

LWIP_IPV4 = src/lwip/src/core/ipv4/autoip.c \
	src/lwip/src/core/ipv4/dhcp.c \
	src/lwip/src/core/ipv4/etharp.c \
	src/lwip/src/core/ipv4/icmp.c \
	src/lwip/src/core/ipv4/igmp.c \
	src/lwip/src/core/ipv4/ip4_frag.c \
	src/lwip/src/core/ipv4/ip4.c \
	src/lwip/src/core/ipv4/ip4_addr.c

LWIP_NETIF = src/lwip/src/netif/ethernet.c

LWIP_SRCS = $(LWIP_CORE) $(LWIP_IPV4) $(LWIP_NETIF)

# LWIP_SRCS = $(wildcard src/lwip/src/core/*.c) \
# 	$(wildcard src/lwip/src/core/ipv4/*.c) \
# 	$(wildcard src/lwip/src/netif/*.c)

OBJS = src/kernel.o \
	src/drivers/e1000.o \
	src/drivers/pci.o \
	src/net/lwip_glue.o \
	src/net/libc_glue.o \
	$(LWIP_SRCS:.c=.o) \
	src/mm/pmm.o \
	src/mm/vmm.o \
	src/arch/interrupts.o \
	src/arch/idt.o \
	src/arch/mpk.o \
	src/xmpp/xmpp_server.o \
	src/xmpp/xmpp_parser.o \
	src/xmpp/xmpp_router.o \
	src/xmpp/xmpp_handlers.o \
	src/xmpp/xmpp_log.o \
	src/xmpp/xmpp_memory.o

all: unikernel.efi

# to get PE32+
unikernel.efi: unikernel.so
	objcopy -j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym -j .rel \
		-j .rela -j .reloc --target=efi-app-x86_64 --subsystem=10 $< $@
	objcopy --only-keep-debug $< unikernel.debug
	mkdir -p internal-fs/EFI/BOOT
	cp $@ internal-fs/EFI/BOOT/BOOTX64.EFI

# /usr/lib/elf_x86_64_efi.lds
# --no-undefined
unikernel.so: $(OBJS)
	ld -shared -Bsymbolic -nostdlib -znocombreloc -z muldefs -L/usr/lib --no-undefined -L/usr/lib64 -T linker.ld \
		/usr/lib/crt0-efi-x86_64.o $(OBJS) -o $@ -lefi -lgnuefi

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.asm
	$(NASM) -f elf64 $< -o $@

clean:
	rm -f $(OBJS) *.so *.efi *.debug