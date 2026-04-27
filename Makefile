CC ?= gcc
NASM ?= nasm

EFI_INC ?= /usr/include/efi
EFI_LIB ?= /usr/lib
EFI_CRT ?= $(EFI_LIB)/crt0-efi-x86_64.o

REQUIRED_TOOLS := $(CC) $(NASM) objcopy ld qemu-img

_check := $(foreach t,$(REQUIRED_TOOLS), \
    $(if $(shell command -v $(t) 2>/dev/null),, \
        $(error Required tool '$(t)' not found. Run: sudo apt install build-essential nasm qemu-utils)))

_check_efi := $(if $(wildcard $(EFI_INC)/efi.h),, \
    $(error EFI headers not found at $(EFI_INC). Run: sudo apt install gnu-efi))

MBEDTLS_DIR ?= ./mbedtls

MBEDTLS_SRCS = \
	$(MBEDTLS_DIR)/library/aes.c \
	$(MBEDTLS_DIR)/library/aesni.c \
	$(MBEDTLS_DIR)/library/asn1parse.c \
	$(MBEDTLS_DIR)/library/asn1write.c \
	$(MBEDTLS_DIR)/library/base64.c \
	$(MBEDTLS_DIR)/library/bignum.c \
	$(MBEDTLS_DIR)/library/bignum_core.c \
	$(MBEDTLS_DIR)/library/bignum_mod.c \
	$(MBEDTLS_DIR)/library/bignum_mod_raw.c \
	$(MBEDTLS_DIR)/library/cipher.c \
	$(MBEDTLS_DIR)/library/cipher_wrap.c \
	$(MBEDTLS_DIR)/library/constant_time.c \
	$(MBEDTLS_DIR)/library/ctr_drbg.c \
	$(MBEDTLS_DIR)/library/ecp.c \
	$(MBEDTLS_DIR)/library/ecp_curves.c \
	$(MBEDTLS_DIR)/library/ecdh.c \
	$(MBEDTLS_DIR)/library/ecdsa.c \
	$(MBEDTLS_DIR)/library/error.c \
	$(MBEDTLS_DIR)/library/gcm.c \
	$(MBEDTLS_DIR)/library/md.c \
	$(MBEDTLS_DIR)/library/md5.c \
	$(MBEDTLS_DIR)/library/memory_buffer_alloc.c \
	$(MBEDTLS_DIR)/library/oid.c \
	$(MBEDTLS_DIR)/library/pem.c \
	$(MBEDTLS_DIR)/library/pk.c \
	$(MBEDTLS_DIR)/library/pk_ecc.c \
	$(MBEDTLS_DIR)/library/pk_wrap.c \
	$(MBEDTLS_DIR)/library/pkparse.c \
	$(MBEDTLS_DIR)/library/pkwrite.c \
	$(MBEDTLS_DIR)/library/platform.c \
	$(MBEDTLS_DIR)/library/platform_util.c \
	$(MBEDTLS_DIR)/library/sha1.c \
	$(MBEDTLS_DIR)/library/sha256.c \
	$(MBEDTLS_DIR)/library/sha512.c \
	$(MBEDTLS_DIR)/library/ssl_ciphersuites.c \
	$(MBEDTLS_DIR)/library/ssl_debug_helpers_generated.c \
	$(MBEDTLS_DIR)/library/ssl_msg.c \
	$(MBEDTLS_DIR)/library/ssl_tls.c \
	$(MBEDTLS_DIR)/library/ssl_tls12_server.c \
	$(MBEDTLS_DIR)/library/x509.c \
	$(MBEDTLS_DIR)/library/x509_crt.c \
	$(MBEDTLS_DIR)/library/x509_create.c \
	$(MBEDTLS_DIR)/library/x509write.c \
	$(MBEDTLS_DIR)/library/x509write_crt.c \
	$(MBEDTLS_DIR)/library/x509write_csr.c

MBEDTLS_OBJS = $(MBEDTLS_SRCS:.c=.o)
LIBGCC := $(shell $(CC) --print-libgcc-file-name)

CFLAGS = -I. -Iinclude -Isrc -Isrc/lwip/src/include \
	-I$(EFI_INC) -I$(EFI_INC)/x86_64 -I$(EFI_INC)/protocol \
	-I$(MBEDTLS_DIR)/include \
	-DMBEDTLS_CONFIG_FILE='"angelic_mbedtls_config.h"' \
	-fno-stack-protector -ffreestanding -fpic -fshort-wchar -mno-red-zone \
	-mno-mmx -mno-sse -mno-avx \
	-Wall -Wextra -DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI -g \
	-DNO_SYS=1 -DUSE_MPK

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
	src/mpk_diagnostic.o \
	src/drivers/e1000.o \
	src/drivers/pci.o \
	src/drivers/ata.o \
	src/drivers/ahci.o \
	src/drivers/disk.o \
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
	src/xmpp/xmpp_store.o \
	src/xmpp/xmpp_persist.o \
	src/xmpp/xmpp_log.o \
	src/xmpp/xmpp_memory.o \
	src/xmpp/xmpp_tls.o \
	src/xmpp/mbedtls_port.o \
	src/xmpp/yxml.o \
	src/xmpp/mpk_benchmark.o \
	src/xmpp/xmpp_sm.o \
	src/xmpp/yxml_sse.o \
	$(MBEDTLS_OBJS)

all: unikernel.efi

unikernel.efi: unikernel.so
	objcopy -j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym -j .rel \
		-j .rela -j .reloc --target=efi-app-x86_64 --subsystem=10 $< $@
	objcopy --only-keep-debug $< unikernel.debug
	mkdir -p internal-fs/EFI/BOOT
	cp $@ internal-fs/EFI/BOOT/BOOTX64.EFI

unikernel.so: $(OBJS)
	ld -shared -Bsymbolic -nostdlib -znocombreloc -L$(EFI_LIB) --no-undefined -T linker.ld \
		 $(EFI_CRT) $(OBJS) -o $@ -lefi -lgnuefi $(LIBGCC)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.asm
	$(NASM) -f elf64 $< -o $@

clean:
	rm -f $(OBJS) *.so *.efi *.debug

mbedtls-fetch:
	git clone --recurse-submodules https://github.com/Mbed-TLS/mbedtls.git $(MBEDTLS_DIR)
	cd $(MBEDTLS_DIR) && git checkout v3.6.4

CFLAGS_SSE42 = $(filter-out -mno-sse -mno-avx -mno-mmx, $(CFLAGS)) -msse4.2
CFLAGS_AESNI = $(CFLAGS_SSE42) -maes -mpclmul

src/xmpp/yxml_sse.o: src/xmpp/yxml_sse.c
	$(CC) $(CFLAGS_SSE42) -c $< -o $@

$(MBEDTLS_DIR)/library/aes.o: $(MBEDTLS_DIR)/library/aes.c
	$(CC) $(CFLAGS_AESNI) -c $< -o $@

$(MBEDTLS_DIR)/library/aesni.o: $(MBEDTLS_DIR)/library/aesni.c
	$(CC) $(CFLAGS_AESNI) -c $< -o $@

$(MBEDTLS_DIR)/library/gcm.o: $(MBEDTLS_DIR)/library/gcm.c
	$(CC) $(CFLAGS_AESNI) -c $< -o $@

check-pku:
	@grep -q pku /proc/cpuinfo \
		&& echo "PKU supported — real-hardware MPK testing is possible" \
		|| echo "PKU NOT found — this CPU cannot run MPK in hardware"

check-kvm:
	@[ -e /dev/kvm ] \
		&& echo "KVM available — use ACCEL=kvm bash run.sh for near-native speed" \
		|| echo "KVM not available — check BIOS VT-x/AMD-V settings"

info:
	@echo "CC = $(CC)"
	@echo "NASM = $(NASM)"
	@echo "EFI_INC = $(EFI_INC)"
	@echo "EFI_LIB = $(EFI_LIB)"
	@echo "EFI_CRT = $(EFI_CRT)"
	@echo "LIBGCC = $(LIBGCC)"
	@echo "MBEDTLS = $(MBEDTLS_DIR)"

.PHONY: all clean mbedtls-fetch check-pku check-kvm info