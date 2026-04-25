CC ?= gcc
NASM ?= nasm

# EFI toolchain paths — override if your distro puts them elsewhere
EFI_INC ?= /usr/include/efi
EFI_LIB ?= /usr/lib
EFI_CRT ?= $(EFI_LIB)/crt0-efi-x86_64.o

# ---------------------------------------------------------------------------
# Validate required tools at the start of every build
# ---------------------------------------------------------------------------
REQUIRED_TOOLS := $(CC) $(NASM) objcopy ld qemu-img
_check := $(foreach t,$(REQUIRED_TOOLS),\
    $(if $(shell command -v $(t) 2>/dev/null),,\
        $(error Required tool '$(t)' not found. Run: sudo apt install build-essential nasm qemu-utils)))

_check_efi := $(if $(wildcard $(EFI_INC)/efi.h),,\
    $(error EFI headers not found at $(EFI_INC). Run: sudo apt install gnu-efi))

# maybe add but are for c++: -fno-exceptions -fno-rtti, also reviwew fno-stack-protector, -mcmodel=large
# ---------------------------------------------------------------------------
# mbedTLS source tree.
# Clone once with:  make mbedtls-fetch
# Then pin to 3.6.x LTS: cd mbedtls && git checkout v3.6.4 && cd ..
# ---------------------------------------------------------------------------
MBEDTLS_DIR ?= ./mbedtls

# ---------------------------------------------------------------------------
# mbedTLS object files
#
# WHY THE CONFIG FILE IS NAMED angelic_mbedtls_config.h (not mbedtls_config.h):
#
#   mbedTLS's build_info.h is located at mbedtls/include/mbedtls/build_info.h.
#   When it does:
#       #include MBEDTLS_CONFIG_FILE   ->   #include "mbedtls_config.h"
#   GCC searches the DIRECTORY OF THE INCLUDING FILE first, which is
#   mbedtls/include/mbedtls/.  The default config is at
#   mbedtls/include/mbedtls/mbedtls_config.h -- same directory, same filename.
#   GCC finds the DEFAULT config (everything enabled) instead of ours.
#   This causes hundreds of linker errors: DES, Camellia, RSA, PSA, debug,
#   DHM, etc. are all enabled but their source files were not compiled.
#
#   Renaming our config to angelic_mbedtls_config.h means there is no file
#   by that name in mbedtls/include/mbedtls/, so GCC falls through to -I.
#   (project root) and finds our file.  All those errors disappear.
#
# Modules enabled in angelic_mbedtls_config.h and compiled here:
#   AES-GCM, ECDHE, ECDSA, SHA-256/384, X.509 write, CTR-DRBG,
#   TLS 1.2 server, memory buffer allocator, error strings.
#
# Explicitly absent (disabled by config and not compiled):
#   MBEDTLS_DEBUG_C, MBEDTLS_NET_C, MBEDTLS_TIMING_C, MBEDTLS_SELF_TEST,
#   MBEDTLS_SSL_CACHE_C, MBEDTLS_SSL_SESSION_TICKETS, MBEDTLS_SSL_CLI_C,
#   MBEDTLS_SSL_PROTO_TLS1_3, MBEDTLS_RSA_C, MBEDTLS_DHM_C,
#   MBEDTLS_DES_C, MBEDTLS_CAMELLIA_C, MBEDTLS_ARIA_C, MBEDTLS_CHACHA20_C.
#
# WHY pk_wrap.c IS IN THIS LIST:
#
#   pk.c calls mbedtls_pk_info_from_type() which references three const
#   mbedtls_pk_info_t structures:
#       mbedtls_eckey_info, mbedtls_eckeydh_info, mbedtls_ecdsa_info
#   These are defined in pk_wrap.c under #if defined(MBEDTLS_PK_HAVE_ECC_KEYS),
#   NOT in pk_ecc.c as one might expect.  Omitting pk_wrap.c produces exactly
#   three "undefined reference" errors for those three symbols at link time.
#   Verified by: nm pk_wrap.o confirms all three as defined (D) symbols.
# ---------------------------------------------------------------------------
MBEDTLS_SRCS = \
	$(MBEDTLS_DIR)/library/aes.c              \
	$(MBEDTLS_DIR)/library/aesni.c            \
	$(MBEDTLS_DIR)/library/asn1parse.c        \
	$(MBEDTLS_DIR)/library/asn1write.c        \
	$(MBEDTLS_DIR)/library/base64.c           \
	$(MBEDTLS_DIR)/library/bignum.c           \
	$(MBEDTLS_DIR)/library/bignum_core.c      \
	$(MBEDTLS_DIR)/library/bignum_mod.c       \
	$(MBEDTLS_DIR)/library/bignum_mod_raw.c   \
	$(MBEDTLS_DIR)/library/cipher.c           \
	$(MBEDTLS_DIR)/library/cipher_wrap.c      \
	$(MBEDTLS_DIR)/library/constant_time.c    \
	$(MBEDTLS_DIR)/library/ctr_drbg.c         \
	$(MBEDTLS_DIR)/library/ecp.c              \
	$(MBEDTLS_DIR)/library/ecp_curves.c       \
	$(MBEDTLS_DIR)/library/ecdh.c             \
	$(MBEDTLS_DIR)/library/ecdsa.c            \
	$(MBEDTLS_DIR)/library/error.c            \
	$(MBEDTLS_DIR)/library/gcm.c              \
	$(MBEDTLS_DIR)/library/md.c               \
	$(MBEDTLS_DIR)/library/md5.c              \
	$(MBEDTLS_DIR)/library/memory_buffer_alloc.c \
	$(MBEDTLS_DIR)/library/oid.c              \
	$(MBEDTLS_DIR)/library/pem.c              \
	$(MBEDTLS_DIR)/library/pk.c               \
	$(MBEDTLS_DIR)/library/pk_ecc.c           \
	$(MBEDTLS_DIR)/library/pk_wrap.c          \
	$(MBEDTLS_DIR)/library/pkparse.c          \
	$(MBEDTLS_DIR)/library/pkwrite.c          \
	$(MBEDTLS_DIR)/library/platform.c         \
	$(MBEDTLS_DIR)/library/platform_util.c    \
	$(MBEDTLS_DIR)/library/sha1.c             \
	$(MBEDTLS_DIR)/library/sha256.c           \
	$(MBEDTLS_DIR)/library/sha512.c           \
	$(MBEDTLS_DIR)/library/ssl_ciphersuites.c             \
	$(MBEDTLS_DIR)/library/ssl_debug_helpers_generated.c \
	$(MBEDTLS_DIR)/library/ssl_msg.c                     \
	$(MBEDTLS_DIR)/library/ssl_tls.c                     \
	$(MBEDTLS_DIR)/library/ssl_tls12_server.c            \
	$(MBEDTLS_DIR)/library/x509.c             \
	$(MBEDTLS_DIR)/library/x509_crt.c         \
	$(MBEDTLS_DIR)/library/x509_create.c      \
	$(MBEDTLS_DIR)/library/x509write.c        \
	$(MBEDTLS_DIR)/library/x509write_crt.c    \
	$(MBEDTLS_DIR)/library/x509write_csr.c

MBEDTLS_OBJS = $(MBEDTLS_SRCS:.c=.o)
LIBGCC := $(shell $(CC) --print-libgcc-file-name)

# ---------------------------------------------------------------------------
# Compiler flags
#
# -DMBEDTLS_CONFIG_FILE: point every mbedTLS TU at our renamed config.
#   Must use the unique name -- see the explanation in MBEDTLS_SRCS above.
# ---------------------------------------------------------------------------
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

# to get PE32+
unikernel.efi: unikernel.so
	objcopy -j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym -j .rel \
		-j .rela -j .reloc --target=efi-app-x86_64 --subsystem=10 $< $@
	objcopy --only-keep-debug $< unikernel.debug
	mkdir -p internal-fs/EFI/BOOT
	cp $@ internal-fs/EFI/BOOT/BOOTX64.EFI

# /usr/lib/elf_x86_64_efi.lds
# --no-undefined
# -z muldefs
unikernel.so: $(OBJS)
	ld -shared -Bsymbolic -nostdlib -znocombreloc -L$(EFI_LIB) --no-undefined -T linker.ld \
		 $(EFI_CRT) $(OBJS) -o $@ -lefi -lgnuefi $(LIBGCC)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.asm
	$(NASM) -f elf64 $< -o $@

clean:
	rm -f $(OBJS) *.so *.efi *.debug

# Fetch and pin mbedTLS to 3.6.4 LTS (run once)
mbedtls-fetch:
	git clone --recurse-submodules https://github.com/Mbed-TLS/mbedtls.git $(MBEDTLS_DIR)
	cd $(MBEDTLS_DIR) && git checkout v3.6.4

CFLAGS_SSE42 = $(filter-out -mno-sse -mno-avx -mno-mmx, $(CFLAGS)) -msse4.2
CFLAGS_AESNI = $(CFLAGS_SSE42) -maes -mpclmul

src/xmpp/yxml_sse.o: src/xmpp/yxml_sse.c
	$(CC) $(CFLAGS_SSE42) -c $< -o $@

# ---------------------------------------------------------------------------
# AES-NI compile rules for mbedTLS aes.c and aesni.c
#
# WHY TWO FILES:
#   aes.c    — top-level AES dispatch; calls mbedtls_aesni_* at runtime
#              when CPUID reports AES-NI present.
#   aesni.c  — the actual AES-NI intrinsic implementations
#              (mbedtls_aesni_crypt_ecb, mbedtls_aesni_gcm_mult,
#               mbedtls_aesni_setkey_enc, mbedtls_aesni_inverse_key,
#               mbedtls_aesni_has_support).
#              aes.c and gcm.c call these symbols at link time — if
#              aesni.c is not compiled, the linker fails with 5 undefined
#              reference errors.
#
# WHY -maes -mpclmul:
#   aesni.c includes <wmmintrin.h> (AES-NI intrinsic header). GCC refuses
#   to include it without -maes.  The global CFLAGS has -mno-sse which
#   would override -maes, so we strip the -mno-* flags first via
#   filter-out, exactly as done for yxml_sse.o above.
#
# SAFE: aesni.c uses __attribute__((target("aes,sse2"))) on every
# function, so AES-NI instructions are emitted ONLY in those functions.
# The rest of the kernel (compiled with -mno-sse) is unaffected.
# enable_sse() in kernel.c activates SSE at line ~153, before
# ExitBootServices and long before any TLS call — so AES-NI is always
# live by the time mbedtls_aesni_has_support() runs its CPUID check.
# ---------------------------------------------------------------------------
$(MBEDTLS_DIR)/library/aes.o: $(MBEDTLS_DIR)/library/aes.c
	$(CC) $(CFLAGS_AESNI) -c $< -o $@

$(MBEDTLS_DIR)/library/aesni.o: $(MBEDTLS_DIR)/library/aesni.c
	$(CC) $(CFLAGS_AESNI) -c $< -o $@

$(MBEDTLS_DIR)/library/gcm.o: $(MBEDTLS_DIR)/library/gcm.c
	$(CC) $(CFLAGS_AESNI) -c $< -o $@

# Check hardware PKU support
check-pku:
	@grep -q pku /proc/cpuinfo \
		&& echo "PKU supported — real-hardware MPK testing is possible" \
		|| echo "PKU NOT found — this CPU cannot run MPK in hardware"

# Check KVM availability
check-kvm:
	@[ -e /dev/kvm ] \
		&& echo "KVM available — use ACCEL=kvm bash run.sh for near-native speed" \
		|| echo "KVM not available — check BIOS VT-x/AMD-V settings"

# Print effective build configuration
info:
	@echo "CC = $(CC)"
	@echo "NASM = $(NASM)"
	@echo "EFI_INC = $(EFI_INC)"
	@echo "EFI_LIB = $(EFI_LIB)"
	@echo "EFI_CRT = $(EFI_CRT)"
	@echo "LIBGCC = $(LIBGCC)"
	@echo "MBEDTLS = $(MBEDTLS_DIR)"

.PHONY: all clean mbedtls-fetch check-pku check-kvm info