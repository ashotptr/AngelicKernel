#!/bin/bash
set -e

# ---------------------------------------------------------------------------
# STORAGE BACKEND SELECTION
#
# Set DISK_BACKEND to choose how data.img is exposed to the kernel:
#
#   ata   — Classic IDE (ATA PIO fallback path in disk.c)
#             Machine: -machine pc (i440fx + PIIX3 chipset)
#             Drive:   -drive if=ide,index=1   ← slave on primary channel
#             When to use: debugging, known-good baseline, or when AHCI
#             support in ahci.c hasn't been validated yet.
#
#   ahci  — Native SATA via AHCI (preferred path in disk.c)
#             Machine: -machine q35 (ICH9 chipset, has native AHCI at 00:1f.2)
#             Drive:   -device ich9-ahci + ide-hd on that bus
#             When to use: production, real hardware targets, or when you
#             want DMA transfers and 48-bit LBA.
#
# The kernel's disk abstraction (drivers/disk.c) detects whichever
# controller is present at runtime — no recompile needed when switching.
# ---------------------------------------------------------------------------
DISK_BACKEND="ata"   # change to "ahci" for SATA

# compile
make

# filesystem
mkdir -p internal-fs/EFI/BOOT
cp unikernel.efi internal-fs/EFI/BOOT/BOOTX64.EFI

# OVMF variable store — copy once, preserve across runs so EFI settings survive
if [ ! -f OVMF_VARS_4M.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd OVMF_VARS_4M.fd
fi

# Persistent data disk — create once (1 MB raw), preserve across runs.
# Layout (managed entirely by xmpp_persist.c):
#   LBA  0       : persist_header_t (magic + CRC32)
#   LBA  1..42   : private_store[]  (XEP-0049)
#   LBA 43..98   : roster_store[]   (RFC 6121)
#   LBA 99..2047 : reserved
#
# NOTE: do NOT delete data.img between runs — it holds the persistent state.
# To wipe all user data and start fresh, run:  rm -f data.img
if [ ! -f data.img ]; then
    echo "Creating data.img (1 MB raw — persistent XMPP store)..."
    qemu-img create -f raw data.img 1M
fi

echo "Launching AngelicKernel (disk backend: ${DISK_BACKEND})..."

# ---------------------------------------------------------------------------
# ATA PIO path — pc machine (i440fx/PIIX3), IDE controller at 0x1F0
# data.img is the IDE slave (index=1), selected by ATA_DATA_DRIVE in ata.h.
# ---------------------------------------------------------------------------
if [ "${DISK_BACKEND}" = "ata" ]; then
    qemu-system-x86_64 \
        -cpu max,+pku \
        -nographic \
        -machine pc,smm=off,accel=tcg \
        -m 512M \
        \
        -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE_4M.fd,readonly=on \
        -drive if=pflash,format=raw,unit=1,file=./OVMF_VARS_4M.fd \
        \
        -drive file=fat:rw:internal-fs,format=raw,if=ide,index=0,media=disk \
        -drive file=data.img,format=raw,if=ide,index=1,media=disk \
        \
        -device e1000,netdev=n0 \
        -netdev user,id=n0,hostfwd=tcp::5222-:5222 \
        \
        -serial file:serial.log \
        -debugcon file:uefi_debug.log \
        -global isa-debugcon.iobase=0x402

# ---------------------------------------------------------------------------
# AHCI path — q35 machine (ICH9 chipset), AHCI controller at PCI 00:1f.2
# data.img is attached to the ICH9 AHCI controller's first port (ahci.0).
# The AHCI driver PCI-scans for class=01/sub=06/pi=01 and finds it automatically.
# ---------------------------------------------------------------------------
elif [ "${DISK_BACKEND}" = "ahci" ]; then
    qemu-system-x86_64 \
        -cpu max,+pku \
        -nographic \
        -machine q35,smm=off,accel=tcg \
        -m 512M \
        \
        -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE_4M.fd,readonly=on \
        -drive if=pflash,format=raw,unit=1,file=./OVMF_VARS_4M.fd \
        \
        -drive file=fat:rw:internal-fs,format=raw,if=ide,index=0,media=disk \
        -device ich9-ahci,id=ahci \
        -drive file=data.img,format=raw,if=none,id=data_drv \
        -device ide-hd,drive=data_drv,bus=ahci.0 \
        \
        -device e1000,netdev=n0 \
        -netdev user,id=n0,hostfwd=tcp::5222-:5222 \
        \
        -serial file:serial.log \
        -debugcon file:uefi_debug.log \
        -global isa-debugcon.iobase=0x402

else
    echo "ERROR: Unknown DISK_BACKEND '${DISK_BACKEND}'. Use 'ata' or 'ahci'."
    exit 1
fi

#   -serial stdio
#   -s -S   # for GDB debugging
# disk images: https://wiki.osdev.org/UEFI