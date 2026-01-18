#!/bin/bash
set -e

# 1. Compile
make

# 2. Filesystem
mkdir -p internal-fs/EFI/BOOT
cp unikernel.efi internal-fs/EFI/BOOT/BOOTX64.EFI

# 3. Launch with Monolithic Firmware + SMM OFF
# We use the file we found in your previous 'find' command: /usr/share/ovmf/OVMF.fd
# We force 'smm=off' and 'accel=tcg' to ensure the firmware cannot lock itself.
echo "Launching Unikernel (Monolithic + SMM OFF)..."
qemu-system-x86_64 \
    -nographic \
    -machine q35,smm=off,accel=tcg \
    -m 512M \
    -bios /usr/share/ovmf/OVMF.fd \
    -drive file=fat:rw:internal-fs,format=raw,media=disk \
    -device e1000,netdev=n0 \
    -netdev user,id=n0,hostfwd=tcp::8080-:80