#!/bin/bash

# 1. Compile the Kernel
make
if [ $? -ne 0 ]; then
    echo "Build failed! Fix errors before running."
    exit 1
fi

# 2. Prepare the Virtual Disk Structure
# UEFI looks for /EFI/BOOT/BOOTX64.EFI to boot automatically
mkdir -p internal-fs/EFI/BOOT
cp unikernel.efi internal-fs/EFI/BOOT/BOOTX64.EFI

# 3. Launch QEMU
# -bios: Uses the OVMF firmware (UEFI for QEMU)
# -drive: Mounts our 'internal-fs' folder as a virtual USB stick
# -net none: We start offline to verify the kernel first
echo "Launching Unikernel..."
qemu-system-x86_64 \
    -nographic \
    -bios /usr/share/ovmf/OVMF.fd \
    -drive file=fat:rw:internal-fs,format=raw \
    -net none