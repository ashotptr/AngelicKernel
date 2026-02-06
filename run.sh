#!/bin/bash
set -e

# compile
make

# filesystem
mkdir -p internal-fs/EFI/BOOT
cp unikernel.efi internal-fs/EFI/BOOT/BOOTX64.EFI

if [ ! -f OVMF_VARS.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd OVMF_VARS_4M.fd
fi

# 3. launch Firmware
echo "Launching Unikernel (Monolithic + SMM OFF)..."
#echo "DEBUG MODE: Waiting for GDB on localhost:1234..."
qemu-system-x86_64 \
    -cpu max \
    -nographic \
    -machine q35,smm=off,accel=tcg \
    -m 512M \
    -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE_4M.fd,readonly=on \
    -drive if=pflash,format=raw,unit=1,file=./OVMF_VARS_4M.fd \
    -drive file=fat:rw:internal-fs,format=raw,media=disk \
    -device e1000,netdev=n0 \
    -netdev user,id=n0,hostfwd=tcp::8080-:80 \
    -debugcon file:uefi_debug.log \
    -global isa-debugcon.iobase=0x402 #\
    #-s -S # for debugging with gdb

#   -serial stdio \
#  -bios /usr/share/ovmf/OVMF.fd \

# for the future create disk images: https://wiki.osdev.org/UEFI