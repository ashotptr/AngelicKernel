#!/bin/bash
set -e

DISK_BACKEND="ata"   # "ahci" for sata

if [ -z "${ACCEL}" ]; then
    if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] && \
       grep -qw pku /proc/cpuinfo; then
        ACCEL="kvm"
    else
        ACCEL="tcg"
        if [ ! -e /dev/kvm ] || [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
            echo "[info] kvm not available, falling back to tcg"
            echo "to enable kvm, use sudo usermod -aG kvm \$USER && newgrp kvm"
        else
            echo "[info] host cpu lacks pku, kvm cannot expose it, falling back to tcg"
        fi
    fi
fi

#ACCEL="tcg"

OVMF_CODE=""
for d in /usr/share/OVMF /usr/share/edk2/ovmf /usr/share/edk2-ovmf /usr/share/qemu /usr/share/ovmf; do
    for name in OVMF_CODE_4M.fd OVMF_CODE.fd OVMF.fd; do
        [ -f "$d/$name" ] && { OVMF_CODE="$d/$name"; break 2; }
    done
done
[ -z "$OVMF_CODE" ] && {
    echo "OVMF firmware not found"
    echo "install with one of:"
    echo "sudo apt install ovmf # debian/ubuntu"
    echo "sudo dnf install edk2-ovmf # fedora"
    echo "sudo pacman -S edk2-ovmf # arch"
    exit 1
}

OVMF_VARS_TEMPLATE=""
for d in /usr/share/OVMF /usr/share/edk2/ovmf /usr/share/edk2-ovmf /usr/share/qemu /usr/share/ovmf; do
    for name in OVMF_VARS_4M.fd OVMF_VARS.fd; do
        [ -f "$d/$name" ] && { OVMF_VARS_TEMPLATE="$d/$name"; break 2; }
    done
done
[ -z "$OVMF_VARS_TEMPLATE" ] && { echo "OVMF_VARS template not found alongside $OVMF_CODE"; exit 1; }

echo "[info] OVMF code: $OVMF_CODE"
echo "[info] OVMF vars: $OVMF_VARS_TEMPLATE (template)"

make

mkdir -p internal-fs/EFI/BOOT
cp unikernel.efi internal-fs/EFI/BOOT/BOOTX64.EFI

if [ ! -f OVMF_VARS.fd ]; then
    cp "$OVMF_VARS_TEMPLATE" OVMF_VARS.fd
fi

if [ ! -f data.img ]; then
    echo "creating data.img (1 mb for persistent XMPP store)"
    qemu-img create -f raw data.img 1M
fi

echo "launching AngelicKernel (disk backend: ${DISK_BACKEND}, accel: ${ACCEL})"

if [ "${DISK_BACKEND}" = "ata" ]; then
    qemu-system-x86_64 \
        -cpu max,+pku \
        -nographic \
        -machine "pc,smm=off,accel=${ACCEL}" \
        -m 512M \
        \
        -drive if=pflash,format=raw,unit=0,file="${OVMF_CODE}",readonly=on \
        -drive if=pflash,format=raw,unit=1,file=./OVMF_VARS.fd \
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

elif [ "${DISK_BACKEND}" = "ahci" ]; then
    qemu-system-x86_64 \
        -cpu max,+pku \
        -nographic \
        -machine "q35,smm=off,accel=${ACCEL}" \
        -m 512M \
        \
        -drive if=pflash,format=raw,unit=0,file="${OVMF_CODE}",readonly=on \
        -drive if=pflash,format=raw,unit=1,file=./OVMF_VARS.fd \
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
    echo "unknown disk_backend '${DISK_BACKEND}'"
    echo "use 'ata' or 'ahci'."
    exit 1
fi

#   -serial stdio
#   -s -S   # for GDB debugging
# disk images: https://wiki.osdev.org/UEFI