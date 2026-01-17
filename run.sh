#!/bin/bash
set -e  # Exit immediately if compilation fails

# 1. Compile
make

# 2. Filesystem Setup
mkdir -p internal-fs/EFI/BOOT
cp unikernel.efi internal-fs/EFI/BOOT/BOOTX64.EFI

# 3. Find Generic Firmware (No Keys = Setup Mode)
OVMF_CODE=$(find /usr/share -name "OVMF_CODE.fd" -o -name "OVMF_CODE_4M.fd" | grep -v "snakeoil" | head -n 1)
OVMF_VARS_TMPL=$(find /usr/share -name "OVMF_VARS.fd" -o -name "OVMF_VARS_4M.fd" | grep -v "snakeoil" | head -n 1)

if [ -z "$OVMF_CODE" ] || [ -z "$OVMF_VARS_TMPL" ]; then
    echo "Error: Generic OVMF firmware not found. Install 'ovmf' package."
    exit 1
fi

echo "Using Code: $OVMF_CODE"
echo "Using Vars: $OVMF_VARS_TMPL"

# 4. Create Fresh Variable Store
cp "$OVMF_VARS_TMPL" OVMF_VARS.fd

# 5. Launch QEMU (Fixed: Removed -serial stdio)
echo "Launching Unikernel (Setup Mode)..."
qemu-system-x86_64 \
    -nographic \
    -m 512M \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file=OVMF_VARS.fd \
    -drive file=fat:rw:internal-fs,format=raw,media=disk \
    -device e1000,netdev=n0 \
    -netdev user,id=n0,hostfwd=tcp::8080-:80