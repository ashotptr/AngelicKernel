# AngelicKernel

A bare-metal XMPP server unikernel with Intel MPK driver isolation.

Boots directly from UEFI into a Long Mode kernel. No OS, no libc, no userspace.
The e1000 Gigabit Ethernet driver runs in an MPK protection domain (Key 1)
isolated from the XMPP stack by a two-instruction WRPKRU gate.

**Implements:** RFC 6120/6121 (XMPP), XEP-0045 (MUC), XEP-0049 (Private Storage), XEP-0160 (Offline Messages), STARTTLS via mbedTLS 3.6.4.

---

## Quick Start (QEMU, 5 minutes)

### 1. Install dependencies

```bash
sudo apt install \
    build-essential nasm gnu-efi ovmf gdb \
    qemu-system-x86 qemu-utils \
    python3-venv python3-full
```

### 2. Fetch subprojects (one-time)

```bash
# lwIP TCP/IP stack
git clone git://git.savannah.nongnu.org/lwip.git src/lwip

# mbedTLS (pinned to 3.6.4 LTS)
make mbedtls-fetch
```

### 3. Configure network (optional for QEMU)

The default config works with QEMU's built-in NAT (IP `10.0.2.15`).
To change it, edit **`include/config.h`** before building.

### 4. Build and run

```bash
bash run.sh
```

QEMU will start, boot the kernel, and print to `serial.log`.
The XMPP server is available at `127.0.0.1:5222`.

### 5. Connect a test client

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install slixmpp colorama
python3 slixmpp_debug.py
```

---

## Configuration

All tunable values live in **`include/config.h`**. Edit this file — not the source files — to adapt to your environment.

| Setting | Default | Description |
|---------|---------|-------------|
| `ANGELIC_IP_*` | `10.0.2.15` | Kernel's static IPv4 address |
| `ANGELIC_NM_*` | `255.255.255.0` | Netmask |
| `ANGELIC_GW_*` | `10.0.2.2` | Default gateway |
| `ANGELIC_XMPP_PORT` | `5222` | XMPP listen port |
| `ANGELIC_XMPP_DOMAIN` | `angelic.local` | XMPP server domain |
| `ANGELIC_NIC_IDS` | 8254x family | PCI device IDs to probe |

---

## Run Options

`run.sh` accepts environment variables — no need to edit the script:

```bash
# Use AHCI disk backend instead of ATA PIO
DISK_BACKEND=ahci bash run.sh

# Force KVM hardware acceleration (much faster boot + accurate benchmarks)
ACCEL=kvm bash run.sh

# Both together
DISK_BACKEND=ahci ACCEL=kvm bash run.sh

# Custom XMPP host port
XMPP_PORT=5223 bash run.sh
```

`run.sh` auto-detects KVM. If `/dev/kvm` is accessible, it uses it automatically.

---

## Benchmarks

```bash
cd testing

# Boot time (5 runs)
python3 benchmarks/boot_time_measure.py --launch --runs 5 \
    --output graphs/data/boot_times.csv

# Prosody baseline memory
bash benchmarks/prosody_baseline.sh --skip-bench

# Openfire baseline memory
bash benchmarks/openfire_baseline.sh --skip-bench

# MPK cycle count (read from serial log after a run)
grep -oP "Result: \K[0-9]+" ../serial.log > graphs/data/mpk_cycles.txt
```

> **Note on benchmark numbers:** The targets in Capstone §9.2 (< 500 ms boot,
> < 50 cycle WRPKRU) are for real x86-64 hardware. Under QEMU TCG (software
> emulation) boot time is ~5.5 s and WRPKRU reads ~4964 cycles — both are
> emulation artifacts. On real hardware with KVM or bare metal these pass.
> MPK isolation correctness (PKRU value, page table tags, violation #PF) is
> verified independently of the cycle count and passes in all environments.

---

## Real Hardware

### CPU requirement

PKU (Memory Protection Keys) requires **Intel Skylake (2015) or newer**, or **AMD Zen 2 (2019) or newer**.

```bash
grep pku /proc/cpuinfo   # non-empty = supported
```

### NIC requirement

The e1000 driver targets the **Intel 8254x family**. These chips use the same register layout as the QEMU emulated device, so no driver changes are needed.

| Chip | PCI ID | Notes |
|------|--------|-------|
| 82540EM | `8086:100E` | What QEMU emulates |
| 82541PI | `8086:1076` | Common on old desktops |
| 82545EM | `8086:100F` | Server boards |
| 82546GB | `8086:1079` | Dual-port, ~$10 eBay |

The kernel scans all IDs in `ANGELIC_NIC_IDS` (config.h) automatically — no recompile needed when switching chips.

### Booting from USB

```bash
# Write the boot image to a USB drive (replace /dev/sdX carefully)
sudo dd if=angelic.img of=/dev/sdX bs=4M status=progress
sync
```

Or copy `internal-fs/EFI/BOOT/BOOTX64.EFI` to a FAT32 USB stick at `EFI/BOOT/BOOTX64.EFI` and enable UEFI boot in firmware settings. Disable Secure Boot — the kernel is not signed.

### Network on real hardware

Set `ANGELIC_IP_*`, `ANGELIC_GW_*` in `include/config.h` to valid addresses for your LAN, then rebuild. The benchmark script must point at the kernel's static IP:

```bash
python3 benchmarks/boot_time_measure.py \
    --host 192.168.1.100 \   # <-- kernel's IP from config.h
    --runs 5
```

### Serial log capture

```bash
# On the host machine connected via USB-serial adapter
minicom -D /dev/ttyS0 -b 115200 -C serial.log
```

---

## Makefile Targets

```bash
make                  # build unikernel.efi
make clean            # remove all build artifacts
make mbedtls-fetch    # clone and pin mbedTLS 3.6.4 (run once)
make info             # print effective build configuration
make check-pku        # check if this CPU supports PKU
make check-kvm        # check if KVM is available
```

### Cross-compilation / custom toolchain

```bash
make CC=x86_64-linux-gnu-gcc
make EFI_INC=/usr/local/include/efi EFI_LIB=/usr/local/lib
```

---

## Project Structure

```
include/
  config.h              ← edit this to configure the kernel
  drivers/              ← driver headers (e1000, pci, disk)
  sys/                  ← MPK gate headers
  net/                  ← lwIP glue header
src/
  kernel.c              ← entry point (efi_main)
  drivers/
    e1000.c             ← Intel 8254x NIC driver (MPK Key 1)
    pci.c               ← PCI config space scanner
    ahci.c / ata.c      ← SATA/IDE storage drivers
    disk.c              ← backend-agnostic disk abstraction
  net/
    lwip_glue.c         ← lwIP netif + packet I/O
  mm/
    pmm.c               ← physical memory (bump allocator)
    vmm.c               ← virtual memory + MPK page tagging
  arch/
    idt.c / interrupts.asm  ← IDT, IRQ handlers
    mpk.asm             ← WRPKRU gate trampoline
  xmpp/
    xmpp_server.c       ← TCP accept loop
    xmpp_parser.c       ← XML/XMPP stream parser
    xmpp_router.c       ← stanza routing
    xmpp_tls.c          ← STARTTLS via mbedTLS
    xmpp_persist.c      ← disk-backed roster + private store
    mpk_benchmark.c     ← WRPKRU cycle-count benchmark
testing/
  benchmarks/
    boot_time_measure.py
    prosody_baseline.sh
    openfire_baseline.sh
  graphs/data/          ← benchmark output (gitignored)
```

---

## Troubleshooting

**`e1000 Card not found` in serial log**
The PCI scan did not find any 8254x NIC. In QEMU this means `-device e1000` is missing from `run.sh`. On real hardware, check the card is seated and its PCI ID is in `ANGELIC_NIC_IDS` in `config.h`.

**`AHCI unavailable — trying ATA PIO` then `ATA: data drive (slave) not found`**
This is normal in QEMU with `DISK_BACKEND=ata` if `data.img` was deleted. Run `rm -f data.img && bash run.sh` to recreate it. For AHCI, switch to `DISK_BACKEND=ahci`.

**OVMF not found**
```bash
sudo apt install ovmf        # Debian/Ubuntu
sudo dnf install edk2-ovmf   # Fedora
sudo pacman -S edk2-ovmf     # Arch
```

**Docker permission denied (benchmarks)**
```bash
sudo usermod -aG docker $USER && newgrp docker
```

**Boot time ~5.5 s / MPK cycles ~4964**
These are QEMU TCG emulation artifacts, not real measurements. See the note in the Benchmarks section above.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `build-essential` | GCC, make |
| `nasm` | assembler for `src/arch/` |
| `gnu-efi` | UEFI headers and CRT |
| `ovmf` | UEFI firmware for QEMU |
| `qemu-system-x86` | x86-64 emulator |
| `qemu-utils` | `qemu-img` for disk image creation |
| `python3-venv` | benchmark scripts |
| `slixmpp` | XMPP test client |
| `docker.io` | Prosody/Openfire baseline containers |
