# **AngelicKernel**
This project is a **unikernel**: a single-purpose operating system that boots directly on the hardware through UEFI and runs exactly one application, an **XMPP chat server**. There is no Linux underneath. The kernel, the drivers, the TCP/IP stack, the TLS library, and the chat server are all linked into a single `BOOTX64.EFI` binary that owns the whole machine.

The main idea of the project is **driver isolation with Intel MPK** (Memory Protection Keys). Everything lives in one address space, but the network driver's memory is locked behind a protection key, so a bug in the protocol code cannot corrupt the driver and a bug in the driver cannot be reached directly from the rest of the kernel.

### `src/kernel.c`
The entry point and the main loop.

* **Boot:** Enables SSE, finds a supported Intel NIC on the PCI bus, takes the UEFI memory map, and calls `ExitBootServices`. From this point on, the kernel runs alone on the machine.
* **Init order:** Physical memory → page tables → MPK → IDT/interrupts → NIC → disk → lwIP → XMPP server.
* **Main loop:** When the NIC interrupt flags `packet_pending`, the loop polls the network interface, drives any TLS handshakes that are waiting to write, sends pending stream-management acks, and runs the lwIP timers.

### `src/mm/`
* **`pmm.c`:** A physical page allocator built from the UEFI memory map.
* **`vmm.c`:** Builds the page tables and tags the driver's pages with a protection key (`vmm_protect_driver`).

### `src/arch/`
* **`idt.c` / `interrupts.asm`:** Interrupt descriptor table, exception handlers, and the NIC IRQ handler (which only sets a flag, the real work happens in the main loop).
* **`mpk.asm`:** Enables MPK in `CR4`, provides `wrpkru` helpers, and implements the call **trampolines**.

### MPK driver isolation
This is the core of the project.

* The e1000 driver code and data are placed into dedicated sections (`.secure_driver_code` / `.secure_driver_data`) using `mpk_sections.h` and `linker.ld`.
* `vmm.c` tags those pages with **protection key 1**, and after boot the kernel sets `PKRU = 0x0C`. Result: lwIP, mbedTLS, and the XMPP server **cannot read or write driver memory**.
* Every call into the driver goes through an assembly trampoline (`mpk_gate.h` + `mpk.asm`) that unlocks the key with `wrpkru`, calls the driver function, and locks it again before returning.
* **`mpk_diagnostic.c`** proves the isolation at boot by showing that a direct access from kernel code faults.
* **`mpk_benchmark.c`** measures the cost of switching the key (a `wrpkru` pair) over 1,000,000 iterations and prints the result in cycles to the serial log.

### `src/drivers/`
* **`pci.c`:** Scans the PCI bus for a supported Intel NIC (the device ID list is in `config.h`).
* **`e1000.c`:** The NIC driver. RX/TX descriptor rings, raw send, and scatter-gather send. This is the code that lives inside the secure sections.
* **`ata.c` / `ahci.c` / `disk.c`:** Two block-device backends (IDE PIO and SATA/AHCI) behind one common read/write interface, used for the persistent XMPP store.

### `src/net/`
* **`lwip_glue.c`:** Connects **lwIP** (`NO_SYS=1`, raw API) to the NIC through the MPK trampolines. The static IP configuration comes from `config.h`.
* **`libc_glue.c`:** A minimal freestanding libc (`mem*`, `str*`, `snprintf`, random, ...) so that lwIP and mbedTLS can run without an operating system.

### `src/xmpp/`
The chat server itself. It listens on port **5222** for the domain **`angelic.local`** and supports up to 20 concurrent clients (limits in `xmpp_core.h`).

* **`xmpp_server.c`:** lwIP TCP callbacks and stream negotiation.
* **`xmpp_parser.c` / `yxml.c` / `yxml_sse.c`:** Stanza parsing with the small yxml pull parser, plus an **SSE4.2** (`pcmpistri`) fast path for finding stanza boundaries.
* **`xmpp_router.c` / `xmpp_handlers.c`:** Stanza routing and the protocol features.
* **`xmpp_tls.c`:** **STARTTLS** with mbedTLS (TLS 1.2). At boot it generates a P-256 key and a self-signed certificate fully in memory, and all TLS allocations come from a static 288 KB pool.
* **`xmpp_sm.c`:** Stream management (XEP-0198, `urn:xmpp:sm:3`), requesting acks every 10 stanzas. Resumption is not implemented yet.
* **`xmpp_store.c` / `xmpp_persist.c`:** The in-RAM store and its on-disk format. State is written to the raw `data.img` disk with a versioned header (magic + CRC32) and fixed regions for rosters, private XML, rooms, offline messages, and pending subscriptions.

Implemented features: SASL **PLAIN** and **ANONYMOUS**, resource binding and session, roster and presence subscriptions, **multi-user chat** (XEP-0045) with room configuration, affiliations and moderation, service discovery, ping (XEP-0199), private XML storage (XEP-0049), blocking (XEP-0191), last activity, software version, and offline messages with delayed delivery (XEP-0203).

### `src/config.h`
Static configuration for the whole kernel:

```
ANGELIC_IP        10.0.2.15   (QEMU user networking)
ANGELIC_XMPP_PORT 5222
ANGELIC_XMPP_DOMAIN "angelic.local"
ANGELIC_NIC_IDS   supported Intel e1000 device IDs

```

### `files inside testing`
Python test suites and benchmarks: raw-socket RFC 6120/6121 and XEP-0045 tests, a slixmpp async suite, a compliance report generator, boot-time and load benchmarks with **Prosody** and **Openfire** baselines, and graph generation for the results. See `testing/README.md` for details.

---

## Usage
### Dependencies
`gcc`, `nasm`, `binutils`, `qemu-system-x86_64`, `qemu-img`, the **gnu-efi** headers, and **OVMF** firmware. The lwIP sources are expected under `src/lwip/`, and mbedTLS is fetched with:

```
make mbedtls-fetch

```

### Build the project

```
make

```

This produces `unikernel.efi` and copies it to `internal-fs/EFI/BOOT/BOOTX64.EFI`.

### Run

```
./run.sh

```

This will:

1. Build the project.
2. Create `data.img` (a 1 MB raw disk for the persistent store) if it does not exist.
3. Find the OVMF firmware and boot the kernel in QEMU, with KVM if the host CPU supports PKU, otherwise with TCG emulation.
4. Forward host port 5222 into the VM and write the kernel output to `serial.log`.

After boot, connect any XMPP client to `localhost:5222` with the domain `angelic.local`.

Useful extras:

* `DISK_BACKEND` at the top of `run.sh` selects the storage backend: `ata` (default) or `ahci`.
* `make check-pku` and `make check-kvm` check what the host machine supports.

> **Note:** MPK requires a CPU with PKU support. Without it, `run.sh` automatically falls back to TCG emulation, which is slower but works everywhere.
