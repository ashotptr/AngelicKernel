# AngelicKernel: Bare-Metal XMPP Unikernel

**Author:** [Ashot]  
**Institution:** [AUA / Computer Science]

---

## Abstract

We present AngelicKernel, a bare-metal XMPP server unikernel that uses Intel Memory Protection Keys (MPK) to isolate its network driver from the protocol stack without the overhead of separate processes or virtual machines. The system boots directly from UEFI into a Long Mode kernel, integrates lwIP 2.x for cooperative networking, and runs a complete XMPP server covering RFC 6120 Core, RFC 6121 Instant Messaging, XEP-0045 Multi-User Chat, XEP-0049 Private XML Storage, XEP-0160 Offline Messages, XEP-0198 Stream Management, XEP-0199 Ping, XEP-0030 Service Discovery, XEP-0092 Software Version, and XEP-0012 Last Activity — all within a single address space. The Intel e1000 Gigabit Ethernet driver is confined to an MPK protection domain (Key 1) by tagging its pages in the live page table with protection key 1 and setting PKRU = 0x0000000C at boot. Every call from the XMPP stack into the driver crosses a hand-written NASM assembly trampoline that atomically unlocks and re-locks Key 1 around the call using two WRPKRU instructions. Under QEMU+KVM the WRPKRU instruction costs  on the test platform the measured cost is 36 cycles. The unikernel executable is under 1 MB on disk and allocates under 1 MB of static XMPP state in BSS.

*Keywords:* unikernel, Intel MPK, XMPP, driver isolation, memory protection keys, bare-metal x86-64, UEFI, lwIP, mbedTLS, NASM

---

## 1. Introduction

### 1.1 Motivation

Modern server software runs on general-purpose operating systems that trade raw performance for programmer convenience. The OS provides process isolation, virtual memory, a scheduler, a filesystem, a network stack, and hundreds of system calls — most of which a single-purpose server like an XMPP messaging daemon never uses.

Unikernels invert this trade-off. Rather than running an application atop a general OS, a unikernel compiles the application and only the OS components it needs into a single executable image. The result boots in milliseconds and occupies megabytes of RAM. There is no /proc, no shell, no dynamic linker, no unused kernel module.

The drawback is that the entire system shares one virtual address space. In a conventional OS, a vulnerable network driver runs in kernel space but the XMPP application runs in user space; a driver buffer overflow cannot directly corrupt application data because the MMU enforces a kernel/user boundary. In a unikernel, driver and application coexist at the same privilege level with no hardware boundary between them. A bug in the e1000 receive path can overwrite the XMPP session table, authentication credentials, or message buffers.

Intel Memory Protection Keys (MPK), available on x86-64 CPU, offer a hardware mechanism to enforce intra-kernel isolation between components at a cost of two instructions per boundary crossing. AngelicKernel uses MPK to partition its single address space into two protection domains: the XMPP stack (Key 0, always accessible) and the e1000 driver (Key 1, locked by default). Any attempt by XMPP code to dereference a pointer into driver memory raises a hardware page fault before any data is read or written.

### 1.2 Research Questions

1. **Correctness**: Can MPK protection keys be configured correctly in ring 0 on a freestanding x86-64 kernel, and can correctness be verified programmatically without an OS?
2. **Overhead**: How many CPU cycles does an MPK gate crossing cost?
3. **Viability**: Does a bare-metal XMPP server with MPK work with xmpp clients, and fit inside a smaller memory footprint than competing implementations?

### 1.3 Contributions

1. First full-featured XMPP server on bare-metal UEFI x86-64 with hardware-enforced driver isolation.
2. Three-tier MPK correctness verification suite (PKRU register readback, PTE walk, violation self-test with IDT recovery) that detects misconfiguration before the server accepts any connection.
3. Write-through ATA disk persistence layer using only PIO I/O registers (no UEFI protocols, no filesystem) for durable XMPP state across reboots.
4. Quantification of the security-performance Pareto frontier for intra-kernel driver isolation on commodity x86 hardware.

---

## 2. Background

### 2.1 Unikernels

A unikernel is a single-address-space operating system that includes only the OS functionality required by one specific application. Unlike containers, which isolate processes within a shared OS kernel, a unikernel runs directly on the hypervisor or bare hardware with no kernel/user protection boundary. For AngelicKernel, the image contains the XMPP server, the lwIP TCP/IP stack, the e1000 Ethernet driver, the mbedTLS 3.6.4 cryptographic library, and a complete freestanding libc implemented from scratch in libc_glue.c.

Three properties of AngelicKernel's unikernel design are central to the design:

**No libc.** After ExitBootServices(), all UEFI runtime services are gone. There is no malloc, no printf, no time(), no errno. libc_glue.c implements every standard C function the rest of the codebase needs: the full mem* family, the full str* family, atoi, putchar, snprintf/vsnprintf, abort, and the cryptographically secure random source.

**No heap.** All significant allocations are static: the lwIP memory pool (128 KB), the mbedTLS TLS pool (288 KB), the XMPP session table, the MUC room array, the roster store, the offline message store, the pending subscription store, the private XML store. There is no malloc after boot.

**No timer hardware.** There is no PIT, no LAPIC timer, and no RTC after ExitBootServices(). The lwIP timestamp function (required by the stack for TCP retransmission timers) reads the TSC and divides by 2,000,000 to approximate milliseconds, calibrated to a 2 GHz TSC.

Prior unikernel work — MirageOS, ClickOS, OSv, HermiTux, EbbRT, LightVM — demonstrates the boot-time and footprint advantages but does not address MPK-based intra-unikernel driver isolation on commodity x86 hardware.

### 2.2 Intel Memory Protection Keys (MPK)

Intel MPK is an x86 feature available since Skylake (2015). Each 4 KB page carries a 4-bit protection key in bits [62:59] of its Page Table Entry. The per-core PKRU (Protection Key Rights for User pages) register carries two bits per key:

| Bits | Name | Effect when set |
|------|------|----------------|
| 2k   | AD   | Access Disable: any read or write to pages with key k raises #PF |
| 2k+1 | WD   | Write Disable: only writes to pages with key k raise #PF |

With 16 keys, PKRU is a 32-bit register. Key 0 occupies bits [1:0], Key 1 occupies bits [3:2]. Writing PKRU requires WRPKRU with EAX = new value, ECX = 0, EDX = 0; non-zero ECX or EDX causes #GP. RDPKRU returns the current value in EAX. WRPKRU is not a serialising instruction in the sense of CPUID or MFENCE, but on most microarchitectures it effectively prevents speculative execution from crossing the PKRU write — a property important for Spectre-variant attacks where an attacker might exploit a speculative window between WRPKRU and the first load.

A critical property: PKRU enforcement applies **only to user-mode pages** — those with U/S = 1 in every level of the paging hierarchy. If any of PML4E, PDPE, PDE, PTE has U/S = 0, PKRU checks are bypassed for that page. AngelicKernel's page-mapping logic sets PTE_USER at all four levels when building the identity map, and the per-page key-assignment routine explicitly sets PTE_USER in the leaf PTE entry when assigning a protection key.

AngelicKernel uses two keys:
- **Key 0** (PKRU bits [1:0] = 00): Kernel code, XMPP data, lwIP state, mbedTLS buffers. Always accessible. AD=0, WD=0.
- **Key 1** (PKRU bits [3:2] = 11): e1000 driver code and DMA rings. Blocked by default. AD=1, WD=1.

Default PKRU = 0x0000000C: bits [3:2] = 0b11 (Key 1 fully locked), all other bits = 0.

### 2.3 XMPP Protocol Stack

The Extensible Messaging and Presence Protocol (XMPP) is defined in RFC 6120 (Core) and RFC 6121 (Instant Messaging). It operates over persistent TCP connections using XML streams. AngelicKernel implements:

| RFC/XEP | Feature |
|---------|---------|
| RFC 6120 | Core: stream negotiation, STARTTLS, SASL PLAIN, resource binding |
| RFC 6121 | Roster management, presence subscriptions, initial presence, direct messaging |
| XEP-0045 | Multi-User Chat: full room lifecycle (join, leave, nick change, kick, ban, private messages, role changes) |
| XEP-0049 | Private XML Storage |
| XEP-0160 | Offline Message Delivery with XEP-0203 delay stamps |
| XEP-0191 | Blocklist (stub handler; full policy enforcement is future work) |
| XEP-0198 | Stream Management (stanza acknowledgement) |
| XEP-0199 | XMPP Ping |
| XEP-0030 | Service Discovery (disco#info and disco#items) |
| XEP-0092 | Software Version |
| XEP-0012 | Last Activity |

The following extensions were evaluated during design but are not yet implemented and are candidates for future work: XEP-0048 (Bookmark Storage), XEP-0071 (XHTML-IM rich text), XEP-0077 (In-Band Registration), XEP-0085 (Chat State Notifications), XEP-0107 (User Mood), XEP-0115 (Entity Capabilities), XEP-0153 (vCard-Based Avatars), XEP-0201 (Message Threads), XEP-0313 (Message Archive Management), XEP-0333 (Chat Markers), XEP-0359 (Unique and Stable Stanza IDs), and XEP-0384 (OMEMO end-to-end encryption).

---

## 3. System Architecture

### 3.1 High-Level Component Map

```
┌─────────────────────────────────────────────────────────┐
│                  AngelicKernel Image                    │
│                                                         │
│  ┌─────────────┐   ┌─────────────┐   ┌───────────────┐  │
│  │ XMPP Stack  │   │  lwIP 2.x   │   │ Memory System │  │
│  │  (Key 0)    │   │ (NO_SYS=1)  │   | pmm+vmm+MPK   │  │
│  └─────────────┘   └─────────────┘   └───────────────┘  │
│                                                         │
│                                                         │
│               MPK Gate                                  │
│         ┌─────────────────┐                             │
│         │  Trampolines    │                             │
│         │  WRPKRU(0)      │                             │
│         │  WRPKRU(0x0C)   │                             │
│         └─────────────────┘                             │
│                                                         │
│  ┌────────────────────────────────────────────────────┐ │
│  │          e1000 Driver Domain (Key 1)               │ │
│  │  .secure_driver_code  |  .secure_driver_data       │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─────────────────────────────────────────────────────┐│
│  │  mbedTLS 3.6.4 (Key 0, 288 KB static pool)          ││
│  └─────────────────────────────────────────────────────┘│
│                                                         │
│  ┌─────────────────────────────────────────────────────┐│
│  │  ATA PIO / AHCI DMA Disk Persistence                ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

### 3.3 Toolchain and Build System

AngelicKernel uses the GNU-EFI toolkit rather than a dedicated cross-compiler. GCC compiles all C and NASM source to ELF64 object files; `objcopy` then converts the final ELF binary to a UEFI-compatible PE32+ executable [gnuefi]. This works correctly for a single-component unikernel image. A dedicated cross-compiler targeting `x86_64-w64-mingw32` or a PE/COFF target would be required only if the build needed to produce user-mode UEFI applications that link against host Linux libraries, or if `objcopy` section conversion produced incorrect attributes for a future image layout [OSDev_CC]. The host OS is Linux (Ubuntu); QEMU with OVMF (`sudo apt install ovmf`) is used for development and testing. For source-level debugging, QEMU's GDB stub (`-s -S` flags) combined with a GDB hardware-watchpoint script can perform instruction-level debugging of UEFI boot code [OSDev_GDB]. Secure-boot signing (`sbsigntool`) is available but not used because the self-signed image would not pass firmware verification.

**Build system prerequisites and dependency management.** The Makefile begins by verifying the presence of every required tool — the C compiler for kernel source, the NASM assembler for the MPK assembly module, the binary conversion utility for ELF-to-PE32+ translation, the linker, the disk image creation tool, and the EFI header package required to compile against the GNU-EFI framework. Any missing tool causes the build to abort with a diagnostic message before a single source file is compiled. The mbedTLS dependency is version-pinned at 3.6.4 LTS and fetched via a dedicated Makefile target that automates the download, preventing unintentional version drift.

**mbedTLS custom configuration injection.** The mbedTLS library normally reads its compile-time feature set from a standard configuration header in the source tree, which enables all features by default. AngelicKernel instead passes `-DMBEDTLS_CONFIG_FILE="angelic_mbedtls_config.h"` to the compiler, which causes the library's build-info header to include the custom configuration file rather than the default. This mechanism guarantees that every translation unit in the mbedTLS build sees the same minimal feature set, enabling only the cryptographic primitives the server actually uses and preventing linker errors from missing symbols for disabled features. The custom configuration file is deliberately named so as not to collide with the standard name, ensuring the compiler's include path resolution always finds the custom version.

**Compiler flag rationale.** The kernel is built with the following key flags and their motivations:

| Flag | Purpose |
|------|---------|
| `-ffreestanding` | Disables standard library assumptions; required for ring-0 code |
| `-fno-stack-protector` | Avoids dependency on the libc stack-canary support function |
| `-fpic` | Position-independent code; required for UEFI relocatable binaries |
| `-fshort-wchar` | 2-byte `wchar_t`; matches the UEFI UTF-16 ABI |
| `-mno-red-zone` | Disables the 128-byte red zone below the stack pointer; required to prevent interrupt handlers from corrupting function-local data |
| `-mno-sse`, `-mno-avx`, `-mno-mmx` | Globally disables SIMD to avoid unmanaged floating-point register state in general kernel code |
| `-DMBEDTLS_CONFIG_FILE` | Injects the custom mbedTLS configuration |
| `-DNO_SYS=1` | Configures lwIP for bare-metal operation with no OS abstraction layer |
| `-DUSE_MPK` | Activates the MPK-related code paths and trampoline call sites |
| `-DGNU_EFI_USE_MS_ABI` | Enables the Microsoft x64 ABI wrappers required for UEFI firmware calls |

GCC's internal runtime library (`libgcc`) is linked explicitly. Although the kernel is built as a freestanding binary, the compiler still emits calls to libgcc for operations such as 64-bit integer arithmetic helpers, and these implicit dependencies must be resolved at link time to prevent undefined-reference errors.

**Hardware acceleration overrides.** To maintain general kernel safety, SIMD instructions are disabled globally. However, two specific subsystems benefit from hardware acceleration and are compiled under dedicated Makefile rules that filter out the global SIMD-disable flags and replace them with the appropriate extension flags. The mbedTLS AES, AES-NI, and GCM source files are compiled with SSE4.2, AES, and PCLMUL extension flags enabled, allowing the library to use hardware AES intrinsics. The vectorised XML scanner is compiled with SSE4.2 enabled. Because SSE is explicitly enabled by the boot sequence before any of these code paths can execute.

**EFI two-step build process.** Because UEFI firmware expects PE32+ (Portable Executable) binaries, producing a unikernel on a Linux host requires two distinct steps. First, the linker combines all compiled objects, the GNU-EFI C runtime, and libgcc into an ELF shared object using `-shared -Bsymbolic` (position-independent, no fixed load address), `-nostdlib` (no glibc startup files), and the custom linker script. The `--no-undefined` flag causes the linker to fail on any missing symbol at link time rather than producing a binary that will crash at runtime. Second, the binary conversion tool transforms the ELF shared object into a PE32+ UEFI application, copying only the sections the firmware can parse (code, data, read-only data, relocation information) and discarding ELF-specific metadata. Debug symbols are extracted into a separate file to keep the final EFI binary lightweight while still enabling GDB-based debugging. The resulting image is placed in a directory hierarchy that mirrors a standard UEFI boot partition structure.

**Build diagnostic targets.** The Makefile includes helper targets that verify the host environment before a test run: one target reads `/proc/cpuinfo` to confirm the host CPU exposes the protection-key feature flag, and another checks for `/dev/kvm` access to determine whether hardware-accelerated virtualisation is available. Both are run at the start of a testing session to catch configuration problems before they produce confusing test failures.

**QEMU launch script.** The run script detects whether both KVM access and the CPU protection-key feature are simultaneously available; if so, it uses KVM acceleration, otherwise it falls back to software emulation. UEFI firmware discovery is automated by scanning a list of known OVMF installation paths for the read-only firmware code image and its writable variable store. The per-run OVMF variable store is copied from the template so that each launch starts with a clean EFI variable state. A 1 MB raw disk image is provisioned via `qemu-img` and attached as a secondary drive, serving as persistent storage for the XMPP server's state. The QEMU invocation exposes all host CPU features to the guest (including protection keys), runs without a graphical display, disables System Management Mode for faster OVMF initialisation, allocates 512 MB of RAM, attaches the virtual Intel Gigabit Ethernet controller, and forwards the host's port 5222 to the guest's port 5222. Standard output is directed to a serial log file and UEFI diagnostic output to a separate file.

The custom linker script (`linker.ld`) uses GNU Binutils LD to place `.secure_driver_code` and `.secure_driver_data` into contiguous output sections with explicit start/end boundary symbols (`__secure_driver_code_start`, `__secure_driver_code_end`, `__secure_driver_data_start`, `__secure_driver_data_end`). These symbols are consumed by the driver-protection routine in the virtual memory manager to determine exactly which pages to tag with Key 1 [GNUldScript]. The script forces every section to start on a 4 KB page boundary — the exact granularity at which MPK operates — ensuring that protection-key assignments cannot accidentally span across section boundaries into adjacent memory. The `ENTRY(_start)` directive identifies the GNU-EFI runtime entry point as the image's initial instruction. An `ImageBase = .` assignment at the start of the layout anchors all internal memory references as relative offsets, making the image fully relocatable. The script also explicitly discards the `.note.GNU-stack` section, which marks the stack as non-executable in the ELF output.

**Debug output and graphics.** UEFI provides the Graphics Output Protocol (GOP, `EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID`) for framebuffer-level pixel drawing [OSDev_GOP]. AngelicKernel chose serial output over GOP: the UART at COM1 (I/O base 0x3F8) continues to function via raw port instructions indefinitely after ExitBootServices(), produces machine-readable line-by-line output forwarded directly to the QEMU host terminal, and is compatible with GDB remote-serial debugging. GOP output is confined to the boot-services phase without explicit framebuffer address retention and requires additional code to remain usable post-ExitBootServices. A framebuffer console is tracked as a future addition for bare-metal display diagnostics.

**Alternative bootloaders surveyed.** UEFI direct boot is one of several viable entry strategies. The Limine bootloader [Limine] is a modern, feature-rich Multiboot2-compatible bootloader capable of loading a 64-bit ELF kernel from a FAT32 ESP without requiring GNU-EFI. It provides a standardized boot protocol and optional early system initialization features such as framebuffer setup, memory map abstraction, and kernel boot configuration. For XMPP server use, these abstractions provide limited benefit compared to direct UEFI entry, since UEFI already exposes the EFI System Table, memory map, and hardware interfaces required during early initialization. GRUB 2 (Multiboot2) was also considered and rejected for similar reasons. The OSDev wiki sources [OSDev_BareBones] [OSDev_MeatySkel] use GRUB Multiboot as their reference entry model; AngelicKernel’s UEFI-based boot path follows the standard UEFI application entry paradigm rather than a Multiboot-style boot protocol.

**Local hostname.** During development and testing, the hostname `angelic.local` is registered in the test machine's `/etc/hosts` as an alias for `127.0.0.1`. The XMPP server domain is hard-coded as `angelic.local`; every test client connects to `angelic.local:5222`. This allows the test suite to run in LAN.

### 3.4 Boot Sequence: From UEFI to First Connection

The boot sequence is strictly ordered. Each step builds on the last.

**Bootloader responsibilities.** A bootloader's four canonical duties are: (1) bring the kernel and all bootstrap data into memory; (2) provide the kernel with the information it needs to operate (memory map, ACPI tables, etc.); (3) switch to an environment the kernel expects (64-bit long mode, paging enabled, A20 line active); and (4) transfer control to the kernel entry point [OSDev_Bootloader]. UEFI firmware performs all four duties before calling `efi_main()`: it loads the PE32+ image, provides the EFI System Table (memory map, configuration tables), and enters long mode with a flat identity map. The A20 line is always enabled by UEFI — the 8042 keyboard controller toggle is a BIOS-only concern [OSDev_A20].

**Two-phase kernel entry.** The kernel entry point executes in two distinct phases. The first phase runs under UEFI Boot Services, during which firmware services are still available. The second phase begins after ExitBootServices() returns and the firmware's runtime environment is permanently gone; from that point every function uses only what the kernel itself provides. The UEFI two-attempt handshake pattern is used for the boot-services exit: the memory map is retrieved once to obtain the map key, and ExitBootServices() is called with that key. Because Boot Services may have modified the map in the interval between the two calls, one retry is permitted — if the first attempt returns an invalid-parameter error, the map is re-fetched and the call is retried once. If both attempts fail, execution spins indefinitely because there is no safe state to return to.

**CPU feature verification and enablement.** Before any subsystem initialises, `efi_main()` verifies and enables the following CPU features. CPUID is called first to confirm each feature is present before writing control registers [OSDev_CPUID]:

| Feature | Register / Instruction | AngelicKernel Action |
|---------|----------------------|----------------------|
| SSE / OSFXSR | CR0.EM=0, CR0.MP=1, CR4.OSFXSR=1, CR4.OSXMMEXCPT=1 | Enabled by `enable_sse()` — required for yxml_sse.c |
| NX/XD (Execute Disable) | EFER.NXE=1 | Set by UEFI before entry; verified, not re-set |
| MPK / PKE | CR4.PKE=1 | Enabled by `mpk_enable()` in mpk.asm |
| RDRAND | CPUID EAX=1 ECX[30] | Checked in `secure_random_u32()`; falls back to xorshift64* if absent |
| AES-NI | CPUID EAX=1 ECX[25] | Detected by mbedTLS; AES-GCM hardware-accelerated if present |
| x87 FPU | CR0.NE=1, `FINIT` | Implicitly enabled by UEFI; not explicitly touched |
| PCID | CR4.PCIDE — not enabled | Not applicable: improves TLB efficiency on context switch |
| SMEP | CR4.SMEP — not enabled | Incompatible: driver pages are tagged U/S=1 for MPK Key 1 enforcement; SMEP would fault on ring-0 access to those pages |
| SYSCALL/SYSRET | EFER.SCE — not enabled | Not applicable: no user-mode code |
| Global Pages | CR4.PGE — not enabled | Not applicable: marks kernel PTEs global to avoid TLB flush on CR3 reload |

Features intentionally not enabled: SMEP (no user-mode code to protect against), PCID (no process switches), Global Pages (no address-space switches), SYSCALL (no user/supervisor boundary). APIC configuration is deferred to future work (§13).

A SMEP compatibility check is performed explicitly: because the driver-protection step marks driver pages as user-mode to enable MPK Key 1 enforcement, SMEP and MPK isolation are mutually exclusive — an active SMEP bit would cause the CPU to fault on any ring-0 attempt to execute those user-tagged pages. The check prints a diagnostic to the serial console if SMEP is found active but does not halt, since on current test hardware SMEP is not set.

```
efi_main() [kernel.c]
  │
  ├─ enable_sse()
  │     CR0.EM=0, CR0.MP=1, CR4.OSFXSR=1, CR4.OSXMMEXCPT=1
  │     Required before any SSE instruction — including those in yxml_sse.c.
  │     Without this, the first SIMD XML parse raises #UD.
  │
  ├─ pci_get_bar(0x8086, 0x100E)
  │     Scans PCI config space for Intel e1000 (vendor/device IDs).
  │     Reads BAR0 → global_mmio_base.
  │
  ├─ GetMemoryMap() + ExitBootServices()
  │     Two-attempt pattern: get MapKey, call ExitBootServices.
  │     If it fails (memory map changed in the interval), refresh and retry once.
  │     After success: UEFI boot services are permanently gone.
  │
  ├─ serial_init()    [first post-ExitBootServices action]
  │     Programs COM1 (I/O base 0x3F8) for 8N1 debug output.
  │     All subsequent serial_print() calls go here.
  │
  ├─ pmm_init(MemoryMap, MapSize, DescriptorSize)
  │     Scans EFI memory map for the largest EfiConventionalMemory region.
  │     Sets free_memory_start = max(region_start, 0x200000).
  │     Starting allocations below 2 MB risks overlapping with kernel image placement or firmware-reserved regions.
  │     Implements a bump allocator: each page allocation returns the current
  │     free pointer and advances it by PAGE_SIZE. Each page is zero-initialised.
  │
  ├─ vmm_init()
  │     Allocates kernel_pml4 via pmm_alloc_page().
  │     Identity-maps the entire first 4 GB (covers all MMIO, DMA, kernel):
  │       for addr in [0, 4GB): vmm_map_page(addr, addr, PTE_PRESENT|PTE_WRITE|PTE_USER)
  │     vmm_map_page() allocates PML4/PDP/PD/PT tables on demand from pmm,
  │     each with PTE_PRESENT|PTE_WRITE|PTE_USER set.
  │     Setting PTE_USER at ALL FOUR TABLE LEVELS is the critical step for
  │     MPK. A page is user-mode only if U/S=1 in every ancestor table entry.
  │     Loads kernel_pml4 into CR3 to activate the new tables.
  │
  ├─ mpk_enable()    [mpk.asm]
  │     BTS CR4, 22 → sets CR4.PKE (bit 22), enabling WRPKRU/RDPKRU.
  │     Without CR4.PKE=1, WRPKRU raises #UD (Undefined Instruction exception).
  │
  ├─ init_idt()
  │     Remaps 8259 PIC: master IRQs to 0x20-0x27, slave to 0x28-0x2F.
  │     Installs ISR stubs for exceptions (INT 0-31) and IRQs (INT 32-47).
  │     The page-fault handler (INT 14) includes the MPK self-test
  │     recovery path: checks mpk_test_in_progress, advances RIP by 2,
  │     sets mpk_test_fault_occurred, and returns rather than halting.
  │
  ├─ mpk_e1000_init(mmio_base, mac_out)   [via trampoline, Key 1 not yet locked]
  │     The trampoline-wrapped entry point for
  │     driver initialisation; calls e1000_init() through mpk_trampoline_2
  │     so that the first access into protected driver memory already follows
  │     the correct unlock/re-lock discipline. Key 1 is not yet locked at
  │     this point (vmm_protect_driver and mpk_set_pkru run later), but the
  │     trampoline path is exercised unconditionally so no call site ever
  │     reaches driver memory through a direct call.
  │
  ├─ disk_init()
  │     Attempts AHCI (PCI scan for class 0x01 subclass 0x06 SATA controller).
  │     Falls back to ATA PIO on primary IDE channel (0x1F0).
  │     Both expose disk_read_sectors() and disk_write_sectors().
  │
  ├─ init_network_stack(mmio_base, mac)
  │     lwip_init(), then netif_add() to register angelic_netif.
  │     netif->output = etharp_output (ARP resolution layer).
  │     netif->linkoutput = low_level_output (scatter-gather TX through trampoline).
  │     IP: 10.0.2.15 / 255.255.255.0, gateway 10.0.2.2 (QEMU user networking).
  │
  ├─ vmm_protect_driver()
  │     Iterates every 4 KB page in:
  │       [__secure_driver_code_start, __secure_driver_code_end)
  │       [__secure_driver_data_start, __secure_driver_data_end)
  │     For each page calls vmm_set_pkey(addr, 1):
  │       • walks live page tables to leaf PTE
  │       • clears bits [62:59] of PTE
  │       • sets bits [62:59] = 1 (Key 1)
  │       • sets PTE_USER, whis is required for PKRU enforcement on this page
  │       • issues INVLPG to flush TLB entry
  │
  ├─ mpk_set_pkru(0x0000000C)
  │     [mpk.asm]: MOV EAX, EDI; XOR ECX, ECX; XOR EDX, EDX; WRPKRU
  │     PKRU = 0x0C: Key 1 AD=1, WD=1 — driver domain LOCKED.
  │     After this instruction, any direct access to Key-1 pages raises #PF.
  │
  │
  ├─ mpk_diagnostic()      [correctness check]
  ├─ mpk_benchmark()       [WRPKRU cycle measurement]
  ├─ STI                   [enable hardware interrupts]
  │
  ├─ xmpp_init_server()
  │     xmpp_persist_load_all()    — restore all stores from disk or fresh_start
  │     xmpp_tls_server_init()     — ECDSA P-256 keygen + self-signed cert
  │     tcp_new() + tcp_bind(:5222) + tcp_listen() + tcp_accept(callback)
  │
  └─ event_loop: while(1)
        ┌─ if (packet_pending):
        │     packet_pending = 0       - clear first
        │     for i in 0..4:           - drain
        │         angelic_netif_poll() → e1000_poll_receive via trampoline → lwIP → tcp_input → xmpp_recv_callback
        ├─ for each client with tls_want_write:
        │     xmpp_tls_handshake_step()  - retry stalled TLS handshakes
        ├─ for each client with sm_want_ack:
        │     sm_want_ack = 0
        │     xmpp_sm_request_ack()      - flush deferred XEP-0198 acks
        └─ sys_check_timeouts()          - lwIP TCP retransmission timers
```


**The deferred Stream Management ack pattern** (`sm_want_ack`) prevents re-entrant send calls. The outbound stanza counter is incremented inside the single output path used by all XMPP handlers. If that counter immediately triggered an acknowledgement request back to the client, it would call the same output path recursively. Instead, a deferred flag is set and the event loop drains all pending ack requests at the top of each iteration, safely outside any active send stack frame.

### 3.5 UEFI Memory Map and ACPI Discovery

`pmm_init()` receives the EFI memory map from UEFI's `GetMemoryMap()` service. The map is an array of `EFI_MEMORY_DESCRIPTOR` structures. Each descriptor carries a type field that maps to an ACPI address-range type [ACPI66, §15, Table 15.6]:

| EFI Type | Mnemonic | ACPI Range Type | PMM Treatment |
|----------|----------|-----------------|---------------|
| 0 | EfiReservedMemoryType | AddressRangeReserved | Skip |
| 1–4 | EfiLoader/BootServices Code/Data | AddressRangeMemory | Skip (kernel lives here) |
| 5–6 | EfiRuntimeServices Code/Data | AddressRangeReserved | Skip |
| 7 | EfiConventionalMemory | AddressRangeMemory | **Usable — PMM selects largest** |
| 8 | EfiUnusableMemory | AddressRangeReserved | Skip |
| 9 | EfiACPIReclaimMemory | AddressRangeACPI | Skip |
| 10 | EfiACPIMemoryNVS | AddressRangeNVS | Skip |
| 11–12 | EfiMemoryMappedIO / PortSpace | AddressRangeReserved | Skip |
| 14 | EfiPersistentMemory | AddressRangePersistentMemory | Skip |

The PMM selects the single largest `EfiConventionalMemory` region and treats it as its allocation pool, starting no lower than physical address 0x200000.

**ACPI and firmware table handling.** UEFI exposes the Root System Description 
Pointer (RSDP) via the EFI Configuration Table, from which an OS would walk the 
XSDT to discover MADT, FADT, MCFG, and other system description tables 
[ACPI66, §5.2.5.2]. AngelicKernel does not perform this walk; the tables are 
present in the QEMU/KVM firmware image but none are parsed at runtime. The 
consequences of each omission are bounded by the server's fixed hardware target:

- **MADT**: not parsed; local APIC and I/O APIC addresses are not discovered. 
  AngelicKernel uses the legacy 8259 PIC, which requires no MADT and SMP is out of scope.
- **FADT**: not parsed; power management and ACPI event handling are entirely bypassed.
- **MCFG**: not parsed; PCIe extended configuration space is not mapped. PCI 
  device enumeration uses I/O port access (0xCF8/0xCFC), which is sufficient to locate the e1000 BAR.
- **DSDT/SSDT**: not parsed; no AML interpreter is present. Device enumeration 
  is static: exactly one NIC and one IDE disk are assumed. Dynamic device 
  description is unnecessary for a fixed-function unikernel.

**Other deliberate omissions:**

- **GPT**: `data.img` is a raw 1 MB disk image with no partition table. The ATA 
  PIO driver addresses sectors by absolute LBA directly, which is sufficient for 
  a single-image.
- **LBA mode**: the ATA PIO driver uses 28-bit LBA (maximum 128 GB addressable). 
  The 1 MB image occupies 2,048 sectors — well within the 28-bit range — so 
  48-bit LBA is unnecessary for the current workload.
- **SMM**: disabled at the QEMU machine level (`-machine ...,smm=off`), which 
  removes firmware SMM complexity and speeds up OVMF initialisation. No SMM 
  interaction is required at the kernel level.

### 3.6 Interrupt Subsystem Design

**3.6.1 Interrupt Dispatch Mechanics**

This section describes interrupts — the concrete path from hardware signal to C handler and back.
Setup — init_idt() and isr_stub_table. Before any interrupt can be handled, init_idt() must register a handler address for every vector. Those addresses come from isr_stub_table, a 48-entry array of 64-bit function pointers defined in interrupts.asm and built at compile time by a NASM %rep macro — one pointer per stub function (isr0 through isr47). init_idt() reads this array via extern void* isr_stub_table[] and calls idt_set_gate() for each entry, writing the address into the corresponding IDT slot split across three non-contiguous fields (low 16, mid 16, upper 32 bits). Each IDT entry also carries kernel_cs = 0x38 (the 64-bit kernel code segment in the GDT, telling the CPU which segment to switch to on entry) and attributes = 0x8E (present, ring 0 only, 64-bit interrupt gate — the interrupt gate type causes the CPU to clear the IF flag automatically on entry, preventing a second interrupt from corrupting the handler stack before registers are saved). Finally init_idt() writes the IDT base address and limit into the CPU's IDTR register via a one-instruction assembly stub. LIDT is a privileged instruction with no C intrinsic, which is the only reason that stub exists.
**Step 1** — CPU receives the interrupt. When the e1000 raises its IRQ line, the 8259 PIC translates it to a vector number (IRQ line + remapping offset of 32) and asserts the CPU's interrupt pin. The CPU finishes its current instruction, switches to ring 0 using the kernel_cs selector stored in the IDT entry, and pushes five values onto the stack automatically: RIP, CS, RFLAGS, RSP, and SS. These record exactly where execution was so it can be resumed later. The CPU then jumps to the stub address registered for that vector.
**Step 2** — The stub normalises the stack. Each stub is two or three instructions generated by one of two macros. Some exceptions cause the CPU to push an error code automatically before jumping to the handler (vectors 8, 10–14, 17, 30 — those for which the CPU has meaningful fault context to report). All other vectors do not. ISR_ERR handles the first group: it pushes only the interrupt number and jumps to isr_common. ISR_NOERR handles everything else: it pushes a dummy zero first to stand in for the missing error code, then the interrupt number, then jumps to isr_common. The dummy zero is the entire reason two macros exist instead of one — without it, isr_common would see a different stack layout depending on which vector fired and would read the wrong values for every field.
**Step 3** — isr_common saves state and calls C. isr_common pushes every general-purpose register onto the stack. The stack now contains, from top to bottom: all GPRs, then int_no, then err_code, then the five values the CPU pushed in Step 1. This layout maps exactly onto the registers_t struct declared in idt.c — the struct fields are declared in the same order as the pushes, so every field sits at exactly the right offset. isr_common then moves the stack pointer into rdi (the first argument register under the System V calling convention) and calls interrupt_handler(). The handler receives a registers_t* that points directly into the live stack. This is what makes the RIP advance in the MPK self-test recovery path actually move execution: iretq will read RIP from that exact stack location on its way out, so writing to it in C directly changes where the CPU resumes.
**Step 4** — interrupt_handler() dispatches. All 48 stubs funnel here. Three cases are handled in strict order. First, if the MPK self-test flag is set and a page fault arrives, the handler records the fault, advances the saved instruction pointer by two bytes to skip past the faulting instruction, and returns — this check must be first so it intercepts the deliberate Tier-3 test fault before the general exception path treats it as fatal. Second, for hardware IRQs (vectors 32–47), the handler sets packet_pending = 1 and sends EOI to the PIC. It does not touch the e1000 ICR register from interrupt context, because doing so would require entering Key-1 driver memory without an MPK trampoline, which would itself fault — the main loop's trampoline-guarded network poll drains the NIC safely. Third, for all other CPU exceptions, the handler prints the interrupt number, error code, and faulting instruction address to serial; for page faults specifically it also reads CR2 and prints the faulting linear address; then halts with CLI; HLT.
**Step 5** — Return. Back in isr_common, every general-purpose register is popped in reverse order. add rsp, 16 then discards the two qwords that are no longer needed — int_no and err_code, pushed by the stub macros in Step 2. Finally iretq atomically pops the five values the CPU pushed in Step 1 — RIP, CS, RFLAGS, RSP, SS — restoring the CPU to exactly the privilege level, stack, and instruction it was at before the interrupt fired. A normal ret would only pop RIP and would leave the CPU in a broken state; iretq exists specifically because the CPU pushed a full five-value context frame, not a standard return address.

**PIC initialisation detail.** The dual-8259 PIC remapping sequence saves the existing interrupt masks before sending the Initialisation Command Word sequence, because ICW1 resets the PIC and wipes the mask register as a side effect. Those masks are restored after the sequence completes. Each PIC is configured for 8086 mode with manual EOI. For hardware IRQs from the slave PIC (vectors 40–47), the end-of-interrupt command must be sent to both the slave and the master, since the slave is cascaded through the master's IRQ2 line; sending EOI only to the slave without also notifying the master would leave the master's in-service register bit set, blocking all future slave IRQs.

**8259 PIC configuration.** AngelicKernel uses the legacy dual-8259 PIC (master + slave cascade). The master is programmed to deliver IRQ 0–7 as INT 0x20–0x27; the slave delivers IRQ 8–15 as INT 0x28–0x2F. This remapping moves PIC vectors above the CPU exception range (INT 0–31) to avoid vector conflicts [OSDev_PIC].

The PIC is configured for **Manual EOI** (End-of-Interrupt command, not Automatic AEOI). With AEOI, the PIC clears the In-Service Register (ISR) bit automatically on the trailing edge of the INTA cycle, before the handler has finished executing. If a higher-priority IRQ arrives before the handler returns, the PIC may deliver it before the first handler completes, producing nested interrupt handling. Manual EOI sends an explicit OCW2 byte (`0x20`) to the PIC at the end of each handler, giving the handler full control over when the ISR bit is cleared. Automatic Rotation and Specific Rotation priority modes are not needed for AngelicKernel.

**Edge vs. level triggering.** The 8259 PIC supports both edge-triggered and 
level-triggered interrupt inputs. The e1000 uses a legacy PCI INTx line, which 
is level-triggered by the PCI specification — the IRQ line is held asserted until 
the device's interrupt cause is cleared. AngelicKernel does not read the ICR 
register in interrupt context — the MPK isolation boundary makes that impossible 
without a trampoline, which is not invoked from interrupt context by design. Instead, the handler sets `packet_pending = 1` and sends EOI; the main loop then calls `e1000_poll_receive` through the trampoline, which drains the descriptor ring by checking the DD (Descriptor Done) bit in each RX descriptor rather than consulting ICR.

**IDT gate types.** Three gate types are defined in the x86-64 architecture [IntelSDM, Vol. 3A §2.1.4]:

| Gate Type | Vector IF Flag | Use in AngelicKernel |
|-----------|---------------|----------------------|
| Interrupt Gate | Clears IF on entry (disables further interrupts) | **Used for all ISRs** |
| Trap Gate | Preserves IF (interrupts remain enabled) | Not used |
| Task Gate | Switches hardware task contexts via TSS | Not applicable (no TSS) |

Interrupt Gates are chosen for all ISR entries: the CPU automatically clears the IF flag on entry, preventing a re-entrant interrupt from corrupting the handler's stack before it has had a chance to save registers. The IDT register (IDTR) is loaded via the `LIDT` instruction with a 10-byte operand (limit + 64-bit base pointer).

**GDT and flat memory model.** AngelicKernel does not configure its own GDT. 
The flat 64-bit GDT established by UEFI firmware before `efi_main()` is called 
is used as-is: a code segment at selector 0x38 and a data segment covering the 
full 64-bit address space. The only GDT reference in the kernel is the hardcoded 
`kernel_cs = 0x38` in `idt_set_gate()`, which references the UEFI-provided code 
segment that the CPU switches to on interrupt entry.

**CR2 register and page fault handling philosophy.** When the CPU raises a page-fault exception (#PF, vector 14), it stores the *linear address* that caused the fault into the CR2 register before invoking the IDT handler [IntelSDM, Vol. 3A §2.5]. The error code pushed to the stack encodes: bit 0 (P — page present), bit 1 (W/R — write vs. read), bit 2 (U/S — user vs. supervisor), bit 4 (I/D — instruction fetch), and bit 5 (PK — protection-key violation). AngelicKernel's page-fault handler reads CR2 and the error code to classify the fault:

- **PK bit (bit 5) set:** MPK protection-key violation — expected during self-test. The handler clears the violation, increments the recovery counter, and resumes.
- **All other page faults:** treated as fatal kernel errors. The handler prints via serial and halts with `CLI; HLT`. There is no recovery for faults.

**PIC special modes not used.** The following 8259 PIC operating modes are not applicable to AngelicKernel's single-device workload and are explicitly not configured: Special Fully Nested Mode, Buffered Mode, Poll Mode (software-polling the ISR instead of hardware interrupt delivery), and Special Mask Mode [OSDev_PIC].

**Programmable Interval Timer (PIT).** The PIT (Intel 8253/8254) is not programmed by AngelicKernel. The TSC-based timestamp implementation provides sufficient timer resolution for lwIP retransmission timeouts.

**APIC (Advanced Programmable Interrupt Controller).** The Local APIC (LAPIC) and I/O APIC [OSDev_APIC] replace the dual-8259 PIC on modern UEFI systems. AngelicKernel uses the legacy 8259 PIC because it is simpler and works correctly.

---

## 4. MPK Driver Isolation: Full Implementation

### 4.1 Linker Section Placement

The linker script (linker.ld) carves two page-aligned subsections out of the standard .text and .data sections:

```
.text : {
    *(.text) *(.text.*) ...
    . = ALIGN(4096);
    __secure_driver_code_start = .;
    *(.secure_driver_code)
    . = ALIGN(4096);
    __secure_driver_code_end = .;
}
.data : {
    *(.rodata*) *(.got.plt) ... *(.bss) ...
    . = ALIGN(4096);
    __secure_driver_data_start = .;
    *(.secure_driver_data)
    . = ALIGN(4096);
    __secure_driver_data_end = .;
}
```

The macros SECURE_DRIVER_CODE and SECURE_DRIVER_DATA (in include/sys/mpk_sections.h) expand to __attribute__((section(".secure_driver_code"))) and __attribute__((section(".secure_driver_data"))). Every e1000 function carries SECURE_DRIVER_CODE; all DMA descriptor ring structures carry SECURE_DRIVER_DATA.

The `__secure_driver_*_start/end` symbols are declared `extern uint64_t` in vmm.c and consumed by `vmm_protect_driver()` and `mpk_diagnostic()`.

The linker script's use of `ALIGN(4096)` before and after each driver section is important. MPK protection keys apply to entire 4 KB pages — there is no sub-page granularity. If driver code were placed immediately adjacent to unprotected kernel code without alignment padding, both would share the same 4 KB page and any key assignment to that page would also restrict access to the neighbouring kernel code. The alignment constraint guarantees clean page boundaries on both sides of each driver section. The broader page-aligned section layout also collapses several standard ELF subsections — read-only data, global offset tables, initialised data, and uninitialised data — into a single consolidated data segment, which simplifies the `objcopy` translation step that produces the final PE32+ image.

### 4.2 Page Table Protection: vmm_set_pkey()

vmm_protect_driver() iterates in 4 KB steps over both section ranges, calling vmm_set_pkey(addr, 1) for each page:

```c
void vmm_set_pkey(uint64_t virt, int pkey) {
    uint64_t* pml4 = kernel_pml4;
    uint64_t* pdp  = (uint64_t*)(pml4[PML4_INDEX(virt)] & ~0xFFFull);
    uint64_t* pd   = (uint64_t*)(pdp [PDP_INDEX(virt)]  & ~0xFFFull);
    uint64_t* pt   = (uint64_t*)(pd  [PD_INDEX(virt)]   & ~0xFFFull);
    uint64_t* pte  = &pt[PT_INDEX(virt)];

    *pte &= ~(0xFULL << 59);
    *pte |=  ((uint64_t)pkey << 59);
    *pte |=  PTE_USER;

    __asm__ volatile("invlpg (%0)" :: "r"(virt) : "memory");
}
```

INVLPG invalidates the cached TLB entry for the modified virtual address on the current CPU core. Without it, the CPU may continue using a stale cached translation that does not reflect the updated PTE, including changes to protection key bits, until the entry is naturally evicted or refreshed.

### 4.3 The Assembly Trampolines (mpk.asm)

Five trampolines handle 0 through 4 arguments. The most-used is mpk_trampoline_3 (for e1000_poll_receive and e1000_send_raw, both taking 3 arguments):

```nasm
mpk_trampoline_3:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx

    xor ecx, ecx
    xor edx, edx
    xor eax, eax
    wrpkru

    mov rdi, r13
    mov rsi, r14
    mov rdx, r15
    call r12

    push rax
    xor ecx, ecx
    xor edx, edx
    mov eax, 0x0C
    wrpkru
    pop rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    ret
```

**Why save arguments before WRPKRU?** The System V AMD64 ABI passes arguments in RDI, RSI, RDX, RCX, R8, R9. WRPKRU requires ECX=0 and EDX=0, which zeros the second and third argument registers (RCX and RDX). If WRPKRU executed before saving arguments to callee-saved registers (R12-R15), a1 (RDX) and a2 (RCX) would be destroyed. Saving them to R12-R15 first preserves them across the WRPKRU boundary.

**PKRU_UNLOCK = 0x00000000** (not just clearing Key 1's bits). During a driver call, Key 0 pages (kernel stack, kernel data) must remain accessible so the trampoline can push/pop to the stack. Setting PKRU=0 makes all 16 keys accessible.

**The 4-argument trampoline** (mpk_trampoline_4) faces an additional constraint: R12, R13, R14, R15 are all consumed for func+a0+a1+a2, leaving no callee-saved register for a3 (which arrives in R8, a caller-saved register that would be clobbered by the indirect call). The solution is to push R8 onto the stack before WRPKRU and pop it into RCX (the fourth argument register) after WRPKRU.

The assembly module closes with an explicit non-executable stack annotation, marking the stack segment as non-executable in the ELF output. This is a defensive measure that prevents any exploit from treating the kernel stack as shellcode.

The trampoline call interface is surfaced through a header that provides four static inline wrappers — one each for driver initialisation, single-buffer transmit, scatter-gather transmit, and receive polling. These wrappers cast their arguments to a uniform type to match the trampoline signature, giving callers a typed function-call interface rather than requiring them to perform manual casts and trampoline selection at each call site.

### 4.4 Three-Tier MPK Correctness Verification

mpk_diagnostic() runs before the first XMPP connection is accepted and verifies isolation through three independent checks.

**Tier 1 — PKRU Register Readback.**
RDPKRU reads the live PKRU register (ECX must be 0). The diagnostic checks four cases:
- 0x0000000C: Key 1 fully locked (AD=1, WD=1) — correct.
- 0x00000000: All keys accessible — MPK not active; WRPKRU was never called.
- 0x00000004: Key 1 WD=1 but AD=0 — writes blocked but reads still allowed; only half the protection is in place.
- Any other value: configuration error.

**Tier 2 — PTE Walk.**
Using the exported kernel_pml4 pointer, the diagnostic walks the four-level page tables for every 4 KB page in both driver sections. For each page it reads bits [62:59] from the leaf PTE. It counts pages with key=1 (correct), wrong key, and unmapped pages. A section where pages_ok=0 and pages_wrong=0 indicates vmm_protect_driver() never ran or produced no output (empty sections).

**Tier 3 — Violation Self-Test.**
This tier deliberately issues a memory read into Key-1 memory without a trampoline, confirms the CPU raises a #PF, and recovers. The flow:

1. Set mpk_test_in_progress=1, mpk_test_fault_occurred=0.
2. Execute `mov (%rax), %al` (2-byte encoding 0x8A 0x00) on the first address of .secure_driver_data. The `"=a"(probe)` output constraint forces the 2-byte AL/RAX encoding.
3. The IDT page-fault handler in idt.c checks mpk_test_in_progress at the top, before any other action. If set, it: sets mpk_test_fault_occurred=1, clears mpk_test_in_progress, advances saved RIP by 2, returns from the interrupt.
4. After the inline asm: if mpk_test_fault_occurred==1, the isolation is confirmed active. If 0, the read succeeded without faulting — MPK is not working.

### 4.5 Paging Architecture and Control Register Roles

AngelicKernel uses the standard IA-32e four-level paging hierarchy [IntelSDM, Vol. 3A §4.5]:

```
CR3 → PML4 (Page Map Level 4, 512 entries)
        └→ PDPT (Page Directory Pointer Table, 512 entries)
              └→ PD (Page Directory, 512 entries)
                    └→ PT (Page Table, 512 entries)
```

Each level is a 4 KB page of 64-bit entries. The page-mapping routine walks this hierarchy, allocating new table pages from the physical memory allocator as needed. All tables are allocated with `PTE_PRESENT | PTE_WRITE | PTE_USER` — the `PTE_USER` bit is critical at every level because Intel SDM §4.6.2 requires U/S=1 in all entries for PKRU enforcement to apply to a leaf page.

**Control registers relevant to AngelicKernel** [IntelSDM, Vol. 3A §2.5]:

| Register | Bit / Field | Role |
|----------|------------|------|
| CR0 | bit 31 (PG) | Enables paging; set by UEFI long-mode entry before `efi_main()` |
| CR3 | [51:12] | Physical base address of the active PML4; written by `vmm_init()` |
| CR4 | bit 9 (OSFXSR) | Enables SSE instruction execution and FXSAVE/FXRSTOR for XMM registers; set by `enable_sse()` |
| CR4 | bit 10 (OSXMMEXCPT) | Enables #XM exception for unmasked SIMD FP exceptions; set by `enable_sse()` |
| CR4 | bit 22 (PKE) | Enables PKRU and WRPKRU/RDPKRU instructions; set by `mpk_enable()` |
| EFER | bit 11 (NXE) | Enables XD/NX bit in PTEs; set by UEFI before long mode [IntelSDM, Vol. 3A §2.2.1] |

**CR4.PKE (bit 22) — set by `mpk_enable()`.** The SDM defines this as: "Enables 
IA-32e paging to associate each linear address with a protection key. The PKRU 
register specifies, for each protection key, whether user-mode linear addresses 
with that protection key can be read or written. This bit also enables access to 
the PKRU register using the RDPKRU and WRPKRU instructions." Without this bit, 
any WRPKRU call raises #UD.

**EFER.NXE (bit 11) — set by UEFI.** Enables bit 63 of each PTE as the XD 
(Execute Disable) flag. When set on a page, any instruction fetch from that page 
raises #PF. UEFI enables NXE before calling `efi_main()`. [IntelSDM, Vol. 3A §2.2.1, Table 2-1].

**PAT (Page Attribute Table)** [IntelSDM, Vol. 3A §11.12]. The PAT MSR (0x277) 
maps each combination of PAT/PCD/PWT bits in a PTE to a memory type. It is 
always active with no separate enable bit. AngelicKernel never writes the PAT 
MSR, so the power-on defaults apply: PA0=WB, PA3=UC. All pages are mapped with 
PAT=PCD=PWT=0, selecting PA0=WB — correct for RAM. UEFI's MTRR configuration 
marks the e1000 MMIO BAR as UC, which takes precedence over the PAT for those 
addresses, so no explicit PTE caching flags are needed.

**TLB management.** The TLB is a hardware structure — software cannot read or 
write individual entries directly. After any PTE modification, software must issue 
`INVLPG <addr>` to force the CPU to discard the cached translation for that 
address [IntelSDM, Vol. 3A §2.8.4]. AngelicKernel issues `INVLPG` in 
`vmm_set_pkey()` after every PTE modification.

### 4.6 Physical Memory Allocator

**Memory allocation taxonomy [OSDev_ProgramMemAllocTypes].** Four categories of memory allocation exist in a kernel; AngelicKernel handles each differently:

| Category | Mechanism | AngelicKernel Treatment |
|----------|-----------|------------------------|
| Global / static memory | Linker (`.data`, `.bss` sections) | All XMPP state, lwIP pools, mbedTLS pool — placed by linker, zero-init at startup |
| Read-only constants | Linker (`.rodata` section) | String literals, lookup tables |
| Stack memory | CPU stack pointer; set up before `efi_main()` | UEFI firmware establishes the initial stack; kernel does not re-establish it |
| Dynamic heap memory | PMM bump allocator | Page-table pages only; no general-purpose heap |

**Current design — linear bump allocator.** The physical memory allocator maintains a single global pointer marking the start of unallocated memory. Each allocation request returns the current pointer value and advances it by PAGE_SIZE (4 KB). Each returned page is zero-initialised before being handed to the caller. The allocator is O(1) and produces no fragmentation, making it appropriate for a system with no dynamic heap. Its fundamental limitation is that memory cannot be freed — the pointer never retreats.

The floor at physical address 0x200000 (2 MB) is a deliberate constraint. Below it risks overlapping with kernel image placement or firmware-reserved regions.

**No virtual address allocator.** The identity map covers the entire first 4 GB, so every physical address is also a valid virtual address.

**Sub-page allocation limitation.** Every allocation from the physical memory allocator consumes exactly one 4 KB page, regardless of how many bytes are actually needed. The lwIP memory pool, mbedTLS pool, and XMPP static arrays are all declared as C global arrays and placed in BSS by the linker — they do not go through the PMM at all. The PMM is used only to allocate page-table pages. This means the sub-page allocation limitation has no practical impact on the current codebase.

**Alternatives surveyed for future work [OSDev_MemAlloc] [OSDev_BrendanMMGuide]:**

| Allocator |
|-----------|
| Linear bump (current) |
| Stack/list of pages |
| Bitmap |
| Buddy system |
| Slab allocator |
| Linked-list heap |

Recursive paging (mapping the PML4 into itself as one of its own entries) is an alternative page-table traversal strategy that would allow the kernel to access any PTE via a fixed virtual address formula without the current explicit four-level walk. It is not implemented but is a future optimisation [OSDev_RecursivePaging].

### 4.7 Virtual Memory Manager

The virtual memory manager initialises the kernel's own four-level page tables and provides the per-page key-assignment interface that the MPK isolation scheme depends on.

During initialisation, a fresh PML4 table is allocated from the physical memory allocator and the entire first 4 GB of physical address space is identity-mapped — every virtual address maps to the same physical address. All pages are mapped with the present, writable, and user-mode flags set. Setting the user-mode flag across the entire mapping — including all four levels of each page table hierarchy — is the step that makes PKRU enforcement possible: as stated in Intel SDM §4.6.2, protection key checks only apply to pages where the user-mode bit is set in every ancestor table entry. Once the tables are built, the PML4 base address is written into CR3, and from that point forward every memory access resolves through mappings the kernel controls rather than whatever UEFI left behind.

The page-mapping routine walks the four-level hierarchy — PML4, PDPT, PD, PT — allocating a new 4 KB table page from the physical memory allocator for any level that has not yet been populated, then writes the physical address and flags into the appropriate leaf entry.

The key-assignment routine applies an MPK protection key to a single 4 KB page. It walks the live page tables to the leaf entry for the target virtual address, clears bits [62:59] (the protection key field), writes the new key into those bits, sets the user-mode flag (which is required for PKRU enforcement to apply), and issues INVLPG to flush the cached TLB translation for that address. Without the TLB flush, the CPU may continue using a stale cached version of the old entry.

The driver-protection pass iterates over the address ranges bounded by the linker-provided start and end symbols for both the driver code section and the driver data section, applying Key 1 to every 4 KB page within those ranges. Adding or removing source files annotated with the driver section attribute automatically changes the protected range without any manual address tracking.

---

## 5. Network Stack

### 5.1 lwIP in NO_SYS=1 Mode

lwIP 2.x runs in NO_SYS=1 mode: no threads, no blocking sockets, no separate timer thread. The entire network stack runs inside the cooperative event loop. Key configuration values:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| NO_SYS | 1 | No OS |
| MEM_LIBC_MALLOC | 0 | No malloc; static heap |
| MEM_SIZE | 128 × 1024 | 128 KB static lwIP heap |
| MEMP_MEM_MALLOC | 0 | Static pool |
| TCP_MSS | 1460 | Ethernet MSS |
| PBUF_POOL_SIZE | 64 | Receive pbufs |

The lwIP timestamp function reads the TSC and divides by 2,000,000 (assuming 2 GHz TSC) to return milliseconds for lwIP's TCP retransmission timers.

**Detailed lwIP pool configuration.** The static memory pool is set to 128 KB, which accommodates all simultaneous TCP connections, pending acknowledgements, and ARP table entries within a predictable footprint. The pbuf pool is configured with 16 pointer-only pbuf slots and 64 pool pbufs each with an attached data buffer. The TCP connection pool is sized to 16 entries, capping simultaneous XMPP sessions at 16 since each connection consumes exactly one entry holding the full TCP state. The transmit segment pool is set to 64 slots shared across all connections, providing capacity for data sitting in send and retransmit queues awaiting acknowledgement.

The TCP maximum segment size is set to 1460 bytes (the standard value for Ethernet with 20-byte IP and 20-byte TCP headers within a 1500-byte MTU). Both the receive window and the send buffer are set to eight times the MSS, giving 11,680 bytes — large enough for OMEMO key bundles.

**Disabled lwIP subsystems.** ARP, Ethernet, IPv4, TCP, UDP, and ICMP are enabled. DHCP is disabled because the kernel uses a static IP address. The NetConn and socket APIs are disabled because they require OS threading abstractions unavailable in a NO_SYS=1 build. DNS is disabled because the kernel never initiates outbound connections by name — clients resolve `angelic.local` on their own machines before connecting, and the kernel sees only raw IP addresses. The checksum generation and verification flags are all enabled.

**lwIP porting contract.** Three header files constitute the porting contract between lwIP and the bare-metal environment:

The type-mapping header maps lwIP's internal type names onto the platform's fixed-width integer types. The pointer arithmetic type is mapped to `uintptr_t` rather than a fixed-width type so that pointer arithmetic inside lwIP's memory allocator is always the correct width. The byte-order macro is set to `LITTLE_ENDIAN`. The structure-packing macros use GCC's `__attribute__((packed))` on the struct itself, which is sufficient and avoids the need for per-field or pragma-based packing. The random number source is aliased to the kernel's TSC-based timestamp function. Diagnostic output is routed through the kernel's serial-backed printf, and assertion failures print to serial and halt with CLI; HLT.

The architecture-abstraction header satisfies lwIP's threading abstraction requirements for the NO_SYS=1 build mode. The mailbox and semaphore null values are defined. The critical-section protection type and hooks are defined as no-ops, since in a single-threaded kernel there is nothing to protect against between lwIP calls.

### 5.2 Receive Path

Hardware interrupt delivery chain.

The precise ordering is what makes the receive architecture safe:
1.  Packet arrives on the wire

2.  NIC converts electrical signals into an Ethernet frame

3.  NIC DMA-writes the frame bytes into rx_ring[i].addr

4.  NIC DMA-writes DD=1 into rx_ring[rx_idx].status

5.  Interrupt fires

6.  CPU vectors through the IDT to interrupt_handler()

7.  interrupt_handler() sets packet_pending=1, sends EOI, returns

8.  Main loop sees packet_pending, clears it

9.  angelic_netif_poll() via mpk_trampoline_3

10. e1000_poll_receive() reads DD=1, copies frame out of DMA buffer

11. lwIP: ethernet_input → ip4_input → tcp_input → xmpp_recv_callback

The NIC hardware guarantees steps 3 and 4 complete before step 5. By the time interrupt_handler() executes, the frame is already sitting in RAM — the interrupt is not a signal that a packet is arriving, it is a signal that a packet has arrived.

Three independent subsystems cooperate to deliver a packet from the NIC to the application layer. The e1000 NIC has no knowledge of the IDT — when a packet arrives, it simply raises its IRQ line on the PCI bus. The 8259 PIC receives that signal, translates it to a vector number by adding the remapping offset of 32, and asserts the CPU's interrupt pin. The CPU looks up that vector in the IDT, finds the stub installed by init_idt(), and jumps to interrupt_handler(). The handler sets packet_pending = 1 and sends EOI back to the PIC so it can deliver future interrupts, then returns immediately without touching the NIC or lwIP. The main loop later sees the flag, clears it, and calls the network polling function through the MPK trampoline to drain the NIC ring.

The e1000 raises a PCI IRQ on packet receipt. The IDT handler sets `volatile int packet_pending = 1` and returns immediately — no lwIP processing in interrupt context. The event loop detects packet_pending, clears it first, then calls the receive poll function up to 4 times per burst.

The network receive poll calls the driver's receive function through the MPK trampoline. If a packet is available, it allocates a pbuf from the static pool, copies the bytes in, and calls the network interface input function, which chains through ethernet_input → ip4_input → tcp_input → xmpp_recv_callback(). If pbuf allocation fails or the input function returns an error, the pbuf is freed immediately to prevent pool exhaustion rather than leaving a leaked slot.

The network interface initialisation callback sets the interface name, registers the IP and link-layer output functions, sets the MTU to 1500 bytes, and raises the broadcast, ARP, and link-up flags. The MAC address is not set inside the callback — it is written directly into the interface structure before registration is called, because the MAC address is available from the driver initialisation output and passing it through the callback would require an additional state variable.

### 5.3 Transmit Path: Zero-Copy Scatter-Gather

The link-layer output callback counts pbuf chain fragments. For chains of up to MAX_TX_SEGS=8 fragments it builds a scatter array of (address, length) pairs directly from the pbuf chain and passes it to the transmit function through the MPK trampoline. No data is copied.

For unusually deep chains (more than 8 fragments), a static fallback buffer `tx_buffer_fallback[1514]` is used: the chain is flattened via memcpy, then sent through the single-buffer transmit trampoline.

### 5.4 e1000 NIC Driver: Hardware Initialisation Sequence

The Intel 82540EM (e1000) is initialised before ExitBootServices() for BAR discovery, then fully configured after vmm_init() completes [IntelE1000]. The sequence:

1. **PCI bus scan.** The PCI scanner iterates bus/device/function triples writing to I/O port 0xCF8 (CONFIG_ADDRESS) and reading from 0xCFC (CONFIG_DATA), searching for vendor ID 0x8086 / device ID 0x100E. On match, BAR0 (Base Address Register 0) yields the MMIO base address for the NIC's register file.

2. **MMIO base extraction.** BAR0 is a 32-bit or 64-bit memory BAR. The lower 4 bits (type flags) are masked off with `& ~0xF` to get `global_mmio_base`. All subsequent register accesses use `volatile uint32_t *` reads/writes to this base plus fixed offsets. The `volatile` qualifier is mandatory — without it, GCC may reorder MMIO reads/writes.

3. **MAC address detection.** The hardware MAC is read from the Receive Address Low (RAL) and Receive Address High (RAH) registers in the NIC EEPROM. RAL holds bytes 0–3 of the MAC; RAH holds bytes 4–5 plus a validity bit. If RAH bit 31 is clear, the address is invalid.

4. **RX/TX descriptor rings.** Both rings are allocated from the PMM: 32 descriptors each, statically sized at 16-byte alignment per descriptor. The Receive Descriptor Base Address Low/High registers point to the physical address of the RX ring; RDLEN holds ring size in bytes; RDH and RDT are the hardware head and software tail pointers. The NIC advances RDH on successful receipt; software advances RDT to hand new descriptors back. TX ring configuration is symmetric: TDBAL/TDBAH/TDLEN/TDH/TDT.

5. **Interrupt mask.** The Interrupt Mask Set register (IMS) enables two cause bits: bit 7 (RXT0 — Receiver Timer Interrupt, fires after a configurable delay following packet receipt) and bit 2 (LSC — Link Status Change). The Interrupt Cause Read (ICR) register is read at the start of every IRQ handler; reading it atomically clears all set bits, deasserts the PCI INTx line, and returns the bitmask of pending causes.

**Detailed hardware initialisation sequence.** The driver performs a software reset by setting and polling the reset bit in the control register, which returns all hardware state to power-on defaults. After reset, three control bits are set: full-duplex mode, the link-up enable bit (required for the link to come up at all), and auto-speed detection. The 128-entry multicast table array is zeroed before the receiver is enabled to prevent spurious frame delivery. The transmit inter-packet gap register is set to the IEEE 802.3 standard values (IPGT=8, IPGR1=4, IPGR2=6), producing the standard 96-bit inter-frame gap. The receive control register enables the receiver, accepts multicast and broadcast frames, sets 2 KB receive buffers, and strips the 4-byte Ethernet CRC so the upper layer never sees it. The transmit control register enables the transmitter, pads short frames to the 64-byte Ethernet minimum, and sets the collision threshold and distance for full-duplex operation. The sequence ends by clearing any interrupts that arrived during initialisation (via the read-to-clear interrupt cause register) and arming three interrupt causes: packet received, receive ring overrun, and link status change.

All driver state — the descriptor rings, the MMIO base address, and the transmit tail index — resides in the `.secure_driver_data` section, placing it under MPK Key 1 protection. All register-access helpers reside in the `.secure_driver_code` section.

**Scatter-gather transmit.** The multi-segment transmit variant maps each element of a scatter array to a separate TX descriptor. The EOP (End of Packet) flag is set only on the last descriptor, telling the NIC that the entire logical frame spans all segments. This avoids the memcpy flatten that the single-buffer fallback path performs for deep pbuf chains.

**Receive polling.** The receive poll function checks whether the next descriptor in the ring has been filled by the NIC by testing the Descriptor Done bit. If no frame is ready it returns immediately. If a frame is ready it copies the data out of the DMA buffer, clears the descriptor status back to zero, advances the software receive index, issues a compiler memory barrier to prevent the descriptor stores from being reordered past the register write, and writes the old index to the receive tail register to return the recycled descriptor slot to the hardware.

**lwIP driver glue (bare-metal porting).** The lwIP Ethernet driver interface requires four functions [lwIPBMPort]:

| Function | Role |
|----------|------|
| `low_level_init()` | Calls e1000 init; sets `netif->hwaddr`, `netif->mtu` |
| `low_level_output()` | Called by ARP / IP to send one frame; routes through MPK trampoline to `e1000_send_raw()` |
| `low_level_output_zerocopy()` | Extended variant; passes pbuf scatter list through trampoline to `e1000_send_scatter()` |
| `low_level_input()` / `angelic_netif_poll()` | Polls the RX descriptor ring through trampoline; wraps received bytes in a pbuf |
| `ethernetif_init()` | Registers the netif and calls `low_level_init()` |
| `ethernet_input()` | Called on received pbuf; dispatches ARP vs. IPv4 |

The porting contract (`lwipopts.h`, `cc.h`, `sys_arch.h`) configures lwIP for the bare-metal environment: no threads, no locking primitives (`SYS_LIGHTWEIGHT_PROT=0`), no dynamic allocation beyond the static pool [lwIPBMPort] [OSDev_lwIP].

### 5.5 PCI Bus Scanner

The PCI scanner accesses configuration space through the two-port I/O mechanism present on every x86 system: a 32-bit address word is written to the address port at 0xCF8 (with bit 31 set as an enable flag), and the data register at 0xCFC is read back. The address word encodes bus number (bits 23:16), device number (bits 15:11), function number (bits 10:8), and the DWORD-aligned register offset (bits 7:2).

Before any BAR is accessed, the scanner enables both the Memory Space bit and the Bus Master bit in the device's PCI Command register. The Memory Space bit must be set before the device's MMIO registers become reachable by the CPU; the Bus Master bit must be set before the device can issue DMA transactions. Neither bit is guaranteed to be set after hardware reset, and firmware may not have set them during POST.

The full scan iterates all 256 buses, 32 devices, and 8 functions. An ID of 0xFFFF in the vendor field means no device is present (the data bus is floating). If function 0 of a slot has the multi-function bit clear in its Header Type register, the device is single-function and functions 1–7 are guaranteed not to exist; the inner loop breaks early rather than issuing seven unnecessary reads per empty slot. On a match, BAR0 is read and the four attribute bits are masked off to yield the physical base address.

The NIC detection entry point iterates over a compile-time table of supported Intel 8254x-series vendor/device ID pairs, stopping at the first match and optionally writing the matched device ID into an output pointer so the boot log can report which physical chip was detected.

### 5.6 Storage Subsystem

All persistent XMPP state is written to a 1 MB raw disk image attached as a secondary drive. The storage abstraction layer selects between two backend drivers at boot time, trying the higher-performance option first and falling back to a fallback if it is unavailable.

**AHCI DMA driver.** The AHCI driver targets a single data drive on the first port with a connected ATA device and uses command slot 0 exclusively for polled DMA transfers with no interrupt-driven completion, no native command queuing, and no port multiplier support.

The driver begins by scanning the PCI bus for a Mass Storage SATA controller (class 0x01, subclass 0x06, interface 0x01). On a match it enables both Memory Space and Bus Master in the device's PCI Command register and reads BAR5 to obtain the AHCI Base Address Register. The BIOS/OS ownership handoff is performed if the controller supports it: the driver sets the OS-Owned Semaphore in the BOHC register and polls until the BIOS-Owned Semaphore and BIOS Busy bits clear. AHCI mode is enabled via the GHC register, and the controller is reset; the GHC.AE bit is re-asserted after the reset because the reset may have cleared it.

Port initialisation checks the physical link status (requiring DET=3, meaning device present with PHY communication established, and IPM=1, meaning the interface is in the active power state) before doing any further work. The DMA engine is stopped by clearing the command start bit and waiting for the command running indicator to clear, then stopping the FIS receive engine similarly. The command list base and FIS receive area base registers are programmed with the physical addresses of statically allocated structures. All three DMA structures are zeroed after the port registers are written, since the controller may begin accessing them as soon as FIS receive is re-enabled. After clearing stale error and interrupt status bits, the port is optionally powered and spun up (if the controller reports staggered spin-up support), a COMRESET is issued to re-establish the PHY link, and the driver verifies the port signature register to confirm an ATA rather than ATAPI device. The DMA engine is then started and the driver waits for the drive to report ready before returning.

The core transfer function waits for the drive to be not-busy and not in data-request mode before building the command, constructs a full Host-to-Device Register FIS in the command table, sets a single PRDT entry covering the entire transfer buffer (with the byte count field set to buffer size minus one, per the AHCI specification), and issues the command by writing to the port command issue register. Write completions call a cache-flush routine that issues ATA FLUSH CACHE EXT (opcode 0xEA) to force the drive's volatile write-back cache to persistent media. The flush is non-fatal: a failure prints a warning but the write return value reflects the DMA result.

**ATA PIO driver.** Where AHCI communicates with the drive indirectly through a controller and DMA, ATA PIO has the CPU talk directly to the drive through a fixed set of I/O ports. Every byte of every sector passes through the CPU, making PIO significantly slower than DMA for large transfers but requiring no memory structures and no controller initialisation — just port reads and writes, which work unconditionally on any x86 machine.

The primary IDE channel is accessed through the command block at 0x1F0–0x1F7 and the control block at 0x3F6. The data port at 0x1F0 is 16 bits wide and is the only port through which sector data flows. The Alternate Status register at 0x3F6 carries identical content to the main Status register but reading it does not acknowledge a pending interrupt, making it safe to poll during PIO transfers without accidentally signalling the PIC.

A 400-nanosecond delay is required after writing the Command or Drive/Head register before the status bits are valid. This delay is implemented by reading the Alternate Status register four times and discarding the results; each I/O port read takes approximately 100 nanoseconds, so four reads produce the minimum required delay without needing a timer.

Probing for drives uses the IDENTIFY DEVICE command. Before waiting for the data-ready bit, the driver checks the LBA Mid and High registers: if those registers contain 0x14 and 0xEB respectively, the device is ATAPI (optical drive) and is skipped, since the kernel has no SCSI packet layer. For confirmed ATA drives, the 256-word IDENTIFY response is read and the model string and sector count are extracted and printed to serial.

After all sectors are written, a FLUSH CACHE command (opcode 0xE7) is issued and its timeout is treated as a fatal error, reflecting the more synchronous nature of PIO operation.

**Storage abstraction layer.** The disk abstraction layer tries AHCI first. If that initialisation succeeds, the backend is locked in. If AHCI is unavailable, it falls back to ATA PIO and checks whether the data drive (the secondary device on the primary IDE channel, as defined by a compile-time constant) is present in the probed drive bitmask. If neither backend produces a usable drive, the backend is set to a no-storage sentinel value and persistence is disabled for the session; the server operates without durability rather than refusing to start.

---

## 6. XMPP Server Implementation

### 6.1 Connection Lifecycle

Each TCP connection accepted on port 5222 gets a slot in client_registry[MAX_USERS] (global array, BSS zero-initialised). The accept callback advances a round-robin index. If the slot has a live PCB (previous occupant did not close cleanly), it releases any active TLS session and closes the TCP connection before reuse. The slot is then zeroed with memset() — without this, stale receive buffer contents, accumulated byte count, protocol state, authentication flag, username, and full JID from the previous occupant persist, causing the new client to inherit the old session state.

**Capacity constants.** The server's capacity limits are defined as compile-time constants. The room count, occupants per room, nick length, room name length, and maximum user count are all adjustable at compile time and chosen for the embedded target's memory constraints. XEP-0045 sets no numeric caps on room or occupant counts; these values are implementation-defined. The per-room ban list is capped at eight entries. The TLS input staging buffer is sized at 32 KB per connection, providing the encrypted input buffer that the STARTTLS layer drains into the mbedTLS decryption engine. The SASL failure counter caps consecutive authentication attempts at five before the server terminates the stream with a policy-violation error, satisfying the brute-force protection guidance in RFC 6120 §6.4.5.

**Stanza type enumeration.** A compile-time enumeration maps every stanza kind the server handles to a named integer constant, avoiding repeated string comparisons against raw XML attribute values in handler code. The four legal IQ type values (get, set, result, error) from RFC 6120 §8.2.3 each have their own constant. Presence subtypes — unavailable, subscribe, subscribed, unsubscribe, unsubscribed, and probe — are each resolved to distinct constants at parse time rather than sharing a single generic presence constant. This means every handler receives a fully typed stanza and never needs to inspect the raw type attribute string to distinguish, for example, a subscription request from an availability update.

xmpp_client_ctx_t holds:

| Field | Purpose |
|-------|---------|
| pcb | lwIP TCP PCB; NULL = slot free |
| state | Current protocol state |
| rx_buffer[4096] | Receive ring for XML stream |
| tls_ctx | Per-session mbedTLS context |
| tls_established | 1 = TLS handshake complete |
| tls_want_write | 1 = TLS handshake stalled, retry needed |
| authenticated | 1 = SASL succeeded |
| username[32] | Authenticated localpart |
| full_jid[96] | Full JID post-binding |
| initial_presence_sent | 0 = first available presence not yet seen |
| sm_enabled | XEP-0198 active |
| sm_stanzas_in/out | Stanza counts for acknowledgement |
| sm_want_ack | Deferred ack request flag |

The protocol state machine:

```
STATE_CONNECTED    TCP accepted; awaiting <stream:stream>
STATE_STARTTLS     Offering STARTTLS; TLS handshake in progress
STATE_SASL         TLS established; SASL negotiation in progress  
STATE_AUTHENTICATED SASL succeeded; awaiting stream re-open
STATE_BIND         Post-SASL features sent; resource binding in progress
STATE_SESSION      Session IQ accepted; XEP exchange allowed
STATE_READY        Full session active; all stanza types accepted
```

**State machine design rationale.** The connection state machine tracks each client through the mandatory negotiation order imposed by RFC 6120 §4. The state values are assigned in ascending order so that a single integer comparison is sufficient to enforce minimum-state requirements: a stanza arriving before the connection has reached the appropriate phase is rejected with a single comparison against the routing table's minimum-state field rather than a chain of conditional checks. The STARTTLS state routes incoming bytes to the TLS staging buffer rather than the XML receive buffer; on handshake completion the state returns to STATE_CONNECTED with the TLS-established flag set, because RFC 6120 §5.2 mandates that both sides reset the XML stream after TLS completes — the next bytes from the client will be a fresh stream opening, not a continuation of the pre-TLS stream. The post-authentication states (STATE_BIND and STATE_SESSION) gate resource binding and session establishment respectively, with STATE_SESSION serving as the terminal state through which all normal stanza exchange is permitted.

**Credential store.** The authentication backing store for SASL PLAIN is a compile-time array of username and password string pairs. Adding a user requires editing this array and recompiling. SASL ANONYMOUS bypasses the table entirely; any client selecting that mechanism is admitted and assigned the default username "user". The ANONYMOUS mechanism is accepted but not advertised in the server's stream features block; only PLAIN appears in the features advertisement.

**MUC data structures.** The room structure owns an array of participant slots, a ban list of bare JIDs, and a set of boolean configuration flags persistent, moderated, and members-only. The creator JID is stored separately from the participant list so that affiliation queries can return the correct owner. The semi-anonymous flag controls the XEP-0045 §7.2.3 anonymity mode: in semi-anonymous mode, real JIDs are visible only to moderators and the owner. The locked flag implements the XEP-0045 §10.1 locked-room state: a newly created room must remain locked until the owner submits a configuration form or an instant-room request. A participant structure binds a TCP connection reference to an occupant's nick and real bare JID.

**Offline and subscription queues.** The offline message store and pending subscription queue are each declared with external linkage so the persistence layer can access them directly and write them to disk. The offline message store holds queued messages with their sender JID, recipient bare JID, extracted local-part, stanza ID, and verbatim payload. The pending subscription queue holds subscription stanzas that arrived while their target user had no active session.

**Private storage and roster.** The private XML storage implements per-user, per-namespace XMLs for XEP-0049, keyed on the inner child element's namespace. The roster store holds per-user contact entries each represented as raw `<item/>` XML. A monotonically incrementing version counter is returned as the `ver=` attribute in roster results per RFC 6121 §2.6, allowing clients to skip a full roster download when their cached version matches.

### 6.2 Three-Phase Stream Negotiation

RFC 6120 mandates a mandatory negotiation sequence. AngelicKernel enforces each step:

**Phase 1 — STARTTLS (RFC 6120 §5):**
Client opens stream -> Server sends features with `<starttls><required/></starttls>` as the sole feature (STARTTLS is mandatory per RFC 6120 §5.3.2 — no other features offered yet) -> Client sends `<starttls/>` -> Server sends `<proceed/>`, enters STATE_STARTTLS -> TLS handshake runs across one or more recv callbacks -> Completion sets tls_established=1, state returns to STATE_CONNECTED, both parties re-open the XML stream.

**Phase 2 — SASL (RFC 6120 §6):**
Client re-opens stream over TLS -> Server offers `<mechanisms><mechanism>PLAIN</mechanism></mechanisms>` (only after TLS — never on cleartext, per RFC 6120 §13.8.4) -> Client sends `<auth mechanism='PLAIN'>BASE64</auth>` -> Server decodes base64 as {authzid NUL authcid NUL passwd} per RFC 4616 §2 -> Checks (authcid, passwd) against xmpp_credentials[] -> Failure: `<not-authorized/>` (RFC 6120 §6.5) -> Bad base64: `<incorrect-encoding/>` (RFC 6120 §6.5.5) -> Wrong mechanism: `<invalid-mechanism/>` (RFC 6120 §6.5.7) -> Success: `<success/>`, state=STATE_AUTHENTICATED.

**Phase 3 — Bind and Session (RFC 6120 §7):**
Client re-opens stream -> Server offers `<bind/>` and `<sm/>` -> Client sends bind IQ -> Server generates full JID (username@angelic.local/resource), state=STATE_BIND -> Client optionally sends session IQ -> Server responds.

**Stream-open handler implementation.** The stream-open handler generates a unpredictable stream ID on every invocation by calling the hardware-entropy-backed random source, satisfying the RFC 6120 §4.7.3 requirement that stream IDs be hard to predict. The `to=` attribute in the server's response header is built from the client's supplied `from=` value if one was present, or omitted entirely if the client did not supply one, as required by RFC 6120 §4.7.2. Attribute extraction from the stream opening tag handles both single- and double-quoted attribute values.

The connection teardown helper sends `</stream:stream>`, tears down TLS if active (writing the close tag through the encrypted channel, flushing the TCP send buffer, and sending a TLS close_notify alert before freeing the session context), and closes the TCP connection.

**Receive callback dispatch.** The lwIP receive callback drives the entire parse-route loop for each connection. When the connection pointer is null, the remote side has closed and the slot is reset. For active TLS handshake traffic, the full pbuf chain is acknowledged immediately and each fragment is fed to the TLS handshake step function. For established TLS, the pbuf chain is decrypted into the receive buffer through the mbedTLS session; the raw encrypted bytes are never copied into the receive buffer directly. For plaintext connections, the pbuf chain is copied with overflow detection — a buffer overflow sends a policy-violation stream error and closes the connection per RFC 6120 §4.9.3.14 rather than silently discarding data. Leading whitespace is stripped from the receive buffer before each parse attempt, handling the RFC 6120 §11.7 whitespace keepalive that some clients send between stanzas.

### 6.3 Routing Table and JID Spoofing Prevention

xmpp_route_stanza() performs a linear scan of 14 routing table entries. Each maps a namespace URI to a handler function and minimum required state:

```c
static struct route_entry router[] = {
    { "urn:ietf:params:xml:ns:xmpp-bind",       handle_core_bind,       STATE_BIND    },
    { "urn:ietf:params:xml:ns:xmpp-session",     handle_core_session,    STATE_AUTHENTICATED },
    { "jabber:iq:roster",                         handle_roster_request,  STATE_SESSION },
    { "http://jabber.org/protocol/disco#info",    handle_disco_info,      STATE_SESSION },
    { "http://jabber.org/protocol/disco#items",   handle_disco_items,     STATE_SESSION },
    { "http://jabber.org/protocol/muc",           handle_muc_presence,    STATE_SESSION },
    { "http://jabber.org/protocol/muc#owner",     handle_muc_owner,       STATE_SESSION },
    { "jabber:iq:private",                        handle_private_storage, STATE_SESSION },
    { "http://jabber.org/protocol/muc#admin",     handle_muc_admin,       STATE_SESSION },
    { "urn:xmpp:blocking",                        handle_blocklist,       STATE_SESSION },
    { "vcard-temp",                               handle_general_success, STATE_SESSION },
    { "jabber:iq:version",                        handle_version,         STATE_SESSION },
    { "jabber:iq:last",                           handle_last,            STATE_SESSION },
    { "urn:ietf:params:xml:ns:xmpp-ping",         handle_ping,            STATE_SESSION },
    { NULL, NULL, 0 }
};
```

The urn:ietf:params:xml:ns:xmpp-sasl namespace is intentionally absent. SASL `<auth>` stanzas are dispatched directly in the receive callback only when the state is STATE_CONNECTED or STATE_SASL. If the SASL entry were in the routing table with min_state=STATE_CONNECTED, an already-authenticated client in STATE_READY could send a stanza with xmlns=xmpp-sasl, match the entry (STATE_READY >= STATE_CONNECTED), and invoke the SASL handler — overwriting the authenticated username and credential flag on a live session. With the entry absent, such a stanza returns `<service-unavailable/>` (RFC 6120 §8.3.3.19).

Resource binding is similarly constrained: STATE_BIND is used as the minimum for the bind namespace rather than STATE_CONNECTED, so that a bind IQ arriving before the post-SASL stream re-open completes receives `<unexpected-request/>` rather than being silently dropped. An additional explicit maximum-state guard inside the bind handler separately blocks re-binding once the connection reaches STATE_SESSION, a case the minimum-state check alone cannot prevent since STATE_SESSION is numerically higher than STATE_BIND.

**JID spoofing prevention (RFC 6120 §8.1.2):** Before any handler is invoked, the dispatcher overwrites the stanza's sender field with the server-assigned full JID stored in the connection context, regardless of whatever `from=` attribute the client supplied. This operation protects all 14 handlers simultaneously.

**Fallback dispatch.** When no routing table entry matches a stanza's namespace, the dispatcher falls through to a type-based fallback gated on STATE_SESSION. Chat messages reach the message handler through this path because a `<message>` stanza's namespace is always `jabber:client` regardless of whether it is a direct chat or a groupchat — the stanza type distinguishes them, not the namespace. Presence routing is the most branched section of the fallback: the target address determines whether the stanza goes to the MUC presence handler or the broadcast presence handler; the initial-presence flag on the connection context further determines whether the first available presence triggers offline-message drain and pending-subscription delivery. Unrecognised IQ get or set stanzas in the fallback path receive `<service-unavailable/>`, and the stanza ID is included in the error response only when it was present on the inbound stanza — when absent, it is omitted entirely rather than echoed as an empty string, per RFC 6120 §8.1.3.

When the routing table state guard fires on an IQ get or set, the dispatcher constructs an `<unexpected-request/>` error and sends it rather than dropping the stanza, satisfying the RFC 6120 §8.2.3 requirement that every IQ get or set receive either a result or an error. Non-IQ stanzas that fail the state guard are silently dropped.

### 6.4 XML Parsing

Stanzas are parsed by a modified yxml streaming parser [yxml]. The parser fills xmpp_stanza_t: name[64], xmlns[128], type[32], id[64], to[96], from[96], payload[1024].

A SIMD-accelerated variant (yxml_sse.c) uses SSE 4.2 PCMPISTRI for substring searches in large stanzas, compiled with -msse4.2 separately from the rest of the kernel.

The static stanza pool holds MAX_STANZAS entries. If the allocator finds no free slot, the receive callback sends `<stream:error><resource-constraint/></stream:error>` and closes the connection (RFC 6120 §4.9.3.17).

**Alternative XML parsers surveyed.** Three other parsers were evaluated before selecting yxml:

| Parser | Streaming? | Bare-metal? | Verdict |
|--------|-----------|-------------|---------|
| yxml (current) [yxml] | Yes | Yes — zero stdlib deps | Selected |
| Mini-XML (mxml) [mxml] | Partial | Requires malloc | Rejected |
| libexpat [libexpat] | Yes | Requires POSIX | Rejected |

yxml was chosen because it is a single-file streaming parser with zero stdlib dependencies, making it trivially portable to a freestanding environment. Mini-XML supports a pull-parser API but requires `malloc()` for the tree; libexpat is a production-grade streaming parser but pulls in POSIX I/O headers.

**Three-phase parse pipeline.** The parser accepts a raw byte buffer accumulated from one or more TCP deliveries and returns a fully populated stanza structure on each complete stanza boundary, advancing the caller's buffer pointer by exactly the number of bytes consumed.

The stanza boundary is located by a depth-counting scanner that tracks open and close tags, distinguishes self-closing tags by testing whether the character before `>` is `/`, and skips processing instructions and declarations by consuming to the next `>` on encountering `<?` or `<!`. The scanner returns the byte offset one past the closing `>` of the root element, or a sentinel value if the buffer ends before the element is complete. Leading whitespace is skipped and its byte count reported to the caller so that RFC 6120 §11.7 keepalive whitespace is drained without waiting indefinitely.

This boundary scanner has a SIMD-accelerated path that uses the SSE4.2 PCMPISTRI instruction to compare sixteen bytes simultaneously against the five XML structure characters (`<`, `>`, `/`, `!`, `?`) in a single clock. When no match is found in a sixteen-byte window the pointer advances by sixteen and the loop continues immediately; when a match is found the pointer advances to that character and control falls to the scalar handling block. The accelerated and scalar implementations are selected at first call through a one-time CPUID check, and subsequent calls resolve through a pre-set function pointer with no further CPUID overhead.

Phase 1 of the parse is a yxml streaming pass. yxml is fed the stanza bytes one character at a time, tracking element depth and responding to element-start and attribute events. At depth 1 the element name determines the stanza kind (message, IQ, presence, or SASL auth). At depth 2, element names for resource binding and session establishment write their namespaces directly because these elements carry a known fixed namespace rather than an explicit xmlns= attribute. Attribute values are delivered by yxml one byte at a time, requiring accumulation into buffers before multi-character comparisons can be made; the IQ type and presence type buffers accumulate character by character and are compared against the full type strings only after the yxml loop completes. An unrecognised or absent IQ type attribute leaves the stanza type as the UNKNOWN constant, which the router rejects with `<bad-request/>`.

Phase 2 is a namespace-detection fallback applied when yxml could not capture the relevant namespace. yxml visits only elements at depth 1 and 2; namespaces declared on deeper elements — notably `http://jabber.org/protocol/muc`, which sits at depth 3 — are invisible to it. The fallback copies up to 1023 bytes of the raw stanza and applies a series of substring checks against known namespace strings. The check ordering matters: the MUC owner and admin namespace strings must precede the plain MUC namespace string because the latter is a substring of neither of the former, but reversing the order would cause owner and admin namespaces to be misclassified as plain MUC.

Phase 3 extracts the inner XML payload of the stanza — the content between the opening tag's closing `>` and the matching closing tag. The payload is silently truncated at 1023 bytes. A self-closing opening tag results in an empty payload.

**Single output path.** All XMPP data sent to clients passes through a single output function. When TLS is established the function writes through the mbedTLS session in a loop until the full buffer is consumed. When TLS is not yet established the data is submitted directly through the lwIP TCP write and output functions. The XEP-0198 outbound stanza counter is incremented at the end of both paths.

### 6.5 Stream ID and Entropy Source

Stream IDs (RFC 6120 §4.7.3) and server-generated resource IDs (RFC 6120 §7.7.1) are generated by the kernel's hardware-entropy-backed random source (libc_glue.c):

1. Attempt Intel RDRAND up to 10 times. RDRAND returns a hardware TRNG value seeded from thermal noise (available since Ivy Bridge). CF=0 means the result is invalid; retry.
2. On failure, fall back to a seeded xorshift64* CSPRNG. Seed = two RDRAND reads XORed together.
3. If RDRAND is unavailable for seeding: seed = 0xDEADBEEFCAFEBABEULL XOR (address of state variable) — provides minimal layout-based entropy and a warning to serial console.
4. Scrambler multiplier: 0x2545F4914F6CDD1D — a Weyl-sequence constant proven to give good statistical quality (Vigna, 2016); period 2^64-1.

rand() (plain LCG) is retained for ABI compatibility.

### 6.6 Multi-User Chat (XEP-0045)

Rooms are stored in rooms[MAX_ROOMS]. Each room_t holds: name, creator_jid, subject, boolean flags (semi_anon, locked, moderated, members_only, persistent), banned_jids[MAX_BANNED_PER_ROOM], and a participant array users[MAX_USERS_PER_ROOM]. Each participant_t holds: full JID, nick, role, affiliation, TCP PCB pointer.

**Room join (XEP-0045 §7.2):** The MUC presence handler extracts the room name and desired nick from the resource part of the target JID. If the room does not exist it is created in locked state per XEP-0045 §10.1, with the creator's bare JID recorded. The locked gate immediately follows: non-creator join attempts on a locked room receive `<item-not-found/>` (404) and return without modifying the room. The ban list is checked before the nick conflict check for new joins; a matching entry in the ban list causes an immediate `<forbidden/>` error (403) without adding the user. A nick conflict sends `<conflict/>` (409). Only after all gates pass is the user added to the participant array.

In-room presence updates and nick changes are detected by scanning the participant array for the sender's bare JID. The scan compares against the bare JID specifically because the participant structure stores the resource-stripped form at join time; comparing against the full JID directly would never match. If found with the same nick, the updated presence payload is reflected to all occupants. If found with a different nick, the handler checks for conflicts, broadcasts type='unavailable' with status code 303 and the new nick to all occupants, updates the participant slot, then broadcasts the new available presence.

The join sequence sends three ordered batches per XEP-0045 §7.2: existing occupants' presences to the new user, the new user's presence to all existing occupants, and the self-presence with status code 110 (plus status code 201 for a new room). Real JID exposure in the `<item jid='...'>` element is gated on the room's semi-anonymous flag and the receiving occupant's role, so owners always see real JIDs and regular members do not in semi-anonymous rooms. The final send is the room subject message.

**Room administration.** The kick handler locates the target occupant by nick, broadcasts type='unavailable' with status code 307 to all remaining occupants, and sends the kicked user the same presence with an additional status code 110. The ban handler performs the same broadcast with code 301 and additionally appends the target's bare JID to the ban list and persists the room state. For owner list queries, the creator JID stored at room creation is returned rather than proxying the first active occupant, which would give incorrect results when the creator has left the room.

**Room owner configuration.** Room destruction is detected by checking for a `<destroy>` child in the IQ-set payload. On match, type='unavailable' with a `<destroy/>` element is broadcast to every current occupant, the room is deactivated, and the state is persisted. For ordinary configuration submission, the locked flag is cleared (the room was placed in locked state at creation). Boolean configuration fields are extracted from the Data Forms payload by finding each `var=` string and reading the following `<value>` element; unsubmitted fields retain their previous values, so a partial form does not reset unconfigured settings to defaults.

### 6.7 Offline Message Delivery (XEP-0160)

When a message targets a user with no active session, the offline enqueue function fills a slot in the shared offline message store and immediately writes the updated store to disk before returning. This write-through discipline means a queued message is durable the moment the enqueue function returns, rather than being at risk from a crash before the next periodic flush.

On the recipient's next initial presence, the offline drain function delivers each queued message wrapped with:
```xml
<message from='SENDER' to='RECIPIENT'>
  <delay xmlns='urn:xmpp:delay' stamp='2024-01-01T00:00:00Z'/>
  PAYLOAD
</message>
```

The fixed timestamp 2024-01-01T00:00:00Z is a known limitation: no wall-clock RTC exists after ExitBootServices(). After the full drain loop, the offline store is written to disk once at the end of the drain rather than once per delivered message, batching the disk write for the entire drain operation.

A per-user soft cap is enforced at half the total pool size, preventing a single user's queue from starving all other users on a system with a small fixed pool. XEP-0160 does not mandate per-user limits, but the cap is a practical necessity given the shared fixed-size pool. The cap check is performed before the enqueue attempt to avoid a partial write followed by an error return; a full per-user queue results in `<service-unavailable/>` without touching the store.

The already-wrapped flag in the message handler controls whether the payload is inserted verbatim or wrapped in `<body>...</body>`. This distinction matters for stanzas carrying structured children such as origin identifiers, chat-state notifications, or XHTML-IM content — all of which must pass through unmodified rather than being re-wrapped.

**Pending subscription delivery.** Subscription stanzas — subscribe, subscribed, unsubscribe, unsubscribed — that arrive while the target user has no active session are queued in a pending subscription store. An identical (type, from, to_user) triple already present in the queue is silently dropped. If the queue is full, the enqueue function first attempts to recycle an existing slot belonging to the same recipient, preserving the most recent intent for that user. The drain function is called after the initial presence broadcast and delivers all queued entries for the newly-available user, then persists the updated queue once at the end of the drain loop.

### 6.8 ATA Disk Persistence Layout

All durable state is persisted to a 1 MB raw disk image (data.img) connected as IDE slave. disk_init() selects AHCI DMA or ATA PIO automatically. The disk layout:

**ATA PIO implementation detail.** The ATA PIO driver (primary channel: I/O ports 0x1F0–0x1F7, secondary: 0x170–0x177) implements the 28-bit LBA addressing scheme. After selecting a drive (master/slave bit in the Drive/Head register at 0x1F6), the driver reads the Status register (0x1F7) **fifteen times** and uses only the last value — this creates a deliberate 14-read delay that allows the selected drive time to assert correct voltages on the bus before the status is trusted [OSDev_ATAPI].

| LBA Range | Sectors | Content |
|-----------|---------|---------|
| 0 | 1 | persist_header_t: magic 0xA6E71C3D, version 5, CRC32, 496-byte pad. _Static_assert: exactly 512 bytes. |
| 1–42 | 42 | private_store[20]: 20 x 1064 B = 21,280 B (XEP-0049) |
| 43–98 | 56 | roster_store[80]: 80 x 356 B = 28,480 B (RFC 6121) |
| 99–106 | 8 | rooms[4]: 4 x 1024 B = 4,096 B (MUC config; no live participants) |
| 107–185 | 79 | offline_store[32]: 32 x 1,252 B = 40,064 B (XEP-0160) |
| 186–193 | 8 | pending_subs[32]: 32 x 116 B = 3,712 B (RFC 6121 §4.3) |
| 194–2047 | 1854 | Reserved |

_Static_assert expressions verify each store fits its sector allocation at compile time.

**Disk persistence layer design.** Five sector-aligned static staging buffers serve as intermediaries between the live in-memory stores and the disk. Each save operation zeroes its staging buffer before packing data into it, preventing residual bytes from a previous write from appearing in unused padding. The on-disk projection of the room table excludes the participant array because that array contains TCP connection pointers, which are only valid during the current process lifetime; persisting pointer-valued fields across restarts would produce dangling pointers and corrupt the TCP stack on load. Room configuration — name, creator JID, subject, the four boolean flags, ban count, and ban list — is all that persists; occupants simply rejoin after restart.

The disk image is versioned. A header sector at LBA 0 holds a magic number, a schema version, and a CRC32 over all five payload regions computed using the IEEE 802.3 polynomial. The version field is checked against the current compile-time version on every load; a mismatch causes the entire image to be discarded and reinitialised rather than attempting migration, which prevents a corrupted or partially-migrated store from reaching the running server.

The CRC computation re-packs each room entry into its on-disk projection structure before feeding the bytes into the checksum accumulator. This ensures the checksum covers exactly the same data that would be written to disk, not the wider in-memory representation that includes live participant state.

Write-through ensures the header CRC always reflects the most recently committed payload: every save function calls the header update after writing its payload regions. A crash between a payload write and its header update leaves the CRC mismatched, triggering a fresh-start rather than leaving the server in a partially committed state.

Recovery on boot attempts to read the header, validate the magic and version, read all five payload regions into staging buffers, populate the live stores, and verify the CRC against the just-loaded data. This ordering is required because the CRC computation reads the live in-memory stores rather than the staging buffers; populating the stores before verifying means the CRC comparison is consistent. Any failure — unreadable sector, wrong magic, version mismatch, or CRC mismatch — causes the recovery to fall back to a clean initialisation, trading potentially partial data for a guaranteed consistent starting state. State restoration happens before any connections are accepted, ensuring that roster data, offline messages, room configuration, and pending subscriptions are all available from the first moment a client can connect.

**Power-loss recovery:** CRC32 (IEEE 802.3) over all five payload regions. Mismatch → fresh_start(): zero all stores, write clean header. fresh_start() is only safe at boot, before any connections are accepted — it zeroes rooms[] including TCP PCB pointer fields; zeroing live PCBs would corrupt lwIP state.

persist_room_entry_t excludes the participant array (TCP PCBs are only valid in the current process lifetime). Room configuration persists; occupants simply rejoin after restart.

### 6.9 Stream Management (XEP-0198)

The stream management implementation covers the minimum viable subset of XEP-0198 needed for reliable stanza tracking on a stateless unikernel: the enable/enabled handshake, inbound stanza counting, acknowledgement request and response exchange, and periodic server-initiated acknowledgement probing. Session resumption is explicitly out of scope; the `<enabled/>` response always carries `resume='false'` so that clients know not to attempt a `<resume/>` exchange.

The enable response generates a random six-hex-digit session token for spec compliance, then initialises all three stream management state fields — enabled flag, inbound stanza count, and outbound stanza count — to zero before sending, ensuring a clean counter baseline regardless of any prior partial negotiation.

The client acknowledgement response (`<r/>`) handler replies with `<a h='N'/>` where N is the current inbound stanza count. This value represents the total number of stanzas received from the client since stream management was enabled and is the exact figure the client needs to determine whether any of its stanzas were lost.

The outbound stanza counter is incremented at the end of every call to the single output path. Every ten outbound stanzas (controlled by a compile-time interval constant), rather than immediately calling the acknowledgement request function, a deferred flag is set on the connection context. The event loop drains all pending deferred flags at the top of each iteration, calling the acknowledgement request function outside any active send stack frame. This two-level design prevents re-entrancy: calling the send path from inside the send path would produce unbounded recursion.

A pre-parse dispatcher intercepts stream management elements (`<enable>`, `<r>`, `<a>`) from the raw receive buffer before the normal stanza parser runs, using prefix matching and namespace verification against the urn:xmpp:sm:3 string. This dispatcher is gated on STATE_SESSION, reflecting that stream management negotiation is only legal after the client has a fully bound JID. Each branch locates the closing `>` of the element, computes the consumed byte count, dispatches the appropriate handler, and slides the consumed bytes out of the receive buffer before returning a handled signal to the caller. A return of not-handled for any buffer content that does not match a recognised stream management element leaves it for the stanza parser.

### 6.10 Protocol Handler Layer

The protocol handler file contains every leaf handler function that processes a fully parsed stanza and produces XML responses. It owns two server-wide stores accessible to the persistence layer: the pending subscription queue and the private XML store.

**Roster management.** The roster handler processes both IQ-get (roster fetch) and IQ-set (roster modification) for the `jabber:iq:roster` namespace. For a set operation, the handler parses and upserts every `<item/>` element in the submitted query body, increments the roster version counter, persists the updated roster to disk, acknowledges with an empty IQ result, and then pushes the raw item XML to every other active resource of the same account — identifying same-account resources by comparing usernames rather than full JIDs, so all resources receive the update. For a get operation with a `ver=` attribute in the query, RFC 6121 §2.6 roster versioning is applied and the live version counter is included in the result.

The roster store supports upsert semantics: for a removal, if a matching slot exists it is deactivated immediately; for all other sets, an existing slot for the same (user, contact JID) pair is reused in place, and if no match exists the first inactive slot is claimed. If the store is full and no existing slot matches, the operation returns a failure.

**Presence handling.** When a client sends its first bare `<presence/>` after session establishment, the initial presence handler stores the stanza's inner XML for subsequent re-use by probe responses and broadcasts, then broadcasts the sender's available presence to every connected peer, iterates all other connected clients and delivers each one's stored presence payload directly to the new user, and finally drains the pending subscription queue and offline message queue in sequence.

Subscription stanzas addressed to a user with no active session are queued in the pending subscription store. For `subscribed` and `unsubscribed` stanzas, the subscription update helper implements the RFC 6121 Appendix A state machine: it locates the existing roster item, reads the current subscription attribute, computes the new state, builds a replacement item XML string, persists via the roster save function, and pushes the updated item to all active resources of the account as an IQ-set roster push, satisfying RFC 6121 §3.1.5 and §3.1.6.

**Private XML storage.** The private storage handler implements XEP-0049 by keying each entry on the inner child element's namespace rather than the enclosing `jabber:iq:private` namespace. The inner namespace is extracted by scanning for `xmlns=` in the portion of the payload that follows the closing `>` of the query's opening tag — a two-step skip is necessary because scanning from the beginning would find the query's own namespace rather than the child's. If the inner namespace is absent, `<not-acceptable/>` is returned without touching the store, enforcing the XEP-0049 §2.3 requirement that at least one namespaced child element be present.

**SASL authentication.** The SASL handler enforces three preconditions before examining the payload: TLS must be established (rejecting with `<encryption-required/>` if not), the mechanism must be PLAIN or ANONYMOUS (rejecting unrecognised mechanisms with `<invalid-mechanism/>`), and the Base64 payload must decode cleanly (rejecting malformed encoding with `<incorrect-encoding/>`). For PLAIN, the decoded buffer is walked twice: once for username extraction (stopping at the second null byte to skip the authzid field per RFC 4616 §2) and once for password extraction starting from the beginning. After username extraction, each character is checked against a set of JID-illegal and XML-injection-enabling characters; a username containing any of these receives `<not-authorized/>` without consulting the credential table. Failed authentication increments the failure counter; at the maximum failure count the server sends a policy-violation stream error, closes the TCP connection, and resets the slot.

**Service discovery.** The disco#info handler has four branches: a query to a specific room JID returns the room's identity and live feature set (with the feature elements derived from the actual room configuration flags); a non-existent room returns `<item-not-found/>`; a query to the bare conference subdomain returns the MUC service identity; and a query carrying a `node=` attribute is forwarded verbatim to the addressed user's connection for their client to answer (XEP-0115 capability verification). The disco#items handler distinguishes between a service-level query (returns the list of active rooms) and a room-level query (returns the current occupant list as `<item jid='room/nick'>` elements).

---

## 7. TLS Implementation

### 7.1 Configuration for a Freestanding Environment

mbedTLS 3.6.4 is configured for four hard constraints:

1. **No POSIX heap:** The platform memory module is enabled; the calloc and free stubs in the port file delegate to the mbedTLS static buffer allocator.
2. **No time():** The time and time-date features are disabled.
3. **No filesystem:** Key and certificate are generated in memory at startup.
4. **No POSIX sockets:** I/O callbacks use the lwIP TCP write and output functions on the connection's PCB.

**Custom configuration file details.** Because the kernel is a freestanding GCC build, `<stdio.h>` is unavailable. The configuration file provides manual forward declarations for `snprintf` and `vsnprintf`, directing mbedTLS to use the kernel's own implementations. The platform-no-standard-functions flag forces the library not to use libc functions unless explicitly provided. The static buffer allocator is enabled via the memory-buffer-alloc compile flag, using a 288 KB pool that is passed to the allocator's initialisation function as the first call in the TLS server initialisation routine — this call must precede every other mbedTLS call, or subsequent allocations will use an uninitialised allocator.

The configuration disables all OS-dependent features: time, date, filesystem I/O, and POSIX network sockets. All client-side TLS logic, RSA, DHE key exchange, and the PSA Crypto subsystem are disabled. TLS 1.2 is strictly enforced. TLS 1.3 is explicitly suppressed by undefining the relevant symbols.

Two ciphersuites are enabled: TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 and TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384. RSA and DHE are excluded because the server uses only ECDSA.

The inbound content length is set to the TLS maximum of 16 KB. XMPP clients transmit large OMEMO key bundles in a single XML stanza. The outbound content length is restricted to 4 KB, since the server only needs to send small XML stanzas.

SHA-1 is included because the OID and X.509 modules reference SHA-1 symbol tables for certificate signature algorithm identification. Base64 and PEM parsing are included because the certificate parser imports PEM routines unconditionally, and their symbols must be present to satisfy the linker.

Internal flags for ECC key handling are defined explicitly.

The printf and snprintf macros redirect mbedTLS's internal formatted output calls to the kernel's own serial-backed implementations. The 64-bit integer flag informs the bignum arithmetic layer that 64-bit integers are natively availables.

**mbedTLS source file selection.** AngelicKernel compiles mbedTLS from a manually selected set of source files rather than using its CMake build system. Inclusion was driven by following linker undefined-reference errors from the TLS server entry point outward until the binary linked cleanly. Exclusions are files with known POSIX dependencies (entropy.c, net_sockets.c, timing.c), unused algorithms (DHE, RSA, ChaCha20-Poly1305, CMAC), TLS 1.3 modules, and threading primitives — none of which are available or needed in a single-threaded freestanding unikernel.

### 7.2 Key and Certificate Generation

At xmpp_tls_server_init():
1. Initialise 288 KB static TLS pool as mbedTLS allocator.
2. Seed the CTR-DRBG context using the kernel's entropy callback, which wraps the hardware random source and fills the requested byte count by issuing successive 32-bit reads, handling any trailing partial word.
3. Generate an ECDSA P-256 private key. This call is blocking, which is acceptable because no clients can connect until the function returns.
4. Create self-signed X.509 cert: CN=XMPP_DOMAIN, valid 2025-01-01 to 2035-01-01, signed with ECDSA P-256. The certificate carries a ten-year validity window; the time-date validity feature is explicitly disabled in the configuration, so the validity range is written into the DER but never verified at runtime since no wall clock exists after ExitBootServices.
5. The serial number API changed between mbedTLS versions; a compile-time version-number guard selects the appropriate API variant.
6. The certificate is written into a static DER buffer and loaded into the shared TLS certificate structure. The shared SSL configuration is set to server mode with no client certificate requirement, since XMPP clients authenticate via SASL over the encrypted channel rather than via TLS client certificates.

If xmpp_tls_server_init() fails, xmpp_init_server() halts — a server unable to offer STARTTLS must not accept connections (RFC 6120 §5.3 requires STARTTLS as mandatory).

### 7.3 AES-NI Hardware Acceleration

The Makefile compiles mbedTLS AES source files with -msse4.2 -maes -mpclmul (overriding the default -mno-sse -mno-avx). This is safe because enable_sse() runs before any TLS operation.

### 7.4 TLS Handshake Stall Handling

The deferred-write flag handles a handshake stall: if the lwIP send buffer is full during a TLS handshake step, mbedTLS returns WANT_WRITE. The receive callback sets the flag on the connection context. The event loop retries the handshake step for all clients with this flag set at the top of each iteration, outside any receive callback. On a successful retry the established flag is set, the deferred-write flag is cleared, the connection state returns to STATE_CONNECTED, and the receive buffer position is zeroed. Any non-recoverable error from the handshake closes the PCB and resets the state.

### 7.5 STARTTLS Flow and TLS Record Layer

The STARTTLS negotiation layer initialises a fresh per-connection TLS session context immediately after the server sends `<proceed/>` and before advancing the connection to the STARTTLS state. The session is linked to the shared server SSL configuration via the setup call, and the send and receive BIO callbacks are registered.

The send BIO callback writes encrypted bytes to the lwIP TCP send buffer. If 
the buffer is full, it tells mbedTLS to pause and try again later. The receive 
BIO callback reads encrypted bytes from a staging buffer that the network 
receive path fills. If the staging buffer is empty, it tells mbedTLS to pause 
until more data arrives.

A staging compaction function slides any unconsumed bytes to the front of the staging buffer after each mbedTLS call, preventing the write cursor from advancing past the end of the array across successive TCP deliveries.

During decryption of established TLS sessions, the receive callback appends the raw encrypted bytes to the staging buffer and loops on the mbedTLS read function, copying each successfully decrypted chunk into the receive buffer for the normal XMPP parse path. The local decode buffer is sized to 16 KB. If the decrypted output would overflow the receive buffer, a policy-violation stream error is written through the TLS session, the TCP output is flushed, and the connection is closed per RFC 6120 §4.9.3.14. A return value of zero from the mbedTLS read function indicates a TLS close_notify and closes the connection cleanly. A fatal record-layer error closes the PCB and clears the established flag so the slot can be reused rather than left in a zombie state where the SSL context is broken but the TCP connection is still nominally open.

---

## 8. Freestanding C Library (libc_glue.c)

Because no libc exists after ExitBootServices(), every standard C function is implemented from scratch. Key decisions:

- **memset, memcpy, memcmp, memchr, memmove:** unsigned char* to avoid type-aliasing issues. memmove handles overlapping regions via direction check.
- **strlen, strcmp, strncmp, strncpy, strcat, strncat, strstr, strchr, strrchr, atoi:** straight implementations. strstr uses O(nm) naive search, sufficient for short XMPP namespace strings.
- **snprintf/vsnprintf:** reduced implementation supporting %s, %d, %u, %x, %c, %p, %%. Sufficient for all XMPP stanza formatting.
- **putchar(c):** wraps serial_print(), redirecting stdout to the UART.
- **abort():** CLI; HLT; spin loop.
- **rand():** for ABI compatibility only.
- **secure_random_u32():** RDRAND (10 retries) with xorshift64* fallback.

The calloc/free stubs in mbedtls_port.c are marked __attribute__((weak)) so mbedTLS's platform layer can override them with its static pool allocator.

**Hardware random number generator.** The RDRAND instruction sets the carry flag on success and clears it if the entropy pool is temporarily exhausted. The hardware random source retries up to ten times before giving up and returning zero, at which point the caller falls back to the software CSPRNG. The xorshift64* fallback CSPRNG is seeded from two successive hardware random reads on the first invocation; if RDRAND is completely unavailable at seeding time, the state is initialised from a compile-time constant XORed with the address of the state variable, and a warning is printed to serial so the condition is immediately visible in the boot log. The scrambler multiplies the shifted state by the Weyl-sequence constant 0x2545F4914F6CDD1D and returns the high 32 bits and the generator has a period of 2^64-1. A guard ensures the state is never zero, which would produce an all-zero output stream.

### 8.1 Serial Debug Subsystem (UART / COM1)

All kernel diagnostics, boot log output, and the test harness's expected-response channel use the PC16550D-compatible UART at COM1 [PC16550D]. COM1 is universally available on both real hardware and QEMU, requires no firmware cooperation after ExitBootServices(), and produces output that the host terminal reads directly via QEMU's `-serial stdio` option.

**Physical connector.** The PC serial port uses a DE-9 (often called "DB-9") 9-pin D-sub connector [RS232]. The two signal pins used by AngelicKernel:

- **Pin 3 — TD (Transmit Data):** this is the computer's *output* wire. `outb(0x3F8, c)` shifts character `c` out on this pin.
- **Pin 2 — RD (Receive Data):** this is the computer's *input* wire. `inb(0x3F8)` reads a byte received on this pin.

**UART initialisation sequence (8N1 at 115200 baud):**

```
1. Write 0x00 to IER (0x3F9)  — disable all UART interrupts (polling mode)
2. Write 0x80 to LCR (0x3FB)  — set DLAB=1 (Divisor Latch Access Bit)
3. Write 0x01 to DLL (0x3F8)  — divisor low byte  (115200 baud: 115200/115200 = 1)
4. Write 0x00 to DLH (0x3F9)  — divisor high byte
5. Write 0x03 to LCR (0x3FB)  — clear DLAB; set 8 data bits, no parity, 1 stop bit (8N1)
6. Write 0xC7 to FCR (0x3FA)  — enable and clear FIFO, 14-byte threshold
7. Write 0x0B to MCR (0x3FC)  — set RTS and DTR (Data Terminal Equipment ready)
```

**UART frame format — 8N1 dissected.** Every character on the wire is wrapped in a frame [OSDev_Serial]:

| Component | Width | Value / Meaning |
|-----------|-------|-----------------|
| Start bit | 1 bit | Always low (space) — signals start of frame |
| Data bits | 8 bits | Character byte, LSB transmitted first |
| Parity bit | 0 bits | "N" = None — no parity check |
| Stop bit | 1 bit | Always high (mark) — signals end of frame |
**Baud rate formula.** The PC16550D contains a programmable baud generator that divides the input clock by a 16-bit divisor to produce a 16× clock [PC16550D, §8.3, Table III]. With a 1.8432 MHz crystal: divisor = clock / (baud × 16). At 38,400 baud: divisor = 3. At 9,600 baud: divisor = 12. AngelicKernel's `serial_init()` writes divisor = 3 (DLL = 0x03, DLH = 0x00), configuring the UART at 38,400 baud.

**DLAB (Divisor Latch Access Bit).** Setting LCR bit 7 (DLAB=1) redirects the I/O addresses 0x3F8 and 0x3F9 from the data/interrupt registers to the baud rate divisor registers (DLL and DLH). This multiplexing means baud rate programming and data transmission cannot happen simultaneously; DLAB must be cleared (bit 7 = 0) before transmitting characters.

**DTE/DCE.** The UART is "Data Terminal Equipment" (DTE) — the computer side. A modem is "Data Communication Equipment" (DCE). QEMU simulates a Null Modem cable between the guest UART and the host terminal, so that the guest's transmit output reaches the host's receive input [QEMUNet].

**Why COM1 over COM2/3/4:** COM1 (0x3F8, IRQ 4) is the only port guaranteed to be present and functional in QEMU's default configuration. COM2 (0x2F8, IRQ 3), COM3 (0x3E8), and COM4 (0x2E8) may not be emulated without explicit QEMU flags.

---

## 9. MPK Overhead Measurement

### 9.1 Benchmark Methodology (mpk_benchmark.c)

WRPKRU is measured using RDTSC bracketed by CPUID serialisation barriers. 
CPUID forces all prior instructions to retire before executing, guaranteeing 
a clean measurement boundary immediately before each RDTSC.

Four steps:

1. **Warm-up (100,000 iterations):** alternating WRPKRU(0x00)/WRPKRU(0x0C) 
   without timing. Stabilises branch predictors, instruction cache.

2. **Calibration (1,000,000 iterations):** empty loop with CPUID+RDTSC 
   brackets and a volatile counter to prevent the compiler from eliminating 
   the loop. Measures harness overhead — loop counter increment, CPUID, and 
   RDTSC — with no WRPKRU instructions present.

3. **Measurement (1,000,000 iterations):** alternating WRPKRU(0x00)/WRPKRU(0x0C) 
   with CPUID+RDTSC brackets. Each iteration executes two WRPKRU instructions.

4. **Net cost:** (meas_ticks − cal_ticks) / (2 × 1,000,000). Subtracting the 
   calibration ticks removes loop and harness overhead; dividing by 2 accounts 
   for two WRPKRU instructions per iteration.

`do_wrpkru()` is marked `__attribute__((noinline))` because it prevents the compiler from inlining the function and optimising away the loop structure around it.

### 9.2 Results

| Platform | Cycles / WRPKRU |
|----------|----------------|
| QEMU + KVM | 36  |


---

## 10. Testing


### §10.1 Client Interoperability

### 10.2 Serial Log Output

### 10.3 External Compliance Validation (Future Work)

Two public automated test suites can provide independent compliance signals:

- **compliance.conversations.im** — a web-based XMPP compliance tester that connects to a publicly routable server and checks feature advertisement and protocol conformance for a curated set of XEPs.
- **connect.xmpp.net** — a connection diagnostics tool that verifies TLS certificate validity, cipher suite selection, and STARTTLS negotiation against RFC 6120 requirements.

AngelicKernel is not yet publicly routable and uses a self-signed certificate; both tools would require DNS, a CA-signed certificate, and a public IPv4/IPv6 address before they can produce useful results. These are tracked as future milestones.

### 10.4 Section 9.2 Metric Summary

All measurements below were collected using QEMU+KVM on a Linux host.

| Metric | Result |
|--------|--------|
| Boot time | ~2.75 s on KVM |
| MPK overhead per WRPKRU | 36 cycles on KVM |
| Memory footprint (idle RSS) | AngelicKernel 95.9 MB; Prosody 8.3 MB; Openfire 147 MB |

*Memory RSS is measured as the delta between the QEMU host process RSS before and after guest boot for AngelicKernel, and as Docker container RSS for Prosody and Openfire. AngelicKernel's 95.9 MB figure reflects guest physical pages dirtied at runtime within the 512 MB QEMU allocation — including kernel image, page tables, lwIP/mbedTLS pools, and XMPP state. Prosody got 8.3 MB and Openfire got 147 MB.

*The KVM boot time of ~2.75 s. Re-measurement on physical hardware is tracked as a future milestone.*

*The KVM WRPKRU costs 36 cycles. Re-measurement on physical hardware is tracked as a future milestone.*

---

## 11. Security Analysis

### 11.1 MPK Isolation Guarantee

**Claim:** A memory-safety bug in the XMPP protocol stack cannot read from or write to the e1000 driver's DMA descriptor rings, receive buffers, transmit buffers, or MMIO registers.

**Basis:** The Tier-3 self-test deliberately executes a ring-0 read of Key-1 memory without a trampoline and confirms the CPU raises #PF (error code bit 5 set — Protection Key violation, Intel SDM Vol. 3A §4.7). Any analogous dereference in XMPP code faults identically, because driver pages have U/S=1 in all four PTE levels and PKRU bits [3:2]=11 (AD=1, WD=1). The fault precedes any data transfer.

**Scope:** MPK provides isolation between components within one kernel, not kernel integrity protection. An attacker with arbitrary ring-0 code execution can write PKRU directly. The threat model is a memory-safety bug in the XMPP layer, not a complete kernel compromise.

**Relationship to prior MPK research.**

- **ERIM** [Vahldiek-Oberwagner2019] applies MPK within a Linux process to 
  isolate sensitive heap data from the rest of the application. AngelicKernel 
  applies the same PKRU-gate mechanism at the kernel level with no OS below it.
- **Hodor** [Hedayati2019] uses MPK to isolate in-process data-plane libraries. 
  Hodor's trampoline design — switch PKRU, call, restore PKRU — is 
  architecturally identical to AngelicKernel's mpk.asm stubs. The 
  RDTSC-bracketed CPUID serialisation methodology used in Hodor's latency 
  characterisation is the same approach used in AngelicKernel's benchmark.
- **Koning et al.** [Koning2017] survey commodity hardware features including 
  MPK for in-process isolation of safe regions. AngelicKernel's protection-key 
  assignments are static and manual rather than compiler-assisted, appropriate 
  for a fixed driver boundary.

### 11.2 Known Limitations

| Limitation | Impact |
|-----------|--------|
| No ASLR | Stack/heap addresses predictable |
| No stack canary | Stack-smashing harder to detect |
| No CET shadow stack | Trampoline call sites could be redirected |
| Self-signed TLS certificate | Clients cannot verify server identity |
| Fixed offline message timestamp | XEP-0203 delay stamp shows 2024-01-01 |
| Hardcoded XML string formatting | Stanzas are assembled via snprintf rather than typed stanza objects; adding new XEPs requires careful string manipulation instead of a structured builder API |
| Monolithic XEP routing | All handlers share a single flat routing table in xmpp_handlers. |
| SASL PLAIN only | SCRAM-SHA-1 and SCRAM-SHA-256 (RFC 5802) and SASL channel binding to TLS (RFC 5056) are not implemented |

### 11.3 Protocol Security Properties

SASL PLAIN credentials (RFC 4616) encode the username and password as cleartext within the Base64 payload. The server withholds the PLAIN mechanism from the feature list until after TLS is established, ensuring credentials never travel unencrypted on the network. The TLS configuration uses ECDSA P-256 with AES-128-GCM-SHA256 at a minimum; TLS 1.2 is enforced at the mbedTLS configuration level. Self-signed certificates mean clients cannot verify server identity via a trusted CA chain.

JID spoofing is prevented by a single chokepoint in the stanza router: before any handler is invoked, the router overwrites the sender field with the authenticated JID stored in the connection context. This line protects all 14 handler paths simultaneously — no individual handler can receive a spoofed sender identity regardless of what the client placed in the `from=` attribute.

Stream IDs are generated from RDRAND hardware entropy. If RDRAND fails after 10 retries, the fallback xorshift64* CSPRNG is seeded from two independent RDRAND reads. If RDRAND is completely unavailable at seed time, a warning is printed to the serial console and the seed falls back to a constant XORed with the address of the state variable.

---

## 12. Related Work

**Unikernels:**
MirageOS constructs unikernels in OCaml for secure, high-performance network 
applications deployable on Xen, KVM, and major cloud platforms [MirageOS].
LightVM (Manco et al., SOSP 2017) reduces KVM boot time to <5 ms.
EbbRT (Schatzberg et al., OSDI 2016) is a C++ library OS for high-performance kernels. 
HermiTux achieves binary compatibility with Linux applications by emulating the Linux ABI at load- and runtime, eliminating the porting burden at a cost of approximately 3% average overhead [HermiTux].
OSv supports a JVM runtime directly on bare metal or KVM.
ClickOS [Martins2014] achieves <30ms boot  ClickOS is small (5MB when running), can
be instantiated in very small times (roughly 30 milliseconds) and can fill up a 10Gb pipe while concurrently running 128 vms on a low-cost commodity server.
IncludeOS is an includable, minimal unikernel operating system for C++ services running in the cloud and on real HW and on qemu/kvm boots in about 300ms.
Unikraft [Unikraft] provides a POSIX-compatible unikernel build framework based on modular micro-libraries.
Nabla containers reduce host attack surface by using library OS techniques to 
avoid Linux system calls, blocking all but seven via seccomp [Nabla].
Rumprun combines NetBSD rump kernels with a hardware abstraction layer to run 
unmodified POSIX applications on bare metal, KVM, or Xen [Rumprun].
HaLVM ports the Glasgow Haskell Compiler toolsuite to run lightweight single-purpose virtual machines directly on the Xen hypervisor [HaLVM].
Solo5 provides a minimal sandboxed execution environment and narrow hardware abstraction layer for unikernels, supporting KVM, Xen, and seccomp-based tenders [Solo5].
Mini-OS is a minimal Xen guest kernel distributed with the Xen hypervisor sources, used as the basis for unikernel development including ClickOS and Rump kernels [MiniOS].
OPS is a tool for packaging and running applications as Nanos unikernels without code changes, with support for major cloud providers [OPS].

**TLS formal verification.** 
miTLS is a formally verified TLS implementation in F* proven memory-safe and cryptographically correct [Kaloper2015].
nqsb-TLS demonstrates that a formally specified, memory-safe TLS stack 
compiled into a unikernel can achieve handshake performance matching OpenSSL 
with a TCB 4% the size of a Linux/OpenSSL stack [nqsbTLS].
AngelicKernel uses mbedTLS instead.

**MPK Systems:** ERIM [Vahldiek-Oberwagner2019], Hodor [Hedayati2019] and Koning et al. Were discussed in §11.1. All three operate in Linux user space; AngelicKernel applies the same hardware primitive at ring 0 without an OS, using assembly trampolines that give precise control over register-saving order.

**Bare-Metal XMPP:** No prior published work implements a full XMPP server on bare-metal x86-64 without an OS with MPK. The closest conceptual predecessor is mirage-xmpp (Amzallag, 2019), an OCaml MirageOS unikernel XMPP server [mirage-xmpp]. That work demonstrates XMPP on a unikernel but targets the MirageOS type-safe OCaml environment rather than bare-metal C on UEFI and does not address intra-component isolation.

**XMPP Server Implementations:** ejabberd (ProcessOne) is an Erlang/OTP server where each XEP is implemented as a separate gen_server behaviour connected via a hook-and-handler dispatch system [ejabberd]. Prosody (Lua) adopts a similar event-driven plugin architecture with clean separation between the XMPP core stream and protocol handlers [Prosody]. Openfire is a Java-based XMPP server with a Netty-backed network layer and a JVM baseline memory footprint [Openfire].
ejabberd's Erlang ecosystem includes two standalone libraries relevant to any C-based XMPP implementation: `processone/xmpp` [pxmpp] (a typed Erlang XMPP stanza library) and `processone/fast_xml` [fast_xml] (a NIF-accelerated streaming XML parser).

---

## 13. Conclusion

AngelicKernel demonstrates that a complete XMPP server with hardware-enforced 
driver isolation can be built on bare x86-64 hardware without an operating 
system. The WRPKRU instruction enforces a hardware boundary between the network 
driver and the XMPP protocol stack — a boundary that would otherwise require 
separate processes or VMs. On the QEMU+KVM test platform the measured WRPKRU 
cost is 36 cycles. The server interoperates with real XMPP clients, validating 
the implementation.

**Future Work.** Several directions are prioritised:

*Security hardening:* Intel CET shadow stacks; ASLR for the kernel image and 
static allocations; stack canaries (currently disabled via `-fno-stack-protector`); 
NX/XD bit enforcement on data-only pages (`PTE_NX` is defined but not applied 
in `vmm_map_page()`).

*SASL and TLS improvements:* SCRAM-SHA-1 and SCRAM-SHA-256 (RFC 5802) to 
eliminate plaintext credential transmission; a CA-signed certificate to allow 
client-side server identity verification.

*Protocol extensions:* XEP-0313 (Message Archive Management); XEP-0384 
(OMEMO); XEP-0359 (Unique Stanza IDs); XEP-0333 (Chat Markers); XEP-0085 
(Chat State Notifications); XEP-0115 (Entity Capabilities); XEP-0077 
(In-Band Registration); XEP-0198 session resumption with full stanza queue 
persistence on disk; XEP-0191 Blocklist full policy enforcement.

*Architectural extensibility:* Replace the monolithic routing table with a 
per-XEP module structure and hook-and-handler dispatch. Replace 
`snprintf`-assembled stanzas with typed stanza builder objects.

*Memory management:* Replace the bump allocator with a buddy or slab allocator 
to support `free()` and sub-page allocations [OSDev_MemAlloc] 
[OSDev_BrendanMMGuide] [Slab].

*Hardware and platform:* RTC integration for accurate XEP-0203 delay stamps; 
APIC timer to replace TSC-based timekeeping; SMP support; real-hardware 
validation of all §9.2 metrics.

*External compliance:* Evaluate against compliance.conversations.im and 
connect.xmpp.net once a public IPv4/IPv6 address and CA-signed certificate 
are available.

---

## References

[Madhavapeddy2014] A. Madhavapeddy et al., "Unikernels: Library Operating Systems for the Cloud," ACM SIGPLAN ASPLOS, 2014.

[Vahldiek-Oberwagner2019] A. Vahldiek-Oberwagner et al., "ERIM: Secure, Efficient In-process Isolation with Protection Keys (MPK)," USENIX Security 2019.

[Hedayati2019] M. Hedayati et al., "Hodor: Intra-Process Isolation for High-Throughput Data Plane Libraries," USENIX ATC 2019.

[Koning2017] K. Koning, X. Chen, H. Bos, C. Giuffrida, E. Athanasopoulos, "No Need to Hide: Protecting Safe Regions on Commodity Hardware," *Proceedings of the Twelfth European Conference on Computer Systems (EuroSys)*, 2017.

[Manco2017] F. Manco et al., "My VM is Lighter (and Safer) than your Container," ACM SOSP 2017.

[Schatzberg2016] D. Schatzberg et al., "EbbRT: A Framework for Building Per-Application Library Operating Systems," USENIX OSDI 2016.

[Martins2014] J. Martins et al., "ClickOS and the Art of Network Function Virtualization," USENIX NSDI 2014.

[IntelSDM] Intel Corporation, "Intel 64 and IA-32 Architectures Software Developer's Manuals," Vols. 1-4, 2024. https://www.intel.com/sdm

[IntelE1000] Intel Corporation, "PCI/PCI-X Family of Gigabit Ethernet Controllers Software Developer's Manual," 2009. https://www.intel.com/content/dam/www/public/us/en/documents/manuals/pcie-gbe-controllers-open-source-manual.pdf

[ACPI66] ACPI Workgroup, "Advanced Configuration and Power Interface (ACPI) Specification, Revision 6.6," 2023. https://uefi.org/sites/default/files/resources/ACPI_Spec_6.6.pdf

[RFC6120] P. Saint-Andre, "XMPP: Core," RFC 6120, IETF, March 2011.

[RFC6121] P. Saint-Andre, "XMPP: Instant Messaging and Presence," RFC 6121, IETF, March 2011.

[RFC4616] K. Zeilenga, "The PLAIN SASL Mechanism," RFC 4616, IETF, August 2006.

[RFC5802] C. Newman et al., "Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms," RFC 5802, IETF, July 2010.

[RFC5056] N. Williams, "On the Use of Channel Bindings to Secure Channels," RFC 5056, IETF, November 2007.

[RFC4122] P. Leach, M. Mealling, R. Salz, "A Universally Unique Identifier (UUID) URN Namespace," RFC 4122, IETF, July 2005.

[XEP0030] J. Hildebrand, P. Millard, R. Eatmon, P. Saint-Andre, "Service Discovery," XEP-0030, XMPP Standards Foundation, 2017.

[XEP0045] P. Saint-Andre, "Multi-User Chat," XEP-0045, XMPP Standards Foundation, v1.34.6, 2023.

[XEP0049] P. Saint-Andre, "Private XML Storage," XEP-0049, XMPP Standards Foundation, 2004.

[XEP0160] J. Hildebrand, P. Saint-Andre, "Offline Messages," XEP-0160, XMPP Standards Foundation, 2006.

[XEP0191] P. Saint-Andre, "Blocking Command," XEP-0191, XMPP Standards Foundation, 2015.

[XEP0198] J. Karneges et al., "Stream Management," XEP-0198, XMPP Standards Foundation, v1.6, 2018.

[XEP0199] P. Saint-Andre, "XMPP Ping," XEP-0199, XMPP Standards Foundation, 2009.

[XEP0203] P. Saint-Andre, "Delayed Delivery," XEP-0203, XMPP Standards Foundation, 2009.

[XEP0313] M. Wild, "Message Archive Management," XEP-0313, XMPP Standards Foundation, 2021.

[XEP0384] A. Husain et al., "OMEMO Encryption," XEP-0384, XMPP Standards Foundation, 2023.

[mbedTLS] Mbed TLS Development Team, "Mbed TLS 3.6.4 Documentation," 2024. https://mbed-tls.readthedocs.io

[lwIP] A. Dunkels, "Design and Implementation of the lwIP TCP/IP Stack," SICS Technical Report T2001-20, 2001.

[Vigna2016] S. Vigna, "An experimental exploration of Marsaglia's xorshift generators, scrambled," ACM Trans. Math. Software, vol. 42, no. 4, 2016.

[gnuefi] GNU-EFI Project, "Toolkit for building EFI applications." https://sourceforge.net/projects/gnu-efi/

[ejabberd] ProcessOne, "ejabberd XMPP Server (Erlang/OTP)." https://github.com/processone/ejabberd

[Prosody] Prosody Community, "Prosody XMPP Server (Lua)." https://hg.prosody.im/trunk/

[Openfire] Ignite Realtime, "Openfire XMPP Server (Java)." https://github.com/igniterealtime/Openfire

[mirage-xmpp] J. Amzallag, "mirage-xmpp: An XMPP Server written in OCaml using MirageOS," 2019. https://github.com/jeffa5/mirage-xmpp

[Unikraft] S. Lankes et al., "Unikraft: Fast, Specialized Unikernels the Easy Way," ACM EuroSys, 2021. https://unikraft.org/

[Nabla] Nabla Containers Project. https://nabla-containers.github.io/

[Rumprun] Rump Kernel Project, "Rumprun: Bare-metal and cloud unikernel based on rump kernels." https://github.com/rumpkernel/rumprun

[RumprunPkgs] Rump Kernel Project, "Rumprun Packages: Pre-ported server applications for rumprun." https://github.com/rumpkernel/rumprun-packages

[NetBSD] The NetBSD Foundation, "NetBSD Operating System." https://www.netbsd.org/

[Solo5] Solo5 Contributors, "Solo5: A sandboxed execution environment for unikernels." https://github.com/Solo5/solo5

[HaLVM] Galois Inc., "HaLVM: The Haskell Lightweight Virtual Machine." https://github.com/GaloisInc/HaLVM

[MiniOS] Xen Project, "Mini-OS: Minimal OS for Xen guests." https://github.com/mirage/mini-os

[MirageOS] MirageOS Team, "MirageOS: A library operating system that constructs unikernels." https://mirage.io/docs

[MirageSkeleton] MirageOS Team, "mirage-skeleton: Example MirageOS applications." https://github.com/mirage/mirage-skeleton

[IncludeOS] IncludeOS Contributors, "IncludeOS: A C++ unikernel for cloud services." https://www.includeos.org/

[OPS] NanoVMs, "OPS: Build and run nanos unikernels." https://docs.ops.city/ops

[Limine] limine-bootloader Contributors, "Limine: Modern, feature-rich bootloader." https://github.com/limine-bootloader/limine

[Kaloper2015] K. Bhargavan, A. Delignat-Lavaud, C. Fournet, A. Pironti, P.-Y. Strub, "Implementing TLS with Verified Cryptographic Security," USENIX Security 2015. https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/kaloper-mersinjak

[Park2019] S. Park et al., "libmpk: Software Abstraction for Intel Memory Protection Keys," USENIX ATC 2019. https://www.usenix.org/system/files/atc19-park-soyeon.pdf

[Jackline] Hannes Mehnert, "Jackline: A minimalistic XMPP client in OCaml." https://github.com/hannesm/jackline

[pxmpp] ProcessOne, "processone/xmpp: Erlang/Elixir XMPP parsing and serialization library." https://github.com/processone/xmpp

[fast_xml] ProcessOne, "processone/fast_xml: Fast Expat-based XML parser for Erlang." https://github.com/processone/fast_xml

[yxml] N. Vernes, "yxml: A small, fast and correct XML parser." https://dev.yorhel.nl/yxml

[mxml] M. Sweet, "Mini-XML: A small XML library." https://www.msweet.org/mxml/

[libexpat] Expat Contributors, "Expat XML Parser." https://libexpat.github.io/

[lwIPBMPort] lwIP Wiki, "Porting For Bare Metal." https://www.nongnu.org/lwip/2_0_x/group__lwip__opts__nosys.html

[OSDev_lwIP] OSDev Wiki, "LwIP on bare metal — community guide." https://wiki.osdev.org/

[OSDev_AML] OSDev Wiki, "AML (ACPI Machine Language)." https://wiki.osdev.org/AML

[OSDev_SMM] OSDev Wiki, "System Management Mode." https://wiki.osdev.org/System_Management_Mode

[OSDev_DSDT] OSDev Wiki, "DSDT (Differentiated System Description Table)." https://wiki.osdev.org/DSDT

[OSDev_ACPI] OSDev Wiki, "ACPI." https://wiki.osdev.org/ACPI

[OSDev_APIC] OSDev Wiki, "APIC." https://wiki.osdev.org/APIC

[OSDev_GPT] OSDev Wiki, "GPT (GUID Partition Table)." https://wiki.osdev.org/GPT

[OSDev_GDT] OSDev Wiki, "Global Descriptor Table." https://wiki.osdev.org/Global_Descriptor_Table

[OSDev_GDT_Tutorial] OSDev Wiki, "GDT Tutorial." https://wiki.osdev.org/GDT_Tutorial

[OSDev_IDT] OSDev Wiki, "Interrupt Descriptor Table." https://wiki.osdev.org/Interrupt_Descriptor_Table

[OSDev_ISR] OSDev Wiki, "Interrupt Service Routines." https://wiki.osdev.org/Interrupt_Service_Routines

[OSDev_PIC] OSDev Wiki, "8259 PIC / Intel 8259A." https://pdos.csail.mit.edu/6.828/2017/readings/hardware/8259A.pdf

[OSDev_ATA] OSDev Wiki, "ATA PIO Mode." https://wiki.osdev.org/ATA_PIO_Mode

[OSDev_AHCI] OSDev Wiki, "AHCI." https://wiki.osdev.org/AHCI

[OSDev_MMIO] OSDev Wiki, "Memory Mapped I/O and volatile." https://wiki.osdev.org/

[OSDev_MemMap] OSDev Wiki, "Memory Map (x86)." https://wiki.osdev.org/

[OSDev_MemAlloc] OSDev Wiki, "Memory Allocation." https://wiki.osdev.org/

[OSDev_BrendanMMGuide] OSDev Wiki / Brendan, "Brendan's Memory Management Guide." https://wiki.osdev.org/Brendan%27s_Memory_Management_Guide

[OSDev_RecursivePaging] OSDev Wiki, "Recursive Paging." https://wiki.osdev.org/

[OSDev_TLB] OSDev Wiki, "TLB Shootdown." https://wiki.osdev.org/

[OSDev_BareBones] OSDev Wiki, "Bare Bones (GCC + GRUB multiboot)." https://wiki.osdev.org/Babystep1

[OSDev_MeatySkel] OSDev Wiki, "Meaty Skeleton." https://wiki.osdev.org/Meaty_Skeleton

[OSDev_LimineBareBones] OSDev Wiki, "Limine Bare Bones." https://wiki.osdev.org/Limine_Bare_Bones

[OSDev_HigherHalf] OSDev Wiki, "Higher Half Kernel." https://wiki.osdev.org/Higher_Half_Kernel

[OSDev_GOP] OSDev Wiki / d-sonuga, "Graphics Output Protocol." https://wiki.osdev.org/GOP

[OSDev_GDB] OSDev Wiki, "QEMU GDB stub for kernel debugging." https://wiki.osdev.org/

[OSDev_CC] OSDev Wiki, "Cross Compiler." https://wiki.osdev.org/

[OSDev_8254x] OSDev Wiki, "Intel 8254x." https://wiki.osdev.org/Intel_8254x

[GNUldScript] GNU Project, "LD Linker Scripts: Basic Script Concepts." https://sourceware.org/binutils/docs/ld/Basic-Script-Concepts.html

[PC16550D] Texas Instruments, "PC16550D Universal Asynchronous Receiver/Transmitter with FIFOs Datasheet." Texas Instruments, 1995.

[ATA8ACS] T13 Technical Committee, "AT Attachment 8 — ATA/ATAPI Command Set (ATA8-ACS)," 2007.

[AHCI13] Intel Corporation, "Serial ATA AHCI 1.3.1 Specification," 2011. https://www.intel.com/

[WikipediaLBA] Wikipedia, "Logical Block Addressing." https://en.wikipedia.org/wiki/Logical_block_addressing

[WikipediaTSC] Wikipedia, "Time Stamp Counter." https://en.wikipedia.org/wiki/Time_Stamp_Counter

[QEMUDocs] QEMU Project, "QEMU System Emulation Documentation." https://www.qemu.org/docs/master/system/introduction.html

[QEMUNet] QEMU Project, "QEMU Network Device Emulation." https://www.qemu.org/docs/master/system/devices/net.html

[QEMUEmul] QEMU Project, "QEMU Emulation." https://www.qemu.org/docs/master/about/emulation.html

[IntelE1000RC82540] Intel Corporation, "RC82540EM Gigabit Ethernet Controller Product Brief." https://www.mouser.com/catalog/specsheets/Intel-RC82540EM-7623794.pdf

[IntelGbEPCI] Intel Corporation, "PCI/PCI-X Family of Gigabit Ethernet Controllers Software Developer's Manual." https://www.intel.com/content/dam/doc/manual/pci-pci-x-family-gbe-controllers-software-dev-manual.pdf

[Paging_Zolutal] Zolutal, "Understanding x86-64 Paging," 2023. https://blog.zolutal.io/understanding-paging/

[Paging_UW] University of Washington CSE 451, "x86-64 Paging Lecture Notes," 2024. https://courses.cs.washington.edu/courses/cse451/24sp/lectures/notes/x86-paging.html

[Paging_Graz] TU Graz, "Paging on Intel x86-64 Tutorial." https://www.isec.tugraz.at/teaching/materials/os/tutorials/paging-on-intel-x86-64/

[MemTutor] T. Voipio, "Memory Management Tutorial," HUT, 2001. https://web.archive.org/web/20081206102136/http://www.cs.hut.fi/~tvoipio/memtutor.html

[Slab] J. Bonwick, "The Slab Allocator: An Object-Caching Kernel Memory Allocator," USENIX 1994.

[LittleOSBook] E. Helin, A. Renberg, "The Little Book About OS Development," 2015. https://littleosbook.github.io/book.pdf

[OSDev_Main] OSDev Wiki, "Expanded Main Page." https://wiki.osdev.org/Expanded_Main_Page

[XenProject] Xen Project, "Xen Hypervisor." https://xenproject.org/

[OSDev_MiniOSDev] Xen Project, "Mini-OS Developer Notes." https://wiki.xenproject.org/wiki/Mini-OS-DevNotes

[IntelMPK_Scribd] Various, "Software Abstraction for Intel Memory Protection Keys," 2019. https://www.scribd.com/document/963166363/Software-Abstraction-for-Intel-Memory-Protection-Keys

[IntelMPK_IEEE] Various, "Intel MPK Survey," IEEE 2023. https://ieeexplore.ieee.org/ielaam/8013/10137354/10077209-aam.pdf

[KernelMPK] Linux Kernel Documentation, "Memory Protection Keys." https://docs.kernel.org/core-api/protection-keys.html

[RS232] Wikipedia, "RS-232 / DE-9 Connector." https://en.wikipedia.org/wiki/RS-232

[OSDev_Serial] OSDev Wiki, "Serial Ports." https://wiki.osdev.org/Serial_Port

[OSDev_UART] OSDev Wiki, "UART." https://wiki.osdev.org/UART

[OSDev_PCI] OSDev Wiki, "PCI." https://wiki.osdev.org/PCI

[OSDev_PF] OSDev Wiki, "I Can't Get Interrupts Working — Problems with IDTs." https://wiki.osdev.org/I_Can%27t_Get_Interrupts_Working

[OSDev_InterruptsTut] OSDev Wiki, "Interrupts Tutorial." https://wiki.osdev.org/Interrupts_Tutorial

[OSDev_PageTables] OSDev Wiki, "Page Tables." https://wiki.osdev.org/Page_Tables

[OSDev_Paging] OSDev Wiki, "Paging." https://wiki.osdev.org/Paging

[OSDev_IdentityPaging] OSDev Wiki, "Identity Paging." https://wiki.osdev.org/Identity_Paging

[OSDev_PageFrameAlloc] OSDev Wiki, "Page Frame Allocation." https://wiki.osdev.org/Page_Frame_Allocation

[OSDev_WritingPageFrameAlloc] OSDev Wiki, "Writing A Page Frame Allocator." https://wiki.osdev.org/Writing_A_Page_Frame_Allocator

[OSDev_SettingUpPaging] OSDev Wiki, "Setting Up Paging." https://wiki.osdev.org/Setting_Up_Paging

[OSDev_MemMgmt] OSDev Wiki, "Memory Management." https://wiki.osdev.org/Memory_management

[OSDev_ProgramMemAllocTypes] OSDev Wiki, "Program Memory Allocation Types." https://wiki.osdev.org/Program_Memory_Allocation_Types

[OSDev_Heap] OSDev Wiki, "Heap." https://wiki.osdev.org/Heap

[OSDev_HeapImpl] OSDev Wiki, "Heap Implementations (Pancakes series)." https://wiki.osdev.org/Writing_a_memory_manager

[OSDev_SimpleHeap] OSDev Wiki, "User:Pancakes/SimpleHeapImplementation." https://wiki.osdev.org/User:Pancakes/SimpleHeapImplementation

[OSDev_LinkedListHeap] OSDev Wiki, "User:Mrvn/LinkedListBucketHeapImplementation." https://wiki.osdev.org/User:Mrvn/LinkedListBucketHeapImplementation

[OSDev_BitmapHeap] OSDev Wiki, "User:Pancakes/BitmapHeapImplementation." https://wiki.osdev.org/User:Pancakes/BitmapHeapImplementation

[OSDev_GarbageCollection] OSDev Wiki, "Garbage Collection." https://wiki.osdev.org/Garbage_collection

[OSDev_MMU] OSDev Wiki, "Memory Management Unit." https://wiki.osdev.org/Memory_Management_Unit

[OSDev_Segmentation] OSDev Wiki, "Segmentation." https://wiki.osdev.org/Segmentation

[OSDev_InlineAsm] OSDev Wiki, "Inline Assembly." https://wiki.osdev.org/Inline_Assembly

[OSDev_UEFI] OSDev Wiki, "UEFI." https://wiki.osdev.org/UEFI

[OSDev_OVMF] OSDev Wiki, "OVMF (Open Virtual Machine Firmware)." https://wiki.osdev.org/OVMF

[OSDev_GNU_EFI] OSDev Wiki, "GNU-EFI." https://wiki.osdev.org/GNU-EFI

[OSDev_Bootloader] OSDev Wiki, "Bootloader." https://wiki.osdev.org/Bootloader

[OSDev_A20] OSDev Wiki, "A20 Line." https://wiki.osdev.org/A20_Line

[OSDev_CPUID] OSDev Wiki, "CPUID." https://wiki.osdev.org/CPUID

[OSDev_BeginnerMistakes] OSDev Wiki, "Beginner Mistakes." https://wiki.osdev.org/Beginner_Mistakes

[OSDev_GoingFurther] OSDev Wiki, "Going Further on x86." https://wiki.osdev.org/Going_Further_on_x86

[OSDev_HigherHalfBB] OSDev Wiki, "Higher Half x86 Bare Bones." https://wiki.osdev.org/Higher_Half_x86_Bare_Bones

[OSDev_DetectMem] OSDev Wiki, "Detecting Memory (x86)." https://wiki.osdev.org/Detecting_Memory_(x86)

[OSDev_DebugUEFI] OSDev Wiki, "Debugging UEFI Applications with GDB." https://wiki.osdev.org/Debugging_UEFI_applications_with_GDB

[OSDev_8254x] OSDev Wiki, "Intel 8254x." https://wiki.osdev.org/Intel_8254x

[ContainerSolUnikernels1] Container Solutions, "All About Unikernels Part 1: What They Are." https://blog.container-solutions.com/all-about-unikernels-part-1-what-they-are

[ContainerSolUnikernels2] Container Solutions, "All About Unikernels Part 2: MirageOS and Rumprun." https://blog.container-solutions.com/all-about-unikernels-part-2-mirageos-and-rumprun

[LPI_Xen_Unikernels] Linux Professional Institute, "Xen Virtualization and Cloud Computing 05: Xen Project Unikernels and Future," 2020. https://www.lpi.org/blog/2020/10/29/xen-virtualization-and-cloud-computing-05-xen-project-unikernels-and-future/

[NXP_lwIP] NXP, "Developing LwIP Application with Sequential API," MCUXpresso SDK Knowledge Base, 2021. https://community.nxp.com/t5/MCUXpresso-SDK-Knowledge-Base/Developing-LwIP-Application-with-Sequential-API/ta-p/1098996

[Infradead_MPK] M. Chehab, "Memory Protection Keys (rst conversion)." https://www.infradead.org/~mchehab/rst_conversion/core-api/protection-keys.html

[ClickOS_GH] Sysml, "ClickOS: High-Performance Virtualized Software Middle Boxes." https://github.com/sysml/clickos

[UEFISpecs] UEFI Forum, "UEFI Specifications." https://uefi.org/specifications

[WikipediaSlab] Wikipedia, "Slab Allocation." https://en.wikipedia.org/wiki/Slab_allocation

---