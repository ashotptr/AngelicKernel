# mpk_gdb.py — GDB Python script for MPK inspection
#
# Attaches to the QEMU GDB stub and verifies MPK isolation.
# Run from inside GDB:
#   (gdb) source mpk_gdb.py
#   (gdb) mpk_check
#
# Or run as a batch script:
#   gdb -x mpk_gdb.py -batch -ex "mpk_check" unikernel.debug
#
# Prerequisites (in run.sh or manually):
#   Add -s -S to QEMU flags to start with GDB server on :1234
#   Then connect: target remote :1234

import gdb
import re
import struct

PAGE_SIZE = 4096

# ─── EFI ASLR load offset ─────────────────────────────────────────────
#
# The EFI binary is compiled with -fpic and loaded at an arbitrary base by
# the UEFI firmware.  GDB symbols (from unikernel.debug) are at their
# pre-relocation addresses.  Section symbols like __secure_driver_code_start
# are therefore WRONG until the offset is applied.
#
# How to find the offset — easiest method:
#   1. Read the serial line: "Function 'init_network_stack' is at: 0x<RUNTIME>"
#   2. In GDB:  p/x 0x<RUNTIME> - (long)&init_network_stack
#      That expression prints the offset directly.
#   3. (gdb) mpk_set_offset <result>
#
# Alternatively fix all symbols at once with:
#   (gdb) add-symbol-file unikernel.debug <offset>
# which also makes breakpoints by name work correctly.

_load_offset = 0   # applied to every section symbol in PTE checks


# ─── PKRU register ────────────────────────────────────────────────────

def read_pkru():
    """Read PKRU via RDPKRU instruction through GDB expression."""
    # Strategy 1: $pkru pseudo-register (GDB >= 8.1 with x86 PKRU support)
    try:
        val = gdb.parse_and_eval("$pkru")
        return int(val)
    except gdb.error:
        pass

    # Strategy 2: parse 'info registers all' — works on QEMU >= 7.0 with
    # -cpu max,+pku even when GDB doesn't expose the pseudo-register.
    # The line looks like: "pkru           0xc                 12"
    try:
        out = gdb.execute("info registers all", to_string=True)
        for line in out.splitlines():
            if "pkru" in line.lower():
                m = re.search(r'\b(0x[0-9a-fA-F]+)\b', line)
                if m:
                    return int(m.group(1), 16)
    except Exception:
        pass

    # Strategy 3: capture and parse 'p/x $pkru' output
    # Output format: "$N = 0x..." or "No register named..."
    try:
        out = gdb.execute("p/x $pkru", to_string=True)
        m = re.search(r'=\s*(0x[0-9a-fA-F]+)', out)
        if m:
            return int(m.group(1), 16)
    except Exception:
        pass

    return None


def decode_pkru(pkru):
    """Decode PKRU value into per-key access rights."""
    print(f"  PKRU = 0x{pkru:08X}  ({pkru:032b} binary)")
    print()
    print(f"  {'Key':>4} {'AD':>4} {'WD':>4}  {'Meaning':<40}")
    print(f"  {'---':>4} {'--':>4} {'--':>4}  {'-------':<40}")
    for key in range(16):
        ad = (pkru >> (key * 2))     & 1
        wd = (pkru >> (key * 2 + 1)) & 1
        if key == 0:
            meaning = "Kernel / XMPP code (should be 00 = accessible)"
        elif key == 1:
            meaning = "e1000 driver       (should be 11 = FULLY BLOCKED)"
        else:
            meaning = "Unused" if (ad == 0 and wd == 0) else "WARNING: unexpected restriction"

        status = "✓" if ((key == 0 and ad == 0 and wd == 0) or
                          (key == 1 and ad == 1 and wd == 1) or
                          (key >= 2 and ad == 0 and wd == 0)) else "✗"
        print(f"  {status} {key:>4}   {ad:>2}   {wd:>2}  {meaning}")
    print()
    if (pkru & 0xC) == 0xC and (pkru & ~0xC) == 0:
        print("  ✓ PKRU CORRECT — driver domain fully isolated")
    elif pkru == 0:
        print("  ✗ PKRU = 0 — MPK not active (or not yet set)")
    else:
        print(f"  ✗ PKRU unexpected — expected 0x0000000C, got 0x{pkru:08X}")


# ─── CR4 / MPK enable bit ─────────────────────────────────────────────

def check_cr4_pke():
    """Verify CR4.PKE (bit 22) is set — prerequisite for WRPKRU."""
    try:
        cr4 = int(gdb.parse_and_eval("$cr4"))
        pke = (cr4 >> 22) & 1
        print(f"  CR4 = 0x{cr4:016X}")
        if pke:
            print("  ✓ CR4.PKE (bit 22) = 1 — WRPKRU/RDPKRU instructions enabled")
        else:
            print("  ✗ CR4.PKE (bit 22) = 0 — MPK instructions DISABLED")
            print("    mpk_enable() has not run or did not take effect")
        return pke
    except gdb.error as e:
        print(f"  Cannot read CR4: {e}")
        return None


# ─── Page-table walk ──────────────────────────────────────────────────

def read_qword(addr):
    """Read an 8-byte little-endian value from guest physical memory."""
    try:
        inf = gdb.inferiors()[0]
        mem = inf.read_memory(addr, 8)
        return struct.unpack_from('<Q', mem, 0)[0]
    except:
        return None


def walk_pte(virt, pml4_phys):
    """
    Walk the 4-level page table and return the PTE for `virt`.
    Returns (pte_value, pte_addr) or (None, None) if not mapped.
    """
    MASK = ~0xFFF & 0xFFFFFFFFFFFF  # strip flags, keep physical address

    def idx(v, shift): return (v >> shift) & 0x1FF

    pml4e_addr = pml4_phys + idx(virt, 39) * 8
    pml4e = read_qword(pml4e_addr)
    if pml4e is None or not (pml4e & 1):
        return None, None

    pdpe_addr = (pml4e & MASK) + idx(virt, 30) * 8
    pdpe = read_qword(pdpe_addr)
    if pdpe is None or not (pdpe & 1):
        return None, None

    pde_addr = (pdpe & MASK) + idx(virt, 21) * 8
    pde = read_qword(pde_addr)
    if pde is None or not (pde & 1):
        return None, None

    pte_addr = (pde & MASK) + idx(virt, 12) * 8
    pte = read_qword(pte_addr)
    return pte, pte_addr


def check_section_ptes(section_name, start_sym, end_sym, expected_key, pml4_phys):
    """Walk every page in a section and verify the protection key."""
    global _load_offset
    try:
        start = int(gdb.parse_and_eval(f"&{start_sym}")) + _load_offset
        end   = int(gdb.parse_and_eval(f"&{end_sym}"))   + _load_offset
    except gdb.error as e:
        print(f"  Cannot resolve {start_sym}: {e}")
        return

    offset_note = f"  (load offset 0x{_load_offset:X} applied)" if _load_offset else ""
    print(f"  Section: {section_name}{offset_note}")
    print(f"  Range:   0x{start:016X} — 0x{end:016X}  ({(end-start)//PAGE_SIZE} pages)")

    if start >= end:
        print("  (empty)\n")
        return

    ok = 0
    bad = []
    for addr in range(start, end, PAGE_SIZE):
        pte, pte_addr = walk_pte(addr, pml4_phys)
        if pte is None:
            bad.append((addr, "NOT MAPPED"))
            continue
        key = (pte >> 59) & 0xF
        if key == expected_key:
            ok += 1
        else:
            bad.append((addr, f"key={key} (expected {expected_key}), PTE=0x{pte:016X}"))

    print(f"  ✓ Correctly tagged (key={expected_key}): {ok} page(s)")
    if bad:
        print(f"  ✗ INCORRECT: {len(bad)} page(s)")
        for addr, reason in bad[:5]:
            print(f"    0x{addr:016X} — {reason}")
        if not _load_offset:
            print()
            print("  ↳ HINT: addresses look like pre-relocation symbols.")
            print("    Read serial: 'init_network_stack is at: 0x<RUNTIME>'")
            print("    In GDB: p/x 0x<RUNTIME> - (long)&init_network_stack")
            print("    Then:   mpk_set_offset <result>")
            print("    Or:     add-symbol-file unikernel.debug <result>")
    else:
        print("  ✓ All pages correctly tagged")
    print()


# ─── mpk_set_offset command ───────────────────────────────────────────

class MPKSetOffsetCommand(gdb.Command):
    """
    mpk_set_offset <hex> — set EFI ASLR load offset for section symbols.

    The EFI binary is PIC; GDB symbols are at pre-relocation addresses.
    This offset is added to every section symbol (__secure_driver_code_start
    etc.) before the PTE walk so the correct runtime addresses are checked.

    How to compute it (run before mpk_check ptes):
      1. Read serial output: "Function 'init_network_stack' is at: 0x<R>"
      2. In GDB: p/x 0x<R> - (long)&init_network_stack
         The result IS the offset.
      3. (gdb) mpk_set_offset <result>

    Example:
      Serial says init_network_stack = 0x1DECD726
      (gdb) p/x 0x1DECD726 - (long)&init_network_stack
      $1 = 0x1deb9000
      (gdb) mpk_set_offset 0x1deb9000
      (gdb) mpk_check ptes

    Tip: 'add-symbol-file unikernel.debug <offset>' fixes ALL symbols
    at once (breakpoints by name, xmpp_route_stanza spot-check, etc.)
    and makes mpk_set_offset unnecessary.
    """

    def __init__(self):
        super().__init__("mpk_set_offset", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global _load_offset
        arg = arg.strip()
        if not arg:
            if _load_offset:
                print(f"  Current load offset: 0x{_load_offset:016X}")
            else:
                print("  Load offset: 0 (not set — section symbols are pre-relocation)")
            print("  Usage: mpk_set_offset <hex_offset>")
            print("  Compute: p/x 0x<runtime_init_network_stack> - (long)&init_network_stack")
            return
        try:
            _load_offset = int(arg, 16)
            print(f"  ✓ Load offset set to 0x{_load_offset:016X}")
            print(f"    All section symbols will be shifted by this amount.")
            print(f"    Run: mpk_check ptes")
        except ValueError:
            print(f"  ✗ Invalid hex value: '{arg}'")


MPKSetOffsetCommand()

# ─── GDB command ─────────────────────────────────────────────────────

class MPKCheckCommand(gdb.Command):
    """
    mpk_check — verify MPK isolation state.

    Usage:
      (gdb) mpk_check
      (gdb) mpk_check pkru       # just print PKRU
      (gdb) mpk_check ptes       # just walk page tables
      (gdb) mpk_check cr4        # just check CR4.PKE
    """

    def __init__(self):
        super().__init__("mpk_check", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        arg = arg.strip().lower()
        print()
        print("=" * 60)
        print(" MPK Isolation Inspector")
        print("=" * 60)

        # ── CR4.PKE ──
        if not arg or arg == "cr4":
            print("\n[1] CR4.PKE — MPK instruction enable")
            print("-" * 40)
            pke = check_cr4_pke()
            if arg == "cr4":
                return

        # ── PKRU ──
        if not arg or arg == "pkru":
            print("\n[2] PKRU register — per-key access rights")
            print("-" * 40)
            pkru = read_pkru()
            if pkru is not None:
                decode_pkru(pkru)
            else:
                print("  Cannot read PKRU via $pkru, 'info registers all', or p/x $pkru")
                print("  Requirements: GDB >= 8.1, QEMU >= 7.0, -cpu max,+pku")
                print("  The kernel's own RDPKRU in mpk_diagnostic.c is authoritative;")
                print("  check the serial console output for the ground truth.")
            if arg == "pkru":
                return

        # ── PTE walk ──
        if not arg or arg == "ptes":
            print("\n[3] Page table walk — protection key in PTEs")
            print("-" * 40)

            # Read PML4 physical address.
            # Primary: kernel_pml4 symbol.
            # Fallback: $cr3 — vmm_init() writes kernel_pml4 into CR3, so
            #   they are always equal after vmm_init() runs.  The symbol
            #   reads as 0 when the EFI load offset hasn't been applied to
            #   GDB (the binary is PIC and UEFI places it at a random base).
            pml4_ptr = None
            try:
                val = int(gdb.parse_and_eval("kernel_pml4"))
                if val != 0:
                    pml4_ptr = val
                    print(f"  kernel_pml4 = 0x{pml4_ptr:016X}")
            except gdb.error:
                print("  Cannot read kernel_pml4 — is the kernel loaded?")
                print("  Load symbols: (gdb) symbol-file unikernel.debug")

            if not pml4_ptr:
                try:
                    cr3 = int(gdb.parse_and_eval("$cr3")) & ~0xFFF
                    if cr3:
                        pml4_ptr = cr3
                        print(f"  kernel_pml4 = 0x0 (EFI ASLR — symbol pre-relocation)")
                        print(f"  $cr3        = 0x{cr3:016X}  ← using as PML4 address")
                        print(f"  (vmm_init() stores kernel_pml4 in CR3; they are always equal)")
                    else:
                        print("  $cr3 is also 0 — vmm_init() has not run yet")
                        return
                except gdb.error as e:
                    print(f"  Cannot read $cr3 either: {e}")
                    return

            if not pml4_ptr:
                return

            print()
            check_section_ptes(
                ".secure_driver_code",
                "__secure_driver_code_start", "__secure_driver_code_end",
                1, pml4_ptr
            )
            check_section_ptes(
                ".secure_driver_data",
                "__secure_driver_data_start", "__secure_driver_data_end",
                1, pml4_ptr
            )

            # Also verify a known Key-0 address (XMPP handler) is NOT tagged
            print("  Spot-check: Key-0 page (xmpp_route_stanza)")
            try:
                xmpp_addr = int(gdb.parse_and_eval("xmpp_route_stanza"))
                pte, _ = walk_pte(xmpp_addr, pml4_ptr)
                if pte is not None:
                    key = (pte >> 59) & 0xF
                    if key == 0:
                        print(f"  ✓ xmpp_route_stanza @ 0x{xmpp_addr:016X}: key=0 (accessible to kernel)")
                    else:
                        print(f"  ✗ xmpp_route_stanza @ 0x{xmpp_addr:016X}: key={key} (UNEXPECTED — XMPP code locked)")
            except:
                print("  (xmpp_route_stanza not found — load debug symbols)")

        print()
        print("=" * 60)
        print()


MPKCheckCommand()
print("MPK inspector loaded.")
print("Commands: mpk_check, mpk_check pkru, mpk_check ptes, mpk_check cr4")
print("          mpk_set_offset <hex>  — fix EFI ASLR for PTE section walk")