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
import struct

PAGE_SIZE = 4096

# ─── PKRU register ────────────────────────────────────────────────────

def read_pkru():
    """Read PKRU via RDPKRU instruction through GDB expression."""
    try:
        # x86-64: PKRU is a user-mode register, readable via
        # the 'pkru' pseudo-register in modern GDB builds.
        val = gdb.parse_and_eval("$pkru")
        return int(val)
    except gdb.error:
        # Fallback: execute RDPKRU in the target and read EAX.
        # This requires the target to be stopped.
        try:
            gdb.execute("p/x (unsigned int)($pkru)", to_string=True)
        except:
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
    try:
        start = int(gdb.parse_and_eval(f"&{start_sym}"))
        end   = int(gdb.parse_and_eval(f"&{end_sym}"))
    except gdb.error as e:
        print(f"  Cannot resolve {start_sym}: {e}")
        return

    print(f"  Section: {section_name}")
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
        for addr, reason in bad[:5]:  # cap output
            print(f"    0x{addr:016X} — {reason}")
    else:
        print("  ✓ All pages correctly tagged")
    print()


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
                print("  Cannot read PKRU — target may not support it")
                print("  Try: (gdb) p/x (int)($pkru)  or check GDB version")
            if arg == "pkru":
                return

        # ── PTE walk ──
        if not arg or arg == "ptes":
            print("\n[3] Page table walk — protection key in PTEs")
            print("-" * 40)

            # Read PML4 physical address from the kernel global
            try:
                pml4_ptr = int(gdb.parse_and_eval("kernel_pml4"))
                print(f"  kernel_pml4 = 0x{pml4_ptr:016X}")
            except gdb.error:
                print("  Cannot read kernel_pml4 — is the kernel loaded?")
                print("  Load symbols: (gdb) symbol-file unikernel.debug")
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
print("MPK inspector loaded. Commands: mpk_check, mpk_check pkru, mpk_check ptes, mpk_check cr4")
