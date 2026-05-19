import gdb
import re
import struct

PAGE_SIZE = 4096

_load_offset = 0

def read_pkru():
    try:
        val = gdb.parse_and_eval("$pkru")

        return int(val)
    except gdb.error:
        pass

    try:
        out = gdb.execute("info registers all", to_string=True)

        for line in out.splitlines():
            if "pkru" in line.lower():
                m = re.search(r'\b(0x[0-9a-fA-F]+)\b', line)

                if m:
                    return int(m.group(1), 16)
    except Exception:
        pass

    try:
        out = gdb.execute("p/x $pkru", to_string=True)

        m = re.search(r'=\s*(0x[0-9a-fA-F]+)', out)

        if m:
            return int(m.group(1), 16)
    except Exception:
        pass

    return None


def decode_pkru(pkru):
    print(f"pkru = 0x{pkru:08X} ({pkru:032b} binary)")
    print()
    print(f"{'key':>4} {'ad':>4} {'wd':>4} {'meaning':<40}")
    print(f"{'---':>4} {'--':>4} {'--':>4} {'-------':<40}")

    for key in range(16):
        ad = (pkru >> (key * 2)) & 1
        wd = (pkru >> (key * 2 + 1)) & 1

        if key == 0:
            meaning = "kernel / xmpp code (should be 00 = accessible)"
        elif key == 1:
            meaning = "e1000 driver (should be 11 = fully blocked)"
        else:
            meaning = "unused" if (ad == 0 and wd == 0) else "warning: unexpected restriction"

        status = "✓" if ((key == 0 and ad == 0 and wd == 0) or (key == 1 and ad == 1 and wd == 1) or (key >= 2 and ad == 0 and wd == 0)) else "✗"

        print(f"{status} {key:>4} {ad:>2} {wd:>2} {meaning}")

    print()

    if (pkru & 0xC) == 0xC and (pkru & ~0xC) == 0:
        print("✓ pkru correct — driver domain fully isolated")
    elif pkru == 0:
        print("✗ pkru = 0 — mpk not active (or not yet set)")
    else:
        print(f"✗ pkru unexpected — expected 0x0000000C, got 0x{pkru:08X}")

def check_cr4_pke():
    try:
        cr4 = int(gdb.parse_and_eval("$cr4"))
        pke = (cr4 >> 22) & 1

        print(f"cr4 = 0x{cr4:016X}")

        if pke:
            print("✓ cr4")
        else:
            print("✗ cr4")
            print("mpk_enable() has not run or did not take effect")
        return pke
    except gdb.error as e:
        print(f"cannot read cr4: {e}")

        return None

def read_qword(addr):
    try:
        inf = gdb.inferiors()[0]
        mem = inf.read_memory(addr, 8)

        return struct.unpack_from('<Q', mem, 0)[0]
    except:
        return None


def walk_pte(virt, pml4_phys):
    MASK = ~0xFFF & 0xFFFFFFFFFFFF

    def idx(v, shift):
        return (v >> shift) & 0x1FF

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
    global _load_offset

    try:
        start = int(gdb.parse_and_eval(f"&{start_sym}")) + _load_offset
        end = int(gdb.parse_and_eval(f"&{end_sym}")) + _load_offset
    except gdb.error as e:
        print(f"cannot resolve {start_sym}: {e}")

        return

    offset_note = f"(load offset 0x{_load_offset:X} applied)" if _load_offset else ""

    print(f"section: {section_name}{offset_note}")
    print(f"range: 0x{start:016X} — 0x{end:016X} ({(end-start)//PAGE_SIZE} pages)")

    if start >= end:
        print("(empty)\n")

        return

    ok = 0
    bad = []

    for addr in range(start, end, PAGE_SIZE):
        pte, pte_addr = walk_pte(addr, pml4_phys)

        if pte is None:
            bad.append((addr, "not mapped"))

            continue

        key = (pte >> 59) & 0xF

        if key == expected_key:
            ok += 1
        else:
            bad.append((addr, f"key={key} (expected {expected_key}), pte=0x{pte:016X}"))

    print(f"✓ correctly tagged (key={expected_key}): {ok} page(s)")

    if bad:
        print(f"✗ incorrect: {len(bad)} page(s)")

        for addr, reason in bad[:5]:
            print(f"0x{addr:016X} — {reason}")
        if not _load_offset:
            print()
    else:
        print("✓ all pages correctly tagged")

    print()

class MPKSetOffsetCommand(gdb.Command):
    def __init__(self):
        super().__init__("mpk_set_offset", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global _load_offset

        arg = arg.strip()

        if not arg:
            if _load_offset:
                print(f"current load offset: 0x{_load_offset:016X}")
            else:
                print("load offset: 0 (not set — section symbols are pre-relocation)")

            print("usage: mpk_set_offset <hex_offset>")
            print("compute: p/x 0x<runtime_init_network_stack> - (long)&init_network_stack")
            
            return
        try:
            _load_offset = int(arg, 16)

            print(f"✓ load offset set to 0x{_load_offset:016X}")
            print(f"all section symbols will be shifted by this amount.")
            print(f"run: mpk_check ptes")
        except ValueError:
            print(f"✗ invalid hex value: '{arg}'")


MPKSetOffsetCommand()

class MPKCheckCommand(gdb.Command):
    def __init__(self):
        super().__init__("mpk_check", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        arg = arg.strip().lower()

        print()
        print("mpk isolation inspector")

        if not arg or arg == "cr4":
            print("\ncr4.pke — mpk instruction enable")

            pke = check_cr4_pke()

            if arg == "cr4":
                return

        if not arg or arg == "pkru":
            print("\nprku register — per-key access rights")

            pkru = read_pkru()

            if pkru is not None:
                decode_pkru(pkru)
            else:
                print("cannot read pkru via $pkru, 'info registers all', or p/x $pkru")
            if arg == "pkru":
                return

        if not arg or arg == "ptes":
            print("\npage table walk — protection key in ptes")

            pml4_ptr = None

            try:
                val = int(gdb.parse_and_eval("kernel_pml4"))

                if val != 0:
                    pml4_ptr = val

                    print(f"kernel_pml4 = 0x{pml4_ptr:016X}")
            except gdb.error:
                print("cannot read kernel_pml4")

            if not pml4_ptr:
                try:
                    cr3 = int(gdb.parse_and_eval("$cr3")) & ~0xFFF

                    if cr3:
                        pml4_ptr = cr3

                        print(f"kernel_pml4 = 0x0 (efi aslr — symbol pre-relocation)")
                        print(f"$cr3 = 0x{cr3:016X} using as pml4 address")
                        print(f"(vmm_init() stores kernel_pml4 in cr3)")
                    else:
                        print("$cr3 is also 0 — vmm_init() has not run yet")

                        return
                except gdb.error as e:
                    print(f"cannot read $cr3 either: {e}")

                    return

            if not pml4_ptr:
                return

            print()

            check_section_ptes(".secure_driver_code", "__secure_driver_code_start", "__secure_driver_code_end", 1, pml4_ptr)
            check_section_ptes(".secure_driver_data", "__secure_driver_data_start", "__secure_driver_data_end", 1, pml4_ptr)

            print("spot-check: key-0 page (xmpp_route_stanza)")

            try:
                xmpp_addr = int(gdb.parse_and_eval("xmpp_route_stanza"))
                pte, _ = walk_pte(xmpp_addr, pml4_ptr)

                if pte is not None:
                    key = (pte >> 59) & 0xF

                    if key == 0:
                        print(f"✓ xmpp_route_stanza @ 0x{xmpp_addr:016X}: key=0 (accessible to kernel)")
                    else:
                        print(f"✗ xmpp_route_stanza @ 0x{xmpp_addr:016X}: key={key} (unexpected — xmpp code locked)")
            except:
                print("(xmpp_route_stanza not found — load debug symbols)")

        print()
        print()


MPKCheckCommand()
print("mpk inspector loaded.")
print("commands: mpk_check, mpk_check pkru, mpk_check ptes, mpk_check cr4")
print("mpk_set_offset <hex> — fix efi aslr for pte section walk")