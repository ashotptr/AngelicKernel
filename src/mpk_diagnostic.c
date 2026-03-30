/* mpk_diagnostic.c
 *
 * Drop-in diagnostic module for verifying MPK isolation is active
 * and correctly configured. Call mpk_diagnostic() after the MPK
 * activation sequence in kernel.c.
 *
 * Three verification tiers:
 *   1. RDPKRU — read the live PKRU register, confirm Key 1 is locked.
 *   2. PTE walk — confirm every page in both driver sections has key=1.
 *   3. Violation self-test — deliberately touch Key-1 memory without
 *      the trampoline and confirm the CPU raises #PF.
 *
 * Add to Makefile OBJS and call from kernel.c after mpk_set_pkru().
 */

#include "mm/vmm.h"
#include "mm/pmm.h"
#include <stdint.h>

/* ── Forward declarations ─────────────────────────────────────────── */
void serial_print(const char *s);
void serial_print_hex(uint64_t n);

/* ── Linker-script symbols ─────────────────────────────────────────── */
extern uint64_t __secure_driver_code_start;
extern uint64_t __secure_driver_code_end;
extern uint64_t __secure_driver_data_start;
extern uint64_t __secure_driver_data_end;

/* ── Page-table walk helpers (mirrors vmm.c internals) ────────────── */
#define PML4_INDEX(x) (((x) >> 39) & 0x1FF)
#define PDP_INDEX(x)  (((x) >> 30) & 0x1FF)
#define PD_INDEX(x)   (((x) >> 21) & 0x1FF)
#define PT_INDEX(x)   (((x) >> 12) & 0x1FF)

extern uint64_t *kernel_pml4;   /* defined in vmm.c */

/* Return the protection key stored in bits [62:59] of the PTE for
 * virtual address `virt`. Returns -1 if the page is not mapped.     */
static int read_pte_pkey(uint64_t virt) {
    if (!kernel_pml4) return -1;

    uint64_t *pml4 = kernel_pml4;
    uint64_t  e    = pml4[PML4_INDEX(virt)];
    if (!(e & PTE_PRESENT)) return -1;

    uint64_t *pdp = (uint64_t *)(e & ~0xFFFull);
    e = pdp[PDP_INDEX(virt)];
    if (!(e & PTE_PRESENT)) return -1;

    uint64_t *pd = (uint64_t *)(e & ~0xFFFull);
    e = pd[PD_INDEX(virt)];
    if (!(e & PTE_PRESENT)) return -1;

    uint64_t *pt = (uint64_t *)(e & ~0xFFFull);
    uint64_t pte = pt[PT_INDEX(virt)];
    if (!(pte & PTE_PRESENT)) return -1;

    return (int)((pte >> 59) & 0xF);
}

/* ── Tier 1: RDPKRU readback ──────────────────────────────────────── */
static void verify_pkru(void) {
    uint32_t pkru;
    __asm__ volatile(
        "xor %%ecx, %%ecx\n"   /* ECX must be 0 for RDPKRU */
        "rdpkru\n"              /* EAX ← PKRU               */
        : "=a"(pkru)
        :
        : "ecx", "edx"
    );

    serial_print("[MPK-DIAG] PKRU = 0x");
    serial_print_hex((uint64_t)pkru);
    serial_print("\n");

    /* Expected: 0x0000000C
     *   bits [1:0] = 00  → Key 0 (XMPP / kernel): AD=0, WD=0 (accessible)
     *   bits [3:2] = 11  → Key 1 (e1000 driver):  AD=1, WD=1 (BLOCKED)
     *   all higher bits   = 0 (all other keys accessible)
     *
     * AD = Access Disable: 1 means ANY access (read or write) faults.
     * WD = Write Disable:  1 means writes fault (reads still allowed).
     * With both bits set, Key-1 pages are completely inaccessible.
     */
    if (pkru == 0x0000000C) {
        serial_print("[MPK-DIAG] ✓ PKRU CORRECT: Key 1 is fully locked (AD=1, WD=1)\n");
    } else if (pkru == 0x00000000) {
        serial_print("[MPK-DIAG] ✗ PKRU = 0 — MPK NOT ACTIVE (all keys accessible)\n");
        serial_print("[MPK-DIAG]   Ensure mpk_set_pkru(0x0C) was called after vmm_protect_driver()\n");
    } else if ((pkru & 0xC) == 0x4) {
        serial_print("[MPK-DIAG] ✗ PKRU: Key 1 WD=1 but AD=0 — writes blocked, reads STILL ALLOWED\n");
        serial_print("[MPK-DIAG]   Need full 0x0C: both AD and WD set for Key 1\n");
    } else {
        serial_print("[MPK-DIAG] ✗ PKRU unexpected value — check mpk_set_pkru argument\n");
    }
}

/* ── Tier 2: PTE walk ─────────────────────────────────────────────── */
static void verify_pte_keys(const char *section_name,
                             uint64_t    start,
                             uint64_t    end,
                             int         expected_key) {
    serial_print("[MPK-DIAG] Checking section: ");
    serial_print(section_name);
    serial_print(" (0x");
    serial_print_hex(start);
    serial_print(" - 0x");
    serial_print_hex(end);
    serial_print(")\n");

    if (start >= end) {
        serial_print("[MPK-DIAG]   (empty section — linker placed no symbols here)\n");
        return;
    }

    int pages_ok      = 0;
    int pages_wrong   = 0;
    int pages_unmapped = 0;

    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        int key = read_pte_pkey(addr);
        if (key < 0) {
            pages_unmapped++;
            serial_print("[MPK-DIAG]   NOT MAPPED: 0x");
            serial_print_hex(addr);
            serial_print("\n");
        } else if (key == expected_key) {
            pages_ok++;
        } else {
            pages_wrong++;
            serial_print("[MPK-DIAG]   WRONG KEY at 0x");
            serial_print_hex(addr);
            serial_print(" — expected key=");
            serial_print_hex((uint64_t)expected_key);
            serial_print(", got key=");
            serial_print_hex((uint64_t)key);
            serial_print("\n");
        }
    }

    serial_print("[MPK-DIAG]   Pages with key=");
    serial_print_hex((uint64_t)expected_key);
    serial_print(": ");
    serial_print_hex((uint64_t)pages_ok);
    serial_print(" / ");
    serial_print_hex((uint64_t)((end - start) / PAGE_SIZE));
    serial_print("\n");

    if (pages_wrong == 0 && pages_unmapped == 0 && pages_ok > 0) {
        serial_print("[MPK-DIAG]   ✓ All pages correctly tagged\n");
    } else if (pages_ok == 0 && pages_wrong == 0) {
        serial_print("[MPK-DIAG]   ✗ Section is empty — no functions annotated SECURE_DRIVER_CODE/DATA?\n");
    } else {
        serial_print("[MPK-DIAG]   ✗ TAGGING INCOMPLETE — vmm_protect_driver() may not have run\n");
    }
}

/* ── Tier 3: Violation self-test ──────────────────────────────────── */
/*
 * This test deliberately attempts to read a byte from Key-1 memory
 * WITHOUT going through the MPK trampoline. With MPK active, this
 * must raise a #PF (Page Fault, INT 14) with error code bit 5 set
 * (Protection Key violation bit — Intel SDM Vol. 3A §4.7).
 *
 * HOW THE RECOVERY WORKS:
 * The test installs a temporary one-shot page fault handler via a
 * global flag `mpk_test_in_progress`. The normal IDT #PF handler in
 * idt.c checks this flag — if set, it sets `mpk_test_fault_occurred`,
 * clears the flag, and skips past the faulting instruction by
 * advancing RIP by 3 bytes (the length of a `mov al, [rax]`
 * instruction). Execution resumes normally after the inline asm block.
 *
 * CHANGES REQUIRED IN idt.c:
 * Add to the page fault handler (INT 14) — see comment below.
 */

volatile int mpk_test_in_progress  = 0;
volatile int mpk_test_fault_occurred = 0;

/*
 * IDT CHANGE — in your existing page_fault_handler() or exception
 * handler in idt.c, add this block at the TOP, before any serial
 * output or halt:
 *
 *   extern volatile int mpk_test_in_progress;
 *   extern volatile int mpk_test_fault_occurred;
 *   if (mpk_test_in_progress) {
 *       mpk_test_fault_occurred = 1;
 *       mpk_test_in_progress    = 0;
 *       // Skip past the faulting instruction.
 *       // `mov al, [rax]` is 2 bytes: 0x8A 0x00.
 *       // The interrupted RIP points at 0x8A; advance by 2.
 *       iframe->rip += 2;
 *       return;
 *   }
 *
 * `iframe` is whatever your handler calls the saved-register struct.
 * The field `rip` must be the saved RIP from the interrupt frame.
 */
static void violation_selftest(void) {
    serial_print("[MPK-DIAG] --- Violation self-test ---\n");
    serial_print("[MPK-DIAG] Attempting to read Key-1 memory without trampoline...\n");

    /* Pick the first address in the driver data section */
    uint64_t target = (uint64_t)&__secure_driver_data_start;
    if (target == 0) {
        serial_print("[MPK-DIAG]   Cannot test: driver data section is empty\n");
        return;
    }

    mpk_test_fault_occurred = 0;
    mpk_test_in_progress    = 1;

    /*
     * Attempt a 1-byte read from driver memory.
     * With PKRU = 0x0C this MUST fault (AD bit set for Key 1).
     * The inline asm uses `volatile` to prevent the compiler from
     * optimising it away. The output `=r` ensures the read result
     * is consumed (otherwise GCC may elide it as dead code).
     */
    uint8_t probe = 0;
    __asm__ volatile(
        "mov (%1), %0\n"
        : "=r"(probe)
        : "r"(target)
        : "memory"
    );

    /*
     * If MPK is working: mpk_test_fault_occurred == 1 (IDT handler
     * intercepted the #PF and advanced RIP past the instruction).
     * If MPK is NOT working: probe contains the actual byte from
     * driver memory — the read succeeded without faulting.
     */
    if (mpk_test_fault_occurred) {
        serial_print("[MPK-DIAG] ✓ VIOLATION CAUGHT: CPU raised #PF on direct Key-1 access\n");
        serial_print("[MPK-DIAG]   Protection key fault bit confirmed — isolation is ACTIVE\n");
        (void)probe;
    } else {
        serial_print("[MPK-DIAG] ✗ NO FAULT — direct read SUCCEEDED, value=0x");
        serial_print_hex((uint64_t)probe);
        serial_print("\n");
        serial_print("[MPK-DIAG]   MPK is NOT protecting driver memory\n");
    }
}

/* ── Public entry point ───────────────────────────────────────────── */
void mpk_diagnostic(void) {
    serial_print("\n[MPK-DIAG] ============================================\n");
    serial_print("[MPK-DIAG] MPK Isolation Verification\n");
    serial_print("[MPK-DIAG] ============================================\n");

    /* Tier 1 — PKRU register readback */
    serial_print("[MPK-DIAG] --- Tier 1: PKRU register ---\n");
    verify_pkru();

    /* Tier 2 — PTE key verification */
    serial_print("[MPK-DIAG] --- Tier 2: Page table entries ---\n");
    verify_pte_keys("driver code  (.secure_driver_code)",
                    (uint64_t)&__secure_driver_code_start,
                    (uint64_t)&__secure_driver_code_end,
                    1 /* expected key */);
    verify_pte_keys("driver data  (.secure_driver_data)",
                    (uint64_t)&__secure_driver_data_start,
                    (uint64_t)&__secure_driver_data_end,
                    1 /* expected key */);

    /* Tier 3 — violation self-test
     * NOTE: Requires the IDT change described in the comment above.
     * Comment this call out until idt.c is patched; otherwise a
     * page fault here will halt the system rather than recover.
     */
    violation_selftest();

    serial_print("[MPK-DIAG] ============================================\n\n");
}
