#include "mm/vmm.h"
#include "mm/pmm.h"
#include <stdint.h>

void serial_print(const char *s);
void serial_print_hex(uint64_t n);

extern uint64_t __secure_driver_code_start;
extern uint64_t __secure_driver_code_end;
extern uint64_t __secure_driver_data_start;
extern uint64_t __secure_driver_data_end;

#define PML4_INDEX(x) (((x) >> 39) & 0x1FF)
#define PDP_INDEX(x) (((x) >> 30) & 0x1FF)
#define PD_INDEX(x) (((x) >> 21) & 0x1FF)
#define PT_INDEX(x) (((x) >> 12) & 0x1FF)

extern uint64_t *kernel_pml4;

static int read_pte_pkey(uint64_t virt) {
    if (!kernel_pml4) {
        return -1;
    }

    uint64_t *pml4 = kernel_pml4;
    uint64_t e = pml4[PML4_INDEX(virt)];
    
    if (!(e & PTE_PRESENT)) {
        return -1;
    }

    uint64_t *pdp = (uint64_t *)(e & ~0xFFFull);
    e = pdp[PDP_INDEX(virt)];
    
    if (!(e & PTE_PRESENT)) {
        return -1;
    }

    uint64_t *pd = (uint64_t *)(e & ~0xFFFull);
    e = pd[PD_INDEX(virt)];

    if (!(e & PTE_PRESENT)) {
        return -1;
    }

    uint64_t *pt = (uint64_t *)(e & ~0xFFFull);
    uint64_t pte = pt[PT_INDEX(virt)];

    if (!(pte & PTE_PRESENT)) {
        return -1;
    }

    return (int)((pte >> 59) & 0xF);
}

static void verify_pkru(void) {
    uint32_t pkru;

    __asm__ volatile(
        "xor %%ecx, %%ecx\n"
        "rdpkru\n"
        : "=a"(pkru)
        :
        : "ecx", "edx"
    );

    serial_print("[mpk_diag] pkru = 0x");
    serial_print_hex((uint64_t)pkru);
    serial_print("\n");

    if (pkru == 0x0000000C) {
        serial_print("[mpk_diag] ✓ pkru correct: key 1 is fully locked (ad=1, wd=1)\n");
    }
    else if (pkru == 0x00000000) {
        serial_print("[mpk_diag] ✗ pkru = 0 — mpk not active (all keys accessible)\n");
        serial_print("[mpk_diag] ensure mpk_set_pkru(0x0C) was called after vmm_protect_driver()\n");
    }
    else if ((pkru & 0xC) == 0x4) {
        serial_print("[mpk_diag] ✗ pkru: key 1 wd=1 but ad=0 — writes blocked, reads still allowed\n");
        serial_print("[mpk_diag] need full 0x0C: both ad and wd set for key 1\n");
    }
    else {
        serial_print("[mpk_diag] ✗ pkru unexpected value — check mpk_set_pkru argument\n");
    }
}

static void verify_pte_keys(const char *section_name, uint64_t start, uint64_t end, int expected_key) {
    serial_print("[mpk_diag] checking section: ");
    serial_print(section_name);
    serial_print(" (0x");
    serial_print_hex(start);
    serial_print(" - 0x");
    serial_print_hex(end);
    serial_print(")\n");

    if (start >= end) {
        serial_print("[mpk_diag] (empty section — linker placed no symbols here)\n");

        return;
    }

    int pages_ok = 0;
    int pages_wrong = 0;
    int pages_unmapped = 0;

    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        int key = read_pte_pkey(addr);

        if (key < 0) {
            pages_unmapped++;
            serial_print("[mpk_diag] not mapped: 0x");
            serial_print_hex(addr);
            serial_print("\n");
        }
        else if (key == expected_key) {
            pages_ok++;
        }
        else {
            pages_wrong++;
            serial_print("[mpk_diag] wrong key at 0x");
            serial_print_hex(addr);
            serial_print(" — expected key=");
            serial_print_hex((uint64_t)expected_key);
            serial_print(", got key=");
            serial_print_hex((uint64_t)key);
            serial_print("\n");
        }
    }

    serial_print("[mpk_diag] pages with key=");
    serial_print_hex((uint64_t)expected_key);
    serial_print(": ");
    serial_print_hex((uint64_t)pages_ok);
    serial_print(" / ");
    serial_print_hex((uint64_t)((end - start) / PAGE_SIZE));
    serial_print("\n");

    if (pages_wrong == 0 && pages_unmapped == 0 && pages_ok > 0) {
        serial_print("[mpk_diag] ✓ all pages correctly tagged\n");
    }
    else if (pages_ok == 0 && pages_wrong == 0) {
        serial_print("[mpk_diag] ✗ section is empty — no functions annotated .secure_driver_code/.secure_driver_data?\n");
    }
    else {
        serial_print("[mpk_diag] ✗ tagging incomplete — vmm_protect_driver() may not have run\n");
    }
}

volatile int mpk_test_in_progress = 0;
volatile int mpk_test_fault_occurred = 0;

static void violation_selftest(void) {
    serial_print("[mpk-diag] violation self-test\n");
    serial_print("[mpk-diag] attempting to read key-1 memory without trampoline\n");

    uint64_t target = (uint64_t)&__secure_driver_data_start;
    if (target == 0) {
        serial_print("[mpk-diag] cannot test: driver data section is empty\n");

        return;
    }

    mpk_test_fault_occurred = 0;
    mpk_test_in_progress = 1;

   uint8_t probe = 0;

    __asm__ volatile(
        "mov (%1), %b0\n"
        : "=a"(probe)
        : "r"(target)
        : "memory"
    );

    if (mpk_test_fault_occurred) {
        serial_print("[mpk-diag] ✓ violation caught: cpu raised #pf on direct key-1 access\n");
        serial_print("[mpk-diag] protection key fault bit confirmed — isolation is active\n");
        (void)probe;
    }
    else {
        serial_print("[mpk-diag] ✗ no fault — direct read succeeded, value=0x");
        serial_print_hex((uint64_t)probe);
        serial_print("\n");
        serial_print("[mpk-diag] mpk is not protecting driver memory\n");
    }
}

void mpk_diagnostic(void) {
    serial_print("\n[mpk-diag]\n");
    serial_print("[mpk-diag] mpk isolation verification\n");
    serial_print("[mpk-diag]\n");

    serial_print("[mpk-diag] pkru register\n");
    verify_pkru();

    serial_print("[mpk-diag] page table entries\n");
    verify_pte_keys("driver code (.secure_driver_code)", (uint64_t)&__secure_driver_code_start, (uint64_t)&__secure_driver_code_end, 1);
    verify_pte_keys("driver data (.secure_driver_data)", (uint64_t)&__secure_driver_data_start, (uint64_t)&__secure_driver_data_end, 1);

    violation_selftest();

    serial_print("[mpk-diag]\n\n");
}
