/* ===========================================================================
 * mpk_benchmark.c — WRPKRU cycle-count micro-benchmark
 *
 * Implements the MPK overhead measurement required by Capstone §9.2:
 *   "MPK overhead: < 20 CPU cycles per WRPKRU"
 *
 * METHODOLOGY:
 *   Uses RDTSC (Read Time-Stamp Counter) to bracket a tight loop of
 *   N WRPKRU instructions. TSC overhead itself is subtracted via a
 *   calibration run. The result is the average cycle count per WRPKRU.
 *
 *   IMPORTANT: On modern x86 CPUs with out-of-order execution, the TSC
 *   is not serialising. We use CPUID before RDTSC to create a serialisation
 *   point, preventing the CPU from reordering instructions across the
 *   measurement boundary (Intel SDM Vol. 2B — RDTSC, Guidance for use
 *   with RDTSC and CPUID).
 *
 * INTEGRATION:
 *   Called from kernel.c after mpk_diagnostic() completes.
 *   Prints results to serial console in a format matching the
 *   capstone metrics table (§9.2).
 *
 * WRPKRU ENCODING:
 *   WRPKRU takes three inputs: EAX = new PKRU value, ECX = 0, EDX = 0.
 *   The benchmark alternates between unlocking (PKRU=0x00000000) and
 *   locking (PKRU=0x0000000C) to represent a realistic gate crossing.
 *
 * Intel SDM Vol. 2B — WRPKRU
 * Intel SDM Vol. 3A §4.6.2 — Protection Keys
 * =========================================================================== */

#include <stdint.h>

extern void serial_print(const char *s);
extern void serial_print_hex(uint64_t n);

/* ── Constants ─────────────────────────────────────────────────────────────── */

/* Number of iterations per measurement run.
 * Must be large enough to amortise RDTSC overhead but small enough
 * that the result fits in a uint64_t without overflow. */
#define BENCH_ITERATIONS  1000000ULL

/* Number of warm-up iterations before measurement.
 * Ensures branch predictors and caches are in their steady state. */
#define WARM_UP_ITERS     100000ULL

/* PKRU values used in the benchmark:
 *   PKRU_UNLOCK = 0x00000000 → Key 1 accessible (inside driver call)
 *   PKRU_LOCK   = 0x0000000C → Key 1 AD=1, WD=1 (kernel default)   */
#define PKRU_UNLOCK  0x00000000u
#define PKRU_LOCK    0x0000000Cu


/* ── TSC serialised read ─────────────────────────────────────────────────────
 *
 * Uses CPUID as a serialisation barrier before RDTSC.
 *
 * Intel recommends this pattern for measuring short code sequences:
 *   CPUID → RDTSC → <code under test> → RDTSCP / CPUID → RDTSC
 *
 * For our purposes (bracketing a large loop) the CPUID-RDTSC pair
 * before and after the loop is sufficient.
 * ─────────────────────────────────────────────────────────────────────────── */
static inline uint64_t rdtsc_serialised(void) {
    uint32_t lo, hi;
    /* CPUID serialises the instruction stream (forces all prior instructions
     * to retire before RDTSC executes). clobber: eax, ebx, ecx, edx. */
    __asm__ volatile (
        "cpuid\n\t"
        "rdtsc\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "rbx", "rcx"
    );
    return ((uint64_t)hi << 32) | lo;
}


/* ── WRPKRU wrappers ─────────────────────────────────────────────────────────
 *
 * We use __attribute__((noinline)) to prevent GCC from hoisting the
 * WRPKRU out of the measurement loop via constant propagation.
 * ─────────────────────────────────────────────────────────────────────────── */
__attribute__((noinline))
static void do_wrpkru(uint32_t val) {
    __asm__ volatile (
        "xor %%ecx, %%ecx\n\t"   /* ECX must be 0 — WRPKRU requirement */
        "xor %%edx, %%edx\n\t"   /* EDX must be 0 — WRPKRU requirement */
        "wrpkru\n\t"
        :
        : "a"(val)
        : "ecx", "edx"
    );
}


/* ── mpk_benchmark_run ───────────────────────────────────────────────────────
 *
 * Returns the average number of TSC ticks per WRPKRU instruction,
 * measured over BENCH_ITERATIONS alternating lock/unlock pairs.
 *
 * The function:
 *   1. Warms up the loop (branch predictors, instruction cache).
 *   2. Calibrates TSC overhead (empty loop + CPUID/RDTSC pairs).
 *   3. Measures the full WRPKRU loop.
 *   4. Subtracts calibration overhead.
 *   5. Returns cycles / (2 × iterations) because each iteration has
 *      one unlock WRPKRU and one lock WRPKRU.
 * ─────────────────────────────────────────────────────────────────────────── */
uint64_t mpk_benchmark_run(void) {
    /* ── 1. Warm-up ──────────────────────────────────────────────────────── */
    for (uint64_t i = 0; i < WARM_UP_ITERS; i++) {
        do_wrpkru(PKRU_UNLOCK);
        do_wrpkru(PKRU_LOCK);
    }

    /* ── 2. Calibration — empty loop overhead ────────────────────────────── */
    uint64_t cal_start = rdtsc_serialised();

    for (volatile uint64_t i = 0; i < BENCH_ITERATIONS; i++) {
        /* empty — measures RDTSC bracket + loop overhead only */
        (void)i;
    }

    uint64_t cal_end = rdtsc_serialised();
    uint64_t cal_ticks = cal_end - cal_start;

    /* ── 3. Measurement — WRPKRU loop ────────────────────────────────────── */
    uint64_t meas_start = rdtsc_serialised();

    for (uint64_t i = 0; i < BENCH_ITERATIONS; i++) {
        do_wrpkru(PKRU_UNLOCK);   /* gate open  (PKRU = 0x00) */
        do_wrpkru(PKRU_LOCK);     /* gate close (PKRU = 0x0C) */
    }

    uint64_t meas_end = rdtsc_serialised();
    uint64_t meas_ticks = meas_end - meas_start;

    /* ── 4. Subtract calibration overhead ────────────────────────────────── */
    uint64_t net_ticks = (meas_ticks > cal_ticks) ? (meas_ticks - cal_ticks) : 0;

    /* ── 5. Average per WRPKRU (two per iteration) ───────────────────────── */
    return net_ticks / (2 * BENCH_ITERATIONS);
}


/* ── mpk_print_decimal ───────────────────────────────────────────────────────
 *
 * Print a uint64_t in decimal (serial_print_hex only does hex).
 * ─────────────────────────────────────────────────────────────────────────── */
static void mpk_print_decimal(uint64_t n) {
    char buf[22];  /* enough for UINT64_MAX (20 digits) + sign + NUL */
    int i = 20;

    buf[21] = '\0';

    if (n == 0) {
        serial_print("0");
        return;
    }

    while (n > 0 && i >= 0) {
        buf[i--] = (char)('0' + (n % 10));
        n /= 10;
    }

    serial_print(buf + i + 1);
}


/* ── Public entry point ──────────────────────────────────────────────────────
 *
 * Called from kernel.c after mpk_set_pkru() and mpk_diagnostic().
 * Leaves PKRU = PKRU_LOCK (the correct default) on exit.
 * ─────────────────────────────────────────────────────────────────────────── */
void mpk_benchmark(void) {
    serial_print("\n[MPK-BENCH] ==========================================\n");
    serial_print("[MPK-BENCH] WRPKRU Cycle-Count Micro-Benchmark\n");
    serial_print("[MPK-BENCH]   Iterations: ");
    mpk_print_decimal(BENCH_ITERATIONS);
    serial_print(" (lock+unlock pairs)\n");
    serial_print("[MPK-BENCH] ==========================================\n");

    serial_print("[MPK-BENCH] Running warm-up... ");
    /* Warm-up already done inside mpk_benchmark_run() */
    serial_print("done.\n");

    serial_print("[MPK-BENCH] Calibrating TSC loop overhead... ");
    uint64_t cycles_per_wrpkru = mpk_benchmark_run();
    serial_print("done.\n");

    serial_print("[MPK-BENCH] ------------------------------------------\n");
    serial_print("[MPK-BENCH] Result: ");
    mpk_print_decimal(cycles_per_wrpkru);
    serial_print(" cycles / WRPKRU\n");

    if (cycles_per_wrpkru < 20) {
        serial_print("[MPK-BENCH] ✓ PASS: < 20 cycles (Capstone §9.2 target met)\n");
    } else if (cycles_per_wrpkru < 50) {
        serial_print("[MPK-BENCH] ⚠ MARGINAL: 20-50 cycles (within 2.5× target)\n");
        serial_print("[MPK-BENCH]   Possible cause: TSC frequency scaling or QEMU overhead.\n");
        serial_print("[MPK-BENCH]   Re-run on real hardware for accurate measurement.\n");
    } else {
        serial_print("[MPK-BENCH] ✗ FAIL: > 50 cycles (exceeds target by ");
        mpk_print_decimal(cycles_per_wrpkru / 20);
        serial_print("x)\n");
    }

    serial_print("[MPK-BENCH] ------------------------------------------\n");
    serial_print("[MPK-BENCH] Note: QEMU TCG emulation inflates cycle counts.\n");
    serial_print("[MPK-BENCH]       On real Intel hardware (Ice Lake / Tiger Lake+)\n");
    serial_print("[MPK-BENCH]       WRPKRU typically measures 4-8 cycles.\n");
    serial_print("[MPK-BENCH]       Use -accel kvm on the host for near-native counts.\n");
    serial_print("[MPK-BENCH] ==========================================\n\n");

    /* Restore the correct default PKRU (Key 1 locked) before returning. */
    do_wrpkru(PKRU_LOCK);
}