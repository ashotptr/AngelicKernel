#include <stdint.h>

extern void serial_print(const char *s);
extern void serial_print_hex(uint64_t n);

#define BENCH_ITERATIONS 1000000ULL
#define WARM_UP_ITERS 100000ULL
#define PKRU_UNLOCK 0x00000000u
#define PKRU_LOCK 0x0000000Cu

static inline uint64_t rdtsc_serialised(void) {
    uint32_t lo, hi;

    __asm__ volatile (
        "cpuid\n\t"
        "rdtsc\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "rbx", "rcx"
    );

    return ((uint64_t)hi << 32) | lo;
}

__attribute__((noinline))
static void do_wrpkru(uint32_t val) {
    __asm__ volatile (
        "xor %%ecx, %%ecx\n\t"
        "xor %%edx, %%edx\n\t"
        "wrpkru\n\t"
        :
        : "a"(val)
        : "ecx", "edx"
    );
}

uint64_t mpk_benchmark_run(void) {
    for (uint64_t i = 0; i < WARM_UP_ITERS; i++) {
        do_wrpkru(PKRU_UNLOCK);
        do_wrpkru(PKRU_LOCK);
    }
    
    uint64_t cal_start = rdtsc_serialised();

    for (volatile uint64_t i = 0; i < BENCH_ITERATIONS; i++) {
        (void)i;
    }

    uint64_t cal_end = rdtsc_serialised();
    uint64_t cal_ticks = cal_end - cal_start;
    uint64_t meas_start = rdtsc_serialised();

    for (uint64_t i = 0; i < BENCH_ITERATIONS; i++) {
        do_wrpkru(PKRU_UNLOCK);
        do_wrpkru(PKRU_LOCK);
    }

    uint64_t meas_end = rdtsc_serialised();
    uint64_t meas_ticks = meas_end - meas_start;
    
    uint64_t net_ticks = (meas_ticks > cal_ticks) ? (meas_ticks - cal_ticks) : 0;
    
    return net_ticks / (2 * BENCH_ITERATIONS);
}

static void mpk_print_decimal(uint64_t n) {
    char buf[22];
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

void mpk_benchmark(void) {
    serial_print("\n[mpk-bench]\n");
    serial_print("[mpk-bench] wrpkru cycle-count micro-benchmark\n");
    serial_print("[mpk-bench] iterations: ");

    mpk_print_decimal(BENCH_ITERATIONS);

    serial_print("(lock+unlock pairs)\n");
    serial_print("[mpk-bench]\n");

    serial_print("[mpk-bench] running warm-up");
    serial_print("done.\n");

    serial_print("[mpk-bench] calibrating tsc loop overhead");

    uint64_t cycles_per_wrpkru = mpk_benchmark_run();
    
    serial_print("done.\n");

    serial_print("[mpk-bench]\n");
    serial_print("[mpk-bench] result: ");

    mpk_print_decimal(cycles_per_wrpkru);
    
    serial_print("cycles / wrpkru\n");

    do_wrpkru(PKRU_LOCK);
}
