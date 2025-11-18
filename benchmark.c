#define _POSIX_C_SOURCE 199309L
#include "vistrutah.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __MACH__
#    include <mach/mach_time.h>
static mach_timebase_info_data_t timebase_info;
static int                       timebase_initialized = 0;

static inline uint64_t
get_nanos()
{
    if (!timebase_initialized) {
        mach_timebase_info(&timebase_info);
        timebase_initialized = 1;
    }
    uint64_t abs_time = mach_absolute_time();
    return abs_time * timebase_info.numer / timebase_info.denom;
}
#else
static inline uint64_t
get_nanos()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#endif

// Comparison function for qsort
static int
compare_double(const void *a, const void *b)
{
    double fa = *(const double *) a;
    double fb = *(const double *) b;
    return (fa > fb) - (fa < fb);
}

// Run benchmark multiple times and get statistics
typedef struct {
    double median;
    double min;
    double max;
    double mean;
} stats_t;

static stats_t
get_stats(double *samples, int n)
{
    stats_t stats;
    double  sum = 0;

    // Sort for median
    qsort(samples, n, sizeof(double), compare_double);

    stats.min    = samples[0];
    stats.max    = samples[n - 1];
    stats.median = samples[n / 2];

    for (int i = 0; i < n; i++) {
        sum += samples[i];
    }
    stats.mean = sum / n;

    return stats;
}

// Initialize random data
static void
init_random_data(uint8_t *data, size_t size)
{
    if (data == NULL) {
        fprintf(stderr, "Error: NULL pointer passed to init_random_data\n");
        exit(1);
    }
    for (size_t i = 0; i < size; i++) {
        data[i] = (uint8_t) rand();
    }
}

// Safe aligned allocation (size must be multiple of alignment on some platforms)
static void *
safe_aligned_alloc(size_t alignment, size_t size)
{
    // Round up size to be a multiple of alignment
    size_t aligned_size = ((size + alignment - 1) / alignment) * alignment;
    void  *ptr          = aligned_alloc(alignment, aligned_size);
    if (ptr == NULL) {
        fprintf(stderr, "Error: aligned_alloc failed for size %zu\n", size);
        exit(1);
    }
    return ptr;
}

// Benchmark throughput (large data)
static void
benchmark_throughput_256(const char *label, const uint8_t *key, int key_size, int rounds,
                         int encrypt)
{
    const int NUM_BLOCKS  = 1000000;
    const int BLOCK_SIZE  = 32;
    const int NUM_SAMPLES = 10;

    uint8_t *data   = safe_aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);
    uint8_t *output = safe_aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);

    init_random_data(data, NUM_BLOCKS * BLOCK_SIZE);

    // Warmup
    for (int i = 0; i < 1000; i++) {
        if (encrypt) {
            vistrutah_256_encrypt(data, output, key, key_size, rounds);
        } else {
            vistrutah_256_decrypt(data, output, key, key_size, rounds);
        }
    }

    double samples[NUM_SAMPLES];

    for (int s = 0; s < NUM_SAMPLES; s++) {
        uint64_t start = get_nanos();
        for (int i = 0; i < NUM_BLOCKS; i++) {
            if (encrypt) {
                vistrutah_256_encrypt(data + i * BLOCK_SIZE, output + i * BLOCK_SIZE, key, key_size,
                                      rounds);
            } else {
                vistrutah_256_decrypt(data + i * BLOCK_SIZE, output + i * BLOCK_SIZE, key, key_size,
                                      rounds);
            }
        }
        uint64_t end     = get_nanos();
        double   elapsed = (end - start) / 1e9;

        // Calculate throughput in MB/s
        samples[s] = (NUM_BLOCKS * BLOCK_SIZE / (1024.0 * 1024.0)) / elapsed;
    }

    stats_t stats = get_stats(samples, NUM_SAMPLES);

    printf("  %-40s %7.1f MB/s  (min: %6.1f, max: %6.1f)\n", label, stats.median, stats.min,
           stats.max);

    free(data);
    free(output);
}

static void
benchmark_throughput_512(const char *label, const uint8_t *key, int key_size, int rounds,
                         int encrypt)
{
    const int NUM_BLOCKS  = 500000;
    const int BLOCK_SIZE  = 64;
    const int NUM_SAMPLES = 10;

    uint8_t *data   = safe_aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);
    uint8_t *output = safe_aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);

    init_random_data(data, NUM_BLOCKS * BLOCK_SIZE);

    // Warmup
    for (int i = 0; i < 1000; i++) {
        if (encrypt) {
            vistrutah_512_encrypt(data, output, key, key_size, rounds);
        } else {
            vistrutah_512_decrypt(data, output, key, key_size, rounds);
        }
    }

    double samples[NUM_SAMPLES];

    for (int s = 0; s < NUM_SAMPLES; s++) {
        uint64_t start = get_nanos();
        for (int i = 0; i < NUM_BLOCKS; i++) {
            if (encrypt) {
                vistrutah_512_encrypt(data + i * BLOCK_SIZE, output + i * BLOCK_SIZE, key, key_size,
                                      rounds);
            } else {
                vistrutah_512_decrypt(data + i * BLOCK_SIZE, output + i * BLOCK_SIZE, key, key_size,
                                      rounds);
            }
        }
        uint64_t end     = get_nanos();
        double   elapsed = (end - start) / 1e9;

        samples[s] = (NUM_BLOCKS * BLOCK_SIZE / (1024.0 * 1024.0)) / elapsed;
    }

    stats_t stats = get_stats(samples, NUM_SAMPLES);

    printf("  %-40s %7.1f MB/s  (min: %6.1f, max: %6.1f)\n", label, stats.median, stats.min,
           stats.max);

    free(data);
    free(output);
}

// Benchmark latency (single block)
static void
benchmark_latency_256(const char *label, const uint8_t *key, int key_size, int rounds, int encrypt)
{
    const int NUM_ITERATIONS = 1000000;
    const int NUM_SAMPLES    = 10;

    uint8_t block[32];
    uint8_t output[32];

    init_random_data(block, 32);

    // Warmup
    for (int i = 0; i < 10000; i++) {
        if (encrypt) {
            vistrutah_256_encrypt(block, output, key, key_size, rounds);
        } else {
            vistrutah_256_decrypt(block, output, key, key_size, rounds);
        }
    }

    double samples[NUM_SAMPLES];

    for (int s = 0; s < NUM_SAMPLES; s++) {
        uint64_t start = get_nanos();
        for (int i = 0; i < NUM_ITERATIONS; i++) {
            if (encrypt) {
                vistrutah_256_encrypt(block, output, key, key_size, rounds);
            } else {
                vistrutah_256_decrypt(block, output, key, key_size, rounds);
            }
        }
        uint64_t end = get_nanos();

        // Calculate ns per operation
        samples[s] = (double) (end - start) / NUM_ITERATIONS;
    }

    stats_t stats = get_stats(samples, NUM_SAMPLES);

    printf("  %-40s %6.1f ns/block  (min: %5.1f, max: %5.1f)\n", label, stats.median, stats.min,
           stats.max);
}

static void
benchmark_latency_512(const char *label, const uint8_t *key, int key_size, int rounds, int encrypt)
{
    const int NUM_ITERATIONS = 1000000;
    const int NUM_SAMPLES    = 10;

    uint8_t block[64];
    uint8_t output[64];

    init_random_data(block, 64);

    // Warmup
    for (int i = 0; i < 10000; i++) {
        if (encrypt) {
            vistrutah_512_encrypt(block, output, key, key_size, rounds);
        } else {
            vistrutah_512_decrypt(block, output, key, key_size, rounds);
        }
    }

    double samples[NUM_SAMPLES];

    for (int s = 0; s < NUM_SAMPLES; s++) {
        uint64_t start = get_nanos();
        for (int i = 0; i < NUM_ITERATIONS; i++) {
            if (encrypt) {
                vistrutah_512_encrypt(block, output, key, key_size, rounds);
            } else {
                vistrutah_512_decrypt(block, output, key, key_size, rounds);
            }
        }
        uint64_t end = get_nanos();

        samples[s] = (double) (end - start) / NUM_ITERATIONS;
    }

    stats_t stats = get_stats(samples, NUM_SAMPLES);

    printf("  %-40s %6.1f ns/block  (min: %5.1f, max: %5.1f)\n", label, stats.median, stats.min,
           stats.max);
}

// Benchmark small messages (various sizes)
static void
benchmark_small_messages()
{
    printf("\nSmall Message Throughput (Vistrutah-256, 14 rounds)\n");
    printf("==================================================\n");

    const int   message_sizes[] = { 32, 64, 128, 256, 512, 1024, 4096, 16384 };
    const char *size_names[]    = { "32B (1 block)",    "64B (2 blocks)",   "128B (4 blocks)",
                                    "256B (8 blocks)",  "512B (16 blocks)", "1KB (32 blocks)",
                                    "4KB (128 blocks)", "16KB (512 blocks)" };
    const int   num_sizes       = 8;

    uint8_t key[32];
    init_random_data(key, 32);

    for (int sz = 0; sz < num_sizes; sz++) {
        int msg_size   = message_sizes[sz];
        int num_blocks = msg_size / 32;

        // Adjust iterations to keep total time reasonable
        int iterations;
        if (msg_size <= 256) {
            iterations = 1000000;
        } else if (msg_size <= 1024) {
            iterations = 500000;
        } else if (msg_size <= 4096) {
            iterations = 100000;
        } else {
            iterations = 50000;
        }

        const int NUM_SAMPLES = 10;
        uint8_t  *input       = safe_aligned_alloc(64, msg_size);
        uint8_t  *output      = safe_aligned_alloc(64, msg_size);

        init_random_data(input, msg_size);

        // Warmup
        for (int i = 0; i < 1000; i++) {
            for (int b = 0; b < num_blocks; b++) {
                vistrutah_256_encrypt(input + b * 32, output + b * 32, key, 32,
                                      VISTRUTAH_256_ROUNDS_LONG);
            }
        }

        double samples[NUM_SAMPLES];

        for (int s = 0; s < NUM_SAMPLES; s++) {
            uint64_t start = get_nanos();
            for (int iter = 0; iter < iterations; iter++) {
                for (int b = 0; b < num_blocks; b++) {
                    vistrutah_256_encrypt(input + b * 32, output + b * 32, key, 32,
                                          VISTRUTAH_256_ROUNDS_LONG);
                }
            }
            uint64_t end     = get_nanos();
            double   elapsed = (end - start) / 1e9;

            // Throughput in MB/s
            samples[s] = ((double) msg_size * iterations / (1024.0 * 1024.0)) / elapsed;
        }

        stats_t stats = get_stats(samples, NUM_SAMPLES);

        printf("  %-25s %7.1f MB/s  (min: %6.1f, max: %6.1f)\n", size_names[sz], stats.median,
               stats.min, stats.max);

        free(input);
        free(output);
    }
}

int
main()
{
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Vistrutah Block Cipher - Performance Benchmark\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Implementation: %s\n", vistrutah_get_impl_name());
    printf("Hardware AES:   %s\n", vistrutah_has_aes_accel() ? "Yes" : "No");
    printf("Block Size:     256-bit (32 bytes) / 512-bit (64 bytes)\n");
    printf("\n");

    srand(12345); // Fixed seed for reproducibility

    uint8_t key128[16];
    uint8_t key256[32];
    uint8_t key512[64];

    init_random_data(key128, 16);
    init_random_data(key256, 32);
    init_random_data(key512, 64);

    // ========================================================================
    // Vistrutah-256 Throughput Benchmarks
    // ========================================================================
    printf("Vistrutah-256 Throughput (32 MB dataset)\n");
    printf("════════════════════════════════════════════════════════════════\n");

    // 128-bit key
    benchmark_throughput_256("128-bit key, 10 rounds (encrypt)", key128, 16,
                             VISTRUTAH_256_ROUNDS_SHORT, 1);
    benchmark_throughput_256("128-bit key, 10 rounds (decrypt)", key128, 16,
                             VISTRUTAH_256_ROUNDS_SHORT, 0);
    benchmark_throughput_256("128-bit key, 14 rounds (encrypt)", key128, 16,
                             VISTRUTAH_256_ROUNDS_LONG, 1);
    benchmark_throughput_256("128-bit key, 14 rounds (decrypt)", key128, 16,
                             VISTRUTAH_256_ROUNDS_LONG, 0);

    // 256-bit key
    benchmark_throughput_256("256-bit key, 10 rounds (encrypt)", key256, 32,
                             VISTRUTAH_256_ROUNDS_SHORT, 1);
    benchmark_throughput_256("256-bit key, 10 rounds (decrypt)", key256, 32,
                             VISTRUTAH_256_ROUNDS_SHORT, 0);
    benchmark_throughput_256("256-bit key, 14 rounds (encrypt)", key256, 32,
                             VISTRUTAH_256_ROUNDS_LONG, 1);
    benchmark_throughput_256("256-bit key, 14 rounds (decrypt)", key256, 32,
                             VISTRUTAH_256_ROUNDS_LONG, 0);

    // 512-bit key
    benchmark_throughput_256("512-bit key, 10 rounds (encrypt)", key512, 64,
                             VISTRUTAH_256_ROUNDS_SHORT, 1);
    benchmark_throughput_256("512-bit key, 10 rounds (decrypt)", key512, 64,
                             VISTRUTAH_256_ROUNDS_SHORT, 0);
    benchmark_throughput_256("512-bit key, 14 rounds (encrypt)", key512, 64,
                             VISTRUTAH_256_ROUNDS_LONG, 1);
    benchmark_throughput_256("512-bit key, 14 rounds (decrypt)", key512, 64,
                             VISTRUTAH_256_ROUNDS_LONG, 0);

    // ========================================================================
    // Vistrutah-512 Throughput Benchmarks
    // ========================================================================
    printf("\nVistrutah-512 Throughput (32 MB dataset)\n");
    printf("════════════════════════════════════════════════════════════════\n");

    // 256-bit key
    benchmark_throughput_512("256-bit key, 10 rounds (encrypt)", key256, 32,
                             VISTRUTAH_512_ROUNDS_SHORT_256KEY, 1);
    benchmark_throughput_512("256-bit key, 10 rounds (decrypt)", key256, 32,
                             VISTRUTAH_512_ROUNDS_SHORT_256KEY, 0);
    benchmark_throughput_512("256-bit key, 14 rounds (encrypt)", key256, 32,
                             VISTRUTAH_512_ROUNDS_LONG_256KEY, 1);
    benchmark_throughput_512("256-bit key, 14 rounds (decrypt)", key256, 32,
                             VISTRUTAH_512_ROUNDS_LONG_256KEY, 0);

    // 512-bit key
    benchmark_throughput_512("512-bit key, 12 rounds (encrypt)", key512, 64,
                             VISTRUTAH_512_ROUNDS_SHORT_512KEY, 1);
    benchmark_throughput_512("512-bit key, 12 rounds (decrypt)", key512, 64,
                             VISTRUTAH_512_ROUNDS_SHORT_512KEY, 0);
    benchmark_throughput_512("512-bit key, 18 rounds (encrypt)", key512, 64,
                             VISTRUTAH_512_ROUNDS_LONG_512KEY, 1);
    benchmark_throughput_512("512-bit key, 18 rounds (decrypt)", key512, 64,
                             VISTRUTAH_512_ROUNDS_LONG_512KEY, 0);

    // ========================================================================
    // Vistrutah-256 Latency Benchmarks
    // ========================================================================
    printf("\nVistrutah-256 Latency (single block)\n");
    printf("════════════════════════════════════════════════════════════════\n");

    benchmark_latency_256("128-bit key, 10 rounds (encrypt)", key128, 16,
                          VISTRUTAH_256_ROUNDS_SHORT, 1);
    benchmark_latency_256("128-bit key, 10 rounds (decrypt)", key128, 16,
                          VISTRUTAH_256_ROUNDS_SHORT, 0);
    benchmark_latency_256("128-bit key, 14 rounds (encrypt)", key128, 16, VISTRUTAH_256_ROUNDS_LONG,
                          1);
    benchmark_latency_256("128-bit key, 14 rounds (decrypt)", key128, 16, VISTRUTAH_256_ROUNDS_LONG,
                          0);

    benchmark_latency_256("256-bit key, 10 rounds (encrypt)", key256, 32,
                          VISTRUTAH_256_ROUNDS_SHORT, 1);
    benchmark_latency_256("256-bit key, 10 rounds (decrypt)", key256, 32,
                          VISTRUTAH_256_ROUNDS_SHORT, 0);
    benchmark_latency_256("256-bit key, 14 rounds (encrypt)", key256, 32, VISTRUTAH_256_ROUNDS_LONG,
                          1);
    benchmark_latency_256("256-bit key, 14 rounds (decrypt)", key256, 32, VISTRUTAH_256_ROUNDS_LONG,
                          0);

    benchmark_latency_256("512-bit key, 10 rounds (encrypt)", key512, 64,
                          VISTRUTAH_256_ROUNDS_SHORT, 1);
    benchmark_latency_256("512-bit key, 10 rounds (decrypt)", key512, 64,
                          VISTRUTAH_256_ROUNDS_SHORT, 0);
    benchmark_latency_256("512-bit key, 14 rounds (encrypt)", key512, 64, VISTRUTAH_256_ROUNDS_LONG,
                          1);
    benchmark_latency_256("512-bit key, 14 rounds (decrypt)", key512, 64, VISTRUTAH_256_ROUNDS_LONG,
                          0);

    // ========================================================================
    // Vistrutah-512 Latency Benchmarks
    // ========================================================================
    printf("\nVistrutah-512 Latency (single block)\n");
    printf("════════════════════════════════════════════════════════════════\n");

    benchmark_latency_512("256-bit key, 10 rounds (encrypt)", key256, 32,
                          VISTRUTAH_512_ROUNDS_SHORT_256KEY, 1);
    benchmark_latency_512("256-bit key, 10 rounds (decrypt)", key256, 32,
                          VISTRUTAH_512_ROUNDS_SHORT_256KEY, 0);
    benchmark_latency_512("256-bit key, 14 rounds (encrypt)", key256, 32,
                          VISTRUTAH_512_ROUNDS_LONG_256KEY, 1);
    benchmark_latency_512("256-bit key, 14 rounds (decrypt)", key256, 32,
                          VISTRUTAH_512_ROUNDS_LONG_256KEY, 0);

    benchmark_latency_512("512-bit key, 12 rounds (encrypt)", key512, 64,
                          VISTRUTAH_512_ROUNDS_SHORT_512KEY, 1);
    benchmark_latency_512("512-bit key, 12 rounds (decrypt)", key512, 64,
                          VISTRUTAH_512_ROUNDS_SHORT_512KEY, 0);
    benchmark_latency_512("512-bit key, 18 rounds (encrypt)", key512, 64,
                          VISTRUTAH_512_ROUNDS_LONG_512KEY, 1);
    benchmark_latency_512("512-bit key, 18 rounds (decrypt)", key512, 64,
                          VISTRUTAH_512_ROUNDS_LONG_512KEY, 0);

    // ========================================================================
    // Small Message Benchmarks
    // ========================================================================
    benchmark_small_messages();

    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Benchmark Complete\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\nNote: All measurements show median over 10 runs.\n");
    printf("      Min/max values indicate measurement stability.\n");

    return 0;
}
