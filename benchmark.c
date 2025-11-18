#define _POSIX_C_SOURCE 199309L
#include "vistrutah.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(VISTRUTAH_INTEL)
#include <immintrin.h>
#elif defined(VISTRUTAH_ARM)
#include <arm_neon.h>
#endif

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

static volatile uint64_t g_benchmark_checksum = 0;

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

        g_benchmark_checksum += output[0];

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

        g_benchmark_checksum += output[0];

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

        g_benchmark_checksum += output[0];

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

        g_benchmark_checksum += output[0];

        samples[s] = (double) (end - start) / NUM_ITERATIONS;
    }

    stats_t stats = get_stats(samples, NUM_SAMPLES);

    printf("  %-40s %6.1f ns/block  (min: %5.1f, max: %5.1f)\n", label, stats.median, stats.min,
           stats.max);
}

#if defined(VISTRUTAH_INTEL)
static inline void
aes128_key_expansion(const uint8_t *key, __m128i *rk)
{
    rk[0] = _mm_loadu_si128((const __m128i*) key);

    __m128i temp1 = rk[0];
    __m128i temp2;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[1] = _mm_xor_si128(temp1, temp2);

    temp2 = _mm_aeskeygenassist_si128(rk[1], 0x02);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(rk[1], _mm_slli_si128(rk[1], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[2] = _mm_xor_si128(temp1, temp2);

    temp2 = _mm_aeskeygenassist_si128(rk[2], 0x04);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(rk[2], _mm_slli_si128(rk[2], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[3] = _mm_xor_si128(temp1, temp2);

    temp2 = _mm_aeskeygenassist_si128(rk[3], 0x08);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(rk[3], _mm_slli_si128(rk[3], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[4] = _mm_xor_si128(temp1, temp2);

    temp2 = _mm_aeskeygenassist_si128(rk[4], 0x10);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(rk[4], _mm_slli_si128(rk[4], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[5] = _mm_xor_si128(temp1, temp2);

    temp2 = _mm_aeskeygenassist_si128(rk[5], 0x20);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(rk[5], _mm_slli_si128(rk[5], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[6] = _mm_xor_si128(temp1, temp2);

    temp2 = _mm_aeskeygenassist_si128(rk[6], 0x40);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(rk[6], _mm_slli_si128(rk[6], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[7] = _mm_xor_si128(temp1, temp2);

    temp2 = _mm_aeskeygenassist_si128(rk[7], 0x80);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(rk[7], _mm_slli_si128(rk[7], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[8] = _mm_xor_si128(temp1, temp2);

    temp2 = _mm_aeskeygenassist_si128(rk[8], 0x1b);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(rk[8], _mm_slli_si128(rk[8], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[9] = _mm_xor_si128(temp1, temp2);

    temp2 = _mm_aeskeygenassist_si128(rk[9], 0x36);
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp1 = _mm_xor_si128(rk[9], _mm_slli_si128(rk[9], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[10] = _mm_xor_si128(temp1, temp2);
}

static inline void
aes128_encrypt_with_schedule(const uint8_t *plaintext, uint8_t *ciphertext, const __m128i *rk)
{
    __m128i state = _mm_loadu_si128((const __m128i*) plaintext);

    state = _mm_xor_si128(state, rk[0]);
    state = _mm_aesenc_si128(state, rk[1]);
    state = _mm_aesenc_si128(state, rk[2]);
    state = _mm_aesenc_si128(state, rk[3]);
    state = _mm_aesenc_si128(state, rk[4]);
    state = _mm_aesenc_si128(state, rk[5]);
    state = _mm_aesenc_si128(state, rk[6]);
    state = _mm_aesenc_si128(state, rk[7]);
    state = _mm_aesenc_si128(state, rk[8]);
    state = _mm_aesenc_si128(state, rk[9]);
    state = _mm_aesenclast_si128(state, rk[10]);

    _mm_storeu_si128((__m128i*) ciphertext, state);
}

static inline void
aes256_key_expansion(const uint8_t *key, __m128i *rk)
{
    rk[0] = _mm_loadu_si128((const __m128i*) key);
    rk[1] = _mm_loadu_si128((const __m128i*) (key + 16));

    __m128i temp1 = rk[0];
    __m128i temp2 = rk[1];
    __m128i temp3;

    temp3 = _mm_aeskeygenassist_si128(temp2, 0x01);
    temp3 = _mm_shuffle_epi32(temp3, 0xff);
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[2] = _mm_xor_si128(temp1, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[2], 0x00);
    temp3 = _mm_shuffle_epi32(temp3, 0xaa);
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    rk[3] = _mm_xor_si128(temp2, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[3], 0x02);
    temp3 = _mm_shuffle_epi32(temp3, 0xff);
    temp1 = _mm_xor_si128(rk[2], _mm_slli_si128(rk[2], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[4] = _mm_xor_si128(temp1, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[4], 0x00);
    temp3 = _mm_shuffle_epi32(temp3, 0xaa);
    temp2 = _mm_xor_si128(rk[3], _mm_slli_si128(rk[3], 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    rk[5] = _mm_xor_si128(temp2, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[5], 0x04);
    temp3 = _mm_shuffle_epi32(temp3, 0xff);
    temp1 = _mm_xor_si128(rk[4], _mm_slli_si128(rk[4], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[6] = _mm_xor_si128(temp1, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[6], 0x00);
    temp3 = _mm_shuffle_epi32(temp3, 0xaa);
    temp2 = _mm_xor_si128(rk[5], _mm_slli_si128(rk[5], 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    rk[7] = _mm_xor_si128(temp2, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[7], 0x08);
    temp3 = _mm_shuffle_epi32(temp3, 0xff);
    temp1 = _mm_xor_si128(rk[6], _mm_slli_si128(rk[6], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[8] = _mm_xor_si128(temp1, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[8], 0x00);
    temp3 = _mm_shuffle_epi32(temp3, 0xaa);
    temp2 = _mm_xor_si128(rk[7], _mm_slli_si128(rk[7], 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    rk[9] = _mm_xor_si128(temp2, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[9], 0x10);
    temp3 = _mm_shuffle_epi32(temp3, 0xff);
    temp1 = _mm_xor_si128(rk[8], _mm_slli_si128(rk[8], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[10] = _mm_xor_si128(temp1, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[10], 0x00);
    temp3 = _mm_shuffle_epi32(temp3, 0xaa);
    temp2 = _mm_xor_si128(rk[9], _mm_slli_si128(rk[9], 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    rk[11] = _mm_xor_si128(temp2, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[11], 0x20);
    temp3 = _mm_shuffle_epi32(temp3, 0xff);
    temp1 = _mm_xor_si128(rk[10], _mm_slli_si128(rk[10], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[12] = _mm_xor_si128(temp1, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[12], 0x00);
    temp3 = _mm_shuffle_epi32(temp3, 0xaa);
    temp2 = _mm_xor_si128(rk[11], _mm_slli_si128(rk[11], 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
    rk[13] = _mm_xor_si128(temp2, temp3);

    temp3 = _mm_aeskeygenassist_si128(rk[13], 0x40);
    temp3 = _mm_shuffle_epi32(temp3, 0xff);
    temp1 = _mm_xor_si128(rk[12], _mm_slli_si128(rk[12], 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    rk[14] = _mm_xor_si128(temp1, temp3);
}

static inline void
aes256_encrypt_with_schedule(const uint8_t *plaintext, uint8_t *ciphertext, const __m128i *rk)
{
    __m128i state = _mm_loadu_si128((const __m128i*) plaintext);

    state = _mm_xor_si128(state, rk[0]);
    state = _mm_aesenc_si128(state, rk[1]);
    state = _mm_aesenc_si128(state, rk[2]);
    state = _mm_aesenc_si128(state, rk[3]);
    state = _mm_aesenc_si128(state, rk[4]);
    state = _mm_aesenc_si128(state, rk[5]);
    state = _mm_aesenc_si128(state, rk[6]);
    state = _mm_aesenc_si128(state, rk[7]);
    state = _mm_aesenc_si128(state, rk[8]);
    state = _mm_aesenc_si128(state, rk[9]);
    state = _mm_aesenc_si128(state, rk[10]);
    state = _mm_aesenc_si128(state, rk[11]);
    state = _mm_aesenc_si128(state, rk[12]);
    state = _mm_aesenc_si128(state, rk[13]);
    state = _mm_aesenclast_si128(state, rk[14]);

    _mm_storeu_si128((__m128i*) ciphertext, state);
}

static void
benchmark_aes_throughput(const char *label, const uint8_t *key, int key_size)
{
    const int NUM_BLOCKS  = 2000000;
    const int BLOCK_SIZE  = 16;
    const int NUM_SAMPLES = 10;

    uint8_t *data   = safe_aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);
    uint8_t *output = safe_aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);

    init_random_data(data, NUM_BLOCKS * BLOCK_SIZE);

    __m128i rk[15];
    if (key_size == 16) {
        aes128_key_expansion(key, rk);
    } else {
        aes256_key_expansion(key, rk);
    }

    for (int i = 0; i < 1000; i++) {
        if (key_size == 16) {
            aes128_encrypt_with_schedule(data, output, rk);
        } else {
            aes256_encrypt_with_schedule(data, output, rk);
        }
    }

    double samples[NUM_SAMPLES];

    for (int s = 0; s < NUM_SAMPLES; s++) {
        uint64_t start = get_nanos();
        for (int i = 0; i < NUM_BLOCKS; i++) {
            if (key_size == 16) {
                aes128_encrypt_with_schedule(data + i * BLOCK_SIZE, output + i * BLOCK_SIZE, rk);
            } else {
                aes256_encrypt_with_schedule(data + i * BLOCK_SIZE, output + i * BLOCK_SIZE, rk);
            }
        }
        uint64_t end     = get_nanos();
        double   elapsed = (end - start) / 1e9;

        g_benchmark_checksum += output[0];

        samples[s] = (NUM_BLOCKS * BLOCK_SIZE / (1024.0 * 1024.0)) / elapsed;
    }

    stats_t stats = get_stats(samples, NUM_SAMPLES);

    printf("  %-40s %7.1f MB/s  (min: %6.1f, max: %6.1f)\n", label, stats.median, stats.min,
           stats.max);

    free(data);
    free(output);
}
#elif defined(VISTRUTAH_ARM)
static inline void
aes128_key_expansion(const uint8_t *key, uint8x16_t *rk)
{
    rk[0] = vld1q_u8(key);

    static const uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    uint8x16_t temp = rk[0];

    for (int i = 0; i < 10; i++) {
        uint32_t t = vgetq_lane_u32(vreinterpretq_u32_u8(temp), 3);
        t = (t >> 8) | (t << 24);

        uint8_t sbox_result[4];
        sbox_result[0] = vgetq_lane_u8(vaeseq_u8(vmovq_n_u8(0), vsetq_lane_u8((t >> 0) & 0xff, vmovq_n_u8(0), 0)), 0);
        sbox_result[1] = vgetq_lane_u8(vaeseq_u8(vmovq_n_u8(0), vsetq_lane_u8((t >> 8) & 0xff, vmovq_n_u8(0), 0)), 0);
        sbox_result[2] = vgetq_lane_u8(vaeseq_u8(vmovq_n_u8(0), vsetq_lane_u8((t >> 16) & 0xff, vmovq_n_u8(0), 0)), 0);
        sbox_result[3] = vgetq_lane_u8(vaeseq_u8(vmovq_n_u8(0), vsetq_lane_u8((t >> 24) & 0xff, vmovq_n_u8(0), 0)), 0);

        t = (sbox_result[0] << 0) | (sbox_result[1] << 8) | (sbox_result[2] << 16) | (sbox_result[3] << 24);
        t ^= rcon[i];

        uint32x4_t t_vec = vdupq_n_u32(t);
        uint32x4_t temp_u32 = vreinterpretq_u32_u8(temp);

        uint32x4_t shifted1 = vextq_u32(vdupq_n_u32(0), temp_u32, 3);
        temp_u32 = veorq_u32(temp_u32, shifted1);
        uint32x4_t shifted2 = vextq_u32(vdupq_n_u32(0), temp_u32, 3);
        temp_u32 = veorq_u32(temp_u32, shifted2);
        uint32x4_t shifted3 = vextq_u32(vdupq_n_u32(0), temp_u32, 3);
        temp_u32 = veorq_u32(temp_u32, shifted3);

        temp_u32 = veorq_u32(temp_u32, vshlq_n_u32(t_vec, 0));
        temp = vreinterpretq_u8_u32(temp_u32);

        rk[i+1] = temp;
    }
}

static inline void
aes128_encrypt_with_schedule(const uint8_t *plaintext, uint8_t *ciphertext, const uint8x16_t *rk)
{
    uint8x16_t state = vld1q_u8(plaintext);

    state = veorq_u8(state, rk[0]);
    state = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), state));
    state = veorq_u8(state, rk[1]);
    state = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), state));
    state = veorq_u8(state, rk[2]);
    state = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), state));
    state = veorq_u8(state, rk[3]);
    state = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), state));
    state = veorq_u8(state, rk[4]);
    state = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), state));
    state = veorq_u8(state, rk[5]);
    state = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), state));
    state = veorq_u8(state, rk[6]);
    state = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), state));
    state = veorq_u8(state, rk[7]);
    state = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), state));
    state = veorq_u8(state, rk[8]);
    state = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), state));
    state = veorq_u8(state, rk[9]);
    state = vaeseq_u8(vmovq_n_u8(0), state);
    state = veorq_u8(state, rk[10]);

    vst1q_u8(ciphertext, state);
}

static inline void
aes256_key_expansion(const uint8_t *key, uint8x16_t *rk)
{
    rk[0] = vld1q_u8(key);
    rk[1] = vld1q_u8(key + 16);

    static const uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};

    for (int i = 0; i < 7; i++) {
        uint8x16_t temp1 = rk[i*2];
        uint8x16_t temp2 = rk[i*2 + 1];

        uint32_t t = vgetq_lane_u32(vreinterpretq_u32_u8(temp2), 3);
        t = (t >> 8) | (t << 24);

        uint8_t sbox_result[4];
        for (int j = 0; j < 4; j++) {
            sbox_result[j] = vgetq_lane_u8(vaeseq_u8(vmovq_n_u8(0), vsetq_lane_u8((t >> (j*8)) & 0xff, vmovq_n_u8(0), 0)), 0);
        }

        t = (sbox_result[0] << 0) | (sbox_result[1] << 8) | (sbox_result[2] << 16) | (sbox_result[3] << 24);
        t ^= rcon[i];

        uint32x4_t t_vec = vdupq_n_u32(t);
        uint32x4_t temp1_u32 = vreinterpretq_u32_u8(temp1);

        uint32x4_t shifted = vextq_u32(vdupq_n_u32(0), temp1_u32, 3);
        temp1_u32 = veorq_u32(temp1_u32, shifted);
        shifted = vextq_u32(vdupq_n_u32(0), temp1_u32, 3);
        temp1_u32 = veorq_u32(temp1_u32, shifted);
        shifted = vextq_u32(vdupq_n_u32(0), temp1_u32, 3);
        temp1_u32 = veorq_u32(temp1_u32, shifted);
        temp1_u32 = veorq_u32(temp1_u32, t_vec);

        rk[i*2 + 2] = vreinterpretq_u8_u32(temp1_u32);

        if (i < 6) {
            t = vgetq_lane_u32(vreinterpretq_u32_u8(rk[i*2 + 2]), 3);

            for (int j = 0; j < 4; j++) {
                sbox_result[j] = vgetq_lane_u8(vaeseq_u8(vmovq_n_u8(0), vsetq_lane_u8((t >> (j*8)) & 0xff, vmovq_n_u8(0), 0)), 0);
            }

            t = (sbox_result[0] << 0) | (sbox_result[1] << 8) | (sbox_result[2] << 16) | (sbox_result[3] << 24);

            t_vec = vdupq_n_u32(t);
            uint32x4_t temp2_u32 = vreinterpretq_u32_u8(temp2);

            shifted = vextq_u32(vdupq_n_u32(0), temp2_u32, 3);
            temp2_u32 = veorq_u32(temp2_u32, shifted);
            shifted = vextq_u32(vdupq_n_u32(0), temp2_u32, 3);
            temp2_u32 = veorq_u32(temp2_u32, shifted);
            shifted = vextq_u32(vdupq_n_u32(0), temp2_u32, 3);
            temp2_u32 = veorq_u32(temp2_u32, shifted);
            temp2_u32 = veorq_u32(temp2_u32, t_vec);

            rk[i*2 + 3] = vreinterpretq_u8_u32(temp2_u32);
        }
    }
}

static inline void
aes256_encrypt_with_schedule(const uint8_t *plaintext, uint8_t *ciphertext, const uint8x16_t *rk)
{
    uint8x16_t state = vld1q_u8(plaintext);

    state = veorq_u8(state, rk[0]);
    for (int i = 1; i < 14; i++) {
        state = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), state));
        state = veorq_u8(state, rk[i]);
    }
    state = vaeseq_u8(vmovq_n_u8(0), state);
    state = veorq_u8(state, rk[14]);

    vst1q_u8(ciphertext, state);
}

static void
benchmark_aes_throughput(const char *label, const uint8_t *key, int key_size)
{
    const int NUM_BLOCKS  = 2000000;
    const int BLOCK_SIZE  = 16;
    const int NUM_SAMPLES = 10;

    uint8_t *data   = safe_aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);
    uint8_t *output = safe_aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);

    init_random_data(data, NUM_BLOCKS * BLOCK_SIZE);

    uint8x16_t rk[15];
    if (key_size == 16) {
        aes128_key_expansion(key, rk);
    } else {
        aes256_key_expansion(key, rk);
    }

    for (int i = 0; i < 1000; i++) {
        if (key_size == 16) {
            aes128_encrypt_with_schedule(data, output, rk);
        } else {
            aes256_encrypt_with_schedule(data, output, rk);
        }
    }

    double samples[NUM_SAMPLES];

    for (int s = 0; s < NUM_SAMPLES; s++) {
        uint64_t start = get_nanos();
        for (int i = 0; i < NUM_BLOCKS; i++) {
            if (key_size == 16) {
                aes128_encrypt_with_schedule(data + i * BLOCK_SIZE, output + i * BLOCK_SIZE, rk);
            } else {
                aes256_encrypt_with_schedule(data + i * BLOCK_SIZE, output + i * BLOCK_SIZE, rk);
            }
        }
        uint64_t end     = get_nanos();
        double   elapsed = (end - start) / 1e9;

        g_benchmark_checksum += output[0];

        samples[s] = (NUM_BLOCKS * BLOCK_SIZE / (1024.0 * 1024.0)) / elapsed;
    }

    stats_t stats = get_stats(samples, NUM_SAMPLES);

    printf("  %-40s %7.1f MB/s  (min: %6.1f, max: %6.1f)\n", label, stats.median, stats.min,
           stats.max);

    free(data);
    free(output);
}
#else
static void
benchmark_aes_throughput(const char *label, const uint8_t *key, int key_size)
{
    (void)label;
    (void)key;
    (void)key_size;
    printf("  AES benchmarks not available (no hardware acceleration)\n");
}
#endif

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

            g_benchmark_checksum += output[0];

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
    // AES Reference Benchmarks
    // ========================================================================
    printf("\nAES Reference Performance (32 MB dataset)\n");
    printf("════════════════════════════════════════════════════════════════\n");

    benchmark_aes_throughput("AES-128 (10 rounds, encrypt)", key128, 16);
    benchmark_aes_throughput("AES-256 (14 rounds, encrypt)", key256, 32);

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
