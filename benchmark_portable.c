#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "vistrutah_portable.h"

// Accurate timing function
double get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}

// Get CPU frequency estimate
double get_cpu_freq() {
    // This is a rough estimate - actual frequency may vary
    #ifdef VISTRUTAH_ARM
        return 3.2e9;  // Typical Apple Silicon frequency
    #else
        return 3.5e9;  // Typical Intel frequency
    #endif
}

// Performance benchmarking
void benchmark_vistrutah_256() {
    const int NUM_BLOCKS = 1000000;
    const int BLOCK_SIZE = 32;
    
    uint8_t *data = aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);
    uint8_t *output = aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);
    uint8_t key[32];
    
    // Initialize with random data
    srand(time(NULL));
    for (int i = 0; i < NUM_BLOCKS * BLOCK_SIZE; i++) {
        data[i] = rand() & 0xff;
    }
    for (int i = 0; i < 32; i++) {
        key[i] = rand() & 0xff;
    }
    
    printf("\nVistrutah-256 Performance Benchmark\n");
    printf("===================================\n");
    printf("Processing %d blocks (%d MB)\n", NUM_BLOCKS, (NUM_BLOCKS * BLOCK_SIZE) / (1024*1024));
    
    // Warmup
    for (int i = 0; i < 1000; i++) {
        vistrutah_256_encrypt(data, output, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    }
    
    // Benchmark encryption
    double start = get_time();
    for (int i = 0; i < NUM_BLOCKS; i++) {
        vistrutah_256_encrypt(data + i*BLOCK_SIZE, output + i*BLOCK_SIZE, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    }
    double enc_time = get_time() - start;
    
    double throughput = (NUM_BLOCKS * BLOCK_SIZE / (1024.0*1024.0)) / enc_time;
    double cycles_per_byte = (get_cpu_freq() * enc_time) / (NUM_BLOCKS * BLOCK_SIZE);
    printf("Encryption: %.3f seconds (%.1f MB/s, %.1f cycles/byte)\n", 
           enc_time, throughput, cycles_per_byte);
    
    // Benchmark decryption
    start = get_time();
    for (int i = 0; i < NUM_BLOCKS; i++) {
        vistrutah_256_decrypt(output + i*BLOCK_SIZE, data + i*BLOCK_SIZE, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    }
    double dec_time = get_time() - start;
    
    throughput = (NUM_BLOCKS * BLOCK_SIZE / (1024.0*1024.0)) / dec_time;
    cycles_per_byte = (get_cpu_freq() * dec_time) / (NUM_BLOCKS * BLOCK_SIZE);
    printf("Decryption: %.3f seconds (%.1f MB/s, %.1f cycles/byte)\n", 
           dec_time, throughput, cycles_per_byte);
    
    // Test short version
    printf("\nShort version (10 rounds):\n");
    start = get_time();
    for (int i = 0; i < NUM_BLOCKS; i++) {
        vistrutah_256_encrypt(data + i*BLOCK_SIZE, output + i*BLOCK_SIZE, key, 32, VISTRUTAH_256_ROUNDS_SHORT);
    }
    enc_time = get_time() - start;
    
    throughput = (NUM_BLOCKS * BLOCK_SIZE / (1024.0*1024.0)) / enc_time;
    cycles_per_byte = (get_cpu_freq() * enc_time) / (NUM_BLOCKS * BLOCK_SIZE);
    printf("Encryption: %.3f seconds (%.1f MB/s, %.1f cycles/byte)\n", 
           enc_time, throughput, cycles_per_byte);
    
    free(data);
    free(output);
}

void benchmark_vistrutah_512() {
    const int NUM_BLOCKS = 500000;
    const int BLOCK_SIZE = 64;
    
    uint8_t *data = aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);
    uint8_t *output = aligned_alloc(64, NUM_BLOCKS * BLOCK_SIZE);
    uint8_t key256[32];
    uint8_t key512[64];
    
    // Initialize with random data
    for (int i = 0; i < NUM_BLOCKS * BLOCK_SIZE; i++) {
        data[i] = rand() & 0xff;
    }
    for (int i = 0; i < 32; i++) {
        key256[i] = rand() & 0xff;
    }
    for (int i = 0; i < 64; i++) {
        key512[i] = rand() & 0xff;
    }
    
    printf("\nVistrutah-512 Performance Benchmark\n");
    printf("===================================\n");
    printf("Processing %d blocks (%d MB)\n", NUM_BLOCKS, (NUM_BLOCKS * BLOCK_SIZE) / (1024*1024));
    
    // Benchmark with 256-bit key
    printf("\n256-bit key (14 rounds):\n");
    double start = get_time();
    for (int i = 0; i < NUM_BLOCKS; i++) {
        vistrutah_512_encrypt(data + i*BLOCK_SIZE, output + i*BLOCK_SIZE, key256, 32, VISTRUTAH_512_ROUNDS_LONG_256KEY);
    }
    double enc_time = get_time() - start;
    
    double throughput = (NUM_BLOCKS * BLOCK_SIZE / (1024.0*1024.0)) / enc_time;
    double cycles_per_byte = (get_cpu_freq() * enc_time) / (NUM_BLOCKS * BLOCK_SIZE);
    printf("Encryption: %.3f seconds (%.1f MB/s, %.1f cycles/byte)\n", 
           enc_time, throughput, cycles_per_byte);
    
    // Benchmark with 512-bit key
    printf("\n512-bit key (18 rounds):\n");
    start = get_time();
    for (int i = 0; i < NUM_BLOCKS; i++) {
        vistrutah_512_encrypt(data + i*BLOCK_SIZE, output + i*BLOCK_SIZE, key512, 64, VISTRUTAH_512_ROUNDS_LONG_512KEY);
    }
    enc_time = get_time() - start;
    
    throughput = (NUM_BLOCKS * BLOCK_SIZE / (1024.0*1024.0)) / enc_time;
    cycles_per_byte = (get_cpu_freq() * enc_time) / (NUM_BLOCKS * BLOCK_SIZE);
    printf("Encryption: %.3f seconds (%.1f MB/s, %.1f cycles/byte)\n", 
           enc_time, throughput, cycles_per_byte);
    
    free(data);
    free(output);
}

void compare_implementations() {
    printf("\nExpected Performance Characteristics\n");
    printf("===================================\n");
    
    #ifdef VISTRUTAH_ARM
    printf("ARM NEON + Crypto:\n");
    printf("- Vistrutah-256: ~2000-2500 MB/s\n");
    printf("- Vistrutah-512: ~1000-1500 MB/s\n");
    #else
    printf("Intel x86-64:\n");
        #ifdef VISTRUTAH_VAES
        printf("- AVX512 + VAES detected\n");
        printf("- Vistrutah-256: ~3000-4000 MB/s expected\n");
        printf("- Vistrutah-512: ~2000-2500 MB/s expected\n");
        #elif defined(VISTRUTAH_AVX512)
        printf("- AVX512 + AES-NI detected\n");
        printf("- Vistrutah-256: ~2500-3000 MB/s expected\n");
        printf("- Vistrutah-512: ~1500-2000 MB/s expected\n");
        #else
        printf("- SSE + AES-NI detected\n");
        printf("- Vistrutah-256: ~2000-2500 MB/s expected\n");
        printf("- Vistrutah-512: ~1200-1500 MB/s expected\n");
        #endif
    #endif
    
    printf("\nComparison with standard algorithms:\n");
    printf("- AES-128:        ~3000 MB/s (0.8 cycles/byte)\n");
    printf("- AES-256:        ~2500 MB/s (1.0 cycles/byte)\n");
    printf("- ChaCha20:       ~2000 MB/s (1.5 cycles/byte)\n");
    printf("- Rijndael-256:   ~800 MB/s  (3.8 cycles/byte)\n");
}

int main() {
    printf("Vistrutah Block Cipher Performance Benchmark\n");
    printf("===========================================\n");
    printf("Implementation: %s\n", vistrutah_get_impl_name());
    printf("Hardware AES: %s\n", vistrutah_has_aes_accel() ? "Yes" : "No");
    
    benchmark_vistrutah_256();
    benchmark_vistrutah_512();
    compare_implementations();
    
    return 0;
}