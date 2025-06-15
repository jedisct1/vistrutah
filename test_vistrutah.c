#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "vistrutah.h"

// Helper function to print hex bytes
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Test vectors (these would normally come from the specification)
void test_vistrutah_256() {
    printf("=== Testing Vistrutah-256 ===\n");
    
    // Test key and plaintext
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t plaintext[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    uint8_t ciphertext[32];
    uint8_t decrypted[32];
    
    // Test long version (14 rounds)
    printf("\nLong version (14 rounds):\n");
    print_hex("Key      ", key, 32);
    print_hex("Plaintext", plaintext, 32);
    
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    print_hex("Ciphertext", ciphertext, 32);
    
    vistrutah_256_decrypt(ciphertext, decrypted, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    print_hex("Decrypted", decrypted, 32);
    
    if (memcmp(plaintext, decrypted, 32) == 0) {
        printf("✓ Encryption/Decryption test PASSED\n");
    } else {
        printf("✗ Encryption/Decryption test FAILED\n");
    }
    
    // Test short version (10 rounds)
    printf("\nShort version (10 rounds):\n");
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_256_ROUNDS_SHORT);
    print_hex("Ciphertext", ciphertext, 32);
    
    vistrutah_256_decrypt(ciphertext, decrypted, key, 32, VISTRUTAH_256_ROUNDS_SHORT);
    if (memcmp(plaintext, decrypted, 32) == 0) {
        printf("✓ Short version test PASSED\n");
    } else {
        printf("✗ Short version test FAILED\n");
    }
}

void test_vistrutah_512() {
    printf("\n=== Testing Vistrutah-512 ===\n");
    
    // Test with 256-bit key
    uint8_t key256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    // Test with 512-bit key
    uint8_t key512[64];
    for (int i = 0; i < 64; i++) {
        key512[i] = i;
    }
    
    uint8_t plaintext[64];
    for (int i = 0; i < 64; i++) {
        plaintext[i] = (i * 17) & 0xff;
    }
    
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    // Test with 256-bit key, long version (14 rounds)
    printf("\n256-bit key, long version (14 rounds):\n");
    print_hex("Key      ", key256, 32);
    print_hex("Plaintext", plaintext, 64);
    
    vistrutah_512_encrypt(plaintext, ciphertext, key256, 32, VISTRUTAH_512_ROUNDS_LONG_256KEY);
    print_hex("Ciphertext", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key256, 32, VISTRUTAH_512_ROUNDS_LONG_256KEY);
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ 256-bit key test PASSED\n");
    } else {
        printf("✗ 256-bit key test FAILED\n");
    }
    
    // Test with 512-bit key, long version (18 rounds)
    printf("\n512-bit key, long version (18 rounds):\n");
    print_hex("Key      ", key512, 64);
    
    vistrutah_512_encrypt(plaintext, ciphertext, key512, 64, VISTRUTAH_512_ROUNDS_LONG_512KEY);
    print_hex("Ciphertext", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key512, 64, VISTRUTAH_512_ROUNDS_LONG_512KEY);
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ 512-bit key test PASSED\n");
    } else {
        printf("✗ 512-bit key test FAILED\n");
    }
}

void benchmark_vistrutah() {
    printf("\n=== Performance Benchmark ===\n");
    
    const int iterations = 1000000;
    uint8_t key[32], plaintext[32], ciphertext[32];
    clock_t start, end;
    double cpu_time_used;
    
    // Initialize with random data
    for (int i = 0; i < 32; i++) {
        key[i] = rand() & 0xff;
        plaintext[i] = rand() & 0xff;
    }
    
    // Benchmark Vistrutah-256 encryption
    start = clock();
    for (int i = 0; i < iterations; i++) {
        vistrutah_256_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Vistrutah-256 encryption: %d iterations in %.3f seconds (%.1f MB/s)\n",
           iterations, cpu_time_used, (iterations * 32.0 / (1024*1024)) / cpu_time_used);
    
    // Benchmark Vistrutah-256 decryption
    start = clock();
    for (int i = 0; i < iterations; i++) {
        vistrutah_256_decrypt(ciphertext, plaintext, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Vistrutah-256 decryption: %d iterations in %.3f seconds (%.1f MB/s)\n",
           iterations, cpu_time_used, (iterations * 32.0 / (1024*1024)) / cpu_time_used);
}

int main() {
    printf("Vistrutah Block Cipher Test Suite\n");
    printf("=================================\n");
    
    test_vistrutah_256();
    test_vistrutah_512();
    benchmark_vistrutah();
    
    return 0;
}