// Comprehensive test for Vistrutah implementation
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "vistrutah_portable.h"

// Function prototypes
void vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                          const uint8_t* key, int key_size, int rounds);
void vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                          const uint8_t* key, int key_size, int rounds);

void print_hex(const char* label, const uint8_t* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) printf("\n    ");
        else if (i < len - 1) printf(" ");
    }
    printf("\n");
}

int test_roundtrip(const char* test_name, 
                   const uint8_t* key, int key_size,
                   const uint8_t* plaintext, int block_size,
                   int rounds) {
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    printf("\n=== %s ===\n", test_name);
    printf("Key size: %d bits, Rounds: %d\n", key_size * 8, rounds);
    
    // Encrypt
    vistrutah_256_encrypt(plaintext, ciphertext, key, key_size, rounds);
    print_hex("Plaintext ", plaintext, block_size);
    print_hex("Ciphertext", ciphertext, block_size);
    
    // Decrypt
    vistrutah_256_decrypt(ciphertext, decrypted, key, key_size, rounds);
    print_hex("Decrypted ", decrypted, block_size);
    
    // Verify
    int match = memcmp(plaintext, decrypted, block_size) == 0;
    printf("Roundtrip test: %s\n", match ? "PASSED" : "FAILED");
    
    if (!match) {
        printf("ERROR: Decryption did not match plaintext!\n");
        for (int i = 0; i < block_size; i++) {
            if (plaintext[i] != decrypted[i]) {
                printf("  Position %2d: expected %02x, got %02x\n",
                       i, plaintext[i], decrypted[i]);
            }
        }
    }
    
    return match ? 0 : 1;
}

int main() {
    printf("Vistrutah Block Cipher Test Suite\n");
    printf("=================================\n");
    
    int errors = 0;
    
    // Test vectors
    uint8_t key_128[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    uint8_t key_256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t plaintext1[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    
    uint8_t plaintext2[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8_t plaintext3[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    
    // Test 1: Vistrutah-256 with 128-bit key
    errors += test_roundtrip("Test 1: Vistrutah-256, 128-bit key, 10 rounds",
                            key_128, 16, plaintext1, 32, 10);
    
    // Test 2: Vistrutah-256 with 256-bit key
    errors += test_roundtrip("Test 2: Vistrutah-256, 256-bit key, 10 rounds",
                            key_256, 32, plaintext1, 32, 10);
    
    // Test 3: Different round counts
    errors += test_roundtrip("Test 3: Vistrutah-256, 256-bit key, 14 rounds",
                            key_256, 32, plaintext1, 32, 14);
    
    // Test 4: All-zero plaintext
    errors += test_roundtrip("Test 4: All-zero plaintext, 256-bit key, 10 rounds",
                            key_256, 32, plaintext2, 32, 10);
    
    // Test 5: All-one plaintext
    errors += test_roundtrip("Test 5: All-one plaintext, 256-bit key, 10 rounds",
                            key_256, 32, plaintext3, 32, 10);
    
    // Test different round counts
    printf("\n=== Testing Different Round Counts ===\n");
    int round_counts[] = {4, 6, 8, 10, 12, 14, 16, 18};
    for (int i = 0; i < sizeof(round_counts)/sizeof(round_counts[0]); i++) {
        char test_name[64];
        snprintf(test_name, sizeof(test_name), 
                 "Round count test: %d rounds", round_counts[i]);
        errors += test_roundtrip(test_name, key_256, 32, plaintext1, 32, round_counts[i]);
    }
    
    // Summary
    printf("\n=================================\n");
    printf("Test Summary: ");
    if (errors == 0) {
        printf("ALL TESTS PASSED\n");
    } else {
        printf("%d TESTS FAILED\n", errors);
    }
    
    return errors;
}