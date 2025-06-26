#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("Testing simple round trip\n");
    printf("========================\n");
    
    // Simple test: all zeros
    uint8_t key[32] = {0};
    uint8_t plaintext[32] = {0};
    uint8_t ciphertext[32];
    uint8_t decrypted[32];
    
    // Test with 1 round
    printf("\nTest 1: All zeros, 1 round\n");
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 1);
    print_hex("Encrypted", ciphertext, 32);
    
    vistrutah_256_decrypt(ciphertext, decrypted, key, 32, 1);
    print_hex("Decrypted", decrypted, 32);
    
    if (memcmp(plaintext, decrypted, 32) == 0) {
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // Test with 2 rounds
    printf("\nTest 2: All zeros, 2 rounds\n");
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 2);
    print_hex("Encrypted", ciphertext, 32);
    
    vistrutah_256_decrypt(ciphertext, decrypted, key, 32, 2);
    print_hex("Decrypted", decrypted, 32);
    
    if (memcmp(plaintext, decrypted, 32) == 0) {
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // Test with non-zero data, 1 round
    printf("\nTest 3: Non-zero data, 1 round\n");
    plaintext[0] = 0x01;
    key[0] = 0x01;
    
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 1);
    print_hex("Encrypted", ciphertext, 32);
    
    vistrutah_256_decrypt(ciphertext, decrypted, key, 32, 1);
    print_hex("Decrypted", decrypted, 32);
    
    if (memcmp(plaintext, decrypted, 32) == 0) {
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // Test with 3 rounds (includes mixing)
    printf("\nTest 4: All zeros, 3 rounds (with mixing)\n");
    memset(plaintext, 0, 32);
    memset(key, 0, 32);
    
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 3);
    print_hex("Encrypted", ciphertext, 32);
    
    vistrutah_256_decrypt(ciphertext, decrypted, key, 32, 3);
    print_hex("Decrypted", decrypted, 32);
    
    if (memcmp(plaintext, decrypted, 32) == 0) {
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
        for (int i = 0; i < 32; i++) {
            if (plaintext[i] != decrypted[i]) {
                printf("  Byte %d: expected %02x, got %02x\n", i, plaintext[i], decrypted[i]);
            }
        }
    }
    
    // Test with actual test vector
    printf("\nTest 5: Actual test vector, 14 rounds\n");
    uint8_t test_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t test_plaintext[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    vistrutah_256_encrypt(test_plaintext, ciphertext, test_key, 32, 14);
    print_hex("Encrypted", ciphertext, 32);
    
    vistrutah_256_decrypt(ciphertext, decrypted, test_key, 32, 14);
    print_hex("Decrypted", decrypted, 32);
    
    if (memcmp(test_plaintext, decrypted, 32) == 0) {
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
        for (int i = 0; i < 32; i++) {
            if (test_plaintext[i] != decrypted[i]) {
                printf("  Byte %d: expected %02x, got %02x\n", i, test_plaintext[i], decrypted[i]);
            }
        }
    }
    
    return 0;
}