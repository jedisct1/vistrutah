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
    printf("Debug Vistrutah-512\n");
    printf("===================\n");
    
    // Simple test with incrementing data
    uint8_t key[32] = {0};
    uint8_t plaintext[64] = {0};
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    // Fill with simple pattern
    for (int i = 0; i < 64; i++) {
        plaintext[i] = i;
    }
    
    // Test with 1 round
    printf("\nTest with 1 round:\n");
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 1);
    print_hex("Encrypted", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 1);
    print_hex("Decrypted", decrypted, 64);
    
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // Test with 2 rounds (no mixing yet)
    printf("\nTest with 2 rounds:\n");
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 2);
    print_hex("Encrypted", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 2);
    print_hex("Decrypted", decrypted, 64);
    
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // Test with 3 rounds (includes mixing)
    printf("\nTest with 3 rounds (includes mixing):\n");
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 3);
    print_hex("Encrypted", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 3);
    print_hex("Decrypted", decrypted, 64);
    
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
        printf("\nDifferences:\n");
        for (int i = 0; i < 64; i++) {
            if (plaintext[i] != decrypted[i]) {
                printf("  Byte %d: expected %02x, got %02x\n", i, plaintext[i], decrypted[i]);
            }
        }
    }
    
    return 0;
}