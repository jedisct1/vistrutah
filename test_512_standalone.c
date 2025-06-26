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
    printf("Standalone Vistrutah-512 Test\n");
    printf("=============================\n");
    
    // Test vectors from test_vistrutah_portable.c
    uint8_t key256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t plaintext[64];
    for (int i = 0; i < 64; i++) {
        plaintext[i] = (i * 17) & 0xff;
    }
    
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    printf("\nTest with 256-bit key, 14 rounds:\n");
    print_hex("Key", key256, 32);
    print_hex("Plaintext", plaintext, 64);
    
    // Encrypt
    vistrutah_512_encrypt(plaintext, ciphertext, key256, 32, 14);
    print_hex("Ciphertext", ciphertext, 64);
    
    // Decrypt
    vistrutah_512_decrypt(ciphertext, decrypted, key256, 32, 14);
    print_hex("Decrypted", decrypted, 64);
    
    // Check if decryption works
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("\n✓ Encryption/Decryption cycle WORKS!\n");
    } else {
        printf("\n✗ Encryption/Decryption cycle FAILED!\n");
        
        // Show differences
        printf("\nDifferences:\n");
        for (int i = 0; i < 64; i++) {
            if (plaintext[i] != decrypted[i]) {
                printf("  Byte %d: expected %02x, got %02x\n", i, plaintext[i], decrypted[i]);
            }
        }
    }
    
    // Test with simple data
    printf("\n\nTest with zeros, 14 rounds:\n");
    memset(plaintext, 0, 64);
    memset(key256, 0, 32);
    
    vistrutah_512_encrypt(plaintext, ciphertext, key256, 32, 14);
    print_hex("Ciphertext", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key256, 32, 14);
    print_hex("Decrypted", decrypted, 64);
    
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    return 0;
}