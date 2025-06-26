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

// Hook into the encryption to debug
void debug_vistrutah_256() {
    printf("=== Debugging Vistrutah-256 ===\n");
    
    // Use the same test vector as in test_vistrutah_portable.c
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
    
    printf("\nTest vector:\n");
    print_hex("Key", key, 32);
    print_hex("Plaintext", plaintext, 32);
    
    // Test with 1 round first
    printf("\n--- Testing 1 round ---\n");
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 1);
    print_hex("After 1 round", ciphertext, 32);
    
    // Test with 2 rounds
    printf("\n--- Testing 2 rounds ---\n");
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 2);
    print_hex("After 2 rounds", ciphertext, 32);
    
    // Test with 3 rounds  
    printf("\n--- Testing 3 rounds ---\n");
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 3);
    print_hex("After 3 rounds", ciphertext, 32);
    
    // Full 14 rounds
    printf("\n--- Testing 14 rounds (full) ---\n");
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 14);
    print_hex("Final ciphertext", ciphertext, 32);
}

int main() {
    printf("Vistrutah Detailed Debug\n");
    printf("Implementation: %s\n", vistrutah_get_impl_name());
    printf("=========================\n");
    
    debug_vistrutah_256();
    
    return 0;
}