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
    printf("Intel Vistrutah-512 Test\n");
    printf("========================\n");
    
    // Use the same test vectors that would produce the expected ARM output
    uint8_t key[32] = {0};  // All zeros
    uint8_t plaintext[64] = {0};  // All zeros
    uint8_t ciphertext[64];
    
    // Test 1: All zeros with 14 rounds (matching the test case)
    printf("\nTest 1: All zeros, 256-bit key, 14 rounds\n");
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 14);
    print_hex("Ciphertext", ciphertext, 64);
    
    // Based on test_arm_output.c, the expected outputs are:
    printf("\nExpected ARM:   280f1988f6058c5527e5e989c92d9a0a2e9eea657d8e9e61e0f29552ac353c7f...\n");
    printf("Actual Intel:   271750cbee3c8077af45943f68e1cd85fed1c1b12d97cd6db9088c3ecbc2e670...\n");
    
    // Test 2: Sequential key and specific plaintext pattern
    printf("\n\nTest 2: Sequential key, pattern plaintext, 14 rounds\n");
    for (int i = 0; i < 32; i++) {
        key[i] = i;
    }
    for (int i = 0; i < 64; i++) {
        plaintext[i] = (i * 17) & 0xff;
    }
    
    print_hex("Key", key, 32);
    print_hex("Plaintext", plaintext, 64);
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 14);
    print_hex("Ciphertext", ciphertext, 64);
    
    // Test 3: Try different round counts to see if the issue is round-specific
    printf("\n\nTest 3: Testing different round counts\n");
    memset(key, 0, 32);
    memset(plaintext, 0, 64);
    
    for (int rounds = 1; rounds <= 14; rounds++) {
        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, rounds);
        printf("Rounds %2d: ", rounds);
        // Print first 32 bytes only for brevity
        for (int i = 0; i < 32; i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("...\n");
    }
    
    return 0;
}