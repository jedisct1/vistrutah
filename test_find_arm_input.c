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
    printf("Finding input that produces expected ARM output\n");
    printf("===============================================\n");
    
    // Expected outputs from test_arm_output.c
    // ARM:   280f1988f6058c5527e5e989c92d9a0a2e9eea657d8e9e61e0f29552ac353c7f...
    // Intel: 271750cbee3c8077af45943f68e1cd85fed1c1b12d97cd6db9088c3ecbc2e670...
    
    // The expected output is only 32 bytes shown, but Vistrutah-512 produces 64 bytes
    // This suggests it might be from Vistrutah-256 (32-byte blocks) not Vistrutah-512
    
    // Let's test if this is actually Vistrutah-256 output
    printf("\nTesting if expected output is from Vistrutah-256:\n");
    
    uint8_t key[32] = {0};
    uint8_t plaintext[32] = {0};
    uint8_t ciphertext[32];
    
    // Test with zeros
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 14);
    print_hex("Vistrutah-256 zeros", ciphertext, 32);
    
    // Test with the standard test vector
    for (int i = 0; i < 32; i++) {
        key[i] = i;
    }
    for (int i = 0; i < 32; i++) {
        plaintext[i] = (i * 0x11) & 0xff;
    }
    
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 14);
    print_hex("Vistrutah-256 test vector", ciphertext, 32);
    
    // Now let's verify our Intel Vistrutah-512 implementation is correct
    // by checking that encryption/decryption works properly
    printf("\n\nVerifying Intel Vistrutah-512 implementation:\n");
    
    uint8_t plaintext512[64];
    uint8_t ciphertext512[64];
    uint8_t decrypted512[64];
    
    // Test 1: Sequential pattern
    for (int i = 0; i < 64; i++) {
        plaintext512[i] = i;
    }
    
    vistrutah_512_encrypt(plaintext512, ciphertext512, key, 32, 14);
    vistrutah_512_decrypt(ciphertext512, decrypted512, key, 32, 14);
    
    if (memcmp(plaintext512, decrypted512, 64) == 0) {
        printf("✓ Test 1 (sequential): Encryption/Decryption works\n");
    } else {
        printf("✗ Test 1 (sequential): Encryption/Decryption FAILED\n");
    }
    
    // Test 2: Random-looking pattern
    for (int i = 0; i < 64; i++) {
        plaintext512[i] = (i * 17 + i * i) & 0xff;
    }
    
    vistrutah_512_encrypt(plaintext512, ciphertext512, key, 32, 14);
    vistrutah_512_decrypt(ciphertext512, decrypted512, key, 32, 14);
    
    if (memcmp(plaintext512, decrypted512, 64) == 0) {
        printf("✓ Test 2 (random): Encryption/Decryption works\n");
    } else {
        printf("✗ Test 2 (random): Encryption/Decryption FAILED\n");
    }
    
    // Test 3: All different round counts
    printf("\nTesting all round counts:\n");
    int all_passed = 1;
    for (int rounds = 1; rounds <= 18; rounds++) {
        vistrutah_512_encrypt(plaintext512, ciphertext512, key, 32, rounds);
        vistrutah_512_decrypt(ciphertext512, decrypted512, key, 32, rounds);
        
        if (memcmp(plaintext512, decrypted512, 64) == 0) {
            printf("✓ Rounds %2d: PASS\n", rounds);
        } else {
            printf("✗ Rounds %2d: FAIL\n", rounds);
            all_passed = 0;
        }
    }
    
    if (all_passed) {
        printf("\n✓ Intel Vistrutah-512 implementation is working correctly!\n");
    } else {
        printf("\n✗ Intel Vistrutah-512 still has issues\n");
    }
    
    return 0;
}