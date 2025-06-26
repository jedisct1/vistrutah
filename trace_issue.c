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
    printf("Tracing the issue with 4 rounds\n");
    printf("================================\n\n");
    
    uint8_t key[32] = {0};
    uint8_t plaintext[64] = {0};
    plaintext[0] = 0x01;  // Single byte difference
    
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    printf("Input:\n");
    print_hex("Key", key, 32);
    print_hex("Plaintext", plaintext, 64);
    
    // Encrypt with 4 rounds
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 4);
    print_hex("\nCiphertext (4 rounds)", ciphertext, 64);
    
    // Decrypt
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 4);
    print_hex("Decrypted", decrypted, 64);
    
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("\n✓ PASS with 4 rounds\n");
    } else {
        printf("\n✗ FAIL with 4 rounds\n");
    }
    
    // Try with 3 rounds
    printf("\n\nTrying with 3 rounds:\n");
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 3);
    print_hex("Ciphertext (3 rounds)", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 3);
    print_hex("Decrypted", decrypted, 64);
    
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("\n✓ PASS with 3 rounds\n");
    } else {
        printf("\n✗ FAIL with 3 rounds\n");
    }
    
    printf("\nAnalysis:\n");
    printf("- 2 rounds work (1 step of 2 rounds)\n");
    printf("- 3 rounds fail (1 step + 1 odd round)\n");
    printf("- 4 rounds fail (2 steps of 2 rounds each)\n");
    printf("\nThis suggests the issue is in the step/round logic!\n");
    
    return 0;
}