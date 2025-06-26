#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) printf(" ");
    }
    printf("\n");
}

int main() {
    printf("Debug non-zero encryption/decryption\n");
    printf("====================================\n\n");
    
    // Test case that fails
    uint8_t key[32] = {0};
    key[0] = 0x01;  // Single non-zero byte in key
    
    uint8_t plaintext[64] = {0};
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    printf("Key with first byte = 0x01:\n");
    print_hex("Key", key, 32);
    print_hex("Plaintext", plaintext, 64);
    
    // Encrypt
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 14);
    print_hex("\nCiphertext", ciphertext, 64);
    
    // Check if ciphertext is repetitive
    bool all_same = true;
    for (int i = 1; i < 64; i++) {
        if (ciphertext[i] != ciphertext[0]) {
            all_same = false;
            break;
        }
    }
    
    if (all_same) {
        printf("Note: Ciphertext is repetitive (all bytes = 0x%02x)\n", ciphertext[0]);
    } else {
        printf("Note: Ciphertext is NOT repetitive\n");
    }
    
    // Decrypt
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 14);
    print_hex("\nDecrypted", decrypted, 64);
    
    // Compare
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("\n✓ Decryption matches plaintext\n");
    } else {
        printf("\n✗ Decryption DOES NOT match plaintext\n");
        
        // Check if decrypted is repetitive
        all_same = true;
        for (int i = 1; i < 64; i++) {
            if (decrypted[i] != decrypted[0]) {
                all_same = false;
                break;
            }
        }
        
        if (all_same) {
            printf("Decrypted is repetitive (all bytes = 0x%02x)\n", decrypted[0]);
        }
    }
    
    // Now test with zero key but non-zero plaintext
    printf("\n\nTest with zero key, non-zero plaintext:\n");
    memset(key, 0, 32);
    memset(plaintext, 0, 64);
    plaintext[0] = 0x01;
    
    print_hex("Key", key, 32);
    print_hex("Plaintext", plaintext, 64);
    
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 14);
    print_hex("Ciphertext", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 14);
    print_hex("Decrypted", decrypted, 64);
    
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("\n✓ Decryption matches plaintext\n");
    } else {
        printf("\n✗ Decryption DOES NOT match plaintext\n");
    }
    
    return 0;
}