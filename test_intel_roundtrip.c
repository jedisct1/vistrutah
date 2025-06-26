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
    printf("Intel Vistrutah-512 Round-trip Test\n");
    printf("===================================\n\n");
    
    // Test 1: All zeros (this works)
    {
        uint8_t key[32] = {0};
        uint8_t plaintext[64] = {0};
        uint8_t ciphertext[64];
        uint8_t decrypted[64];
        
        printf("Test 1: All zeros\n");
        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 14);
        vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 14);
        
        if (memcmp(plaintext, decrypted, 64) == 0) {
            printf("✓ PASS\n");
        } else {
            printf("✗ FAIL\n");
        }
        print_hex("Ciphertext", ciphertext, 64);
    }
    
    // Test 2: Non-zero key, zero plaintext
    {
        uint8_t key[32] = {0};
        key[0] = 0x01;
        uint8_t plaintext[64] = {0};
        uint8_t ciphertext[64];
        uint8_t decrypted[64];
        
        printf("\nTest 2: Key[0]=0x01, plaintext=zeros\n");
        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 14);
        vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 14);
        
        if (memcmp(plaintext, decrypted, 64) == 0) {
            printf("✓ PASS\n");
        } else {
            printf("✗ FAIL - Decryption doesn't match!\n");
            print_hex("Expected", plaintext, 64);
            print_hex("Got", decrypted, 64);
        }
    }
    
    // Test 3: Zero key, non-zero plaintext
    {
        uint8_t key[32] = {0};
        uint8_t plaintext[64] = {0};
        plaintext[0] = 0x01;
        uint8_t ciphertext[64];
        uint8_t decrypted[64];
        
        printf("\nTest 3: Key=zeros, plaintext[0]=0x01\n");
        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 14);
        vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 14);
        
        if (memcmp(plaintext, decrypted, 64) == 0) {
            printf("✓ PASS\n");
        } else {
            printf("✗ FAIL - Decryption doesn't match!\n");
            print_hex("Expected", plaintext, 64);
            print_hex("Got", decrypted, 64);
        }
    }
    
    // Test 4: Simple pattern
    {
        uint8_t key[32] = {0};
        uint8_t plaintext[64];
        for (int i = 0; i < 64; i++) plaintext[i] = i;
        uint8_t ciphertext[64];
        uint8_t decrypted[64];
        
        printf("\nTest 4: Key=zeros, plaintext=0,1,2,...,63\n");
        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 14);
        vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 14);
        
        if (memcmp(plaintext, decrypted, 64) == 0) {
            printf("✓ PASS\n");
        } else {
            printf("✗ FAIL - Decryption doesn't match!\n");
            // Show first few differences
            int diffs = 0;
            for (int i = 0; i < 64 && diffs < 10; i++) {
                if (plaintext[i] != decrypted[i]) {
                    printf("  [%d]: expected %02x, got %02x\n", i, plaintext[i], decrypted[i]);
                    diffs++;
                }
            }
            if (diffs == 10) printf("  ... more differences\n");
        }
    }
    
    // Test 5: Fewer rounds
    {
        uint8_t key[32] = {0};
        uint8_t plaintext[64];
        for (int i = 0; i < 64; i++) plaintext[i] = i;
        uint8_t ciphertext[64];
        uint8_t decrypted[64];
        
        printf("\nTest 5: Same as test 4 but with 2 rounds only\n");
        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 2);
        vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 2);
        
        if (memcmp(plaintext, decrypted, 64) == 0) {
            printf("✓ PASS\n");
        } else {
            printf("✗ FAIL - Decryption doesn't match!\n");
        }
    }
    
    return 0;
}