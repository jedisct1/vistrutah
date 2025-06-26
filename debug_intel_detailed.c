#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"

void print_hex_compact(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_state_blocks(const char* label, const uint8_t* state) {
    printf("%s:\n", label);
    for (int block = 0; block < 4; block++) {
        printf("  Block %d: ", block);
        for (int i = 0; i < 16; i++) {
            printf("%02x", state[block * 16 + i]);
        }
        printf("\n");
    }
}

// Create a version that shows internal state
void debug_vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                                 const uint8_t* key, int key_size, int rounds) {
    printf("\n=== DEBUG ENCRYPTION ===\n");
    printf("Rounds: %d\n", rounds);
    
    uint8_t state[64];
    memcpy(state, plaintext, 64);
    
    print_state_blocks("Initial plaintext", state);
    
    // Simulate the encryption process step by step
    // This is a simplified version to understand the flow
    
    // The issue might be in how the state is managed
    // Let's trace through what should happen
    
    printf("\nExpected flow for %d rounds:\n", rounds);
    printf("- Initial XOR with round key 0\n");
    
    int round_idx = 1;
    for (int step = 0; step < rounds / 2; step++) {
        printf("- Step %d:\n", step);
        printf("  - Round %d: AES round + XOR with key %d\n", round_idx, round_idx);
        round_idx++;
        printf("  - Round %d: AES round + XOR with key %d\n", round_idx, round_idx);
        round_idx++;
        if (step < (rounds / 2) - 1) {
            printf("  - Apply mixing layer\n");
        }
    }
    
    if (rounds % 2 == 1) {
        printf("- Odd round %d: AES final round + XOR with key %d\n", rounds, rounds);
    }
    
    // Call the actual encryption
    vistrutah_512_encrypt(plaintext, ciphertext, key, key_size, rounds);
    print_state_blocks("\nFinal ciphertext", ciphertext);
}

int main() {
    printf("Detailed Intel Vistrutah-512 Debug\n");
    printf("==================================\n");
    
    // Test 1: Simple pattern to see if all blocks are processed
    uint8_t key[32] = {0};
    uint8_t plaintext[64];
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    // Initialize each block with a different pattern
    for (int block = 0; block < 4; block++) {
        for (int i = 0; i < 16; i++) {
            plaintext[block * 16 + i] = (block << 4) | i;
        }
    }
    
    printf("\nTest 1: Different pattern per block\n");
    print_hex_compact("Key (all zeros)", key, 32);
    print_state_blocks("Plaintext", plaintext);
    
    // Test with 2 rounds (should work)
    printf("\n--- 2 rounds (should work) ---\n");
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 2);
    print_state_blocks("Ciphertext", ciphertext);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 2);
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ Decryption successful\n");
    } else {
        printf("✗ Decryption failed\n");
        print_state_blocks("Decrypted", decrypted);
    }
    
    // Test with 4 rounds (mixing layer involved)
    printf("\n--- 4 rounds (mixing layer involved) ---\n");
    debug_vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 4);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 4);
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ Decryption successful\n");
    } else {
        printf("✗ Decryption failed\n");
        print_state_blocks("Decrypted", decrypted);
    }
    
    // Test 2: Check if round constants are the issue
    printf("\n\nTest 2: Round constant effect\n");
    memset(plaintext, 0, 64);
    
    for (int r = 1; r <= 6; r++) {
        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, r);
        printf("Rounds %d, first block: ", r);
        for (int i = 0; i < 16; i++) {
            printf("%02x", ciphertext[i]);
        }
        
        // Check if all blocks are identical
        int all_same = 1;
        for (int block = 1; block < 4; block++) {
            if (memcmp(ciphertext, ciphertext + block * 16, 16) != 0) {
                all_same = 0;
                break;
            }
        }
        printf(" %s\n", all_same ? "(all blocks identical)" : "(blocks differ)");
    }
    
    return 0;
}