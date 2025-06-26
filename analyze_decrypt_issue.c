#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"
#include <immintrin.h>

extern const uint8_t ROUND_CONSTANTS[38];

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Trace through the decryption to find the issue
void trace_decrypt_issue() {
    printf("=== Analyzing Decryption Issue ===\n\n");
    
    // Simple test case
    uint8_t key[32] = {0};
    uint8_t plaintext[64] = {0};
    plaintext[0] = 0x01;  // Single non-zero byte
    
    uint8_t ciphertext[64];
    
    // First encrypt
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 4);  // Just 4 rounds
    
    printf("Plaintext: ");
    print_hex("", plaintext, 16);
    printf("Ciphertext after 4 rounds: ");
    print_hex("", ciphertext, 16);
    
    // Now let's trace the decryption manually
    printf("\n--- Manual Decryption Trace ---\n");
    
    vistrutah_key_schedule_t ks = {0};
    
    // Generate round keys (same as encryption)
    __m128i k0 = _mm_setzero_si128();
    __m128i k1 = _mm_setzero_si128();
    
    for (int i = 0; i <= 4; i++) {
        if (i % 2 == 0) {
            ks.round_keys[i] = _mm_set1_epi8(ROUND_CONSTANTS[i]);
            printf("Round key %d: 0x%02x (fixed)\n", i, ROUND_CONSTANTS[i]);
        } else {
            int key_idx = (i / 2) % 4;
            ks.round_keys[i] = (key_idx < 2) ? k0 : k1;
            printf("Round key %d: zeros (variable)\n", i);
        }
    }
    
    // Load ciphertext
    __m128i s0 = _mm_loadu_si128((const __m128i*)ciphertext);
    
    printf("\nStarting decryption with ciphertext block 0\n");
    
    // The issue is in the decryption logic!
    // Let's check the round indexing
    
    printf("\nIn encryption with 4 rounds:\n");
    printf("- Round 0: Initial key addition with RC[0]\n");
    printf("- Round 1: AES + key[1] (variable)\n");
    printf("- Round 2: AES + key[2] (RC[2])\n");
    printf("- Round 3: AES + key[3] (variable)\n");
    printf("- Round 4: AES final + key[4] (RC[4])\n");
    
    printf("\nIn decryption, we need to reverse this:\n");
    printf("- Remove key[4], inverse AES final\n");
    printf("- Remove key[3], inverse AES\n");
    printf("- Remove key[2], inverse AES\n");
    printf("- Remove key[1], inverse AES\n");
    printf("- Remove key[0]\n");
    
    printf("\nThe issue might be in how odd rounds are handled!\n");
}

// Check the specific issue with step calculation
void check_step_calculation() {
    printf("\n\n=== Checking Step Calculation ===\n");
    
    for (int rounds = 1; rounds <= 14; rounds++) {
        int steps = rounds / ROUNDS_PER_STEP;
        int odd_rounds = rounds % ROUNDS_PER_STEP;
        
        printf("Rounds=%2d: steps=%d, odd_rounds=%d", rounds, steps, odd_rounds);
        
        if (odd_rounds == 1) {
            printf(" (has odd final round)");
        }
        printf("\n");
    }
    
    printf("\nThe decryption logic needs to match this structure!\n");
}

int main() {
    trace_decrypt_issue();
    check_step_calculation();
    
    printf("\n=== DIAGNOSIS ===\n");
    printf("The issue is in the decryption's round management.\n");
    printf("Looking at the code:\n");
    printf("1. Encryption processes rounds 1..rounds\n");
    printf("2. Decryption needs to process rounds..1 in reverse\n");
    printf("3. The 'step' loop iteration might be off\n");
    
    return 0;
}