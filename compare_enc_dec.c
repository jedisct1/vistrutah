#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"
#include <immintrin.h>

extern const uint8_t ROUND_CONSTANTS[38];

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) printf(" ");
    }
    printf("\n");
}

void print_round_keys(int rounds) {
    printf("Round keys for %d rounds:\n", rounds);
    
    vistrutah_key_schedule_t ks = {0};
    __m128i k0 = _mm_setzero_si128();
    __m128i k1 = _mm_setzero_si128();
    
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            ks.round_keys[i] = _mm_set1_epi8(ROUND_CONSTANTS[i]);
            printf("  Round %d: RC[%d] = 0x%02x\n", i, i, ROUND_CONSTANTS[i]);
        } else {
            int key_idx = (i / 2) % 4;
            ks.round_keys[i] = (key_idx < 2) ? k0 : k1;
            printf("  Round %d: Variable key_idx=%d (zeros)\n", i, key_idx);
        }
    }
}

void trace_encryption_rounds(int rounds) {
    printf("\nEncryption with %d rounds:\n", rounds);
    printf("Round 0: Initial key addition with RC[0]\n");
    
    int round_idx = 1;
    for (int step = 0; step < rounds / ROUNDS_PER_STEP; step++) {
        printf("\nStep %d:\n", step);
        for (int r = 0; r < ROUNDS_PER_STEP && round_idx <= rounds; r++) {
            if (round_idx == rounds) {
                printf("  Round %d: AES final round + key[%d]\n", round_idx, round_idx);
            } else {
                printf("  Round %d: AES round + key[%d]\n", round_idx, round_idx);
            }
            round_idx++;
        }
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            printf("  Apply mixing layer\n");
        }
    }
    
    if (rounds % ROUNDS_PER_STEP == 1) {
        printf("\nOdd round %d: AES final + key[%d]\n", rounds, rounds);
    }
}

void trace_decryption_rounds(int rounds) {
    printf("\nDecryption with %d rounds:\n", rounds);
    
    int round_idx = rounds;
    
    if (rounds % ROUNDS_PER_STEP == 1) {
        printf("Handle odd round %d: Remove key[%d] + inverse AES final\n", round_idx, round_idx);
        round_idx--;
    }
    
    for (int step = (rounds / ROUNDS_PER_STEP) - 1; step >= 0; step--) {
        printf("\nStep %d (reverse):\n", step);
        
        // This is the key: within each step, rounds go forward!
        int first_round_in_step = round_idx - ROUNDS_PER_STEP + 1;
        for (int r = 0; r < ROUNDS_PER_STEP; r++) {
            int current_round = first_round_in_step + r;
            bool is_last_round = (step == (rounds / ROUNDS_PER_STEP) - 1) && 
                                (r == ROUNDS_PER_STEP - 1) && 
                                (rounds % ROUNDS_PER_STEP == 0);
            
            if (is_last_round) {
                printf("  Round %d: Remove key[%d] + inverse AES final\n", current_round, current_round);
            } else {
                printf("  Round %d: Remove key[%d] + InvMixColumns + inverse AES\n", current_round, current_round);
            }
        }
        round_idx -= ROUNDS_PER_STEP;
        
        if (step > 0) {
            printf("  Apply inverse mixing layer\n");
        }
    }
    
    printf("\nRound 0: Remove initial key RC[0]\n");
}

int main() {
    printf("Comparing Encryption and Decryption Round Structure\n");
    printf("==================================================\n\n");
    
    for (int rounds = 2; rounds <= 5; rounds++) {
        printf("\n=== %d ROUNDS ===\n", rounds);
        print_round_keys(rounds);
        trace_encryption_rounds(rounds);
        trace_decryption_rounds(rounds);
        printf("\n");
    }
    
    printf("\nKEY INSIGHT:\n");
    printf("The issue is that decryption processes rounds within each step in forward order,\n");
    printf("but the round_idx is being decremented after each round.\n");
    printf("This causes the wrong round keys to be used!\n");
    
    return 0;
}