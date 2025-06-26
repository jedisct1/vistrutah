#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"
#include <immintrin.h>

// External declarations
extern const uint8_t ROUND_CONSTANTS[38];

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf(" ");
    }
    printf("\n");
}

void print_m128i(const char* label, __m128i v) {
    uint8_t buf[16];
    _mm_storeu_si128((__m128i*)buf, v);
    print_hex(label, buf, 16);
}

// Modified version to debug the issue
void debug_vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_512_state_t state;
    vistrutah_key_schedule_t ks = {0};
    
    printf("\n=== DEBUG: Vistrutah-512 Encryption ===\n");
    printf("Key size: %d, Rounds: %d\n", key_size, rounds);
    
    // Key expansion
    __m128i k0, k1;
    k0 = _mm_loadu_si128((const __m128i*)key);
    k1 = _mm_loadu_si128((const __m128i*)(key + 16));
    
    print_m128i("Master key k0", k0);
    print_m128i("Master key k1", k1);
    
    // Generate round keys
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            // Fixed round key with round constant
            ks.round_keys[i] = _mm_set1_epi8(ROUND_CONSTANTS[i]);
            printf("Round key %d (fixed): %02x repeated\n", i, ROUND_CONSTANTS[i]);
        } else {
            // Variable round key (cyclic permutation of master key)
            int key_idx = (i / 2) % 4;
            switch (key_idx) {
                case 0: ks.round_keys[i] = k0; break;
                case 1: ks.round_keys[i] = k1; break;
                case 2: ks.round_keys[i] = k0; break;  // For 256-bit key, k2 = k0
                case 3: ks.round_keys[i] = k1; break;  // For 256-bit key, k3 = k1
            }
            printf("Round key %d (variable): key_idx=%d\n", i, key_idx);
            print_m128i("", ks.round_keys[i]);
        }
    }
    
#ifndef VISTRUTAH_VAES
    // Standard AES-NI: Process 4 blocks separately
    __m128i s0 = _mm_loadu_si128((const __m128i*)plaintext);
    __m128i s1 = _mm_loadu_si128((const __m128i*)(plaintext + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*)(plaintext + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*)(plaintext + 48));
    
    printf("\nInitial state:\n");
    print_m128i("s0", s0);
    print_m128i("s1", s1);
    print_m128i("s2", s2);
    print_m128i("s3", s3);
    
    // Initial key addition
    s0 = _mm_xor_si128(s0, ks.round_keys[0]);
    s1 = _mm_xor_si128(s1, ks.round_keys[0]);
    s2 = _mm_xor_si128(s2, ks.round_keys[0]);
    s3 = _mm_xor_si128(s3, ks.round_keys[0]);
    
    printf("\nAfter initial key addition:\n");
    print_m128i("s0", s0);
    print_m128i("s1", s1);
    print_m128i("s2", s2);
    print_m128i("s3", s3);
    
    // Store state for mixing layer
    _mm_storeu_si128((__m128i*)((uint8_t*)&state), s0);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 16), s1);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 32), s2);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 48), s3);
    
    // Main rounds
    int round_idx = 1;
    for (int step = 0; step < rounds / ROUNDS_PER_STEP; step++) {
        printf("\n=== Step %d ===\n", step);
        
        // Two AES rounds per step
        for (int r = 0; r < ROUNDS_PER_STEP; r++) {
            printf("\nRound %d:\n", round_idx);
            
            // Load current state
            s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state));
            s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 16));
            s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 32));
            s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 48));
            
            printf("Before AES round:\n");
            print_m128i("s0", s0);
            print_m128i("s1", s1);
            print_m128i("s2", s2);
            print_m128i("s3", s3);
            
            if (round_idx == rounds) {
                // Final round (no MixColumns)
                s0 = _mm_aesenclast_si128(s0, _mm_setzero_si128());
                s1 = _mm_aesenclast_si128(s1, _mm_setzero_si128());
                s2 = _mm_aesenclast_si128(s2, _mm_setzero_si128());
                s3 = _mm_aesenclast_si128(s3, _mm_setzero_si128());
                s0 = _mm_xor_si128(s0, ks.round_keys[round_idx]);
                s1 = _mm_xor_si128(s1, ks.round_keys[round_idx]);
                s2 = _mm_xor_si128(s2, ks.round_keys[round_idx]);
                s3 = _mm_xor_si128(s3, ks.round_keys[round_idx]);
                printf("Applied final round\n");
            } else {
                // Regular round
                s0 = _mm_aesenc_si128(s0, _mm_setzero_si128());
                s1 = _mm_aesenc_si128(s1, _mm_setzero_si128());
                s2 = _mm_aesenc_si128(s2, _mm_setzero_si128());
                s3 = _mm_aesenc_si128(s3, _mm_setzero_si128());
                s0 = _mm_xor_si128(s0, ks.round_keys[round_idx]);
                s1 = _mm_xor_si128(s1, ks.round_keys[round_idx]);
                s2 = _mm_xor_si128(s2, ks.round_keys[round_idx]);
                s3 = _mm_xor_si128(s3, ks.round_keys[round_idx]);
                printf("Applied regular round\n");
            }
            
            printf("After AES round:\n");
            print_m128i("s0", s0);
            print_m128i("s1", s1);
            print_m128i("s2", s2);
            print_m128i("s3", s3);
            
            // Store state back
            _mm_storeu_si128((__m128i*)((uint8_t*)&state), s0);
            _mm_storeu_si128((__m128i*)((uint8_t*)&state + 16), s1);
            _mm_storeu_si128((__m128i*)((uint8_t*)&state + 32), s2);
            _mm_storeu_si128((__m128i*)((uint8_t*)&state + 48), s3);
            round_idx++;
        }
        
        // Apply mixing layer (except after last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            printf("\nBefore mixing:\n");
            print_hex("State", (uint8_t*)&state, 64);
            
            // Mixing layer code would go here
            printf("(Mixing layer skipped for debugging)\n");
            
            printf("After mixing:\n");
            print_hex("State", (uint8_t*)&state, 64);
        }
    }
    
    // Handle odd number of rounds
    if (rounds % ROUNDS_PER_STEP == 1) {
        printf("\nHandling odd round %d:\n", rounds);
        // Load current state
        s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state));
        s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 16));
        s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 32));
        s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 48));
        
        s0 = _mm_aesenclast_si128(s0, _mm_setzero_si128());
        s1 = _mm_aesenclast_si128(s1, _mm_setzero_si128());
        s2 = _mm_aesenclast_si128(s2, _mm_setzero_si128());
        s3 = _mm_aesenclast_si128(s3, _mm_setzero_si128());
        s0 = _mm_xor_si128(s0, ks.round_keys[rounds]);
        s1 = _mm_xor_si128(s1, ks.round_keys[rounds]);
        s2 = _mm_xor_si128(s2, ks.round_keys[rounds]);
        s3 = _mm_xor_si128(s3, ks.round_keys[rounds]);
    } else {
        // Load final state
        s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state));
        s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 16));
        s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 32));
        s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 48));
    }
    
    printf("\nFinal state:\n");
    print_m128i("s0", s0);
    print_m128i("s1", s1);
    print_m128i("s2", s2);
    print_m128i("s3", s3);
    
    _mm_storeu_si128((__m128i*)ciphertext, s0);
    _mm_storeu_si128((__m128i*)(ciphertext + 16), s1);
    _mm_storeu_si128((__m128i*)(ciphertext + 32), s2);
    _mm_storeu_si128((__m128i*)(ciphertext + 48), s3);
#endif
}

int main() {
    printf("Debug Intel Vistrutah-512 Implementation\n");
    printf("======================================\n");
    
    // Simple test with zeros
    uint8_t key[32] = {0};
    uint8_t plaintext[64] = {0};
    uint8_t ciphertext[64];
    
    // Add some pattern to plaintext
    for (int i = 0; i < 64; i++) {
        plaintext[i] = i;
    }
    
    print_hex("Key", key, 32);
    print_hex("Plaintext", plaintext, 64);
    
    debug_vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 14);
    
    print_hex("\nFinal ciphertext", ciphertext, 64);
    
    // Check for repetition
    bool repetitive = true;
    for (int i = 1; i < 64; i++) {
        if (ciphertext[i] != ciphertext[0]) {
            repetitive = false;
            break;
        }
    }
    
    if (repetitive) {
        printf("\n*** WARNING: Output is repetitive (all bytes = %02x) ***\n", ciphertext[0]);
    }
    
    return 0;
}