// Vistrutah Block Cipher - Debug Implementation
// Detailed tracing of AES operations

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arm_neon.h>
#include "vistrutah_portable.h"

// External round constants
extern const uint8_t ROUND_CONSTANTS[256];

// ASURA mixing permutation for Vistrutah-256
static const uint8_t MIXING_PERM_256[32] = {
    0, 17, 2, 19, 4, 21, 6, 23, 8, 25, 10, 27, 12, 29, 14, 31,
    16, 1, 18, 3, 20, 5, 22, 7, 24, 9, 26, 11, 28, 13, 30, 15
};

// Helper to print a 128-bit vector
static void print_vec(const char* label, uint8x16_t vec) {
    uint8_t bytes[16];
    vst1q_u8(bytes, vec);
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

// Helper to print state
static void print_state(const char* label, const vistrutah_256_state_t* state) {
    printf("\n%s:\n", label);
    uint8_t bytes[32];
    vst1q_u8(bytes, state->slice[0]);
    vst1q_u8(bytes + 16, state->slice[1]);
    for (int i = 0; i < 32; i++) {
        printf("%02x ", bytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
}

// Apply Vistrutah-256 mixing layer (ASURA)
static void vistrutah_256_mix(vistrutah_256_state_t* state) {
    uint8_t temp[32];
    uint8_t* state_bytes = (uint8_t*)state;
    
    printf("  Applying ASURA mixing...\n");
    
    // Apply ASURA permutation
    for (int i = 0; i < 32; i++) {
        temp[i] = state_bytes[MIXING_PERM_256[i]];
    }
    
    memcpy(state_bytes, temp, 32);
}

// Inverse Vistrutah-256 mixing layer
static void vistrutah_256_inv_mix(vistrutah_256_state_t* state) {
    uint8_t temp[32];
    uint8_t* state_bytes = (uint8_t*)state;
    
    printf("  Applying inverse ASURA mixing...\n");
    
    // Apply inverse permutation
    for (int i = 0; i < 32; i++) {
        temp[MIXING_PERM_256[i]] = state_bytes[i];
    }
    
    memcpy(state_bytes, temp, 32);
}

// Debug key schedule
static void vistrutah_256_key_expansion_debug(const uint8_t* key, int key_size,
                                             vistrutah_key_schedule_t* ks, int rounds) {
    printf("\n=== Key Schedule Generation ===\n");
    
    // Load master key
    uint8x16_t k0, k1;
    if (key_size == 16) {
        k0 = vld1q_u8(key);
        k1 = k0;
    } else {
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
    }
    
    print_vec("K0", k0);
    print_vec("K1", k1);
    
    // Generate round keys
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            ks->round_keys[i] = veorq_u8(k0, vdupq_n_u8(ROUND_CONSTANTS[i]));
            printf("Round %2d (even): K0 XOR RC[%d] = K0 XOR 0x%02x\n", 
                   i, i, ROUND_CONSTANTS[i]);
        } else {
            ks->round_keys[i] = veorq_u8(k1, vdupq_n_u8(ROUND_CONSTANTS[i]));
            printf("Round %2d (odd):  K1 XOR RC[%d] = K1 XOR 0x%02x\n", 
                   i, i, ROUND_CONSTANTS[i]);
        }
        print_vec("  Result", ks->round_keys[i]);
    }
}

// Debug encryption - trace each operation
void vistrutah_256_encrypt_debug(const uint8_t* plaintext, uint8_t* ciphertext,
                                const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    printf("\n=== ENCRYPTION DEBUG TRACE ===\n");
    
    // Key expansion
    vistrutah_256_key_expansion_debug(key, key_size, &ks, rounds);
    
    // Load plaintext into state
    state.slice[0] = vld1q_u8(plaintext);
    state.slice[1] = vld1q_u8(plaintext + 16);
    
    print_state("Initial state (plaintext)", &state);
    
    // Initial whitening
    printf("\nInitial whitening:\n");
    state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[0]);
    state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[0]);
    print_state("After initial key addition", &state);
    
    // Process rounds
    for (int round = 1; round <= rounds; round++) {
        printf("\n--- Round %d ---\n", round);
        
        // AES round operations
        printf("Applying AES operations:\n");
        
        if (round == rounds) {
            // Final round (no MixColumns)
            printf("  Final round - vaeseq_u8 (SubBytes + ShiftRows + AddRoundKey with 0)\n");
            state.slice[0] = vaeseq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaeseq_u8(state.slice[1], vdupq_n_u8(0));
            print_state("After vaeseq_u8", &state);
            
            // Add round key
            printf("  Adding round key %d\n", round);
            state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round]);
            print_state("After key addition", &state);
        } else {
            // Regular round
            printf("  vaeseq_u8 (SubBytes + ShiftRows + AddRoundKey with 0)\n");
            state.slice[0] = vaeseq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaeseq_u8(state.slice[1], vdupq_n_u8(0));
            print_state("After vaeseq_u8", &state);
            
            printf("  vaesmcq_u8 (MixColumns)\n");
            state.slice[0] = vaesmcq_u8(state.slice[0]);
            state.slice[1] = vaesmcq_u8(state.slice[1]);
            print_state("After vaesmcq_u8", &state);
            
            // Add round key
            printf("  Adding round key %d\n", round);
            state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round]);
            print_state("After key addition", &state);
        }
        
        // Apply mixing layer after every 2 rounds (except last)
        if ((round % 2 == 0) && (round < rounds)) {
            vistrutah_256_mix(&state);
            print_state("After ASURA mixing", &state);
        }
    }
    
    // Store ciphertext
    vst1q_u8(ciphertext, state.slice[0]);
    vst1q_u8(ciphertext + 16, state.slice[1]);
    
    printf("\nFinal ciphertext:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", ciphertext[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
}

// Debug decryption - trace each operation
void vistrutah_256_decrypt_debug(const uint8_t* ciphertext, uint8_t* plaintext,
                                const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    printf("\n\n=== DECRYPTION DEBUG TRACE ===\n");
    
    // Key expansion (reuse same schedule)
    vistrutah_256_key_expansion_debug(key, key_size, &ks, rounds);
    
    // Prepare inverse round keys
    printf("\nPreparing inverse round keys:\n");
    for (int i = 1; i < rounds; i++) {
        ks.inv_round_keys[i] = vaesimcq_u8(ks.round_keys[i]);
        printf("Round %d: Applied inverse MixColumns\n", i);
    }
    ks.inv_round_keys[0] = ks.round_keys[0];
    ks.inv_round_keys[rounds] = ks.round_keys[rounds];
    
    // Load ciphertext into state
    state.slice[0] = vld1q_u8(ciphertext);
    state.slice[1] = vld1q_u8(ciphertext + 16);
    
    print_state("Initial state (ciphertext)", &state);
    
    // Initial whitening (with last round key)
    printf("\nInitial whitening with round key %d:\n", rounds);
    state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[rounds]);
    state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[rounds]);
    print_state("After initial key addition", &state);
    
    // Process rounds in reverse
    for (int round = rounds - 1; round >= 0; round--) {
        printf("\n--- Round %d (inverse) ---\n", round);
        
        // Apply inverse mixing layer before rounds (when appropriate)
        if ((round % 2 == 1) && (round < rounds - 1)) {
            vistrutah_256_inv_mix(&state);
            print_state("After inverse ASURA mixing", &state);
        }
        
        if (round == rounds - 1) {
            // First decryption round (inverse of final encryption round)
            printf("  First decryption round - vaesdq_u8\n");
            state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
            print_state("After vaesdq_u8", &state);
            
            printf("  Adding inverse round key %d\n", round);
            state.slice[0] = veorq_u8(state.slice[0], ks.inv_round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.inv_round_keys[round]);
            print_state("After key addition", &state);
        } else if (round == 0) {
            // Final decryption round
            printf("  Final decryption round\n");
            printf("  vaesimcq_u8 (InvMixColumns)\n");
            state.slice[0] = vaesimcq_u8(state.slice[0]);
            state.slice[1] = vaesimcq_u8(state.slice[1]);
            print_state("After vaesimcq_u8", &state);
            
            printf("  vaesdq_u8\n");
            state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
            print_state("After vaesdq_u8", &state);
            
            printf("  Adding inverse round key %d\n", round);
            state.slice[0] = veorq_u8(state.slice[0], ks.inv_round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.inv_round_keys[round]);
            print_state("After key addition", &state);
        } else {
            // Regular inverse round
            printf("  Regular inverse round\n");
            printf("  vaesimcq_u8 (InvMixColumns)\n");
            state.slice[0] = vaesimcq_u8(state.slice[0]);
            state.slice[1] = vaesimcq_u8(state.slice[1]);
            print_state("After vaesimcq_u8", &state);
            
            printf("  vaesdq_u8\n");
            state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
            print_state("After vaesdq_u8", &state);
            
            printf("  Adding inverse round key %d\n", round);
            state.slice[0] = veorq_u8(state.slice[0], ks.inv_round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.inv_round_keys[round]);
            print_state("After key addition", &state);
        }
    }
    
    // Store plaintext
    vst1q_u8(plaintext, state.slice[0]);
    vst1q_u8(plaintext + 16, state.slice[1]);
    
    printf("\nRecovered plaintext:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", plaintext[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
}

// Test with debug output
void test_vistrutah_256_debug() {
    printf("=== Vistrutah-256 Debug Test ===\n");
    
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t plaintext[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    
    uint8_t ciphertext[32];
    uint8_t decrypted[32];
    
    // Test with minimal rounds for clarity
    printf("\nTesting with 4 rounds for debugging:\n");
    vistrutah_256_encrypt_debug(plaintext, ciphertext, key, 32, 4);
    vistrutah_256_decrypt_debug(ciphertext, decrypted, key, 32, 4);
    
    // Check if decryption matches plaintext
    int match = 1;
    for (int i = 0; i < 32; i++) {
        if (plaintext[i] != decrypted[i]) {
            match = 0;
            break;
        }
    }
    
    printf("\n\nRoundtrip test: %s\n", match ? "PASSED" : "FAILED");
    
    if (!match) {
        printf("\nMismatch details:\n");
        for (int i = 0; i < 32; i++) {
            if (plaintext[i] != decrypted[i]) {
                printf("  Position %2d: expected %02x, got %02x\n", 
                       i, plaintext[i], decrypted[i]);
            }
        }
    }
}

int main() {
    test_vistrutah_256_debug();
    return 0;
}