// Vistrutah Block Cipher - Working Implementation
// Properly implementing AES operations for encryption/decryption

#include <stdint.h>
#include <string.h>
#include <arm_neon.h>
#include "vistrutah_portable.h"

// External round constants
extern const uint8_t ROUND_CONSTANTS[256];

// ASURA mixing permutation for Vistrutah-256
static const uint8_t MIXING_PERM_256[32] = {
    0, 17, 2, 19, 4, 21, 6, 23, 8, 25, 10, 27, 12, 29, 14, 31,
    16, 1, 18, 3, 20, 5, 22, 7, 24, 9, 26, 11, 28, 13, 30, 15
};

// Apply Vistrutah-256 mixing layer (ASURA)
static void vistrutah_256_mix(vistrutah_256_state_t* state) {
    uint8_t temp[32];
    uint8_t* state_bytes = (uint8_t*)state;
    
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
    
    // Apply inverse permutation
    for (int i = 0; i < 32; i++) {
        temp[MIXING_PERM_256[i]] = state_bytes[i];
    }
    
    memcpy(state_bytes, temp, 32);
}

// Key expansion
static void vistrutah_256_key_expansion(const uint8_t* key, int key_size,
                                       vistrutah_key_schedule_t* ks, int rounds) {
    // Load master key
    uint8x16_t k0, k1;
    if (key_size == 16) {
        k0 = vld1q_u8(key);
        k1 = k0;
    } else {
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
    }
    
    // Generate round keys
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            ks->round_keys[i] = veorq_u8(k0, vdupq_n_u8(ROUND_CONSTANTS[i]));
        } else {
            ks->round_keys[i] = veorq_u8(k1, vdupq_n_u8(ROUND_CONSTANTS[i]));
        }
    }
}

// Working Vistrutah-256 encryption
void vistrutah_256_encrypt_working(const uint8_t* plaintext, uint8_t* ciphertext,
                                  const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_256_key_expansion(key, key_size, &ks, rounds);
    
    // Load plaintext into state
    state.slice[0] = vld1q_u8(plaintext);
    state.slice[1] = vld1q_u8(plaintext + 16);
    
    // Initial round key addition
    state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[0]);
    state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[0]);
    
    // Process rounds
    for (int round = 1; round <= rounds; round++) {
        if (round == rounds) {
            // Final round (no MixColumns)
            // vaeseq_u8 performs: AddRoundKey(0) + SubBytes + ShiftRows
            state.slice[0] = vaeseq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaeseq_u8(state.slice[1], vdupq_n_u8(0));
            // Add round key
            state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round]);
        } else {
            // Regular round with MixColumns
            state.slice[0] = vaeseq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaeseq_u8(state.slice[1], vdupq_n_u8(0));
            state.slice[0] = vaesmcq_u8(state.slice[0]);
            state.slice[1] = vaesmcq_u8(state.slice[1]);
            // Add round key
            state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round]);
        }
        
        // Apply mixing layer after every 2 rounds (except last)
        if ((round % 2 == 0) && (round < rounds)) {
            vistrutah_256_mix(&state);
        }
    }
    
    // Store ciphertext
    vst1q_u8(ciphertext, state.slice[0]);
    vst1q_u8(ciphertext + 16, state.slice[1]);
}

// Working Vistrutah-256 decryption
void vistrutah_256_decrypt_working(const uint8_t* ciphertext, uint8_t* plaintext,
                                  const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_256_key_expansion(key, key_size, &ks, rounds);
    
    // Load ciphertext into state
    state.slice[0] = vld1q_u8(ciphertext);
    state.slice[1] = vld1q_u8(ciphertext + 16);
    
    // Process rounds in reverse
    for (int round = rounds; round >= 1; round--) {
        // Remove round key first
        state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round]);
        state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round]);
        
        if (round == rounds) {
            // Inverse of final round (no InvMixColumns)
            // vaesdq_u8 performs: InvShiftRows + InvSubBytes + AddRoundKey(0)
            state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
        } else {
            // Undo mixing layer before processing the round that applied it
            if ((round % 2 == 0) && (round < rounds)) {
                vistrutah_256_inv_mix(&state);
            }
            
            // Regular inverse round
            // First InvMixColumns
            state.slice[0] = vaesimcq_u8(state.slice[0]);
            state.slice[1] = vaesimcq_u8(state.slice[1]);
            // Then InvShiftRows + InvSubBytes
            state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
        }
    }
    
    // Remove initial round key
    state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[0]);
    state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[0]);
    
    // Store plaintext
    vst1q_u8(plaintext, state.slice[0]);
    vst1q_u8(plaintext + 16, state.slice[1]);
}

// Test the working implementation
#include <stdio.h>

void test_vistrutah_256_working() {
    printf("\n=== Testing Working Vistrutah-256 Implementation ===\n");
    
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
    
    // Test with different round counts
    int test_rounds[] = {4, 6, 8, 10, 12, 14};
    int num_tests = sizeof(test_rounds) / sizeof(test_rounds[0]);
    
    printf("\nRunning encryption/decryption tests:\n");
    
    int all_passed = 1;
    for (int i = 0; i < num_tests; i++) {
        int rounds = test_rounds[i];
        
        vistrutah_256_encrypt_working(plaintext, ciphertext, key, 32, rounds);
        vistrutah_256_decrypt_working(ciphertext, decrypted, key, 32, rounds);
        
        // Check if decryption matches plaintext
        int match = 1;
        for (int j = 0; j < 32; j++) {
            if (plaintext[j] != decrypted[j]) {
                match = 0;
                all_passed = 0;
                break;
            }
        }
        
        printf("%2d rounds: %s\n", rounds, match ? "PASSED" : "FAILED");
        
        if (!match) {
            printf("  Plaintext:  ");
            for (int j = 0; j < 32; j++) printf("%02x ", plaintext[j]);
            printf("\n");
            
            printf("  Ciphertext: ");
            for (int j = 0; j < 32; j++) printf("%02x ", ciphertext[j]);
            printf("\n");
            
            printf("  Decrypted:  ");
            for (int j = 0; j < 32; j++) printf("%02x ", decrypted[j]);
            printf("\n");
        }
    }
    
    printf("\nOverall result: %s\n", all_passed ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
}

int main() {
    test_vistrutah_256_working();
    return 0;
}