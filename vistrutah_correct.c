// Vistrutah Block Cipher - Correct Implementation
// Following ARM NEON AES instruction semantics properly

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

// Simple key schedule for testing
static void vistrutah_256_key_expansion_simple(const uint8_t* key, int key_size,
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
    
    // For now, use a simple alternating schedule
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            ks->round_keys[i] = veorq_u8(k0, vdupq_n_u8(ROUND_CONSTANTS[i]));
        } else {
            ks->round_keys[i] = veorq_u8(k1, vdupq_n_u8(ROUND_CONSTANTS[i]));
        }
    }
}

// Correct Vistrutah-256 encryption
void vistrutah_256_encrypt_correct(const uint8_t* plaintext, uint8_t* ciphertext,
                                  const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_256_key_expansion_simple(key, key_size, &ks, rounds);
    
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
            // vaeseq_u8 does: AddRoundKey ⊕ SubBytes ⊕ ShiftRows
            state.slice[0] = vaeseq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaeseq_u8(state.slice[1], vdupq_n_u8(0));
            // Final key addition
            state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round]);
        } else {
            // Regular round: AES round with MixColumns
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

// Correct Vistrutah-256 decryption
void vistrutah_256_decrypt_correct(const uint8_t* ciphertext, uint8_t* plaintext,
                                  const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_256_key_expansion_simple(key, key_size, &ks, rounds);
    
    // Prepare decryption keys (apply inverse MixColumns to middle round keys)
    for (int i = 1; i < rounds; i++) {
        ks.inv_round_keys[i] = vaesimcq_u8(ks.round_keys[i]);
    }
    ks.inv_round_keys[0] = ks.round_keys[0];
    ks.inv_round_keys[rounds] = ks.round_keys[rounds];
    
    // Load ciphertext into state
    state.slice[0] = vld1q_u8(ciphertext);
    state.slice[1] = vld1q_u8(ciphertext + 16);
    
    // Initial round key addition
    state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[rounds]);
    state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[rounds]);
    
    // Process rounds in reverse
    for (int round = rounds - 1; round >= 0; round--) {
        // Apply inverse mixing layer before rounds (when appropriate)
        if ((round % 2 == 1) && (round < rounds - 1)) {
            vistrutah_256_inv_mix(&state);
        }
        
        if (round == rounds - 1) {
            // Inverse final round (no InvMixColumns)
            // vaesdq_u8 does: InvShiftRows ⊕ InvSubBytes ⊕ AddRoundKey
            state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
            state.slice[0] = veorq_u8(state.slice[0], ks.inv_round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.inv_round_keys[round]);
        } else if (round == 0) {
            // Final decryption round
            state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
            state.slice[0] = veorq_u8(state.slice[0], ks.inv_round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.inv_round_keys[round]);
        } else {
            // Regular inverse round
            state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
            state.slice[0] = vaesimcq_u8(state.slice[0]);
            state.slice[1] = vaesimcq_u8(state.slice[1]);
            state.slice[0] = veorq_u8(state.slice[0], ks.inv_round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.inv_round_keys[round]);
        }
    }
    
    // Store plaintext
    vst1q_u8(plaintext, state.slice[0]);
    vst1q_u8(plaintext + 16, state.slice[1]);
}

// Test the corrected implementation
#include <stdio.h>

void test_vistrutah_256_correct() {
    printf("\n=== Testing Correct Vistrutah-256 Implementation ===\n");
    
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
    
    // Test with 10 rounds
    vistrutah_256_encrypt_correct(plaintext, ciphertext, key, 32, 10);
    vistrutah_256_decrypt_correct(ciphertext, decrypted, key, 32, 10);
    
    // Check if decryption matches plaintext
    int match = 1;
    for (int i = 0; i < 32; i++) {
        if (plaintext[i] != decrypted[i]) {
            match = 0;
            break;
        }
    }
    
    printf("Encryption/Decryption test: %s\n", match ? "PASSED" : "FAILED");
    
    if (!match) {
        printf("\nPlaintext:  ");
        for (int i = 0; i < 32; i++) printf("%02x ", plaintext[i]);
        printf("\n");
        
        printf("Ciphertext: ");
        for (int i = 0; i < 32; i++) printf("%02x ", ciphertext[i]);
        printf("\n");
        
        printf("Decrypted:  ");
        for (int i = 0; i < 32; i++) printf("%02x ", decrypted[i]);
        printf("\n");
    }
}