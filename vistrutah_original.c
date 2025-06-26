#include "vistrutah_portable.h"
#include <arm_neon.h>
#include <arm_acle.h>
#include <stdbool.h>

#ifdef VISTRUTAH_ARM

// CPU feature detection for ARM
bool vistrutah_has_aes_accel(void) {
    // On ARM64, crypto extensions are detected at compile time
    // Runtime detection would require parsing /proc/cpuinfo or similar
    return true;
}

const char* vistrutah_get_impl_name(void) {
    return "ARM NEON+Crypto";
}

// External round constants
extern const uint8_t ROUND_CONSTANTS[38];

// Mixing layer permutation for Vistrutah-256 (ASURA mixing)
static const uint8_t MIXING_PERM_256[32] = {
    0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
    1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31
};

// Helper function to perform AES round using ARM crypto extensions
uint8x16_t aes_round(uint8x16_t state, uint8x16_t round_key) {
    // AESE performs: SubBytes + ShiftRows
    state = vaeseq_u8(state, vdupq_n_u8(0));
    // AESMC performs: MixColumns
    state = vaesmcq_u8(state);
    // AddRoundKey
    return veorq_u8(state, round_key);
}

// Helper function to perform AES final round (no MixColumns)
uint8x16_t aes_final_round(uint8x16_t state, uint8x16_t round_key) {
    // AESE performs: SubBytes + ShiftRows
    state = vaeseq_u8(state, vdupq_n_u8(0));
    // AddRoundKey (no MixColumns)
    return veorq_u8(state, round_key);
}

// Helper function for inverse AES round
uint8x16_t aes_inv_round(uint8x16_t state, uint8x16_t round_key) {
    // AddRoundKey
    state = veorq_u8(state, round_key);
    // AESIMC performs: InvMixColumns
    state = vaesimcq_u8(state);
    // AESD performs: InvSubBytes + InvShiftRows
    return vaesdq_u8(state, vdupq_n_u8(0));
}

// Helper function for inverse AES final round
uint8x16_t aes_inv_final_round(uint8x16_t state, uint8x16_t round_key) {
    // AddRoundKey
    state = veorq_u8(state, round_key);
    // AESD performs: InvSubBytes + InvShiftRows
    return vaesdq_u8(state, vdupq_n_u8(0));
}

// Vistrutah-256 mixing layer
static void vistrutah_256_mix(vistrutah_256_state_t* state) {
    uint8_t temp[32];
    uint8_t* state_bytes = (uint8_t*)state;
    
    // Apply permutation
    for (int i = 0; i < 32; i++) {
        temp[i] = state_bytes[MIXING_PERM_256[i]];
    }
    
    // Copy back
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
    
    // Copy back
    memcpy(state_bytes, temp, 32);
}

// Key expansion for Vistrutah-256
static void vistrutah_256_key_expansion(const uint8_t* key, int key_size,
                                vistrutah_key_schedule_t* ks, int rounds) {
    // Load master key
    uint8x16_t k0, k1;
    if (key_size == 16) {
        k0 = vld1q_u8(key);
        k1 = k0;  // Duplicate for 256-bit key
    } else {
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
    }
    
    // Generate round keys using alternating fixed and variable keys
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            // Fixed round key with round constant
            ks->round_keys[i] = vdupq_n_u8(ROUND_CONSTANTS[i]);
        } else {
            // Variable round key (permuted master key)
            if (i % 4 == 1) {
                ks->round_keys[i] = k0;
            } else {
                ks->round_keys[i] = k1;
            }
        }
    }
}

// Vistrutah-256 encryption
void vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_256_key_expansion(key, key_size, &ks, rounds);
    
    // Load plaintext into state
    state.slice[0] = vld1q_u8(plaintext);
    state.slice[1] = vld1q_u8(plaintext + 16);
    
    // Initial key addition
    state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[0]);
    state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[0]);
    
    // Main rounds
    int round_idx = 1;
    for (int step = 0; step < rounds / ROUNDS_PER_STEP; step++) {
        // Two AES rounds per step
        for (int r = 0; r < ROUNDS_PER_STEP; r++) {
            if (round_idx == rounds) {
                // Last round (no MixColumns)
                state.slice[0] = aes_final_round(state.slice[0], ks.round_keys[round_idx]);
                state.slice[1] = aes_final_round(state.slice[1], ks.round_keys[round_idx]);
            } else {
                // Regular round
                state.slice[0] = aes_round(state.slice[0], ks.round_keys[round_idx]);
                state.slice[1] = aes_round(state.slice[1], ks.round_keys[round_idx]);
            }
            round_idx++;
        }
        
        // Apply mixing layer (except after last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            vistrutah_256_mix(&state);
        }
    }
    
    // Handle odd number of rounds
    if (rounds % ROUNDS_PER_STEP == 1) {
        state.slice[0] = aes_final_round(state.slice[0], ks.round_keys[rounds]);
        state.slice[1] = aes_final_round(state.slice[1], ks.round_keys[rounds]);
    }
    
    // Store ciphertext
    vst1q_u8(ciphertext, state.slice[0]);
    vst1q_u8(ciphertext + 16, state.slice[1]);
}

// Vistrutah-256 decryption
void vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_256_key_expansion(key, key_size, &ks, rounds);
    
    // Load ciphertext into state
    state.slice[0] = vld1q_u8(ciphertext);
    state.slice[1] = vld1q_u8(ciphertext + 16);
    
    // Process rounds in reverse order
    int round_idx = rounds;
    
    // Handle odd number of rounds first
    if (rounds % ROUNDS_PER_STEP == 1) {
        // This is a final round without mixing
        state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round_idx]);
        state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round_idx]);
        state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
        state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
        round_idx--;
    }
    
    // Main rounds (in reverse)
    for (int step = (rounds / ROUNDS_PER_STEP) - 1; step >= 0; step--) {
        // Two AES rounds per step (in reverse)
        for (int r = 0; r < ROUNDS_PER_STEP; r++) {
            bool is_last_round = (step == (rounds / ROUNDS_PER_STEP) - 1) && 
                                (r == ROUNDS_PER_STEP - 1) && 
                                (rounds % ROUNDS_PER_STEP == 0);
            
            if (is_last_round) {
                // Last round of encryption was final round (no MixColumns)
                state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round_idx]);
                state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round_idx]);
                state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
                state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
            } else {
                // Regular inverse round
                state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round_idx]);
                state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round_idx]);
                state.slice[0] = vaesimcq_u8(state.slice[0]);
                state.slice[1] = vaesimcq_u8(state.slice[1]);
                state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
                state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
            }
            round_idx--;
        }
        
        // Apply inverse mixing layer (except after first step)
        if (step > 0) {
            vistrutah_256_inv_mix(&state);
        }
    }
    
    // Final key addition (round 0)
    state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[0]);
    state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[0]);
    
    // Store plaintext
    vst1q_u8(plaintext, state.slice[0]);
    vst1q_u8(plaintext + 16, state.slice[1]);
}

#endif // VISTRUTAH_ARM

