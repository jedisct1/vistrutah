#include "vistrutah_portable.h"
#include <arm_neon.h>
#include <arm_acle.h>
#include <stdbool.h>

#ifdef VISTRUTAH_ARM

// External declarations
extern const uint8_t ROUND_CONSTANTS[256];

// Forward declarations from vistrutah.c
extern uint8x16_t aes_round(uint8x16_t state, uint8x16_t round_key);
extern uint8x16_t aes_final_round(uint8x16_t state, uint8x16_t round_key);

// Vistrutah-512 mixing layer using transpose operations
static void vistrutah_512_mix(vistrutah_512_state_t* state) {
    // The mixing layer for Vistrutah-512 uses transpose operations
    // This implements the efficient mixing using ARM NEON transpose instructions
    
    // Load all 4 slices
    uint8x16_t s0 = state->slice[0];
    uint8x16_t s1 = state->slice[1];
    uint8x16_t s2 = state->slice[2];
    uint8x16_t s3 = state->slice[3];
    
    // Transpose operation using ARM NEON
    // First, transpose pairs
    uint8x16x2_t t01 = vtrnq_u8(s0, s1);
    uint8x16x2_t t23 = vtrnq_u8(s2, s3);
    
    // Then transpose the results to get full 4x4 transpose
    uint16x8x2_t t0 = vtrnq_u16(vreinterpretq_u16_u8(t01.val[0]), 
                                 vreinterpretq_u16_u8(t23.val[0]));
    uint16x8x2_t t1 = vtrnq_u16(vreinterpretq_u16_u8(t01.val[1]), 
                                 vreinterpretq_u16_u8(t23.val[1]));
    
    // Final transpose step
    uint32x4x2_t t2 = vtrnq_u32(vreinterpretq_u32_u16(t0.val[0]),
                                 vreinterpretq_u32_u16(t1.val[0]));
    uint32x4x2_t t3 = vtrnq_u32(vreinterpretq_u32_u16(t0.val[1]),
                                 vreinterpretq_u32_u16(t1.val[1]));
    
    // Store back the transposed result
    state->slice[0] = vreinterpretq_u8_u32(t2.val[0]);
    state->slice[1] = vreinterpretq_u8_u32(t3.val[0]);
    state->slice[2] = vreinterpretq_u8_u32(t2.val[1]);
    state->slice[3] = vreinterpretq_u8_u32(t3.val[1]);
}

// Inverse Vistrutah-512 mixing layer
static void vistrutah_512_inv_mix(vistrutah_512_state_t* state) {
    // The transpose is self-inverse, so we can use the same function
    vistrutah_512_mix(state);
}

// Helper functions from vistrutah.c
extern uint8x16_t aes_round(uint8x16_t state, uint8x16_t round_key);
extern uint8x16_t aes_final_round(uint8x16_t state, uint8x16_t round_key);
extern uint8x16_t aes_inv_round(uint8x16_t state, uint8x16_t round_key);
extern uint8x16_t aes_inv_final_round(uint8x16_t state, uint8x16_t round_key);

// Key expansion for Vistrutah-512
static void vistrutah_512_key_expansion(const uint8_t* key, int key_size,
                                vistrutah_key_schedule_t* ks, int rounds) {
    // Load master key components
    uint8x16_t k0, k1, k2, k3;
    
    if (key_size == 32) {  // 256-bit key
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
        k2 = k0;  // Replicate for 512-bit state
        k3 = k1;
    } else {  // 512-bit key
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
        k2 = vld1q_u8(key + 32);
        k3 = vld1q_u8(key + 48);
    }
    
    // Generate round keys using alternating fixed and variable keys
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            // Fixed round key with round constant
            ks->round_keys[i] = vdupq_n_u8(ROUND_CONSTANTS[i]);
        } else {
            // Variable round key (cyclic permutation of master key)
            int key_idx = (i / 2) % 4;
            switch (key_idx) {
                case 0: ks->round_keys[i] = k0; break;
                case 1: ks->round_keys[i] = k1; break;
                case 2: ks->round_keys[i] = k2; break;
                case 3: ks->round_keys[i] = k3; break;
            }
        }
    }
}

// Vistrutah-512 encryption
void vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_512_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_512_key_expansion(key, key_size, &ks, rounds);
    
    // Load plaintext into state
    state.slice[0] = vld1q_u8(plaintext);
    state.slice[1] = vld1q_u8(plaintext + 16);
    state.slice[2] = vld1q_u8(plaintext + 32);
    state.slice[3] = vld1q_u8(plaintext + 48);
    
    // Initial key addition
    state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[0]);
    state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[0]);
    state.slice[2] = veorq_u8(state.slice[2], ks.round_keys[0]);
    state.slice[3] = veorq_u8(state.slice[3], ks.round_keys[0]);
    
    // Main rounds
    int round_idx = 1;
    for (int step = 0; step < rounds / ROUNDS_PER_STEP; step++) {
        // Two AES rounds per step
        for (int r = 0; r < ROUNDS_PER_STEP; r++) {
            if (round_idx == rounds) {
                // Last round (no MixColumns)
                state.slice[0] = aes_final_round(state.slice[0], ks.round_keys[round_idx]);
                state.slice[1] = aes_final_round(state.slice[1], ks.round_keys[round_idx]);
                state.slice[2] = aes_final_round(state.slice[2], ks.round_keys[round_idx]);
                state.slice[3] = aes_final_round(state.slice[3], ks.round_keys[round_idx]);
            } else {
                // Regular round
                state.slice[0] = aes_round(state.slice[0], ks.round_keys[round_idx]);
                state.slice[1] = aes_round(state.slice[1], ks.round_keys[round_idx]);
                state.slice[2] = aes_round(state.slice[2], ks.round_keys[round_idx]);
                state.slice[3] = aes_round(state.slice[3], ks.round_keys[round_idx]);
            }
            round_idx++;
        }
        
        // Apply mixing layer (except after last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            vistrutah_512_mix(&state);
        }
    }
    
    // Handle odd number of rounds
    if (rounds % ROUNDS_PER_STEP == 1) {
        state.slice[0] = aes_final_round(state.slice[0], ks.round_keys[rounds]);
        state.slice[1] = aes_final_round(state.slice[1], ks.round_keys[rounds]);
        state.slice[2] = aes_final_round(state.slice[2], ks.round_keys[rounds]);
        state.slice[3] = aes_final_round(state.slice[3], ks.round_keys[rounds]);
    }
    
    // Store ciphertext
    vst1q_u8(ciphertext, state.slice[0]);
    vst1q_u8(ciphertext + 16, state.slice[1]);
    vst1q_u8(ciphertext + 32, state.slice[2]);
    vst1q_u8(ciphertext + 48, state.slice[3]);
}

// Vistrutah-512 decryption
void vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_512_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_512_key_expansion(key, key_size, &ks, rounds);
    
    // Load ciphertext into state
    state.slice[0] = vld1q_u8(ciphertext);
    state.slice[1] = vld1q_u8(ciphertext + 16);
    state.slice[2] = vld1q_u8(ciphertext + 32);
    state.slice[3] = vld1q_u8(ciphertext + 48);
    
    // Process rounds in reverse order
    int round_idx = rounds;
    
    // Handle odd number of rounds first
    if (rounds % ROUNDS_PER_STEP == 1) {
        // This is a final round without mixing
        state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round_idx]);
        state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round_idx]);
        state.slice[2] = veorq_u8(state.slice[2], ks.round_keys[round_idx]);
        state.slice[3] = veorq_u8(state.slice[3], ks.round_keys[round_idx]);
        state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
        state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
        state.slice[2] = vaesdq_u8(state.slice[2], vdupq_n_u8(0));
        state.slice[3] = vaesdq_u8(state.slice[3], vdupq_n_u8(0));
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
                state.slice[2] = veorq_u8(state.slice[2], ks.round_keys[round_idx]);
                state.slice[3] = veorq_u8(state.slice[3], ks.round_keys[round_idx]);
                state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
                state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
                state.slice[2] = vaesdq_u8(state.slice[2], vdupq_n_u8(0));
                state.slice[3] = vaesdq_u8(state.slice[3], vdupq_n_u8(0));
            } else {
                // Regular inverse round
                state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round_idx]);
                state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round_idx]);
                state.slice[2] = veorq_u8(state.slice[2], ks.round_keys[round_idx]);
                state.slice[3] = veorq_u8(state.slice[3], ks.round_keys[round_idx]);
                state.slice[0] = vaesimcq_u8(state.slice[0]);
                state.slice[1] = vaesimcq_u8(state.slice[1]);
                state.slice[2] = vaesimcq_u8(state.slice[2]);
                state.slice[3] = vaesimcq_u8(state.slice[3]);
                state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
                state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
                state.slice[2] = vaesdq_u8(state.slice[2], vdupq_n_u8(0));
                state.slice[3] = vaesdq_u8(state.slice[3], vdupq_n_u8(0));
            }
            round_idx--;
        }
        
        // Apply inverse mixing layer (except after first step)
        if (step > 0) {
            vistrutah_512_inv_mix(&state);
        }
    }
    
    // Final key addition (round 0)
    state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[0]);
    state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[0]);
    state.slice[2] = veorq_u8(state.slice[2], ks.round_keys[0]);
    state.slice[3] = veorq_u8(state.slice[3], ks.round_keys[0]);
    
    // Store plaintext
    vst1q_u8(plaintext, state.slice[0]);
    vst1q_u8(plaintext + 16, state.slice[1]);
    vst1q_u8(plaintext + 32, state.slice[2]);
    vst1q_u8(plaintext + 48, state.slice[3]);
}

#endif // VISTRUTAH_ARM