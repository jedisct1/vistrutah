// Vistrutah Block Cipher - Fixed implementation for Apple Silicon
// Corrected mixing layer and decryption logic

#include "vistrutah_portable.h"
#include <arm_neon.h>
#include <arm_acle.h>
#include <stdbool.h>
#include <string.h>

#ifdef VISTRUTAH_ARM

// CPU feature detection for Apple Silicon
bool vistrutah_has_aes_accel(void) {
    return true;
}

const char* vistrutah_get_impl_name(void) {
    return "Apple Silicon ARM64+NEON+Crypto (Fixed)";
}

// External round constants
extern const uint8_t ROUND_CONSTANTS[256];

// ASURA mixing permutation for Vistrutah-256
static const uint8_t MIXING_PERM_256[32] = {
    0, 17, 2, 19, 4, 21, 6, 23, 8, 25, 10, 27, 12, 29, 14, 31,
    16, 1, 18, 3, 20, 5, 22, 7, 24, 9, 26, 11, 28, 13, 30, 15
};

// Apply Vistrutah-256 mixing layer
static void vistrutah_256_mix(vistrutah_256_state_t* state) {
    uint8_t temp[32];
    uint8_t* state_bytes = (uint8_t*)state;
    
    // Apply ASURA permutation
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

// Vistrutah-256 encryption
void vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_256_key_expansion(key, key_size, &ks, rounds);
    
    // Load plaintext
    state.slice[0] = vld1q_u8(plaintext);
    state.slice[1] = vld1q_u8(plaintext + 16);
    
    // Initial round key addition
    state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[0]);
    state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[0]);
    
    // Process rounds
    for (int round = 1; round <= rounds; round++) {
        if (round == rounds) {
            // Final round (no MixColumns)
            state.slice[0] = vaeseq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaeseq_u8(state.slice[1], vdupq_n_u8(0));
            state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round]);
            state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round]);
        } else {
            // Regular round
            state.slice[0] = vaeseq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaeseq_u8(state.slice[1], vdupq_n_u8(0));
            state.slice[0] = vaesmcq_u8(state.slice[0]);
            state.slice[1] = vaesmcq_u8(state.slice[1]);
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

// Vistrutah-256 decryption
void vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_256_key_expansion(key, key_size, &ks, rounds);
    
    // Load ciphertext
    state.slice[0] = vld1q_u8(ciphertext);
    state.slice[1] = vld1q_u8(ciphertext + 16);
    
    // Process rounds in reverse
    for (int round = rounds; round >= 1; round--) {
        // Remove round key first
        state.slice[0] = veorq_u8(state.slice[0], ks.round_keys[round]);
        state.slice[1] = veorq_u8(state.slice[1], ks.round_keys[round]);
        
        if (round == rounds) {
            // Inverse of final round
            state.slice[0] = vaesdq_u8(state.slice[0], vdupq_n_u8(0));
            state.slice[1] = vaesdq_u8(state.slice[1], vdupq_n_u8(0));
        } else {
            // Apply inverse mixing layer before the appropriate rounds
            if ((round % 2 == 0) && (round < rounds)) {
                vistrutah_256_inv_mix(&state);
            }
            
            // Regular inverse round
            state.slice[0] = vaesimcq_u8(state.slice[0]);
            state.slice[1] = vaesimcq_u8(state.slice[1]);
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

// Vistrutah-512 encryption
void vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_512_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Simple key schedule
    uint8x16_t k0, k1;
    if (key_size == 16) {
        k0 = vld1q_u8(key);
        k1 = k0;
    } else {
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
    }
    
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            ks.round_keys[i] = veorq_u8(k0, vdupq_n_u8(ROUND_CONSTANTS[i]));
        } else {
            ks.round_keys[i] = veorq_u8(k1, vdupq_n_u8(ROUND_CONSTANTS[i]));
        }
    }
    
    // Load plaintext
    for (int i = 0; i < 4; i++) {
        state.slice[i] = vld1q_u8(plaintext + i * 16);
    }
    
    // Initial key addition
    for (int i = 0; i < 4; i++) {
        state.slice[i] = veorq_u8(state.slice[i], ks.round_keys[0]);
    }
    
    // Process rounds
    for (int round = 1; round <= rounds; round++) {
        if (round == rounds) {
            // Final round
            for (int i = 0; i < 4; i++) {
                state.slice[i] = vaeseq_u8(state.slice[i], vdupq_n_u8(0));
                state.slice[i] = veorq_u8(state.slice[i], ks.round_keys[round]);
            }
        } else {
            // Regular round
            for (int i = 0; i < 4; i++) {
                state.slice[i] = vaeseq_u8(state.slice[i], vdupq_n_u8(0));
                state.slice[i] = vaesmcq_u8(state.slice[i]);
                state.slice[i] = veorq_u8(state.slice[i], ks.round_keys[round]);
            }
        }
        
        // Mixing layer for 512-bit variant would go here
    }
    
    // Store ciphertext
    for (int i = 0; i < 4; i++) {
        vst1q_u8(ciphertext + i * 16, state.slice[i]);
    }
}

// Vistrutah-512 decryption
void vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_512_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key schedule
    uint8x16_t k0, k1;
    if (key_size == 16) {
        k0 = vld1q_u8(key);
        k1 = k0;
    } else {
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
    }
    
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            ks.round_keys[i] = veorq_u8(k0, vdupq_n_u8(ROUND_CONSTANTS[i]));
        } else {
            ks.round_keys[i] = veorq_u8(k1, vdupq_n_u8(ROUND_CONSTANTS[i]));
        }
    }
    
    // Load ciphertext
    for (int i = 0; i < 4; i++) {
        state.slice[i] = vld1q_u8(ciphertext + i * 16);
    }
    
    // Process in reverse
    for (int round = rounds; round >= 1; round--) {
        // Remove round key
        for (int i = 0; i < 4; i++) {
            state.slice[i] = veorq_u8(state.slice[i], ks.round_keys[round]);
        }
        
        if (round == rounds) {
            // Inverse final round
            for (int i = 0; i < 4; i++) {
                state.slice[i] = vaesdq_u8(state.slice[i], vdupq_n_u8(0));
            }
        } else {
            // Regular inverse round
            for (int i = 0; i < 4; i++) {
                state.slice[i] = vaesimcq_u8(state.slice[i]);
                state.slice[i] = vaesdq_u8(state.slice[i], vdupq_n_u8(0));
            }
        }
    }
    
    // Remove initial key
    for (int i = 0; i < 4; i++) {
        state.slice[i] = veorq_u8(state.slice[i], ks.round_keys[0]);
    }
    
    // Store plaintext
    for (int i = 0; i < 4; i++) {
        vst1q_u8(plaintext + i * 16, state.slice[i]);
    }
}

#endif // VISTRUTAH_ARM