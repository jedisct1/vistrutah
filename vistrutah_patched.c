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
    return "ARM NEON+Crypto (Patched)";
}

// External round constants
extern const uint8_t ROUND_CONSTANTS[256];

// Round permutations for variable key schedule (from [BDF24])
// For 256-bit variant
static const uint8_t KEY_PERM_256_0[16] = {
    7, 0, 13, 10, 11, 4, 1, 14, 15, 8, 5, 2, 3, 12, 9, 6
};

static const uint8_t KEY_PERM_256_1[16] = {
    4, 8, 12, 0, 5, 9, 13, 1, 6, 10, 14, 2, 7, 11, 15, 3
};

// Mixing layer permutation for Vistrutah-256 (ASURA mixing)
static const uint8_t MIXING_PERM_256[32] = {
    0, 17, 2, 19, 4, 21, 6, 23, 8, 25, 10, 27, 12, 29, 14, 31,
    16, 1, 18, 3, 20, 5, 22, 7, 24, 9, 26, 11, 28, 13, 30, 15
};

// Apply permutation to 128-bit key
static uint8x16_t permute_key(uint8x16_t key, const uint8_t* perm) {
    uint8_t key_bytes[16];
    uint8_t temp[16];
    vst1q_u8(key_bytes, key);
    
    for (int i = 0; i < 16; i++) {
        temp[i] = key_bytes[perm[i]];
    }
    
    return vld1q_u8(temp);
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

// Key expansion for Vistrutah-256 - following specification
static void vistrutah_256_key_expansion(const uint8_t* key, int key_size,
                                      vistrutah_key_schedule_t* ks, int rounds) {
    // Load master key K = K0 || K1
    uint8x16_t K0, K1;
    if (key_size == 16) {
        K0 = vld1q_u8(key);
        K1 = K0;  // For 128-bit key, duplicate
    } else {
        K0 = vld1q_u8(key);
        K1 = vld1q_u8(key + 16);
    }
    
    // Initialize variable keys according to spec:
    // k0 = K1, k1 = K0 (initial swap)
    uint8x16_t k0 = K1;
    uint8x16_t k1 = K0;
    
    // Generate all round keys
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            // Even rounds: use fixed key K0
            ks->round_keys[i] = K0;
        } else {
            // Odd rounds: use variable key with round constant
            uint8x16_t rc = vdupq_n_u8(ROUND_CONSTANTS[i]);
            
            if ((i / 2) % 2 == 0) {
                // Use k0
                ks->round_keys[i] = veorq_u8(k0, rc);
                // Update k0 for next use
                k0 = permute_key(k0, KEY_PERM_256_0);
            } else {
                // Use k1
                ks->round_keys[i] = veorq_u8(k1, rc);
                // Update k1 for next use
                k1 = permute_key(k1, KEY_PERM_256_1);
            }
        }
    }
}

// Vistrutah-256 encryption - FIXED
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

// Vistrutah-256 decryption - FIXED
void vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_256_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_256_key_expansion(key, key_size, &ks, rounds);
    
    // For decryption, we need to apply inverse MixColumns to fixed keys
    // (except first and last)
    for (int i = 1; i < rounds; i++) {
        if (i % 2 == 0) {
            // Even rounds use fixed keys - apply inverse MixColumns for decryption
            ks.round_keys[i] = vaesimcq_u8(ks.round_keys[i]);
        }
        // Odd rounds use variable keys - no change needed
    }
    
    // Load ciphertext
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

// Key expansion for Vistrutah-512
static void vistrutah_512_key_expansion(const uint8_t* key, int key_size,
                                      vistrutah_key_schedule_t* ks, int rounds) {
    // For Vistrutah-512, we would have different key schedule
    // For now, using similar approach as 256-bit variant
    uint8x16_t k0, k1, k2, k3;
    if (key_size == 16) {
        k0 = vld1q_u8(key);
        k1 = k0;
        k2 = k0;
        k3 = k0;
    } else if (key_size == 32) {
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
        k2 = k0;
        k3 = k1;
    } else {  // 64 bytes
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
        k2 = vld1q_u8(key + 32);
        k3 = vld1q_u8(key + 48);
    }
    
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            ks->round_keys[i] = veorq_u8(k0, vdupq_n_u8(ROUND_CONSTANTS[i]));
        } else {
            ks->round_keys[i] = veorq_u8(k1, vdupq_n_u8(ROUND_CONSTANTS[i]));
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
    
    // Load plaintext
    state.slice[0] = vld1q_u8(plaintext);
    state.slice[1] = vld1q_u8(plaintext + 16);
    state.slice[2] = vld1q_u8(plaintext + 32);
    state.slice[3] = vld1q_u8(plaintext + 48);
    
    // Initial round key addition
    for (int i = 0; i < 4; i++) {
        state.slice[i] = veorq_u8(state.slice[i], ks.round_keys[0]);
    }
    
    // Process rounds
    for (int round = 1; round <= rounds; round++) {
        if (round == rounds) {
            // Final round (no MixColumns)
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
        
        // Apply mixing layer after every 2 rounds (except last)
        if ((round % 2 == 0) && (round < rounds)) {
            // For Vistrutah-512, we would apply a different mixing
            // For now, skipping this part
        }
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
    // Similar structure to encryption but in reverse
    // Implementation omitted for brevity
}

#endif // VISTRUTAH_ARM