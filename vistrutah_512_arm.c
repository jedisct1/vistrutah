#include "vistrutah_portable.h"

#ifdef VISTRUTAH_ARM

#    include <arm_neon.h>

// External declarations
extern const uint8_t ROUND_CONSTANTS[38];

// Helper macros for ARM AES operations (same as in vistrutah_arm.c)
#    define AES_ENC(A, B)      veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), (A))), (B))
#    define AES_ENC_LAST(A, B) veorq_u8(vaeseq_u8(vmovq_n_u8(0), (A)), (B))
#    define AES_DEC(A, B)      veorq_u8(vaesimcq_u8(vaesdq_u8(vmovq_n_u8(0), (A))), (B))
#    define AES_DEC_LAST(A, B) veorq_u8(vaesdq_u8(vmovq_n_u8(0), (A)), (B))

// Vistrutah-512 mixing layer (4x4 transpose) for ARM
static void
vistrutah_512_mix_arm(uint8_t state[64])
{
    // Implement 4x4 transpose of 32-bit elements
    // This matches the Intel and portable implementations
    uint8_t   temp[64];
    uint32_t* state32 = (uint32_t*) state;
    uint32_t* temp32  = (uint32_t*) temp;

    // Input layout (32-bit words):
    // Block 0: [0,  1,  2,  3 ]
    // Block 1: [4,  5,  6,  7 ]
    // Block 2: [8,  9,  10, 11]
    // Block 3: [12, 13, 14, 15]
    //
    // After transpose:
    // Block 0: [0,  4,  8,  12]
    // Block 1: [1,  5,  9,  13]
    // Block 2: [2,  6,  10, 14]
    // Block 3: [3,  7,  11, 15]

    // Perform the transpose
    // For simplicity and correctness, use the scalar approach
    // This ensures we get the exact same result as Intel/portable
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            temp32[row * 4 + col] = state32[col * 4 + row];
        }
    }

    // Copy back to state
    memcpy(state, temp, 64);
}

// Inverse mixing is the same as forward mixing (transpose is self-inverse)
static void
vistrutah_512_inv_mix_arm(uint8_t state[64])
{
    vistrutah_512_mix_arm(state);
}

// Key expansion for Vistrutah-512
static void
vistrutah_512_key_expansion_arm(const uint8_t* key, int key_size, uint8x16_t round_keys[],
                                int rounds)
{
    uint8x16_t k0, k1, k2, k3;

    if (key_size == 32) {
        // 256-bit key
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
        k2 = k0; // For 256-bit key, k2 = k0
        k3 = k1; // For 256-bit key, k3 = k1
    } else {
        // 512-bit key
        k0 = vld1q_u8(key);
        k1 = vld1q_u8(key + 16);
        k2 = vld1q_u8(key + 32);
        k3 = vld1q_u8(key + 48);
    }

    // Generate round keys using alternating fixed and variable keys
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            // Fixed round key with round constant
            round_keys[i] = vdupq_n_u8(ROUND_CONSTANTS[i]);
        } else {
            // Variable round key (cyclic permutation of master key)
            int key_idx = (i / 2) % 4;
            switch (key_idx) {
            case 0:
                round_keys[i] = k0;
                break;
            case 1:
                round_keys[i] = k1;
                break;
            case 2:
                round_keys[i] = k2;
                break;
            case 3:
                round_keys[i] = k3;
                break;
            }
        }
    }
}

// Vistrutah-512 encryption for ARM
void
vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8x16_t round_keys[MAX_ROUNDS + 1];
    uint8_t    state[64];

    // Key expansion
    vistrutah_512_key_expansion_arm(key, key_size, round_keys, rounds);

    // Load plaintext into four 128-bit blocks
    uint8x16_t s0 = vld1q_u8(plaintext);
    uint8x16_t s1 = vld1q_u8(plaintext + 16);
    uint8x16_t s2 = vld1q_u8(plaintext + 32);
    uint8x16_t s3 = vld1q_u8(plaintext + 48);

    // Initial key addition
    s0 = veorq_u8(s0, round_keys[0]);
    s1 = veorq_u8(s1, round_keys[0]);
    s2 = veorq_u8(s2, round_keys[0]);
    s3 = veorq_u8(s3, round_keys[0]);

    // Store initial state
    vst1q_u8(state, s0);
    vst1q_u8(state + 16, s1);
    vst1q_u8(state + 32, s2);
    vst1q_u8(state + 48, s3);

    // Main rounds
    int round_idx = 1;
    for (int step = 0; step < rounds / ROUNDS_PER_STEP; step++) {
        // Two AES rounds per step
        for (int r = 0; r < ROUNDS_PER_STEP; r++) {
            // Load current state
            s0 = vld1q_u8(state);
            s1 = vld1q_u8(state + 16);
            s2 = vld1q_u8(state + 32);
            s3 = vld1q_u8(state + 48);

            if (round_idx == rounds) {
                // Final round (no MixColumns)
                s0 = AES_ENC_LAST(s0, round_keys[round_idx]);
                s1 = AES_ENC_LAST(s1, round_keys[round_idx]);
                s2 = AES_ENC_LAST(s2, round_keys[round_idx]);
                s3 = AES_ENC_LAST(s3, round_keys[round_idx]);
            } else {
                // Regular round
                s0 = AES_ENC(s0, round_keys[round_idx]);
                s1 = AES_ENC(s1, round_keys[round_idx]);
                s2 = AES_ENC(s2, round_keys[round_idx]);
                s3 = AES_ENC(s3, round_keys[round_idx]);
            }

            // Store state back
            vst1q_u8(state, s0);
            vst1q_u8(state + 16, s1);
            vst1q_u8(state + 32, s2);
            vst1q_u8(state + 48, s3);
            round_idx++;
        }

        // Apply mixing layer (except after last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            vistrutah_512_mix_arm(state);
        }
    }

    // Handle odd number of rounds
    if (rounds % ROUNDS_PER_STEP == 1) {
        // Load current state
        s0 = vld1q_u8(state);
        s1 = vld1q_u8(state + 16);
        s2 = vld1q_u8(state + 32);
        s3 = vld1q_u8(state + 48);

        // Final round
        s0 = AES_ENC_LAST(s0, round_keys[rounds]);
        s1 = AES_ENC_LAST(s1, round_keys[rounds]);
        s2 = AES_ENC_LAST(s2, round_keys[rounds]);
        s3 = AES_ENC_LAST(s3, round_keys[rounds]);

        // Store final state
        vst1q_u8(state, s0);
        vst1q_u8(state + 16, s1);
        vst1q_u8(state + 32, s2);
        vst1q_u8(state + 48, s3);
    }

    // Copy state to ciphertext
    memcpy(ciphertext, state, 64);
}

// Vistrutah-512 decryption for ARM
void
vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8x16_t round_keys[MAX_ROUNDS + 1];
    uint8_t    state[64];

    // Key expansion
    vistrutah_512_key_expansion_arm(key, key_size, round_keys, rounds);

    // Copy ciphertext to state
    memcpy(state, ciphertext, 64);

    // Handle odd number of rounds first
    int round_idx = rounds;
    if (rounds % ROUNDS_PER_STEP == 1) {
        // Load state
        uint8x16_t s0 = vld1q_u8(state);
        uint8x16_t s1 = vld1q_u8(state + 16);
        uint8x16_t s2 = vld1q_u8(state + 32);
        uint8x16_t s3 = vld1q_u8(state + 48);

        // Remove round key
        s0 = veorq_u8(s0, round_keys[round_idx]);
        s1 = veorq_u8(s1, round_keys[round_idx]);
        s2 = veorq_u8(s2, round_keys[round_idx]);
        s3 = veorq_u8(s3, round_keys[round_idx]);

        // Inverse final round
        s0 = vaesdq_u8(vmovq_n_u8(0), s0);
        s1 = vaesdq_u8(vmovq_n_u8(0), s1);
        s2 = vaesdq_u8(vmovq_n_u8(0), s2);
        s3 = vaesdq_u8(vmovq_n_u8(0), s3);

        // Store state
        vst1q_u8(state, s0);
        vst1q_u8(state + 16, s1);
        vst1q_u8(state + 32, s2);
        vst1q_u8(state + 48, s3);

        round_idx--;
    }

    // Main rounds in reverse
    for (int step = (rounds / ROUNDS_PER_STEP) - 1; step >= 0; step--) {
        // Apply inverse mixing layer (except before first step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            vistrutah_512_inv_mix_arm(state);
        }

        // Two AES rounds per step in reverse
        for (int r = ROUNDS_PER_STEP - 1; r >= 0; r--) {
            // Load current state
            uint8x16_t s0 = vld1q_u8(state);
            uint8x16_t s1 = vld1q_u8(state + 16);
            uint8x16_t s2 = vld1q_u8(state + 32);
            uint8x16_t s3 = vld1q_u8(state + 48);

            // Remove round key
            s0 = veorq_u8(s0, round_keys[round_idx]);
            s1 = veorq_u8(s1, round_keys[round_idx]);
            s2 = veorq_u8(s2, round_keys[round_idx]);
            s3 = veorq_u8(s3, round_keys[round_idx]);

            if (round_idx == rounds) {
                // Inverse final round
                s0 = vaesdq_u8(vmovq_n_u8(0), s0);
                s1 = vaesdq_u8(vmovq_n_u8(0), s1);
                s2 = vaesdq_u8(vmovq_n_u8(0), s2);
                s3 = vaesdq_u8(vmovq_n_u8(0), s3);
            } else {
                // Regular inverse round
                s0 = vaesimcq_u8(s0);
                s1 = vaesimcq_u8(s1);
                s2 = vaesimcq_u8(s2);
                s3 = vaesimcq_u8(s3);
                s0 = vaesdq_u8(vmovq_n_u8(0), s0);
                s1 = vaesdq_u8(vmovq_n_u8(0), s1);
                s2 = vaesdq_u8(vmovq_n_u8(0), s2);
                s3 = vaesdq_u8(vmovq_n_u8(0), s3);
            }

            // Store state back
            vst1q_u8(state, s0);
            vst1q_u8(state + 16, s1);
            vst1q_u8(state + 32, s2);
            vst1q_u8(state + 48, s3);
            round_idx--;
        }
    }

    // Remove initial round key
    uint8x16_t s0 = vld1q_u8(state);
    uint8x16_t s1 = vld1q_u8(state + 16);
    uint8x16_t s2 = vld1q_u8(state + 32);
    uint8x16_t s3 = vld1q_u8(state + 48);

    s0 = veorq_u8(s0, round_keys[0]);
    s1 = veorq_u8(s1, round_keys[0]);
    s2 = veorq_u8(s2, round_keys[0]);
    s3 = veorq_u8(s3, round_keys[0]);

    // Store plaintext
    vst1q_u8(plaintext, s0);
    vst1q_u8(plaintext + 16, s1);
    vst1q_u8(plaintext + 32, s2);
    vst1q_u8(plaintext + 48, s3);
}

#endif // VISTRUTAH_ARM