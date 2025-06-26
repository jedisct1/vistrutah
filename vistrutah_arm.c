#include "vistrutah_portable.h"

#ifdef VISTRUTAH_ARM

#    include <arm_neon.h>

// Round constants
extern const uint8_t ROUND_CONSTANTS[38];

// Helper macro for ARM AES operations
// ARM vaeseq_u8 XORs the second argument BEFORE the AES transformation
// So to do AES_ENC(state, round_key), we need: veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0),
// state)), round_key)
#    define AES_ENC(A, B)      veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), (A))), (B))
#    define AES_ENC_LAST(A, B) veorq_u8(vaeseq_u8(vmovq_n_u8(0), (A)), (B))

// For decryption
#    define AES_DEC(A, B)      veorq_u8(vaesimcq_u8(vaesdq_u8(vmovq_n_u8(0), (A))), (B))
#    define AES_DEC_LAST(A, B) veorq_u8(vaesdq_u8(vmovq_n_u8(0), (A)), (B))

// CPU feature detection
bool
vistrutah_has_aes_accel(void)
{
    // On ARM64, check for crypto extensions at runtime
    // This is platform-specific - simplified version
    return true; // Assume available for now
}

const char*
vistrutah_get_impl_name(void)
{
    return "ARM64 NEON+Crypto";
}

// ASURA mixing permutation for Vistrutah-256
static void
vistrutah_256_mix_arm(uint8_t state[32])
{
    static const uint8_t MIXING_PERM_256[32] = { 0,  17, 2,  19, 4,  21, 6,  23, 8,  25, 10,
                                                 27, 12, 29, 14, 31, 16, 1,  18, 3,  20, 5,
                                                 22, 7,  24, 9,  26, 11, 28, 13, 30, 15 };

    uint8_t temp[32];

    // Use NEON table lookup for permutation
    uint8x16_t indices_low  = vld1q_u8(MIXING_PERM_256);
    uint8x16_t indices_high = vld1q_u8(MIXING_PERM_256 + 16);

    // Load state
    uint8x16_t state_low  = vld1q_u8(state);
    uint8x16_t state_high = vld1q_u8(state + 16);

    // Create combined table for vtbl
    uint8x16x2_t table = { state_low, state_high };

    // Apply permutation using table lookup
    uint8x16_t perm_low  = vqtbl2q_u8(table, indices_low);
    uint8x16_t perm_high = vqtbl2q_u8(table, indices_high);

    // Store result
    vst1q_u8(temp, perm_low);
    vst1q_u8(temp + 16, perm_high);

    memcpy(state, temp, 32);
}

// Inverse ASURA mixing permutation
static void
vistrutah_256_inv_mix_arm(uint8_t state[32])
{
    uint8_t temp[32];

    static const uint8_t MIXING_PERM_256[32] = { 0,  17, 2,  19, 4,  21, 6,  23, 8,  25, 10,
                                                 27, 12, 29, 14, 31, 16, 1,  18, 3,  20, 5,
                                                 22, 7,  24, 9,  26, 11, 28, 13, 30, 15 };

    // Apply inverse permutation
    for (int i = 0; i < 32; i++) {
        temp[MIXING_PERM_256[i]] = state[i];
    }

    memcpy(state, temp, 32);
}

// Key expansion for Vistrutah-256
static void
vistrutah_256_key_expansion_arm(const uint8_t* key, int key_size, uint8x16_t round_keys[],
                                int rounds)
{
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
        uint8x16_t rc = vdupq_n_u8(ROUND_CONSTANTS[i]);
        if (i % 2 == 0) {
            round_keys[i] = veorq_u8(k0, rc);
        } else {
            round_keys[i] = veorq_u8(k1, rc);
        }
    }
}

// Vistrutah-256 encryption for ARM
void
vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8x16_t round_keys[MAX_ROUNDS + 1];
    uint8_t    state[32];

    // Key expansion
    vistrutah_256_key_expansion_arm(key, key_size, round_keys, rounds);

    // Load plaintext into two 128-bit blocks
    uint8x16_t s0 = vld1q_u8(plaintext);
    uint8x16_t s1 = vld1q_u8(plaintext + 16);

    // Initial key addition
    s0 = veorq_u8(s0, round_keys[0]);
    s1 = veorq_u8(s1, round_keys[0]);

    // Process rounds
    for (int round = 1; round <= rounds; round++) {
        if (round == rounds) {
            // Final round (no MixColumns)
            s0 = AES_ENC_LAST(s0, round_keys[round]);
            s1 = AES_ENC_LAST(s1, round_keys[round]);
        } else {
            // Regular round
            s0 = AES_ENC(s0, round_keys[round]);
            s1 = AES_ENC(s1, round_keys[round]);
        }

        // Apply mixing layer after every 2 rounds (except last)
        if ((round % 2 == 0) && (round < rounds)) {
            vst1q_u8(state, s0);
            vst1q_u8(state + 16, s1);
            vistrutah_256_mix_arm(state);
            s0 = vld1q_u8(state);
            s1 = vld1q_u8(state + 16);
        }
    }

    // Store ciphertext
    vst1q_u8(ciphertext, s0);
    vst1q_u8(ciphertext + 16, s1);
}

// Vistrutah-256 decryption for ARM
void
vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8x16_t round_keys[MAX_ROUNDS + 1];
    uint8_t    state[32];

    // Key expansion
    vistrutah_256_key_expansion_arm(key, key_size, round_keys, rounds);

    // Load ciphertext
    uint8x16_t s0 = vld1q_u8(ciphertext);
    uint8x16_t s1 = vld1q_u8(ciphertext + 16);

    // Process rounds in reverse
    for (int round = rounds; round >= 1; round--) {
        // Remove round key first
        s0 = veorq_u8(s0, round_keys[round]);
        s1 = veorq_u8(s1, round_keys[round]);

        if (round == rounds) {
            // Inverse of final round
            s0 = vaesdq_u8(vmovq_n_u8(0), s0);
            s1 = vaesdq_u8(vmovq_n_u8(0), s1);
        } else {
            // Apply inverse mixing layer before the appropriate rounds
            if ((round % 2 == 0) && (round < rounds)) {
                vst1q_u8(state, s0);
                vst1q_u8(state + 16, s1);
                vistrutah_256_inv_mix_arm(state);
                s0 = vld1q_u8(state);
                s1 = vld1q_u8(state + 16);
            }

            // Regular inverse round
            s0 = vaesimcq_u8(s0);
            s1 = vaesimcq_u8(s1);
            s0 = vaesdq_u8(vmovq_n_u8(0), s0);
            s1 = vaesdq_u8(vmovq_n_u8(0), s1);
        }
    }

    // Remove initial round key
    s0 = veorq_u8(s0, round_keys[0]);
    s1 = veorq_u8(s1, round_keys[0]);

    // Store plaintext
    vst1q_u8(plaintext, s0);
    vst1q_u8(plaintext + 16, s1);
}

#endif // VISTRUTAH_ARM