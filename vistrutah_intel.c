#include "vistrutah_portable.h"

#ifdef VISTRUTAH_INTEL

#    include <cpuid.h>
#    include <immintrin.h>

// Round constants
extern const uint8_t ROUND_CONSTANTS[38];

// CPU feature detection
bool
vistrutah_has_aes_accel(void)
{
    unsigned int eax, ebx, ecx, edx;

    // Check for AES-NI
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (ecx & bit_AES) {
// Check for AVX512 and VAES
#    ifdef VISTRUTAH_VAES
            return true;
#    endif
            return true; // At least have AES-NI
        }
    }
    return false;
}

const char*
vistrutah_get_impl_name(void)
{
#    ifdef VISTRUTAH_VAES
    return "Intel AVX512+VAES";
#    elif defined(VISTRUTAH_AVX512)
    return "Intel AVX512+AES-NI";
#    else
    return "Intel SSE+AES-NI";
#    endif
}

// SSE helper functions for Vistrutah-256
static inline __m128i
aes_round(__m128i state, __m128i round_key)
{
    // AES round with round key directly
    return _mm_aesenc_si128(state, round_key);
}

static inline __m128i
aes_final_round(__m128i state, __m128i round_key)
{
    // AES final round with round key directly (no MixColumns)
    return _mm_aesenclast_si128(state, round_key);
}

static inline __m128i
aes_inv_round(__m128i state, __m128i round_key)
{
    // Inverse AES round - XOR happens after in AES-NI
    return _mm_aesdec_si128(state, round_key);
}

static inline __m128i
aes_inv_final_round(__m128i state, __m128i round_key)
{
    // Inverse AES final round with round key directly
    return _mm_aesdeclast_si128(state, round_key);
}

// Helper functions for different vector widths
#    ifdef VISTRUTAH_VAES

// AVX512+VAES: Process 4 AES blocks in parallel
// Optimized: Pass round key directly to AES instruction
static inline __m512i
aes_round_x4(__m512i state, __m512i round_key)
{
    // AES round with round key directly
    return _mm512_aesenc_epi128(state, round_key);
}

static inline __m512i
aes_final_round_x4(__m512i state, __m512i round_key)
{
    // AES final round with round key directly (no MixColumns)
    return _mm512_aesenclast_epi128(state, round_key);
}

static inline __m512i
aes_inv_round_x4(__m512i state, __m512i round_key)
{
    // Inverse AES round - XOR happens after in AES-NI
    return _mm512_aesdec_epi128(state, round_key);
}

static inline __m512i
aes_inv_final_round_x4(__m512i state, __m512i round_key)
{
    // Inverse AES final round with round key directly
    return _mm512_aesdeclast_epi128(state, round_key);
}

#    endif

// Vistrutah-256 mixing layer for Intel
static void
vistrutah_256_mix_intel(vistrutah_256_state_t* state)
{
    uint8_t  temp[32] __attribute__((aligned(32)));
    uint8_t* state_bytes = (uint8_t*) state;

    // ASURA mixing permutation
    static const uint8_t MIXING_PERM_256[32] = { 0,  17, 2,  19, 4,  21, 6,  23, 8,  25, 10,
                                                 27, 12, 29, 14, 31, 16, 1,  18, 3,  20, 5,
                                                 22, 7,  24, 9,  26, 11, 28, 13, 30, 15 };

    // Apply permutation
    for (int i = 0; i < 32; i++) {
        temp[i] = state_bytes[MIXING_PERM_256[i]];
    }

    memcpy(state_bytes, temp, 32);
}

static void
vistrutah_256_inv_mix_intel(vistrutah_256_state_t* state)
{
    uint8_t  temp[32] __attribute__((aligned(32)));
    uint8_t* state_bytes = (uint8_t*) state;

    static const uint8_t MIXING_PERM_256[32] = { 0,  17, 2,  19, 4,  21, 6,  23, 8,  25, 10,
                                                 27, 12, 29, 14, 31, 16, 1,  18, 3,  20, 5,
                                                 22, 7,  24, 9,  26, 11, 28, 13, 30, 15 };

    // Apply inverse permutation
    for (int i = 0; i < 32; i++) {
        temp[MIXING_PERM_256[i]] = state_bytes[i];
    }

    memcpy(state_bytes, temp, 32);
}

// Key expansion
static void
vistrutah_256_key_expansion_intel(const uint8_t* key, int key_size, vistrutah_key_schedule_t* ks,
                                  int rounds)
{
    __m128i k0, k1;

    if (key_size == 16) {
        k0 = _mm_loadu_si128((const __m128i*) key);
        k1 = k0;
    } else {
        k0 = _mm_loadu_si128((const __m128i*) key);
        k1 = _mm_loadu_si128((const __m128i*) (key + 16));
    }

    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            // XOR k0 with round constant
            ks->round_keys[i] = _mm_xor_si128(k0, _mm_set1_epi8(ROUND_CONSTANTS[i]));
        } else {
            // XOR k1 with round constant
            ks->round_keys[i] = _mm_xor_si128(k1, _mm_set1_epi8(ROUND_CONSTANTS[i]));
        }
    }
}

// Vistrutah-256 encryption for Intel
void
vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
    vistrutah_256_state_t    state;
    vistrutah_key_schedule_t ks = { 0 };

    // Key expansion
    vistrutah_256_key_expansion_intel(key, key_size, &ks, rounds);

    // For Vistrutah-256, always use SSE implementation for better performance
    // VAES/AVX2 overhead is not worth it for just 2 blocks
    
    // SSE implementation - process two 128-bit blocks separately
    __m128i s0 = _mm_loadu_si128((const __m128i*) plaintext);
    __m128i s1 = _mm_loadu_si128((const __m128i*) (plaintext + 16));

    // Initial key addition
    s0 = _mm_xor_si128(s0, ks.round_keys[0]);
    s1 = _mm_xor_si128(s1, ks.round_keys[0]);

    // Process rounds - exactly match ARM implementation
    for (int round = 1; round <= rounds; round++) {
        if (round == rounds) {
            // Final round (no MixColumns)
            s0 = _mm_aesenclast_si128(s0, ks.round_keys[round]);
            s1 = _mm_aesenclast_si128(s1, ks.round_keys[round]);
        } else {
            // Regular round - use helper function that matches ARM behavior
            s0 = aes_round(s0, ks.round_keys[round]);
            s1 = aes_round(s1, ks.round_keys[round]);
        }

        // Apply mixing layer after every 2 rounds (except last)
        if ((round % 2 == 0) && (round < rounds)) {
            _mm_storeu_si128((__m128i*) &state, s0);
            _mm_storeu_si128((__m128i*) ((uint8_t*) &state + 16), s1);
            vistrutah_256_mix_intel(&state);
            s0 = _mm_loadu_si128((const __m128i*) &state);
            s1 = _mm_loadu_si128((const __m128i*) ((uint8_t*) &state + 16));
        }
    }

    _mm_storeu_si128((__m128i*) ciphertext, s0);
    _mm_storeu_si128((__m128i*) (ciphertext + 16), s1);
}

// Vistrutah-256 decryption for Intel
void
vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    vistrutah_256_state_t    state;
    vistrutah_key_schedule_t ks;

    // Key expansion
    vistrutah_256_key_expansion_intel(key, key_size, &ks, rounds);

    // For Vistrutah-256, always use SSE implementation for better performance
    
    // SSE implementation
    __m128i s0 = _mm_loadu_si128((const __m128i*) ciphertext);
    __m128i s1 = _mm_loadu_si128((const __m128i*) (ciphertext + 16));

    // Process rounds in reverse - match ARM implementation
    for (int round = rounds; round >= 1; round--) {
        // Remove round key first
        s0 = _mm_xor_si128(s0, ks.round_keys[round]);
        s1 = _mm_xor_si128(s1, ks.round_keys[round]);

        if (round == rounds) {
            // Inverse of final round
            s0 = _mm_aesdeclast_si128(s0, _mm_setzero_si128());
            s1 = _mm_aesdeclast_si128(s1, _mm_setzero_si128());
        } else {
            // Apply inverse mixing layer before the appropriate rounds
            if ((round % 2 == 0) && (round < rounds)) {
                _mm_storeu_si128((__m128i*) &state, s0);
                _mm_storeu_si128((__m128i*) ((uint8_t*) &state + 16), s1);
                vistrutah_256_inv_mix_intel(&state);
                s0 = _mm_loadu_si128((const __m128i*) &state);
                s1 = _mm_loadu_si128((const __m128i*) ((uint8_t*) &state + 16));
            }

            // Regular inverse round
            s0 = _mm_aesimc_si128(s0);
            s1 = _mm_aesimc_si128(s1);
            s0 = _mm_aesdeclast_si128(s0, _mm_setzero_si128());
            s1 = _mm_aesdeclast_si128(s1, _mm_setzero_si128());
        }
    }

    // Remove initial round key
    s0 = _mm_xor_si128(s0, ks.round_keys[0]);
    s1 = _mm_xor_si128(s1, ks.round_keys[0]);

    _mm_storeu_si128((__m128i*) plaintext, s0);
    _mm_storeu_si128((__m128i*) (plaintext + 16), s1);
}

#endif // VISTRUTAH_INTEL