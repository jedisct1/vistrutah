#include "vistrutah_portable.h"

#ifdef VISTRUTAH_INTEL

#include <immintrin.h>

// External declarations
extern const uint8_t ROUND_CONSTANTS[38];

// Vistrutah-512 mixing layer for Intel
static void vistrutah_512_mix_intel(vistrutah_512_state_t* state) {
#ifdef VISTRUTAH_VAES
    // With AVX512, we can work on the entire 512-bit state at once
    __m512i s = state->state;
    
    // Transpose operation using AVX512 shuffle
    // This implements a 4x4 transpose of 128-bit blocks
    const __m512i shuffle_mask = _mm512_set_epi32(
        15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0
    );
    state->state = _mm512_permutexvar_epi32(shuffle_mask, s);
    
#else
    // For non-AVX512, work with 4 separate 128-bit blocks
    __m128i s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)state));
    __m128i s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)state + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)state + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)state + 48));
    
    // Perform 4x4 transpose using SSE instructions
    // This is more complex but achieves the same result
    __m128i t0, t1, t2, t3;
    
    // First level: transpose pairs
    t0 = _mm_unpacklo_epi32(s0, s1);
    t1 = _mm_unpackhi_epi32(s0, s1);
    t2 = _mm_unpacklo_epi32(s2, s3);
    t3 = _mm_unpackhi_epi32(s2, s3);
    
    // Second level: complete transpose
    s0 = _mm_unpacklo_epi64(t0, t2);
    s1 = _mm_unpackhi_epi64(t0, t2);
    s2 = _mm_unpacklo_epi64(t1, t3);
    s3 = _mm_unpackhi_epi64(t1, t3);
    
    _mm_storeu_si128((__m128i*)((uint8_t*)state), s0);
    _mm_storeu_si128((__m128i*)((uint8_t*)state + 16), s1);
    _mm_storeu_si128((__m128i*)((uint8_t*)state + 32), s2);
    _mm_storeu_si128((__m128i*)((uint8_t*)state + 48), s3);
#endif
}

// Key expansion for Vistrutah-512
static void vistrutah_512_key_expansion_intel(const uint8_t* key, int key_size,
                                              vistrutah_key_schedule_t* ks, int rounds) {
    __m128i k0, k1, k2, k3;
    
    if (key_size == 32) {
        k0 = _mm_loadu_si128((const __m128i*)key);
        k1 = _mm_loadu_si128((const __m128i*)(key + 16));
        k2 = k0;
        k3 = k1;
    } else {
        k0 = _mm_loadu_si128((const __m128i*)key);
        k1 = _mm_loadu_si128((const __m128i*)(key + 16));
        k2 = _mm_loadu_si128((const __m128i*)(key + 32));
        k3 = _mm_loadu_si128((const __m128i*)(key + 48));
    }
    
    // Match the simpler key schedule from vistrutah.c
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            // XOR k0 with round constant (like vistrutah.c)
            ks->round_keys[i] = _mm_xor_si128(k0, _mm_set1_epi8(ROUND_CONSTANTS[i]));
        } else {
            // XOR k1 with round constant (like vistrutah.c)
            ks->round_keys[i] = _mm_xor_si128(k1, _mm_set1_epi8(ROUND_CONSTANTS[i]));
        }
    }
}

// Vistrutah-512 encryption
void vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_512_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_512_key_expansion_intel(key, key_size, &ks, rounds);
    
#ifdef VISTRUTAH_VAES
    // AVX512+VAES: Process all 4 blocks in parallel
    state.state = _mm512_loadu_si512((const __m512i*)plaintext);
    
    // Initial key addition
    __m512i rk = _mm512_broadcast_i32x4(ks.round_keys[0]);
    state.state = _mm512_xor_si512(state.state, rk);
    
    // Main rounds
    int round_idx = 1;
    for (int step = 0; step < rounds / ROUNDS_PER_STEP; step++) {
        // Two AES rounds per step
        for (int r = 0; r < ROUNDS_PER_STEP; r++) {
            rk = _mm512_broadcast_i32x4(ks.round_keys[round_idx]);
            
            if (round_idx == rounds) {
                // Final round (no MixColumns)
                state.state = _mm512_aesenclast_epi128(state.state, _mm512_setzero_si512());
                state.state = _mm512_xor_si512(state.state, rk);
            } else {
                // Regular round
                state.state = _mm512_aesenc_epi128(state.state, _mm512_setzero_si512());
                state.state = _mm512_xor_si512(state.state, rk);
            }
            round_idx++;
        }
        
        // Apply mixing layer (except after last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            vistrutah_512_mix_intel(&state);
        }
    }
    
    // Handle odd number of rounds
    if (rounds % ROUNDS_PER_STEP == 1) {
        rk = _mm512_broadcast_i32x4(ks.round_keys[rounds]);
        state.state = _mm512_aesenclast_epi128(state.state, _mm512_setzero_si512());
        state.state = _mm512_xor_si512(state.state, rk);
    }
    
    _mm512_storeu_si512((__m512i*)ciphertext, state.state);
    
#else
    // Standard AES-NI: Process 4 blocks separately
    __m128i s0 = _mm_loadu_si128((const __m128i*)plaintext);
    __m128i s1 = _mm_loadu_si128((const __m128i*)(plaintext + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*)(plaintext + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*)(plaintext + 48));
    
    // Initial key addition
    s0 = _mm_xor_si128(s0, ks.round_keys[0]);
    s1 = _mm_xor_si128(s1, ks.round_keys[0]);
    s2 = _mm_xor_si128(s2, ks.round_keys[0]);
    s3 = _mm_xor_si128(s3, ks.round_keys[0]);
    
    // Store state for mixing layer
    state.slice[0] = s0;
    state.slice[1] = s1;
    state.slice[2] = s2;
    state.slice[3] = s3;
    
    // Main rounds
    int round_idx = 1;
    for (int step = 0; step < rounds / ROUNDS_PER_STEP; step++) {
        // Two AES rounds per step
        for (int r = 0; r < ROUNDS_PER_STEP; r++) {
            if (round_idx == rounds) {
                // Final round (no MixColumns)
                state.slice[0] = _mm_aesenclast_si128(state.slice[0], _mm_setzero_si128());
                state.slice[1] = _mm_aesenclast_si128(state.slice[1], _mm_setzero_si128());
                state.slice[2] = _mm_aesenclast_si128(state.slice[2], _mm_setzero_si128());
                state.slice[3] = _mm_aesenclast_si128(state.slice[3], _mm_setzero_si128());
                state.slice[0] = _mm_xor_si128(state.slice[0], ks.round_keys[round_idx]);
                state.slice[1] = _mm_xor_si128(state.slice[1], ks.round_keys[round_idx]);
                state.slice[2] = _mm_xor_si128(state.slice[2], ks.round_keys[round_idx]);
                state.slice[3] = _mm_xor_si128(state.slice[3], ks.round_keys[round_idx]);
            } else {
                // Regular round
                state.slice[0] = _mm_aesenc_si128(state.slice[0], _mm_setzero_si128());
                state.slice[1] = _mm_aesenc_si128(state.slice[1], _mm_setzero_si128());
                state.slice[2] = _mm_aesenc_si128(state.slice[2], _mm_setzero_si128());
                state.slice[3] = _mm_aesenc_si128(state.slice[3], _mm_setzero_si128());
                state.slice[0] = _mm_xor_si128(state.slice[0], ks.round_keys[round_idx]);
                state.slice[1] = _mm_xor_si128(state.slice[1], ks.round_keys[round_idx]);
                state.slice[2] = _mm_xor_si128(state.slice[2], ks.round_keys[round_idx]);
                state.slice[3] = _mm_xor_si128(state.slice[3], ks.round_keys[round_idx]);
            }
            round_idx++;
        }
        
        // Apply mixing layer (except after last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            vistrutah_512_mix_intel(&state);
        }
    }
    
    // Handle odd number of rounds
    if (rounds % ROUNDS_PER_STEP == 1) {
        state.slice[0] = _mm_aesenclast_si128(state.slice[0], _mm_setzero_si128());
        state.slice[1] = _mm_aesenclast_si128(state.slice[1], _mm_setzero_si128());
        state.slice[2] = _mm_aesenclast_si128(state.slice[2], _mm_setzero_si128());
        state.slice[3] = _mm_aesenclast_si128(state.slice[3], _mm_setzero_si128());
        state.slice[0] = _mm_xor_si128(state.slice[0], ks.round_keys[rounds]);
        state.slice[1] = _mm_xor_si128(state.slice[1], ks.round_keys[rounds]);
        state.slice[2] = _mm_xor_si128(state.slice[2], ks.round_keys[rounds]);
        state.slice[3] = _mm_xor_si128(state.slice[3], ks.round_keys[rounds]);
    }
    
    _mm_storeu_si128((__m128i*)ciphertext, state.slice[0]);
    _mm_storeu_si128((__m128i*)(ciphertext + 16), state.slice[1]);
    _mm_storeu_si128((__m128i*)(ciphertext + 32), state.slice[2]);
    _mm_storeu_si128((__m128i*)(ciphertext + 48), state.slice[3]);
#endif
}

// Vistrutah-512 decryption
void vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_512_state_t state;
    vistrutah_key_schedule_t ks;
    
    // Key expansion
    vistrutah_512_key_expansion_intel(key, key_size, &ks, rounds);
    
    // Load ciphertext
    __m128i s0 = _mm_loadu_si128((const __m128i*)ciphertext);
    __m128i s1 = _mm_loadu_si128((const __m128i*)(ciphertext + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*)(ciphertext + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*)(ciphertext + 48));
    
    // Process rounds in reverse - match simple ARM implementation
    for (int round = rounds; round >= 1; round--) {
        // Remove round key
        s0 = _mm_xor_si128(s0, ks.round_keys[round]);
        s1 = _mm_xor_si128(s1, ks.round_keys[round]);
        s2 = _mm_xor_si128(s2, ks.round_keys[round]);
        s3 = _mm_xor_si128(s3, ks.round_keys[round]);
        
        if (round == rounds) {
            // Inverse final round
            s0 = _mm_aesdeclast_si128(s0, _mm_setzero_si128());
            s1 = _mm_aesdeclast_si128(s1, _mm_setzero_si128());
            s2 = _mm_aesdeclast_si128(s2, _mm_setzero_si128());
            s3 = _mm_aesdeclast_si128(s3, _mm_setzero_si128());
        } else {
            // Regular inverse round
            s0 = _mm_aesimc_si128(s0);
            s1 = _mm_aesimc_si128(s1);
            s2 = _mm_aesimc_si128(s2);
            s3 = _mm_aesimc_si128(s3);
            s0 = _mm_aesdeclast_si128(s0, _mm_setzero_si128());
            s1 = _mm_aesdeclast_si128(s1, _mm_setzero_si128());
            s2 = _mm_aesdeclast_si128(s2, _mm_setzero_si128());
            s3 = _mm_aesdeclast_si128(s3, _mm_setzero_si128());
        }
    }
    
    // Final key addition
    s0 = _mm_xor_si128(s0, ks.round_keys[0]);
    s1 = _mm_xor_si128(s1, ks.round_keys[0]);
    s2 = _mm_xor_si128(s2, ks.round_keys[0]);
    s3 = _mm_xor_si128(s3, ks.round_keys[0]);
    
    _mm_storeu_si128((__m128i*)plaintext, s0);
    _mm_storeu_si128((__m128i*)(plaintext + 16), s1);
    _mm_storeu_si128((__m128i*)(plaintext + 32), s2);
    _mm_storeu_si128((__m128i*)(plaintext + 48), s3);
}

#endif // VISTRUTAH_INTEL