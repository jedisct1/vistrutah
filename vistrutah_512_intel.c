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

// Inverse mixing is the same as forward mixing (transpose is self-inverse)
static void vistrutah_512_inv_mix_intel(vistrutah_512_state_t* state) {
    vistrutah_512_mix_intel(state);
}

// Key expansion for Vistrutah-512
static void vistrutah_512_key_expansion_intel(const uint8_t* key, int key_size,
                                              vistrutah_key_schedule_t* ks, int rounds) {
    __m128i k0, k1;
    
    if (key_size == 32) {
        k0 = _mm_loadu_si128((const __m128i*)key);
        k1 = _mm_loadu_si128((const __m128i*)(key + 16));
    } else {
        k0 = _mm_loadu_si128((const __m128i*)key);
        k1 = _mm_loadu_si128((const __m128i*)(key + 16));
    }
    
    // Generate round keys using alternating fixed and variable keys
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            // Fixed round key with round constant
            ks->round_keys[i] = _mm_set1_epi8(ROUND_CONSTANTS[i]);
        } else {
            // Variable round key (cyclic permutation of master key)
            int key_idx = (i / 2) % 4;
            switch (key_idx) {
                case 0: ks->round_keys[i] = k0; break;
                case 1: ks->round_keys[i] = k1; break;
                case 2: ks->round_keys[i] = k0; break;  // For 256-bit key, k2 = k0
                case 3: ks->round_keys[i] = k1; break;  // For 256-bit key, k3 = k1
            }
        }
    }
}

// Vistrutah-512 encryption
void vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_512_state_t state;
    vistrutah_key_schedule_t ks = {0};
    
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
                state.state = _mm512_aesenclast_epi128(state.state, rk);
            } else {
                // Regular round
                state.state = _mm512_aesenc_epi128(state.state, rk);
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
        state.state = _mm512_aesenclast_epi128(state.state, rk);
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
    
    // Store state for mixing layer - need to use the raw state storage
    _mm_storeu_si128((__m128i*)((uint8_t*)&state), s0);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 16), s1);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 32), s2);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 48), s3);
    
    // Main rounds
    int round_idx = 1;
    for (int step = 0; step < rounds / ROUNDS_PER_STEP; step++) {
        // Two AES rounds per step
        for (int r = 0; r < ROUNDS_PER_STEP; r++) {
            // Load current state
            s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state));
            s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 16));
            s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 32));
            s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 48));
            
            if (round_idx == rounds) {
                // Final round (no MixColumns)
                s0 = _mm_aesenclast_si128(s0, ks.round_keys[round_idx]);
                s1 = _mm_aesenclast_si128(s1, ks.round_keys[round_idx]);
                s2 = _mm_aesenclast_si128(s2, ks.round_keys[round_idx]);
                s3 = _mm_aesenclast_si128(s3, ks.round_keys[round_idx]);
            } else {
                // Regular round
                s0 = _mm_aesenc_si128(s0, ks.round_keys[round_idx]);
                s1 = _mm_aesenc_si128(s1, ks.round_keys[round_idx]);
                s2 = _mm_aesenc_si128(s2, ks.round_keys[round_idx]);
                s3 = _mm_aesenc_si128(s3, ks.round_keys[round_idx]);
            }
            
            // Store state back
            _mm_storeu_si128((__m128i*)((uint8_t*)&state), s0);
            _mm_storeu_si128((__m128i*)((uint8_t*)&state + 16), s1);
            _mm_storeu_si128((__m128i*)((uint8_t*)&state + 32), s2);
            _mm_storeu_si128((__m128i*)((uint8_t*)&state + 48), s3);
            round_idx++;
        }
        
        // Apply mixing layer (except after last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            vistrutah_512_mix_intel(&state);
        }
    }
    
    // Handle odd number of rounds
    if (rounds % ROUNDS_PER_STEP == 1) {
        // Load current state
        s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state));
        s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 16));
        s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 32));
        s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 48));
        
        s0 = _mm_aesenclast_si128(s0, ks.round_keys[rounds]);
        s1 = _mm_aesenclast_si128(s1, ks.round_keys[rounds]);
        s2 = _mm_aesenclast_si128(s2, ks.round_keys[rounds]);
        s3 = _mm_aesenclast_si128(s3, ks.round_keys[rounds]);
    } else {
        // Load final state
        s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state));
        s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 16));
        s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 32));
        s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 48));
    }
    
    _mm_storeu_si128((__m128i*)ciphertext, s0);
    _mm_storeu_si128((__m128i*)(ciphertext + 16), s1);
    _mm_storeu_si128((__m128i*)(ciphertext + 32), s2);
    _mm_storeu_si128((__m128i*)(ciphertext + 48), s3);
#endif
}

// Vistrutah-512 decryption
void vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                          const uint8_t* key, int key_size, int rounds) {
    vistrutah_512_state_t state;
    vistrutah_key_schedule_t ks = {0};
    
    // Key expansion
    vistrutah_512_key_expansion_intel(key, key_size, &ks, rounds);
    
#ifdef VISTRUTAH_VAES
    // AVX512+VAES: Process all 4 blocks in parallel
    state.state = _mm512_loadu_si512((const __m512i*)ciphertext);
    
    // Handle odd rounds at the end if necessary
    int round_idx = rounds;
    if (rounds % ROUNDS_PER_STEP == 1) {
        __m512i rk = _mm512_broadcast_i32x4(ks.round_keys[round_idx]);
        state.state = _mm512_aesdeclast_epi128(state.state, rk);
        round_idx--;
    }
    
    // Main rounds (in reverse), processing in steps of 2 rounds
    for (int step = (rounds / ROUNDS_PER_STEP) - 1; step >= 0; step--) {
        // Apply inverse mixing layer BEFORE processing rounds (except for last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            vistrutah_512_inv_mix_intel(&state);
        }
        
        // Two AES rounds per step (in reverse)
        for (int r = ROUNDS_PER_STEP - 1; r >= 0; r--) {
            round_idx = step * ROUNDS_PER_STEP + r + 1;
            
            // Skip if we've gone past the total rounds
            if (round_idx > rounds) continue;
            
            bool is_last_round = (round_idx == rounds) && (rounds % ROUNDS_PER_STEP == 0);
            
            __m512i rk = _mm512_broadcast_i32x4(ks.round_keys[round_idx]);
            
            // Remove round key first
            state.state = _mm512_xor_si512(state.state, rk);
            
            if (is_last_round) {
                // Inverse of final round
                state.state = _mm512_aesdeclast_epi128(state.state, _mm512_setzero_si512());
            } else {
                // Regular inverse round
                __m128i t0 = _mm512_extracti32x4_epi32(state.state, 0);
                __m128i t1 = _mm512_extracti32x4_epi32(state.state, 1);
                __m128i t2 = _mm512_extracti32x4_epi32(state.state, 2);
                __m128i t3 = _mm512_extracti32x4_epi32(state.state, 3);
                t0 = _mm_aesimc_si128(t0);
                t1 = _mm_aesimc_si128(t1);
                t2 = _mm_aesimc_si128(t2);
                t3 = _mm_aesimc_si128(t3);
                state.state = _mm512_inserti32x4(state.state, t0, 0);
                state.state = _mm512_inserti32x4(state.state, t1, 1);
                state.state = _mm512_inserti32x4(state.state, t2, 2);
                state.state = _mm512_inserti32x4(state.state, t3, 3);
                state.state = _mm512_aesdeclast_epi128(state.state, _mm512_setzero_si512());
            }
        }
    }
    
    // Final key addition (round 0)
    __m512i rk = _mm512_broadcast_i32x4(ks.round_keys[0]);
    state.state = _mm512_xor_si512(state.state, rk);
    
    _mm512_storeu_si512((__m512i*)plaintext, state.state);
    
#else
    // Standard AES-NI: Process 4 blocks separately
    __m128i s0 = _mm_loadu_si128((const __m128i*)ciphertext);
    __m128i s1 = _mm_loadu_si128((const __m128i*)(ciphertext + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*)(ciphertext + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*)(ciphertext + 48));
    
    // Handle odd rounds at the end if necessary
    int round_idx = rounds;
    if (rounds % ROUNDS_PER_STEP == 1) {
        s0 = _mm_aesdeclast_si128(s0, ks.round_keys[round_idx]);
        s1 = _mm_aesdeclast_si128(s1, ks.round_keys[round_idx]);
        s2 = _mm_aesdeclast_si128(s2, ks.round_keys[round_idx]);
        s3 = _mm_aesdeclast_si128(s3, ks.round_keys[round_idx]);
        round_idx--;
    }
    
    // Main rounds (in reverse), processing in steps of 2 rounds
    for (int step = (rounds / ROUNDS_PER_STEP) - 1; step >= 0; step--) {
        // Apply inverse mixing layer BEFORE processing rounds (except for last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            // Store current state for mixing
            _mm_storeu_si128((__m128i*)((uint8_t*)&state), s0);
            _mm_storeu_si128((__m128i*)((uint8_t*)&state + 16), s1);
            _mm_storeu_si128((__m128i*)((uint8_t*)&state + 32), s2);
            _mm_storeu_si128((__m128i*)((uint8_t*)&state + 48), s3);
            
            vistrutah_512_inv_mix_intel(&state);
            
            // Load mixed state
            s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state));
            s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 16));
            s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 32));
            s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 48));
        }
        
        // Two AES rounds per step (in reverse order)
        for (int r = ROUNDS_PER_STEP - 1; r >= 0; r--) {
            round_idx = step * ROUNDS_PER_STEP + r + 1;
            
            // Skip if we've gone past the total rounds
            if (round_idx > rounds) break;
            
            bool is_last_round = (round_idx == rounds) && (rounds % ROUNDS_PER_STEP == 0);
            
            // Remove round key first
            s0 = _mm_xor_si128(s0, ks.round_keys[round_idx]);
            s1 = _mm_xor_si128(s1, ks.round_keys[round_idx]);
            s2 = _mm_xor_si128(s2, ks.round_keys[round_idx]);
            s3 = _mm_xor_si128(s3, ks.round_keys[round_idx]);
            
            if (is_last_round) {
                // Inverse of final round
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
    }
    
    // Final key addition (round 0)
    s0 = _mm_xor_si128(s0, ks.round_keys[0]);
    s1 = _mm_xor_si128(s1, ks.round_keys[0]);
    s2 = _mm_xor_si128(s2, ks.round_keys[0]);
    s3 = _mm_xor_si128(s3, ks.round_keys[0]);
    
    // Store plaintext
    _mm_storeu_si128((__m128i*)plaintext, s0);
    _mm_storeu_si128((__m128i*)(plaintext + 16), s1);
    _mm_storeu_si128((__m128i*)(plaintext + 32), s2);
    _mm_storeu_si128((__m128i*)(plaintext + 48), s3);
#endif
}

#endif // VISTRUTAH_INTEL