#include "vistrutah.h"

#ifdef VISTRUTAH_INTEL

#    include <immintrin.h>
#    include <string.h>

extern const uint8_t ROUND_CONSTANTS[16 * 48];
extern const uint8_t VISTRUTAH_KEXP_SHUFFLE[32];
extern const uint8_t VISTRUTAH_ZERO[16];

#ifdef VISTRUTAH_VAES

// AVX-512 + VAES optimized version - process all 4 slices in parallel

static inline __m512i
aes_round_512(__m512i state, __m512i round_key)
{
    return _mm512_aesenc_epi128(state, round_key);
}

static inline __m512i
aes_final_round_512(__m512i state, __m512i round_key)
{
    return _mm512_aesenclast_epi128(state, round_key);
}

static inline __m512i
aes_inv_round_512(__m512i state, __m512i round_key)
{
    return _mm512_aesdec_epi128(state, round_key);
}

static inline __m512i
aes_inv_final_round_512(__m512i state, __m512i round_key)
{
    return _mm512_aesdeclast_epi128(state, round_key);
}

static inline __m512i
mixing_layer_512(__m512i state)
{
    const __m512i mask0 = _mm512_set_epi8(
        60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0,
        60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0,
        60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0,
        60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0
    );
    const __m512i mask1 = _mm512_set_epi8(
        61, 57, 53, 49, 45, 41, 37, 33, 29, 25, 21, 17, 13, 9, 5, 1,
        61, 57, 53, 49, 45, 41, 37, 33, 29, 25, 21, 17, 13, 9, 5, 1,
        61, 57, 53, 49, 45, 41, 37, 33, 29, 25, 21, 17, 13, 9, 5, 1,
        61, 57, 53, 49, 45, 41, 37, 33, 29, 25, 21, 17, 13, 9, 5, 1
    );
    const __m512i mask2 = _mm512_set_epi8(
        62, 58, 54, 50, 46, 42, 38, 34, 30, 26, 22, 18, 14, 10, 6, 2,
        62, 58, 54, 50, 46, 42, 38, 34, 30, 26, 22, 18, 14, 10, 6, 2,
        62, 58, 54, 50, 46, 42, 38, 34, 30, 26, 22, 18, 14, 10, 6, 2,
        62, 58, 54, 50, 46, 42, 38, 34, 30, 26, 22, 18, 14, 10, 6, 2
    );
    const __m512i mask3 = _mm512_set_epi8(
        63, 59, 55, 51, 47, 43, 39, 35, 31, 27, 23, 19, 15, 11, 7, 3,
        63, 59, 55, 51, 47, 43, 39, 35, 31, 27, 23, 19, 15, 11, 7, 3,
        63, 59, 55, 51, 47, 43, 39, 35, 31, 27, 23, 19, 15, 11, 7, 3,
        63, 59, 55, 51, 47, 43, 39, 35, 31, 27, 23, 19, 15, 11, 7, 3
    );

    __m512i p0 = _mm512_shuffle_epi8(state, mask0);
    __m512i p1 = _mm512_shuffle_epi8(state, mask1);
    __m512i p2 = _mm512_shuffle_epi8(state, mask2);
    __m512i p3 = _mm512_shuffle_epi8(state, mask3);

    __m128i p0_0 = _mm512_extracti32x4_epi32(p0, 0);
    __m128i p0_1 = _mm512_extracti32x4_epi32(p0, 1);
    __m128i p0_2 = _mm512_extracti32x4_epi32(p0, 2);
    __m128i p0_3 = _mm512_extracti32x4_epi32(p0, 3);

    __m128i p1_0 = _mm512_extracti32x4_epi32(p1, 0);
    __m128i p1_1 = _mm512_extracti32x4_epi32(p1, 1);
    __m128i p1_2 = _mm512_extracti32x4_epi32(p1, 2);
    __m128i p1_3 = _mm512_extracti32x4_epi32(p1, 3);

    __m128i p2_0 = _mm512_extracti32x4_epi32(p2, 0);
    __m128i p2_1 = _mm512_extracti32x4_epi32(p2, 1);
    __m128i p2_2 = _mm512_extracti32x4_epi32(p2, 2);
    __m128i p2_3 = _mm512_extracti32x4_epi32(p2, 3);

    __m128i p3_0 = _mm512_extracti32x4_epi32(p3, 0);
    __m128i p3_1 = _mm512_extracti32x4_epi32(p3, 1);
    __m128i p3_2 = _mm512_extracti32x4_epi32(p3, 2);
    __m128i p3_3 = _mm512_extracti32x4_epi32(p3, 3);

    __m128i r0_01 = _mm_unpacklo_epi32(p0_0, p0_1);
    __m128i r0_23 = _mm_unpacklo_epi32(p0_2, p0_3);
    __m128i r1_01 = _mm_unpacklo_epi32(p1_0, p1_1);
    __m128i r1_23 = _mm_unpacklo_epi32(p1_2, p1_3);
    __m128i r2_01 = _mm_unpacklo_epi32(p2_0, p2_1);
    __m128i r2_23 = _mm_unpacklo_epi32(p2_2, p2_3);
    __m128i r3_01 = _mm_unpacklo_epi32(p3_0, p3_1);
    __m128i r3_23 = _mm_unpacklo_epi32(p3_2, p3_3);

    __m128i r0 = _mm_unpacklo_epi64(r0_01, r0_23);
    __m128i r1 = _mm_unpacklo_epi64(r1_01, r1_23);
    __m128i r2 = _mm_unpacklo_epi64(r2_01, r2_23);
    __m128i r3 = _mm_unpacklo_epi64(r3_01, r3_23);

    return _mm512_inserti32x4(_mm512_inserti32x4(_mm512_inserti32x4(
        _mm512_castsi128_si512(r0), r1, 1), r2, 2), r3, 3);
}

static inline __m512i
inv_mixing_layer_512(__m512i state)
{
    __m128i s0 = _mm512_extracti32x4_epi32(state, 0);
    __m128i s1 = _mm512_extracti32x4_epi32(state, 1);
    __m128i s2 = _mm512_extracti32x4_epi32(state, 2);
    __m128i s3 = _mm512_extracti32x4_epi32(state, 3);

    __m128i step1_0 = _mm_unpacklo_epi8(s0, s1);
    __m128i step1_1 = _mm_unpackhi_epi8(s0, s1);
    __m128i step1_2 = _mm_unpacklo_epi8(s2, s3);
    __m128i step1_3 = _mm_unpackhi_epi8(s2, s3);

    __m128i step2_0 = _mm_unpacklo_epi16(step1_0, step1_2);
    __m128i step2_1 = _mm_unpackhi_epi16(step1_0, step1_2);
    __m128i step2_2 = _mm_unpacklo_epi16(step1_1, step1_3);
    __m128i step2_3 = _mm_unpackhi_epi16(step1_1, step1_3);

    return _mm512_inserti32x4(_mm512_inserti32x4(_mm512_inserti32x4(
        _mm512_castsi128_si512(step2_0), step2_1, 1), step2_2, 2), step2_3, 3);
}

// Rotate bytes within a 128-bit lane using shuffle
static inline __m128i
rotate_bytes_128(__m128i data, int shift)
{
    // Create shuffle control mask for rotation
    uint8_t mask[16];
    for (int i = 0; i < 16; i++) {
        mask[i] = (i + shift) % 16;
    }
    __m128i shuffle_mask = _mm_loadu_si128((const __m128i*)mask);
    return _mm_shuffle_epi8(data, shuffle_mask);
}

#endif // VISTRUTAH_VAES

// SSE/AES-NI functions - always available for fallback and mixed use
static inline __m128i
aes_round(__m128i state, __m128i round_key)
{
    return _mm_aesenc_si128(state, round_key);
}

static inline __m128i
aes_final_round(__m128i state, __m128i round_key)
{
    return _mm_aesenclast_si128(state, round_key);
}

static inline __m128i
aes_inv_round(__m128i state, __m128i round_key)
{
    return _mm_aesdec_si128(state, round_key);
}

static inline __m128i
aes_inv_final_round(__m128i state, __m128i round_key)
{
    return _mm_aesdeclast_si128(state, round_key);
}

#ifndef VISTRUTAH_VAES
static void
mixing_layer_512_sse(__m128i* s0, __m128i* s1, __m128i* s2, __m128i* s3)
{
    __m128i t0 = *s0, t1 = *s1, t2 = *s2, t3 = *s3;

    const __m128i mask0 = _mm_set_epi8(12, 8, 4, 0, 12, 8, 4, 0, 12, 8, 4, 0, 12, 8, 4, 0);
    const __m128i mask1 = _mm_set_epi8(13, 9, 5, 1, 13, 9, 5, 1, 13, 9, 5, 1, 13, 9, 5, 1);
    const __m128i mask2 = _mm_set_epi8(14, 10, 6, 2, 14, 10, 6, 2, 14, 10, 6, 2, 14, 10, 6, 2);
    const __m128i mask3 = _mm_set_epi8(15, 11, 7, 3, 15, 11, 7, 3, 15, 11, 7, 3, 15, 11, 7, 3);

    __m128i s0_0 = _mm_shuffle_epi8(t0, mask0);
    __m128i s1_0 = _mm_shuffle_epi8(t1, mask0);
    __m128i s2_0 = _mm_shuffle_epi8(t2, mask0);
    __m128i s3_0 = _mm_shuffle_epi8(t3, mask0);

    __m128i s0_1 = _mm_shuffle_epi8(t0, mask1);
    __m128i s1_1 = _mm_shuffle_epi8(t1, mask1);
    __m128i s2_1 = _mm_shuffle_epi8(t2, mask1);
    __m128i s3_1 = _mm_shuffle_epi8(t3, mask1);

    __m128i s0_2 = _mm_shuffle_epi8(t0, mask2);
    __m128i s1_2 = _mm_shuffle_epi8(t1, mask2);
    __m128i s2_2 = _mm_shuffle_epi8(t2, mask2);
    __m128i s3_2 = _mm_shuffle_epi8(t3, mask2);

    __m128i s0_3 = _mm_shuffle_epi8(t0, mask3);
    __m128i s1_3 = _mm_shuffle_epi8(t1, mask3);
    __m128i s2_3 = _mm_shuffle_epi8(t2, mask3);
    __m128i s3_3 = _mm_shuffle_epi8(t3, mask3);

    __m128i r0_lo = _mm_unpacklo_epi32(s0_0, s1_0);
    __m128i r0_hi = _mm_unpacklo_epi32(s2_0, s3_0);
    __m128i r1_lo = _mm_unpacklo_epi32(s0_1, s1_1);
    __m128i r1_hi = _mm_unpacklo_epi32(s2_1, s3_1);
    __m128i r2_lo = _mm_unpacklo_epi32(s0_2, s1_2);
    __m128i r2_hi = _mm_unpacklo_epi32(s2_2, s3_2);
    __m128i r3_lo = _mm_unpacklo_epi32(s0_3, s1_3);
    __m128i r3_hi = _mm_unpacklo_epi32(s2_3, s3_3);

    *s0 = _mm_unpacklo_epi64(r0_lo, r0_hi);
    *s1 = _mm_unpacklo_epi64(r1_lo, r1_hi);
    *s2 = _mm_unpacklo_epi64(r2_lo, r2_hi);
    *s3 = _mm_unpacklo_epi64(r3_lo, r3_hi);
}

static void
inv_mixing_layer_512_sse(__m128i* s0, __m128i* s1, __m128i* s2, __m128i* s3)
{
    __m128i t0 = *s0, t1 = *s1, t2 = *s2, t3 = *s3;

    __m128i step1_0 = _mm_unpacklo_epi8(t0, t1);
    __m128i step1_1 = _mm_unpackhi_epi8(t0, t1);
    __m128i step1_2 = _mm_unpacklo_epi8(t2, t3);
    __m128i step1_3 = _mm_unpackhi_epi8(t2, t3);

    __m128i step2_0 = _mm_unpacklo_epi16(step1_0, step1_2);
    __m128i step2_1 = _mm_unpackhi_epi16(step1_0, step1_2);
    __m128i step2_2 = _mm_unpacklo_epi16(step1_1, step1_3);
    __m128i step2_3 = _mm_unpackhi_epi16(step1_1, step1_3);

    *s0 = step2_0;
    *s1 = step2_1;
    *s2 = step2_2;
    *s3 = step2_3;
}

static void
rotate_bytes(uint8_t* data, int shift, int len)
{
    uint8_t temp[16];
    for (int i = 0; i < len; i++) {
        temp[i] = data[(i + shift) % len];
    }
    memcpy(data, temp, len);
}
#endif

void
vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
#ifdef VISTRUTAH_VAES
    // AVX-512 + VAES optimized version
    uint8_t fixed_key[64] __attribute__((aligned(64)));
    uint8_t round_key[64] __attribute__((aligned(64)));
    int     steps = rounds / ROUNDS_PER_STEP;

    // Load plaintext into a single 512-bit register (4 x 128-bit slices)
    __m512i state = _mm512_loadu_si512((const __m512i*) plaintext);

    // Setup fixed key
    if (key_size == 32) {
        memcpy(fixed_key, key, 32);
        memcpy(fixed_key + 32, key, 32);
    } else {
        memcpy(fixed_key, key, 64);
    }

    if (key_size == 64) {
        uint8_t temp[32];
        memcpy(temp, fixed_key + 32, 32);
        for (int i = 0; i < 32; i++) {
            fixed_key[32 + i] = temp[VISTRUTAH_KEXP_SHUFFLE[i]];
        }
    }

    // Setup initial round key
    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);
    memcpy(round_key + 32, fixed_key + 48, 16);
    memcpy(round_key + 48, fixed_key + 32, 16);

    __m512i fk   = _mm512_loadu_si512((const __m512i*) fixed_key);
    __m512i rk   = _mm512_loadu_si512((const __m512i*) round_key);
    __m512i zero = _mm512_setzero_si512();

    // Initial round: XOR with round key, then AES round with fixed key
    state = _mm512_xor_si512(state, rk);
    state = aes_round_512(state, fk);

    // Main rounds
    for (int i = 1; i < steps; i++) {
        // AES round with zero key
        state = aes_round_512(state, zero);

        // Mixing layer (transpose)
        state = mixing_layer_512(state);

        // Update round keys using rotation
        __m128i rk0 = _mm_loadu_si128((const __m128i*) round_key);
        __m128i rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));
        __m128i rk2 = _mm_loadu_si128((const __m128i*) (round_key + 32));
        __m128i rk3 = _mm_loadu_si128((const __m128i*) (round_key + 48));

        rk0 = rotate_bytes_128(rk0, 5);
        rk1 = rotate_bytes_128(rk1, 10);
        rk2 = rotate_bytes_128(rk2, 5);
        rk3 = rotate_bytes_128(rk3, 10);

        _mm_storeu_si128((__m128i*) round_key, rk0);
        _mm_storeu_si128((__m128i*) (round_key + 16), rk1);
        _mm_storeu_si128((__m128i*) (round_key + 32), rk2);
        _mm_storeu_si128((__m128i*) (round_key + 48), rk3);

        rk = _mm512_loadu_si512((const __m512i*) round_key);

        // XOR round key
        state = _mm512_xor_si512(state, rk);

        // XOR round constant to first slice only
        __m128i rc  = _mm_loadu_si128((const __m128i*) &ROUND_CONSTANTS[16 * (i - 1)]);
        __m512i rc_512 = _mm512_castsi128_si512(rc);
        state = _mm512_xor_si512(state, rc_512);

        // AES round with fixed key
        state = aes_round_512(state, fk);
    }

    // Final round
    __m128i rk0 = _mm_loadu_si128((const __m128i*) round_key);
    __m128i rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));
    __m128i rk2 = _mm_loadu_si128((const __m128i*) (round_key + 32));
    __m128i rk3 = _mm_loadu_si128((const __m128i*) (round_key + 48));

    rk0 = rotate_bytes_128(rk0, 5);
    rk1 = rotate_bytes_128(rk1, 10);
    rk2 = rotate_bytes_128(rk2, 5);
    rk3 = rotate_bytes_128(rk3, 10);

    _mm_storeu_si128((__m128i*) round_key, rk0);
    _mm_storeu_si128((__m128i*) (round_key + 16), rk1);
    _mm_storeu_si128((__m128i*) (round_key + 32), rk2);
    _mm_storeu_si128((__m128i*) (round_key + 48), rk3);

    rk = _mm512_loadu_si512((const __m512i*) round_key);

    state = aes_final_round_512(state, rk);

    // Store ciphertext
    _mm512_storeu_si512((__m512i*) ciphertext, state);

#else
    // SSE/AES-NI fallback version
    uint8_t fixed_key[64];
    uint8_t round_key[64];
    int     steps = rounds / ROUNDS_PER_STEP;

    __m128i s0 = _mm_loadu_si128((const __m128i*) plaintext);
    __m128i s1 = _mm_loadu_si128((const __m128i*) (plaintext + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*) (plaintext + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*) (plaintext + 48));

    if (key_size == 32) {
        memcpy(fixed_key, key, 32);
        memcpy(fixed_key + 32, key, 32);
    } else {
        memcpy(fixed_key, key, 64);
    }

    if (key_size == 64) {
        uint8_t temp[32];
        memcpy(temp, fixed_key + 32, 32);
        for (int i = 0; i < 32; i++) {
            fixed_key[32 + i] = temp[VISTRUTAH_KEXP_SHUFFLE[i]];
        }
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);
    memcpy(round_key + 32, fixed_key + 48, 16);
    memcpy(round_key + 48, fixed_key + 32, 16);

    __m128i fk0  = _mm_loadu_si128((const __m128i*) fixed_key);
    __m128i fk1  = _mm_loadu_si128((const __m128i*) (fixed_key + 16));
    __m128i fk2  = _mm_loadu_si128((const __m128i*) (fixed_key + 32));
    __m128i fk3  = _mm_loadu_si128((const __m128i*) (fixed_key + 48));
    __m128i zero = _mm_setzero_si128();

    __m128i rk0 = _mm_loadu_si128((const __m128i*) round_key);
    __m128i rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));
    __m128i rk2 = _mm_loadu_si128((const __m128i*) (round_key + 32));
    __m128i rk3 = _mm_loadu_si128((const __m128i*) (round_key + 48));

    s0 = _mm_xor_si128(s0, rk0);
    s1 = _mm_xor_si128(s1, rk1);
    s2 = _mm_xor_si128(s2, rk2);
    s3 = _mm_xor_si128(s3, rk3);

    s0 = aes_round(s0, fk0);
    s1 = aes_round(s1, fk1);
    s2 = aes_round(s2, fk2);
    s3 = aes_round(s3, fk3);

    for (int i = 1; i < steps; i++) {
        s0 = aes_round(s0, zero);
        s1 = aes_round(s1, zero);
        s2 = aes_round(s2, zero);
        s3 = aes_round(s3, zero);

        mixing_layer_512_sse(&s0, &s1, &s2, &s3);

        rotate_bytes(round_key, 5, 16);
        rotate_bytes(round_key + 16, 10, 16);
        rotate_bytes(round_key + 32, 5, 16);
        rotate_bytes(round_key + 48, 10, 16);

        rk0 = _mm_loadu_si128((const __m128i*) round_key);
        rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));
        rk2 = _mm_loadu_si128((const __m128i*) (round_key + 32));
        rk3 = _mm_loadu_si128((const __m128i*) (round_key + 48));

        s0 = _mm_xor_si128(s0, rk0);
        s1 = _mm_xor_si128(s1, rk1);
        s2 = _mm_xor_si128(s2, rk2);
        s3 = _mm_xor_si128(s3, rk3);

        __m128i rc = _mm_loadu_si128((const __m128i*) &ROUND_CONSTANTS[16 * (i - 1)]);
        s0         = _mm_xor_si128(s0, rc);

        s0 = aes_round(s0, fk0);
        s1 = aes_round(s1, fk1);
        s2 = aes_round(s2, fk2);
        s3 = aes_round(s3, fk3);
    }

    rotate_bytes(round_key, 5, 16);
    rotate_bytes(round_key + 16, 10, 16);
    rotate_bytes(round_key + 32, 5, 16);
    rotate_bytes(round_key + 48, 10, 16);

    rk0 = _mm_loadu_si128((const __m128i*) round_key);
    rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));
    rk2 = _mm_loadu_si128((const __m128i*) (round_key + 32));
    rk3 = _mm_loadu_si128((const __m128i*) (round_key + 48));

    s0 = aes_final_round(s0, rk0);
    s1 = aes_final_round(s1, rk1);
    s2 = aes_final_round(s2, rk2);
    s3 = aes_final_round(s3, rk3);

    _mm_storeu_si128((__m128i*) ciphertext, s0);
    _mm_storeu_si128((__m128i*) (ciphertext + 16), s1);
    _mm_storeu_si128((__m128i*) (ciphertext + 32), s2);
    _mm_storeu_si128((__m128i*) (ciphertext + 48), s3);
#endif
}

void
vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
#ifdef VISTRUTAH_VAES
    uint8_t fixed_key[64] __attribute__((aligned(64)));
    uint8_t round_key[64] __attribute__((aligned(64)));
    uint8_t round_keys[48][64] __attribute__((aligned(64)));
    int     steps = rounds / ROUNDS_PER_STEP;

    __m512i state = _mm512_loadu_si512((const __m512i*) ciphertext);

    if (key_size == 32) {
        memcpy(fixed_key, key, 32);
        memcpy(fixed_key + 32, key, 32);
    } else {
        memcpy(fixed_key, key, 64);
    }

    if (key_size == 64) {
        uint8_t temp[32];
        memcpy(temp, fixed_key + 32, 32);
        for (int i = 0; i < 32; i++) {
            fixed_key[32 + i] = temp[VISTRUTAH_KEXP_SHUFFLE[i]];
        }
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);
    memcpy(round_key + 32, fixed_key + 48, 16);
    memcpy(round_key + 48, fixed_key + 32, 16);
    memcpy(round_keys[0], round_key, 64);

    for (int i = 1; i <= steps; i++) {
        __m128i rk0 = _mm_loadu_si128((const __m128i*) round_key);
        __m128i rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));
        __m128i rk2 = _mm_loadu_si128((const __m128i*) (round_key + 32));
        __m128i rk3 = _mm_loadu_si128((const __m128i*) (round_key + 48));

        rk0 = rotate_bytes_128(rk0, 5);
        rk1 = rotate_bytes_128(rk1, 10);
        rk2 = rotate_bytes_128(rk2, 5);
        rk3 = rotate_bytes_128(rk3, 10);

        _mm_storeu_si128((__m128i*) round_key, rk0);
        _mm_storeu_si128((__m128i*) (round_key + 16), rk1);
        _mm_storeu_si128((__m128i*) (round_key + 32), rk2);
        _mm_storeu_si128((__m128i*) (round_key + 48), rk3);

        memcpy(round_keys[i], round_key, 64);
    }

    uint8_t fk_imc_temp[64] __attribute__((aligned(64)));
    __m128i fk0_imc = _mm_aesimc_si128(_mm_loadu_si128((const __m128i*) fixed_key));
    __m128i fk1_imc = _mm_aesimc_si128(_mm_loadu_si128((const __m128i*) (fixed_key + 16)));
    __m128i fk2_imc = _mm_aesimc_si128(_mm_loadu_si128((const __m128i*) (fixed_key + 32)));
    __m128i fk3_imc = _mm_aesimc_si128(_mm_loadu_si128((const __m128i*) (fixed_key + 48)));
    _mm_storeu_si128((__m128i*) fk_imc_temp, fk0_imc);
    _mm_storeu_si128((__m128i*) (fk_imc_temp + 16), fk1_imc);
    _mm_storeu_si128((__m128i*) (fk_imc_temp + 32), fk2_imc);
    _mm_storeu_si128((__m128i*) (fk_imc_temp + 48), fk3_imc);
    __m512i fk_imc = _mm512_load_si512((const __m512i*)fk_imc_temp);

    __m512i rk = _mm512_loadu_si512((const __m512i*) round_keys[steps]);

    state = _mm512_xor_si512(state, rk);
    state = aes_inv_round_512(state, fk_imc);

    for (int i = steps - 1; i >= 1; i--) {
        rk = _mm512_loadu_si512((const __m512i*) round_keys[i]);

        state = aes_inv_final_round_512(state, rk);

        __m128i rc  = _mm_loadu_si128((const __m128i*) &ROUND_CONSTANTS[16 * (i - 1)]);
        __m512i rc_512 = _mm512_castsi128_si512(rc);
        state = _mm512_xor_si512(state, rc_512);

        state = inv_mixing_layer_512(state);

        uint8_t temp[64] __attribute__((aligned(64)));
        _mm512_store_si512((__m512i*)temp, state);

        __m128i s0 = _mm_loadu_si128((const __m128i*) temp);
        __m128i s1 = _mm_loadu_si128((const __m128i*) (temp + 16));
        __m128i s2 = _mm_loadu_si128((const __m128i*) (temp + 32));
        __m128i s3 = _mm_loadu_si128((const __m128i*) (temp + 48));

        s0 = _mm_aesimc_si128(s0);
        s1 = _mm_aesimc_si128(s1);
        s2 = _mm_aesimc_si128(s2);
        s3 = _mm_aesimc_si128(s3);

        _mm_storeu_si128((__m128i*) temp, s0);
        _mm_storeu_si128((__m128i*) (temp + 16), s1);
        _mm_storeu_si128((__m128i*) (temp + 32), s2);
        _mm_storeu_si128((__m128i*) (temp + 48), s3);

        state = _mm512_load_si512((const __m512i*)temp);

        state = aes_inv_round_512(state, fk_imc);
    }

    rk = _mm512_loadu_si512((const __m512i*) round_keys[0]);
    state = aes_inv_final_round_512(state, rk);

    _mm512_storeu_si512((__m512i*) plaintext, state);
#else
    uint8_t fixed_key[64];
    uint8_t round_key[64];
    uint8_t round_keys[48][64];
    int     steps = rounds / ROUNDS_PER_STEP;

    __m128i s0 = _mm_loadu_si128((const __m128i*) ciphertext);
    __m128i s1 = _mm_loadu_si128((const __m128i*) (ciphertext + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*) (ciphertext + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*) (ciphertext + 48));

    if (key_size == 32) {
        memcpy(fixed_key, key, 32);
        memcpy(fixed_key + 32, key, 32);
    } else {
        memcpy(fixed_key, key, 64);
    }

    if (key_size == 64) {
        uint8_t temp[32];
        memcpy(temp, fixed_key + 32, 32);
        for (int i = 0; i < 32; i++) {
            fixed_key[32 + i] = temp[VISTRUTAH_KEXP_SHUFFLE[i]];
        }
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);
    memcpy(round_key + 32, fixed_key + 48, 16);
    memcpy(round_key + 48, fixed_key + 32, 16);
    memcpy(round_keys[0], round_key, 64);

    for (int i = 1; i <= steps; i++) {
        rotate_bytes(round_key, 5, 16);
        rotate_bytes(round_key + 16, 10, 16);
        rotate_bytes(round_key + 32, 5, 16);
        rotate_bytes(round_key + 48, 10, 16);
        memcpy(round_keys[i], round_key, 64);
    }

    __m128i fk0 = _mm_loadu_si128((const __m128i*) fixed_key);
    __m128i fk1 = _mm_loadu_si128((const __m128i*) (fixed_key + 16));
    __m128i fk2 = _mm_loadu_si128((const __m128i*) (fixed_key + 32));
    __m128i fk3 = _mm_loadu_si128((const __m128i*) (fixed_key + 48));

    __m128i fk0_imc = _mm_aesimc_si128(fk0);
    __m128i fk1_imc = _mm_aesimc_si128(fk1);
    __m128i fk2_imc = _mm_aesimc_si128(fk2);
    __m128i fk3_imc = _mm_aesimc_si128(fk3);

    __m128i rk0 = _mm_loadu_si128((const __m128i*) round_keys[steps]);
    __m128i rk1 = _mm_loadu_si128((const __m128i*) (round_keys[steps] + 16));
    __m128i rk2 = _mm_loadu_si128((const __m128i*) (round_keys[steps] + 32));
    __m128i rk3 = _mm_loadu_si128((const __m128i*) (round_keys[steps] + 48));

    s0 = _mm_xor_si128(s0, rk0);
    s1 = _mm_xor_si128(s1, rk1);
    s2 = _mm_xor_si128(s2, rk2);
    s3 = _mm_xor_si128(s3, rk3);
    s0 = aes_inv_round(s0, fk0_imc);
    s1 = aes_inv_round(s1, fk1_imc);
    s2 = aes_inv_round(s2, fk2_imc);
    s3 = aes_inv_round(s3, fk3_imc);

    for (int i = steps - 1; i >= 1; i--) {
        rk0 = _mm_loadu_si128((const __m128i*) round_keys[i]);
        rk1 = _mm_loadu_si128((const __m128i*) (round_keys[i] + 16));
        rk2 = _mm_loadu_si128((const __m128i*) (round_keys[i] + 32));
        rk3 = _mm_loadu_si128((const __m128i*) (round_keys[i] + 48));

        s0 = aes_inv_final_round(s0, rk0);
        s1 = aes_inv_final_round(s1, rk1);
        s2 = aes_inv_final_round(s2, rk2);
        s3 = aes_inv_final_round(s3, rk3);

        __m128i rc = _mm_loadu_si128((const __m128i*) &ROUND_CONSTANTS[16 * (i - 1)]);
        s0         = _mm_xor_si128(s0, rc);

        inv_mixing_layer_512_sse(&s0, &s1, &s2, &s3);

        s0 = _mm_aesimc_si128(s0);
        s1 = _mm_aesimc_si128(s1);
        s2 = _mm_aesimc_si128(s2);
        s3 = _mm_aesimc_si128(s3);

        s0 = aes_inv_round(s0, fk0_imc);
        s1 = aes_inv_round(s1, fk1_imc);
        s2 = aes_inv_round(s2, fk2_imc);
        s3 = aes_inv_round(s3, fk3_imc);
    }

    rk0 = _mm_loadu_si128((const __m128i*) round_keys[0]);
    rk1 = _mm_loadu_si128((const __m128i*) (round_keys[0] + 16));
    rk2 = _mm_loadu_si128((const __m128i*) (round_keys[0] + 32));
    rk3 = _mm_loadu_si128((const __m128i*) (round_keys[0] + 48));

    s0 = aes_inv_final_round(s0, rk0);
    s1 = aes_inv_final_round(s1, rk1);
    s2 = aes_inv_final_round(s2, rk2);
    s3 = aes_inv_final_round(s3, rk3);

    _mm_storeu_si128((__m128i*) plaintext, s0);
    _mm_storeu_si128((__m128i*) (plaintext + 16), s1);
    _mm_storeu_si128((__m128i*) (plaintext + 32), s2);
    _mm_storeu_si128((__m128i*) (plaintext + 48), s3);
#endif
}

#endif
