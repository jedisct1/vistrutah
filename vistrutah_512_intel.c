#include "vistrutah.h"

#ifdef VISTRUTAH_INTEL

#    include <immintrin.h>
#    include <string.h>

extern const uint8_t ROUND_CONSTANTS[16 * 48];
extern const uint8_t VISTRUTAH_KEXP_SHUFFLE[32];
extern const uint8_t VISTRUTAH_ZERO[16];

// SSE/AES-NI functions
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

static void
mixing_layer_512_sse(__m128i* s0, __m128i* s1, __m128i* s2, __m128i* s3)
{
    __m128i lo01, hi01, lo23, hi23;

    lo01 = _mm_unpacklo_epi8(*s0, *s1);
    hi01 = _mm_unpackhi_epi8(*s0, *s1);
    lo23 = _mm_unpacklo_epi8(*s2, *s3);
    hi23 = _mm_unpackhi_epi8(*s2, *s3);

    *s0 = _mm_unpacklo_epi16(lo01, lo23);
    *s2 = _mm_unpackhi_epi16(lo01, lo23);
    *s1 = _mm_unpacklo_epi16(hi01, hi23);
    *s3 = _mm_unpackhi_epi16(hi01, hi23);
}

static void
inv_mixing_layer_512_sse(__m128i* s0, __m128i* s1, __m128i* s2, __m128i* s3)
{
    const __m128i extract_mask = _mm_set_epi8(15,11,7,3, 14,10,6,2, 13,9,5,1, 12,8,4,0);

    __m128i e0 = _mm_shuffle_epi8(*s0, extract_mask);
    __m128i e1 = _mm_shuffle_epi8(*s1, extract_mask);
    __m128i e2 = _mm_shuffle_epi8(*s2, extract_mask);
    __m128i e3 = _mm_shuffle_epi8(*s3, extract_mask);

    __m128i t0 = _mm_unpacklo_epi32(e0, e2);
    __m128i t1 = _mm_unpackhi_epi32(e0, e2);
    __m128i t2 = _mm_unpacklo_epi32(e1, e3);
    __m128i t3 = _mm_unpackhi_epi32(e1, e3);

    *s0 = _mm_unpacklo_epi64(t0, t2);
    *s1 = _mm_unpackhi_epi64(t0, t2);
    *s2 = _mm_unpacklo_epi64(t1, t3);
    *s3 = _mm_unpackhi_epi64(t1, t3);
}

// Fast byte rotation using SSSE3 _mm_alignr_epi8
static inline void
rotate_bytes(uint8_t* data, int shift, int len __attribute__((unused)))
{
    __m128i v = _mm_loadu_si128((const __m128i*) data);
    __m128i rotated;

    // _mm_alignr_epi8 concatenates two vectors and extracts from the middle
    // alignr(a, b, n) = (a << 128) | b >> (n*8)
    // For rotation: alignr(v, v, shift) gives us v rotated left by shift bytes
    switch (shift) {
    case 0:
        return;
    case 1:
        rotated = _mm_alignr_epi8(v, v, 1);
        break;
    case 2:
        rotated = _mm_alignr_epi8(v, v, 2);
        break;
    case 3:
        rotated = _mm_alignr_epi8(v, v, 3);
        break;
    case 4:
        rotated = _mm_alignr_epi8(v, v, 4);
        break;
    case 5:
        rotated = _mm_alignr_epi8(v, v, 5);
        break;
    case 6:
        rotated = _mm_alignr_epi8(v, v, 6);
        break;
    case 7:
        rotated = _mm_alignr_epi8(v, v, 7);
        break;
    case 8:
        rotated = _mm_alignr_epi8(v, v, 8);
        break;
    case 9:
        rotated = _mm_alignr_epi8(v, v, 9);
        break;
    case 10:
        rotated = _mm_alignr_epi8(v, v, 10);
        break;
    case 11:
        rotated = _mm_alignr_epi8(v, v, 11);
        break;
    case 12:
        rotated = _mm_alignr_epi8(v, v, 12);
        break;
    case 13:
        rotated = _mm_alignr_epi8(v, v, 13);
        break;
    case 14:
        rotated = _mm_alignr_epi8(v, v, 14);
        break;
    case 15:
        rotated = _mm_alignr_epi8(v, v, 15);
        break;
    default:
        return;
    }

    _mm_storeu_si128((__m128i*) data, rotated);
}

void
vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
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

    uint8_t temp[32];
    memcpy(temp, fixed_key + 32, 32);
    for (int i = 0; i < 32; i++) {
        fixed_key[32 + i] = temp[VISTRUTAH_KEXP_SHUFFLE[i]];
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
}

// Helper to rotate backward (used for reverse key schedule)
// Rotate backward is equivalent to rotate forward by (16 - shift)
static inline void
rotate_bytes_backward(uint8_t* data, int shift, int len)
{
    rotate_bytes(data, len - shift, len);
}

void
vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t fixed_key[64];
    uint8_t round_key[64];
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

    uint8_t temp[32];
    memcpy(temp, fixed_key + 32, 32);
    for (int i = 0; i < 32; i++) {
        fixed_key[32 + i] = temp[VISTRUTAH_KEXP_SHUFFLE[i]];
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);
    memcpy(round_key + 32, fixed_key + 48, 16);
    memcpy(round_key + 48, fixed_key + 32, 16);

    for (int i = 0; i < steps; i++) {
        rotate_bytes(round_key, 5, 16);
        rotate_bytes(round_key + 16, 10, 16);
        rotate_bytes(round_key + 32, 5, 16);
        rotate_bytes(round_key + 48, 10, 16);
    }

    __m128i fk0 = _mm_loadu_si128((const __m128i*) fixed_key);
    __m128i fk1 = _mm_loadu_si128((const __m128i*) (fixed_key + 16));
    __m128i fk2 = _mm_loadu_si128((const __m128i*) (fixed_key + 32));
    __m128i fk3 = _mm_loadu_si128((const __m128i*) (fixed_key + 48));

    __m128i fk0_imc = _mm_aesimc_si128(fk0);
    __m128i fk1_imc = _mm_aesimc_si128(fk1);
    __m128i fk2_imc = _mm_aesimc_si128(fk2);
    __m128i fk3_imc = _mm_aesimc_si128(fk3);

    __m128i rk0 = _mm_loadu_si128((const __m128i*) round_key);
    __m128i rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));
    __m128i rk2 = _mm_loadu_si128((const __m128i*) (round_key + 32));
    __m128i rk3 = _mm_loadu_si128((const __m128i*) (round_key + 48));

    s0 = _mm_xor_si128(s0, rk0);
    s1 = _mm_xor_si128(s1, rk1);
    s2 = _mm_xor_si128(s2, rk2);
    s3 = _mm_xor_si128(s3, rk3);
    s0 = aes_inv_round(s0, fk0_imc);
    s1 = aes_inv_round(s1, fk1_imc);
    s2 = aes_inv_round(s2, fk2_imc);
    s3 = aes_inv_round(s3, fk3_imc);

    for (int i = steps - 1; i >= 1; i--) {
        rotate_bytes_backward(round_key, 5, 16);
        rotate_bytes_backward(round_key + 16, 10, 16);
        rotate_bytes_backward(round_key + 32, 5, 16);
        rotate_bytes_backward(round_key + 48, 10, 16);

        rk0 = _mm_loadu_si128((const __m128i*) round_key);
        rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));
        rk2 = _mm_loadu_si128((const __m128i*) (round_key + 32));
        rk3 = _mm_loadu_si128((const __m128i*) (round_key + 48));

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

    rotate_bytes_backward(round_key, 5, 16);
    rotate_bytes_backward(round_key + 16, 10, 16);
    rotate_bytes_backward(round_key + 32, 5, 16);
    rotate_bytes_backward(round_key + 48, 10, 16);

    rk0 = _mm_loadu_si128((const __m128i*) round_key);
    rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));
    rk2 = _mm_loadu_si128((const __m128i*) (round_key + 32));
    rk3 = _mm_loadu_si128((const __m128i*) (round_key + 48));

    s0 = aes_inv_final_round(s0, rk0);
    s1 = aes_inv_final_round(s1, rk1);
    s2 = aes_inv_final_round(s2, rk2);
    s3 = aes_inv_final_round(s3, rk3);

    _mm_storeu_si128((__m128i*) plaintext, s0);
    _mm_storeu_si128((__m128i*) (plaintext + 16), s1);
    _mm_storeu_si128((__m128i*) (plaintext + 32), s2);
    _mm_storeu_si128((__m128i*) (plaintext + 48), s3);
}

#endif
