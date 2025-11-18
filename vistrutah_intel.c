#include "vistrutah.h"

#ifdef VISTRUTAH_INTEL

#    include <cpuid.h>
#    include <immintrin.h>
#    include <string.h>

extern const uint8_t ROUND_CONSTANTS[16 * 48];
extern const uint8_t VISTRUTAH_P4[16];
extern const uint8_t VISTRUTAH_P5[16];
extern const uint8_t VISTRUTAH_P4_INV[16];
extern const uint8_t VISTRUTAH_P5_INV[16];
extern const uint8_t VISTRUTAH_ZERO[16];

bool
vistrutah_has_aes_accel(void)
{
    unsigned int eax, ebx, ecx, edx;

    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & bit_AES) != 0;
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

#    ifdef VISTRUTAH_VAES

static inline __m256i
aes_round_256(__m256i state, __m256i round_key)
{
    return _mm256_aesenc_epi128(state, round_key);
}

static inline __m256i
aes_final_round_256(__m256i state, __m256i round_key)
{
    return _mm256_aesenclast_epi128(state, round_key);
}

static inline __m256i
aes_inv_round_256(__m256i state, __m256i round_key)
{
    return _mm256_aesdec_epi128(state, round_key);
}

static inline __m256i
aes_inv_final_round_256(__m256i state, __m256i round_key)
{
    return _mm256_aesdeclast_epi128(state, round_key);
}

static inline __m256i
mixing_layer_256_avx2(__m256i state)
{
    const __m256i even_mask = _mm256_set_epi8(14, 12, 10, 8, 6, 4, 2, 0, 14, 12, 10, 8, 6, 4, 2, 0,
                                              14, 12, 10, 8, 6, 4, 2, 0, 14, 12, 10, 8, 6, 4, 2, 0);
    const __m256i odd_mask  = _mm256_set_epi8(15, 13, 11, 9, 7, 5, 3, 1, 15, 13, 11, 9, 7, 5, 3, 1,
                                              15, 13, 11, 9, 7, 5, 3, 1, 15, 13, 11, 9, 7, 5, 3, 1);

    __m256i even = _mm256_shuffle_epi8(state, even_mask);
    __m256i odd  = _mm256_shuffle_epi8(state, odd_mask);

    __m128i even_lo = _mm256_castsi256_si128(even);
    __m128i even_hi = _mm256_extracti128_si256(even, 1);
    __m128i odd_lo  = _mm256_castsi256_si128(odd);
    __m128i odd_hi  = _mm256_extracti128_si256(odd, 1);

    __m128i result0 = _mm_unpacklo_epi64(even_lo, even_hi);
    __m128i result1 = _mm_unpacklo_epi64(odd_lo, odd_hi);

    return _mm256_setr_m128i(result0, result1);
}

static inline __m256i
inv_mixing_layer_256_avx2(__m256i state)
{
    __m128i lo = _mm256_castsi256_si128(state);
    __m128i hi = _mm256_extracti128_si256(state, 1);

    __m128i result0 = _mm_unpacklo_epi8(lo, hi);
    __m128i result1 = _mm_unpackhi_epi8(lo, hi);

    return _mm256_setr_m128i(result0, result1);
}

#    endif

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

#    ifndef VISTRUTAH_VAES
static void
mixing_layer_256(__m128i* s0, __m128i* s1)
{
    __m128i t0 = *s0;
    __m128i t1 = *s1;

    const __m128i even_mask = _mm_set_epi8(14, 12, 10, 8, 6, 4, 2, 0, 14, 12, 10, 8, 6, 4, 2, 0);
    const __m128i odd_mask  = _mm_set_epi8(15, 13, 11, 9, 7, 5, 3, 1, 15, 13, 11, 9, 7, 5, 3, 1);

    __m128i s0_even = _mm_shuffle_epi8(t0, even_mask);
    __m128i s1_even = _mm_shuffle_epi8(t1, even_mask);
    __m128i s0_odd  = _mm_shuffle_epi8(t0, odd_mask);
    __m128i s1_odd  = _mm_shuffle_epi8(t1, odd_mask);

    *s0 = _mm_unpacklo_epi64(s0_even, s1_even);
    *s1 = _mm_unpacklo_epi64(s0_odd, s1_odd);
}
#    endif

static void
inv_mixing_layer_256(__m128i* s0, __m128i* s1)
{
    __m128i t0 = *s0;
    __m128i t1 = *s1;

    *s0 = _mm_unpacklo_epi8(t0, t1);
    *s1 = _mm_unpackhi_epi8(t0, t1);
}

static void
apply_permutation(const uint8_t* perm, uint8_t* data, int len __attribute__((unused)))
{
    __m128i d      = _mm_loadu_si128((const __m128i*) data);
    __m128i p      = _mm_loadu_si128((const __m128i*) perm);
    __m128i result = _mm_shuffle_epi8(d, p);
    _mm_storeu_si128((__m128i*) data, result);
}

void
vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
#    ifdef VISTRUTAH_VAES
    uint8_t fixed_key[32] __attribute__((aligned(32)));
    uint8_t round_key[32] __attribute__((aligned(32)));
    int     steps = rounds / ROUNDS_PER_STEP;

    __m256i state = _mm256_loadu_si256((const __m256i*) plaintext);

    if (key_size == 16) {
        __m128i k = _mm_loadu_si128((const __m128i*) key);
        _mm_storeu_si128((__m128i*) fixed_key, k);
        _mm_storeu_si128((__m128i*) (fixed_key + 16), k);
    } else {
        memcpy(fixed_key, key, 32);
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);

    __m256i fk   = _mm256_loadu_si256((const __m256i*) fixed_key);
    __m256i rk   = _mm256_loadu_si256((const __m256i*) round_key);
    __m256i zero = _mm256_setzero_si256();

    state = _mm256_xor_si256(state, rk);
    state = aes_round_256(state, fk);

    for (int i = 1; i < steps; i++) {
        state = aes_round_256(state, zero);
        state = mixing_layer_256_avx2(state);

        apply_permutation(VISTRUTAH_P4, round_key, 16);
        apply_permutation(VISTRUTAH_P5, round_key + 16, 16);

        rk    = _mm256_loadu_si256((const __m256i*) round_key);
        state = _mm256_xor_si256(state, rk);

        __m128i rc     = _mm_loadu_si128((const __m128i*) &ROUND_CONSTANTS[16 * (i - 1)]);
        __m256i rc_256 = _mm256_castsi128_si256(rc);
        state          = _mm256_xor_si256(state, rc_256);

        state = aes_round_256(state, fk);
    }

    apply_permutation(VISTRUTAH_P4, round_key, 16);
    apply_permutation(VISTRUTAH_P5, round_key + 16, 16);

    rk    = _mm256_loadu_si256((const __m256i*) round_key);
    state = aes_final_round_256(state, rk);

    _mm256_storeu_si256((__m256i*) ciphertext, state);
#    else
    uint8_t fixed_key[32];
    uint8_t round_key[32];
    int     steps = rounds / ROUNDS_PER_STEP;

    __m128i s0 = _mm_loadu_si128((const __m128i*) plaintext);
    __m128i s1 = _mm_loadu_si128((const __m128i*) (plaintext + 16));

    if (key_size == 16) {
        __m128i k = _mm_loadu_si128((const __m128i*) key);
        _mm_storeu_si128((__m128i*) fixed_key, k);
        _mm_storeu_si128((__m128i*) (fixed_key + 16), k);
    } else {
        memcpy(fixed_key, key, 32);
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);

    __m128i fk0  = _mm_loadu_si128((const __m128i*) fixed_key);
    __m128i fk1  = _mm_loadu_si128((const __m128i*) (fixed_key + 16));
    __m128i rk0  = _mm_loadu_si128((const __m128i*) round_key);
    __m128i rk1  = _mm_loadu_si128((const __m128i*) (round_key + 16));
    __m128i zero = _mm_setzero_si128();

    s0 = _mm_xor_si128(s0, rk0);
    s1 = _mm_xor_si128(s1, rk1);
    s0 = aes_round(s0, fk0);
    s1 = aes_round(s1, fk1);

    for (int i = 1; i < steps; i++) {
        s0 = aes_round(s0, zero);
        s1 = aes_round(s1, zero);
        mixing_layer_256(&s0, &s1);

        apply_permutation(VISTRUTAH_P4, round_key, 16);
        apply_permutation(VISTRUTAH_P5, round_key + 16, 16);

        rk0 = _mm_loadu_si128((const __m128i*) round_key);
        rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));

        s0 = _mm_xor_si128(s0, rk0);
        s1 = _mm_xor_si128(s1, rk1);

        __m128i rc = _mm_loadu_si128((const __m128i*) &ROUND_CONSTANTS[16 * (i - 1)]);
        s0         = _mm_xor_si128(s0, rc);

        s0 = aes_round(s0, fk0);
        s1 = aes_round(s1, fk1);
    }

    apply_permutation(VISTRUTAH_P4, round_key, 16);
    apply_permutation(VISTRUTAH_P5, round_key + 16, 16);

    rk0 = _mm_loadu_si128((const __m128i*) round_key);
    rk1 = _mm_loadu_si128((const __m128i*) (round_key + 16));

    s0 = aes_final_round(s0, rk0);
    s1 = aes_final_round(s1, rk1);

    _mm_storeu_si128((__m128i*) ciphertext, s0);
    _mm_storeu_si128((__m128i*) (ciphertext + 16), s1);
#    endif
}

void
vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t fixed_key[32];
    uint8_t round_key[32];
    uint8_t round_keys[48][32];
    int     steps = rounds / ROUNDS_PER_STEP;

    __m128i s0 = _mm_loadu_si128((const __m128i*) ciphertext);
    __m128i s1 = _mm_loadu_si128((const __m128i*) (ciphertext + 16));

    if (key_size == 16) {
        __m128i k = _mm_loadu_si128((const __m128i*) key);
        _mm_storeu_si128((__m128i*) fixed_key, k);
        _mm_storeu_si128((__m128i*) (fixed_key + 16), k);
    } else {
        memcpy(fixed_key, key, 32);
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);
    memcpy(round_keys[0], round_key, 32);

    for (int i = 1; i <= steps; i++) {
        apply_permutation(VISTRUTAH_P4, round_key, 16);
        apply_permutation(VISTRUTAH_P5, round_key + 16, 16);
        memcpy(round_keys[i], round_key, 32);
    }

    __m128i fk0 = _mm_loadu_si128((const __m128i*) fixed_key);
    __m128i fk1 = _mm_loadu_si128((const __m128i*) (fixed_key + 16));

    __m128i fk0_imc = _mm_aesimc_si128(fk0);
    __m128i fk1_imc = _mm_aesimc_si128(fk1);

    __m128i rk0 = _mm_loadu_si128((const __m128i*) round_keys[steps]);
    __m128i rk1 = _mm_loadu_si128((const __m128i*) (round_keys[steps] + 16));

    s0 = _mm_xor_si128(s0, rk0);
    s1 = _mm_xor_si128(s1, rk1);
    s0 = aes_inv_round(s0, fk0_imc);
    s1 = aes_inv_round(s1, fk1_imc);

    for (int i = steps - 1; i >= 1; i--) {
        rk0 = _mm_loadu_si128((const __m128i*) round_keys[i]);
        rk1 = _mm_loadu_si128((const __m128i*) (round_keys[i] + 16));

        s0 = aes_inv_final_round(s0, rk0);
        s1 = aes_inv_final_round(s1, rk1);

        __m128i rc = _mm_loadu_si128((const __m128i*) &ROUND_CONSTANTS[16 * (i - 1)]);
        s0         = _mm_xor_si128(s0, rc);

        inv_mixing_layer_256(&s0, &s1);

        s0 = _mm_aesimc_si128(s0);
        s1 = _mm_aesimc_si128(s1);

        s0 = aes_inv_round(s0, fk0_imc);
        s1 = aes_inv_round(s1, fk1_imc);
    }

    rk0 = _mm_loadu_si128((const __m128i*) round_keys[0]);
    rk1 = _mm_loadu_si128((const __m128i*) (round_keys[0] + 16));

    s0 = aes_inv_final_round(s0, rk0);
    s1 = aes_inv_final_round(s1, rk1);

    _mm_storeu_si128((__m128i*) plaintext, s0);
    _mm_storeu_si128((__m128i*) (plaintext + 16), s1);
}

#endif
