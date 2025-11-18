#include "vistrutah_portable.h"

#ifdef VISTRUTAH_INTEL

#    include <immintrin.h>
#    include <string.h>

extern const uint8_t ROUND_CONSTANTS[16 * 48];
extern const uint8_t VISTRUTAH_KEXP_SHUFFLE[32];
extern const uint8_t VISTRUTAH_ZERO[16];

static void
rotate_bytes(uint8_t* data, int shift, int len)
{
    uint8_t temp[16];
    for (int i = 0; i < len; i++) {
        temp[i] = data[(i + shift) % len];
    }
    memcpy(data, temp, len);
}

static void
mixing_layer_512(__m128i* s0, __m128i* s1, __m128i* s2, __m128i* s3)
{
    uint8_t temp[64];
    _mm_storeu_si128((__m128i*) temp, *s0);
    _mm_storeu_si128((__m128i*) (temp + 16), *s1);
    _mm_storeu_si128((__m128i*) (temp + 32), *s2);
    _mm_storeu_si128((__m128i*) (temp + 48), *s3);

    uint8_t result[64];
    for (int i = 0; i < 16; i++) {
        result[i] = temp[4 * i];
        result[16 + i] = temp[4 * i + 1];
        result[32 + i] = temp[4 * i + 2];
        result[48 + i] = temp[4 * i + 3];
    }

    *s0 = _mm_loadu_si128((const __m128i*) result);
    *s1 = _mm_loadu_si128((const __m128i*) (result + 16));
    *s2 = _mm_loadu_si128((const __m128i*) (result + 32));
    *s3 = _mm_loadu_si128((const __m128i*) (result + 48));
}

static void
inv_mixing_layer_512(__m128i* s0, __m128i* s1, __m128i* s2, __m128i* s3)
{
    uint8_t temp[64];
    _mm_storeu_si128((__m128i*) temp, *s0);
    _mm_storeu_si128((__m128i*) (temp + 16), *s1);
    _mm_storeu_si128((__m128i*) (temp + 32), *s2);
    _mm_storeu_si128((__m128i*) (temp + 48), *s3);

    uint8_t result[64];
    for (int i = 0; i < 16; i++) {
        result[4 * i] = temp[i];
        result[4 * i + 1] = temp[16 + i];
        result[4 * i + 2] = temp[32 + i];
        result[4 * i + 3] = temp[48 + i];
    }

    *s0 = _mm_loadu_si128((const __m128i*) result);
    *s1 = _mm_loadu_si128((const __m128i*) (result + 16));
    *s2 = _mm_loadu_si128((const __m128i*) (result + 32));
    *s3 = _mm_loadu_si128((const __m128i*) (result + 48));
}

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

    __m128i fk0 = _mm_loadu_si128((const __m128i*) fixed_key);
    __m128i fk1 = _mm_loadu_si128((const __m128i*) (fixed_key + 16));
    __m128i fk2 = _mm_loadu_si128((const __m128i*) (fixed_key + 32));
    __m128i fk3 = _mm_loadu_si128((const __m128i*) (fixed_key + 48));
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

        mixing_layer_512(&s0, &s1, &s2, &s3);

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
        s0 = _mm_xor_si128(s0, rc);

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

void
vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
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

    __m128i zero = _mm_setzero_si128();

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
        s0 = _mm_xor_si128(s0, rc);

        inv_mixing_layer_512(&s0, &s1, &s2, &s3);

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
}

#endif
