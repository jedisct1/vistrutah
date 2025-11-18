#include "vistrutah_portable.h"

#ifdef VISTRUTAH_ARM

#    include <arm_neon.h>
#    include <string.h>

extern const uint8_t ROUND_CONSTANTS[16 * 48];
extern const uint8_t VISTRUTAH_KEXP_SHUFFLE[32];
extern const uint8_t VISTRUTAH_ZERO[16];

#    define AES_ENC(A, B)      veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), (A))), (B))
#    define AES_ENC_LAST(A, B) veorq_u8(vaeseq_u8(vmovq_n_u8(0), (A)), (B))
#    define AES_DEC(A, B)      veorq_u8(vaesimcq_u8(vaesdq_u8(vmovq_n_u8(0), (A))), (B))
#    define AES_DEC_LAST(A, B) veorq_u8(vaesdq_u8(vmovq_n_u8(0), (A)), (B))
#    define INV_MIX_COLUMNS(A) vaesimcq_u8(A)

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
mixing_layer_512(uint8x16_t* s0, uint8x16_t* s1, uint8x16_t* s2, uint8x16_t* s3)
{
    uint8_t temp[64];
    vst1q_u8(temp, *s0);
    vst1q_u8(temp + 16, *s1);
    vst1q_u8(temp + 32, *s2);
    vst1q_u8(temp + 48, *s3);

    uint8_t result[64];
    for (int i = 0; i < 16; i++) {
        result[i] = temp[4 * i];
        result[16 + i] = temp[4 * i + 1];
        result[32 + i] = temp[4 * i + 2];
        result[48 + i] = temp[4 * i + 3];
    }

    *s0 = vld1q_u8(result);
    *s1 = vld1q_u8(result + 16);
    *s2 = vld1q_u8(result + 32);
    *s3 = vld1q_u8(result + 48);
}

static void
inv_mixing_layer_512(uint8x16_t* s0, uint8x16_t* s1, uint8x16_t* s2, uint8x16_t* s3)
{
    uint8_t temp[64];
    vst1q_u8(temp, *s0);
    vst1q_u8(temp + 16, *s1);
    vst1q_u8(temp + 32, *s2);
    vst1q_u8(temp + 48, *s3);

    uint8_t result[64];
    for (int i = 0; i < 16; i++) {
        result[4 * i] = temp[i];
        result[4 * i + 1] = temp[16 + i];
        result[4 * i + 2] = temp[32 + i];
        result[4 * i + 3] = temp[48 + i];
    }

    *s0 = vld1q_u8(result);
    *s1 = vld1q_u8(result + 16);
    *s2 = vld1q_u8(result + 32);
    *s3 = vld1q_u8(result + 48);
}

void
vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t fixed_key[64];
    uint8_t round_key[64];
    int     steps = rounds / ROUNDS_PER_STEP;

    uint8x16_t s0 = vld1q_u8(plaintext);
    uint8x16_t s1 = vld1q_u8(plaintext + 16);
    uint8x16_t s2 = vld1q_u8(plaintext + 32);
    uint8x16_t s3 = vld1q_u8(plaintext + 48);

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

    uint8x16_t fk0 = vld1q_u8(fixed_key);
    uint8x16_t fk1 = vld1q_u8(fixed_key + 16);
    uint8x16_t fk2 = vld1q_u8(fixed_key + 32);
    uint8x16_t fk3 = vld1q_u8(fixed_key + 48);
    uint8x16_t zero = vmovq_n_u8(0);

    uint8x16_t rk0 = vld1q_u8(round_key);
    uint8x16_t rk1 = vld1q_u8(round_key + 16);
    uint8x16_t rk2 = vld1q_u8(round_key + 32);
    uint8x16_t rk3 = vld1q_u8(round_key + 48);

    s0 = veorq_u8(s0, rk0);
    s1 = veorq_u8(s1, rk1);
    s2 = veorq_u8(s2, rk2);
    s3 = veorq_u8(s3, rk3);

    s0 = AES_ENC(s0, fk0);
    s1 = AES_ENC(s1, fk1);
    s2 = AES_ENC(s2, fk2);
    s3 = AES_ENC(s3, fk3);

    for (int i = 1; i < steps; i++) {
        s0 = AES_ENC(s0, zero);
        s1 = AES_ENC(s1, zero);
        s2 = AES_ENC(s2, zero);
        s3 = AES_ENC(s3, zero);

        mixing_layer_512(&s0, &s1, &s2, &s3);

        rotate_bytes(round_key, 5, 16);
        rotate_bytes(round_key + 16, 10, 16);
        rotate_bytes(round_key + 32, 5, 16);
        rotate_bytes(round_key + 48, 10, 16);

        rk0 = vld1q_u8(round_key);
        rk1 = vld1q_u8(round_key + 16);
        rk2 = vld1q_u8(round_key + 32);
        rk3 = vld1q_u8(round_key + 48);

        s0 = veorq_u8(s0, rk0);
        s1 = veorq_u8(s1, rk1);
        s2 = veorq_u8(s2, rk2);
        s3 = veorq_u8(s3, rk3);

        uint8x16_t rc = vld1q_u8(&ROUND_CONSTANTS[16 * (i - 1)]);
        s0 = veorq_u8(s0, rc);

        s0 = AES_ENC(s0, fk0);
        s1 = AES_ENC(s1, fk1);
        s2 = AES_ENC(s2, fk2);
        s3 = AES_ENC(s3, fk3);
    }

    rotate_bytes(round_key, 5, 16);
    rotate_bytes(round_key + 16, 10, 16);
    rotate_bytes(round_key + 32, 5, 16);
    rotate_bytes(round_key + 48, 10, 16);

    rk0 = vld1q_u8(round_key);
    rk1 = vld1q_u8(round_key + 16);
    rk2 = vld1q_u8(round_key + 32);
    rk3 = vld1q_u8(round_key + 48);

    s0 = AES_ENC_LAST(s0, rk0);
    s1 = AES_ENC_LAST(s1, rk1);
    s2 = AES_ENC_LAST(s2, rk2);
    s3 = AES_ENC_LAST(s3, rk3);

    vst1q_u8(ciphertext, s0);
    vst1q_u8(ciphertext + 16, s1);
    vst1q_u8(ciphertext + 32, s2);
    vst1q_u8(ciphertext + 48, s3);
}

void
vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t fixed_key[64];
    uint8_t round_key[64];
    int     steps = rounds / ROUNDS_PER_STEP;

    uint8x16_t s0 = vld1q_u8(ciphertext);
    uint8x16_t s1 = vld1q_u8(ciphertext + 16);
    uint8x16_t s2 = vld1q_u8(ciphertext + 32);
    uint8x16_t s3 = vld1q_u8(ciphertext + 48);

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

    rotate_bytes(round_key, (5 * steps) % 16, 16);
    rotate_bytes(round_key + 16, (10 * steps) % 16, 16);
    rotate_bytes(round_key + 32, (5 * steps) % 16, 16);
    rotate_bytes(round_key + 48, (10 * steps) % 16, 16);

    uint8x16_t fk0 = vld1q_u8(fixed_key);
    uint8x16_t fk1 = vld1q_u8(fixed_key + 16);
    uint8x16_t fk2 = vld1q_u8(fixed_key + 32);
    uint8x16_t fk3 = vld1q_u8(fixed_key + 48);

    fk0 = INV_MIX_COLUMNS(fk0);
    fk1 = INV_MIX_COLUMNS(fk1);
    fk2 = INV_MIX_COLUMNS(fk2);
    fk3 = INV_MIX_COLUMNS(fk3);

    uint8x16_t rk0 = vld1q_u8(round_key);
    uint8x16_t rk1 = vld1q_u8(round_key + 16);
    uint8x16_t rk2 = vld1q_u8(round_key + 32);
    uint8x16_t rk3 = vld1q_u8(round_key + 48);

    s0 = veorq_u8(s0, rk0);
    s1 = veorq_u8(s1, rk1);
    s2 = veorq_u8(s2, rk2);
    s3 = veorq_u8(s3, rk3);

    s0 = AES_DEC(s0, fk0);
    s1 = AES_DEC(s1, fk1);
    s2 = AES_DEC(s2, fk2);
    s3 = AES_DEC(s3, fk3);

    for (int i = 1; i < steps; i++) {
        rotate_bytes(round_key, 11, 16);
        rotate_bytes(round_key + 16, 6, 16);
        rotate_bytes(round_key + 32, 11, 16);
        rotate_bytes(round_key + 48, 6, 16);

        rk0 = vld1q_u8(round_key);
        rk1 = vld1q_u8(round_key + 16);
        rk2 = vld1q_u8(round_key + 32);
        rk3 = vld1q_u8(round_key + 48);

        s0 = AES_DEC_LAST(s0, rk0);
        s1 = AES_DEC_LAST(s1, rk1);
        s2 = AES_DEC_LAST(s2, rk2);
        s3 = AES_DEC_LAST(s3, rk3);

        uint8x16_t rc = vld1q_u8(&ROUND_CONSTANTS[16 * (steps - i - 1)]);
        s0 = veorq_u8(s0, rc);

        inv_mixing_layer_512(&s0, &s1, &s2, &s3);

        s0 = INV_MIX_COLUMNS(s0);
        s1 = INV_MIX_COLUMNS(s1);
        s2 = INV_MIX_COLUMNS(s2);
        s3 = INV_MIX_COLUMNS(s3);

        s0 = AES_DEC(s0, fk0);
        s1 = AES_DEC(s1, fk1);
        s2 = AES_DEC(s2, fk2);
        s3 = AES_DEC(s3, fk3);
    }

    rotate_bytes(round_key, 11, 16);
    rotate_bytes(round_key + 16, 6, 16);
    rotate_bytes(round_key + 32, 11, 16);
    rotate_bytes(round_key + 48, 6, 16);

    rk0 = vld1q_u8(round_key);
    rk1 = vld1q_u8(round_key + 16);
    rk2 = vld1q_u8(round_key + 32);
    rk3 = vld1q_u8(round_key + 48);

    s0 = AES_DEC_LAST(s0, rk0);
    s1 = AES_DEC_LAST(s1, rk1);
    s2 = AES_DEC_LAST(s2, rk2);
    s3 = AES_DEC_LAST(s3, rk3);

    vst1q_u8(plaintext, s0);
    vst1q_u8(plaintext + 16, s1);
    vst1q_u8(plaintext + 32, s2);
    vst1q_u8(plaintext + 48, s3);
}

#endif
