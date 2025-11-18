#include "vistrutah.h"

#ifdef VISTRUTAH_ARM

#    include <arm_neon.h>
#    include <string.h>

extern const uint8_t ROUND_CONSTANTS[16 * 48];
extern const uint8_t VISTRUTAH_P4[16];
extern const uint8_t VISTRUTAH_P5[16];
extern const uint8_t VISTRUTAH_P4_INV[16];
extern const uint8_t VISTRUTAH_P5_INV[16];
extern const uint8_t VISTRUTAH_ZERO[16];

#    define AES_ENC(A, B)      veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), (A))), (B))
#    define AES_ENC_LAST(A, B) veorq_u8(vaeseq_u8(vmovq_n_u8(0), (A)), (B))
#    define AES_DEC(A, B)      veorq_u8(vaesimcq_u8(vaesdq_u8(vmovq_n_u8(0), (A))), (B))
#    define AES_DEC_LAST(A, B) veorq_u8(vaesdq_u8(vmovq_n_u8(0), (A)), (B))
#    define INV_MIX_COLUMNS(A) vaesimcq_u8(A)

bool
vistrutah_has_aes_accel(void)
{
    return true;
}

const char*
vistrutah_get_impl_name(void)
{
    return "ARM64 NEON+Crypto";
}

static void
mixing_layer_256(uint8x16_t* s0, uint8x16_t* s1)
{
    uint8x16_t t0 = *s0;
    uint8x16_t t1 = *s1;
    *s0           = vuzp1q_u8(t0, t1);
    *s1           = vuzp2q_u8(t0, t1);
}

static void
inv_mixing_layer_256(uint8x16_t* s0, uint8x16_t* s1)
{
    uint8x16_t t0 = *s0;
    uint8x16_t t1 = *s1;
    *s0           = vzip1q_u8(t0, t1);
    *s1           = vzip2q_u8(t0, t1);
}

static void
apply_permutation(const uint8_t* perm, uint8_t* data, int len __attribute__((unused)))
{
    uint8x16_t d      = vld1q_u8(data);
    uint8x16_t p      = vld1q_u8(perm);
    uint8x16_t result = vqtbl1q_u8(d, p);
    vst1q_u8(data, result);
}

void
vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t fixed_key[32];
    uint8_t round_key[32];
    int     steps = rounds / ROUNDS_PER_STEP;

    uint8x16_t s0 = vld1q_u8(plaintext);
    uint8x16_t s1 = vld1q_u8(plaintext + 16);

    if (key_size == 16) {
        uint8x16_t k = vld1q_u8(key);
        vst1q_u8(fixed_key, k);
        vst1q_u8(fixed_key + 16, k);
    } else {
        memcpy(fixed_key, key, 32);
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);

    uint8x16_t fk0  = vld1q_u8(fixed_key);
    uint8x16_t fk1  = vld1q_u8(fixed_key + 16);
    uint8x16_t rk0  = vld1q_u8(round_key);
    uint8x16_t rk1  = vld1q_u8(round_key + 16);
    uint8x16_t zero = vmovq_n_u8(0);

    s0 = veorq_u8(s0, rk0);
    s1 = veorq_u8(s1, rk1);
    s0 = AES_ENC(s0, fk0);
    s1 = AES_ENC(s1, fk1);

    for (int i = 1; i < steps; i++) {
        s0 = AES_ENC(s0, zero);
        s1 = AES_ENC(s1, zero);
        mixing_layer_256(&s0, &s1);

        apply_permutation(VISTRUTAH_P4, round_key, 16);
        apply_permutation(VISTRUTAH_P5, round_key + 16, 16);

        rk0 = vld1q_u8(round_key);
        rk1 = vld1q_u8(round_key + 16);

        s0 = veorq_u8(s0, rk0);
        s1 = veorq_u8(s1, rk1);

        uint8x16_t rc = vld1q_u8(&ROUND_CONSTANTS[16 * (i - 1)]);
        s0            = veorq_u8(s0, rc);

        s0 = AES_ENC(s0, fk0);
        s1 = AES_ENC(s1, fk1);
    }

    apply_permutation(VISTRUTAH_P4, round_key, 16);
    apply_permutation(VISTRUTAH_P5, round_key + 16, 16);

    rk0 = vld1q_u8(round_key);
    rk1 = vld1q_u8(round_key + 16);

    s0 = AES_ENC_LAST(s0, rk0);
    s1 = AES_ENC_LAST(s1, rk1);

    vst1q_u8(ciphertext, s0);
    vst1q_u8(ciphertext + 16, s1);
}

void
vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t fixed_key[32];
    uint8_t round_key[32];
    int     steps = rounds / ROUNDS_PER_STEP;

    uint8x16_t s0 = vld1q_u8(ciphertext);
    uint8x16_t s1 = vld1q_u8(ciphertext + 16);

    if (key_size == 16) {
        uint8x16_t k = vld1q_u8(key);
        vst1q_u8(fixed_key, k);
        vst1q_u8(fixed_key + 16, k);
    } else {
        memcpy(fixed_key, key, 32);
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);

    for (int i = 0; i < steps; i++) {
        apply_permutation(VISTRUTAH_P4, round_key, 16);
        apply_permutation(VISTRUTAH_P5, round_key + 16, 16);
    }

    uint8x16_t fk0 = vld1q_u8(fixed_key);
    uint8x16_t fk1 = vld1q_u8(fixed_key + 16);

    fk0 = INV_MIX_COLUMNS(fk0);
    fk1 = INV_MIX_COLUMNS(fk1);

    uint8x16_t rk0 = vld1q_u8(round_key);
    uint8x16_t rk1 = vld1q_u8(round_key + 16);

    s0 = veorq_u8(s0, rk0);
    s1 = veorq_u8(s1, rk1);

    s0 = AES_DEC(s0, fk0);
    s1 = AES_DEC(s1, fk1);

    for (int i = steps - 1; i > 0; i--) {
        apply_permutation(VISTRUTAH_P4_INV, round_key, 16);
        apply_permutation(VISTRUTAH_P5_INV, round_key + 16, 16);

        rk0 = vld1q_u8(round_key);
        rk1 = vld1q_u8(round_key + 16);

        s0 = AES_DEC_LAST(s0, rk0);
        s1 = AES_DEC_LAST(s1, rk1);

        uint8x16_t rc = vld1q_u8(&ROUND_CONSTANTS[16 * (i - 1)]);
        s0            = veorq_u8(s0, rc);

        inv_mixing_layer_256(&s0, &s1);

        s0 = INV_MIX_COLUMNS(s0);
        s1 = INV_MIX_COLUMNS(s1);

        s0 = AES_DEC(s0, fk0);
        s1 = AES_DEC(s1, fk1);
    }

    apply_permutation(VISTRUTAH_P4_INV, round_key, 16);
    apply_permutation(VISTRUTAH_P5_INV, round_key + 16, 16);

    rk0 = vld1q_u8(round_key);
    rk1 = vld1q_u8(round_key + 16);

    s0 = AES_DEC_LAST(s0, rk0);
    s1 = AES_DEC_LAST(s1, rk1);

    vst1q_u8(plaintext, s0);
    vst1q_u8(plaintext + 16, s1);
}

#endif
