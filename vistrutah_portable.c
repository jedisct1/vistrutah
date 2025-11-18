#include "vistrutah_portable.h"

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static uint8_t
gmul2(uint8_t a)
{
    return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
}

static uint8_t
gmul3(uint8_t a)
{
    return gmul2(a) ^ a;
}

static uint8_t
gmul9(uint8_t a)
{
    return gmul2(gmul2(gmul2(a))) ^ a;
}

static uint8_t
gmul11(uint8_t a)
{
    return gmul2(gmul2(gmul2(a)) ^ a) ^ a;
}

static uint8_t
gmul13(uint8_t a)
{
    return gmul2(gmul2(gmul3(a))) ^ a;
}

static uint8_t
gmul14(uint8_t a)
{
    return gmul2(gmul2(gmul3(a)) ^ a);
}

bool
vistrutah_has_aes_accel(void)
{
    return false;
}

const char*
vistrutah_get_impl_name(void)
{
    return "Portable (no hardware acceleration)";
}

static void
aes_sub_bytes(uint8_t state[16])
{
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

static void
aes_inv_sub_bytes(uint8_t state[16])
{
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

static void
aes_shift_rows(uint8_t state[16])
{
    uint8_t temp;

    temp      = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = temp;

    temp      = state[2];
    state[2]  = state[10];
    state[10] = temp;
    temp      = state[6];
    state[6]  = state[14];
    state[14] = temp;

    temp      = state[3];
    state[3]  = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = temp;
}

static void
aes_inv_shift_rows(uint8_t state[16])
{
    uint8_t temp;

    temp      = state[13];
    state[13] = state[9];
    state[9]  = state[5];
    state[5]  = state[1];
    state[1]  = temp;

    temp      = state[2];
    state[2]  = state[10];
    state[10] = temp;
    temp      = state[6];
    state[6]  = state[14];
    state[14] = temp;

    temp      = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3]  = temp;
}

static void
aes_mix_columns(uint8_t state[16])
{
    uint8_t temp[16];

    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i * 4 + 0];
        uint8_t s1 = state[i * 4 + 1];
        uint8_t s2 = state[i * 4 + 2];
        uint8_t s3 = state[i * 4 + 3];

        temp[i * 4 + 0] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3;
        temp[i * 4 + 1] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3;
        temp[i * 4 + 2] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3);
        temp[i * 4 + 3] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3);
    }

    memcpy(state, temp, 16);
}

static void
aes_inv_mix_columns(uint8_t state[16])
{
    uint8_t temp[16];

    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i * 4 + 0];
        uint8_t s1 = state[i * 4 + 1];
        uint8_t s2 = state[i * 4 + 2];
        uint8_t s3 = state[i * 4 + 3];

        temp[i * 4 + 0] = gmul14(s0) ^ gmul11(s1) ^ gmul13(s2) ^ gmul9(s3);
        temp[i * 4 + 1] = gmul9(s0) ^ gmul14(s1) ^ gmul11(s2) ^ gmul13(s3);
        temp[i * 4 + 2] = gmul13(s0) ^ gmul9(s1) ^ gmul14(s2) ^ gmul11(s3);
        temp[i * 4 + 3] = gmul11(s0) ^ gmul13(s1) ^ gmul9(s2) ^ gmul14(s3);
    }

    memcpy(state, temp, 16);
}

static void
aes_round(uint8_t state[16], const uint8_t round_key[16])
{
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_mix_columns(state);
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

static void
aes_final_round(uint8_t state[16], const uint8_t round_key[16])
{
    aes_sub_bytes(state);
    aes_shift_rows(state);
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

static void
aes_dec_round(uint8_t state[16], const uint8_t round_key[16])
{
    aes_inv_sub_bytes(state);
    aes_inv_shift_rows(state);
    aes_inv_mix_columns(state);
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

static void
aes_dec_final_round(uint8_t state[16], const uint8_t round_key[16])
{
    aes_inv_sub_bytes(state);
    aes_inv_shift_rows(state);
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

static void
apply_permutation(const uint8_t* perm, uint8_t* data, int len)
{
    uint8_t temp[64];
    memcpy(temp, data, len);
    for (int i = 0; i < len; i++) {
        data[i] = temp[perm[i]];
    }
}

static void
rotate_bytes(uint8_t* data, int len, int n)
{
    uint8_t temp[64];
    memcpy(temp, data, len);
    for (int i = 0; i < len; i++) {
        data[i] = temp[(i + n) % len];
    }
}

static void
swap_16(uint8_t* a, uint8_t* b)
{
    uint8_t temp[16];
    memcpy(temp, a, 16);
    memcpy(a, b, 16);
    memcpy(b, temp, 16);
}

static void
mixing_layer_256(uint8_t state[32])
{
    uint8_t temp[32];
    for (int i = 0; i < 16; i++) {
        temp[i]      = state[2 * i];
        temp[16 + i] = state[2 * i + 1];
    }
    memcpy(state, temp, 32);
}

static void
inv_mixing_layer_256(uint8_t state[32])
{
    uint8_t temp[32];
    for (int i = 0; i < 16; i++) {
        temp[2 * i]     = state[i];
        temp[2 * i + 1] = state[16 + i];
    }
    memcpy(state, temp, 32);
}

static const uint8_t vzip[64] = {
    0,  16, 32, 48, 1,  17, 33, 49, 2,  18, 34, 50, 3,  19, 35, 51,
    8,  24, 40, 56, 9,  25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    4,  20, 36, 52, 5,  21, 37, 53, 6,  22, 38, 54, 7,  23, 39, 55,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};

static const uint8_t vunzip[64] = {
    0,  4,  8,  12, 32, 36, 40, 44, 16, 20, 24, 28, 48, 52, 56, 60,
    1,  5,  9,  13, 33, 37, 41, 45, 17, 21, 25, 29, 49, 53, 57, 61,
    2,  6,  10, 14, 34, 38, 42, 46, 18, 22, 26, 30, 50, 54, 58, 62,
    3,  7,  11, 15, 35, 39, 43, 47, 19, 23, 27, 31, 51, 55, 59, 63
};

static void
mixing_layer_512(uint8_t state[64])
{
    apply_permutation(vzip, state, 64);
}

static void
inv_mixing_layer_512(uint8_t state[64])
{
    apply_permutation(vunzip, state, 64);
}

void
vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t state[32];
    uint8_t fixed_key[32];
    uint8_t round_key[32];
    int     steps = rounds / ROUNDS_PER_STEP;

    memcpy(state, plaintext, 32);

    if (key_size == 16) {
        memcpy(fixed_key, key, 16);
        memcpy(fixed_key + 16, key, 16);
    } else {
        memcpy(fixed_key, key, 32);
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);

    for (int i = 0; i < 32; i++) {
        state[i] ^= round_key[i];
    }

    aes_round(state, fixed_key);
    aes_round(state + 16, fixed_key + 16);

    for (int i = 1; i < steps; i++) {
        aes_round(state, VISTRUTAH_ZERO);
        aes_round(state + 16, VISTRUTAH_ZERO);

        mixing_layer_256(state);

        apply_permutation(VISTRUTAH_P4, round_key, 16);
        apply_permutation(VISTRUTAH_P5, round_key + 16, 16);

        for (int j = 0; j < 32; j++) {
            state[j] ^= round_key[j];
        }
        for (int j = 0; j < 16; j++) {
            state[j] ^= ROUND_CONSTANTS[16 * (i - 1) + j];
        }

        aes_round(state, fixed_key);
        aes_round(state + 16, fixed_key + 16);
    }

    apply_permutation(VISTRUTAH_P4, round_key, 16);
    apply_permutation(VISTRUTAH_P5, round_key + 16, 16);

    aes_final_round(state, round_key);
    aes_final_round(state + 16, round_key + 16);

    memcpy(ciphertext, state, 32);
}

void
vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t state[32];
    uint8_t fixed_key[32];
    uint8_t round_key[32];
    int     steps = rounds / ROUNDS_PER_STEP;

    memcpy(state, ciphertext, 32);

    if (key_size == 16) {
        memcpy(fixed_key, key, 16);
        memcpy(fixed_key + 16, key, 16);
    } else {
        memcpy(fixed_key, key, 32);
    }

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);

    for (int i = 0; i < steps; i++) {
        apply_permutation(VISTRUTAH_P4, round_key, 16);
        apply_permutation(VISTRUTAH_P5, round_key + 16, 16);
    }

    aes_inv_mix_columns(fixed_key);
    aes_inv_mix_columns(fixed_key + 16);

    for (int i = 0; i < 32; i++) {
        state[i] ^= round_key[i];
    }

    aes_dec_round(state, fixed_key);
    aes_dec_round(state + 16, fixed_key + 16);

    for (int i = steps - 1; i > 0; i--) {
        apply_permutation(VISTRUTAH_P4_INV, round_key, 16);
        apply_permutation(VISTRUTAH_P5_INV, round_key + 16, 16);

        aes_dec_final_round(state, round_key);
        aes_dec_final_round(state + 16, round_key + 16);

        for (int j = 0; j < 16; j++) {
            state[j] ^= ROUND_CONSTANTS[16 * (i - 1) + j];
        }

        inv_mixing_layer_256(state);

        aes_inv_mix_columns(state);
        aes_inv_mix_columns(state + 16);

        aes_dec_round(state, fixed_key);
        aes_dec_round(state + 16, fixed_key + 16);
    }

    apply_permutation(VISTRUTAH_P4_INV, round_key, 16);
    apply_permutation(VISTRUTAH_P5_INV, round_key + 16, 16);

    aes_dec_final_round(state, round_key);
    aes_dec_final_round(state + 16, round_key + 16);

    memcpy(plaintext, state, 32);
}

void
vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t state[64];
    uint8_t fixed_key[64];
    uint8_t round_key[64];
    int     steps = rounds / ROUNDS_PER_STEP;

    memcpy(state, plaintext, 64);

    memcpy(fixed_key, key, 32);
    memcpy(fixed_key + 32, key, 32);
    apply_permutation(VISTRUTAH_KEXP_SHUFFLE, fixed_key + 32, 32);

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);
    memcpy(round_key + 32, fixed_key + 48, 16);
    memcpy(round_key + 48, fixed_key + 32, 16);

    for (int i = 0; i < 64; i++) {
        state[i] ^= round_key[i];
    }

    aes_round(state, fixed_key);
    aes_round(state + 16, fixed_key + 16);
    aes_round(state + 32, fixed_key + 32);
    aes_round(state + 48, fixed_key + 48);

    for (int i = 1; i < steps; i++) {
        aes_round(state, VISTRUTAH_ZERO);
        aes_round(state + 16, VISTRUTAH_ZERO);
        aes_round(state + 32, VISTRUTAH_ZERO);
        aes_round(state + 48, VISTRUTAH_ZERO);

        mixing_layer_512(state);

        rotate_bytes(round_key, 16, 5);
        rotate_bytes(round_key + 16, 16, 10);
        rotate_bytes(round_key + 32, 16, 5);
        rotate_bytes(round_key + 48, 16, 10);

        for (int j = 0; j < 64; j++) {
            state[j] ^= round_key[j];
        }
        for (int j = 0; j < 16; j++) {
            state[j] ^= ROUND_CONSTANTS[16 * (i - 1) + j];
        }

        aes_round(state, fixed_key);
        aes_round(state + 16, fixed_key + 16);
        aes_round(state + 32, fixed_key + 32);
        aes_round(state + 48, fixed_key + 48);
    }

    rotate_bytes(round_key, 16, 5);
    rotate_bytes(round_key + 16, 16, 10);
    rotate_bytes(round_key + 32, 16, 5);
    rotate_bytes(round_key + 48, 16, 10);

    aes_final_round(state, round_key);
    aes_final_round(state + 16, round_key + 16);
    aes_final_round(state + 32, round_key + 32);
    aes_final_round(state + 48, round_key + 48);

    memcpy(ciphertext, state, 64);
}

void
vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t state[64];
    uint8_t fixed_key[64];
    uint8_t round_key[64];
    int     steps = rounds / ROUNDS_PER_STEP;

    memcpy(state, ciphertext, 64);

    memcpy(fixed_key, key, 32);
    memcpy(fixed_key + 32, key, 32);
    apply_permutation(VISTRUTAH_KEXP_SHUFFLE, fixed_key + 32, 32);

    memcpy(round_key, fixed_key + 16, 16);
    memcpy(round_key + 16, fixed_key, 16);
    memcpy(round_key + 32, fixed_key + 48, 16);
    memcpy(round_key + 48, fixed_key + 32, 16);

    rotate_bytes(round_key, 16, (5 * steps) % 16);
    rotate_bytes(round_key + 16, 16, (10 * steps) % 16);
    rotate_bytes(round_key + 32, 16, (5 * steps) % 16);
    rotate_bytes(round_key + 48, 16, (10 * steps) % 16);

    aes_inv_mix_columns(fixed_key);
    aes_inv_mix_columns(fixed_key + 16);
    aes_inv_mix_columns(fixed_key + 32);
    aes_inv_mix_columns(fixed_key + 48);

    for (int i = 0; i < 64; i++) {
        state[i] ^= round_key[i];
    }

    aes_dec_round(state, fixed_key);
    aes_dec_round(state + 16, fixed_key + 16);
    aes_dec_round(state + 32, fixed_key + 32);
    aes_dec_round(state + 48, fixed_key + 48);

    for (int i = 1; i < steps; i++) {
        rotate_bytes(round_key, 16, 11);
        rotate_bytes(round_key + 16, 16, 6);
        rotate_bytes(round_key + 32, 16, 11);
        rotate_bytes(round_key + 48, 16, 6);

        aes_dec_final_round(state, round_key);
        aes_dec_final_round(state + 16, round_key + 16);
        aes_dec_final_round(state + 32, round_key + 32);
        aes_dec_final_round(state + 48, round_key + 48);

        for (int j = 0; j < 16; j++) {
            state[j] ^= ROUND_CONSTANTS[16 * (steps - i - 1) + j];
        }

        inv_mixing_layer_512(state);

        aes_inv_mix_columns(state);
        aes_inv_mix_columns(state + 16);
        aes_inv_mix_columns(state + 32);
        aes_inv_mix_columns(state + 48);

        aes_dec_round(state, fixed_key);
        aes_dec_round(state + 16, fixed_key + 16);
        aes_dec_round(state + 32, fixed_key + 32);
        aes_dec_round(state + 48, fixed_key + 48);
    }

    rotate_bytes(round_key, 16, 11);
    rotate_bytes(round_key + 16, 16, 6);
    rotate_bytes(round_key + 32, 16, 11);
    rotate_bytes(round_key + 48, 16, 6);

    aes_dec_final_round(state, round_key);
    aes_dec_final_round(state + 16, round_key + 16);
    aes_dec_final_round(state + 32, round_key + 32);
    aes_dec_final_round(state + 48, round_key + 48);

    memcpy(plaintext, state, 64);
}
