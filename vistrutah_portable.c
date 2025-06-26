#include "vistrutah_portable.h"

// AES S-box lookup tables
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

// Inverse S-box
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

// Galois field multiplication by 2 (for MixColumns)
static uint8_t
gmul2(uint8_t a)
{
    if (a & 0x80) {
        return (a << 1) ^ 0x1b;
    } else {
        return a << 1;
    }
}

// Galois field multiplication by 3 (for MixColumns)
static uint8_t
gmul3(uint8_t a)
{
    return gmul2(a) ^ a;
}

// Galois field multiplication by 9 (for InvMixColumns)
static uint8_t
gmul9(uint8_t a)
{
    return gmul2(gmul2(gmul2(a))) ^ a;
}

// Galois field multiplication by 11 (for InvMixColumns)
static uint8_t
gmul11(uint8_t a)
{
    return gmul2(gmul2(gmul2(a)) ^ a) ^ a;
}

// Galois field multiplication by 13 (for InvMixColumns)
static uint8_t
gmul13(uint8_t a)
{
    return gmul2(gmul2(gmul3(a))) ^ a;
}

// Galois field multiplication by 14 (for InvMixColumns)
static uint8_t
gmul14(uint8_t a)
{
    return gmul2(gmul2(gmul3(a)) ^ a);
}

// External round constants
extern const uint8_t ROUND_CONSTANTS[38];

// CPU feature detection (portable version always returns false)
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

// Portable AES SubBytes operation
static void
aes_sub_bytes(uint8_t state[16])
{
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

// Portable AES InvSubBytes operation
static void
aes_inv_sub_bytes(uint8_t state[16])
{
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

// Portable AES ShiftRows operation
static void
aes_shift_rows(uint8_t state[16])
{
    uint8_t temp;

    // Row 1: shift left by 1
    temp      = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = temp;

    // Row 2: shift left by 2
    temp      = state[2];
    state[2]  = state[10];
    state[10] = temp;
    temp      = state[6];
    state[6]  = state[14];
    state[14] = temp;

    // Row 3: shift left by 3
    temp      = state[3];
    state[3]  = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = temp;
}

// Portable AES InvShiftRows operation
static void
aes_inv_shift_rows(uint8_t state[16])
{
    uint8_t temp;

    // Row 1: shift right by 1
    temp      = state[13];
    state[13] = state[9];
    state[9]  = state[5];
    state[5]  = state[1];
    state[1]  = temp;

    // Row 2: shift right by 2
    temp      = state[2];
    state[2]  = state[10];
    state[10] = temp;
    temp      = state[6];
    state[6]  = state[14];
    state[14] = temp;

    // Row 3: shift right by 3
    temp      = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3]  = temp;
}

// Portable AES MixColumns operation
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

// Portable AES InvMixColumns operation
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

// Portable AES AddRoundKey operation
static void
aes_add_round_key(uint8_t state[16], const uint8_t key[16])
{
    for (int i = 0; i < 16; i++) {
        state[i] ^= key[i];
    }
}

// Portable AES round (equivalent to AES-NI _mm_aesenc_si128)
static void
aes_round(uint8_t state[16], const uint8_t round_key[16])
{
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_mix_columns(state);
    aes_add_round_key(state, round_key);
}

// Portable AES final round (equivalent to AES-NI _mm_aesenclast_si128)
static void
aes_final_round(uint8_t state[16], const uint8_t round_key[16])
{
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, round_key);
}

// Vistrutah-256 mixing layer for portable
static void
vistrutah_256_mix_portable(uint8_t state[32])
{
    uint8_t temp[32];

    // ASURA mixing permutation
    static const uint8_t MIXING_PERM_256[32] = { 0,  17, 2,  19, 4,  21, 6,  23, 8,  25, 10,
                                                 27, 12, 29, 14, 31, 16, 1,  18, 3,  20, 5,
                                                 22, 7,  24, 9,  26, 11, 28, 13, 30, 15 };

    // Apply permutation
    for (int i = 0; i < 32; i++) {
        temp[i] = state[MIXING_PERM_256[i]];
    }

    memcpy(state, temp, 32);
}

// Vistrutah-256 inverse mixing layer for portable
static void
vistrutah_256_inv_mix_portable(uint8_t state[32])
{
    uint8_t temp[32];

    static const uint8_t MIXING_PERM_256[32] = { 0,  17, 2,  19, 4,  21, 6,  23, 8,  25, 10,
                                                 27, 12, 29, 14, 31, 16, 1,  18, 3,  20, 5,
                                                 22, 7,  24, 9,  26, 11, 28, 13, 30, 15 };

    // Apply inverse permutation
    for (int i = 0; i < 32; i++) {
        temp[MIXING_PERM_256[i]] = state[i];
    }

    memcpy(state, temp, 32);
}

// Vistrutah-512 mixing layer for portable
static void
vistrutah_512_mix_portable(uint8_t state[64])
{
    uint8_t   temp[64];
    uint32_t* state32 = (uint32_t*) state;
    uint32_t* temp32  = (uint32_t*) temp;

    // 4x4 transpose of 32-bit elements (matching Intel implementation)
    // Each 128-bit block contains 4 x 32-bit elements
    // We need to transpose the 4x4 matrix of 32-bit elements

    // Input layout (32-bit words):
    // Block 0: [0,  1,  2,  3 ]
    // Block 1: [4,  5,  6,  7 ]
    // Block 2: [8,  9,  10, 11]
    // Block 3: [12, 13, 14, 15]
    //
    // After transpose:
    // Block 0: [0,  4,  8,  12]
    // Block 1: [1,  5,  9,  13]
    // Block 2: [2,  6,  10, 14]
    // Block 3: [3,  7,  11, 15]

    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            temp32[row * 4 + col] = state32[col * 4 + row];
        }
    }

    memcpy(state, temp, 64);
}

// Vistrutah-512 inverse mixing layer for portable (same as forward)
static void
vistrutah_512_inv_mix_portable(uint8_t state[64])
{
    vistrutah_512_mix_portable(state);
}

// Key expansion for portable implementation
static void
vistrutah_key_expansion_portable(const uint8_t* key, int key_size, uint8_t round_keys[][16],
                                 int rounds)
{
    uint8_t k0[16], k1[16];

    if (key_size == 16) {
        memcpy(k0, key, 16);
        memcpy(k1, key, 16);
    } else {
        memcpy(k0, key, 16);
        memcpy(k1, key + 16, 16);
    }

    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            // XOR k0 with round constant
            memcpy(round_keys[i], k0, 16);
            for (int j = 0; j < 16; j++) {
                round_keys[i][j] ^= ROUND_CONSTANTS[i];
            }
        } else {
            // XOR k1 with round constant
            memcpy(round_keys[i], k1, 16);
            for (int j = 0; j < 16; j++) {
                round_keys[i][j] ^= ROUND_CONSTANTS[i];
            }
        }
    }
}

// Vistrutah-256 encryption (portable)
void
vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t state[32];
    uint8_t round_keys[MAX_ROUNDS + 1][16];

    // Initialize state
    memcpy(state, plaintext, 32);

    // Key expansion
    vistrutah_key_expansion_portable(key, key_size, round_keys, rounds);

    // Initial key addition
    aes_add_round_key(state, round_keys[0]);
    aes_add_round_key(state + 16, round_keys[0]);

    // Process rounds
    for (int round = 1; round <= rounds; round++) {
        if (round == rounds) {
            // Final round (no MixColumns)
            aes_final_round(state, round_keys[round]);
            aes_final_round(state + 16, round_keys[round]);
        } else {
            // Regular round
            aes_round(state, round_keys[round]);
            aes_round(state + 16, round_keys[round]);
        }

        // Apply mixing layer after every 2 rounds (except last)
        if ((round % 2 == 0) && (round < rounds)) {
            vistrutah_256_mix_portable(state);
        }
    }

    memcpy(ciphertext, state, 32);
}

// Vistrutah-256 decryption (portable)
void
vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t state[32];
    uint8_t round_keys[MAX_ROUNDS + 1][16];

    // Initialize state
    memcpy(state, ciphertext, 32);

    // Key expansion
    vistrutah_key_expansion_portable(key, key_size, round_keys, rounds);

    // Process rounds in reverse - match Intel implementation exactly
    for (int round = rounds; round >= 1; round--) {
        // Remove round key first
        aes_add_round_key(state, round_keys[round]);
        aes_add_round_key(state + 16, round_keys[round]);

        if (round == rounds) {
            // Inverse of final round (InvShiftRows + InvSubBytes only)
            aes_inv_shift_rows(state);
            aes_inv_sub_bytes(state);
            aes_inv_shift_rows(state + 16);
            aes_inv_sub_bytes(state + 16);
        } else {
            // Apply inverse mixing layer before the appropriate rounds
            if ((round % 2 == 0) && (round < rounds)) {
                vistrutah_256_inv_mix_portable(state);
            }

            // Regular inverse round (InvMixColumns + InvShiftRows + InvSubBytes)
            aes_inv_mix_columns(state);
            aes_inv_shift_rows(state);
            aes_inv_sub_bytes(state);
            aes_inv_mix_columns(state + 16);
            aes_inv_shift_rows(state + 16);
            aes_inv_sub_bytes(state + 16);
        }
    }

    // Remove initial round key
    aes_add_round_key(state, round_keys[0]);
    aes_add_round_key(state + 16, round_keys[0]);

    memcpy(plaintext, state, 32);
}

// Key expansion for Vistrutah-512 (portable)
static void
vistrutah_512_key_expansion_portable(const uint8_t* key, int key_size, uint8_t round_keys[][16],
                                     int rounds)
{
    uint8_t k0[16], k1[16];

    if (key_size == 32) {
        memcpy(k0, key, 16);
        memcpy(k1, key + 16, 16);
    } else {
        memcpy(k0, key, 16);
        memcpy(k1, key + 16, 16);
    }

    // Generate round keys using alternating fixed and variable keys
    for (int i = 0; i <= rounds; i++) {
        if (i % 2 == 0) {
            // Fixed round key with round constant
            memset(round_keys[i], ROUND_CONSTANTS[i], 16);
        } else {
            // Variable round key (cyclic permutation of master key)
            int key_idx = (i / 2) % 4;
            switch (key_idx) {
            case 0:
                memcpy(round_keys[i], k0, 16);
                break;
            case 1:
                memcpy(round_keys[i], k1, 16);
                break;
            case 2:
                memcpy(round_keys[i], k0, 16);
                break; // For 256-bit key, k2 = k0
            case 3:
                memcpy(round_keys[i], k1, 16);
                break; // For 256-bit key, k3 = k1
            }
        }
    }
}

// Vistrutah-512 encryption (portable)
void
vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t state[64];
    uint8_t round_keys[MAX_ROUNDS + 1][16];

    // Initialize state
    memcpy(state, plaintext, 64);

    // Key expansion
    vistrutah_512_key_expansion_portable(key, key_size, round_keys, rounds);

    // Initial key addition
    aes_add_round_key(state, round_keys[0]);
    aes_add_round_key(state + 16, round_keys[0]);
    aes_add_round_key(state + 32, round_keys[0]);
    aes_add_round_key(state + 48, round_keys[0]);

    // Main rounds
    int round_idx = 1;
    for (int step = 0; step < rounds / ROUNDS_PER_STEP; step++) {
        // Two AES rounds per step
        for (int r = 0; r < ROUNDS_PER_STEP; r++) {
            if (round_idx == rounds) {
                // Final round (no MixColumns)
                aes_final_round(state, round_keys[round_idx]);
                aes_final_round(state + 16, round_keys[round_idx]);
                aes_final_round(state + 32, round_keys[round_idx]);
                aes_final_round(state + 48, round_keys[round_idx]);
            } else {
                // Regular round
                aes_round(state, round_keys[round_idx]);
                aes_round(state + 16, round_keys[round_idx]);
                aes_round(state + 32, round_keys[round_idx]);
                aes_round(state + 48, round_keys[round_idx]);
            }
            round_idx++;
        }

        // Apply mixing layer (except after last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            vistrutah_512_mix_portable(state);
        }
    }

    // Handle odd number of rounds
    if (rounds % ROUNDS_PER_STEP == 1) {
        aes_final_round(state, round_keys[rounds]);
        aes_final_round(state + 16, round_keys[rounds]);
        aes_final_round(state + 32, round_keys[rounds]);
        aes_final_round(state + 48, round_keys[rounds]);
    }

    memcpy(ciphertext, state, 64);
}

// Vistrutah-512 decryption (portable)
void
vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                      int key_size, int rounds)
{
    uint8_t state[64];
    uint8_t round_keys[MAX_ROUNDS + 1][16];

    // Initialize state
    memcpy(state, ciphertext, 64);

    // Key expansion
    vistrutah_512_key_expansion_portable(key, key_size, round_keys, rounds);

    // Handle odd rounds at the end if necessary
    int round_idx = rounds;
    if (rounds % ROUNDS_PER_STEP == 1) {
        // Remove round key first
        aes_add_round_key(state, round_keys[round_idx]);
        aes_add_round_key(state + 16, round_keys[round_idx]);
        aes_add_round_key(state + 32, round_keys[round_idx]);
        aes_add_round_key(state + 48, round_keys[round_idx]);

        // Inverse of final round (InvShiftRows + InvSubBytes only)
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_inv_shift_rows(state + 16);
        aes_inv_sub_bytes(state + 16);
        aes_inv_shift_rows(state + 32);
        aes_inv_sub_bytes(state + 32);
        aes_inv_shift_rows(state + 48);
        aes_inv_sub_bytes(state + 48);
        round_idx--;
    }

    // Main rounds (in reverse), processing in steps of 2 rounds
    for (int step = (rounds / ROUNDS_PER_STEP) - 1; step >= 0; step--) {
        // Apply inverse mixing layer BEFORE processing rounds (except for last step)
        if (step < (rounds / ROUNDS_PER_STEP) - 1) {
            vistrutah_512_inv_mix_portable(state);
        }

        // Two AES rounds per step (in reverse order)
        for (int r = ROUNDS_PER_STEP - 1; r >= 0; r--) {
            round_idx = step * ROUNDS_PER_STEP + r + 1;

            // Skip if we've gone past the total rounds
            if (round_idx > rounds)
                continue;

            bool is_last_round = (round_idx == rounds) && (rounds % ROUNDS_PER_STEP == 0);

            // Remove round key first
            aes_add_round_key(state, round_keys[round_idx]);
            aes_add_round_key(state + 16, round_keys[round_idx]);
            aes_add_round_key(state + 32, round_keys[round_idx]);
            aes_add_round_key(state + 48, round_keys[round_idx]);

            if (is_last_round) {
                // Inverse of final round (InvShiftRows + InvSubBytes only)
                aes_inv_shift_rows(state);
                aes_inv_sub_bytes(state);
                aes_inv_shift_rows(state + 16);
                aes_inv_sub_bytes(state + 16);
                aes_inv_shift_rows(state + 32);
                aes_inv_sub_bytes(state + 32);
                aes_inv_shift_rows(state + 48);
                aes_inv_sub_bytes(state + 48);
            } else {
                // Regular inverse round (InvMixColumns + InvShiftRows + InvSubBytes)
                aes_inv_mix_columns(state);
                aes_inv_shift_rows(state);
                aes_inv_sub_bytes(state);
                aes_inv_mix_columns(state + 16);
                aes_inv_shift_rows(state + 16);
                aes_inv_sub_bytes(state + 16);
                aes_inv_mix_columns(state + 32);
                aes_inv_shift_rows(state + 32);
                aes_inv_sub_bytes(state + 32);
                aes_inv_mix_columns(state + 48);
                aes_inv_shift_rows(state + 48);
                aes_inv_sub_bytes(state + 48);
            }
        }
    }

    // Final key addition (round 0)
    aes_add_round_key(state, round_keys[0]);
    aes_add_round_key(state + 16, round_keys[0]);
    aes_add_round_key(state + 32, round_keys[0]);
    aes_add_round_key(state + 48, round_keys[0]);

    memcpy(plaintext, state, 64);
}