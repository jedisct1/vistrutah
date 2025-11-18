#ifndef VISTRUTAH_PORTABLE_H
#define VISTRUTAH_PORTABLE_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// CPU feature detection
#if defined(__x86_64__) || defined(_M_X64)
#    ifndef VISTRUTAH_INTEL
#        define VISTRUTAH_INTEL
#    endif
#    include <immintrin.h>

// Check for AVX512 and VAES support
#    ifndef VISTRUTAH_AVX512
#        ifdef __AVX512F__
#            define VISTRUTAH_AVX512
#        endif
#    endif

#    ifndef VISTRUTAH_VAES
#        ifdef __VAES__
#            define VISTRUTAH_VAES
#        endif
#    endif
#elif defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
#    ifndef VISTRUTAH_ARM
#        define VISTRUTAH_ARM
#    endif
#    include <arm_neon.h>
#endif

// Core constants
#define VISTRUTAH_256_BLOCK_SIZE 32
#define VISTRUTAH_512_BLOCK_SIZE 64
#define VISTRUTAH_KEY_SIZE_128   16
#define VISTRUTAH_KEY_SIZE_256   32
#define VISTRUTAH_KEY_SIZE_512   64

// Number of AES rounds per step
#define ROUNDS_PER_STEP 2

// Number of rounds for different versions
#define VISTRUTAH_256_ROUNDS_SHORT        10
#define VISTRUTAH_256_ROUNDS_LONG         14
#define VISTRUTAH_512_ROUNDS_SHORT_256KEY 10
#define VISTRUTAH_512_ROUNDS_SHORT_512KEY 12
#define VISTRUTAH_512_ROUNDS_LONG_256KEY  14
#define VISTRUTAH_512_ROUNDS_LONG_512KEY  18

// Portable vector types
#ifdef VISTRUTAH_INTEL
typedef __m128i v128_t;
typedef __m256i v256_t;
typedef __m512i v512_t;
#elif defined(VISTRUTAH_ARM)
typedef uint8x16_t v128_t;
// ARM doesn't have native 256/512-bit vectors, so we use structs
typedef struct {
    uint8x16_t val[2];
} v256_t;
typedef struct {
    uint8x16_t val[4];
} v512_t;
#else
// Fallback for portable implementation
typedef struct {
    uint8_t bytes[16];
} v128_t;
typedef struct {
    uint8_t bytes[32];
} v256_t;
typedef struct {
    uint8_t bytes[64];
} v512_t;
#endif

// Function prototypes
void vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                           int key_size, int rounds);
void vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                           int key_size, int rounds);

void vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key,
                           int key_size, int rounds);
void vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* key,
                           int key_size, int rounds);

// CPU capability detection
bool        vistrutah_has_aes_accel(void);
const char* vistrutah_get_impl_name(void);

// External constants (defined in vistrutah_common.c)
extern const uint8_t ROUND_CONSTANTS[16 * 48];
extern const uint8_t VISTRUTAH_P4[16];
extern const uint8_t VISTRUTAH_P5[16];
extern const uint8_t VISTRUTAH_P4_INV[16];
extern const uint8_t VISTRUTAH_P5_INV[16];
extern const uint8_t VISTRUTAH_KEXP_SHUFFLE[32];
extern const uint8_t VISTRUTAH_ZERO[16];

#endif // VISTRUTAH_PORTABLE_H