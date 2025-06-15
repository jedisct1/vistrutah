#ifndef VISTRUTAH_H
#define VISTRUTAH_H

#include <stdint.h>
#include <string.h>
#include <arm_neon.h>

// Core constants
#define VISTRUTAH_256_BLOCK_SIZE 32  // 256 bits = 32 bytes
#define VISTRUTAH_512_BLOCK_SIZE 64  // 512 bits = 64 bytes
#define VISTRUTAH_KEY_SIZE_128 16
#define VISTRUTAH_KEY_SIZE_256 32
#define VISTRUTAH_KEY_SIZE_512 64

// Number of AES rounds per step
#define ROUNDS_PER_STEP 2

// Number of rounds for different versions
#define VISTRUTAH_256_ROUNDS_SHORT 10
#define VISTRUTAH_256_ROUNDS_LONG 14
#define VISTRUTAH_512_ROUNDS_SHORT_256KEY 10
#define VISTRUTAH_512_ROUNDS_SHORT_512KEY 12
#define VISTRUTAH_512_ROUNDS_LONG_256KEY 14
#define VISTRUTAH_512_ROUNDS_LONG_512KEY 18

// State structure for Vistrutah-256 (2 AES states)
typedef struct {
    uint8x16_t slice[2];
} vistrutah_256_state_t;

// State structure for Vistrutah-512 (4 AES states)
typedef struct {
    uint8x16_t slice[4];
} vistrutah_512_state_t;

// Key schedule structures
typedef struct {
    uint8x16_t round_keys[15];  // Max rounds for Vistrutah-256
} vistrutah_256_key_schedule_t;

typedef struct {
    uint8x16_t round_keys[19];  // Max rounds for Vistrutah-512
} vistrutah_512_key_schedule_t;

// Function prototypes

// Vistrutah-256 functions
void vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, 
                          const uint8_t* key, int key_size, int rounds);
void vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                          const uint8_t* key, int key_size, int rounds);

// Vistrutah-512 functions
void vistrutah_512_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                          const uint8_t* key, int key_size, int rounds);
void vistrutah_512_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                          const uint8_t* key, int key_size, int rounds);

// Key expansion functions
void vistrutah_256_key_expansion(const uint8_t* key, int key_size,
                                vistrutah_256_key_schedule_t* ks, int rounds);
void vistrutah_512_key_expansion(const uint8_t* key, int key_size,
                                vistrutah_512_key_schedule_t* ks, int rounds);

#endif // VISTRUTAH_H