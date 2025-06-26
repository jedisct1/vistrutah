#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>

void print_hex128(const char* label, __m128i val) {
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i*)bytes, val);
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

int main() {
    printf("Testing Intel AES operations\n");
    printf("=============================\n");
    
    // Test data
    uint8_t data[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    
    __m128i state = _mm_loadu_si128((const __m128i*)data);
    __m128i round_key = _mm_loadu_si128((const __m128i*)key);
    
    print_hex128("Initial state", state);
    print_hex128("Round key", round_key);
    
    // Test 1: AES encrypt with zero key (like ARM does)
    printf("\nTest 1: AES encrypt with zero key\n");
    __m128i enc_zero = _mm_aesenc_si128(state, _mm_setzero_si128());
    print_hex128("After AESENC with zero", enc_zero);
    
    // Test 2: AES encrypt with actual key
    printf("\nTest 2: AES encrypt with key\n");
    __m128i enc_key = _mm_aesenc_si128(state, round_key);
    print_hex128("After AESENC with key", enc_key);
    
    // Test 3: Manual approach - AES with zero then XOR
    printf("\nTest 3: AESENC(zero) then XOR with key\n");
    __m128i manual = _mm_xor_si128(enc_zero, round_key);
    print_hex128("Result", manual);
    
    // Check if Test 2 and Test 3 are the same
    if (memcmp(&enc_key, &manual, 16) == 0) {
        printf("\n✓ AESENC(state, key) == AESENC(state, 0) XOR key\n");
    } else {
        printf("\n✗ AESENC(state, key) != AESENC(state, 0) XOR key\n");
    }
    
    // Test inverse operations
    printf("\n\nTesting inverse operations:\n");
    
    // Start with encrypted state
    __m128i encrypted = enc_key;
    print_hex128("Encrypted state", encrypted);
    
    // Method 1: Direct AESDEC with key
    __m128i dec1 = _mm_aesdec_si128(encrypted, round_key);
    print_hex128("AESDEC with key", dec1);
    
    // Method 2: XOR first, then AESDEC with zero
    __m128i temp = _mm_xor_si128(encrypted, round_key);
    __m128i dec2 = _mm_aesdec_si128(temp, _mm_setzero_si128());
    print_hex128("XOR then AESDEC(0)", dec2);
    
    // Method 3: AESIMC then AESDECLAST
    __m128i imc = _mm_aesimc_si128(encrypted);
    __m128i dec3 = _mm_aesdeclast_si128(imc, round_key);
    print_hex128("AESIMC then AESDECLAST", dec3);
    
    return 0;
}