#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"
#include <immintrin.h>

// External declarations
extern const uint8_t ROUND_CONSTANTS[38];

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) printf(" ");
    }
    printf("\n");
}

void print_m128i(const char* label, __m128i v) {
    uint8_t buf[16];
    _mm_storeu_si128((__m128i*)buf, v);
    print_hex(label, buf, 16);
}

// Test a single AES round operation
void test_aes_operation() {
    printf("=== Testing AES Operations ===\n\n");
    
    // Test input
    uint8_t input_data[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    
    __m128i state = _mm_loadu_si128((const __m128i*)input_data);
    __m128i zero = _mm_setzero_si128();
    
    print_m128i("Original state", state);
    
    // Test AES round with zero key
    __m128i after_aes = _mm_aesenc_si128(state, zero);
    print_m128i("After aesenc(state, 0)", after_aes);
    
    // Test with round constant
    __m128i rc = _mm_set1_epi8(0x01);
    __m128i with_rc = _mm_xor_si128(after_aes, rc);
    print_m128i("After XOR with 0x01", with_rc);
    
    // Test final round
    __m128i final_round = _mm_aesenclast_si128(state, zero);
    print_m128i("After aesenclast(state, 0)", final_round);
    
    printf("\n");
}

// Analyze why all zeros produces repetitive output
void analyze_zero_case() {
    printf("=== Analyzing Zero Input Case ===\n\n");
    
    uint8_t zeros[64] = {0};
    uint8_t key[32] = {0};
    
    // Initial state
    __m128i s0 = _mm_setzero_si128();
    __m128i s1 = _mm_setzero_si128();
    __m128i s2 = _mm_setzero_si128();
    __m128i s3 = _mm_setzero_si128();
    
    printf("Initial state: all zeros\n");
    
    // Round 0: XOR with round constant 0x01
    __m128i rc0 = _mm_set1_epi8(ROUND_CONSTANTS[0]); // 0x01
    s0 = _mm_xor_si128(s0, rc0);
    s1 = _mm_xor_si128(s1, rc0);
    s2 = _mm_xor_si128(s2, rc0);
    s3 = _mm_xor_si128(s3, rc0);
    
    printf("\nAfter round 0 key addition (RC=%02x):\n", ROUND_CONSTANTS[0]);
    print_m128i("All blocks become", s0);
    
    // Round 1: AES round
    s0 = _mm_aesenc_si128(s0, _mm_setzero_si128());
    s1 = _mm_aesenc_si128(s1, _mm_setzero_si128());
    s2 = _mm_aesenc_si128(s2, _mm_setzero_si128());
    s3 = _mm_aesenc_si128(s3, _mm_setzero_si128());
    
    // Key for round 1 is k0 = 0
    s0 = _mm_xor_si128(s0, _mm_setzero_si128());
    s1 = _mm_xor_si128(s1, _mm_setzero_si128());
    s2 = _mm_xor_si128(s2, _mm_setzero_si128());
    s3 = _mm_xor_si128(s3, _mm_setzero_si128());
    
    printf("\nAfter round 1 (AES + key 0):\n");
    print_m128i("All blocks are", s0);
    
    // Continue analysis...
    printf("\nKey point: With zero key and identical input blocks,\n");
    printf("all 4 blocks remain identical throughout encryption!\n");
}

// Test the mixing layer
void test_mixing_layer() {
    printf("\n=== Testing Mixing Layer ===\n\n");
    
    vistrutah_512_state_t state;
    
    // Initialize with distinct patterns
    for (int i = 0; i < 64; i++) {
        ((uint8_t*)&state)[i] = i;
    }
    
    printf("Before mixing:\n");
    print_hex("State", (uint8_t*)&state, 64);
    
    // Load as __m128i for transpose
    __m128i s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state));
    __m128i s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 48));
    
    // Perform transpose (mixing layer)
    __m128i t0, t1, t2, t3;
    
    // First level: transpose pairs
    t0 = _mm_unpacklo_epi32(s0, s1);
    t1 = _mm_unpackhi_epi32(s0, s1);
    t2 = _mm_unpacklo_epi32(s2, s3);
    t3 = _mm_unpackhi_epi32(s2, s3);
    
    // Second level: complete transpose
    s0 = _mm_unpacklo_epi64(t0, t2);
    s1 = _mm_unpackhi_epi64(t0, t2);
    s2 = _mm_unpacklo_epi64(t1, t3);
    s3 = _mm_unpackhi_epi64(t1, t3);
    
    _mm_storeu_si128((__m128i*)((uint8_t*)&state), s0);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 16), s1);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 32), s2);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 48), s3);
    
    printf("\nAfter mixing (transpose):\n");
    print_hex("State", (uint8_t*)&state, 64);
    
    // Check if transpose is working correctly
    printf("\nChecking transpose correctness:\n");
    printf("Original byte 0x00 should be at position 0: %02x\n", ((uint8_t*)&state)[0]);
    printf("Original byte 0x10 should be at position 1: %02x\n", ((uint8_t*)&state)[1]);
    printf("Original byte 0x20 should be at position 2: %02x\n", ((uint8_t*)&state)[2]);
    printf("Original byte 0x30 should be at position 3: %02x\n", ((uint8_t*)&state)[3]);
}

int main() {
    printf("Intel Vistrutah-512 Issue Analysis\n");
    printf("==================================\n\n");
    
    test_aes_operation();
    analyze_zero_case();
    test_mixing_layer();
    
    printf("\n=== DIAGNOSIS ===\n");
    printf("The issue with repetitive output (0x4b4b4b...) occurs because:\n");
    printf("1. With zero key and plaintext, all 4 blocks start identical\n");
    printf("2. They receive the same transformations at each step\n");
    printf("3. The mixing layer (transpose) doesn't help when all blocks are identical\n");
    printf("4. Result: all 64 bytes end up with the same value\n");
    printf("\nThe non-zero test case fails because the implementation\n");
    printf("might have an issue with state management between rounds.\n");
    
    return 0;
}