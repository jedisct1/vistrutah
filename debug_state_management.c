#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"
#include <immintrin.h>

extern const uint8_t ROUND_CONSTANTS[38];

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) printf(" ");
    }
    printf("\n");
}

// Simplified test of state management issue
void test_state_management() {
    printf("=== Testing State Management ===\n\n");
    
    vistrutah_512_state_t state;
    
    // Initialize with distinct values
    uint8_t test_data[64];
    for (int i = 0; i < 64; i++) {
        test_data[i] = i;
    }
    
    // Load into __m128i registers
    __m128i s0 = _mm_loadu_si128((const __m128i*)(test_data));
    __m128i s1 = _mm_loadu_si128((const __m128i*)(test_data + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*)(test_data + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*)(test_data + 48));
    
    printf("Initial values:\n");
    print_hex("s0", (uint8_t*)&s0, 16);
    print_hex("s1", (uint8_t*)&s1, 16);
    print_hex("s2", (uint8_t*)&s2, 16);
    print_hex("s3", (uint8_t*)&s3, 16);
    
    // Store to state structure
    _mm_storeu_si128((__m128i*)((uint8_t*)&state), s0);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 16), s1);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 32), s2);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 48), s3);
    
    printf("\nState after storing:\n");
    print_hex("State", (uint8_t*)&state, 64);
    
    // Modify s0-s3
    s0 = _mm_xor_si128(s0, _mm_set1_epi8(0xFF));
    s1 = _mm_xor_si128(s1, _mm_set1_epi8(0xFF));
    s2 = _mm_xor_si128(s2, _mm_set1_epi8(0xFF));
    s3 = _mm_xor_si128(s3, _mm_set1_epi8(0xFF));
    
    printf("\nModified s0-s3 (XORed with 0xFF):\n");
    print_hex("s0", (uint8_t*)&s0, 16);
    
    // Load back from state - should get original values
    s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state));
    s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 16));
    s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 32));
    s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 48));
    
    printf("\nReloaded from state:\n");
    print_hex("s0", (uint8_t*)&s0, 16);
    print_hex("s1", (uint8_t*)&s1, 16);
    print_hex("s2", (uint8_t*)&s2, 16);
    print_hex("s3", (uint8_t*)&s3, 16);
}

// Test the actual issue in the encryption
void test_encryption_issue() {
    printf("\n\n=== Testing Encryption Issue ===\n\n");
    
    // Use simple test vector
    uint8_t key[32] = {0};
    key[0] = 0x01;  // Non-zero key
    
    uint8_t plaintext[64] = {0};
    for (int i = 0; i < 64; i++) {
        plaintext[i] = i;
    }
    
    vistrutah_512_state_t state;
    vistrutah_key_schedule_t ks = {0};
    
    // Simple key schedule
    __m128i k0 = _mm_loadu_si128((const __m128i*)key);
    __m128i k1 = _mm_loadu_si128((const __m128i*)(key + 16));
    
    // Just test first few rounds
    ks.round_keys[0] = _mm_set1_epi8(0x01);  // RC[0]
    ks.round_keys[1] = k0;                    // Variable key
    ks.round_keys[2] = _mm_set1_epi8(0x04);  // RC[2]
    
    // Load plaintext
    __m128i s0 = _mm_loadu_si128((const __m128i*)plaintext);
    __m128i s1 = _mm_loadu_si128((const __m128i*)(plaintext + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*)(plaintext + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*)(plaintext + 48));
    
    printf("Plaintext:\n");
    print_hex("Block 0", (uint8_t*)&s0, 16);
    print_hex("Block 1", (uint8_t*)&s1, 16);
    print_hex("Block 2", (uint8_t*)&s2, 16);
    print_hex("Block 3", (uint8_t*)&s3, 16);
    
    // Round 0: Initial key addition
    s0 = _mm_xor_si128(s0, ks.round_keys[0]);
    s1 = _mm_xor_si128(s1, ks.round_keys[0]);
    s2 = _mm_xor_si128(s2, ks.round_keys[0]);
    s3 = _mm_xor_si128(s3, ks.round_keys[0]);
    
    printf("\nAfter round 0 (key addition with RC=0x01):\n");
    print_hex("Block 0", (uint8_t*)&s0, 16);
    print_hex("Block 1", (uint8_t*)&s1, 16);
    
    // Store state
    _mm_storeu_si128((__m128i*)((uint8_t*)&state), s0);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 16), s1);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 32), s2);
    _mm_storeu_si128((__m128i*)((uint8_t*)&state + 48), s3);
    
    // Round 1: Load from state (THIS IS THE ISSUE!)
    printf("\nRound 1 - Loading from state:\n");
    s0 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state));
    s1 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 16));
    s2 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 32));
    s3 = _mm_loadu_si128((const __m128i*)((uint8_t*)&state + 48));
    
    print_hex("Loaded Block 0", (uint8_t*)&s0, 16);
    print_hex("Loaded Block 1", (uint8_t*)&s1, 16);
    
    // Apply AES round
    s0 = _mm_aesenc_si128(s0, _mm_setzero_si128());
    s1 = _mm_aesenc_si128(s1, _mm_setzero_si128());
    s2 = _mm_aesenc_si128(s2, _mm_setzero_si128());
    s3 = _mm_aesenc_si128(s3, _mm_setzero_si128());
    
    printf("\nAfter AES round:\n");
    print_hex("Block 0", (uint8_t*)&s0, 16);
    print_hex("Block 1", (uint8_t*)&s1, 16);
    
    // Add round key
    s0 = _mm_xor_si128(s0, ks.round_keys[1]);
    s1 = _mm_xor_si128(s1, ks.round_keys[1]);
    s2 = _mm_xor_si128(s2, ks.round_keys[1]);
    s3 = _mm_xor_si128(s3, ks.round_keys[1]);
    
    printf("\nAfter key addition:\n");
    print_hex("Block 0", (uint8_t*)&s0, 16);
    print_hex("Block 1", (uint8_t*)&s1, 16);
}

int main() {
    test_state_management();
    test_encryption_issue();
    
    printf("\n\n=== ANALYSIS ===\n");
    printf("The state management appears correct.\n");
    printf("The issue might be in the overall algorithm flow.\n");
    
    return 0;
}