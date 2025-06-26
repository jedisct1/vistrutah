#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <immintrin.h>

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s:\n", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

// Correct 4x4 transpose of 16-byte blocks
void transpose_4x4_blocks(uint8_t state[64]) {
    uint8_t temp[64];
    
    // View as 4x4 matrix of 16-byte blocks
    // Original layout:
    // Block 0: bytes 0-15
    // Block 1: bytes 16-31  
    // Block 2: bytes 32-47
    // Block 3: bytes 48-63
    
    // After transpose, byte at position (block_i * 16 + byte_j) 
    // goes to position (block_j * 16 + block_i * 4 + byte_j % 4)
    
    // Actually, looking at the ARM code more carefully, it seems to do
    // a transpose at the 32-bit word level within the 128-bit blocks
    
    // Let's implement what the ARM code does:
    // It transposes 4x4 matrix where each element is a 32-bit word
    
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            // Copy 32-bit word from block i, word j to block j, word i
            memcpy(temp + j * 16 + i * 4, 
                   state + i * 16 + j * 4, 
                   4);
        }
    }
    
    memcpy(state, temp, 64);
}

// Intel implementation using SSE
void transpose_4x4_blocks_intel(uint8_t state[64]) {
    __m128i s0 = _mm_loadu_si128((const __m128i*)(state));
    __m128i s1 = _mm_loadu_si128((const __m128i*)(state + 16));
    __m128i s2 = _mm_loadu_si128((const __m128i*)(state + 32));
    __m128i s3 = _mm_loadu_si128((const __m128i*)(state + 48));
    
    // Transpose 4x4 matrix of 32-bit words
    __m128i t0, t1, t2, t3;
    
    // First transpose pairs of rows
    t0 = _mm_unpacklo_epi32(s0, s1);  // a0 b0 a1 b1
    t1 = _mm_unpackhi_epi32(s0, s1);  // a2 b2 a3 b3
    t2 = _mm_unpacklo_epi32(s2, s3);  // c0 d0 c1 d1
    t3 = _mm_unpackhi_epi32(s2, s3);  // c2 d2 c3 d3
    
    // Second transpose to get final result
    s0 = _mm_unpacklo_epi64(t0, t2);  // a0 b0 c0 d0
    s1 = _mm_unpackhi_epi64(t0, t2);  // a1 b1 c1 d1
    s2 = _mm_unpacklo_epi64(t1, t3);  // a2 b2 c2 d2
    s3 = _mm_unpackhi_epi64(t1, t3);  // a3 b3 c3 d3
    
    _mm_storeu_si128((__m128i*)(state), s0);
    _mm_storeu_si128((__m128i*)(state + 16), s1);
    _mm_storeu_si128((__m128i*)(state + 32), s2);
    _mm_storeu_si128((__m128i*)(state + 48), s3);
}

int main() {
    printf("Testing Correct Mixing Layer Implementation\n");
    printf("==========================================\n\n");
    
    // Test data: sequential bytes
    uint8_t state1[64];
    uint8_t state2[64];
    for (int i = 0; i < 64; i++) {
        state1[i] = i;
        state2[i] = i;
    }
    
    printf("Original state:\n");
    print_hex("Blocks", state1, 64);
    
    // Apply reference transpose
    transpose_4x4_blocks(state1);
    printf("\nAfter reference transpose:\n");
    print_hex("Blocks", state1, 64);
    
    // Apply Intel transpose
    transpose_4x4_blocks_intel(state2);
    printf("\nAfter Intel transpose:\n");
    print_hex("Blocks", state2, 64);
    
    // Compare
    if (memcmp(state1, state2, 64) == 0) {
        printf("\n✓ Intel implementation matches reference!\n");
    } else {
        printf("\n✗ Intel implementation differs from reference!\n");
    }
    
    // Show the transpose pattern more clearly
    printf("\nTranspose pattern (32-bit words):\n");
    printf("Original: word[block][word_idx]\n");
    printf("After:    word[word_idx][block]\n");
    printf("\nExample mappings:\n");
    printf("Block 0, Word 0 (bytes 00-03) -> Block 0, Word 0 (bytes 00-03)\n");
    printf("Block 0, Word 1 (bytes 04-07) -> Block 1, Word 0 (bytes 10-13)\n");
    printf("Block 1, Word 0 (bytes 10-13) -> Block 0, Word 1 (bytes 04-07)\n");
    printf("Block 3, Word 3 (bytes 3c-3f) -> Block 3, Word 3 (bytes 3c-3f)\n");
    
    return 0;
}