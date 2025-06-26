#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"

void print_state_as_matrix(const char* label, const uint8_t* state) {
    printf("%s:\n", label);
    for (int row = 0; row < 4; row++) {
        printf("Row %d: ", row);
        for (int col = 0; col < 16; col++) {
            printf("%02x ", state[row * 16 + col]);
        }
        printf("\n");
    }
    printf("\n");
}

void print_state_by_words(const char* label, const uint8_t* state) {
    printf("%s (32-bit words):\n", label);
    for (int i = 0; i < 16; i++) {
        printf("Word %2d: ", i);
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[i * 4 + j]);
        }
        printf("\n");
    }
    printf("\n");
}

// External function declarations
void vistrutah_512_mix_intel(vistrutah_512_state_t* state);

int main() {
    printf("Testing Vistrutah-512 Mixing Layer (Intel)\n");
    printf("==========================================\n\n");
    
    vistrutah_512_state_t state;
    uint8_t test_data[64];
    
    // Initialize with sequential values to see the pattern clearly
    for (int i = 0; i < 64; i++) {
        test_data[i] = i;
    }
    
    printf("Initial state (sequential 0-63):\n");
    print_state_as_matrix("By rows", test_data);
    
    // Copy to state
    memcpy(&state, test_data, 64);
    
    // Apply mixing layer
    vistrutah_512_mix_intel(&state);
    
    // Copy back
    uint8_t mixed[64];
    memcpy(mixed, &state, 64);
    
    printf("After mixing:\n");
    print_state_as_matrix("By rows", mixed);
    print_state_by_words("By 32-bit words", mixed);
    
    // Now let's see what a 4x4 transpose of 128-bit blocks should look like
    printf("\nExpected 4x4 transpose of 128-bit blocks:\n");
    printf("Original blocks:\n");
    printf("Block 0 (bytes  0-15): 00-0f\n");
    printf("Block 1 (bytes 16-31): 10-1f\n");
    printf("Block 2 (bytes 32-47): 20-2f\n");
    printf("Block 3 (bytes 48-63): 30-3f\n");
    printf("\nAfter transpose, blocks should be in same positions,\n");
    printf("but internal structure might be rearranged.\n");
    
    // Test with a simpler pattern to understand the transpose
    printf("\n\nTest 2: Simple pattern\n");
    printf("======================\n");
    
    for (int block = 0; block < 4; block++) {
        for (int i = 0; i < 16; i++) {
            test_data[block * 16 + i] = (block << 4) | i;
        }
    }
    
    printf("Initial (block_id << 4 | position):\n");
    for (int i = 0; i < 64; i++) {
        if (i % 16 == 0) printf("\nBlock %d: ", i / 16);
        printf("%02x ", test_data[i]);
    }
    printf("\n");
    
    memcpy(&state, test_data, 64);
    vistrutah_512_mix_intel(&state);
    memcpy(mixed, &state, 64);
    
    printf("\nAfter mixing:\n");
    for (int i = 0; i < 64; i++) {
        if (i % 16 == 0) printf("\nBlock %d: ", i / 16);
        printf("%02x ", mixed[i]);
    }
    printf("\n");
    
    return 0;
}