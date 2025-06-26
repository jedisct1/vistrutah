#include <stdio.h>
#include <string.h>
#include <stdint.h>

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf(" ");
    }
    printf("\n");
}

void print_state_blocks(const char* label, const uint8_t* state) {
    printf("%s:\n", label);
    printf("  Block 0: ");
    for (int i = 0; i < 16; i++) printf("%02x", state[i]);
    printf("\n  Block 1: ");
    for (int i = 16; i < 32; i++) printf("%02x", state[i]);
    printf("\n  Block 2: ");
    for (int i = 32; i < 48; i++) printf("%02x", state[i]);
    printf("\n  Block 3: ");
    for (int i = 48; i < 64; i++) printf("%02x", state[i]);
    printf("\n");
}

// Simulate the ARM transpose mixing for 512-bit state
void arm_transpose_mix(uint8_t* state) {
    uint8_t temp[64];
    
    // This simulates the ARM NEON transpose operations
    // It performs a 4x4 transpose of 128-bit blocks
    // Block arrangement: [0,1,2,3] -> transpose -> new arrangement
    
    // Copy original state
    memcpy(temp, state, 64);
    
    // Perform 4x4 transpose at the 32-bit word level
    // This matches what the ARM NEON vtrn instructions do
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            // Copy 4-byte word from position (i,j) to position (j,i)
            memcpy(state + (j * 16 + i * 4), temp + (i * 16 + j * 4), 4);
        }
    }
}

// Simulate the Intel transpose mixing for 512-bit state  
void intel_transpose_mix(uint8_t* state) {
    uint8_t temp[64];
    memcpy(temp, state, 64);
    
    // Intel SSE implementation from the code
    // Uses unpacklo/hi operations which work differently
    uint32_t* s = (uint32_t*)temp;
    uint32_t* d = (uint32_t*)state;
    
    // First level: transpose pairs (simulating _mm_unpacklo/hi_epi32)
    uint32_t t[16];
    t[0] = s[0]; t[1] = s[4]; t[2] = s[1]; t[3] = s[5];     // unpacklo(s0,s1)
    t[4] = s[2]; t[5] = s[6]; t[6] = s[3]; t[7] = s[7];     // unpackhi(s0,s1)
    t[8] = s[8]; t[9] = s[12]; t[10] = s[9]; t[11] = s[13]; // unpacklo(s2,s3)
    t[12] = s[10]; t[13] = s[14]; t[14] = s[11]; t[15] = s[15]; // unpackhi(s2,s3)
    
    // Second level: complete transpose (simulating _mm_unpacklo/hi_epi64)
    d[0] = t[0]; d[1] = t[1]; d[2] = t[8]; d[3] = t[9];     // unpacklo64(t0,t2)
    d[4] = t[2]; d[5] = t[3]; d[6] = t[10]; d[7] = t[11];   // unpackhi64(t0,t2)
    d[8] = t[4]; d[9] = t[5]; d[10] = t[12]; d[11] = t[13]; // unpacklo64(t1,t3)
    d[12] = t[6]; d[13] = t[7]; d[14] = t[14]; d[15] = t[15]; // unpackhi64(t1,t3)
}

int main() {
    printf("Analysis of ARM vs Intel Vistrutah-512 Differences\n");
    printf("==================================================\n\n");
    
    // Test 1: Compare mixing operations with identical blocks
    printf("Test 1: Mixing with identical blocks\n");
    printf("------------------------------------\n");
    
    uint8_t state_arm[64];
    uint8_t state_intel[64];
    
    // Fill with pattern where all blocks are identical
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 16; j++) {
            state_arm[i * 16 + j] = j;
            state_intel[i * 16 + j] = j;
        }
    }
    
    print_state_blocks("Initial state (identical blocks)", state_arm);
    
    arm_transpose_mix(state_arm);
    intel_transpose_mix(state_intel);
    
    print_state_blocks("After ARM transpose", state_arm);
    print_state_blocks("After Intel transpose", state_intel);
    
    // Check if they're the same
    if (memcmp(state_arm, state_intel, 64) == 0) {
        printf("✓ Transposes produce SAME result\n");
    } else {
        printf("✗ Transposes produce DIFFERENT results!\n");
    }
    
    // Test 2: Mixing with different blocks
    printf("\n\nTest 2: Mixing with different blocks\n");
    printf("------------------------------------\n");
    
    for (int i = 0; i < 64; i++) {
        state_arm[i] = i;
        state_intel[i] = i;
    }
    
    print_state_blocks("Initial state (sequential bytes)", state_arm);
    
    arm_transpose_mix(state_arm);
    intel_transpose_mix(state_intel);
    
    print_state_blocks("After ARM transpose", state_arm);
    print_state_blocks("After Intel transpose", state_intel);
    
    if (memcmp(state_arm, state_intel, 64) == 0) {
        printf("✓ Transposes produce SAME result\n");
    } else {
        printf("✗ Transposes produce DIFFERENT results!\n");
        
        // Show byte-by-byte differences
        printf("\nByte differences:\n");
        for (int i = 0; i < 64; i++) {
            if (state_arm[i] != state_intel[i]) {
                printf("  Byte %2d: ARM=%02x, Intel=%02x\n", i, state_arm[i], state_intel[i]);
            }
        }
    }
    
    // Test 3: Key expansion differences
    printf("\n\nTest 3: Key Expansion Analysis\n");
    printf("------------------------------\n");
    
    // Analyze how round keys are generated
    printf("ARM Key Expansion:\n");
    printf("  Round 0 (even): Fixed key = ROUND_CONSTANT[0] broadcast to all bytes\n");
    printf("  Round 1 (odd):  Variable key = k0 (first 16 bytes of master key)\n");
    printf("  Round 2 (even): Fixed key = ROUND_CONSTANT[2] broadcast to all bytes\n");
    printf("  Round 3 (odd):  Variable key = k1 (second 16 bytes of master key)\n");
    printf("  Round 4 (even): Fixed key = ROUND_CONSTANT[4] broadcast to all bytes\n");
    printf("  Round 5 (odd):  Variable key = k2 (for 256-bit key, k2=k0)\n");
    printf("  etc.\n");
    
    printf("\nIntel Key Expansion (from vistrutah_512_intel.c):\n");
    printf("  Follows same pattern as ARM\n");
    
    // Test 4: Encryption flow analysis
    printf("\n\nTest 4: Encryption Flow Analysis\n");
    printf("--------------------------------\n");
    
    printf("ARM Encryption Flow (2 rounds):\n");
    printf("1. Initial key addition (round 0) to ALL blocks\n");
    printf("2. Round 1: AES round on each block with round_keys[1]\n");
    printf("3. Round 2: AES round on each block with round_keys[2]\n");
    printf("4. Apply mixing layer (transpose)\n");
    printf("\n");
    
    printf("Intel Encryption Flow - Issues Found:\n");
    printf("1. In SSE implementation, state is loaded/stored multiple times\n");
    printf("2. Mixing is applied after every 2 rounds, but round counting may be off\n");
    printf("3. The decryption round ordering seems incorrect\n");
    
    return 0;
}