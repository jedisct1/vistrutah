#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"

extern const uint8_t ROUND_CONSTANTS[38];

int main() {
    printf("Round Constants Check\n");
    printf("====================\n\n");
    
    printf("Round constants for 14 rounds:\n");
    for (int i = 0; i <= 14; i++) {
        printf("RC[%2d] = 0x%02x\n", i, ROUND_CONSTANTS[i]);
    }
    
    printf("\nFor zero plaintext and key, after 14 rounds:\n");
    printf("If all blocks get same transformations -> 0x4b repeated\n");
    
    // Let's trace through what happens with zero input
    uint8_t state = 0x00;
    
    printf("\nManual trace with single byte:\n");
    printf("Initial: 0x%02x\n", state);
    
    // Round 0: XOR with RC[0]
    state ^= ROUND_CONSTANTS[0];
    printf("After round 0 key: 0x%02x (XOR with RC[0]=0x%02x)\n", state, ROUND_CONSTANTS[0]);
    
    // The issue is more complex than a simple trace...
    
    printf("\nThe issue is that with zero key and plaintext:\n");
    printf("1. All 4 blocks start as zeros\n");
    printf("2. Round 0 XORs all blocks with same constant (0x01)\n");
    printf("3. All blocks remain identical throughout\n");
    printf("4. Final result: all bytes = 0x4b\n");
    
    printf("\nBut the REAL issue is the encrypt/decrypt mismatch with non-zero data!\n");
    
    return 0;
}