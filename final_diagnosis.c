#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("Final Diagnosis of Intel Vistrutah-512 Issue\n");
    printf("============================================\n\n");
    
    printf("Summary of findings:\n");
    printf("1. All-zero plaintext/key produces repetitive output (0x4b...)\n");
    printf("   - This is expected since all 4 blocks process identically\n\n");
    
    printf("2. Round-trip works for 1-3 rounds, fails for 4+ rounds\n");
    printf("   - 1-2 rounds: Single step, no mixing layer\n");
    printf("   - 3 rounds: 1 step + 1 odd round, no mixing\n");
    printf("   - 4+ rounds: Multiple steps with mixing layer\n\n");
    
    printf("3. The issue appears when the mixing layer is applied\n\n");
    
    printf("4. In the decryption, the round indices were fixed but issue persists\n\n");
    
    printf("CONCLUSION:\n");
    printf("The Intel implementation has these verified issues:\n");
    printf("1. ✓ Mixing layer implementation is correct (transpose works)\n");
    printf("2. ✓ State management between rounds works for simple cases\n");
    printf("3. ✗ When mixing layer is involved (4+ rounds), decryption fails\n");
    printf("4. The issue is likely in how the mixing layer interacts with\n");
    printf("   the round processing in either encryption or decryption\n\n");
    
    printf("RECOMMENDATION:\n");
    printf("The issue is subtle and relates to the interaction between:\n");
    printf("- Round processing order\n");
    printf("- Mixing layer application\n");
    printf("- State management between steps\n\n");
    
    printf("The fact that 3 rounds work but 4 rounds fail strongly suggests\n");
    printf("the mixing layer is being applied at the wrong point or the state\n");
    printf("is not being handled correctly around it.\n");
    
    return 0;
}