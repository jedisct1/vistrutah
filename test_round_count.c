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

void test_specific_rounds(int rounds) {
    printf("\nTesting with %d rounds:\n", rounds);
    
    uint8_t key[32] = {0};
    uint8_t plaintext[64] = {0};
    plaintext[0] = 0x01;  // Single non-zero byte
    
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, rounds);
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, rounds);
    
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ PASS - Round trip successful\n");
    } else {
        printf("✗ FAIL - Round trip failed\n");
        print_hex("Expected", plaintext, 16);
        print_hex("Got", decrypted, 16);
    }
}

int main() {
    printf("Testing round count issues\n");
    printf("==========================\n");
    
    // Test various round counts
    test_specific_rounds(1);
    test_specific_rounds(2);
    test_specific_rounds(3);
    test_specific_rounds(4);
    test_specific_rounds(5);
    test_specific_rounds(6);
    test_specific_rounds(10);
    test_specific_rounds(14);
    
    printf("\n\nPattern analysis:\n");
    printf("- Rounds 1-2: PASS (1 step, no mixing)\n");
    printf("- Rounds 3+: FAIL\n");
    printf("\nThis suggests the issue happens when:\n");
    printf("1. There's an odd round (3, 5, etc.)\n");
    printf("2. OR there's mixing between steps (4+)\n");
    
    return 0;
}