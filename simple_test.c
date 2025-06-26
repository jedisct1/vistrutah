#include <stdio.h>
#include <string.h>
#include "vistrutah.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Test with all zeros to establish baseline
void test_zeros() {
    printf("Test 1: All zeros\n");
    printf("-----------------\n");
    
    uint8_t key[32] = {0};
    uint8_t plaintext[32] = {0};
    uint8_t ciphertext[32];
    
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 14);
    print_hex("Key       ", key, 32);
    print_hex("Plaintext ", plaintext, 32);
    print_hex("Ciphertext", ciphertext, 32);
    printf("\n");
}

// Test with incrementing pattern
void test_pattern() {
    printf("Test 2: Incrementing pattern\n");
    printf("----------------------------\n");
    
    uint8_t key[32];
    uint8_t plaintext[32];
    uint8_t ciphertext[32];
    
    for (int i = 0; i < 32; i++) {
        key[i] = i;
        plaintext[i] = i + 32;
    }
    
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 14);
    print_hex("Key       ", key, 32);
    print_hex("Plaintext ", plaintext, 32);
    print_hex("Ciphertext", ciphertext, 32);
    printf("\n");
}

// Test single bit change
void test_avalanche() {
    printf("Test 3: Avalanche effect (single bit change)\n");
    printf("--------------------------------------------\n");
    
    uint8_t key[32] = {0};
    uint8_t plaintext1[32] = {0};
    uint8_t plaintext2[32] = {0};
    uint8_t ciphertext1[32];
    uint8_t ciphertext2[32];
    
    plaintext2[0] = 0x01;  // Single bit difference
    
    vistrutah_256_encrypt(plaintext1, ciphertext1, key, 32, 14);
    vistrutah_256_encrypt(plaintext2, ciphertext2, key, 32, 14);
    
    print_hex("Plaintext1 ", plaintext1, 32);
    print_hex("Ciphertext1", ciphertext1, 32);
    print_hex("Plaintext2 ", plaintext2, 32);
    print_hex("Ciphertext2", ciphertext2, 32);
    
    // Count bit differences
    int bit_diff = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
        for (int j = 0; j < 8; j++) {
            if (diff & (1 << j)) bit_diff++;
        }
    }
    printf("Bit differences: %d/256 (%.1f%%)\n\n", bit_diff, bit_diff * 100.0 / 256);
}

// Test encryption consistency
void test_consistency() {
    printf("Test 4: Encryption consistency\n");
    printf("------------------------------\n");
    
    uint8_t key[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t plaintext[32] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t ciphertext1[32];
    uint8_t ciphertext2[32];
    
    // Encrypt twice - should get same result
    vistrutah_256_encrypt(plaintext, ciphertext1, key, 32, 14);
    vistrutah_256_encrypt(plaintext, ciphertext2, key, 32, 14);
    
    if (memcmp(ciphertext1, ciphertext2, 32) == 0) {
        printf("✓ Encryption is consistent\n");
    } else {
        printf("✗ Encryption is NOT consistent!\n");
    }
    
    print_hex("Ciphertext", ciphertext1, 32);
    printf("\n");
}

// Self-inverse test for mixing layer
void test_mixing_inverse() {
    printf("Test 5: Mixing layer self-inverse property\n");
    printf("------------------------------------------\n");
    
    // The implementation detail - we'll test if applying mix twice gives original
    // This is a white-box test that assumes access to internals
    printf("Note: This would require exposing internal functions\n\n");
}

int main() {
    printf("Vistrutah Simplified Correctness Tests\n");
    printf("=====================================\n\n");
    
    test_zeros();
    test_pattern();
    test_avalanche();
    test_consistency();
    test_mixing_inverse();
    
    printf("Note: Without official test vectors, we can verify:\n");
    printf("- Consistency (same input → same output)\n");
    printf("- Avalanche effect (small input change → large output change)\n");
    printf("- Non-trivial output (not all zeros/ones)\n");
    printf("- Performance characteristics match specification\n");
    
    return 0;
}