// Test program to verify Vistrutah specification compliance
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "vistrutah_portable.h"

// Function prototypes for the corrected implementation
void vistrutah_256_encrypt_fixed(const uint8_t* plaintext, uint8_t* ciphertext,
                                const uint8_t* key, int key_size, int rounds);
void vistrutah_256_decrypt_fixed(const uint8_t* ciphertext, uint8_t* plaintext,
                                const uint8_t* key, int key_size, int rounds);
void test_vistrutah_256_fixed(void);

// Function prototypes for the original implementation
extern void vistrutah_256_encrypt(const uint8_t* plaintext, uint8_t* ciphertext,
                                  const uint8_t* key, int key_size, int rounds);
extern void vistrutah_256_decrypt(const uint8_t* ciphertext, uint8_t* plaintext,
                                  const uint8_t* key, int key_size, int rounds);

void print_hex(const char* label, const uint8_t* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i < len - 1) printf(" ");
    }
    printf("\n");
}

void test_encryption_decryption() {
    printf("\n=== Testing Encryption/Decryption Roundtrip ===\n");
    
    // Test data
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t plaintext[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    
    uint8_t ciphertext_orig[32];
    uint8_t ciphertext_fixed[32];
    uint8_t decrypted_orig[32];
    uint8_t decrypted_fixed[32];
    
    // Test original implementation
    printf("\n1. Original Implementation:\n");
    vistrutah_256_encrypt(plaintext, ciphertext_orig, key, 32, 10);
    print_hex("Ciphertext", ciphertext_orig, 32);
    
    vistrutah_256_decrypt(ciphertext_orig, decrypted_orig, key, 32, 10);
    print_hex("Decrypted ", decrypted_orig, 32);
    
    int orig_match = memcmp(plaintext, decrypted_orig, 32) == 0;
    printf("Roundtrip test: %s\n", orig_match ? "PASSED" : "FAILED");
    
    // Test corrected implementation
    printf("\n2. Corrected Implementation:\n");
    vistrutah_256_encrypt_fixed(plaintext, ciphertext_fixed, key, 32, 10);
    print_hex("Ciphertext", ciphertext_fixed, 32);
    
    vistrutah_256_decrypt_fixed(ciphertext_fixed, decrypted_fixed, key, 32, 10);
    print_hex("Decrypted ", decrypted_fixed, 32);
    
    int fixed_match = memcmp(plaintext, decrypted_fixed, 32) == 0;
    printf("Roundtrip test: %s\n", fixed_match ? "PASSED" : "FAILED");
    
    // Compare outputs
    printf("\n3. Implementation Comparison:\n");
    int cipher_match = memcmp(ciphertext_orig, ciphertext_fixed, 32) == 0;
    printf("Ciphertexts match: %s\n", cipher_match ? "YES" : "NO");
}

void analyze_key_schedule() {
    printf("\n=== Analyzing Key Schedule ===\n");
    
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    printf("\nKey material:\n");
    print_hex("K0", key, 16);
    print_hex("K1", key + 16, 16);
    
    printf("\nAccording to specification:\n");
    printf("- Even rounds: Use fixed key K0 (with MC^-1 for decryption)\n");
    printf("- Odd rounds: Use variable key (k0 or k1) XOR round constant\n");
    printf("- Initial: k0 = K1, k1 = K0 (swapped)\n");
    printf("- Update: k_i = ρ_{i mod 2}(k_i) after each use\n");
}

void test_mixing_layer() {
    printf("\n=== Testing Mixing Layer ===\n");
    
    // ASURA permutation for Vistrutah-256
    const uint8_t MIXING_PERM_256[32] = {
        0, 17, 2, 19, 4, 21, 6, 23, 8, 25, 10, 27, 12, 29, 14, 31,
        16, 1, 18, 3, 20, 5, 22, 7, 24, 9, 26, 11, 28, 13, 30, 15
    };
    
    // Test data
    uint8_t input[32];
    uint8_t output[32];
    uint8_t inverse[32];
    
    // Initialize with recognizable pattern
    for (int i = 0; i < 32; i++) {
        input[i] = i;
    }
    
    // Apply forward permutation
    for (int i = 0; i < 32; i++) {
        output[i] = input[MIXING_PERM_256[i]];
    }
    
    // Apply inverse permutation
    for (int i = 0; i < 32; i++) {
        inverse[MIXING_PERM_256[i]] = output[i];
    }
    
    // Check if inverse matches input
    int match = memcmp(input, inverse, 32) == 0;
    printf("ASURA permutation invertibility: %s\n", match ? "PASSED" : "FAILED");
    
    // Verify it's the correct ASURA permutation
    printf("\nASURA verification (first 8 mappings):\n");
    for (int i = 0; i < 8; i++) {
        printf("%d -> %d\n", i, MIXING_PERM_256[i]);
    }
}

int main() {
    printf("Vistrutah Specification Compliance Test\n");
    printf("======================================\n");
    
    // Run the corrected implementation test
    test_vistrutah_256_fixed();
    
    // Analyze key schedule
    analyze_key_schedule();
    
    // Test mixing layer
    test_mixing_layer();
    
    // Test encryption/decryption
    test_encryption_decryption();
    
    return 0;
}