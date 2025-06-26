#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "vistrutah_portable.h"

// Helper function to print hex bytes
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Test vectors (these would normally come from the specification)
void test_vistrutah_256() {
    printf("=== Testing Vistrutah-256 ===\n");
    
    // Test key and plaintext
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t plaintext[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    uint8_t ciphertext[32];
    uint8_t decrypted[32];
    
    // Test long version (14 rounds)
    printf("\nLong version (14 rounds):\n");
    print_hex("Key      ", key, 32);
    print_hex("Plaintext", plaintext, 32);
    
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    print_hex("Ciphertext", ciphertext, 32);
    
    vistrutah_256_decrypt(ciphertext, decrypted, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    print_hex("Decrypted", decrypted, 32);
    
    if (memcmp(plaintext, decrypted, 32) == 0) {
        printf("✓ Encryption/Decryption test PASSED\n");
    } else {
        printf("✗ Encryption/Decryption test FAILED\n");
    }
    
    // Test short version (10 rounds)
    printf("\nShort version (10 rounds):\n");
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_256_ROUNDS_SHORT);
    print_hex("Ciphertext", ciphertext, 32);
    
    vistrutah_256_decrypt(ciphertext, decrypted, key, 32, VISTRUTAH_256_ROUNDS_SHORT);
    if (memcmp(plaintext, decrypted, 32) == 0) {
        printf("✓ Short version test PASSED\n");
    } else {
        printf("✗ Short version test FAILED\n");
    }
}

void test_vistrutah_512() {
    printf("\n=== Testing Vistrutah-512 ===\n");
    
    // Test with 256-bit key
    uint8_t key256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    // Test with 512-bit key
    uint8_t key512[64];
    for (int i = 0; i < 64; i++) {
        key512[i] = i;
    }
    
    uint8_t plaintext[64];
    for (int i = 0; i < 64; i++) {
        plaintext[i] = (i * 17) & 0xff;
    }
    
    
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    // Test with 256-bit key, long version (14 rounds)
    printf("\n256-bit key, long version (14 rounds):\n");
    print_hex("Key      ", key256, 32);
    print_hex("Plaintext", plaintext, 64);
    
    vistrutah_512_encrypt(plaintext, ciphertext, key256, 32, VISTRUTAH_512_ROUNDS_LONG_256KEY);
    print_hex("Ciphertext", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key256, 32, VISTRUTAH_512_ROUNDS_LONG_256KEY);
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ 256-bit key test PASSED\n");
    } else {
        printf("✗ 256-bit key test FAILED\n");
    }
    
    // Test with 512-bit key, long version (18 rounds)
    printf("\n512-bit key, long version (18 rounds):\n");
    print_hex("Key      ", key512, 64);
    
    vistrutah_512_encrypt(plaintext, ciphertext, key512, 64, VISTRUTAH_512_ROUNDS_LONG_512KEY);
    print_hex("Ciphertext", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key512, 64, VISTRUTAH_512_ROUNDS_LONG_512KEY);
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("✓ 512-bit key test PASSED\n");
    } else {
        printf("✗ 512-bit key test FAILED\n");
    }
}

// Test vectors from specification (if available)
void test_official_vectors() {
    printf("\n=== Official Test Vectors ===\n");
    
    // Vistrutah-256 test vectors
    struct {
        uint8_t key[32];
        uint8_t plaintext[32];
        uint8_t expected[32];
        int rounds;
        const char* description;
    } vistrutah256_vectors[] = {
        // Test vector 1: All zeros
        {
            {0}, // key
            {0}, // plaintext
            {0}, // expected (to be computed)
            VISTRUTAH_256_ROUNDS_LONG,
            "All zeros"
        },
        // Test vector 2: Sequential bytes
        {
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
             0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            {0}, // expected (to be computed)
            VISTRUTAH_256_ROUNDS_LONG,
            "Sequential pattern"
        },
        // Test vector 3: All ones
        {
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            {0}, // expected (to be computed)
            VISTRUTAH_256_ROUNDS_LONG,
            "All ones"
        }
    };
    
    printf("\nVistrutah-256 vectors:\n");
    for (size_t i = 0; i < sizeof(vistrutah256_vectors)/sizeof(vistrutah256_vectors[0]); i++) {
        uint8_t output[32];
        uint8_t decrypted[32];
        
        printf("\nTest %zu: %s\n", i+1, vistrutah256_vectors[i].description);
        print_hex("Key      ", vistrutah256_vectors[i].key, 32);
        print_hex("Plaintext", vistrutah256_vectors[i].plaintext, 32);
        
        vistrutah_256_encrypt(vistrutah256_vectors[i].plaintext, output, 
                             vistrutah256_vectors[i].key, 32, 
                             vistrutah256_vectors[i].rounds);
        print_hex("Ciphertext", output, 32);
        
        // Verify decryption
        vistrutah_256_decrypt(output, decrypted, 
                             vistrutah256_vectors[i].key, 32, 
                             vistrutah256_vectors[i].rounds);
        
        if (memcmp(vistrutah256_vectors[i].plaintext, decrypted, 32) == 0) {
            printf("✓ Decryption verified\n");
        } else {
            printf("✗ Decryption FAILED\n");
        }
    }
}

void test_avalanche() {
    printf("\n=== Avalanche Effect Test ===\n");
    
    uint8_t key[32] = {0};
    uint8_t plaintext1[32] = {0};
    uint8_t plaintext2[32] = {0};
    uint8_t ciphertext1[32];
    uint8_t ciphertext2[32];
    
    // Test 1: Single bit change in plaintext
    printf("\nTest 1: Single bit change in plaintext\n");
    plaintext2[0] = 0x01;  // Single bit difference
    
    vistrutah_256_encrypt(plaintext1, ciphertext1, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    vistrutah_256_encrypt(plaintext2, ciphertext2, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    
    // Count bit differences
    int bit_diff = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
        for (int j = 0; j < 8; j++) {
            if (diff & (1 << j)) bit_diff++;
        }
    }
    printf("Bit differences: %d/256 (%.1f%%)\n", bit_diff, bit_diff * 100.0 / 256);
    printf("Expected: ~50%% (good avalanche should be 45-55%%)\n");
    
    // Test 2: Single bit change in key
    printf("\nTest 2: Single bit change in key\n");
    memset(plaintext2, 0, 32);  // Reset plaintext2
    uint8_t key2[32] = {0};
    key2[0] = 0x01;  // Single bit difference in key
    
    vistrutah_256_encrypt(plaintext1, ciphertext1, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    vistrutah_256_encrypt(plaintext1, ciphertext2, key2, 32, VISTRUTAH_256_ROUNDS_LONG);
    
    bit_diff = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
        for (int j = 0; j < 8; j++) {
            if (diff & (1 << j)) bit_diff++;
        }
    }
    printf("Bit differences: %d/256 (%.1f%%)\n", bit_diff, bit_diff * 100.0 / 256);
    
    // Test 3: Progressive avalanche (how many rounds until good diffusion)
    printf("\nTest 3: Progressive avalanche by round\n");
    plaintext2[0] = 0x01;
    for (int rounds = 1; rounds <= 20; rounds++) {
        vistrutah_256_encrypt(plaintext1, ciphertext1, key, 32, rounds);
        vistrutah_256_encrypt(plaintext2, ciphertext2, key, 32, rounds);
        
        bit_diff = 0;
        for (int i = 0; i < 32; i++) {
            uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
            for (int j = 0; j < 8; j++) {
                if (diff & (1 << j)) bit_diff++;
            }
        }
        printf("Round %2d: %3d bits changed (%.1f%%)\n", 
               rounds, bit_diff, bit_diff * 100.0 / 256);
    }
}

void test_diffusion() {
    printf("\n=== Diffusion Test ===\n");
    printf("Testing how changes propagate through the cipher\n");
    
    uint8_t key[32] = {0};
    uint8_t plaintext[32] = {0};
    uint8_t reference[32];
    
    // Get reference ciphertext
    vistrutah_256_encrypt(plaintext, reference, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    
    // Test each input byte position
    printf("\nChanging each plaintext byte position:\n");
    for (int pos = 0; pos < 32; pos++) {
        uint8_t test_plaintext[32] = {0};
        uint8_t ciphertext[32];
        test_plaintext[pos] = 0xff;
        
        vistrutah_256_encrypt(test_plaintext, ciphertext, key, 32, VISTRUTAH_256_ROUNDS_LONG);
        
        // Count affected output bytes
        int affected_bytes = 0;
        for (int i = 0; i < 32; i++) {
            if (ciphertext[i] != reference[i]) {
                affected_bytes++;
            }
        }
        
        if (pos % 8 == 0) printf("\n");
        printf("Pos %2d: %2d bytes affected  ", pos, affected_bytes);
    }
    printf("\n\nGood diffusion: all positions should affect most output bytes\n");
}

void test_key_schedule() {
    printf("\n=== Key Schedule Test ===\n");
    
    // Test that similar keys produce different round keys
    uint8_t key1[32] = {0};
    uint8_t key2[32] = {0};
    key2[0] = 0x01;  // Single bit difference
    
    uint8_t plaintext[32] = {0};
    uint8_t ciphertext1[32];
    uint8_t ciphertext2[32];
    
    // Test with various round counts to see key schedule impact
    printf("\nTesting key schedule diffusion:\n");
    for (int rounds = 1; rounds <= 20; rounds += 2) {
        vistrutah_256_encrypt(plaintext, ciphertext1, key1, 32, rounds);
        vistrutah_256_encrypt(plaintext, ciphertext2, key2, 32, rounds);
        
        int bit_diff = 0;
        for (int i = 0; i < 32; i++) {
            uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
            for (int j = 0; j < 8; j++) {
                if (diff & (1 << j)) bit_diff++;
            }
        }
        printf("Round %2d: %3d bits different (%.1f%%)\n", 
               rounds, bit_diff, bit_diff * 100.0 / 256);
    }
}

void test_edge_cases() {
    printf("\n=== Edge Case Tests ===\n");
    
    uint8_t output[64];
    uint8_t decrypted[64];
    int passed = 0;
    int total = 0;
    
    // Test 1: All zeros
    printf("\nTest 1: All zeros\n");
    uint8_t zeros[64] = {0};
    vistrutah_256_encrypt(zeros, output, zeros, 32, VISTRUTAH_256_ROUNDS_LONG);
    vistrutah_256_decrypt(output, decrypted, zeros, 32, VISTRUTAH_256_ROUNDS_LONG);
    total++;
    if (memcmp(zeros, decrypted, 32) == 0) {
        printf("✓ All zeros test passed\n");
        passed++;
    } else {
        printf("✗ All zeros test failed\n");
    }
    
    // Test 2: All ones
    printf("\nTest 2: All ones\n");
    uint8_t ones[64];
    memset(ones, 0xff, 64);
    vistrutah_256_encrypt(ones, output, ones, 32, VISTRUTAH_256_ROUNDS_LONG);
    vistrutah_256_decrypt(output, decrypted, ones, 32, VISTRUTAH_256_ROUNDS_LONG);
    total++;
    if (memcmp(ones, decrypted, 32) == 0) {
        printf("✓ All ones test passed\n");
        passed++;
    } else {
        printf("✗ All ones test failed\n");
    }
    
    // Test 3: Alternating pattern
    printf("\nTest 3: Alternating 0xAA/0x55 pattern\n");
    uint8_t pattern[64];
    for (int i = 0; i < 64; i++) {
        pattern[i] = (i % 2) ? 0xAA : 0x55;
    }
    vistrutah_256_encrypt(pattern, output, pattern, 32, VISTRUTAH_256_ROUNDS_LONG);
    vistrutah_256_decrypt(output, decrypted, pattern, 32, VISTRUTAH_256_ROUNDS_LONG);
    total++;
    if (memcmp(pattern, decrypted, 32) == 0) {
        printf("✓ Pattern test passed\n");
        passed++;
    } else {
        printf("✗ Pattern test failed\n");
    }
    
    // Test 4: Single bit set
    printf("\nTest 4: Single bit set\n");
    uint8_t single_bit[32] = {0};
    single_bit[0] = 0x80;
    vistrutah_256_encrypt(single_bit, output, zeros, 32, VISTRUTAH_256_ROUNDS_LONG);
    vistrutah_256_decrypt(output, decrypted, zeros, 32, VISTRUTAH_256_ROUNDS_LONG);
    total++;
    if (memcmp(single_bit, decrypted, 32) == 0) {
        printf("✓ Single bit test passed\n");
        passed++;
    } else {
        printf("✗ Single bit test failed\n");
    }
    
    printf("\nEdge cases: %d/%d passed\n", passed, total);
}

void test_consistency() {
    printf("\n=== Consistency Test ===\n");
    printf("Testing multiple encrypt/decrypt cycles\n");
    
    uint8_t key[32];
    uint8_t plaintext[32];
    uint8_t temp1[32];
    uint8_t temp2[32];
    
    // Random key and plaintext
    srand(time(NULL));
    for (int i = 0; i < 32; i++) {
        key[i] = rand() & 0xff;
        plaintext[i] = rand() & 0xff;
    }
    
    memcpy(temp1, plaintext, 32);
    
    // Multiple encrypt/decrypt cycles
    const int cycles = 100;
    for (int i = 0; i < cycles; i++) {
        vistrutah_256_encrypt(temp1, temp2, key, 32, VISTRUTAH_256_ROUNDS_LONG);
        vistrutah_256_decrypt(temp2, temp1, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    }
    
    if (memcmp(plaintext, temp1, 32) == 0) {
        printf("✓ %d encrypt/decrypt cycles passed\n", cycles);
    } else {
        printf("✗ Consistency test failed after %d cycles\n", cycles);
    }
}

int main() {
    printf("Vistrutah Block Cipher Test Suite\n");
    printf("=================================\n");
    printf("Implementation: %s\n", vistrutah_get_impl_name());
    printf("Hardware AES: %s\n\n", vistrutah_has_aes_accel() ? "Yes" : "No");
    
    // Basic functionality tests
    test_vistrutah_256();
    test_vistrutah_512();
    
    // Test vectors
    test_official_vectors();
    
    // Cryptographic property tests
    test_avalanche();
    test_diffusion();
    test_key_schedule();
    
    // Edge cases and consistency
    test_edge_cases();
    test_consistency();
    
    printf("\n=== All Tests Completed ===\n");
    
    return 0;
}