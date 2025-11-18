#include "vistrutah.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_ROUNDS 18

void
print_hex(const char* label, const uint8_t* data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Test vectors (these would normally come from the specification)
void
test_vistrutah_256()
{
    printf("=== Testing Vistrutah-256 ===\n");

    // Test key and plaintext
    uint8_t key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    uint8_t plaintext[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
                              0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                              0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };

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

void
test_vistrutah_512()
{
    printf("\n=== Testing Vistrutah-512 ===\n");

    // Test with 256-bit key
    uint8_t key256[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                           0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                           0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

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

// Comprehensive test vectors for all cipher variants
void
test_comprehensive_vectors()
{
    printf("\n=== Comprehensive Test Vectors ===\n");

    // Vistrutah-256 test vectors
    struct {
        uint8_t     key[32];
        int         key_size;
        uint8_t     plaintext[32];
        int         rounds;
        const char* description;
    } vistrutah256_vectors[] = {
        // Test vector 1: All zeros, 128-bit key, short rounds
        { { 0 }, // key
          16, // key_size
          { 0 }, // plaintext
          VISTRUTAH_256_ROUNDS_SHORT,
          "All zeros, 128-bit key, 10 rounds" },
        // Test vector 2: All zeros, 256-bit key, long rounds
        { { 0 }, // key
          32, // key_size
          { 0 }, // plaintext
          VISTRUTAH_256_ROUNDS_LONG,
          "All zeros, 256-bit key, 14 rounds" },
        // Test vector 3: Sequential bytes, 256-bit key
        { { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
          32, // key_size
          { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 },
          VISTRUTAH_256_ROUNDS_LONG,
          "Sequential pattern, 256-bit key, 14 rounds" },
        // Test vector 4: All ones, 256-bit key
        { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
          32, // key_size
          { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
          VISTRUTAH_256_ROUNDS_LONG,
          "All ones, 256-bit key, 14 rounds" },
        // Test vector 5: Random-like pattern
        { { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
            0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b,
            0x4d, 0xa5, 0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19, 0x0c, 0xfe },
          32, // key_size
          { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98,
            0xa2, 0xe0, 0x37, 0x07, 0x34, 0x4a, 0x40, 0x93, 0x82, 0x22, 0x99,
            0xf3, 0x1d, 0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8 },
          VISTRUTAH_256_ROUNDS_SHORT,
          "Random-like pattern, 256-bit key, 10 rounds" }
    };

    // Vistrutah-512 test vectors
    struct {
        uint8_t     key[64];
        int         key_size;
        uint8_t     plaintext[64];
        int         rounds;
        const char* description;
    } vistrutah512_vectors[] = {
        // Test vector 1: All zeros, 256-bit key, short rounds
        { { 0 }, // key
          32, // key_size
          { 0 }, // plaintext
          VISTRUTAH_512_ROUNDS_SHORT_256KEY,
          "All zeros, 256-bit key, 10 rounds" },
        // Test vector 2: All zeros, 256-bit key, long rounds
        { { 0 }, // key
          32, // key_size
          { 0 }, // plaintext
          VISTRUTAH_512_ROUNDS_LONG_256KEY,
          "All zeros, 256-bit key, 14 rounds" },
        // Test vector 3: All zeros, 512-bit key, short rounds
        { { 0 }, // key
          64, // key_size
          { 0 }, // plaintext
          VISTRUTAH_512_ROUNDS_SHORT_512KEY,
          "All zeros, 512-bit key, 12 rounds" },
        // Test vector 4: All zeros, 512-bit key, long rounds
        { { 0 }, // key
          64, // key_size
          { 0 }, // plaintext
          VISTRUTAH_512_ROUNDS_LONG_512KEY,
          "All zeros, 512-bit key, 18 rounds" },
        // Test vector 5: Sequential pattern, 256-bit key
        { { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
          32, // key_size
          { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
            0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69,
            0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x0f },
          VISTRUTAH_512_ROUNDS_LONG_256KEY,
          "Sequential pattern, 256-bit key, 14 rounds" },
        // Test vector 6: Full 512-bit key with pattern
        { // Generate full 512-bit key pattern
          { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
            0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f },
          64, // key_size
          { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
            0x22, 0x11, 0x00, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23,
            0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96,
            0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f, 0x0f, 0x1e, 0x2d, 0x3c,
            0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0 },
          VISTRUTAH_512_ROUNDS_LONG_512KEY,
          "Full pattern, 512-bit key, 18 rounds" }
    };

    printf("\n=== Vistrutah-256 Test Vectors ===\n");
    for (size_t i = 0; i < sizeof(vistrutah256_vectors) / sizeof(vistrutah256_vectors[0]); i++) {
        uint8_t output[32];
        uint8_t decrypted[32];

        printf("\nVector %zu: %s\n", i + 1, vistrutah256_vectors[i].description);
        print_hex("Key      ", vistrutah256_vectors[i].key, vistrutah256_vectors[i].key_size);
        print_hex("Plaintext", vistrutah256_vectors[i].plaintext, 32);

        vistrutah_256_encrypt(vistrutah256_vectors[i].plaintext, output,
                              vistrutah256_vectors[i].key, vistrutah256_vectors[i].key_size,
                              vistrutah256_vectors[i].rounds);
        print_hex("Ciphertext", output, 32);

        // Verify decryption
        vistrutah_256_decrypt(output, decrypted, vistrutah256_vectors[i].key,
                              vistrutah256_vectors[i].key_size, vistrutah256_vectors[i].rounds);

        if (memcmp(vistrutah256_vectors[i].plaintext, decrypted, 32) == 0) {
            printf("✓ Encrypt/Decrypt verified\n");
        } else {
            printf("✗ Encrypt/Decrypt FAILED\n");
            print_hex("Expected ", vistrutah256_vectors[i].plaintext, 32);
            print_hex("Got      ", decrypted, 32);
        }
    }

    printf("\n=== Vistrutah-512 Test Vectors ===\n");
    for (size_t i = 0; i < sizeof(vistrutah512_vectors) / sizeof(vistrutah512_vectors[0]); i++) {
        uint8_t output[64];
        uint8_t decrypted[64];

        printf("\nVector %zu: %s\n", i + 1, vistrutah512_vectors[i].description);
        print_hex("Key      ", vistrutah512_vectors[i].key, vistrutah512_vectors[i].key_size);
        print_hex("Plaintext", vistrutah512_vectors[i].plaintext, 64);

        vistrutah_512_encrypt(vistrutah512_vectors[i].plaintext, output,
                              vistrutah512_vectors[i].key, vistrutah512_vectors[i].key_size,
                              vistrutah512_vectors[i].rounds);
        print_hex("Ciphertext", output, 64);

        // Verify decryption
        vistrutah_512_decrypt(output, decrypted, vistrutah512_vectors[i].key,
                              vistrutah512_vectors[i].key_size, vistrutah512_vectors[i].rounds);

        if (memcmp(vistrutah512_vectors[i].plaintext, decrypted, 64) == 0) {
            printf("✓ Encrypt/Decrypt verified\n");
        } else {
            printf("✗ Encrypt/Decrypt FAILED\n");
            print_hex("Expected ", vistrutah512_vectors[i].plaintext, 64);
            print_hex("Got      ", decrypted, 64);
        }
    }
}

void
test_avalanche()
{
    printf("\n=== Avalanche Effect Test ===\n");

    uint8_t key[32]        = { 0 };
    uint8_t plaintext1[32] = { 0 };
    uint8_t plaintext2[32] = { 0 };
    uint8_t ciphertext1[32];
    uint8_t ciphertext2[32];

    // Test 1: Single bit change in plaintext
    printf("\nTest 1: Single bit change in plaintext\n");
    plaintext2[0] = 0x01; // Single bit difference

    vistrutah_256_encrypt(plaintext1, ciphertext1, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    vistrutah_256_encrypt(plaintext2, ciphertext2, key, 32, VISTRUTAH_256_ROUNDS_LONG);

    // Count bit differences
    int bit_diff = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
        for (int j = 0; j < 8; j++) {
            if (diff & (1 << j))
                bit_diff++;
        }
    }
    printf("Bit differences: %d/256 (%.1f%%)\n", bit_diff, bit_diff * 100.0 / 256);
    printf("Expected: ~50%% (good avalanche should be 45-55%%)\n");

    // Test 2: Single bit change in key
    printf("\nTest 2: Single bit change in key\n");
    memset(plaintext2, 0, 32); // Reset plaintext2
    uint8_t key2[32] = { 0 };
    key2[0]          = 0x01; // Single bit difference in key

    vistrutah_256_encrypt(plaintext1, ciphertext1, key, 32, VISTRUTAH_256_ROUNDS_LONG);
    vistrutah_256_encrypt(plaintext1, ciphertext2, key2, 32, VISTRUTAH_256_ROUNDS_LONG);

    bit_diff = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
        for (int j = 0; j < 8; j++) {
            if (diff & (1 << j))
                bit_diff++;
        }
    }
    printf("Bit differences: %d/256 (%.1f%%)\n", bit_diff, bit_diff * 100.0 / 256);

    // Test 3: Progressive avalanche (how many rounds until good diffusion)
    printf("\nTest 3: Progressive avalanche by round\n");
    plaintext2[0] = 0x01;
    for (int rounds = 1; rounds <= MAX_ROUNDS; rounds++) {
        vistrutah_256_encrypt(plaintext1, ciphertext1, key, 32, rounds);
        vistrutah_256_encrypt(plaintext2, ciphertext2, key, 32, rounds);

        bit_diff = 0;
        for (int i = 0; i < 32; i++) {
            uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
            for (int j = 0; j < 8; j++) {
                if (diff & (1 << j))
                    bit_diff++;
            }
        }
        printf("Round %2d: %3d bits changed (%.1f%%)\n", rounds, bit_diff, bit_diff * 100.0 / 256);
    }
}

void
test_diffusion()
{
    printf("\n=== Diffusion Test ===\n");
    printf("Testing how changes propagate through the cipher\n");

    uint8_t key[32]       = { 0 };
    uint8_t plaintext[32] = { 0 };
    uint8_t reference[32];

    // Get reference ciphertext
    vistrutah_256_encrypt(plaintext, reference, key, 32, VISTRUTAH_256_ROUNDS_LONG);

    // Test each input byte position
    printf("\nChanging each plaintext byte position:\n");
    for (int pos = 0; pos < 32; pos++) {
        uint8_t test_plaintext[32] = { 0 };
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

        if (pos % 8 == 0)
            printf("\n");
        printf("Pos %2d: %2d bytes affected  ", pos, affected_bytes);
    }
    printf("\n\nGood diffusion: all positions should affect most output bytes\n");
}

void
test_key_schedule()
{
    printf("\n=== Key Schedule Test ===\n");

    // Test that similar keys produce different round keys
    uint8_t key1[32] = { 0 };
    uint8_t key2[32] = { 0 };
    key2[0]          = 0x01; // Single bit difference

    uint8_t plaintext[32] = { 0 };
    uint8_t ciphertext1[32];
    uint8_t ciphertext2[32];

    // Test with various round counts to see key schedule impact
    printf("\nTesting key schedule diffusion:\n");
    for (int rounds = 1; rounds <= MAX_ROUNDS; rounds += 2) {
        vistrutah_256_encrypt(plaintext, ciphertext1, key1, 32, rounds);
        vistrutah_256_encrypt(plaintext, ciphertext2, key2, 32, rounds);

        int bit_diff = 0;
        for (int i = 0; i < 32; i++) {
            uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
            for (int j = 0; j < 8; j++) {
                if (diff & (1 << j))
                    bit_diff++;
            }
        }
        printf("Round %2d: %3d bits different (%.1f%%)\n", rounds, bit_diff,
               bit_diff * 100.0 / 256);
    }
}

void
test_edge_cases()
{
    printf("\n=== Edge Case Tests ===\n");

    uint8_t output[64];
    uint8_t decrypted[64];
    int     passed = 0;
    int     total  = 0;

    // Test 1: All zeros
    printf("\nTest 1: All zeros\n");
    uint8_t zeros[64] = { 0 };
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
    uint8_t single_bit[32] = { 0 };
    single_bit[0]          = 0x80;
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

// Helper to reverse bits in a byte (matches reference implementation)
static uint8_t
reverse_bits(uint8_t byte)
{
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 1) | (byte & 1);
        byte >>= 1;
    }
    return result;
}

// Test against reference implementation vectors
void
test_reference_vectors()
{
    printf("\n=== Reference Implementation Test Vectors ===\n");
    printf("Testing against /tmp/Vistrutah-code-isolated reference outputs\n");

    int total_tests  = 0;
    int passed_tests = 0;

    // Reference test uses: key[i] = reverse_bits(i+1), plaintext[i] = i

    // Vistrutah-256 test vectors
    {
        uint8_t key[32];
        uint8_t plaintext[32];
        uint8_t ciphertext[32];
        uint8_t decrypted[32];

        // Initialize key and plaintext as reference implementation does
        for (int i = 0; i < 32; i++) {
            key[i]       = reverse_bits(i + 1);
            plaintext[i] = i;
        }

        // Test 1: Vistrutah-256, 10 rounds (short)
        printf("\nVistrutah-256, 10 rounds (ROUNDS_SHORT):\n");
        uint8_t expected_256_10r[32] = { 0xA9, 0x80, 0x3C, 0xC5, 0x4F, 0x27, 0x74, 0x53,
                                         0x66, 0xA4, 0xF7, 0xE7, 0x99, 0xA3, 0x4E, 0x24,
                                         0xF4, 0xC6, 0x9E, 0x37, 0xC2, 0x7E, 0x13, 0xC0,
                                         0x32, 0xD8, 0x0E, 0xE5, 0x7F, 0x9F, 0xA3, 0x6E };

        vistrutah_256_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_256_ROUNDS_SHORT);
        total_tests++;
        if (memcmp(ciphertext, expected_256_10r, 32) == 0) {
            printf("✓ Encryption matches reference\n");
            passed_tests++;
        } else {
            printf("✗ Encryption FAILED - does not match reference!\n");
            print_hex("Expected ", expected_256_10r, 32);
            print_hex("Got      ", ciphertext, 32);
            exit(1); // Fail fast
        }

        // Verify decryption
        vistrutah_256_decrypt(ciphertext, decrypted, key, 32, VISTRUTAH_256_ROUNDS_SHORT);
        total_tests++;
        if (memcmp(plaintext, decrypted, 32) == 0) {
            printf("✓ Decryption matches original plaintext\n");
            passed_tests++;
        } else {
            printf("✗ Decryption FAILED!\n");
            print_hex("Expected ", plaintext, 32);
            print_hex("Got      ", decrypted, 32);
            exit(1); // Fail fast
        }

        // Test 2: Vistrutah-256, 14 rounds (long)
        printf("\nVistrutah-256, 14 rounds (ROUNDS_LONG):\n");
        uint8_t expected_256_14r[32] = { 0x04, 0x22, 0x7D, 0x3C, 0xD0, 0x0D, 0x1C, 0x7B,
                                         0xE7, 0xDA, 0x78, 0x6B, 0x8C, 0x88, 0xF9, 0x59,
                                         0x4E, 0x11, 0x43, 0x17, 0x22, 0x1C, 0x74, 0x30,
                                         0xB4, 0x7E, 0xD2, 0x1E, 0x8E, 0xB1, 0x5B, 0xBD };

        vistrutah_256_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_256_ROUNDS_LONG);
        total_tests++;
        if (memcmp(ciphertext, expected_256_14r, 32) == 0) {
            printf("✓ Encryption matches reference\n");
            passed_tests++;
        } else {
            printf("✗ Encryption FAILED - does not match reference!\n");
            print_hex("Expected ", expected_256_14r, 32);
            print_hex("Got      ", ciphertext, 32);
            exit(1); // Fail fast
        }

        vistrutah_256_decrypt(ciphertext, decrypted, key, 32, VISTRUTAH_256_ROUNDS_LONG);
        total_tests++;
        if (memcmp(plaintext, decrypted, 32) == 0) {
            printf("✓ Decryption matches original plaintext\n");
            passed_tests++;
        } else {
            printf("✗ Decryption FAILED!\n");
            print_hex("Expected ", plaintext, 32);
            print_hex("Got      ", decrypted, 32);
            exit(1); // Fail fast
        }
    }

    // Vistrutah-512 test vectors
    {
        uint8_t key[32];
        uint8_t plaintext[64];
        uint8_t ciphertext[64];
        uint8_t decrypted[64];

        // Initialize key and plaintext as reference implementation does
        for (int i = 0; i < 32; i++) {
            key[i] = reverse_bits(i + 1);
        }
        for (int i = 0; i < 64; i++) {
            plaintext[i] = i;
        }

        // Test 3: Vistrutah-512, 10 rounds, 256-bit key
        printf("\nVistrutah-512, 10 rounds, 256-bit key (ROUNDS_SHORT_256KEY):\n");
        uint8_t expected_512_10r[64] = { 0x09, 0xC3, 0x87, 0x69, 0x84, 0x35, 0x50, 0x41, 0xA4, 0x9A,
                                         0xCF, 0x0C, 0xB8, 0x68, 0xE2, 0x64, 0x58, 0x52, 0x35, 0xE0,
                                         0x58, 0x20, 0x05, 0x5C, 0x80, 0x8A, 0x3A, 0x03, 0xEA, 0xAE,
                                         0x15, 0x7B, 0x00, 0x10, 0x0B, 0xC9, 0xB3, 0x01, 0x16, 0x96,
                                         0xC0, 0xE1, 0xE8, 0x95, 0xE2, 0x16, 0x0C, 0xCC, 0xEF, 0x31,
                                         0xA3, 0x45, 0x4E, 0x21, 0x6C, 0xA0, 0x1B, 0xCF, 0x63, 0x66,
                                         0xF5, 0x84, 0xE2, 0x36 };

        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_512_ROUNDS_SHORT_256KEY);
        total_tests++;
        if (memcmp(ciphertext, expected_512_10r, 64) == 0) {
            printf("✓ Encryption matches reference\n");
            passed_tests++;
        } else {
            printf("✗ Encryption FAILED - does not match reference!\n");
            print_hex("Expected ", expected_512_10r, 64);
            print_hex("Got      ", ciphertext, 64);
            exit(1); // Fail fast
        }

        vistrutah_512_decrypt(ciphertext, decrypted, key, 32, VISTRUTAH_512_ROUNDS_SHORT_256KEY);
        total_tests++;
        if (memcmp(plaintext, decrypted, 64) == 0) {
            printf("✓ Decryption matches original plaintext\n");
            passed_tests++;
        } else {
            printf("✗ Decryption FAILED!\n");
            exit(1); // Fail fast
        }

        // Test 4: Vistrutah-512, 12 rounds, 256-bit key
        printf("\nVistrutah-512, 12 rounds, 256-bit key (ROUNDS_SHORT_512KEY):\n");
        uint8_t expected_512_12r[64] = { 0xA6, 0x90, 0x27, 0x48, 0xC6, 0xF1, 0xF9, 0x33, 0x3C, 0xA6,
                                         0x12, 0xB8, 0x5F, 0x86, 0x56, 0x1F, 0xD0, 0x46, 0x62, 0xE3,
                                         0xC4, 0x05, 0xAC, 0x50, 0x13, 0x16, 0x82, 0x6A, 0x70, 0x2F,
                                         0xCD, 0x4A, 0x23, 0x45, 0x94, 0xF8, 0xF9, 0xA5, 0xDD, 0xA2,
                                         0x78, 0xD4, 0x4C, 0xC7, 0x23, 0xF5, 0xB8, 0x76, 0x72, 0x00,
                                         0x0E, 0x42, 0x37, 0xE3, 0x82, 0x39, 0xC1, 0xBC, 0x06, 0x59,
                                         0x1D, 0xE6, 0x29, 0x7C };

        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_512_ROUNDS_SHORT_512KEY);
        total_tests++;
        if (memcmp(ciphertext, expected_512_12r, 64) == 0) {
            printf("✓ Encryption matches reference\n");
            passed_tests++;
        } else {
            printf("✗ Encryption FAILED - does not match reference!\n");
            print_hex("Expected ", expected_512_12r, 64);
            print_hex("Got      ", ciphertext, 64);
            exit(1); // Fail fast
        }

        vistrutah_512_decrypt(ciphertext, decrypted, key, 32, VISTRUTAH_512_ROUNDS_SHORT_512KEY);
        total_tests++;
        if (memcmp(plaintext, decrypted, 64) == 0) {
            printf("✓ Decryption matches original plaintext\n");
            passed_tests++;
        } else {
            printf("✗ Decryption FAILED!\n");
            exit(1); // Fail fast
        }

        // Test 5: Vistrutah-512, 14 rounds, 256-bit key
        printf("\nVistrutah-512, 14 rounds, 256-bit key (ROUNDS_LONG_256KEY):\n");
        uint8_t expected_512_14r[64] = { 0xA8, 0x75, 0xE9, 0xF9, 0x13, 0x0B, 0xE6, 0x8B, 0x68, 0x67,
                                         0xCB, 0x66, 0xF4, 0x03, 0x18, 0xEC, 0x7E, 0x16, 0xA3, 0xA0,
                                         0x50, 0x16, 0x51, 0xFF, 0xF3, 0xBE, 0x08, 0xFE, 0x70, 0xB3,
                                         0xC7, 0x96, 0x0D, 0x9B, 0x1A, 0x83, 0x44, 0xC9, 0xEB, 0x61,
                                         0xC2, 0xBF, 0xCB, 0xF2, 0xF6, 0x02, 0x8E, 0x1F, 0xCD, 0x94,
                                         0x6B, 0xFF, 0xC9, 0x5B, 0xB4, 0x2F, 0x9E, 0x0E, 0x87, 0x61,
                                         0x75, 0x83, 0x19, 0xE3 };

        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_512_ROUNDS_LONG_256KEY);
        total_tests++;
        if (memcmp(ciphertext, expected_512_14r, 64) == 0) {
            printf("✓ Encryption matches reference\n");
            passed_tests++;
        } else {
            printf("✗ Encryption FAILED - does not match reference!\n");
            print_hex("Expected ", expected_512_14r, 64);
            print_hex("Got      ", ciphertext, 64);
            exit(1); // Fail fast
        }

        vistrutah_512_decrypt(ciphertext, decrypted, key, 32, VISTRUTAH_512_ROUNDS_LONG_256KEY);
        total_tests++;
        if (memcmp(plaintext, decrypted, 64) == 0) {
            printf("✓ Decryption matches original plaintext\n");
            passed_tests++;
        } else {
            printf("✗ Decryption FAILED!\n");
            exit(1); // Fail fast
        }

        // Test 6: Vistrutah-512, 18 rounds, 256-bit key
        printf("\nVistrutah-512, 18 rounds, 256-bit key (ROUNDS_LONG_512KEY):\n");
        uint8_t expected_512_18r[64] = { 0x6D, 0x7F, 0x18, 0x33, 0x6B, 0x35, 0xED, 0x4D, 0x78, 0x5D,
                                         0xF2, 0x2D, 0xCE, 0x13, 0x49, 0x35, 0xAF, 0x3F, 0xC1, 0x4F,
                                         0xD7, 0xC3, 0x80, 0x48, 0x85, 0x3E, 0xEE, 0x54, 0x02, 0x1C,
                                         0xFB, 0x56, 0xBD, 0x30, 0x66, 0x96, 0xAD, 0x4C, 0x1E, 0x49,
                                         0x82, 0xFD, 0x41, 0x36, 0xB5, 0x7D, 0x65, 0xEE, 0x0F, 0xE4,
                                         0xB0, 0xC1, 0x05, 0x43, 0xDB, 0x5C, 0x9C, 0xAF, 0xFB, 0x7C,
                                         0xBD, 0x26, 0x61, 0x13 };

        vistrutah_512_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_512_ROUNDS_LONG_512KEY);
        total_tests++;
        if (memcmp(ciphertext, expected_512_18r, 64) == 0) {
            printf("✓ Encryption matches reference\n");
            passed_tests++;
        } else {
            printf("✗ Encryption FAILED - does not match reference!\n");
            print_hex("Expected ", expected_512_18r, 64);
            print_hex("Got      ", ciphertext, 64);
            exit(1); // Fail fast
        }

        vistrutah_512_decrypt(ciphertext, decrypted, key, 32, VISTRUTAH_512_ROUNDS_LONG_512KEY);
        total_tests++;
        if (memcmp(plaintext, decrypted, 64) == 0) {
            printf("✓ Decryption matches original plaintext\n");
            passed_tests++;
        } else {
            printf("✗ Decryption FAILED!\n");
            exit(1); // Fail fast
        }
    }

    printf("\n✓✓✓ All reference tests passed: %d/%d ✓✓✓\n", passed_tests, total_tests);
}

void
test_consistency()
{
    printf("\n=== Consistency Test ===\n");
    printf("Testing multiple encrypt/decrypt cycles\n");

    uint8_t key[32];
    uint8_t plaintext[32];
    uint8_t temp1[32];
    uint8_t temp2[32];

    // Random key and plaintext
    srand(time(NULL));
    for (int i = 0; i < 32; i++) {
        key[i]       = rand() & 0xff;
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

int
main()
{
    printf("Vistrutah Block Cipher Test Suite\n");
    printf("=================================\n");
    printf("Implementation: %s\n", vistrutah_get_impl_name());
    printf("Hardware AES: %s\n\n", vistrutah_has_aes_accel() ? "Yes" : "No");

    // FIRST: Test against reference implementation (fail fast if mismatched)
    test_reference_vectors();

    // Basic functionality tests
    test_vistrutah_256();
    test_vistrutah_512();

    // Comprehensive test vectors for all cipher variants
    test_comprehensive_vectors();

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