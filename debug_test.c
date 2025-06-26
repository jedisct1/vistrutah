#include "vistrutah_portable.h"
#include <stdio.h>
#include <string.h>

void print_hex(const char* label, const uint8_t* data, int len) {
    printf("%-10s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Test Vistrutah-512 with 256-bit key
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t plaintext[64] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
        0x20, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97,
        0xa8, 0xb9, 0xca, 0xdb, 0xec, 0xfd, 0x0e, 0x1f,
        0x30, 0x41, 0x52, 0x63, 0x74, 0x85, 0x96, 0xa7,
        0xb8, 0xc9, 0xda, 0xeb, 0xfc, 0x0d, 0x1e, 0x2f
    };
    
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    printf("Testing Vistrutah-512 with 256-bit key\n");
    print_hex("Key", key, 32);
    print_hex("Plaintext", plaintext, 64);
    
    vistrutah_512_encrypt(plaintext, ciphertext, key, 32, 14);
    print_hex("Encrypted", ciphertext, 64);
    
    vistrutah_512_decrypt(ciphertext, decrypted, key, 32, 14);
    print_hex("Decrypted", decrypted, 64);
    
    if (memcmp(plaintext, decrypted, 64) == 0) {
        printf("SUCCESS: Decryption matches plaintext\n");
    } else {
        printf("FAILED: Decryption does not match plaintext\n");
        // Show differences
        for (int i = 0; i < 64; i++) {
            if (plaintext[i] != decrypted[i]) {
                printf("  Byte %d: expected %02x, got %02x\n", i, plaintext[i], decrypted[i]);
            }
        }
    }
    
    return 0;
}
