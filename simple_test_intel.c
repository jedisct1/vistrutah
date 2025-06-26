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
    printf("Simple Vistrutah-256 Test\n");
    printf("Implementation: %s\n", vistrutah_get_impl_name());
    
    // Simple test with zeros
    uint8_t key[32] = {0};
    uint8_t plaintext[32] = {0};
    uint8_t ciphertext[32];
    uint8_t decrypted[32];
    
    key[0] = 0x01;  // Non-zero key
    plaintext[0] = 0x01;  // Non-zero plaintext
    
    print_hex("Key      ", key, 32);
    print_hex("Plaintext", plaintext, 32);
    
    // Test with 10 rounds
    vistrutah_256_encrypt(plaintext, ciphertext, key, 32, 10);
    print_hex("Ciphertext", ciphertext, 32);
    
    vistrutah_256_decrypt(ciphertext, decrypted, key, 32, 10);
    print_hex("Decrypted", decrypted, 32);
    
    if (memcmp(plaintext, decrypted, 32) == 0) {
        printf("✓ Test PASSED\n");
    } else {
        printf("✗ Test FAILED\n");
    }
    
    return 0;
}