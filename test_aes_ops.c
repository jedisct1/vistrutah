// Test AES operations to understand their exact behavior
#include <stdint.h>
#include <stdio.h>
#include <arm_neon.h>

void print_vec(const char* label, uint8x16_t vec) {
    uint8_t bytes[16];
    vst1q_u8(bytes, vec);
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

int main() {
    printf("=== Testing ARM NEON AES Operations ===\n\n");
    
    // Test data
    uint8_t test_data[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    
    uint8_t key_data[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    uint8x16_t state = vld1q_u8(test_data);
    uint8x16_t key = vld1q_u8(key_data);
    uint8x16_t zero = vdupq_n_u8(0);
    
    print_vec("Initial state", state);
    print_vec("Key", key);
    
    // Test 1: Understanding vaeseq_u8
    printf("\nTest 1: vaeseq_u8 operations\n");
    printf("According to ARM docs: vaeseq_u8 performs AES single round encryption\n");
    printf("This includes: AddRoundKey, SubBytes, ShiftRows\n");
    
    // Method A: vaeseq_u8 with key
    uint8x16_t enc_a = vaeseq_u8(state, key);
    print_vec("vaeseq_u8(state, key)", enc_a);
    
    // Method B: XOR first, then vaeseq_u8 with zero
    uint8x16_t xor_state = veorq_u8(state, key);
    uint8x16_t enc_b = vaeseq_u8(xor_state, zero);
    print_vec("state XOR key", xor_state);
    print_vec("vaeseq_u8(state^key, 0)", enc_b);
    
    // Check if they're the same
    uint8x16_t diff = veorq_u8(enc_a, enc_b);
    print_vec("Difference", diff);
    
    // Test 2: Round trip with and without MixColumns
    printf("\nTest 2: Encryption/Decryption round trip\n");
    
    // Full AES round (with MixColumns)
    uint8x16_t enc_full = vaeseq_u8(state, key);
    uint8x16_t enc_full_mc = vaesmcq_u8(enc_full);
    print_vec("After full round", enc_full_mc);
    
    // Inverse operations
    uint8x16_t dec_imc = vaesimcq_u8(enc_full_mc);
    uint8x16_t dec_full = vaesdq_u8(dec_imc, key);
    print_vec("After inverse round", dec_full);
    
    // Check if we got back the original
    diff = veorq_u8(state, dec_full);
    print_vec("Roundtrip difference", diff);
    
    // Test 3: Final round (no MixColumns)
    printf("\nTest 3: Final round operations\n");
    uint8x16_t enc_final = vaeseq_u8(state, key);
    print_vec("Final round encrypt", enc_final);
    
    uint8x16_t dec_final = vaesdq_u8(enc_final, key);
    print_vec("Final round decrypt", dec_final);
    
    diff = veorq_u8(state, dec_final);
    print_vec("Final round difference", diff);
    
    // Test 4: Key addition timing
    printf("\nTest 4: Key addition timing in Vistrutah\n");
    printf("For Vistrutah, we need to understand when to add keys\n");
    
    // Encryption sequence:
    // 1. Initial: state = state XOR k0
    // 2. Round i: state = AESRound(state) XOR ki
    
    // Start with plaintext
    uint8x16_t pt = state;
    print_vec("Plaintext", pt);
    
    // Initial key addition
    uint8x16_t s1 = veorq_u8(pt, key);
    print_vec("After initial key", s1);
    
    // Round 1: AES operations then key
    uint8x16_t s2 = vaeseq_u8(s1, zero);
    uint8x16_t s3 = vaesmcq_u8(s2);
    uint8x16_t s4 = veorq_u8(s3, key);
    print_vec("After round 1", s4);
    
    // Now decrypt back
    printf("\nDecryption sequence:\n");
    // Start with s4
    uint8x16_t d1 = veorq_u8(s4, key);
    print_vec("Remove round 1 key", d1);
    
    uint8x16_t d2 = vaesimcq_u8(d1);
    uint8x16_t d3 = vaesdq_u8(d2, zero);
    print_vec("After inv round 1", d3);
    
    uint8x16_t d4 = veorq_u8(d3, key);
    print_vec("Remove initial key", d4);
    
    diff = veorq_u8(pt, d4);
    print_vec("Full roundtrip diff", diff);
    
    return 0;
}