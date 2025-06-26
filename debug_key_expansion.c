#include <stdio.h>
#include <string.h>
#include "vistrutah_portable.h"
#include <immintrin.h>

extern const uint8_t ROUND_CONSTANTS[38];

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_m128i(const char* label, __m128i v) {
    uint8_t buf[16];
    _mm_storeu_si128((__m128i*)buf, v);
    print_hex(label, buf, 16);
}

void debug_key_expansion() {
    printf("=== Key Expansion Debug ===\n\n");
    
    // Test with key[0] = 0x01
    uint8_t key[32] = {0};
    key[0] = 0x01;
    
    print_hex("Master key", key, 32);
    
    vistrutah_key_schedule_t ks = {0};
    
    // Load key parts
    __m128i k0 = _mm_loadu_si128((const __m128i*)key);
    __m128i k1 = _mm_loadu_si128((const __m128i*)(key + 16));
    
    print_m128i("k0", k0);
    print_m128i("k1", k1);
    
    printf("\nRound keys for 14 rounds:\n");
    for (int i = 0; i <= 14; i++) {
        if (i % 2 == 0) {
            ks.round_keys[i] = _mm_set1_epi8(ROUND_CONSTANTS[i]);
            printf("Round %2d (fixed): ", i);
            print_m128i("", ks.round_keys[i]);
        } else {
            int key_idx = (i / 2) % 4;
            switch (key_idx) {
                case 0: ks.round_keys[i] = k0; break;
                case 1: ks.round_keys[i] = k1; break;
                case 2: ks.round_keys[i] = k0; break;
                case 3: ks.round_keys[i] = k1; break;
            }
            printf("Round %2d (var %d): ", i, key_idx);
            print_m128i("", ks.round_keys[i]);
        }
    }
    
    printf("\nObservation: Variable round keys use k0 and k1\n");
    printf("k0 has 0x01 in first byte, k1 is all zeros\n");
    printf("This explains why blocks don't remain identical with non-zero key!\n");
}

int main() {
    debug_key_expansion();
    
    printf("\n\nKEY INSIGHT:\n");
    printf("With key[0]=0x01, the variable round keys alternate between:\n");
    printf("- k0 (has 0x01 in first byte)\n");
    printf("- k1 (all zeros)\n");
    printf("This breaks the symmetry between blocks!\n");
    printf("\nBut the real issue is: why doesn't decryption invert encryption?\n");
    
    return 0;
}