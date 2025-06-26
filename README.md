# Implementation of the Vistrutah Block Cipher

## Overview

Vistrutah is a large-block cipher family offering 256-bit and 512-bit block sizes, designed for high-performance authenticated encryption modes. This implementation provides optimized versions for x86-64 (with AES-NI/AVX/VAES) and ARM64 (with crypto extensions), as well as a portable C reference.

### Design Philosophy

Vistrutah addresses the need for efficient large-block ciphers in modern cryptographic constructions while leveraging ubiquitous AES hardware acceleration. The design prioritizes:

- **Hardware acceleration**: Direct use of AES-NI and similar instructions
- **Parallelism**: Multiple AES blocks processed simultaneously
- **Memory efficiency**: Inline key schedule with no precomputed round keys
- **Mode flexibility**: Variants optimized for different security/performance trade-offs

## Cipher Specification

### Parameters

| Variant       | Block Size | Key Sizes     | Rounds (Short/Long) |
| ------------- | ---------- | ------------- | ------------------- |
| Vistrutah-256 | 256 bits   | 128, 256 bits | 10/14               |
| Vistrutah-512 | 512 bits   | 256, 512 bits | 10-12/14-18         |

### Structure

Both variants follow a generalized Even-Mansour construction with AES-based round functions:

```text
C = π_r ∘ ρ_{K_r} ∘ ... ∘ π_1 ∘ ρ_{K_1} ∘ ρ_{K_0}(P)
```

Where:

- `ρ_K`: Key addition (XOR with round key)
- `π_i`: Step function consisting of parallel AES rounds followed by mixing

### Round Function

Each step function `π_i` applies:

1. **Parallel AES rounds**: 2 rounds of AES to each 128-bit slice
2. **Mixing layer**: Full-state permutation (except final step)

The AES rounds use standard operations (SubBytes, ShiftRows, MixColumns, AddRoundKey) with the last round omitting MixColumns.

### Key Schedule

Vistrutah employs an alternating inline key schedule:

- **Even rounds**: `K_{2i} = k_{i mod s} ⊕ RC[i]` (fixed round key)
- **Odd rounds**: `K_{2i+1} = k_{i mod s}` (variable round key)

Where:

- `k_0, k_1, ...` are master key segments
- `RC[i]` are round constants derived from AES S-box recursion
- `s` is the number of key segments (1, 2, or 4)

This design eliminates precomputed round keys, improving key agility and cold boot attack resistance.

### Mixing Layers

#### Vistrutah-256: ASURA Permutation

The ASURA permutation is a carefully designed byte-level shuffle with optimal diffusion properties:

```text
σ(x[0..31]) = x[0,17,2,19,4,21,6,23,8,25,10,27,12,29,14,31,
                16,1,18,3,20,5,22,7,24,9,26,11,28,13,30,15]
```

Key properties:

- Self-inverse: `σ(σ(x)) = x`
- Full diffusion in 2 rounds
- Efficiently implementable with SIMD byte shuffle instructions

#### Vistrutah-512: Transpose Mixing

Uses a 4×4 transpose of 32-bit words, viewing the 512-bit state as a matrix:

```text
[a0 a1 a2 a3]     [a0 b0 c0 d0]
[b0 b1 b2 b3]  →  [a1 b1 c1 d1]
[c0 c1 c2 c3]     [a2 b2 c2 d2]
[d0 d1 d2 d3]     [a3 b3 c3 d3]
```

Also self-inverse and SIMD-friendly.

## Security Analysis

### Design Rationale

1. **Wide Trail Strategy**: The mixing layers ensure active S-boxes spread across all AES blocks
2. **Key Schedule Security**: Alternating structure prevents slide and related-key attacks
3. **Conservative Rounds**: Round counts chosen with significant security margins

### Cryptanalytic Results

Extensive analysis has been performed:

- **Differential/Linear**: No characteristics with probability > 2^{-256} for full rounds
- **Integral**: 4-round distinguisher exists; full rounds secure
- **Impossible Differential**: No exploitable properties found
- **Meet-in-the-Middle**: Prevented by key schedule design
- **Related-Key**: Alternating schedule provides strong resistance

### Security Claims

- **Vistrutah-256**: 256-bit security against all attacks
- **Vistrutah-512-256**: 256-bit security
- **Vistrutah-512-512**: 512-bit security

Short variants (reduced rounds) are intended for use in modes like HCTR2 where the block cipher is not the primary security component.

## Usage

### Basic Encryption/Decryption

```c
#include "vistrutah_portable.h"

// Vistrutah-256 with 256-bit key
uint8_t key[32] = {...};
uint8_t plaintext[32] = {...};
uint8_t ciphertext[32];

vistrutah_256_encrypt(plaintext, ciphertext, key, 32, VISTRUTAH_256_ROUNDS_LONG);
vistrutah_256_decrypt(ciphertext, plaintext, key, 32, VISTRUTAH_256_ROUNDS_LONG);

// Vistrutah-512 with 512-bit key  
uint8_t key512[64] = {...};
uint8_t plaintext512[64] = {...};
uint8_t ciphertext512[64];

vistrutah_512_encrypt(plaintext512, ciphertext512, key512, 64, VISTRUTAH_512_ROUNDS_LONG_512KEY);
```

### Feature Detection

```c
if (vistrutah_has_aes_accel()) {
    printf("Using hardware-accelerated implementation: %s\n", 
           vistrutah_get_impl_name());
}
```

### Building

```bash
# Auto-detect architecture and build optimized version
make

# Force portable build
make portable

# Run test suite
make test

# Benchmark performance
make bench
```
