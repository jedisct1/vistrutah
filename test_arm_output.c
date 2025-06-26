#include <stdio.h>
#include <string.h>

// Simulate ARM output based on what the test expects
int main() {
    printf("Expected ARM output (from test failure message):\n");
    printf("Ciphertext: 280f1988f6058c5527e5e989c92d9a0a2e9eea657d8e9e61e0f29552ac353c7f\n");
    printf("\nActual Intel output:\n");
    printf("Ciphertext: 271750cbee3c8077af45943f68e1cd85fed1c1b12d97cd6db9088c3ecbc2e670\n");
    
    return 0;
}