#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libkeccak.h>

// Function to print Keccak state
void print_state(const libkeccak_state_t *state, const char *label) {
    printf("\n%s (State):\n", label);
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            printf("%016lx ", state->S[i*5 + j]);
        }
        printf("\n");
    }
}

// Compute SHA3-256 hash from intermediate state
void sha3_256_from_intermediate(uint8_t *output, 
                                const uint8_t *intermediate_state,
                                const uint8_t *data, 
                                size_t data_len,
                                int print_intermediate) {
    libkeccak_state_t state;
    libkeccak_spec_t spec;
    
    // Set SHA3-256 parameters
    spec.bitrate = 1088;
    spec.capacity = 512;
    spec.output = 256;  // Output length in bits
    
    // Initialize state
    if (libkeccak_state_initialise(&state, &spec) < 0) {
        fprintf(stderr, "State initialization failed\n");
        return;
    }
    
    // Copy intermediate state (200 bytes = 25 * 8 bytes)
    memcpy(state.S, intermediate_state, 25 * sizeof(uint64_t));
    
    // Reset buffer position (assumes we're at block boundary)
    state.m = 0;
    
    if (print_intermediate) 
        print_state(&state, "Restored State");
    
    // Process additional data
    size_t block_size = spec.bitrate / 8;
    size_t offset = 0;
    
    while (offset < data_len) {
        size_t chunk_size = (data_len - offset > block_size) 
                            ? block_size : data_len - offset;
        
        if (libkeccak_fast_absorb(&state, data + offset, chunk_size) < 0) {
            fprintf(stderr, "Absorption failed\n");
            return;
        }
        offset += chunk_size;
        
        if (print_intermediate) {
            printf("\nAbsorbed %zu bytes", chunk_size);
            print_state(&state, "After Absorption");
        }
        
        if (chunk_size == block_size) {
            if (libkeccak_fast_digest(&state) < 0) {
                fprintf(stderr, "Permutation failed\n");
                return;
            }
            if (print_intermediate) 
                print_state(&state, "After Permutation");
        }
    }
    
    // Apply SHA3 padding (0x06)
    uint8_t pad = 0x06;
    if (libkeccak_fast_pad(&state, &pad, 1) < 0) {
        fprintf(stderr, "Padding failed\n");
        return;
    }
    
    if (print_intermediate) 
        print_state(&state, "After Padding");
    
    // Final permutation
    if (libkeccak_fast_digest(&state) < 0) {
        fprintf(stderr, "Final permutation failed\n");
        return;
    }
    
    // Squeeze output (32 bytes for SHA3-256)
    libkeccak_fast_squeeze(&state, 32);
    memcpy(output, state.M, 32);
    
    if (print_intermediate) {
        printf("\nSqueezed 32 bytes");
        print_state(&state, "After Squeeze");
    }
    
    libkeccak_state_fast_destroy(&state);
}

// Helper to print hex output
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Test 1: Full hash calculation
    const char *full_msg = "The quick brown fox jumps over the lazy dog";
    uint8_t full_hash[32];
    
    {
        libkeccak_state_t state;
        libkeccak_spec_t spec = {1088, 512, 256};
        libkeccak_state_initialise(&state, &spec);
        
        // Process full message
        libkeccak_fast_absorb(&state, (uint8_t*)full_msg, strlen(full_msg));
        
        // Apply padding and get hash
        uint8_t pad = 0x06;
        libkeccak_fast_pad(&state, &pad, 1);
        libkeccak_fast_digest(&state);
        libkeccak_fast_squeeze(&state, 32);
        memcpy(full_hash, state.M, 32);
        
        libkeccak_state_fast_destroy(&state);
    }
    
    print_hex("Full SHA3-256", full_hash, 32);
    
    // Test 2: Continue from intermediate state
    const char *part1 = "The quick brown fox";
    const char *part2 = " jumps over the lazy dog";
    uint8_t intermediate_state[200];  // 25 * 8 = 200 bytes
    uint8_t continued_hash[32];
    int print_steps = 1;
    
    // Get intermediate state after first part
    {
        libkeccak_state_t state;
        libkeccak_spec_t spec = {1088, 512, 256};
        libkeccak_state_initialise(&state, &spec);
        
        // Process first part
        libkeccak_fast_absorb(&state, (uint8_t*)part1, strlen(part1));
        
        // Force process to block boundary
        if (libkeccak_fast_digest(&state) < 0) {
            fprintf(stderr, "Intermediate permutation failed\n");
            return 1;
        }
        
        // Save intermediate state (200 bytes)
        memcpy(intermediate_state, state.S, 200);
        
        libkeccak_state_fast_destroy(&state);
    }
    
    // Continue from intermediate state with second part
    sha3_256_from_intermediate(
        continued_hash,
        intermediate_state,
        (uint8_t*)part2,
        strlen(part2),
        print_steps
    );
    
    print_hex("\nContinued SHA3-256", continued_hash, 32);
    
    // Verify results match
    if (memcmp(full_hash, continued_hash, 32) == 0) {
        printf("\nSUCCESS: Hashes match!\n");
    } else {
        printf("\nERROR: Hashes differ!\n");
    }
    
    return 0;
}
