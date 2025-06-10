#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libkeccak.h>

// Function to print Keccak state
void print_state(const uint64_t state[25], const char *label) {
    printf("\n%s (State):\n", label);
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            printf("%016lx ", state[i*5 + j]);
        }
        printf("\n");
    }
}

// Compute SHA3-256 hash from intermediate state
void sha3_256_from_intermediate(uint8_t *output, 
                                const uint64_t intermediate_state[25],
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
    
    // Copy intermediate state (25 uint64_t values)
    memcpy(&state.S, intermediate_state, 25 * sizeof(uint64_t));
    
    // Reset buffer position (assumes we're at block boundary)
    state.m = 0;
    
    if (print_intermediate) 
        print_state((uint64_t*)&state.S, "Restored State");
    
    // Process additional data
    size_t block_size = spec.bitrate / 8;
    size_t offset = 0;
    
    while (offset < data_len) {
        size_t chunk_size = (data_len - offset > block_size) 
                            ? block_size : data_len - offset;
        
        // Process chunk
        if (libkeccak_update(&state, data + offset, chunk_size) < 0) {
            fprintf(stderr, "Update failed\n");
            return;
        }
        offset += chunk_size;
        
        if (print_intermediate) {
            printf("\nAbsorbed %zu bytes", chunk_size);
            print_state((uint64_t*)&state.S, "After Absorption");
        }
    }
    
    // Apply SHA3 padding (0x06)
    uint8_t pad = 0x06;
    if (libkeccak_update(&state, &pad, 1) < 0) {
        fprintf(stderr, "Padding failed\n");
        return;
    }
    
    // Final bit (0x80)
    uint8_t final_bit = 0x80;
    if (libkeccak_update(&state, &final_bit, 1) < 0) {
        fprintf(stderr, "Final bit failed\n");
        return;
    }
    
    if (print_intermediate) 
        print_state((uint64_t*)&state.S, "After Padding");
    
    // Final digest with proper arguments
    libkeccak_digest_t digest;
    if (libkeccak_digest_init(&digest, &state, 32) < 0) {
        fprintf(stderr, "Digest init failed\n");
        return;
    }
    
    if (libkeccak_digest_update(&digest, NULL, 0) < 0) {
        fprintf(stderr, "Digest update failed\n");
        return;
    }
    
    if (libkeccak_digest_sum(&digest, output) < 0) {
        fprintf(stderr, "Digest sum failed\n");
        return;
    }
    
    if (print_intermediate) {
        printf("\nFinal output generated");
        print_state((uint64_t*)&state.S, "After Final Digest");
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
    // Test case: "The quick brown fox jumps over the lazy dog"
    const char *part1 = "The quick brown fox";
    const char *part2 = " jumps over the lazy dog";
    uint64_t intermediate_state[25];
    uint8_t final_hash[32];
    int print_steps = 1;
    
    // Step 1: Process first part and save state
    {
        libkeccak_state_t state;
        libkeccak_spec_t spec = {1088, 512, 256};
        if (libkeccak_state_initialise(&state, &spec) < 0) {
            fprintf(stderr, "Initialization failed\n");
            return 1;
        }
        
        // Process first part
        if (libkeccak_update(&state, (uint8_t*)part1, strlen(part1)) < 0) {
            fprintf(stderr, "Update failed\n");
            return 1;
        }
        
        // Force to block boundary
        libkeccak_digest_t digest;
        if (libkeccak_digest_init(&digest, &state, 0) < 0 ||
            libkeccak_digest_update(&digest, NULL, 0) < 0) {
            fprintf(stderr, "Digest failed\n");
            return 1;
        }
        
        // Save state (25 uint64_t values)
        memcpy(intermediate_state, &state.S, 25 * sizeof(uint64_t));
        
        if (print_steps) {
            printf("Saved intermediate state after processing:\n\"%s\"", part1);
            print_state(intermediate_state, "Intermediate State");
        }
        
        libkeccak_state_fast_destroy(&state);
    }
    
    // Step 2: Continue from intermediate state
    sha3_256_from_intermediate(
        final_hash,
        intermediate_state,
        (uint8_t*)part2,
        strlen(part2),
        print_steps
    );
    
    print_hex("\nFinal SHA3-256 hash", final_hash, 32);
    
    // Verification: Compute full hash normally
    uint8_t reference_hash[32];
    {
        libkeccak_state_t state;
        libkeccak_spec_t spec = {1088, 512, 256};
        libkeccak_state_initialise(&state, &spec);
        
        const char *full_msg = "The quick brown fox jumps over the lazy dog";
        libkeccak_update(&state, (uint8_t*)full_msg, strlen(full_msg));
        
        uint8_t pad = 0x06;
        libkeccak_update(&state, &pad, 1);
        uint8_t final_bit = 0x80;
        libkeccak_update(&state, &final_bit, 1);
        
        libkeccak_digest_t digest;
        libkeccak_digest_init(&digest, &state, 32);
        libkeccak_digest_update(&digest, NULL, 0);
        libkeccak_digest_sum(&digest, reference_hash);
        libkeccak_state_fast_destroy(&state);
    }
    
    print_hex("Reference hash", reference_hash, 32);
    
    if (memcmp(final_hash, reference_hash, 32) == 0) {
        printf("\nSUCCESS: Hashes match!\n");
    } else {
        printf("\nERROR: Hashes differ!\n");
    }
    
    return 0;
}
