#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

void print_hex(const unsigned char* data, size_t len, const char* label) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0) printf("\n    ");  // Line break every 32 bytes for readability
    }
    printf("\n");
}

void print_state_lanes(const uint64_t* state) {
    printf("Keccak State (25 lanes, 64-bit each):\n");
    for (int y = 0; y < 5; y++) {
        printf("Row %d: ", y);
        for (int x = 0; x < 5; x++) {
            printf("%016lx ", state[y * 5 + x]);
        }
        printf("\n");
    }
    printf("\n");
}

int sha3_with_intermediate(const char* input, size_t input_len, int sha3_variant) {
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    unsigned char* output;
    size_t hash_size;
    
    // Set up SHA-3 specification
    switch (sha3_variant) {
        case 224:
            libkeccak_spec_sha3(&spec, 224);
            hash_size = 28;  // 224/8
            break;
        case 256:
            libkeccak_spec_sha3(&spec, 256);
            hash_size = 32;  // 256/8
            break;
        case 384:
            libkeccak_spec_sha3(&spec, 384);
            hash_size = 48;  // 384/8
            break;
        case 512:
            libkeccak_spec_sha3(&spec, 512);
            hash_size = 64;  // 512/8
            break;
        default:
            fprintf(stderr, "Error: Unsupported SHA-3 variant. Use 224, 256, 384, or 512.\n");
            return -1;
    }
    
    // Initialize state
    if (libkeccak_state_initialise(&state, &spec) < 0) {
        fprintf(stderr, "Error: Failed to initialize SHA-3 state\n");
        return -1;
    }
    
    // Allocate output buffer
    output = malloc(hash_size);
    if (!output) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    printf("=== SHA-3-%d Computation ===\n", sha3_variant);
    printf("Input: \"%s\" (%zu bytes)\n", input, input_len);
    printf("Rate: %zu bits, Capacity: %zu bits\n\n", spec.bitrate, spec.capacity);
    
    // Show initial state (should be all zeros)
    printf("Initial State (200 bytes):\n");
    print_hex((unsigned char*)&state.S, 200, "State");
    print_state_lanes((uint64_t*)&state.S);
    
    // Process input
    if (libkeccak_update(&state, input, input_len) < 0) {
        fprintf(stderr, "Error: Failed to update SHA-3 state\n");
        free(output);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    // Show state after absorbing input
    printf("State after absorbing input (200 bytes):\n");
    print_hex((unsigned char*)&state.S, 200, "State");
    print_state_lanes((uint64_t*)&state.S);
    
    // Generate final hash
    if (libkeccak_digest(&state, NULL, 0, 0, NULL, output) < 0) {
        fprintf(stderr, "Error: Failed to generate SHA-3 hash\n");
        free(output);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    // Show final state after padding and final rounds
    printf("Final State after padding and finalization (200 bytes):\n");
    print_hex((unsigned char*)&state.S, 200, "State");
    print_state_lanes((uint64_t*)&state.S);
    
    // Show final hash
    printf("Final SHA-3-%d Hash (%zu bytes):\n", sha3_variant, hash_size);
    print_hex(output, hash_size, "Hash");
    
    free(output);
    libkeccak_state_destroy(&state);
    return 0;
}

int sha3_step_by_step(const char* input, size_t input_len, int sha3_variant) {
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    unsigned char* output;
    size_t hash_size;
    size_t rate_bytes;
    
    // Set up SHA-3 specification
    switch (sha3_variant) {
        case 224:
            libkeccak_spec_sha3(&spec, 224);
            hash_size = 28;
            break;
        case 256:
            libkeccak_spec_sha3(&spec, 256);
            hash_size = 32;
            break;
        case 384:
            libkeccak_spec_sha3(&spec, 384);
            hash_size = 48;
            break;
        case 512:
            libkeccak_spec_sha3(&spec, 512);
            hash_size = 64;
            break;
        default:
            fprintf(stderr, "Error: Unsupported SHA-3 variant\n");
            return -1;
    }
    
    rate_bytes = spec.bitrate / 8;
    
    if (libkeccak_state_initialise(&state, &spec) < 0) {
        fprintf(stderr, "Error: Failed to initialize state\n");
        return -1;
    }
    
    output = malloc(hash_size);
    if (!output) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    printf("=== SHA-3-%d Step-by-Step Processing ===\n", sha3_variant);
    printf("Input: \"%s\" (%zu bytes)\n", input, input_len);
    printf("Rate: %zu bytes, Processing in blocks of %zu bytes\n\n", rate_bytes, rate_bytes);
    
    size_t processed = 0;
    size_t block_num = 0;
    
    // Process input block by block to show intermediate states
    while (processed < input_len) {
        size_t chunk_size = (input_len - processed > rate_bytes) ? rate_bytes : (input_len - processed);
        
        printf("--- Block %zu (bytes %zu-%zu) ---\n", block_num, processed, processed + chunk_size - 1);
        printf("Block data: \"");
        for (size_t i = 0; i < chunk_size; i++) {
            printf("%c", input[processed + i]);
        }
        printf("\"\n");
        
        if (libkeccak_update(&state, input + processed, chunk_size) < 0) {
            fprintf(stderr, "Error during block processing\n");
            free(output);
            libkeccak_state_destroy(&state);
            return -1;
        }
        
        printf("State after block %zu:\n", block_num);
        print_hex((unsigned char*)&state.S, 200, "200-byte state");
        
        processed += chunk_size;
        block_num++;
        printf("\n");
    }
    
    // Final digest
    if (libkeccak_digest(&state, NULL, 0, 0, NULL, output) < 0) {
        fprintf(stderr, "Error generating final hash\n");
        free(output);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    printf("=== FINAL RESULTS ===\n");
    printf("Final 200-byte state:\n");
    print_hex((unsigned char*)&state.S, 200, "State");
    printf("\nFinal SHA-3-%d hash:\n", sha3_variant);
    print_hex(output, hash_size, "Hash");
    
    free(output);
    libkeccak_state_destroy(&state);
    return 0;
}

int sha3_oneshot_verify(const char* input, size_t input_len, int sha3_variant) {
    struct libkeccak_spec spec;
    unsigned char* output;
    size_t hash_size;
    
    // Set up SHA-3 specification
    switch (sha3_variant) {
        case 224:
            libkeccak_spec_sha3(&spec, 224);
            hash_size = 28;
            break;
        case 256:
            libkeccak_spec_sha3(&spec, 256);
            hash_size = 32;
            break;
        case 384:
            libkeccak_spec_sha3(&spec, 384);
            hash_size = 48;
            break;
        case 512:
            libkeccak_spec_sha3(&spec, 512);
            hash_size = 64;
            break;
        default:
            fprintf(stderr, "Error: Unsupported SHA-3 variant\n");
            return -1;
    }
    
    output = malloc(hash_size);
    if (!output) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }
    
    printf("=== ONESHOT VERIFICATION ===\n");
    printf("Computing SHA-3-%d using libkeccak_digest() oneshot function...\n", sha3_variant);
    
    // Use the oneshot digest function
    if (libkeccak_digest(&spec, input, input_len, 0, NULL, output) < 0) {
        fprintf(stderr, "Error: Oneshot digest failed\n");
        free(output);
        return -1;
    }
    
    printf("Oneshot SHA-3-%d result:\n", sha3_variant);
    print_hex(output, hash_size, "Hash");
    
    free(output);
    return 0;
}

int sha3_compare_methods(const char* input, size_t input_len, int sha3_variant) {
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    unsigned char* output_stepwise;
    unsigned char* output_oneshot;
    size_t hash_size;
    
    // Set up SHA-3 specification
    switch (sha3_variant) {
        case 224:
            libkeccak_spec_sha3(&spec, 224);
            hash_size = 28;
            break;
        case 256:
            libkeccak_spec_sha3(&spec, 256);
            hash_size = 32;
            break;
        case 384:
            libkeccak_spec_sha3(&spec, 384);
            hash_size = 48;
            break;
        case 512:
            libkeccak_spec_sha3(&spec, 512);
            hash_size = 64;
            break;
        default:
            fprintf(stderr, "Error: Unsupported SHA-3 variant\n");
            return -1;
    }
    
    output_stepwise = malloc(hash_size);
    output_oneshot = malloc(hash_size);
    if (!output_stepwise || !output_oneshot) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(output_stepwise);
        free(output_oneshot);
        return -1;
    }
    
    printf("=== COMPARISON: STEPWISE vs ONESHOT ===\n");
    printf("Input: \"%s\" (%zu bytes)\n", input, input_len);
    printf("SHA-3 variant: %d-bit\n\n", sha3_variant);
    
    // Method 1: Stepwise computation
    printf("Method 1: Stepwise computation\n");
    if (libkeccak_state_initialise(&state, &spec) < 0) {
        fprintf(stderr, "Error: Failed to initialize state\n");
        free(output_stepwise);
        free(output_oneshot);
        return -1;
    }
    
    if (libkeccak_update(&state, input, input_len) < 0) {
        fprintf(stderr, "Error: Failed to update state\n");
        free(output_stepwise);
        free(output_oneshot);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    if (libkeccak_digest(&state, NULL, 0, 0, NULL, output_stepwise) < 0) {
        fprintf(stderr, "Error: Failed stepwise digest\n");
        free(output_stepwise);
        free(output_oneshot);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    print_hex(output_stepwise, hash_size, "Stepwise");
    
    // Method 2: Oneshot computation
    printf("\nMethod 2: Oneshot computation\n");
    if (libkeccak_digest(&spec, input, input_len, 0, NULL, output_oneshot) < 0) {
        fprintf(stderr, "Error: Failed oneshot digest\n");
        free(output_stepwise);
        free(output_oneshot);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    print_hex(output_oneshot, hash_size, "Oneshot ");
    
    // Compare results
    printf("\n=== VERIFICATION ===\n");
    if (memcmp(output_stepwise, output_oneshot, hash_size) == 0) {
        printf("✅ SUCCESS: Both methods produce identical results!\n");
        printf("Hash verification: PASSED\n");
    } else {
        printf("❌ ERROR: Methods produce different results!\n");
        printf("Hash verification: FAILED\n");
        
        // Show byte-by-byte difference
        printf("\nByte-by-byte comparison:\n");
        for (size_t i = 0; i < hash_size; i++) {
            if (output_stepwise[i] != output_oneshot[i]) {
                printf("Difference at byte %zu: stepwise=0x%02x, oneshot=0x%02x\n", 
                       i, output_stepwise[i], output_oneshot[i]);
            }
        }
    }
    
    free(output_stepwise);
    free(output_oneshot);
    libkeccak_state_destroy(&state);
    return 0;
}

void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS] <input_string>\n", program_name);
    printf("Options:\n");
    printf("  --sha3-224 <input>     Compute SHA-3-224 with intermediate states\n");
    printf("  --sha3-256 <input>     Compute SHA-3-256 with intermediate states\n");
    printf("  --sha3-384 <input>     Compute SHA-3-384 with intermediate states\n");
    printf("  --sha3-512 <input>     Compute SHA-3-512 with intermediate states\n");
    printf("  --step <variant> <input>  Step-by-step processing (224/256/384/512)\n");
    printf("  --oneshot <variant> <input>  Quick oneshot hash computation\n");
    printf("  --verify <variant> <input>   Compare stepwise vs oneshot methods\n");
    printf("\nExamples:\n");
    printf("  %s --sha3-256 \"Hello World\"\n", program_name);
    printf("  %s --step 256 \"Test Data\"\n", program_name);
    printf("  %s --oneshot 256 \"Quick hash\"\n", program_name);
    printf("  %s --verify 256 \"Verify this\"\n", program_name);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* mode = argv[1];
    
    if (strcmp(mode, "--sha3-224") == 0) {
        return sha3_with_intermediate(argv[2], strlen(argv[2]), 224);
    } else if (strcmp(mode, "--sha3-256") == 0) {
        return sha3_with_intermediate(argv[2], strlen(argv[2]), 256);
    } else if (strcmp(mode, "--sha3-384") == 0) {
        return sha3_with_intermediate(argv[2], strlen(argv[2]), 384);
    } else if (strcmp(mode, "--sha3-512") == 0) {
        return sha3_with_intermediate(argv[2], strlen(argv[2]), 512);
    } else if (strcmp(mode, "--step") == 0 && argc >= 4) {
        int variant = atoi(argv[2]);
        return sha3_step_by_step(argv[3], strlen(argv[3]), variant);
    } else if (strcmp(mode, "--oneshot") == 0 && argc >= 4) {
        int variant = atoi(argv[2]);
        return sha3_oneshot_verify(argv[3], strlen(argv[3]), variant);
    } else if (strcmp(mode, "--verify") == 0 && argc >= 4) {
        int variant = atoi(argv[2]);
        return sha3_compare_methods(argv[3], strlen(argv[3]), variant);
    } else {
        print_usage(argv[0]);
        return 1;
    }
}
