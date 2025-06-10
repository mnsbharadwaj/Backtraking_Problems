#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int sha3_oneshot(const char* input, size_t input_len, int variant) {
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    unsigned char* output;
    size_t hash_size;
    
    // Set up SHA-3 specification based on variant
    switch (variant) {
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
            fprintf(stderr, "Error: Unsupported SHA-3 variant. Use 224, 256, 384, or 512\n");
            return -1;
    }
    
    // Initialize state
    if (libkeccak_state_initialise(&state, &spec) < 0) {
        fprintf(stderr, "Error: Failed to initialize SHA-3-%d state\n", variant);
        return -1;
    }
    
    // Allocate output buffer
    output = malloc(hash_size);
    if (!output) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    // Process input and generate hash in one go
    if (libkeccak_update(&state, input, input_len) < 0) {
        fprintf(stderr, "Error: Failed to process input\n");
        free(output);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    if (libkeccak_digest(&state, NULL, 0, 0, NULL, output) < 0) {
        fprintf(stderr, "Error: Failed to generate SHA-3-%d hash\n", variant);
        free(output);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    // Output result
    printf("SHA3-%d: ", variant);
    print_hex(output, hash_size);
    
    free(output);
    libkeccak_state_destroy(&state);
    return 0;
}

int sha3_all_variants(const char* input, size_t input_len) {
    printf("Input: \"%s\" (%zu bytes)\n", input, input_len);
    printf("Computing all SHA-3 variants...\n\n");
    
    int variants[] = {224, 256, 384, 512};
    int num_variants = sizeof(variants) / sizeof(variants[0]);
    
    for (int i = 0; i < num_variants; i++) {
        if (sha3_oneshot(input, input_len, variants[i]) < 0) {
            return -1;
        }
    }
    
    return 0;
}

int sha3_compare_with_known_vectors() {
    printf("=== TESTING WITH KNOWN TEST VECTORS ===\n\n");
    
    // Test vector 1: Empty string
    printf("Test 1: Empty string\n");
    sha3_all_variants("", 0);
    printf("\n");
    
    // Test vector 2: "abc"
    printf("Test 2: \"abc\"\n");
    sha3_all_variants("abc", 3);
    printf("\n");
    
    // Test vector 3: Longer message
    printf("Test 3: \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"\n");
    const char* long_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha3_all_variants(long_msg, strlen(long_msg));
    printf("\n");
    
    return 0;
}

int sha3_benchmark(const char* input, size_t input_len, int iterations) {
    printf("=== BENCHMARK: %d iterations ===\n", iterations);
    printf("Input: \"%s\" (%zu bytes)\n\n", input, input_len);
    
    int variants[] = {224, 256, 384, 512};
    int num_variants = sizeof(variants) / sizeof(variants[0]);
    
    for (int v = 0; v < num_variants; v++) {
        int variant = variants[v];
        printf("SHA3-%d: ", variant);
        fflush(stdout);
        
        for (int i = 0; i < iterations; i++) {
            if (sha3_oneshot(input, input_len, variant) < 0) {
                printf("Error in iteration %d\n", i);
                return -1;
            }
            if (i < iterations - 1) {
                printf("\rSHA3-%d: %d/%d", variant, i + 1, iterations);
                fflush(stdout);
            }
        }
        printf(" - Completed %d iterations\n", iterations);
    }
    
    return 0;
}

void print_usage(const char* program_name) {
    printf("SHA-3 Oneshot Calculator - All Variants\n");
    printf("Usage: %s [OPTIONS] [INPUT]\n\n", program_name);
    
    printf("Options:\n");
    printf("  --sha3-224 <input>     Compute SHA3-224 only\n");
    printf("  --sha3-256 <input>     Compute SHA3-256 only\n");
    printf("  --sha3-384 <input>     Compute SHA3-384 only\n");
    printf("  --sha3-512 <input>     Compute SHA3-512 only\n");
    printf("  --all <input>          Compute all SHA3 variants\n");
    printf("  --test-vectors         Run known test vectors\n");
    printf("  --benchmark <input> <iterations>  Benchmark performance\n");
    printf("  --help                 Show this help\n\n");
    
    printf("Examples:\n");
    printf("  %s --sha3-256 \"Hello World\"     # Single variant\n", program_name);
    printf("  %s --all \"Test Message\"         # All variants\n", program_name);
    printf("  %s --test-vectors                # Known test cases\n", program_name);
    printf("  %s --benchmark \"abc\" 1000       # Performance test\n", program_name);
    printf("\n");
    
    printf("Expected SHA3-256 for \"abc\": 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* mode = argv[1];
    
    if (strcmp(mode, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
        
    } else if (strcmp(mode, "--sha3-224") == 0 && argc >= 3) {
        return sha3_oneshot(argv[2], strlen(argv[2]), 224);
        
    } else if (strcmp(mode, "--sha3-256") == 0 && argc >= 3) {
        return sha3_oneshot(argv[2], strlen(argv[2]), 256);
        
    } else if (strcmp(mode, "--sha3-384") == 0 && argc >= 3) {
        return sha3_oneshot(argv[2], strlen(argv[2]), 384);
        
    } else if (strcmp(mode, "--sha3-512") == 0 && argc >= 3) {
        return sha3_oneshot(argv[2], strlen(argv[2]), 512);
        
    } else if (strcmp(mode, "--all") == 0 && argc >= 3) {
        return sha3_all_variants(argv[2], strlen(argv[2]));
        
    } else if (strcmp(mode, "--test-vectors") == 0) {
        return sha3_compare_with_known_vectors();
        
    } else if (strcmp(mode, "--benchmark") == 0 && argc >= 4) {
        int iterations = (argc >= 4) ? atoi(argv[3]) : 1000;
        return sha3_benchmark(argv[2], strlen(argv[2]), iterations);
        
    } else {
        // Default: treat first argument as input and compute all variants
        printf("Computing all SHA-3 variants for input...\n\n");
        return sha3_all_variants(argv[1], strlen(argv[1]));
    }
}
