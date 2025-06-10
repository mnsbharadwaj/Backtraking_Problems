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

int shake_hash(const char* input, size_t input_len, int shake_variant, size_t output_bytes) {
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    unsigned char* output;
    
    // Set up SHAKE specification
    if (shake_variant == 128) {
        libkeccak_spec_shake(&spec, 128, output_bytes * 8);  // bits, not bytes
    } else if (shake_variant == 256) {
        libkeccak_spec_shake(&spec, 256, output_bytes * 8);  // bits, not bytes
    } else {
        fprintf(stderr, "Error: Unsupported SHAKE variant. Use 128 or 256.\n");
        return -1;
    }
    
    // Initialize state
    if (libkeccak_state_initialise(&state, &spec) < 0) {
        fprintf(stderr, "Error: Failed to initialize SHAKE state\n");
        return -1;
    }
    
    // Allocate output buffer
    output = malloc(output_bytes);
    if (!output) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    // Process input and generate hash
    if (libkeccak_update(&state, input, input_len) < 0) {
        fprintf(stderr, "Error: Failed to update SHAKE state\n");
        free(output);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    if (libkeccak_digest(&state, NULL, 0, 0, NULL, output) < 0) {
        fprintf(stderr, "Error: Failed to generate SHAKE hash\n");
        free(output);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    printf("SHAKE%d (%zu bytes): ", shake_variant, output_bytes);
    print_hex(output, output_bytes);
    
    free(output);
    libkeccak_state_destroy(&state);
    return 0;
}

int cshake_hash(const char* input, size_t input_len, int cshake_variant, 
                size_t output_bytes, const char* function_name, const char* customization) {
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    unsigned char* output;
    
    // Set up cSHAKE specification - first create basic SHAKE spec
    if (cshake_variant == 128) {
        libkeccak_spec_shake(&spec, 128, output_bytes * 8);
    } else if (cshake_variant == 256) {
        libkeccak_spec_shake(&spec, 256, output_bytes * 8);
    } else {
        fprintf(stderr, "Error: Unsupported cSHAKE variant. Use 128 or 256.\n");
        return -1;
    }
    
    // Initialize state
    if (libkeccak_state_initialise(&state, &spec) < 0) {
        fprintf(stderr, "Error: Failed to initialize cSHAKE state\n");
        return -1;
    }
    
    // Allocate output buffer
    output = malloc(output_bytes);
    if (!output) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    // Process customization parameters for cSHAKE
    // First update with function name if provided
    if (function_name && strlen(function_name) > 0) {
        if (libkeccak_update(&state, function_name, strlen(function_name)) < 0) {
            fprintf(stderr, "Error: Failed to update with function name\n");
            free(output);
            libkeccak_state_destroy(&state);
            return -1;
        }
    }
    
    // Then update with customization string if provided  
    if (customization && strlen(customization) > 0) {
        if (libkeccak_update(&state, customization, strlen(customization)) < 0) {
            fprintf(stderr, "Error: Failed to update with customization\n");
            free(output);
            libkeccak_state_destroy(&state);
            return -1;
        }
    }
    
    // Process input and generate hash
    if (libkeccak_update(&state, input, input_len) < 0) {
        fprintf(stderr, "Error: Failed to update cSHAKE state\n");
        free(output);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    if (libkeccak_digest(&state, NULL, 0, 0, NULL, output) < 0) {
        fprintf(stderr, "Error: Failed to generate cSHAKE hash\n");
        free(output);
        libkeccak_state_destroy(&state);
        return -1;
    }
    
    printf("cSHAKE%d (%zu bytes): ", cshake_variant, output_bytes);
    print_hex(output, output_bytes);
    
    free(output);
    libkeccak_state_destroy(&state);
    return 0;
}

void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS] <input_string>\n", program_name);
    printf("Options:\n");
    printf("  --shake128 <bytes>     Generate SHAKE128 with specified output length\n");
    printf("  --shake256 <bytes>     Generate SHAKE256 with specified output length\n");
    printf("  --cshake128 <bytes> <function_name> <customization>\n");
    printf("                         Generate cSHAKE128 with customization\n");
    printf("  --cshake256 <bytes> <function_name> <customization>\n");
    printf("                         Generate cSHAKE256 with customization\n");
    printf("  --all <bytes>          Generate all variants with specified output length\n");
    printf("\nExamples:\n");
    printf("  %s --shake128 32 \"Hello World\"\n", program_name);
    printf("  %s --cshake256 64 \"MyApp\" \"Email\" \"user@example.com\"\n", program_name);
    printf("  %s --all 32 \"Test Data\"\n", program_name);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* mode = argv[1];
    const char* input;
    size_t output_bytes;
    
    if (strcmp(mode, "--shake128") == 0 && argc >= 4) {
        output_bytes = (size_t)atoi(argv[2]);
        input = argv[3];
        return shake_hash(input, strlen(input), 128, output_bytes);
        
    } else if (strcmp(mode, "--shake256") == 0 && argc >= 4) {
        output_bytes = (size_t)atoi(argv[2]);
        input = argv[3];
        return shake_hash(input, strlen(input), 256, output_bytes);
        
    } else if (strcmp(mode, "--cshake128") == 0 && argc >= 6) {
        output_bytes = (size_t)atoi(argv[2]);
        const char* function_name = argv[3];
        const char* customization = argv[4];
        input = argv[5];
        return cshake_hash(input, strlen(input), 128, output_bytes, function_name, customization);
        
    } else if (strcmp(mode, "--cshake256") == 0 && argc >= 6) {
        output_bytes = (size_t)atoi(argv[2]);
        const char* function_name = argv[3];
        const char* customization = argv[4];
        input = argv[5];
        return cshake_hash(input, strlen(input), 256, output_bytes, function_name, customization);
        
    } else if (strcmp(mode, "--all") == 0 && argc >= 4) {
        output_bytes = (size_t)atoi(argv[2]);
        input = argv[3];
        
        printf("Input: \"%s\"\n", input);
        printf("Output length: %zu bytes\n\n", output_bytes);
        
        shake_hash(input, strlen(input), 128, output_bytes);
        shake_hash(input, strlen(input), 256, output_bytes);
        cshake_hash(input, strlen(input), 128, output_bytes, "TestApp", "Example");
        cshake_hash(input, strlen(input), 256, output_bytes, "TestApp", "Example");
        
        return 0;
    } else {
        print_usage(argv[0]);
        return 1;
    }
}
