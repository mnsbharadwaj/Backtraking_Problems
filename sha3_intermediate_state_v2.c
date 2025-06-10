#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

// Maximum sizes for stack allocation
#define MAX_HASH_SIZE 64        // SHA3-512 output
#define STATE_SIZE 200          // Keccak state size in bytes
#define MAX_HEX_INPUT 800       // 400 hex chars + safety margin

// Helper functions
size_t safe_strlen(const char* str) {
    return str ? strlen(str) : 0;
}

void print_hex(const unsigned char* data, size_t len, const char* label) {
    if (label) printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i < len - 1) printf("\n    ");
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

// Context structure for SHA-3 with intermediate state access
typedef struct {
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    int variant;
    size_t hash_size;
    unsigned char current_state[STATE_SIZE];
    int initialized;
    int state_captured;  // Flag to track if we've captured intermediate state
} sha3_intermediate_context_t;

// ================================
// SHA-3 Intermediate Core Functions
// ================================

int sha3_intermediate_init(sha3_intermediate_context_t* ctx, int variant) {
    if (!ctx) {
        fprintf(stderr, "Error: NULL context\n");
        return -1;
    }
    
    memset(ctx, 0, sizeof(sha3_intermediate_context_t));
    ctx->variant = variant;
    
    // Set up SHA-3 specification
    switch (variant) {
        case 224:
            libkeccak_spec_sha3(&ctx->spec, 224);
            ctx->hash_size = 28;
            break;
        case 256:
            libkeccak_spec_sha3(&ctx->spec, 256);
            ctx->hash_size = 32;
            break;
        case 384:
            libkeccak_spec_sha3(&ctx->spec, 384);
            ctx->hash_size = 48;
            break;
        case 512:
            libkeccak_spec_sha3(&ctx->spec, 512);
            ctx->hash_size = 64;
            break;
        default:
            fprintf(stderr, "Error: Unsupported SHA-3 variant. Use 224, 256, 384, or 512\n");
            return -1;
    }
    
    // Initialize state
    if (libkeccak_state_initialise(&ctx->state, &ctx->spec) < 0) {
        fprintf(stderr, "Error: Failed to initialize SHA-3-%d state\n", variant);
        return -1;
    }
    
    // Capture initial state (all zeros)
    memcpy(ctx->current_state, &ctx->state.S, STATE_SIZE);
    ctx->initialized = 1;
    return 0;
}

int sha3_intermediate_process(sha3_intermediate_context_t* ctx, const void* data, size_t len) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: Context not initialized\n");
        return -1;
    }
    
    // Handle zero-length data
    if (len == 0 || data == NULL) {
        return 0;
    }
    
    if (libkeccak_update(&ctx->state, (const char*)data, len) < 0) {
        fprintf(stderr, "Error: Failed to process data\n");
        return -1;
    }
    
    // Capture current state after processing
    memcpy(ctx->current_state, &ctx->state.S, STATE_SIZE);
    ctx->state_captured = 1;
    
    return 0;
}

int sha3_intermediate_finalize(sha3_intermediate_context_t* ctx, unsigned char* output) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: Context not initialized\n");
        return -1;
    }
    
    if (!output) {
        fprintf(stderr, "Error: NULL output buffer\n");
        return -1;
    }
    
    if (libkeccak_digest(&ctx->state, NULL, 0, 0, NULL, output) < 0) {
        fprintf(stderr, "Error: Failed to generate SHA-3-%d hash\n", ctx->variant);
        return -1;
    }
    
    // Capture final state after finalization
    memcpy(ctx->current_state, &ctx->state.S, STATE_SIZE);
    
    return 0;
}

int sha3_intermediate_get_state(sha3_intermediate_context_t* ctx, unsigned char* state_output) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: Context not initialized\n");
        return -1;
    }
    
    if (!state_output) {
        fprintf(stderr, "Error: NULL state output buffer\n");
        return -1;
    }
    
    memcpy(state_output, ctx->current_state, STATE_SIZE);
    return 0;
}

int sha3_intermediate_set_state(sha3_intermediate_context_t* ctx, const unsigned char* state_input) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: Context not initialized\n");
        return -1;
    }
    
    if (!state_input) {
        fprintf(stderr, "Error: NULL state input\n");
        return -1;
    }
    
    // Load the provided state into both our copy and the libkeccak state
    memcpy(ctx->current_state, state_input, STATE_SIZE);
    memcpy(&ctx->state.S, state_input, STATE_SIZE);
    ctx->state_captured = 1;
    
    return 0;
}

void sha3_intermediate_cleanup(sha3_intermediate_context_t* ctx) {
    if (ctx && ctx->initialized) {
        libkeccak_state_destroy(&ctx->state);
        memset(ctx->current_state, 0, STATE_SIZE);
        ctx->initialized = 0;
        ctx->state_captured = 0;
    }
}

// ================================
// Utility Functions for Hex Conversion
// ================================

int hex_to_bytes(const char* hex_string, unsigned char* bytes, size_t expected_bytes) {
    if (!hex_string || !bytes) {
        fprintf(stderr, "Error: NULL input\n");
        return -1;
    }
    
    size_t hex_len = strlen(hex_string);
    if (hex_len != expected_bytes * 2) {
        fprintf(stderr, "Error: Expected %zu hex characters, got %zu\n", expected_bytes * 2, hex_len);
        return -1;
    }
    
    for (size_t i = 0; i < expected_bytes; i++) {
        char hex_byte[3] = {hex_string[i*2], hex_string[i*2+1], '\0'};
        char* endptr;
        long byte_val = strtol(hex_byte, &endptr, 16);
        
        if (*endptr != '\0' || byte_val < 0 || byte_val > 255) {
            fprintf(stderr, "Error: Invalid hex byte at position %zu: %.2s\n", i, hex_byte);
            return -1;
        }
        
        bytes[i] = (unsigned char)byte_val;
    }
    
    return 0;
}

void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex_string) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_string + i*2, "%02x", bytes[i]);
    }
    hex_string[len*2] = '\0';
}

// ================================
// High-Level API Functions
// ================================

int sha3_with_state_dump(const char* input, size_t input_len, int variant) {
    sha3_intermediate_context_t ctx;
    unsigned char output[MAX_HASH_SIZE];
    unsigned char state_after_input[STATE_SIZE];
    char hex_state[STATE_SIZE * 2 + 1];
    
    printf("=== SHA-3-%d WITH STATE DUMP ===\n", variant);
    if (input_len == 0) {
        printf("Input: <empty> (0 bytes)\n");
    } else {
        printf("Input: \"%s\" (%zu bytes)\n", input, input_len);
    }
    
    // Initialize
    if (sha3_intermediate_init(&ctx, variant) < 0) {
        return -1;
    }
    
    printf("\nInitial state (all zeros):\n");
    print_hex(ctx.current_state, STATE_SIZE, "State");
    
    // Process input
    if (sha3_intermediate_process(&ctx, input, input_len) < 0) {
        sha3_intermediate_cleanup(&ctx);
        return -1;
    }
    
    // Get intermediate state after input processing
    if (sha3_intermediate_get_state(&ctx, state_after_input) < 0) {
        sha3_intermediate_cleanup(&ctx);
        return -1;
    }
    
    printf("\n*** INTERMEDIATE STATE AFTER INPUT ***\n");
    print_hex(state_after_input, STATE_SIZE, "200-byte state");
    print_state_lanes((uint64_t*)state_after_input);
    
    // Convert to hex string for easy copying
    bytes_to_hex(state_after_input, STATE_SIZE, hex_state);
    printf("Hex string (copy this for --from-state):\n%s\n\n", hex_state);
    
    // Finalize
    if (sha3_intermediate_finalize(&ctx, output) < 0) {
        sha3_intermediate_cleanup(&ctx);
        return -1;
    }
    
    printf("Final hash:\n");
    print_hex(output, ctx.hash_size, "SHA-3");
    
    sha3_intermediate_cleanup(&ctx);
    return 0;
}

int sha3_from_intermediate_state(const char* state_hex, const char* additional_data, 
                                size_t additional_len, int variant) {
    sha3_intermediate_context_t ctx;
    unsigned char intermediate_state[STATE_SIZE];
    unsigned char output[MAX_HASH_SIZE];
    
    printf("=== SHA-3-%d FROM INTERMEDIATE STATE ===\n", variant);
    
    // Convert hex string to bytes
    if (hex_to_bytes(state_hex, intermediate_state, STATE_SIZE) < 0) {
        fprintf(stderr, "Error: Failed to parse intermediate state hex\n");
        return -1;
    }
    
    // Initialize context
    if (sha3_intermediate_init(&ctx, variant) < 0) {
        return -1;
    }
    
    // Load the intermediate state
    if (sha3_intermediate_set_state(&ctx, intermediate_state) < 0) {
        sha3_intermediate_cleanup(&ctx);
        return -1;
    }
    
    printf("Loaded intermediate state:\n");
    print_hex(intermediate_state, STATE_SIZE, "State");
    print_state_lanes((uint64_t*)intermediate_state);
    
    // Process additional data if provided
    if (additional_data && additional_len > 0) {
        printf("Processing additional data: \"%s\" (%zu bytes)\n", additional_data, additional_len);
        
        if (sha3_intermediate_process(&ctx, additional_data, additional_len) < 0) {
            sha3_intermediate_cleanup(&ctx);
            return -1;
        }
        
        printf("\nState after processing additional data:\n");
        print_hex(ctx.current_state, STATE_SIZE, "State");
        print_state_lanes((uint64_t*)ctx.current_state);
    } else {
        printf("No additional data to process\n");
    }
    
    // Finalize
    if (sha3_intermediate_finalize(&ctx, output) < 0) {
        sha3_intermediate_cleanup(&ctx);
        return -1;
    }
    
    printf("\nFinal hash:\n");
    print_hex(output, ctx.hash_size, "SHA-3");
    
    sha3_intermediate_cleanup(&ctx);
    return 0;
}

int sha3_streaming_with_states(const char* data1, size_t len1, const char* data2, size_t len2, int variant) {
    sha3_intermediate_context_t ctx;
    unsigned char output[MAX_HASH_SIZE];
    unsigned char state_buffer[STATE_SIZE];
    char hex_state[STATE_SIZE * 2 + 1];
    
    printf("=== SHA-3-%d STREAMING WITH INTERMEDIATE STATES ===\n", variant);
    if (len1 > 0) printf("Chunk 1: \"%s\" (%zu bytes)\n", data1, len1);
    else printf("Chunk 1: <empty> (0 bytes)\n");
    if (len2 > 0) printf("Chunk 2: \"%s\" (%zu bytes)\n", data2, len2);
    else printf("Chunk 2: <empty> (0 bytes)\n");
    
    // Initialize
    if (sha3_intermediate_init(&ctx, variant) < 0) {
        return -1;
    }
    
    printf("\nStep 1: Initial state\n");
    print_hex(ctx.current_state, STATE_SIZE, "State");
    
    // Process first chunk
    if (sha3_intermediate_process(&ctx, data1, len1) < 0) {
        sha3_intermediate_cleanup(&ctx);
        return -1;
    }
    
    sha3_intermediate_get_state(&ctx, state_buffer);
    printf("\nStep 2: State after first chunk\n");
    print_hex(state_buffer, STATE_SIZE, "State");
    bytes_to_hex(state_buffer, STATE_SIZE, hex_state);
    printf("Hex: %s\n", hex_state);
    
    // Process second chunk
    if (sha3_intermediate_process(&ctx, data2, len2) < 0) {
        sha3_intermediate_cleanup(&ctx);
        return -1;
    }
    
    sha3_intermediate_get_state(&ctx, state_buffer);
    printf("\nStep 3: State after second chunk\n");
    print_hex(state_buffer, STATE_SIZE, "State");
    bytes_to_hex(state_buffer, STATE_SIZE, hex_state);
    printf("Hex: %s\n", hex_state);
    
    // Finalize
    if (sha3_intermediate_finalize(&ctx, output) < 0) {
        sha3_intermediate_cleanup(&ctx);
        return -1;
    }
    
    printf("\nFinal result:\n");
    print_hex(output, ctx.hash_size, "SHA-3");
    
    sha3_intermediate_cleanup(&ctx);
    return 0;
}

int sha3_verify_intermediate_computation(const char* full_input, const char* split_point, int variant) {
    size_t full_len = strlen(full_input);
    size_t split_pos = strlen(split_point);
    
    if (split_pos > full_len) {
        fprintf(stderr, "Error: Split point longer than full input\n");
        return -1;
    }
    
    printf("=== VERIFICATION: FULL vs INTERMEDIATE COMPUTATION ===\n");
    printf("Full input: \"%s\"\n", full_input);
    printf("Split after: \"%s\" (position %zu)\n", split_point, split_pos);
    printf("Remaining: \"%s\"\n\n", full_input + split_pos);
    
    // Method 1: Full computation
    printf("Method 1: Full computation\n");
    sha3_intermediate_context_t ctx1;
    unsigned char output1[MAX_HASH_SIZE];
    
    if (sha3_intermediate_init(&ctx1, variant) < 0) return -1;
    if (sha3_intermediate_process(&ctx1, full_input, full_len) < 0) {
        sha3_intermediate_cleanup(&ctx1);
        return -1;
    }
    if (sha3_intermediate_finalize(&ctx1, output1) < 0) {
        sha3_intermediate_cleanup(&ctx1);
        return -1;
    }
    
    print_hex(output1, ctx1.hash_size, "Full hash");
    sha3_intermediate_cleanup(&ctx1);
    
    // Method 2: Split computation
    printf("\nMethod 2: Split computation\n");
    sha3_intermediate_context_t ctx2;
    unsigned char output2[MAX_HASH_SIZE];
    unsigned char intermediate_state[STATE_SIZE];
    char hex_state[STATE_SIZE * 2 + 1];
    
    // First part
    if (sha3_intermediate_init(&ctx2, variant) < 0) return -1;
    if (sha3_intermediate_process(&ctx2, split_point, split_pos) < 0) {
        sha3_intermediate_cleanup(&ctx2);
        return -1;
    }
    
    // Get intermediate state
    sha3_intermediate_get_state(&ctx2, intermediate_state);
    bytes_to_hex(intermediate_state, STATE_SIZE, hex_state);
    printf("Intermediate state: %s\n", hex_state);
    
    // Continue with remaining data
    if (sha3_intermediate_process(&ctx2, full_input + split_pos, full_len - split_pos) < 0) {
        sha3_intermediate_cleanup(&ctx2);
        return -1;
    }
    if (sha3_intermediate_finalize(&ctx2, output2) < 0) {
        sha3_intermediate_cleanup(&ctx2);
        return -1;
    }
    
    print_hex(output2, ctx2.hash_size, "Split hash");
    sha3_intermediate_cleanup(&ctx2);
    
    // Compare results
    printf("\n=== VERIFICATION RESULT ===\n");
    if (memcmp(output1, output2, ctx1.hash_size) == 0) {
        printf("✅ SUCCESS: Both methods produce identical results!\n");
        return 0;
    } else {
        printf("❌ ERROR: Methods produce different results!\n");
        return -1;
    }
}

void print_usage(const char* program_name) {
    printf("SHA-3 with 200-byte Intermediate State Access\n");
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    
    printf("State Dump Options:\n");
    printf("  --dump <variant> <input>              Show intermediate state after input\n");
    printf("  --from-state <variant> <state_hex> [additional_data]\n");
    printf("                                        Continue from intermediate state\n\n");
    
    printf("Streaming Options:\n");
    printf("  --stream <variant> <data1> <data2>    Stream with intermediate states\n");
    printf("  --verify <variant> <full_input> <split_point>\n");
    printf("                                        Verify split computation\n\n");
    
    printf("Variants: 224, 256, 384, 512\n\n");
    
    printf("Examples:\n");
    printf("  # Get intermediate state\n");
    printf("  %s --dump 256 \"Hello\"\n", program_name);
    printf("\n");
    printf("  # Use intermediate state\n");
    printf("  %s --from-state 256 <400-hex-chars> \" World\"\n", program_name);
    printf("\n");
    printf("  # Streaming with states\n");
    printf("  %s --stream 256 \"Hello\" \" World\"\n", program_name);
    printf("\n");
    printf("  # Verify computation\n");
    printf("  %s --verify 256 \"Hello World\" \"Hello\"\n", program_name);
    printf("\n");
    printf("Note: state_hex should be exactly 400 hex characters (200 bytes)\n");
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
        
    } else if (strcmp(mode, "--dump") == 0 && argc >= 4) {
        int variant = atoi(argv[2]);
        const char* input = argv[3];
        return sha3_with_state_dump(input, strlen(input), variant);
        
    } else if (strcmp(mode, "--from-state") == 0 && argc >= 4) {
        int variant = atoi(argv[2]);
        const char* state_hex = argv[3];
        const char* additional = (argc >= 5) ? argv[4] : NULL;
        size_t additional_len = additional ? strlen(additional) : 0;
        return sha3_from_intermediate_state(state_hex, additional, additional_len, variant);
        
    } else if (strcmp(mode, "--stream") == 0 && argc >= 5) {
        int variant = atoi(argv[2]);
        const char* data1 = argv[3];
        const char* data2 = argv[4];
        return sha3_streaming_with_states(data1, strlen(data1), data2, strlen(data2), variant);
        
    } else if (strcmp(mode, "--verify") == 0 && argc >= 5) {
        int variant = atoi(argv[2]);
        const char* full_input = argv[3];
        const char* split_point = argv[4];
        return sha3_verify_intermediate_computation(full_input, split_point, variant);
        
    } else {
        print_usage(argv[0]);
        return 1;
    }
}
