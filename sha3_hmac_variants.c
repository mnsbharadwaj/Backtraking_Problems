#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

// Maximum sizes for stack allocation
#define MAX_HASH_SIZE 64        // SHA3-512 output
#define MAX_KEY_INPUT 1024      // Maximum key input length
#define MAX_BLOCK_SIZE 144      // Maximum block size (SHA3-224)

// Helper function to safely get string length, treating NULL as empty
size_t safe_strlen(const char* str) {
    return str ? strlen(str) : 0;
}

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Context structure to hold state information
typedef struct {
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    int variant;
    size_t hash_size;
    int initialized;
} sha3_context_t;

typedef struct {
    sha3_context_t inner_ctx;
    sha3_context_t outer_ctx;
    unsigned char padded_key[MAX_BLOCK_SIZE];
    unsigned char inner_hash[MAX_HASH_SIZE];
    size_t block_size;
    int initialized;
} hmac_sha3_context_t;

// ================================
// SHA-3 Core Functions
// ================================

int sha3_init(sha3_context_t* ctx, int variant) {
    if (!ctx) {
        fprintf(stderr, "Error: NULL context\n");
        return -1;
    }
    
    memset(ctx, 0, sizeof(sha3_context_t));
    ctx->variant = variant;
    
    // Set up SHA-3 specification based on variant
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
    
    ctx->initialized = 1;
    return 0;
}

int sha3_process(sha3_context_t* ctx, const void* data, size_t len) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: Context not initialized\n");
        return -1;
    }
    
    // Handle zero-length data properly
    if (len == 0 || data == NULL) {
        return 0;  // Nothing to process, but not an error
    }
    
    if (libkeccak_update(&ctx->state, (const char*)data, len) < 0) {
        fprintf(stderr, "Error: Failed to process data\n");
        return -1;
    }
    
    return 0;
}

int sha3_finalize(sha3_context_t* ctx, unsigned char* output) {
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
    
    return 0;
}

void sha3_cleanup(sha3_context_t* ctx) {
    if (ctx && ctx->initialized) {
        libkeccak_state_destroy(&ctx->state);
        ctx->initialized = 0;
    }
}

// ================================
// HMAC-SHA3 Core Functions
// ================================

int hmac_sha3_init(hmac_sha3_context_t* ctx, int variant, const void* key, size_t key_len) {
    if (!ctx) {
        fprintf(stderr, "Error: NULL HMAC context\n");
        return -1;
    }
    
    memset(ctx, 0, sizeof(hmac_sha3_context_t));
    
    // Initialize inner and outer SHA-3 contexts
    if (sha3_init(&ctx->inner_ctx, variant) < 0) {
        return -1;
    }
    if (sha3_init(&ctx->outer_ctx, variant) < 0) {
        sha3_cleanup(&ctx->inner_ctx);
        return -1;
    }
    
    // Determine block size based on SHA-3 variant (rate in bytes)
    switch (variant) {
        case 224: ctx->block_size = 144; break;  // 1152/8
        case 256: ctx->block_size = 136; break;  // 1088/8
        case 384: ctx->block_size = 104; break;  // 832/8
        case 512: ctx->block_size = 72;  break;  // 576/8
        default:
            fprintf(stderr, "Error: Unsupported HMAC-SHA3 variant\n");
            sha3_cleanup(&ctx->inner_ctx);
            sha3_cleanup(&ctx->outer_ctx);
            return -1;
    }
    
    // Prepare key - padded_key is already zeroed from memset
    if (key_len > ctx->block_size) {
        // Key is too long, hash it first
        sha3_context_t key_ctx;
        if (sha3_init(&key_ctx, variant) < 0) {
            sha3_cleanup(&ctx->inner_ctx);
            sha3_cleanup(&ctx->outer_ctx);
            return -1;
        }
        
        if (key_len > 0 && key != NULL) {
            sha3_process(&key_ctx, key, key_len);
        }
        sha3_finalize(&key_ctx, ctx->padded_key);
        sha3_cleanup(&key_ctx);
    } else {
        // Key fits in block size, just copy it
        if (key_len > 0 && key != NULL) {
            memcpy(ctx->padded_key, key, key_len);
        }
        // Rest is already zeros from memset
    }
    
    // Create ipad and start inner hash
    unsigned char ipad[MAX_BLOCK_SIZE];
    for (size_t i = 0; i < ctx->block_size; i++) {
        ipad[i] = ctx->padded_key[i] ^ 0x36;
    }
    
    // Start inner hash with ipad
    if (sha3_process(&ctx->inner_ctx, ipad, ctx->block_size) < 0) {
        sha3_cleanup(&ctx->inner_ctx);
        sha3_cleanup(&ctx->outer_ctx);
        return -1;
    }
    
    ctx->initialized = 1;
    return 0;
}

int hmac_sha3_process(hmac_sha3_context_t* ctx, const void* data, size_t len) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: HMAC context not initialized\n");
        return -1;
    }
    
    // Process data with inner hash
    return sha3_process(&ctx->inner_ctx, data, len);
}

int hmac_sha3_finalize(hmac_sha3_context_t* ctx, unsigned char* output) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: HMAC context not initialized\n");
        return -1;
    }
    
    if (!output) {
        fprintf(stderr, "Error: NULL output buffer\n");
        return -1;
    }
    
    // Finalize inner hash
    if (sha3_finalize(&ctx->inner_ctx, ctx->inner_hash) < 0) {
        return -1;
    }
    
    // Create opad and process with outer hash
    unsigned char opad[MAX_BLOCK_SIZE];
    for (size_t i = 0; i < ctx->block_size; i++) {
        opad[i] = ctx->padded_key[i] ^ 0x5c;
    }
    
    // Process opad with outer context (which should be fresh)
    if (sha3_process(&ctx->outer_ctx, opad, ctx->block_size) < 0) {
        return -1;
    }
    
    // Process inner hash result
    if (sha3_process(&ctx->outer_ctx, ctx->inner_hash, ctx->inner_ctx.hash_size) < 0) {
        return -1;
    }
    
    // Generate final HMAC result
    if (sha3_finalize(&ctx->outer_ctx, output) < 0) {
        return -1;
    }
    
    return 0;
}

void hmac_sha3_cleanup(hmac_sha3_context_t* ctx) {
    if (ctx && ctx->initialized) {
        sha3_cleanup(&ctx->inner_ctx);
        sha3_cleanup(&ctx->outer_ctx);
        // Clear sensitive data
        memset(ctx->padded_key, 0, sizeof(ctx->padded_key));
        memset(ctx->inner_hash, 0, sizeof(ctx->inner_hash));
        ctx->initialized = 0;
    }
}

// ================================
// High-Level API Functions
// ================================

int sha3_oneshot(const char* input, size_t input_len, int variant) {
    sha3_context_t ctx;
    unsigned char output[MAX_HASH_SIZE];
    
    if (sha3_init(&ctx, variant) < 0) {
        return -1;
    }
    
    // Process input (handles zero-length properly)
    if (sha3_process(&ctx, input, input_len) < 0) {
        sha3_cleanup(&ctx);
        return -1;
    }
    
    if (sha3_finalize(&ctx, output) < 0) {
        sha3_cleanup(&ctx);
        return -1;
    }
    
    printf("SHA3-%d: ", variant);
    print_hex(output, ctx.hash_size);
    
    sha3_cleanup(&ctx);
    return 0;
}

int hmac_sha3_oneshot(const char* key, size_t key_len, const char* message, size_t message_len, int variant) {
    hmac_sha3_context_t ctx;
    unsigned char output[MAX_HASH_SIZE];
    
    if (hmac_sha3_init(&ctx, variant, key, key_len) < 0) {
        return -1;
    }
    
    // Process message (handles zero-length properly)
    if (hmac_sha3_process(&ctx, message, message_len) < 0) {
        hmac_sha3_cleanup(&ctx);
        return -1;
    }
    
    if (hmac_sha3_finalize(&ctx, output) < 0) {
        hmac_sha3_cleanup(&ctx);
        return -1;
    }
    
    printf("HMAC-SHA3-%d: ", variant);
    print_hex(output, ctx.inner_ctx.hash_size);
    
    hmac_sha3_cleanup(&ctx);
    return 0;
}

// ================================
// Streaming API Examples
// ================================

int sha3_streaming_example(const char* data1, size_t len1, const char* data2, size_t len2, int variant) {
    sha3_context_t ctx;
    unsigned char output[MAX_HASH_SIZE];
    
    printf("=== SHA3-%d STREAMING EXAMPLE ===\n", variant);
    printf("Processing data in multiple chunks...\n");
    if (len1 > 0) printf("Chunk 1: \"%s\" (%zu bytes)\n", data1, len1);
    else printf("Chunk 1: <empty> (0 bytes)\n");
    if (len2 > 0) printf("Chunk 2: \"%s\" (%zu bytes)\n", data2, len2);
    else printf("Chunk 2: <empty> (0 bytes)\n");
    
    // Initialize
    if (sha3_init(&ctx, variant) < 0) {
        return -1;
    }
    
    // Process first chunk
    if (sha3_process(&ctx, data1, len1) < 0) {
        sha3_cleanup(&ctx);
        return -1;
    }
    
    // Process second chunk
    if (sha3_process(&ctx, data2, len2) < 0) {
        sha3_cleanup(&ctx);
        return -1;
    }
    
    // Finalize
    if (sha3_finalize(&ctx, output) < 0) {
        sha3_cleanup(&ctx);
        return -1;
    }
    
    printf("Result SHA3-%d: ", variant);
    print_hex(output, ctx.hash_size);
    
    sha3_cleanup(&ctx);
    return 0;
}

int hmac_streaming_example(const char* key, size_t key_len, 
                          const char* data1, size_t len1, 
                          const char* data2, size_t len2, int variant) {
    hmac_sha3_context_t ctx;
    unsigned char output[MAX_HASH_SIZE];
    
    printf("=== HMAC-SHA3-%d STREAMING EXAMPLE ===\n", variant);
    if (key_len > 0) printf("Key: \"%s\" (%zu bytes)\n", key, key_len);
    else printf("Key: <empty> (0 bytes)\n");
    printf("Processing message in multiple chunks...\n");
    if (len1 > 0) printf("Chunk 1: \"%s\" (%zu bytes)\n", data1, len1);
    else printf("Chunk 1: <empty> (0 bytes)\n");
    if (len2 > 0) printf("Chunk 2: \"%s\" (%zu bytes)\n", data2, len2);
    else printf("Chunk 2: <empty> (0 bytes)\n");
    
    // Initialize
    if (hmac_sha3_init(&ctx, variant, key, key_len) < 0) {
        return -1;
    }
    
    // Process chunks
    if (hmac_sha3_process(&ctx, data1, len1) < 0) {
        hmac_sha3_cleanup(&ctx);
        return -1;
    }
    
    if (hmac_sha3_process(&ctx, data2, len2) < 0) {
        hmac_sha3_cleanup(&ctx);
        return -1;
    }
    
    // Finalize
    if (hmac_sha3_finalize(&ctx, output) < 0) {
        hmac_sha3_cleanup(&ctx);
        return -1;
    }
    
    printf("Result HMAC-SHA3-%d: ", variant);
    print_hex(output, ctx.inner_ctx.hash_size);
    
    hmac_sha3_cleanup(&ctx);
    return 0;
}

// Function to securely read key from user input
int read_key_input(const char* prompt, char* key_buffer, size_t buffer_size) {
    printf("%s", prompt);
    fflush(stdout);
    
    if (fgets(key_buffer, buffer_size, stdin) == NULL) {
        fprintf(stderr, "Error: Failed to read key input\n");
        return -1;
    }
    
    // Remove newline if present
    size_t len = strlen(key_buffer);
    if (len > 0 && key_buffer[len-1] == '\n') {
        key_buffer[len-1] = '\0';
    }
    
    return 0;
}

// Enhanced HMAC function with interactive key input
int hmac_sha3_with_key_input(const char* message, size_t message_len, int variant) {
    char key[MAX_KEY_INPUT];
    
    if (read_key_input("Enter HMAC key (or press Enter for empty key): ", key, sizeof(key)) < 0) {
        return -1;
    }
    
    size_t key_len = strlen(key);
    printf("Using key: ");
    if (key_len == 0) {
        printf("<empty> (0 bytes)\n");
    } else {
        printf("\"%s\" (%zu bytes)\n", key, key_len);
    }
    
    int result = hmac_sha3_oneshot(key, key_len, message, message_len, variant);
    
    // Clear key from memory for security
    memset(key, 0, sizeof(key));
    
    return result;
}

int hmac_sha3_all_variants_with_key_input(const char* message, size_t message_len) {
    char key[MAX_KEY_INPUT];
    
    if (read_key_input("Enter HMAC key (or press Enter for empty key): ", key, sizeof(key)) < 0) {
        return -1;
    }
    
    size_t key_len = strlen(key);
    printf("Using key: ");
    if (key_len == 0) {
        printf("<empty> (0 bytes)\n");
    } else {
        printf("\"%s\" (%zu bytes)\n", key, key_len);
    }
    
    int result = hmac_sha3_all_variants(key, key_len, message, message_len);
    
    // Clear key from memory for security
    memset(key, 0, sizeof(key));
    
    return result;
}

// Enhanced streaming HMAC with key input
int hmac_streaming_with_key_input(const char* data1, size_t len1, 
                                 const char* data2, size_t len2, int variant) {
    char key[MAX_KEY_INPUT];
    
    if (read_key_input("Enter HMAC key (or press Enter for empty key): ", key, sizeof(key)) < 0) {
        return -1;
    }
    
    size_t key_len = strlen(key);
    int result = hmac_streaming_example(key, key_len, data1, len1, data2, len2, variant);
    
    // Clear key from memory for security
    memset(key, 0, sizeof(key));
    
    return result;
}

// ================================
// Utility Functions
// ================================

int sha3_all_variants(const char* input, size_t input_len) {
    if (input_len == 0) {
        printf("Input: <empty> (0 bytes)\n");
    } else {
        printf("Input: \"%s\" (%zu bytes)\n", input, input_len);
    }
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

int hmac_sha3_all_variants(const char* key, size_t key_len, const char* message, size_t message_len) {
    if (key_len == 0) {
        printf("Key: <empty> (0 bytes)\n");
    } else {
        printf("Key: \"%s\" (%zu bytes)\n", key, key_len);
    }
    
    if (message_len == 0) {
        printf("Message: <empty> (0 bytes)\n");
    } else {
        printf("Message: \"%s\" (%zu bytes)\n", message, message_len);
    }
    printf("Computing all HMAC-SHA3 variants...\n\n");
    
    int variants[] = {224, 256, 384, 512};
    int num_variants = sizeof(variants) / sizeof(variants[0]);
    
    for (int i = 0; i < num_variants; i++) {
        if (hmac_sha3_oneshot(key, key_len, message, message_len, variants[i]) < 0) {
            return -1;
        }
    }
    
    return 0;
}

void print_usage(const char* program_name) {
    printf("SHA-3 and HMAC-SHA3 Calculator - Stack-Based Arrays\n");
    printf("Usage: %s [OPTIONS] [ARGS]\n\n", program_name);
    
    printf("SHA-3 Options:\n");
    printf("  --sha3-224 <input>     Compute SHA3-224\n");
    printf("  --sha3-256 <input>     Compute SHA3-256\n");
    printf("  --sha3-384 <input>     Compute SHA3-384\n");
    printf("  --sha3-512 <input>     Compute SHA3-512\n");
    printf("  --all <input>          Compute all SHA3 variants\n");
    printf("  --empty                Compute hash of empty string\n\n");
    
    printf("HMAC-SHA3 Options:\n");
    printf("  --hmac-224 <key> <message>     Compute HMAC-SHA3-224\n");
    printf("  --hmac-256 <key> <message>     Compute HMAC-SHA3-256\n");
    printf("  --hmac-384 <key> <message>     Compute HMAC-SHA3-384\n");
    printf("  --hmac-512 <key> <message>     Compute HMAC-SHA3-512\n");
    printf("  --hmac-all <key> <message>     Compute all HMAC-SHA3 variants\n\n");
    
    printf("Interactive Key Input:\n");
    printf("  --hmac-224-key <message>       Prompt for key, then compute HMAC-SHA3-224\n");
    printf("  --hmac-256-key <message>       Prompt for key, then compute HMAC-SHA3-256\n");
    printf("  --hmac-384-key <message>       Prompt for key, then compute HMAC-SHA3-384\n");
    printf("  --hmac-512-key <message>       Prompt for key, then compute HMAC-SHA3-512\n");
    printf("  --hmac-all-key <message>       Prompt for key, then compute all HMAC variants\n\n");
    
    printf("Streaming Examples:\n");
    printf("  --stream-sha3 <variant> <data1> <data2>    Streaming SHA3 example\n");
    printf("  --stream-hmac <variant> <key> <data1> <data2>  Streaming HMAC example\n");
    printf("  --stream-hmac-key <variant> <data1> <data2>    Streaming HMAC with key input\n\n");
    
    printf("Zero-Length Data Support:\n");
    printf("  Use \"\" for empty strings or omit arguments for interactive input\n");
    printf("  All functions properly handle zero-length keys and messages\n\n");
    
    printf("Examples:\n");
    printf("  %s --sha3-256 \"Hello World\"            # Basic SHA3\n", program_name);
    printf("  %s --sha3-256 \"\"                       # SHA3 of empty string\n", program_name);
    printf("  %s --hmac-256 \"secret\" \"message\"       # Basic HMAC\n", program_name);
    printf("  %s --hmac-256 \"\" \"message\"             # HMAC with empty key\n", program_name);
    printf("  %s --hmac-256 \"key\" \"\"                 # HMAC with empty message\n", program_name);
    printf("  %s --hmac-256-key \"message\"             # Interactive key input\n", program_name);
    printf("  %s --stream-hmac-key 256 \"part1\" \"part2\" # Streaming with key input\n", program_name);
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
        
    } else if (strcmp(mode, "--empty") == 0) {
        return sha3_all_variants("", 0);
        
    } else if (strcmp(mode, "--sha3-224") == 0) {
        const char* input = (argc >= 3) ? argv[2] : "";
        return sha3_oneshot(input, strlen(input), 224);
        
    } else if (strcmp(mode, "--sha3-256") == 0) {
        const char* input = (argc >= 3) ? argv[2] : "";
        return sha3_oneshot(input, strlen(input), 256);
        
    } else if (strcmp(mode, "--sha3-384") == 0) {
        const char* input = (argc >= 3) ? argv[2] : "";
        return sha3_oneshot(input, strlen(input), 384);
        
    } else if (strcmp(mode, "--sha3-512") == 0) {
        const char* input = (argc >= 3) ? argv[2] : "";
        return sha3_oneshot(input, strlen(input), 512);
        
    } else if (strcmp(mode, "--all") == 0) {
        const char* input = (argc >= 3) ? argv[2] : "";
        return sha3_all_variants(input, strlen(input));
        
    } else if (strcmp(mode, "--hmac-224") == 0) {
        const char* key = (argc >= 3) ? argv[2] : "";
        const char* message = (argc >= 4) ? argv[3] : "";
        return hmac_sha3_oneshot(key, strlen(key), message, strlen(message), 224);
        
    } else if (strcmp(mode, "--hmac-256") == 0) {
        const char* key = (argc >= 3) ? argv[2] : "";
        const char* message = (argc >= 4) ? argv[3] : "";
        return hmac_sha3_oneshot(key, strlen(key), message, strlen(message), 256);
        
    } else if (strcmp(mode, "--hmac-384") == 0) {
        const char* key = (argc >= 3) ? argv[2] : "";
        const char* message = (argc >= 4) ? argv[3] : "";
        return hmac_sha3_oneshot(key, strlen(key), message, strlen(message), 384);
        
    } else if (strcmp(mode, "--hmac-512") == 0) {
        const char* key = (argc >= 3) ? argv[2] : "";
        const char* message = (argc >= 4) ? argv[3] : "";
        return hmac_sha3_oneshot(key, strlen(key), message, strlen(message), 512);
        
    } else if (strcmp(mode, "--hmac-all") == 0) {
        const char* key = (argc >= 3) ? argv[2] : "";
        const char* message = (argc >= 4) ? argv[3] : "";
        return hmac_sha3_all_variants(key, strlen(key), message, strlen(message));
        
    // Interactive key input modes
    } else if (strcmp(mode, "--hmac-224-key") == 0) {
        const char* message = (argc >= 3) ? argv[2] : "";
        return hmac_sha3_with_key_input(message, strlen(message), 224);
        
    } else if (strcmp(mode, "--hmac-256-key") == 0) {
        const char* message = (argc >= 3) ? argv[2] : "";
        return hmac_sha3_with_key_input(message, strlen(message), 256);
        
    } else if (strcmp(mode, "--hmac-384-key") == 0) {
        const char* message = (argc >= 3) ? argv[2] : "";
        return hmac_sha3_with_key_input(message, strlen(message), 384);
        
    } else if (strcmp(mode, "--hmac-512-key") == 0) {
        const char* message = (argc >= 3) ? argv[2] : "";
        return hmac_sha3_with_key_input(message, strlen(message), 512);
        
    } else if (strcmp(mode, "--hmac-all-key") == 0) {
        const char* message = (argc >= 3) ? argv[2] : "";
        return hmac_sha3_all_variants_with_key_input(message, strlen(message));
        
    // Streaming modes
    } else if (strcmp(mode, "--stream-sha3") == 0 && argc >= 5) {
        int variant = atoi(argv[2]);
        const char* data1 = argv[3];
        const char* data2 = argv[4];
        return sha3_streaming_example(data1, strlen(data1), data2, strlen(data2), variant);
        
    } else if (strcmp(mode, "--stream-hmac") == 0 && argc >= 6) {
        int variant = atoi(argv[2]);
        const char* key = argv[3];
        const char* data1 = argv[4];
        const char* data2 = argv[5];
        return hmac_streaming_example(key, strlen(key), data1, strlen(data1), data2, strlen(data2), variant);
        
    } else if (strcmp(mode, "--stream-hmac-key") == 0 && argc >= 5) {
        int variant = atoi(argv[2]);
        const char* data1 = argv[3];
        const char* data2 = argv[4];
        return hmac_streaming_with_key_input(data1, strlen(data1), data2, strlen(data2), variant);
        
    } else {
        printf("Computing all SHA-3 variants for input...\n\n");
        return sha3_all_variants(argv[1], strlen(argv[1]));
    }
}
