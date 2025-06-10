#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

// Maximum sizes for stack allocation
#define MAX_OUTPUT_SIZE 1024    // Maximum output length
#define MAX_FUNCTION_NAME 256   // Maximum function name length
#define MAX_CUSTOMIZATION 512   // Maximum customization string length
#define MAX_INPUT_BUFFER 2048   // Maximum input buffer

// Helper function to safely get string length
size_t safe_strlen(const char* str) {
    return str ? strlen(str) : 0;
}

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i < len - 1) printf("\n    ");
    }
    printf("\n");
}

// Context structures for SHAKE and cSHAKE
typedef struct {
    struct libkeccak_spec spec;
    struct libkeccak_state state;
    int variant;           // 128 or 256
    size_t output_length;  // Desired output length in bytes
    int initialized;
} shake_context_t;

typedef struct {
    shake_context_t base_ctx;
    char function_name[MAX_FUNCTION_NAME];
    char customization[MAX_CUSTOMIZATION];
    int has_customization;  // Flag if we have any customization
    int initialized;
} cshake_context_t;

// ================================
// SHAKE Core Functions
// ================================

int shake_init(shake_context_t* ctx, int variant, size_t output_length) {
    if (!ctx) {
        fprintf(stderr, "Error: NULL SHAKE context\n");
        return -1;
    }
    
    if (variant != 128 && variant != 256) {
        fprintf(stderr, "Error: Unsupported SHAKE variant. Use 128 or 256\n");
        return -1;
    }
    
    if (output_length == 0 || output_length > MAX_OUTPUT_SIZE) {
        fprintf(stderr, "Error: Invalid output length. Use 1-%d bytes\n", MAX_OUTPUT_SIZE);
        return -1;
    }
    
    memset(ctx, 0, sizeof(shake_context_t));
    ctx->variant = variant;
    ctx->output_length = output_length;
    
    // Set up SHAKE specification
    libkeccak_spec_shake(&ctx->spec, variant, output_length * 8);  // bits
    
    // Initialize state
    if (libkeccak_state_initialise(&ctx->state, &ctx->spec) < 0) {
        fprintf(stderr, "Error: Failed to initialize SHAKE%d state\n", variant);
        return -1;
    }
    
    ctx->initialized = 1;
    return 0;
}

int shake_process(shake_context_t* ctx, const void* data, size_t len) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: SHAKE context not initialized\n");
        return -1;
    }
    
    // Handle zero-length data
    if (len == 0 || data == NULL) {
        return 0;
    }
    
    if (libkeccak_update(&ctx->state, (const char*)data, len) < 0) {
        fprintf(stderr, "Error: Failed to process data in SHAKE\n");
        return -1;
    }
    
    return 0;
}

int shake_finalize(shake_context_t* ctx, unsigned char* output) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: SHAKE context not initialized\n");
        return -1;
    }
    
    if (!output) {
        fprintf(stderr, "Error: NULL output buffer\n");
        return -1;
    }
    
    if (libkeccak_digest(&ctx->state, NULL, 0, 0, NULL, output) < 0) {
        fprintf(stderr, "Error: Failed to generate SHAKE%d output\n", ctx->variant);
        return -1;
    }
    
    return 0;
}

void shake_cleanup(shake_context_t* ctx) {
    if (ctx && ctx->initialized) {
        libkeccak_state_destroy(&ctx->state);
        ctx->initialized = 0;
    }
}

// ================================
// cSHAKE Core Functions  
// ================================

int cshake_init(cshake_context_t* ctx, int variant, size_t output_length, 
                const char* function_name, const char* customization) {
    if (!ctx) {
        fprintf(stderr, "Error: NULL cSHAKE context\n");
        return -1;
    }
    
    memset(ctx, 0, sizeof(cshake_context_t));
    
    // Copy function name and customization (handle NULLs)
    if (function_name && strlen(function_name) > 0) {
        strncpy(ctx->function_name, function_name, sizeof(ctx->function_name) - 1);
        ctx->has_customization = 1;
    }
    
    if (customization && strlen(customization) > 0) {
        strncpy(ctx->customization, customization, sizeof(ctx->customization) - 1);
        ctx->has_customization = 1;
    }
    
    // If no customization, cSHAKE = SHAKE
    if (!ctx->has_customization) {
        printf("Note: No customization provided, cSHAKE%d equals SHAKE%d\n", variant, variant);
        return shake_init(&ctx->base_ctx, variant, output_length);
    }
    
    // Initialize base SHAKE context
    if (shake_init(&ctx->base_ctx, variant, output_length) < 0) {
        return -1;
    }
    
    // Process customization parameters first
    if (ctx->function_name[0] != '\0') {
        if (shake_process(&ctx->base_ctx, ctx->function_name, strlen(ctx->function_name)) < 0) {
            shake_cleanup(&ctx->base_ctx);
            return -1;
        }
    }
    
    if (ctx->customization[0] != '\0') {
        if (shake_process(&ctx->base_ctx, ctx->customization, strlen(ctx->customization)) < 0) {
            shake_cleanup(&ctx->base_ctx);
            return -1;
        }
    }
    
    ctx->initialized = 1;
    return 0;
}

int cshake_process(cshake_context_t* ctx, const void* data, size_t len) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: cSHAKE context not initialized\n");
        return -1;
    }
    
    return shake_process(&ctx->base_ctx, data, len);
}

int cshake_finalize(cshake_context_t* ctx, unsigned char* output) {
    if (!ctx || !ctx->initialized) {
        fprintf(stderr, "Error: cSHAKE context not initialized\n");
        return -1;
    }
    
    return shake_finalize(&ctx->base_ctx, output);
}

void cshake_cleanup(cshake_context_t* ctx) {
    if (ctx && ctx->initialized) {
        shake_cleanup(&ctx->base_ctx);
        // Clear sensitive customization data
        memset(ctx->function_name, 0, sizeof(ctx->function_name));
        memset(ctx->customization, 0, sizeof(ctx->customization));
        ctx->initialized = 0;
    }
}

// ================================
// High-Level API Functions
// ================================

int shake_oneshot(const char* input, size_t input_len, int variant, size_t output_len) {
    shake_context_t ctx;
    unsigned char output[MAX_OUTPUT_SIZE];
    
    if (output_len > MAX_OUTPUT_SIZE) {
        fprintf(stderr, "Error: Output length too large (max %d bytes)\n", MAX_OUTPUT_SIZE);
        return -1;
    }
    
    if (shake_init(&ctx, variant, output_len) < 0) {
        return -1;
    }
    
    if (shake_process(&ctx, input, input_len) < 0) {
        shake_cleanup(&ctx);
        return -1;
    }
    
    if (shake_finalize(&ctx, output) < 0) {
        shake_cleanup(&ctx);
        return -1;
    }
    
    printf("SHAKE%d (%zu bytes): ", variant, output_len);
    print_hex(output, output_len);
    
    shake_cleanup(&ctx);
    return 0;
}

int cshake_oneshot(const char* input, size_t input_len, int variant, size_t output_len,
                   const char* function_name, const char* customization) {
    cshake_context_t ctx;
    unsigned char output[MAX_OUTPUT_SIZE];
    
    if (output_len > MAX_OUTPUT_SIZE) {
        fprintf(stderr, "Error: Output length too large (max %d bytes)\n", MAX_OUTPUT_SIZE);
        return -1;
    }
    
    if (cshake_init(&ctx, variant, output_len, function_name, customization) < 0) {
        return -1;
    }
    
    if (cshake_process(&ctx, input, input_len) < 0) {
        cshake_cleanup(&ctx);
        return -1;
    }
    
    if (cshake_finalize(&ctx, output) < 0) {
        cshake_cleanup(&ctx);
        return -1;
    }
    
    printf("cSHAKE%d (%zu bytes): ", variant, output_len);
    print_hex(output, output_len);
    
    cshake_cleanup(&ctx);
    return 0;
}

// ================================
// Streaming Examples
// ================================

int shake_streaming_example(const char* data1, size_t len1, const char* data2, size_t len2, 
                           int variant, size_t output_len) {
    shake_context_t ctx;
    unsigned char output[MAX_OUTPUT_SIZE];
    
    printf("=== SHAKE%d STREAMING EXAMPLE ===\n", variant);
    printf("Output length: %zu bytes\n", output_len);
    if (len1 > 0) printf("Chunk 1: \"%s\" (%zu bytes)\n", data1, len1);
    else printf("Chunk 1: <empty> (0 bytes)\n");
    if (len2 > 0) printf("Chunk 2: \"%s\" (%zu bytes)\n", data2, len2);
    else printf("Chunk 2: <empty> (0 bytes)\n");
    
    if (shake_init(&ctx, variant, output_len) < 0) {
        return -1;
    }
    
    if (shake_process(&ctx, data1, len1) < 0) {
        shake_cleanup(&ctx);
        return -1;
    }
    
    if (shake_process(&ctx, data2, len2) < 0) {
        shake_cleanup(&ctx);
        return -1;
    }
    
    if (shake_finalize(&ctx, output) < 0) {
        shake_cleanup(&ctx);
        return -1;
    }
    
    printf("Result: ");
    print_hex(output, output_len);
    
    shake_cleanup(&ctx);
    return 0;
}

int cshake_streaming_example(const char* data1, size_t len1, const char* data2, size_t len2,
                            int variant, size_t output_len, const char* function_name, 
                            const char* customization) {
    cshake_context_t ctx;
    unsigned char output[MAX_OUTPUT_SIZE];
    
    printf("=== cSHAKE%d STREAMING EXAMPLE ===\n", variant);
    printf("Output length: %zu bytes\n", output_len);
    printf("Function name: \"%s\"\n", function_name ? function_name : "");
    printf("Customization: \"%s\"\n", customization ? customization : "");
    if (len1 > 0) printf("Chunk 1: \"%s\" (%zu bytes)\n", data1, len1);
    else printf("Chunk 1: <empty> (0 bytes)\n");
    if (len2 > 0) printf("Chunk 2: \"%s\" (%zu bytes)\n", data2, len2);
    else printf("Chunk 2: <empty> (0 bytes)\n");
    
    if (cshake_init(&ctx, variant, output_len, function_name, customization) < 0) {
        return -1;
    }
    
    if (cshake_process(&ctx, data1, len1) < 0) {
        cshake_cleanup(&ctx);
        return -1;
    }
    
    if (cshake_process(&ctx, data2, len2) < 0) {
        cshake_cleanup(&ctx);
        return -1;
    }
    
    if (cshake_finalize(&ctx, output) < 0) {
        cshake_cleanup(&ctx);
        return -1;
    }
    
    printf("Result: ");
    print_hex(output, output_len);
    
    cshake_cleanup(&ctx);
    return 0;
}

// ================================
// Interactive Functions
// ================================

int read_string_input(const char* prompt, char* buffer, size_t buffer_size) {
    printf("%s", prompt);
    fflush(stdout);
    
    if (fgets(buffer, buffer_size, stdin) == NULL) {
        fprintf(stderr, "Error: Failed to read input\n");
        return -1;
    }
    
    // Remove newline
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == '\n') {
        buffer[len-1] = '\0';
    }
    
    return 0;
}

int cshake_interactive() {
    char function_name[MAX_FUNCTION_NAME];
    char customization[MAX_CUSTOMIZATION];
    char input[MAX_INPUT_BUFFER];
    int variant;
    size_t output_len;
    
    printf("=== Interactive cSHAKE ===\n");
    
    printf("Enter variant (128 or 256): ");
    if (scanf("%d", &variant) != 1) {
        fprintf(stderr, "Error: Invalid variant\n");
        return -1;
    }
    getchar(); // consume newline
    
    printf("Enter output length in bytes: ");
    if (scanf("%zu", &output_len) != 1) {
        fprintf(stderr, "Error: Invalid output length\n");
        return -1;
    }
    getchar(); // consume newline
    
    if (read_string_input("Enter function name (or press Enter for none): ", 
                         function_name, sizeof(function_name)) < 0) {
        return -1;
    }
    
    if (read_string_input("Enter customization string (or press Enter for none): ", 
                         customization, sizeof(customization)) < 0) {
        return -1;
    }
    
    if (read_string_input("Enter input data: ", input, sizeof(input)) < 0) {
        return -1;
    }
    
    return cshake_oneshot(input, strlen(input), variant, output_len, 
                         function_name[0] ? function_name : NULL,
                         customization[0] ? customization : NULL);
}

// ================================
// Utility Functions
// ================================

int shake_all_variants(const char* input, size_t input_len, size_t output_len) {
    if (input_len == 0) {
        printf("Input: <empty> (0 bytes)\n");
    } else {
        printf("Input: \"%s\" (%zu bytes)\n", input, input_len);
    }
    printf("Output length: %zu bytes\n", output_len);
    printf("Computing SHAKE variants...\n\n");
    
    if (shake_oneshot(input, input_len, 128, output_len) < 0) return -1;
    if (shake_oneshot(input, input_len, 256, output_len) < 0) return -1;
    
    return 0;
}

int cshake_comparison(const char* input, size_t input_len, size_t output_len) {
    printf("=== cSHAKE vs SHAKE Comparison ===\n");
    printf("Input: \"%s\" (%zu bytes)\n", input, input_len);
    printf("Output length: %zu bytes\n\n", output_len);
    
    printf("SHAKE (no customization):\n");
    shake_oneshot(input, input_len, 128, output_len);
    shake_oneshot(input, input_len, 256, output_len);
    
    printf("\ncSHAKE with customization:\n");
    cshake_oneshot(input, input_len, 128, output_len, "TestApp", "Example");
    cshake_oneshot(input, input_len, 256, output_len, "TestApp", "Example");
    
    printf("\ncSHAKE without customization (should equal SHAKE):\n");
    cshake_oneshot(input, input_len, 128, output_len, "", "");
    cshake_oneshot(input, input_len, 256, output_len, "", "");
    
    return 0;
}

void print_usage(const char* program_name) {
    printf("SHAKE and cSHAKE Calculator\n");
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    
    printf("SHAKE Options:\n");
    printf("  --shake128 <input> <output_bytes>    Compute SHAKE128\n");
    printf("  --shake256 <input> <output_bytes>    Compute SHAKE256\n");
    printf("  --shake-all <input> <output_bytes>   Compute both SHAKE variants\n\n");
    
    printf("cSHAKE Options:\n");
    printf("  --cshake128 <input> <output_bytes> <function_name> <customization>\n");
    printf("  --cshake256 <input> <output_bytes> <function_name> <customization>\n");
    printf("  --cshake-interactive              Interactive cSHAKE mode\n\n");
    
    printf("Streaming Options:\n");
    printf("  --stream-shake <variant> <output_bytes> <data1> <data2>\n");
    printf("  --stream-cshake <variant> <output_bytes> <func> <custom> <data1> <data2>\n\n");
    
    printf("Comparison Options:\n");
    printf("  --compare <input> <output_bytes>     Compare SHAKE vs cSHAKE\n\n");
    
    printf("Examples:\n");
    printf("  %s --shake128 \"Hello\" 32\n", program_name);
    printf("  %s --cshake256 \"data\" 64 \"MyApp\" \"Email\"\n", program_name);
    printf("  %s --shake-all \"test\" 16\n", program_name);
    printf("  %s --compare \"Hello World\" 32\n", program_name);
    printf("  %s --cshake-interactive\n", program_name);
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
        
    } else if (strcmp(mode, "--shake128") == 0 && argc >= 4) {
        const char* input = argv[2];
        size_t output_len = (size_t)atoi(argv[3]);
        return shake_oneshot(input, strlen(input), 128, output_len);
        
    } else if (strcmp(mode, "--shake256") == 0 && argc >= 4) {
        const char* input = argv[2];
        size_t output_len = (size_t)atoi(argv[3]);
        return shake_oneshot(input, strlen(input), 256, output_len);
        
    } else if (strcmp(mode, "--shake-all") == 0 && argc >= 4) {
        const char* input = argv[2];
        size_t output_len = (size_t)atoi(argv[3]);
        return shake_all_variants(input, strlen(input), output_len);
        
    } else if (strcmp(mode, "--cshake128") == 0 && argc >= 6) {
        const char* input = argv[2];
        size_t output_len = (size_t)atoi(argv[3]);
        const char* function_name = argv[4];
        const char* customization = argv[5];
        return cshake_oneshot(input, strlen(input), 128, output_len, function_name, customization);
        
    } else if (strcmp(mode, "--cshake256") == 0 && argc >= 6) {
        const char* input = argv[2];
        size_t output_len = (size_t)atoi(argv[3]);
        const char* function_name = argv[4];
        const char* customization = argv[5];
        return cshake_oneshot(input, strlen(input), 256, output_len, function_name, customization);
        
    } else if (strcmp(mode, "--cshake-interactive") == 0) {
        return cshake_interactive();
        
    } else if (strcmp(mode, "--stream-shake") == 0 && argc >= 6) {
        int variant = atoi(argv[2]);
        size_t output_len = (size_t)atoi(argv[3]);
        const char* data1 = argv[4];
        const char* data2 = argv[5];
        return shake_streaming_example(data1, strlen(data1), data2, strlen(data2), variant, output_len);
        
    } else if (strcmp(mode, "--stream-cshake") == 0 && argc >= 8) {
        int variant = atoi(argv[2]);
        size_t output_len = (size_t)atoi(argv[3]);
        const char* function_name = argv[4];
        const char* customization = argv[5];
        const char* data1 = argv[6];
        const char* data2 = argv[7];
        return cshake_streaming_example(data1, strlen(data1), data2, strlen(data2), 
                                       variant, output_len, function_name, customization);
        
    } else if (strcmp(mode, "--compare") == 0 && argc >= 4) {
        const char* input = argv[2];
        size_t output_len = (size_t)atoi(argv[3]);
        return cshake_comparison(input, strlen(input), output_len);
        
    } else {
        print_usage(argv[0]);
        return 1;
    }
}
