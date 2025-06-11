#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccac.h>

// Hash variant enumeration
typedef enum {
    VARIANT_SHA3_224,
    VARIANT_SHA3_256,
    VARIANT_SHA3_384,
    VARIANT_SHA3_512,
    VARIANT_SHAKE128,
    VARIANT_SHAKE256,
    VARIANT_RAWSHAKE128,
    VARIANT_RAWSHAKE256,
    VARIANT_CSHAKE128,
    VARIANT_CSHAKE256,
    VARIANT_HMAC_SHA3_224,
    VARIANT_HMAC_SHA3_256,
    VARIANT_HMAC_SHA3_384,
    VARIANT_HMAC_SHA3_512
} hash_variant_t;

// Multi-part context structure
typedef struct {
    struct libkeccac_state state;
    struct libkeccac_spec spec;
    char intermediate_data[200];
    size_t intermediate_len;
    int is_initialized;
    int variant_type; // 0=SHA3, 1=SHAKE, 2=RAWSHAKE, 3=CSHAKE, 4=HMAC
    const char *suffix; // Domain suffix for different variants
    char *cshake_suffix; // Dynamic suffix for cSHAKE
    char function_name[256]; // Function name (N) for cSHAKE
    char customization[256]; // Customization string (S) for cSHAKE
} keccac_multipart_ctx_t;

// HMAC context structure
typedef struct {
    keccac_multipart_ctx_t inner_ctx;
    keccac_multipart_ctx_t outer_ctx;
    size_t block_size;
} hmac_sha3_ctx_t;

// Initialize context for specific variant
int keccac_multipart_init(keccac_multipart_ctx_t *ctx, hash_variant_t variant, 
                         const char *function_name, const char *customization) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(keccac_multipart_ctx_t));
    
    switch (variant) {
        case VARIANT_SHA3_224:
            libkeccac_spec_sha3(&ctx->spec, 224);
            ctx->variant_type = 0;
            ctx->suffix = LIBKECCAC_SHA3_SUFFIX;
            break;
        case VARIANT_SHA3_256:
            libkeccac_spec_sha3(&ctx->spec, 256);
            ctx->variant_type = 0;
            ctx->suffix = LIBKECCAC_SHA3_SUFFIX;
            break;
        case VARIANT_SHA3_384:
            libkeccac_spec_sha3(&ctx->spec, 384);
            ctx->variant_type = 0;
            ctx->suffix = LIBKECCAC_SHA3_SUFFIX;
            break;
        case VARIANT_SHA3_512:
            libkeccac_spec_sha3(&ctx->spec, 512);
            ctx->variant_type = 0;
            ctx->suffix = LIBKECCAC_SHA3_SUFFIX;
            break;
        case VARIANT_SHAKE128:
            libkeccac_spec_shake(&ctx->spec, 128);
            ctx->variant_type = 1;
            ctx->suffix = LIBKECCAC_SHAKE_SUFFIX;
            break;
        case VARIANT_SHAKE256:
            libkeccac_spec_shake(&ctx->spec, 256);
            ctx->variant_type = 1;
            ctx->suffix = LIBKECCAC_SHAKE_SUFFIX;
            break;
        case VARIANT_RAWSHAKE128:
            libkeccac_spec_rawshake(&ctx->spec, 128);
            ctx->variant_type = 2;
            ctx->suffix = LIBKECCAC_RAWSHAKE_SUFFIX;
            break;
        case VARIANT_RAWSHAKE256:
            libkeccac_spec_rawshake(&ctx->spec, 256);
            ctx->variant_type = 2;
            ctx->suffix = LIBKECCAC_RAWSHAKE_SUFFIX;
            break;
        case VARIANT_CSHAKE128:
            libkeccac_spec_shake(&ctx->spec, 128);
            ctx->variant_type = 3;
            // Store function name (N) and customization string (S)
            if (function_name) {
                strncpy(ctx->function_name, function_name, sizeof(ctx->function_name) - 1);
                ctx->function_name[sizeof(ctx->function_name) - 1] = '\0';
            } else {
                ctx->function_name[0] = '\0';
            }
            if (customization) {
                strncpy(ctx->customization, customization, sizeof(ctx->customization) - 1);
                ctx->customization[sizeof(ctx->customization) - 1] = '\0';
            } else {
                ctx->customization[0] = '\0';
            }
            // Generate cSHAKE suffix using libkeccac function with both N and S
            ctx->cshake_suffix = malloc(100); // Allocate buffer for suffix
            if (!ctx->cshake_suffix) return -1;
            libkeccac_cshake_suffix(ctx->cshake_suffix, 
                                   ctx->function_name, strlen(ctx->function_name),
                                   ctx->customization, strlen(ctx->customization));
            ctx->suffix = ctx->cshake_suffix;
            break;
        case VARIANT_CSHAKE256:
            libkeccac_spec_shake(&ctx->spec, 256);
            ctx->variant_type = 3;
            // Store function name (N) and customization string (S)
            if (function_name) {
                strncpy(ctx->function_name, function_name, sizeof(ctx->function_name) - 1);
                ctx->function_name[sizeof(ctx->function_name) - 1] = '\0';
            } else {
                ctx->function_name[0] = '\0';
            }
            if (customization) {
                strncpy(ctx->customization, customization, sizeof(ctx->customization) - 1);
                ctx->customization[sizeof(ctx->customization) - 1] = '\0';
            } else {
                ctx->customization[0] = '\0';
            }
            // Generate cSHAKE suffix using libkeccac function with both N and S
            ctx->cshake_suffix = malloc(100); // Allocate buffer for suffix
            if (!ctx->cshake_suffix) return -1;
            libkeccac_cshake_suffix(ctx->cshake_suffix, 
                                   ctx->function_name, strlen(ctx->function_name),
                                   ctx->customization, strlen(ctx->customization));
            ctx->suffix = ctx->cshake_suffix;
            break;
        default:
            return -1;
    }
    
    if (libkeccac_state_initialise(&ctx->state, &ctx->spec) < 0) {
        return -1;
    }
    
    ctx->is_initialized = 1;
    return 0;
}

// Set intermediate state (up to 200 bytes)
int keccac_set_intermediate_state(keccac_multipart_ctx_t *ctx, const char *intermediate_data) {
    if (!ctx || !ctx->is_initialized || !intermediate_data) {
        return -1;
    }
    
    size_t len = strlen(intermediate_data);
    if (len > 200) len = 200;
    
    memcpy(ctx->intermediate_data, intermediate_data, len);
    ctx->intermediate_len = len;
    
    return libkeccac_update(&ctx->state, intermediate_data, len);
}

// Update with new data
int keccac_multipart_update(keccac_multipart_ctx_t *ctx, const void *data) {
    if (!ctx || !ctx->is_initialized || !data) {
        return -1;
    }
    
    size_t len = strlen((const char*)data);
    return libkeccac_update(&ctx->state, data, len);
}

// Finalize and get hash
int keccac_multipart_finalize(keccac_multipart_ctx_t *ctx, unsigned char *output) {
    if (!ctx || !ctx->is_initialized || !output) {
        return -1;
    }
    
    // Use the appropriate suffix for the variant
    return libkeccac_digest(&ctx->state, NULL, 0, 0, ctx->suffix, output);
}

// Cleanup context
void keccac_multipart_cleanup(keccac_multipart_ctx_t *ctx) {
    if (ctx && ctx->is_initialized) {
        libkeccac_state_destroy(&ctx->state);
        if (ctx->cshake_suffix) {
            free(ctx->cshake_suffix);
            ctx->cshake_suffix = NULL;
        }
        memset(ctx, 0, sizeof(keccac_multipart_ctx_t));
    }
}

// Initialize HMAC context
int hmac_sha3_init(hmac_sha3_ctx_t *hmac_ctx, hash_variant_t variant, const unsigned char *key) {
    if (!hmac_ctx || variant < VARIANT_HMAC_SHA3_224 || variant > VARIANT_HMAC_SHA3_512 || !key) {
        return -1;
    }
    
    memset(hmac_ctx, 0, sizeof(hmac_sha3_ctx_t));
    size_t key_len = strlen((const char*)key);
    
    // Determine block size and base variant
    hash_variant_t base_variant;
    switch (variant) {
        case VARIANT_HMAC_SHA3_224:
            base_variant = VARIANT_SHA3_224;
            hmac_ctx->block_size = 144; // (1600 - 2*224) / 8
            break;
        case VARIANT_HMAC_SHA3_256:
            base_variant = VARIANT_SHA3_256;
            hmac_ctx->block_size = 136; // (1600 - 2*256) / 8
            break;
        case VARIANT_HMAC_SHA3_384:
            base_variant = VARIANT_SHA3_384;
            hmac_ctx->block_size = 104; // (1600 - 2*384) / 8
            break;
        case VARIANT_HMAC_SHA3_512:
            base_variant = VARIANT_SHA3_512;
            hmac_ctx->block_size = 72;  // (1600 - 2*512) / 8
            break;
        default:
            return -1;
    }
    
    // Process key if too long
    unsigned char processed_key[64] = {0};
    if (key_len > hmac_ctx->block_size) {
        keccac_multipart_ctx_t key_ctx;
        if (keccac_multipart_init(&key_ctx, base_variant, NULL, NULL) < 0) return -1;
        if (libkeccac_update(&key_ctx.state, key, key_len) < 0) return -1;
        if (libkeccac_digest(&key_ctx.state, NULL, 0, 0, LIBKECCAC_SHA3_SUFFIX, processed_key) < 0) return -1;
        key_len = key_ctx.spec.output / 8;
        keccac_multipart_cleanup(&key_ctx);
    } else {
        memcpy(processed_key, key, key_len);
    }
    
    // Create padded keys
    unsigned char ipad[200] = {0}, opad[200] = {0};
    for (size_t i = 0; i < hmac_ctx->block_size; i++) {
        ipad[i] = (i < key_len) ? processed_key[i] ^ 0x36 : 0x36;
        opad[i] = (i < key_len) ? processed_key[i] ^ 0x5C : 0x5C;
    }
    
    // Initialize contexts
    if (keccac_multipart_init(&hmac_ctx->inner_ctx, base_variant, NULL, NULL) < 0) return -1;
    if (libkeccac_update(&hmac_ctx->inner_ctx.state, ipad, hmac_ctx->block_size) < 0) return -1;
    
    if (keccac_multipart_init(&hmac_ctx->outer_ctx, base_variant, NULL, NULL) < 0) return -1;
    if (libkeccac_update(&hmac_ctx->outer_ctx.state, opad, hmac_ctx->block_size) < 0) return -1;
    
    return 0;
}

// Update HMAC with data
int hmac_sha3_update(hmac_sha3_ctx_t *hmac_ctx, const void *data) {
    if (!hmac_ctx) return -1;
    return keccac_multipart_update(&hmac_ctx->inner_ctx, data);
}

// Finalize HMAC
int hmac_sha3_finalize(hmac_sha3_ctx_t *hmac_ctx, unsigned char *output) {
    if (!hmac_ctx) return -1;
    
    unsigned char inner_hash[64];
    size_t hash_len = hmac_ctx->inner_ctx.spec.output / 8;
    
    if (keccac_multipart_finalize(&hmac_ctx->inner_ctx, inner_hash) < 0) {
        return -1;
    }
    
    if (libkeccac_update(&hmac_ctx->outer_ctx.state, inner_hash, hash_len) < 0) {
        return -1;
    }
    
    return keccac_multipart_finalize(&hmac_ctx->outer_ctx, output);
}

// Cleanup HMAC context
void hmac_sha3_cleanup(hmac_sha3_ctx_t *hmac_ctx) {
    if (hmac_ctx) {
        keccac_multipart_cleanup(&hmac_ctx->inner_ctx);
        keccac_multipart_cleanup(&hmac_ctx->outer_ctx);
        memset(hmac_ctx, 0, sizeof(hmac_sha3_ctx_t));
    }
}

// Utility function to print hex
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Example usage
int main() {
    printf("=== LibKeccac Multi-Part Hashing (Codeberg Version) ===\n\n");
    
    const char *intermediate_data = "This is 200 bytes of intermediate data representing previous processing state from earlier computation phases.";
    const char *current_data = "Current message part to process with multipart hashing.";
    const char *hmac_key = "secret_key_for_hmac";
    const char *cshake_function = "MyProtocol"; // Function name (N)
    const char *cshake_custom = "KeyDerivation-2024"; // Customization string (S)
    
    // Test SHA3-256
    printf("SHA3-256 with intermediate state:\n");
    keccac_multipart_ctx_t ctx;
    unsigned char output[32];
    
    if (keccac_multipart_init(&ctx, VARIANT_SHA3_256, NULL, NULL) == 0) {
        // Set intermediate state first
        if (keccac_set_intermediate_state(&ctx, intermediate_data) == 0) {
            // Update with current data
            if (keccac_multipart_update(&ctx, current_data) == 0) {
                // Finalize
                if (keccac_multipart_finalize(&ctx, output) == 0) {
                    printf("  Hash: ");
                    print_hex(output, 32);
                } else {
                    printf("  Finalization failed\n");
                }
            } else {
                printf("  Update failed\n");
            }
        } else {
            printf("  Setting intermediate state failed\n");
        }
        keccac_multipart_cleanup(&ctx);
    }
    
    // Test cSHAKE128 with both function name and customization
    printf("\ncSHAKE128 with function name and customization:\n");
    unsigned char cshake_output[32]; // 256-bit output for cSHAKE128
    
    if (keccac_multipart_init(&ctx, VARIANT_CSHAKE128, cshake_function, cshake_custom) == 0) {
        keccac_set_intermediate_state(&ctx, intermediate_data);
        keccac_multipart_update(&ctx, current_data);
        if (keccac_multipart_finalize(&ctx, cshake_output) == 0) {
            printf("  Hash (N='%s', S='%s'): ", cshake_function, cshake_custom);
            print_hex(cshake_output, 32);
        } else {
            printf("  Finalization failed\n");
        }
        keccac_multipart_cleanup(&ctx);
    }
    
    // Test cSHAKE256 with different parameters
    printf("\ncSHAKE256 with different parameters:\n");
    unsigned char cshake256_output[64]; // 512-bit output for cSHAKE256
    
    if (keccac_multipart_init(&ctx, VARIANT_CSHAKE256, "KMAC", "Database-Hashing") == 0) {
        keccac_set_intermediate_state(&ctx, intermediate_data);
        keccac_multipart_update(&ctx, current_data);
        if (keccac_multipart_finalize(&ctx, cshake256_output) == 0) {
            printf("  Hash (N='KMAC', S='Database-Hashing'): ");
            print_hex(cshake256_output, 64);
        } else {
            printf("  Finalization failed\n");
        }
        keccac_multipart_cleanup(&ctx);
    }
    
    // Test cSHAKE128 with empty function name (behaves like SHAKE)
    printf("\ncSHAKE128 with empty function name (SHAKE-like):\n");
    
    if (keccac_multipart_init(&ctx, VARIANT_CSHAKE128, "", "OnlyCustomization") == 0) {
        keccac_set_intermediate_state(&ctx, intermediate_data);
        keccac_multipart_update(&ctx, current_data);
        if (keccac_multipart_finalize(&ctx, cshake_output) == 0) {
            printf("  Hash (N='', S='OnlyCustomization'): ");
            print_hex(cshake_output, 32);
        }
        keccac_multipart_cleanup(&ctx);
    } else {
        printf("  Initialization failed\n");
    }
    
    // Test SHAKE128
    printf("\nSHAKE128 with intermediate state:\n");
    unsigned char shake_output[32]; // 256-bit output for SHAKE128
    
    if (keccac_multipart_init(&ctx, VARIANT_SHAKE128, NULL, NULL) == 0) {
        keccac_set_intermediate_state(&ctx, intermediate_data);
        keccac_multipart_update(&ctx, current_data);
        if (keccac_multipart_finalize(&ctx, shake_output) == 0) {
            printf("  Hash: ");
            print_hex(shake_output, 32);
        } else {
            printf("  Finalization failed\n");
        }
        keccac_multipart_cleanup(&ctx);
    }
    
    // Test RawSHAKE256
    printf("\nRawSHAKE256 with intermediate state:\n");
    unsigned char rawshake_output[64]; // 512-bit output for RawSHAKE256
    
    if (keccac_multipart_init(&ctx, VARIANT_RAWSHAKE256, NULL, NULL) == 0) {
        keccac_set_intermediate_state(&ctx, intermediate_data);
        keccac_multipart_update(&ctx, current_data);
        if (keccac_multipart_finalize(&ctx, rawshake_output) == 0) {
            printf("  Hash: ");
            print_hex(rawshake_output, 64);
        } else {
            printf("  Finalization failed\n");
        }
        keccac_multipart_cleanup(&ctx);
    }
    
    // Test HMAC-SHA3-256
    printf("\nHMAC-SHA3-256 with intermediate state:\n");
    hmac_sha3_ctx_t hmac_ctx;
    unsigned char hmac_output[32];
    
    if (hmac_sha3_init(&hmac_ctx, VARIANT_HMAC_SHA3_256, (const unsigned char*)hmac_key) == 0) {
        // Set intermediate state on inner context
        if (keccac_set_intermediate_state(&hmac_ctx.inner_ctx, intermediate_data) == 0) {
            if (hmac_sha3_update(&hmac_ctx, current_data) == 0) {
                if (hmac_sha3_finalize(&hmac_ctx, hmac_output) == 0) {
                    printf("  HMAC: ");
                    print_hex(hmac_output, 32);
                } else {
                    printf("  HMAC finalization failed\n");
                }
            } else {
                printf("  HMAC update failed\n");
            }
        } else {
            printf("  Setting HMAC intermediate state failed\n");
        }
        hmac_sha3_cleanup(&hmac_ctx);
    } else {
        printf("  HMAC initialization failed\n");
    }
    
    printf("\n=== Multi-part processing without intermediate state ===\n");
    
    // Example of regular multi-part processing (without intermediate state)
    printf("SHA3-512 multi-part (no intermediate state):\n");
    unsigned char sha3_512_output[64];
    
    if (keccac_multipart_init(&ctx, VARIANT_SHA3_512, NULL, NULL) == 0) {
        // Process data in multiple chunks (simulate multi-part)
        const char *chunk1 = "First chunk of data ";
        const char *chunk2 = "Second chunk of data ";
        const char *chunk3 = "Final chunk of data";
        
        keccac_multipart_update(&ctx, chunk1);
        keccac_multipart_update(&ctx, chunk2);
        keccac_multipart_update(&ctx, chunk3);
        
        if (keccac_multipart_finalize(&ctx, sha3_512_output) == 0) {
            printf("  Hash: ");
            print_hex(sha3_512_output, 64);
        }
        keccac_multipart_cleanup(&ctx);
    }
    
    return 0;
}

// Compilation: gcc -o keccac_clean keccac_clean.c -lkeccac
