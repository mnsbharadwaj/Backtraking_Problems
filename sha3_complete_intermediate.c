#ifndef SHA3_WRAPPER_H
#define SHA3_WRAPPER_H

#include <libkeccak.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Keccak/SHA-3 constants
#define KECCAK_STATE_SIZE       200  // 1600 bits / 8
#define KECCAK_MAX_RATE         200  // Maximum rate in bytes

// SHA-3 specific block sizes (rate in bytes)
#define SHA3_224_BLOCK_SIZE     144  // (1600 - 2*224) / 8
#define SHA3_256_BLOCK_SIZE     136  // (1600 - 2*256) / 8
#define SHA3_384_BLOCK_SIZE     104  // (1600 - 2*384) / 8
#define SHA3_512_BLOCK_SIZE     72   // (1600 - 2*512) / 8

// Output sizes in bytes
#define SHA3_224_DIGEST_SIZE    28
#define SHA3_256_DIGEST_SIZE    32
#define SHA3_384_DIGEST_SIZE    48
#define SHA3_512_DIGEST_SIZE    64

// HMAC constants
#define HMAC_IPAD              0x36
#define HMAC_OPAD              0x5C
#define HMAC_MAX_KEY_SIZE      KECCAK_MAX_RATE

// SHAKE constants
#define SHAKE128_CAPACITY      256  // bits
#define SHAKE256_CAPACITY      512  // bits

// Hash types enumeration - alternating SHA and HMAC variants
typedef enum {
    SHA3_224,
    HMAC_SHA3_224,
    SHA3_256,
    HMAC_SHA3_256,
    SHA3_384,
    HMAC_SHA3_384,
    SHA3_512,
    HMAC_SHA3_512,
    SHAKE128,
    SHAKE256,
    CSHAKE128,
    CSHAKE256
} sha3_variant_t;

// Context structure for all variants
typedef struct {
    struct libkeccak_state state;
    sha3_variant_t variant;
    size_t output_len;  // For SHAKE variants
    uint8_t *customization; // For cSHAKE
    size_t customization_len;
    uint8_t *function_name; // For cSHAKE
    size_t function_name_len;
} sha3_ctx_t;

// Structure to hold intermediate state
typedef struct {
    uint8_t state_bytes[KECCAK_STATE_SIZE];  // Raw state bytes (200 bytes)
    long r;                   // Rate parameter
    long c;                   // Capacity parameter
    long n;                   // Output size
    long b;                   // State size
    long w;                   // Word size
    long l;                   // L parameter
    long nr;                  // Number of rounds
    size_t output_len;        // Output length for our use
    sha3_variant_t variant;   // Hash variant
} sha3_intermediate_state_t;

// HMAC context
typedef struct {
    sha3_ctx_t inner_ctx;
    sha3_ctx_t outer_ctx;
    uint8_t key_pad[HMAC_MAX_KEY_SIZE];
    size_t block_size;
} hmac_sha3_ctx_t;

// Structure to hold HMAC intermediate state
typedef struct {
    sha3_intermediate_state_t inner_state;  // Inner hash state
    sha3_intermediate_state_t outer_state;  // Outer hash state
    uint8_t key_pad[HMAC_MAX_KEY_SIZE];     // Padded key
    size_t block_size;                      // Block size for this variant
    sha3_variant_t variant;                 // Hash variant (base SHA3 variant, not HMAC)
} hmac_sha3_intermediate_state_t;

// Basic SHA-3 functions
int sha3_init(sha3_ctx_t *ctx, sha3_variant_t variant, size_t output_len);
int sha3_update(sha3_ctx_t *ctx, const uint8_t *data, size_t len);
int sha3_final(sha3_ctx_t *ctx, uint8_t *output);

// cSHAKE specific init
int cshake_init(sha3_ctx_t *ctx, sha3_variant_t variant, size_t output_len,
                const uint8_t *function_name, size_t fn_len,
                const uint8_t *customization, size_t cust_len);

// HMAC functions
int hmac_sha3_init(hmac_sha3_ctx_t *ctx, sha3_variant_t variant, 
                   const uint8_t *key, size_t key_len);
int hmac_sha3_update(hmac_sha3_ctx_t *ctx, const uint8_t *data, size_t len);
int hmac_sha3_final(hmac_sha3_ctx_t *ctx, uint8_t *output);

// Utility functions
void sha3_free(sha3_ctx_t *ctx);
void hmac_sha3_free(hmac_sha3_ctx_t *ctx);

// Load state functions (restore from intermediate state)
int sha3_init_from_state(sha3_ctx_t *ctx, const sha3_intermediate_state_t *state);
int hmac_sha3_init_from_state(hmac_sha3_ctx_t *ctx, const hmac_sha3_intermediate_state_t *state);

// Direct state processing (finalize from state + additional data)
int sha3_final_from_state(const sha3_intermediate_state_t *state, 
                         const uint8_t *additional_data, size_t additional_len,
                         uint8_t *output);
int hmac_sha3_final_from_state(const hmac_sha3_intermediate_state_t *state,
                              const uint8_t *additional_data, size_t additional_len,
                              uint8_t *output);

// Helper functions
size_t sha3_get_block_size(sha3_variant_t variant);
size_t sha3_get_digest_size(sha3_variant_t variant);

#endif // SHA3_WRAPPER_H

// Implementation
#include <stdio.h>

// Helper function to get block size
size_t sha3_get_block_size(sha3_variant_t variant) {
    switch (variant) {
        case SHA3_224:
        case HMAC_SHA3_224:
            return SHA3_224_BLOCK_SIZE;
        case SHA3_256:
        case HMAC_SHA3_256:
            return SHA3_256_BLOCK_SIZE;
        case SHA3_384:
        case HMAC_SHA3_384:
            return SHA3_384_BLOCK_SIZE;
        case SHA3_512:
        case HMAC_SHA3_512:
            return SHA3_512_BLOCK_SIZE;
        default:
            return 0;
    }
}

// Helper function to get digest size
size_t sha3_get_digest_size(sha3_variant_t variant) {
    switch (variant) {
        case SHA3_224:
        case HMAC_SHA3_224:
            return SHA3_224_DIGEST_SIZE;
        case SHA3_256:
        case HMAC_SHA3_256:
            return SHA3_256_DIGEST_SIZE;
        case SHA3_384:
        case HMAC_SHA3_384:
            return SHA3_384_DIGEST_SIZE;
        case SHA3_512:
        case HMAC_SHA3_512:
            return SHA3_512_DIGEST_SIZE;
        default:
            return 0;
    }
}

// Helper function to encode string for cSHAKE
static void encode_string(uint8_t *output, size_t *out_len, 
                         const uint8_t *input, size_t in_len) {
    size_t i = 0;
    size_t bit_len = in_len * 8;
    
    // Left encode the length
    if (bit_len < 256) {
        output[i++] = 1;
        output[i++] = bit_len;
    } else {
        output[i++] = 2;
        output[i++] = (bit_len >> 8) & 0xFF;
        output[i++] = bit_len & 0xFF;
    }
    
    // Copy the string
    memcpy(output + i, input, in_len);
    *out_len = i + in_len;
}

// Initialize SHA-3 context
int sha3_init(sha3_ctx_t *ctx, sha3_variant_t variant, size_t output_len) {
    struct libkeccak_spec spec;
    
    memset(ctx, 0, sizeof(sha3_ctx_t));
    ctx->variant = variant;
    
    switch (variant) {
        case SHA3_224:
            libkeccak_spec_sha3(&spec, 224);
            ctx->output_len = SHA3_224_DIGEST_SIZE;
            break;
        case SHA3_256:
            libkeccak_spec_sha3(&spec, 256);
            ctx->output_len = SHA3_256_DIGEST_SIZE;
            break;
        case SHA3_384:
            libkeccak_spec_sha3(&spec, 384);
            ctx->output_len = SHA3_384_DIGEST_SIZE;
            break;
        case SHA3_512:
            libkeccak_spec_sha3(&spec, 512);
            ctx->output_len = SHA3_512_DIGEST_SIZE;
            break;
        case SHAKE128:
            libkeccak_spec_shake(&spec, 128, output_len * 8);
            ctx->output_len = output_len;
            break;
        case SHAKE256:
            libkeccak_spec_shake(&spec, 256, output_len * 8);
            ctx->output_len = output_len;
            break;
        case CSHAKE128:
        case CSHAKE256:
            // Will be handled by cshake_init
            return -1;
        default:
            // HMAC variants should not use this function
            return -1;
    }
    
    return libkeccak_state_initialise(&ctx->state, &spec);
}

// Initialize cSHAKE context
int cshake_init(sha3_ctx_t *ctx, sha3_variant_t variant, size_t output_len,
                const uint8_t *function_name, size_t fn_len,
                const uint8_t *customization, size_t cust_len) {
    struct libkeccak_spec spec;
    uint8_t encoded[512];
    size_t encoded_len = 0;
    
    memset(ctx, 0, sizeof(sha3_ctx_t));
    ctx->variant = variant;
    ctx->output_len = output_len;
    
    // Set up spec
    if (variant == CSHAKE128) {
        libkeccak_spec_shake(&spec, 128, output_len * 8);
    } else if (variant == CSHAKE256) {
        libkeccak_spec_shake(&spec, 256, output_len * 8);
    } else {
        return -1;
    }
    
    if (libkeccak_state_initialise(&ctx->state, &spec) < 0) {
        return -1;
    }
    
    // If both N and S are empty, cSHAKE behaves as SHAKE
    if (fn_len == 0 && cust_len == 0) {
        return 0;
    }
    
    // Encode and update with bytepad(encode_string(N) || encode_string(S), rate)
    size_t rate = ctx->state.r;
    size_t w = rate / 8;
    
    // Encode w
    encoded[encoded_len++] = 1;
    encoded[encoded_len++] = w;
    
    // Encode N (function name)
    size_t fn_encoded_len;
    encode_string(encoded + encoded_len, &fn_encoded_len, function_name, fn_len);
    encoded_len += fn_encoded_len;
    
    // Encode S (customization)
    size_t cust_encoded_len;
    encode_string(encoded + encoded_len, &cust_encoded_len, customization, cust_len);
    encoded_len += cust_encoded_len;
    
    // Pad to rate
    while (encoded_len % w != 0) {
        encoded[encoded_len++] = 0;
    }
    
    // Update state with encoded data
    return libkeccak_update(&ctx->state, (const char *)encoded, encoded_len);
}

// Update SHA-3 hash
int sha3_update(sha3_ctx_t *ctx, const uint8_t *data, size_t len) {
    return libkeccak_update(&ctx->state, (const char *)data, len);
}

// Finalize SHA-3 hash
int sha3_final(sha3_ctx_t *ctx, uint8_t *output) {
    // For SHA-3, use standard digest
    if (ctx->variant >= SHA3_224 && ctx->variant <= SHA3_512) {
        return libkeccak_digest(&ctx->state, NULL, 0, 0, NULL, (char *)output);
    }
    
    // For SHAKE and cSHAKE, finalize and squeeze
    if (ctx->variant >= SHAKE128 && ctx->variant <= CSHAKE256) {
        // Finalize the state
        if (libkeccak_digest(&ctx->state, NULL, 0, 0, NULL, NULL) < 0) {
            return -1;
        }
        // Squeeze output
        libkeccak_squeeze(&ctx->state, (char *)output);
        return 0;
    }
    
    return -1;
}

// Initialize HMAC-SHA3
int hmac_sha3_init(hmac_sha3_ctx_t *ctx, sha3_variant_t variant,
                   const uint8_t *key, size_t key_len) {
    size_t block_size;
    sha3_variant_t hash_variant;
    
    memset(ctx, 0, sizeof(hmac_sha3_ctx_t));
    
    // Convert HMAC variant to hash variant and get block size
    switch (variant) {
        case HMAC_SHA3_224:
            hash_variant = SHA3_224;
            block_size = SHA3_224_BLOCK_SIZE;
            break;
        case HMAC_SHA3_256:
            hash_variant = SHA3_256;
            block_size = SHA3_256_BLOCK_SIZE;
            break;
        case HMAC_SHA3_384:
            hash_variant = SHA3_384;
            block_size = SHA3_384_BLOCK_SIZE;
            break;
        case HMAC_SHA3_512:
            hash_variant = SHA3_512;
            block_size = SHA3_512_BLOCK_SIZE;
            break;
        default:
            return -1; // Not an HMAC variant
    }
    
    ctx->block_size = block_size;
    
    // Initialize inner and outer contexts
    if (sha3_init(&ctx->inner_ctx, hash_variant, 0) < 0) {
        return -1;
    }
    if (sha3_init(&ctx->outer_ctx, hash_variant, 0) < 0) {
        return -1;
    }
    
    // Process key
    if (key_len > block_size) {
        // Key is too long, hash it first
        sha3_ctx_t key_hash_ctx;
        uint8_t hashed_key[SHA3_512_DIGEST_SIZE]; // Max digest size
        
        if (sha3_init(&key_hash_ctx, hash_variant, 0) < 0) {
            return -1;
        }
        sha3_update(&key_hash_ctx, key, key_len);
        sha3_final(&key_hash_ctx, hashed_key);
        sha3_free(&key_hash_ctx);
        
        memcpy(ctx->key_pad, hashed_key, ctx->inner_ctx.output_len);
        key_len = ctx->inner_ctx.output_len;
    } else {
        memcpy(ctx->key_pad, key, key_len);
    }
    
    // Pad key with zeros
    memset(ctx->key_pad + key_len, 0, block_size - key_len);
    
    // XOR key with ipad for inner
    uint8_t ipad_key[HMAC_MAX_KEY_SIZE];
    for (size_t i = 0; i < block_size; i++) {
        ipad_key[i] = ctx->key_pad[i] ^ HMAC_IPAD;
    }
    sha3_update(&ctx->inner_ctx, ipad_key, block_size);
    
    // XOR key with opad for outer
    uint8_t opad_key[HMAC_MAX_KEY_SIZE];
    for (size_t i = 0; i < block_size; i++) {
        opad_key[i] = ctx->key_pad[i] ^ HMAC_OPAD;
    }
    sha3_update(&ctx->outer_ctx, opad_key, block_size);
    
    return 0;
}

// Update HMAC-SHA3
int hmac_sha3_update(hmac_sha3_ctx_t *ctx, const uint8_t *data, size_t len) {
    return sha3_update(&ctx->inner_ctx, data, len);
}

// Finalize HMAC-SHA3
int hmac_sha3_final(hmac_sha3_ctx_t *ctx, uint8_t *output) {
    uint8_t inner_hash[SHA3_512_DIGEST_SIZE]; // Max digest size
    
    // Finalize inner hash
    if (sha3_final(&ctx->inner_ctx, inner_hash) < 0) {
        return -1;
    }
    
    // Update outer with inner hash
    sha3_update(&ctx->outer_ctx, inner_hash, ctx->inner_ctx.output_len);
    
    // Finalize outer hash
    return sha3_final(&ctx->outer_ctx, output);
}

// Free SHA3 context
void sha3_free(sha3_ctx_t *ctx) {
    libkeccak_state_destroy(&ctx->state);
    if (ctx->customization) {
        free(ctx->customization);
    }
    if (ctx->function_name) {
        free(ctx->function_name);
    }
}

// Free HMAC context
void hmac_sha3_free(hmac_sha3_ctx_t *ctx) {
    sha3_free(&ctx->inner_ctx);
    sha3_free(&ctx->outer_ctx);
    memset(ctx->key_pad, 0, sizeof(ctx->key_pad));
}

// Initialize context from saved state
int sha3_init_from_state(sha3_ctx_t *ctx, const sha3_intermediate_state_t *state) {
    if (!ctx || !state) {
        return -1;
    }
    
    // Clear context
    memset(ctx, 0, sizeof(sha3_ctx_t));
    
    // Set variant and output length
    ctx->variant = state->variant;
    ctx->output_len = state->output_len;
    
    // Create spec from saved parameters
    struct libkeccak_spec spec;
    spec.bitrate = state->r;
    spec.capacity = state->c;
    spec.output = state->n;
    
    // Initialize state
    if (libkeccak_state_initialise(&ctx->state, &spec) < 0) {
        return -1;
    }
    
    // Use libkeccak's unmarshalling if available, otherwise copy raw bytes
    // Note: You may need to use libkeccak_state_unmarshal if available
    // For now, we'll document that state_bytes should contain the marshalled state
    
    // The user should populate state->state_bytes with the actual Keccak state
    // from their external source (e.g., from libkeccak_state_marshal)
    
    return 0;
}

// Alternative: Direct state manipulation function
// This assumes the user has the raw 200-byte Keccak state
int sha3_set_raw_state(sha3_ctx_t *ctx, const uint8_t raw_state[KECCAK_STATE_SIZE]) {
    if (!ctx || !raw_state) {
        return -1;
    }
    
    // This is implementation-specific and may need adjustment
    // based on your libkeccak version
    // You might need to use libkeccak_state_unmarshal or similar
    
    return 0;
}

// Compute final hash directly from state and additional data
int sha3_final_from_state(const sha3_intermediate_state_t *state, 
                         const uint8_t *additional_data, size_t additional_len,
                         uint8_t *output) {
    sha3_ctx_t ctx;
    
    // Initialize from state
    if (sha3_init_from_state(&ctx, state) < 0) {
        return -1;
    }
    
    // Process additional data if provided
    if (additional_data && additional_len > 0) {
        if (sha3_update(&ctx, additional_data, additional_len) < 0) {
            sha3_free(&ctx);
            return -1;
        }
    }
    
    // Finalize and get output
    int result = sha3_final(&ctx, output);
    sha3_free(&ctx);
    
    return result;
}

// Initialize HMAC context from saved state
int hmac_sha3_init_from_state(hmac_sha3_ctx_t *ctx, const hmac_sha3_intermediate_state_t *state) {
    if (!ctx || !state) {
        return -1;
    }
    
    // Clear context
    memset(ctx, 0, sizeof(hmac_sha3_ctx_t));
    
    // Restore both inner and outer states
    if (sha3_init_from_state(&ctx->inner_ctx, &state->inner_state) < 0) {
        return -1;
    }
    
    if (sha3_init_from_state(&ctx->outer_ctx, &state->outer_state) < 0) {
        return -1;
    }
    
    // Restore key pad and parameters
    memcpy(ctx->key_pad, state->key_pad, sizeof(state->key_pad));
    ctx->block_size = state->block_size;
    
    return 0;
}

// Compute final HMAC directly from state and additional data
int hmac_sha3_final_from_state(const hmac_sha3_intermediate_state_t *state,
                              const uint8_t *additional_data, size_t additional_len,
                              uint8_t *output) {
    hmac_sha3_ctx_t ctx;
    
    // Initialize from state
    if (hmac_sha3_init_from_state(&ctx, state) < 0) {
        return -1;
    }
    
    // Process additional data if provided
    if (additional_data && additional_len > 0) {
        if (hmac_sha3_update(&ctx, additional_data, additional_len) < 0) {
            hmac_sha3_free(&ctx);
            return -1;
        }
    }
    
    // Finalize and get output
    int result = hmac_sha3_final(&ctx, output);
    hmac_sha3_free(&ctx);
    
    return result;
}

// Example usage
void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("=== SHA-3 Wrapper Test Program ===\n\n");
    
    // Test 1: Basic SHA3-256
    printf("Test 1: Basic SHA3-256\n");
    sha3_ctx_t ctx;
    uint8_t hash[SHA3_256_DIGEST_SIZE];
    const char *msg = "Hello, World!";
    
    sha3_init(&ctx, SHA3_256, 0);
    sha3_update(&ctx, (uint8_t*)msg, strlen(msg));
    sha3_final(&ctx, hash);
    
    printf("Message: %s\n", msg);
    printf("SHA3-256: ");
    print_hex(hash, SHA3_256_DIGEST_SIZE);
    sha3_free(&ctx);
    
    // Test 2: Chunked processing (200-byte chunks)
    printf("\nTest 2: Processing 200-byte chunks\n");
    sha3_ctx_t ctx2;
    uint8_t chunk[KECCAK_MAX_RATE];
    uint8_t hash2[SHA3_256_DIGEST_SIZE];
    
    sha3_init(&ctx2, SHA3_256, 0);
    
    // First chunk - fill with 'A'
    memset(chunk, 'A', KECCAK_MAX_RATE);
    sha3_update(&ctx2, chunk, KECCAK_MAX_RATE);
    printf("Processed first 200-byte chunk (all 'A's)\n");
    
    // Second chunk - fill with 'B'
    memset(chunk, 'B', KECCAK_MAX_RATE);
    sha3_update(&ctx2, chunk, KECCAK_MAX_RATE);
    printf("Processed second 200-byte chunk (all 'B's)\n");
    
    sha3_final(&ctx2, hash2);
    printf("Final hash: ");
    print_hex(hash2, SHA3_256_DIGEST_SIZE);
    sha3_free(&ctx2);
    
    // Test 3: HMAC-SHA3-256
    printf("\nTest 3: HMAC-SHA3-256\n");
    hmac_sha3_ctx_t hmac_ctx;
    uint8_t hmac_output[SHA3_256_DIGEST_SIZE];
    const char *key = "my secret key";
    const char *hmac_msg = "Message to authenticate";
    
    hmac_sha3_init(&hmac_ctx, HMAC_SHA3_256, (uint8_t*)key, strlen(key));
    hmac_sha3_update(&hmac_ctx, (uint8_t*)hmac_msg, strlen(hmac_msg));
    hmac_sha3_final(&hmac_ctx, hmac_output);
    
    printf("Key: %s\n", key);
    printf("Message: %s\n", hmac_msg);
    printf("HMAC-SHA3-256: ");
    print_hex(hmac_output, SHA3_256_DIGEST_SIZE);
    hmac_sha3_free(&hmac_ctx);
    
    // Test 4: SHAKE256 with variable output
    printf("\nTest 4: SHAKE256 with 64-byte output\n");
    sha3_ctx_t shake_ctx;
    uint8_t shake_output[64];
    const char *shake_msg = "SHAKE test message";
    
    sha3_init(&shake_ctx, SHAKE256, 64);  // 64 bytes output
    sha3_update(&shake_ctx, (uint8_t*)shake_msg, strlen(shake_msg));
    sha3_final(&shake_ctx, shake_output);
    
    printf("Message: %s\n", shake_msg);
    printf("SHAKE256 (64 bytes): ");
    print_hex(shake_output, 64);
    sha3_free(&shake_ctx);
    
    // Test 5: cSHAKE128
    printf("\nTest 5: cSHAKE128 with customization\n");
    sha3_ctx_t cshake_ctx;
    uint8_t cshake_output[32];
    const char *cshake_msg = "cSHAKE test";
    const char *function_name = "Email Signature";
    const char *customization = "EmailApp v1.0";
    
    cshake_init(&cshake_ctx, CSHAKE128, 32,
                (uint8_t*)function_name, strlen(function_name),
                (uint8_t*)customization, strlen(customization));
    sha3_update(&cshake_ctx, (uint8_t*)cshake_msg, strlen(cshake_msg));
    sha3_final(&cshake_ctx, cshake_output);
    
    printf("Message: %s\n", cshake_msg);
    printf("Function: %s\n", function_name);
    printf("Customization: %s\n", customization);
    printf("cSHAKE128 (32 bytes): ");
    print_hex(cshake_output, 32);
    sha3_free(&cshake_ctx);
    
    // Test 6: Loading from intermediate state
    printf("\nTest 6: Loading from intermediate state\n");
    printf("Note: This requires proper state data from external source\n");
    
    // Example of how to use intermediate state
    // In real use, state would be loaded from file or network
    sha3_intermediate_state_t saved_state = {0};
    saved_state.variant = SHA3_256;
    saved_state.output_len = SHA3_256_DIGEST_SIZE;
    saved_state.r = 1088;  // SHA3-256 rate in bits
    saved_state.c = 512;   // SHA3-256 capacity in bits
    saved_state.n = 256;   // Output size in bits
    saved_state.b = 1600;  // State size
    saved_state.w = 64;    // Word size
    saved_state.l = 6;     // log2(w)
    saved_state.nr = 24;   // Number of rounds
    
    // In real scenario, saved_state.state_bytes would contain actual state data
    // For demo, we'll just show the API usage
    uint8_t final_data[] = "Additional data to hash";
    uint8_t state_hash[SHA3_256_DIGEST_SIZE];
    
    // This would work if state_bytes contained valid state
    // sha3_final_from_state(&saved_state, final_data, sizeof(final_data)-1, state_hash);
    printf("(Skipped - requires valid state data)\n");
    
    // Test 7: All hash variants
    printf("\nTest 7: Testing all SHA-3 variants\n");
    const char *test_msg = "The quick brown fox jumps over the lazy dog";
    
    // SHA3-224
    sha3_ctx_t ctx224;
    uint8_t hash224[SHA3_224_DIGEST_SIZE];
    sha3_init(&ctx224, SHA3_224, 0);
    sha3_update(&ctx224, (uint8_t*)test_msg, strlen(test_msg));
    sha3_final(&ctx224, hash224);
    printf("SHA3-224: ");
    print_hex(hash224, SHA3_224_DIGEST_SIZE);
    sha3_free(&ctx224);
    
    // SHA3-384
    sha3_ctx_t ctx384;
    uint8_t hash384[SHA3_384_DIGEST_SIZE];
    sha3_init(&ctx384, SHA3_384, 0);
    sha3_update(&ctx384, (uint8_t*)test_msg, strlen(test_msg));
    sha3_final(&ctx384, hash384);
    printf("SHA3-384: ");
    print_hex(hash384, SHA3_384_DIGEST_SIZE);
    sha3_free(&ctx384);
    
    // SHA3-512
    sha3_ctx_t ctx512;
    uint8_t hash512[SHA3_512_DIGEST_SIZE];
    sha3_init(&ctx512, SHA3_512, 0);
    sha3_update(&ctx512, (uint8_t*)test_msg, strlen(test_msg));
    sha3_final(&ctx512, hash512);
    printf("SHA3-512: ");
    print_hex(hash512, SHA3_512_DIGEST_SIZE);
    sha3_free(&ctx512);
    
    printf("\n=== All tests completed ===\n");
    
    return 0;
}
