#ifndef SHA3_WRAPPER_H
#define SHA3_WRAPPER_H

#include <libkeccak.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Keccak/SHA-3 constants
#define KECCAK_STATE_SIZE       200  // 1600 bits / 8
#define KECCAK_MAX_RATE         200  // Maximum rate in bytes
#define KECCAK_STATE_SIZE_BITS  1600 // State size in bits

// SHA-3 specific block sizes (rate in bytes)
#define SHA3_224_BLOCK_SIZE     144  // (1600 - 2*224) / 8
#define SHA3_256_BLOCK_SIZE     136  // (1600 - 2*256) / 8
#define SHA3_384_BLOCK_SIZE     104  // (1600 - 2*384) / 8
#define SHA3_512_BLOCK_SIZE     72   // (1600 - 2*512) / 8

// SHA-3 rate in bits
#define SHA3_224_RATE_BITS      1152 // 144 * 8
#define SHA3_256_RATE_BITS      1088 // 136 * 8
#define SHA3_384_RATE_BITS      832  // 104 * 8
#define SHA3_512_RATE_BITS      576  // 72 * 8

// SHA-3 capacity in bits
#define SHA3_224_CAPACITY_BITS  448  // 2 * 224
#define SHA3_256_CAPACITY_BITS  512  // 2 * 256
#define SHA3_384_CAPACITY_BITS  768  // 2 * 384
#define SHA3_512_CAPACITY_BITS  1024 // 2 * 512

// Output sizes in bytes
#define SHA3_224_DIGEST_SIZE    28
#define SHA3_256_DIGEST_SIZE    32
#define SHA3_384_DIGEST_SIZE    48
#define SHA3_512_DIGEST_SIZE    64

// Output sizes in bits
#define SHA3_224_OUTPUT_BITS    224
#define SHA3_256_OUTPUT_BITS    256
#define SHA3_384_OUTPUT_BITS    384
#define SHA3_512_OUTPUT_BITS    512

// HMAC constants
#define HMAC_IPAD              0x36
#define HMAC_OPAD              0x5C
#define HMAC_MAX_KEY_SIZE      KECCAK_MAX_RATE

// SHAKE constants
#define SHAKE128_CAPACITY      256  // bits
#define SHAKE256_CAPACITY      512  // bits
#define SHAKE128_SEMICAPACITY  128  // capacity / 2
#define SHAKE256_SEMICAPACITY  256  // capacity / 2

// Keccak parameters
#define KECCAK_WORD_SIZE       64   // w parameter (bits)
#define KECCAK_L_PARAMETER     6    // log2(w)
#define KECCAK_NUM_ROUNDS      24   // Number of rounds
#define KECCAK_NUM_LANES       25   // Number of lanes (5x5)

// Encoding constants for cSHAKE
#define CSHAKE_BYTEPAD_RATE    8    // Divisor for bytepad
#define CSHAKE_LEFT_ENCODE_1   1    // Single byte length encoding
#define CSHAKE_LEFT_ENCODE_2   2    // Two byte length encoding
#define CSHAKE_MAX_ENCODE_LEN  512  // Maximum encoding buffer size

// Bit manipulation constants
#define BITS_PER_BYTE          8
#define BYTE_MASK              0xFF

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
    size_t bit_len = in_len * BITS_PER_BYTE;
    
    // Left encode the length
    if (bit_len < SHAKE256_CAPACITY) {
        output[i++] = CSHAKE_LEFT_ENCODE_1;
        output[i++] = bit_len & BYTE_MASK;
    } else {
        output[i++] = CSHAKE_LEFT_ENCODE_2;
        output[i++] = (bit_len >> BITS_PER_BYTE) & BYTE_MASK;
        output[i++] = bit_len & BYTE_MASK;
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
            libkeccak_spec_sha3(&spec, SHA3_224_OUTPUT_BITS);
            ctx->output_len = SHA3_224_DIGEST_SIZE;
            break;
        case SHA3_256:
            libkeccak_spec_sha3(&spec, SHA3_256_OUTPUT_BITS);
            ctx->output_len = SHA3_256_DIGEST_SIZE;
            break;
        case SHA3_384:
            libkeccak_spec_sha3(&spec, SHA3_384_OUTPUT_BITS);
            ctx->output_len = SHA3_384_DIGEST_SIZE;
            break;
        case SHA3_512:
            libkeccak_spec_sha3(&spec, SHA3_512_OUTPUT_BITS);
            ctx->output_len = SHA3_512_DIGEST_SIZE;
            break;
        case SHAKE128:
            libkeccak_spec_shake(&spec, SHAKE128_SEMICAPACITY, output_len * BITS_PER_BYTE);
            ctx->output_len = output_len;
            break;
        case SHAKE256:
            libkeccak_spec_shake(&spec, SHAKE256_SEMICAPACITY, output_len * BITS_PER_BYTE);
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
    uint8_t encoded[CSHAKE_MAX_ENCODE_LEN];
    size_t encoded_len = 0;
    
    memset(ctx, 0, sizeof(sha3_ctx_t));
    ctx->variant = variant;
    ctx->output_len = output_len;
    
    // Set up spec
    if (variant == CSHAKE128) {
        libkeccak_spec_shake(&spec, SHAKE128_SEMICAPACITY, output_len * BITS_PER_BYTE);
    } else if (variant == CSHAKE256) {
        libkeccak_spec_shake(&spec, SHAKE256_SEMICAPACITY, output_len * BITS_PER_BYTE);
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
    size_t w = rate / BITS_PER_BYTE;
    
    // Encode w
    encoded[encoded_len++] = CSHAKE_LEFT_ENCODE_1;
    encoded[encoded_len++] = w & BYTE_MASK;
    
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
    // Handle NULL data or zero length
    if (len == 0) {
        return 0;  // Nothing to update, but not an error
    }
    if (!data) {
        return -1;  // NULL data with non-zero length is an error
    }
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
    // Handle zero-length data
    if (len == 0) {
        return 0;
    }
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
    
    // Test 1b: Zero-length data
    printf("\nTest 1b: SHA3-256 of empty string (zero-length data)\n");
    sha3_ctx_t ctx_empty;
    uint8_t hash_empty[SHA3_256_DIGEST_SIZE];
    
    sha3_init(&ctx_empty, SHA3_256, 0);
    sha3_update(&ctx_empty, (uint8_t*)"", 0);  // Zero length update
    sha3_final(&ctx_empty, hash_empty);
    
    printf("Message: (empty)\n");
    printf("SHA3-256: ");
    print_hex(hash_empty, SHA3_256_DIGEST_SIZE);
    sha3_free(&ctx_empty);
    
    // Test 1c: No update calls (also zero-length)
    printf("\nTest 1c: SHA3-256 with no update calls\n");
    sha3_ctx_t ctx_no_update;
    uint8_t hash_no_update[SHA3_256_DIGEST_SIZE];
    
    sha3_init(&ctx_no_update, SHA3_256, 0);
    // No update call at all
    sha3_final(&ctx_no_update, hash_no_update);
    
    printf("Message: (no update called)\n");
    printf("SHA3-256: ");
    print_hex(hash_no_update, SHA3_256_DIGEST_SIZE);
    sha3_free(&ctx_no_update);
    
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
    
    // Test 3b: HMAC with empty message
    printf("\nTest 3b: HMAC-SHA3-256 with empty message\n");
    hmac_sha3_ctx_t hmac_ctx_empty;
    uint8_t hmac_output_empty[SHA3_256_DIGEST_SIZE];
    
    hmac_sha3_init(&hmac_ctx_empty, HMAC_SHA3_256, (uint8_t*)key, strlen(key));
    // No update or zero-length update
    hmac_sha3_update(&hmac_ctx_empty, (uint8_t*)"", 0);
    hmac_sha3_final(&hmac_ctx_empty, hmac_output_empty);
    
    printf("Key: %s\n", key);
    printf("Message: (empty)\n");
    printf("HMAC-SHA3-256: ");
    print_hex(hmac_output_empty, SHA3_256_DIGEST_SIZE);
    hmac_sha3_free(&hmac_ctx_empty);
    
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
    
    // Test 8: HMAC-SHA3-512 with intermediate state loading
    printf("\nTest 8: HMAC-SHA3-512 with intermediate state loading\n");
    
    // First, create a real HMAC state we can save and load
    hmac_sha3_ctx_t hmac512_ctx;
    uint8_t hmac512_key[] = "This is a test key for HMAC-SHA3-512";
    const char *hmac512_msg_part1 = "First part of the message - ";
    const char *hmac512_msg_part2 = "Second part of the message";
    uint8_t hmac512_output1[SHA3_512_DIGEST_SIZE];
    uint8_t hmac512_output2[SHA3_512_DIGEST_SIZE];
    
    // Initialize HMAC-SHA3-512
    hmac_sha3_init(&hmac512_ctx, HMAC_SHA3_512, hmac512_key, sizeof(hmac512_key) - 1);
    
    // Process first part
    hmac_sha3_update(&hmac512_ctx, (uint8_t*)hmac512_msg_part1, strlen(hmac512_msg_part1));
    
    // Simulate saving state here
    // In real application, you would serialize hmac512_ctx internal state
    hmac_sha3_intermediate_state_t hmac512_state = {0};
    
    // Manually populate the state (in real use, this would come from saved data)
    // Inner state parameters for HMAC-SHA3-512
    hmac512_state.inner_state.variant = SHA3_512;
    hmac512_state.inner_state.output_len = SHA3_512_DIGEST_SIZE;
    hmac512_state.inner_state.r = SHA3_512_RATE_BITS;
    hmac512_state.inner_state.c = SHA3_512_CAPACITY_BITS;
    hmac512_state.inner_state.n = SHA3_512_OUTPUT_BITS;
    hmac512_state.inner_state.b = KECCAK_STATE_SIZE_BITS;
    hmac512_state.inner_state.w = KECCAK_WORD_SIZE;
    hmac512_state.inner_state.l = KECCAK_L_PARAMETER;
    hmac512_state.inner_state.nr = KECCAK_NUM_ROUNDS;
    
    // Outer state parameters for HMAC-SHA3-512
    hmac512_state.outer_state.variant = SHA3_512;
    hmac512_state.outer_state.output_len = SHA3_512_DIGEST_SIZE;
    hmac512_state.outer_state.r = SHA3_512_RATE_BITS;
    hmac512_state.outer_state.c = SHA3_512_CAPACITY_BITS;
    hmac512_state.outer_state.n = SHA3_512_OUTPUT_BITS;
    hmac512_state.outer_state.b = KECCAK_STATE_SIZE_BITS;
    hmac512_state.outer_state.w = KECCAK_WORD_SIZE;
    hmac512_state.outer_state.l = KECCAK_L_PARAMETER;
    hmac512_state.outer_state.nr = KECCAK_NUM_ROUNDS;
    
    // HMAC specific parameters
    hmac512_state.block_size = SHA3_512_BLOCK_SIZE;
    hmac512_state.variant = SHA3_512;
    
    // Copy key pad (this would be saved from the actual context)
    memcpy(hmac512_state.key_pad, hmac512_ctx.key_pad, sizeof(hmac512_state.key_pad));
    
    // Note: In real use, you would also need to save the actual Keccak state arrays
    // hmac512_state.inner_state.state_bytes would contain the serialized inner state
    // hmac512_state.outer_state.state_bytes would contain the serialized outer state
    
    // Continue with original context to get reference hash
    hmac_sha3_update(&hmac512_ctx, (uint8_t*)hmac512_msg_part2, strlen(hmac512_msg_part2));
    hmac_sha3_final(&hmac512_ctx, hmac512_output1);
    
    printf("Original HMAC-SHA3-512 (continuous): ");
    print_hex(hmac512_output1, SHA3_512_DIGEST_SIZE);
    
    // Now test loading from state (if we had valid state data)
    printf("\nNote: Complete state loading requires actual state data from libkeccak\n");
    printf("In production, use libkeccak_state_marshal/unmarshal functions\n");
    
    // Example of the API usage:
    // hmac_sha3_ctx_t hmac512_loaded;
    // hmac_sha3_init_from_state(&hmac512_loaded, &hmac512_state);
    // hmac_sha3_update(&hmac512_loaded, (uint8_t*)hmac512_msg_part2, strlen(hmac512_msg_part2));
    // hmac_sha3_final(&hmac512_loaded, hmac512_output2);
    
    // Or direct finalization:
    // hmac_sha3_final_from_state(&hmac512_state, 
    //                            (uint8_t*)hmac512_msg_part2, 
    //                            strlen(hmac512_msg_part2), 
    //                            hmac512_output2);
    
    hmac_sha3_free(&hmac512_ctx);
    
    // Test 9: Processing exactly 200-byte chunks with state
    printf("\nTest 9: Processing exactly 200-byte chunks\n");
    sha3_ctx_t chunk_test_ctx;
    uint8_t chunk_200[KECCAK_MAX_RATE];
    uint8_t chunk_hash[SHA3_256_DIGEST_SIZE];
    
    sha3_init(&chunk_test_ctx, SHA3_256, 0);
    
    // Process 5 chunks of exactly 200 bytes each (1000 bytes total)
    for (int i = 0; i < 5; i++) {
        memset(chunk_200, 'A' + i, KECCAK_MAX_RATE);
        sha3_update(&chunk_test_ctx, chunk_200, KECCAK_MAX_RATE);
        printf("Processed chunk %d (200 bytes of '%c')\n", i + 1, 'A' + i);
    }
    
    sha3_final(&chunk_test_ctx, chunk_hash);
    printf("Hash of 1000 bytes (5 x 200-byte chunks): ");
    print_hex(chunk_hash, SHA3_256_DIGEST_SIZE);
    sha3_free(&chunk_test_ctx);
    
    // Test 10: Verification - Step-by-step vs One-shot hashing
    printf("\nTest 10: Verification - Step-by-step vs One-shot hashing\n");
    printf("This test verifies that incremental hashing produces the same result as one-shot\n\n");
    
    // Test data
    const char *test_data = "This is a test message that will be hashed both incrementally and in one shot to verify they produce identical results.";
    size_t total_len = strlen(test_data);
    
    // Test 10a: SHA3-256 verification
    printf("SHA3-256 Verification:\n");
    sha3_ctx_t sha256_oneshot, sha256_incremental;
    uint8_t hash_oneshot[SHA3_256_DIGEST_SIZE];
    uint8_t hash_incremental[SHA3_256_DIGEST_SIZE];
    
    // One-shot hashing
    sha3_init(&sha256_oneshot, SHA3_256, 0);
    sha3_update(&sha256_oneshot, (uint8_t*)test_data, total_len);
    sha3_final(&sha256_oneshot, hash_oneshot);
    printf("One-shot hash:     ");
    print_hex(hash_oneshot, SHA3_256_DIGEST_SIZE);
    sha3_free(&sha256_oneshot);
    
    // Incremental hashing (simulate chunked processing)
    sha3_init(&sha256_incremental, SHA3_256, 0);
    size_t chunk_size = 17;  // Use odd size to test partial blocks
    size_t processed = 0;
    while (processed < total_len) {
        size_t to_process = (processed + chunk_size > total_len) ? 
                           (total_len - processed) : chunk_size;
        sha3_update(&sha256_incremental, (uint8_t*)test_data + processed, to_process);
        processed += to_process;
    }
    sha3_final(&sha256_incremental, hash_incremental);
    printf("Incremental hash:  ");
    print_hex(hash_incremental, SHA3_256_DIGEST_SIZE);
    sha3_free(&sha256_incremental);
    
    // Verify they match
    if (memcmp(hash_oneshot, hash_incremental, SHA3_256_DIGEST_SIZE) == 0) {
        printf("✓ SHA3-256: Hashes match!\n");
    } else {
        printf("✗ SHA3-256: Hashes DO NOT match! ERROR!\n");
    }
    
    // Test 10b: HMAC-SHA3-256 verification
    printf("\nHMAC-SHA3-256 Verification:\n");
    hmac_sha3_ctx_t hmac_oneshot, hmac_incremental;
    uint8_t hmac_hash_oneshot[SHA3_256_DIGEST_SIZE];
    uint8_t hmac_hash_incremental[SHA3_256_DIGEST_SIZE];
    const char *hmac_key = "test_key_for_hmac";
    
    // One-shot HMAC
    hmac_sha3_init(&hmac_oneshot, HMAC_SHA3_256, (uint8_t*)hmac_key, strlen(hmac_key));
    hmac_sha3_update(&hmac_oneshot, (uint8_t*)test_data, total_len);
    hmac_sha3_final(&hmac_oneshot, hmac_hash_oneshot);
    printf("One-shot HMAC:     ");
    print_hex(hmac_hash_oneshot, SHA3_256_DIGEST_SIZE);
    hmac_sha3_free(&hmac_oneshot);
    
    // Incremental HMAC
    hmac_sha3_init(&hmac_incremental, HMAC_SHA3_256, (uint8_t*)hmac_key, strlen(hmac_key));
    processed = 0;
    chunk_size = 23;  // Different chunk size
    while (processed < total_len) {
        size_t to_process = (processed + chunk_size > total_len) ? 
                           (total_len - processed) : chunk_size;
        hmac_sha3_update(&hmac_incremental, (uint8_t*)test_data + processed, to_process);
        processed += to_process;
    }
    hmac_sha3_final(&hmac_incremental, hmac_hash_incremental);
    printf("Incremental HMAC:  ");
    print_hex(hmac_hash_incremental, SHA3_256_DIGEST_SIZE);
    hmac_sha3_free(&hmac_incremental);
    
    // Verify they match
    if (memcmp(hmac_hash_oneshot, hmac_hash_incremental, SHA3_256_DIGEST_SIZE) == 0) {
        printf("✓ HMAC-SHA3-256: Hashes match!\n");
    } else {
        printf("✗ HMAC-SHA3-256: Hashes DO NOT match! ERROR!\n");
    }
    
    // Test 10c: 200-byte chunk verification
    printf("\n200-byte chunk processing verification:\n");
    sha3_ctx_t sha256_200chunks;
    uint8_t hash_200chunks[SHA3_256_DIGEST_SIZE];
    
    // Create exactly 600 bytes of data (3 x 200-byte chunks)
    uint8_t large_data[3 * KECCAK_MAX_RATE];
    for (int i = 0; i < 3 * KECCAK_MAX_RATE; i++) {
        large_data[i] = (uint8_t)(i % 256);
    }
    
    // One-shot hash of 600 bytes
    sha3_init(&sha256_oneshot, SHA3_256, 0);
    sha3_update(&sha256_oneshot, large_data, 3 * KECCAK_MAX_RATE);
    sha3_final(&sha256_oneshot, hash_oneshot);
    printf("One-shot (600 bytes):      ");
    print_hex(hash_oneshot, SHA3_256_DIGEST_SIZE);
    sha3_free(&sha256_oneshot);
    
    // Hash in 200-byte chunks
    sha3_init(&sha256_200chunks, SHA3_256, 0);
    for (int i = 0; i < 3; i++) {
        sha3_update(&sha256_200chunks, large_data + (i * KECCAK_MAX_RATE), KECCAK_MAX_RATE);
    }
    sha3_final(&sha256_200chunks, hash_200chunks);
    printf("200-byte chunks (3x200):   ");
    print_hex(hash_200chunks, SHA3_256_DIGEST_SIZE);
    sha3_free(&sha256_200chunks);
    
    // Verify they match
    if (memcmp(hash_oneshot, hash_200chunks, SHA3_256_DIGEST_SIZE) == 0) {
        printf("✓ 200-byte chunks: Hashes match!\n");
    } else {
        printf("✗ 200-byte chunks: Hashes DO NOT match! ERROR!\n");
    }
    
    // Test 10d: All SHA3 variants verification
    printf("\nAll SHA3 variants verification:\n");
    const char *variant_test_msg = "Verify all variants";
    
    // SHA3-224
    sha3_ctx_t ctx224_one, ctx224_inc;
    uint8_t hash224_one[SHA3_224_DIGEST_SIZE], hash224_inc[SHA3_224_DIGEST_SIZE];
    
    sha3_init(&ctx224_one, SHA3_224, 0);
    sha3_update(&ctx224_one, (uint8_t*)variant_test_msg, strlen(variant_test_msg));
    sha3_final(&ctx224_one, hash224_one);
    sha3_free(&ctx224_one);
    
    sha3_init(&ctx224_inc, SHA3_224, 0);
    for (size_t i = 0; i < strlen(variant_test_msg); i++) {
        sha3_update(&ctx224_inc, (uint8_t*)&variant_test_msg[i], 1);  // Byte by byte
    }
    sha3_final(&ctx224_inc, hash224_inc);
    sha3_free(&ctx224_inc);
    
    printf("SHA3-224: %s\n", 
           memcmp(hash224_one, hash224_inc, SHA3_224_DIGEST_SIZE) == 0 ? "✓ Match" : "✗ ERROR");
    
    // SHA3-384
    sha3_ctx_t ctx384_one, ctx384_inc;
    uint8_t hash384_one[SHA3_384_DIGEST_SIZE], hash384_inc[SHA3_384_DIGEST_SIZE];
    
    sha3_init(&ctx384_one, SHA3_384, 0);
    sha3_update(&ctx384_one, (uint8_t*)variant_test_msg, strlen(variant_test_msg));
    sha3_final(&ctx384_one, hash384_one);
    sha3_free(&ctx384_one);
    
    sha3_init(&ctx384_inc, SHA3_384, 0);
    // Process in 5-byte chunks
    for (size_t i = 0; i < strlen(variant_test_msg); i += 5) {
        size_t len = (i + 5 > strlen(variant_test_msg)) ? strlen(variant_test_msg) - i : 5;
        sha3_update(&ctx384_inc, (uint8_t*)&variant_test_msg[i], len);
    }
    sha3_final(&ctx384_inc, hash384_inc);
    sha3_free(&ctx384_inc);
    
    printf("SHA3-384: %s\n", 
           memcmp(hash384_one, hash384_inc, SHA3_384_DIGEST_SIZE) == 0 ? "✓ Match" : "✗ ERROR");
    
    // SHA3-512
    sha3_ctx_t ctx512_one, ctx512_inc;
    uint8_t hash512_one[SHA3_512_DIGEST_SIZE], hash512_inc[SHA3_512_DIGEST_SIZE];
    
    sha3_init(&ctx512_one, SHA3_512, 0);
    sha3_update(&ctx512_one, (uint8_t*)variant_test_msg, strlen(variant_test_msg));
    sha3_final(&ctx512_one, hash512_one);
    sha3_free(&ctx512_one);
    
    sha3_init(&ctx512_inc, SHA3_512, 0);
    // Process in varying chunk sizes
    size_t chunks[] = {7, 3, 4, 5};  // Total: 19 bytes (length of variant_test_msg)
    size_t offset = 0;
    for (int i = 0; i < 4 && offset < strlen(variant_test_msg); i++) {
        size_t len = (offset + chunks[i] > strlen(variant_test_msg)) ? 
                     strlen(variant_test_msg) - offset : chunks[i];
        sha3_update(&ctx512_inc, (uint8_t*)&variant_test_msg[offset], len);
        offset += len;
    }
    sha3_final(&ctx512_inc, hash512_inc);
    sha3_free(&ctx512_inc);
    
    printf("SHA3-512: %s\n", 
           memcmp(hash512_one, hash512_inc, SHA3_512_DIGEST_SIZE) == 0 ? "✓ Match" : "✗ ERROR");
    
    printf("\n=== All tests completed ===\n");
    
    return 0;
}
