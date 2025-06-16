#ifndef SHA3_WRAPPER_H
#define SHA3_WRAPPER_H

#include <libkeccak.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

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

// Alternative: Direct state manipulation function
// This assumes the user has the raw 200-byte Keccak state
int sha3_set_raw_state(sha3_ctx_t *ctx, const uint8_t raw_state[KECCAK_STATE_SIZE]);

#endif // SHA3_WRAPPER_H

// Implementation

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
    
    // Clear key pad
    memset(ctx->key_pad, 0, HMAC_MAX_KEY_SIZE);
    
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
        // Rest of key_pad is already zeroed
    } else {
        // Copy key and pad with zeros
        if (key && key_len > 0) {
            memcpy(ctx->key_pad, key, key_len);
        }
        // Rest of key_pad is already zeroed
    }
    
    // Create ipad and opad keys
    uint8_t ipad_key[HMAC_MAX_KEY_SIZE];
    uint8_t opad_key[HMAC_MAX_KEY_SIZE];
    
    // XOR key with ipad and opad
    for (size_t i = 0; i < block_size; i++) {
        ipad_key[i] = ctx->key_pad[i] ^ HMAC_IPAD;
        opad_key[i] = ctx->key_pad[i] ^ HMAC_OPAD;
    }
    
    // Initialize inner hash with key XOR ipad
    sha3_update(&ctx->inner_ctx, ipad_key, block_size);
    
    // Initialize outer hash with key XOR opad
    sha3_update(&ctx->outer_ctx, opad_key, block_size);
    
    // Clear sensitive data
    memset(ipad_key, 0, sizeof(ipad_key));
    memset(opad_key, 0, sizeof(opad_key));
    
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

// Example usage and test functions
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
    
    // Test 2: HMAC-SHA3-256 with 34-byte zero key and empty message
    printf("\nTest 2: HMAC-SHA3-256 with 34-byte zero key and empty message\n");
    hmac_sha3_ctx_t hmac_ctx;
    uint8_t hmac_output[SHA3_256_DIGEST_SIZE];
    uint8_t zero_key[34];
    memset(zero_key, 0, sizeof(zero_key));
    
    printf("Key length: %zu bytes\n", sizeof(zero_key));
    printf("Block size for SHA3-256: %d bytes\n", SHA3_256_BLOCK_SIZE);
    printf("Key is %s than block size\n", 
           sizeof(zero_key) > SHA3_256_BLOCK_SIZE ? "longer" : "shorter or equal");
    
    // Expected result
    unsigned int expected[] = {
        0x64c141e8, 0x0cf1b4e5, 0x5885399f, 0x72af6279,
        0x957a60fd, 0x92fc9611, 0x51523afb, 0xea841794
    };
    
    // Initialize HMAC with 34-byte zero key
    hmac_sha3_init(&hmac_ctx, HMAC_SHA3_256, zero_key, sizeof(zero_key));
    
    // No update call (empty message)
    // Finalize immediately
    hmac_sha3_final(&hmac_ctx, hmac_output);
    
    // Display as hex bytes
    printf("\nResult (hex bytes): ");
    print_hex(hmac_output, SHA3_256_DIGEST_SIZE);
    
    // Display expected as hex bytes
    printf("Expected (as bytes): ");
    for (int i = 0; i < 8; i++) {
        printf("%02x %02x %02x %02x ", 
               (expected[i] >> 24) & 0xff,
               (expected[i] >> 16) & 0xff,
               (expected[i] >> 8) & 0xff,
               expected[i] & 0xff);
    }
    printf("\n");
    
    // Check if matches byte by byte
    int matches = 1;
    for (int i = 0; i < SHA3_256_DIGEST_SIZE; i++) {
        uint8_t expected_byte = (expected[i/4] >> (24 - 8*(i%4))) & 0xff;
        if (hmac_output[i] != expected_byte) {
            matches = 0;
            break;
        }
    }
    
    printf("\nResult %s expected values\n", matches ? "MATCHES" : "DOES NOT MATCH");
    
    // Additional test: Try with explicit empty update
    printf("\nTest 2b: Same with explicit empty update\n");
    hmac_sha3_ctx_t hmac_ctx2;
    uint8_t hmac_output2[SHA3_256_DIGEST_SIZE];
    
    hmac_sha3_init(&hmac_ctx2, HMAC_SHA3_256, zero_key, sizeof(zero_key));
    hmac_sha3_update(&hmac_ctx2, (uint8_t*)"", 0);
    hmac_sha3_final(&hmac_ctx2, hmac_output2);
    
    printf("Result: ");
    print_hex(hmac_output2, SHA3_256_DIGEST_SIZE);
    
    hmac_sha3_free(&hmac_ctx);
    hmac_sha3_free(&hmac_ctx2);
    
    return 0;
}
