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
    int64_t S[25];            // The state array (1600 bits = 25 * 64)
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

// State save/restore functions
int sha3_save_state(sha3_ctx_t *ctx, sha3_intermediate_state_t *state);
int sha3_restore_state(sha3_ctx_t *ctx, const sha3_intermediate_state_t *state);
int sha3_init_from_state(sha3_ctx_t *ctx, const sha3_intermediate_state_t *state);

// Direct state processing
int sha3_final_from_state(const sha3_intermediate_state_t *state, 
                         const uint8_t *additional_data, size_t additional_len,
                         uint8_t *output);

// HMAC state save/restore functions
int hmac_sha3_save_state(hmac_sha3_ctx_t *ctx, hmac_sha3_intermediate_state_t *state);
int hmac_sha3_restore_state(hmac_sha3_ctx_t *ctx, const hmac_sha3_intermediate_state_t *state);
int hmac_sha3_init_from_state(hmac_sha3_ctx_t *ctx, const hmac_sha3_intermediate_state_t *state);

// Direct HMAC state processing
int hmac_sha3_final_from_state(const hmac_sha3_intermediate_state_t *state,
                              const uint8_t *additional_data, size_t additional_len,
                              uint8_t *output);

// Helper function to get block size for a variant
size_t sha3_get_block_size(sha3_variant_t variant);

// Helper function to get digest size for a variant
size_t sha3_get_digest_size(sha3_variant_t variant);

#endif // SHA3_WRAPPER_H

// Implementation
#ifdef SHA3_WRAPPER_IMPLEMENTATION

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

// Save current state to intermediate state structure
int sha3_save_state(sha3_ctx_t *ctx, sha3_intermediate_state_t *state) {
    if (!ctx || !state) {
        return -1;
    }
    
    // Copy the Keccak state array
    memcpy(state->S, ctx->state.S, sizeof(state->S));
    
    // Save parameters
    state->r = ctx->state.r;
    state->c = ctx->state.c;
    state->n = ctx->state.n;
    state->b = ctx->state.b;
    state->w = ctx->state.w;
    state->l = ctx->state.l;
    state->nr = ctx->state.nr;
    state->output_len = ctx->output_len;
    state->variant = ctx->variant;
    
    return 0;
}

// Restore state from intermediate state structure
int sha3_restore_state(sha3_ctx_t *ctx, const sha3_intermediate_state_t *state) {
    if (!ctx || !state) {
        return -1;
    }
    
    // First initialize the context with the same variant
    if (state->variant >= SHAKE128) {
        sha3_init(ctx, state->variant, state->output_len);
    } else {
        sha3_init(ctx, state->variant, 0);
    }
    
    // Restore the Keccak state array
    memcpy(ctx->state.S, state->S, sizeof(state->S));
    
    // Restore parameters
    ctx->state.r = state->r;
    ctx->state.c = state->c;
    ctx->state.n = state->n;
    ctx->state.b = state->b;
    ctx->state.w = state->w;
    ctx->state.l = state->l;
    ctx->state.nr = state->nr;
    ctx->output_len = state->output_len;
    
    return 0;
}

// Initialize context directly from saved state
int sha3_init_from_state(sha3_ctx_t *ctx, const sha3_intermediate_state_t *state) {
    return sha3_restore_state(ctx, state);
}

// Compute final hash directly from state and additional data
int sha3_final_from_state(const sha3_intermediate_state_t *state, 
                         const uint8_t *additional_data, size_t additional_len,
                         uint8_t *output) {
    sha3_ctx_t ctx;
    
    // Restore the state
    if (sha3_restore_state(&ctx, state) < 0) {
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

// Save HMAC state
int hmac_sha3_save_state(hmac_sha3_ctx_t *ctx, hmac_sha3_intermediate_state_t *state) {
    if (!ctx || !state) {
        return -1;
    }
    
    // Save both inner and outer states
    if (sha3_save_state(&ctx->inner_ctx, &state->inner_state) < 0) {
        return -1;
    }
    
    if (sha3_save_state(&ctx->outer_ctx, &state->outer_state) < 0) {
        return -1;
    }
    
    // Save key pad and parameters
    memcpy(state->key_pad, ctx->key_pad, sizeof(ctx->key_pad));
    state->block_size = ctx->block_size;
    state->variant = ctx->inner_ctx.variant;
    
    return 0;
}

// Restore HMAC state
int hmac_sha3_restore_state(hmac_sha3_ctx_t *ctx, const hmac_sha3_intermediate_state_t *state) {
    if (!ctx || !state) {
        return -1;
    }
    
    // Clear context
    memset(ctx, 0, sizeof(hmac_sha3_ctx_t));
    
    // Restore both inner and outer states
    if (sha3_restore_state(&ctx->inner_ctx, &state->inner_state) < 0) {
        return -1;
    }
    
    if (sha3_restore_state(&ctx->outer_ctx, &state->outer_state) < 0) {
        return -1;
    }
    
    // Restore key pad and parameters
    memcpy(ctx->key_pad, state->key_pad, sizeof(state->key_pad));
    ctx->block_size = state->block_size;
    
    return 0;
}

// Initialize HMAC context from saved state
int hmac_sha3_init_from_state(hmac_sha3_ctx_t *ctx, const hmac_sha3_intermediate_state_t *state) {
    return hmac_sha3_restore_state(ctx, state);
}

// Compute final HMAC directly from state and additional data
int hmac_sha3_final_from_state(const hmac_sha3_intermediate_state_t *state,
                              const uint8_t *additional_data, size_t additional_len,
                              uint8_t *output) {
    hmac_sha3_ctx_t ctx;
    
    // Restore the state
    if (hmac_sha3_restore_state(&ctx, state) < 0) {
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

#endif // SHA3_WRAPPER_IMPLEMENTATION

// Example usage
#ifdef SHA3_EXAMPLE

#include <stdio.h>

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Example 1: SHA3-256 with chunked input
    printf("SHA3-256 example:\n");
    sha3_ctx_t sha3_ctx;
    uint8_t hash[SHA3_256_DIGEST_SIZE];
    
    sha3_init(&sha3_ctx, SHA3_256, 0);
    
    // Process data in 200-byte chunks
    uint8_t chunk1[KECCAK_MAX_RATE] = "First chunk of data...";
    uint8_t chunk2[KECCAK_MAX_RATE] = "Second chunk of data...";
    
    sha3_update(&sha3_ctx, chunk1, strlen((char*)chunk1));
    sha3_update(&sha3_ctx, chunk2, strlen((char*)chunk2));
    
    sha3_final(&sha3_ctx, hash);
    printf("Hash: ");
    print_hex(hash, SHA3_256_DIGEST_SIZE);
    sha3_free(&sha3_ctx);
    
    // Example 2: HMAC-SHA3-256
    printf("\nHMAC-SHA3-256 example:\n");
    hmac_sha3_ctx_t hmac_ctx;
    uint8_t hmac_output[SHA3_256_DIGEST_SIZE];
    uint8_t key[] = "secret key";
    
    hmac_sha3_init(&hmac_ctx, HMAC_SHA3_256, key, strlen((char*)key));
    hmac_sha3_update(&hmac_ctx, (uint8_t*)"Message to authenticate", 23);
    hmac_sha3_final(&hmac_ctx, hmac_output);
    printf("HMAC: ");
    print_hex(hmac_output, SHA3_256_DIGEST_SIZE);
    hmac_sha3_free(&hmac_ctx);
    
    // Example 3: State save/restore with 200-byte chunks
    printf("\nProcessing 200-byte chunks with state saving:\n");
    sha3_ctx_t ctx;
    sha3_intermediate_state_t saved_state;
    uint8_t final_hash[SHA3_256_DIGEST_SIZE];
    uint8_t data_chunk[KECCAK_MAX_RATE];
    
    // Initialize and process first chunk
    sha3_init(&ctx, SHA3_256, 0);
    memset(data_chunk, 'A', KECCAK_MAX_RATE);
    sha3_update(&ctx, data_chunk, KECCAK_MAX_RATE);
    
    // Save state
    sha3_save_state(&ctx, &saved_state);
    printf("State saved after %d bytes\n", KECCAK_MAX_RATE);
    
    // Process directly from saved state with another chunk
    memset(data_chunk, 'B', KECCAK_MAX_RATE);
    sha3_final_from_state(&saved_state, data_chunk, KECCAK_MAX_RATE, final_hash);
    printf("Final hash after %d bytes total: ", 2 * KECCAK_MAX_RATE);
    print_hex(final_hash, SHA3_256_DIGEST_SIZE);
    
    sha3_free(&ctx);
    
    // Example 4: HMAC state save/restore
    printf("\nHMAC-SHA3-256 state save/restore:\n");
    hmac_sha3_ctx_t hmac_ctx1, hmac_ctx2;
    hmac_sha3_intermediate_state_t hmac_state;
    uint8_t hmac_out1[SHA3_256_DIGEST_SIZE], hmac_out2[SHA3_256_DIGEST_SIZE];
    
    // Start HMAC
    hmac_sha3_init(&hmac_ctx1, HMAC_SHA3_256, key, strlen((char*)key));
    hmac_sha3_update(&hmac_ctx1, data_chunk, KECCAK_MAX_RATE);
    
    // Save state
    hmac_sha3_save_state(&hmac_ctx1, &hmac_state);
    
    // Continue normally
    memset(data_chunk, 'C', KECCAK_MAX_RATE);
    hmac_sha3_update(&hmac_ctx1, data_chunk, KECCAK_MAX_RATE);
    hmac_sha3_final(&hmac_ctx1, hmac_out1);
    
    // Restore and continue
    hmac_sha3_init_from_state(&hmac_ctx2, &hmac_state);
    hmac_sha3_update(&hmac_ctx2, data_chunk, KECCAK_MAX_RATE);
    hmac_sha3_final(&hmac_ctx2, hmac_out2);
    
    printf("HMAC from continuous: ");
    print_hex(hmac_out1, SHA3_256_DIGEST_SIZE);
    printf("HMAC from restored:   ");
    print_hex(hmac_out2, SHA3_256_DIGEST_SIZE);
    
    hmac_sha3_free(&hmac_ctx1);
    hmac_sha3_free(&hmac_ctx2);
    
    return 0;
}

#endif // SHA3_EXAMPLE
