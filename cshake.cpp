#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

typedef struct {
    struct libkeccak_spec spec;
    struct libkeccak_generalised_spec gspec;
    struct libkeccak_state state;
} cshake_ctx;

int cshake_init(cshake_ctx *ctx, int is_cshake128) {
    libkeccak_spec_initialise(&ctx->spec, is_cshake128 ? 1344 : 1088, is_cshake128 ? 256 : 512);
    libkeccak_generalised_spec_from_spec(&ctx->gspec, &ctx->spec);

    ctx->gspec.use_custom = 1;              // Skip internal cSHAKE domain separation (pre-padded input)
    ctx->gspec.delimited_suffix = 0x04;     // XOF suffix for SHAKE/cSHAKE

    if (libkeccak_state_initialise(&ctx->state, &ctx->gspec) < 0) {
        fprintf(stderr, "State initialise failed\n");
        return -1;
    }
    return 0;
}

int cshake_process(cshake_ctx *ctx, const unsigned char *data, size_t len) {
    if (libkeccak_fast_update(&ctx->state, data, len) < 0) {
        fprintf(stderr, "Update failed\n");
        return -1;
    }
    return 0;
}

int cshake_done(cshake_ctx *ctx, unsigned char *out, size_t outlen) {
    if (libkeccak_fast_squeeze(&ctx->state, out, outlen) < 0) {
        fprintf(stderr, "Squeeze failed\n");
        return -1;
    }
    libkeccak_state_destroy(&ctx->state);
    return 0;
}

int main() {
    /* Simulated pre-padded data for cSHAKE128: 172 bytes = 168 + 4 split */
    unsigned char data[172];
    for (int i = 0; i < 172; i++) {
        data[i] = i & 0xFF; // Example pattern data
    }

    unsigned char out[64];

    printf("cSHAKE128, 172 bytes split (168+4) using libkeccak:\n");

    cshake_ctx ctx;
    if (cshake_init(&ctx, 1) != 0) return -1; // cSHAKE128

    // Process first block: 168 bytes
    if (cshake_process(&ctx, data, 168) != 0) return -1;

    // Process second block: 4 bytes
    if (cshake_process(&ctx, data + 168, 4) != 0) return -1;

    if (cshake_done(&ctx, out, 32) != 0) return -1; // 32-byte output

    print_hex(out, 32);

    return 0;
}
