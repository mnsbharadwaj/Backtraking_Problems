#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkeccak.h>

int main(void) {
    // Step 1: HMAC key (34 bytes of 0)
    const unsigned char key[34] = {0};

    // Step 2: Message is empty
    const unsigned char *msg = (const unsigned char *)"";
    size_t msglen = 0;

    // Step 3: SHA3-256 spec
    struct libkeccak_spec spec;
    spec.capacity = 512;
    spec.output = 256;

    // Step 4: Keccak state
    struct libkeccak_state *state = libkeccak_state_create(&spec);
    if (!state) {
        fprintf(stderr, "Failed to create keccak state\n");
        return 1;
    }

    // Step 5: HMAC state
    struct libkeccak_hmac_state *hctx = libkeccak_hmac_state_create();
    if (!hctx) {
        fprintf(stderr, "Failed to create hmac state\n");
        libkeccak_state_destroy(state);
        return 1;
    }

    // Step 6: Initialize HMAC
    if (libkeccak_hmac_initialise(hctx, state, &spec, key, sizeof(key)) < 0) {
        fprintf(stderr, "libkeccak_hmac_initialise() failed\n");
        libkeccak_hmac_state_destroy(hctx);
        libkeccak_state_destroy(state);
        return 1;
    }

    // Step 7: Update with empty message
    if (libkeccak_hmac_update(hctx, msg, msglen) < 0) {
        fprintf(stderr, "HMAC update failed\n");
        libkeccak_hmac_state_destroy(hctx);
        libkeccak_state_destroy(state);
        return 1;
    }

    // Step 8: Compute digest
    unsigned char digest[32];
    if (libkeccak_hmac_digest(hctx, state, &spec, digest, sizeof(digest),
                              LIBKECCAK_PADDING_SHA3, LIBKECCAK_KECCAK) < 0) {
        fprintf(stderr, "HMAC digest failed\n");
        libkeccak_hmac_state_destroy(hctx);
        libkeccak_state_destroy(state);
        return 1;
    }

    // Step 9: Print digest
    printf("HMAC-SHA3-256: ");
    for (size_t i = 0; i < sizeof(digest); ++i)
        printf("%02x", digest[i]);
    printf("\n");

    // Step 10: Cleanup
    libkeccak_hmac_state_destroy(hctx);
    libkeccak_state_destroy(state);

    return 0;
}
