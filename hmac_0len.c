#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libkeccak.h>

int main(void) {
    // Step 1: Define key (34 bytes of 0)
    unsigned char key[34] = {0};

    // Step 2: Empty message
    const unsigned char *msg = (const unsigned char *)"";
    size_t msglen = 0;

    // Step 3: SHA3-256 spec
    struct libkeccak_spec spec = {
        .capacity = 512,
        .output = 256
    };

    // Step 4: Initialize main keccak state
    struct libkeccak_state state;
    if (libkeccak_state_initialise(&state, &spec) < 0) {
        fprintf(stderr, "Failed to init libkeccak_state\n");
        return 1;
    }

    // Step 5: Initialize HMAC
    struct libkeccak_hmac_state hmac;
    if (libkeccak_hmac_initialise(&hmac, &state, &spec, key, sizeof(key)) < 0) {
        fprintf(stderr, "Failed to init HMAC\n");
        libkeccak_state_destroy(&state);
        return 1;
    }

    // Step 6: Update HMAC with message
    if (libkeccak_hmac_update(&hmac, msg, msglen) < 0) {
        fprintf(stderr, "HMAC update failed\n");
        libkeccak_hmac_destroy(&hmac);
        libkeccak_state_destroy(&state);
        return 1;
    }

    // Step 7: Finalize and get digest
    unsigned char digest[32];
    if (libkeccak_hmac_digest(&hmac, &state, &spec, digest, sizeof(digest)) < 0) {
        fprintf(stderr, "HMAC digest failed\n");
        libkeccak_hmac_destroy(&hmac);
        libkeccak_state_destroy(&state);
        return 1;
    }

    // Step 8: Print the digest
    printf("HMAC-SHA3-256: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", digest[i]);
    printf("\n");

    // Step 9: Cleanup
    libkeccak_hmac_destroy(&hmac);
    libkeccak_state_destroy(&state);

    return 0;
}
