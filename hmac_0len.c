#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libkeccak.h>
#include <libkeccak/keccak.h>
#include <libkeccak/hmac.h>

int main(void) {
    // Define a 34-byte zero key
    unsigned char key[34] = {0};

    // Empty message
    const unsigned char *msg = "";
    size_t msglen = 0;

    // Set Keccak parameters for SHA3-256
    struct libkeccak_spec spec;
    libkeccak_spec_sha3(&spec, 256); // Sets capacity/output correctly

    // Initialize Keccak state
    struct libkeccak_state *state = libkeccak_state_create(&spec);
    if (!state) {
        fprintf(stderr, "Failed to create Keccak state\n");
        return 1;
    }

    // Initialize HMAC state
    struct libkeccak_hmac_state *hmac = libkeccak_hmac_state_create();
    if (!hmac) {
        fprintf(stderr, "Failed to create HMAC state\n");
        libkeccak_state_destroy(state);
        return 1;
    }

    if (libkeccak_hmac_initialise(hmac, state, &spec, key, sizeof(key)) != 0) {
        fprintf(stderr, "Failed to initialize HMAC\n");
        libkeccak_hmac_state_destroy(hmac);
        libkeccak_state_destroy(state);
        return 1;
    }

    // Process message
    if (libkeccak_hmac_update(hmac, msg, msglen) != 0) {
        fprintf(stderr, "HMAC update failed\n");
        libkeccak_hmac_state_destroy(hmac);
        libkeccak_state_destroy(state);
        return 1;
    }

    // Finalize
    unsigned char digest[32];
    if (libkeccak_hmac_digest(hmac, state, &spec, digest, 32) != 0) {
        fprintf(stderr, "HMAC digest failed\n");
        libkeccak_hmac_state_destroy(hmac);
        libkeccak_state_destroy(state);
        return 1;
    }

    // Print digest
    printf("HMAC-SHA3-256: ");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    libkeccak_hmac_state_destroy(hmac);
    libkeccak_state_destroy(state);

    return 0;
}
