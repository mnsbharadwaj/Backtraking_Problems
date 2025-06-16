#include <stdio.h>
#include <string.h>
#include <libkeccak.h>

int main() {
    // 34-byte key (all 0s)
    unsigned char key[34] = {0};

    // Empty message
    const unsigned char *message = (unsigned char *)"";
    size_t msglen = 0;

    // Output buffer
    unsigned char digest[32];
    size_t digestlen = sizeof(digest);

    // Step 1: Define Keccak specification
    struct libkeccak_spec spec;
    spec.capacity = 512;  // SHA3-256 → capacity = 512 bits
    spec.output = 256;    // output bits

    // Step 2: Initialize HMAC state
    struct libkeccak_hmac_state state;
    if (libkeccak_hmac_initialise(&state, &spec) < 0) {
        fprintf(stderr, "Error: libkeccak_hmac_initialise failed\n");
        return 1;
    }

    // Step 3: Set the key
    if (libkeccak_hmac_set_key(&state, key, sizeof(key)) < 0) {
        fprintf(stderr, "Error: libkeccak_hmac_set_key failed\n");
        libkeccak_hmac_destroy(&state);
        return 1;
    }

    // Step 4: Feed the message (empty)
    if (libkeccak_hmac_update(&state, message, msglen) < 0) {
        fprintf(stderr, "Error: libkeccak_hmac_update failed\n");
        libkeccak_hmac_destroy(&state);
        return 1;
    }

    // Step 5: Finalize and get digest
    if (libkeccak_hmac_digest(&state, digest, &digestlen) < 0) {
        fprintf(stderr, "Error: libkeccak_hmac_digest failed\n");
        libkeccak_hmac_destroy(&state);
        return 1;
    }

    // Step 6: Print the digest
    for (size_t i = 0; i < digestlen; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // Step 7: Clean up
    libkeccak_hmac_destroy(&state);
    return 0;
}
