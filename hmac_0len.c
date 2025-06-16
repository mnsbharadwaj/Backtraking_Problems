#include <stdio.h>
#include <string.h>
#include <libkeccak.h>

int main() {
    // Input key: 34 bytes of 0x00
    unsigned char key[34] = {0};

    // Empty message
    const char *message = "";
    size_t message_len = 0;

    // Keccak spec for SHA3-256
    struct libkeccak_spec spec;
    spec.capacity = 512;  // SHA3-256 → capacity = 512
    spec.output = 256;    // Output bits

    // HMAC state
    struct libkeccak_hmac_state hmac_state;
    // General Keccak state (used internally)
    struct libkeccak_state state;

    // Initialise Keccak state
    if (libkeccak_state_initialise(&state, &spec)) {
        fprintf(stderr, "libkeccak_state_initialise failed\n");
        return 1;
    }

    // Initialise HMAC
    if (libkeccak_hmac_initialise(&hmac_state, &state, &spec, key, sizeof(key))) {
        fprintf(stderr, "libkeccak_hmac_initialise failed\n");
        return 1;
    }

    // Update with message (empty)
    if (libkeccak_hmac_update(&hmac_state, message, message_len)) {
        fprintf(stderr, "libkeccak_hmac_update failed\n");
        return 1;
    }

    // Finalise and get digest
    unsigned char digest[32];
    if (libkeccak_hmac_final(&hmac_state, &state, &spec, digest)) {
        fprintf(stderr, "libkeccak_hmac_final failed\n");
        return 1;
    }

    // Print the digest
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // Free state
    libkeccak_hmac_destroy(&hmac_state);
    libkeccak_state_destroy(&state);

    return 0;
}
