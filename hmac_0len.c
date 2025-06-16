#include <stdio.h>
#include <string.h>
#include <libkeccak.h>

int main() {
    // 34-byte key of 0x00
    unsigned char key[34] = {0};

    // Empty message
    const unsigned char *msg = (const unsigned char *)"";
    size_t msglen = 0;

    // Output digest (SHA3-256 = 32 bytes)
    unsigned char digest[32];
    size_t digestlen = sizeof(digest);

    // Keccak spec: SHA3-256 → capacity 512, output 256
    struct libkeccak_spec spec;
    spec.rate = 1088;        // 1600 - 512
    spec.capacity = 512;
    spec.output = 256;

    // HMAC state
    struct libkeccak_hmac_state state;

    // Initialize HMAC
    if (libkeccak_hmac_initialise(&state, &spec) < 0) {
        fprintf(stderr, "Failed to initialize HMAC\n");
        return 1;
    }

    // Set HMAC key
    if (libkeccak_hmac_set_key(&state, key, sizeof(key)) < 0) {
        fprintf(stderr, "Failed to set HMAC key\n");
        libkeccak_hmac_destroy(&state);
        return 1;
    }

    // Feed empty message
    if (libkeccak_hmac_update(&state, msg, msglen) < 0) {
        fprintf(stderr, "Failed to update HMAC\n");
        libkeccak_hmac_destroy(&state);
        return 1;
    }

    // Finalize
    if (libkeccak_hmac_digest(&state, digest, &digestlen) < 0) {
        fprintf(stderr, "Failed to finalize HMAC\n");
        libkeccak_hmac_destroy(&state);
        return 1;
    }

    // Clean up
    libkeccak_hmac_destroy(&state);

    // Print digest
    for (size_t i = 0; i < digestlen; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}
