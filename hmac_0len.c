#include <stdio.h>
#include <string.h>
#include <libkeccak.h>

int main() {
    // 34-byte key, all zeros
    unsigned char key[34] = {0};

    // Empty message
    const unsigned char *msg = (unsigned char *)"";
    size_t msglen = 0;

    // Digest buffer
    unsigned char digest[32];
    size_t digestlen = sizeof(digest);

    // Libkeccak state
    struct libkeccak_hmac_state state;

    // Initialize HMAC state for SHA3-256 (capacity = 512)
    if (libkeccak_hmac_initialise(&state, 256, 512) < 0) {
        fprintf(stderr, "Failed to initialize HMAC state\n");
        return 1;
    }

    // Set the key (HMAC)
    if (libkeccak_hmac_set_key(&state, key, sizeof(key)) < 0) {
        fprintf(stderr, "Failed to set HMAC key\n");
        libkeccak_hmac_destroy(&state);
        return 1;
    }

    // Update with the message (which is empty here)
    if (libkeccak_hmac_update(&state, msg, msglen) < 0) {
        fprintf(stderr, "Failed to update HMAC\n");
        libkeccak_hmac_destroy(&state);
        return 1;
    }

    // Finalize and get digest
    if (libkeccak_hmac_digest(&state, digest, &digestlen) < 0) {
        fprintf(stderr, "Failed to finalize HMAC\n");
        libkeccak_hmac_destroy(&state);
        return 1;
    }

    libkeccak_hmac_destroy(&state);

    // Print digest
    for (size_t i = 0; i < digestlen; i++)
        printf("%02x", digest[i]);
    printf("\n");

    return 0;
}
