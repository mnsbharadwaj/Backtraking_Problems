#include <stdio.h>
#include <string.h>
#include <libkeccak.h>

int main() {
    // 1. Key: 34 bytes of 0x00
    unsigned char key[34] = {0};

    // 2. Empty message
    const unsigned char *message = (const unsigned char *)"";
    size_t message_len = 0;

    // 3. Output buffer for SHA3-256
    unsigned char digest[32];

    // 4. Keccak spec for SHA3-256
    struct libkeccak_spec spec;
    spec.capacity = 512;
    spec.output = 256;

    // 5. Parent state
    struct libkeccak_state parent;
    if (libkeccak_state_initialise(&parent, &spec) < 0) {
        fprintf(stderr, "Failed to initialize parent state\n");
        return 1;
    }

    // 6. HMAC state
    struct libkeccak_hmac_state hmac;
    if (libkeccak_hmac_initialise(&hmac, &parent, &spec, key, sizeof(key)) < 0) {
        fprintf(stderr, "Failed to initialize HMAC\n");
        libkeccak_state_destroy(&parent);
        return 1;
    }

    // 7. Feed message
    if (libkeccak_hmac_update(&hmac, message, message_len) < 0) {
        fprintf(stderr, "Failed to update HMAC\n");
        libkeccak_hmac_destroy(&hmac);
        libkeccak_state_destroy(&parent);
        return 1;
    }

    // 8. Finalize and get digest
    if (libkeccak_hmac_digest(&hmac, &parent, &spec, digest, sizeof(digest)) < 0) {
        fprintf(stderr, "Failed to finalize HMAC\n");
        libkeccak_hmac_destroy(&hmac);
        libkeccak_state_destroy(&parent);
        return 1;
    }

    // 9. Output digest
    for (int i = 0; i < sizeof(digest); i++)
        printf("%02x", digest[i]);
    printf("\n");

    // 10. Cleanup
    libkeccak_hmac_destroy(&hmac);
    libkeccak_state_destroy(&parent);

    return 0;
}
