#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Must be included in this order to avoid macro redefinition issues
#include <libkeccak/keccak.h>
#include <libkeccak/spec.h>
#include <libkeccak/hmac.h>

int main(void) {
    // Define key: 34 bytes of 0x00
    unsigned char key[34] = {0};

    // Message: empty
    const unsigned char *msg = "";
    size_t msglen = 0;

    // Output buffer for SHA3-256
    unsigned char digest[32];

    // Step 1: Define SHA3-256 spec
    struct libkeccak_spec spec;
    libkeccak_spec_sha3(&spec, 256); // sets capacity = 512, output = 256

    // Step 2: Initialize keccak sponge state
    struct libkeccak_state sponge;
    if (libkeccak_state_initialise(&sponge, &spec) < 0) {
        fprintf(stderr, "Failed to initialize Keccak state\n");
        return 1;
    }

    // Step 3: Initialize HMAC state
    struct libkeccak_hmac_state hmac;
    if (libkeccak_hmac_initialise(&hmac, &sponge, &spec, key, sizeof(key)) < 0) {
        fprintf(stderr, "Failed to initialize HMAC\n");
        libkeccak_state_destroy(&sponge);
        return 1;
    }

    // Step 4: Update with empty message
    if (libkeccak_hmac_update(&hmac, msg, msglen) < 0) {
        fprintf(stderr, "HMAC update failed\n");
        libkeccak_hmac_destroy(&hmac);
        libkeccak_state_destroy(&sponge);
        return 1;
    }

    // Step 5: Finalize
    if (libkeccak_hmac_final(&hmac, digest) < 0) {
        fprintf(stderr, "HMAC final failed\n");
        libkeccak_hmac_destroy(&hmac);
        libkeccak_state_destroy(&sponge);
        return 1;
    }

    // Step 6: Output digest
    printf("HMAC-SHA3-256: ");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // Cleanup
    libkeccak_hmac_destroy(&hmac);
    libkeccak_state_destroy(&sponge);

    return 0;
}
