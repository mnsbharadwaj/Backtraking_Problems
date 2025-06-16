#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libkeccak.h>
#include <libkeccak/keccak.h>
#include <libkeccak/hmac.h>

int main(void) {
    // --- Step 1: Define key and message ---
    unsigned char key[34] = {0};  // 34-byte key of all zeros
    const unsigned char *message = (const unsigned char *)"";  // Empty message
    size_t msg_len = 0;

    // --- Step 2: Prepare SHA3-256 spec ---
    struct libkeccak_spec spec;
    spec.capacity = 512;  // SHA3-256: capacity = 2 × output length
    spec.output = 256;    // Output length in bits

    // --- Step 3: Initialize sponge state ---
    struct libkeccak_state sponge;
    if (libkeccak_state_initialise(&sponge, &spec) != 0) {
        fprintf(stderr, "Error: Failed to initialize Keccak state.\n");
        return 1;
    }

    // --- Step 4: Initialize HMAC state ---
    struct libkeccak_hmac_state hmac;
    if (libkeccak_hmac_initialise(&hmac, &sponge, &spec, key, sizeof(key)) != 0) {
        fprintf(stderr, "Error: Failed to initialize HMAC state.\n");
        libkeccak_state_destroy(&sponge);
        return 1;
    }

    // --- Step 5: Update with message data ---
    if (libkeccak_hmac_update(&hmac, message, msg_len) != 0) {
        fprintf(stderr, "Error: HMAC update failed.\n");
        libkeccak_hmac_destroy(&hmac);
        libkeccak_state_destroy(&sponge);
        return 1;
    }

    // --- Step 6: Finalize HMAC and get digest ---
    unsigned char digest[32];  // 32 bytes for SHA3-256
    if (libkeccak_hmac_final(&hmac, digest) != 0) {
        fprintf(stderr, "Error: HMAC final failed.\n");
        libkeccak_hmac_destroy(&hmac);
        libkeccak_state_destroy(&sponge);
        return 1;
    }

    // --- Step 7: Print digest ---
    printf("HMAC-SHA3-256: ");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // --- Step 8: Cleanup ---
    libkeccak_hmac_destroy(&hmac);
    libkeccak_state_destroy(&sponge);

    return 0;
}
