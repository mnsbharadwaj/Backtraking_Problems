#include <stdio.h>
#include <string.h>
#include <libkeccak.h>

int main() {
    // Step 1: Define 34-byte key (all zero)
    unsigned char key[34] = {0};

    // Step 2: Empty message
    const unsigned char *message = (const unsigned char *)"";
    size_t msglen = 0;

    // Step 3: SHA3-256 digest output (32 bytes)
    unsigned char digest[32];
    size_t digestlen = sizeof(digest);

    // Step 4: Define the Keccak spec for SHA3-256
    struct libkeccak_spec spec;
    spec.capacity = 512;
    spec.output = 256;

    // Step 5: Create HMAC state
    struct libkeccak_hmac_state hmac;

    // Step 6: Initialise HMAC state with spec
    if (libkeccak_hmac_initialise(&hmac, &spec) < 0) {
        fprintf(stderr, "Error: HMAC initialise failed\n");
        return 1;
    }

    // Step 7: Set the HMAC key
    if (libkeccak_hmac_set_key(&hmac, key, sizeof(key)) < 0) {
        fprintf(stderr, "Error: HMAC set key failed\n");
        libkeccak_hmac_destroy(&hmac);
        return 1;
    }

    // Step 8: Feed the message
    if (libkeccak_hmac_update(&hmac, message, msglen) < 0) {
        fprintf(stderr, "Error: HMAC update failed\n");
        libkeccak_hmac_destroy(&hmac);
        return 1;
    }

    // Step 9: Finalize and get digest
    if (libkeccak_hmac_digest(&hmac, &spec, digest, &digestlen) < 0) {
        fprintf(stderr, "Error: HMAC digest failed\n");
        libkeccak_hmac_destroy(&hmac);
        return 1;
    }

    // Step 10: Print the digest
    for (size_t i = 0; i < digestlen; ++i)
        printf("%02x", digest[i]);
    printf("\n");

    // Step 11: Cleanup
    libkeccak_hmac_destroy(&hmac);

    return 0;
}
