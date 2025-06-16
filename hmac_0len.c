#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libkeccak.h>

int main(void) {
    // Step 1: Define key (34 bytes of 0)
    unsigned char key[34] = {0};

    // Step 2: Message is empty
    const unsigned char *msg = (const unsigned char *)"";
    size_t msglen = 0;

    // Step 3: HMAC context
    struct libkeccak_hmac_state hctx;

    // Step 4: Init with SHA3-256
    if (libkeccak_hmac_initialise(&hctx, key, sizeof(key)) < 0) {
        fprintf(stderr, "HMAC init failed\n");
        return 1;
    }

    // Step 5: Process message
    if (libkeccak_hmac_update(&hctx, msg, msglen) < 0) {
        fprintf(stderr, "HMAC update failed\n");
        libkeccak_hmac_destroy(&hctx);
        return 1;
    }

    // Step 6: Finalize
    unsigned char digest[32]; // 256 bits = 32 bytes
    if (libkeccak_hmac_final(&hctx, digest) < 0) {
        fprintf(stderr, "HMAC final failed\n");
        libkeccak_hmac_destroy(&hctx);
        return 1;
    }

    // Step 7: Print output
    printf("HMAC-SHA3-256: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // Step 8: Cleanup
    libkeccak_hmac_destroy(&hctx);
    return 0;
}
