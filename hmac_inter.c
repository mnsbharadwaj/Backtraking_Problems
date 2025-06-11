#include <tomcrypt.h>
#include <stdio.h>

int main() {
    const char *hash_name = "sha3-384";
    int hash_id = find_hash(hash_name);
    if (hash_id == -1) {
        printf("Hash not found\n");
        return 1;
    }

    unsigned char key[64] = {0};               // Example key
    unsigned char intermediate[200] = {1};     // Example 200-byte part
    unsigned char rest_data[100] = {2};        // Example final part

    unsigned char hmac_result[64];
    unsigned long outlen = sizeof(hmac_result);

    hmac_state hmac;
    int err;

    if ((err = hmac_init(&hmac, hash_id, key, sizeof(key))) != CRYPT_OK) {
        printf("Init error: %s\n", error_to_string(err));
        return 1;
    }

    if ((err = hmac_process(&hmac, intermediate, 200)) != CRYPT_OK) {
        printf("Process 1 error: %s\n", error_to_string(err));
        return 1;
    }

    if ((err = hmac_process(&hmac, rest_data, sizeof(rest_data))) != CRYPT_OK) {
        printf("Process 2 error: %s\n", error_to_string(err));
        return 1;
    }

    if ((err = hmac_done(&hmac, hmac_result, &outlen)) != CRYPT_OK) {
        printf("Done error: %s\n", error_to_string(err));
        return 1;
    }

    printf("HMAC-SHA3-384: ");
    for (unsigned int i = 0; i < outlen; i++) {
        printf("%02x", hmac_result[i]);
    }
    printf("\n");

    return 0;
}
