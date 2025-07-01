#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL includes */
#include <openssl/evp.h>

/* LibTomCrypt includes */
#include <tomcrypt.h>

/* ====== OpenSSL SHAKE ====== */

typedef struct {
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
} openssl_shake_ctx;

int openssl_shake_init(openssl_shake_ctx *sctx, int is_shake128) {
    sctx->ctx = EVP_MD_CTX_new();
    sctx->md = is_shake128 ? EVP_shake128() : EVP_shake256();
    if (!sctx->ctx || !sctx->md) return -1;
    if (EVP_DigestInit_ex(sctx->ctx, sctx->md, NULL) != 1) return -1;
    return 0;
}

int openssl_shake_process(openssl_shake_ctx *sctx, const unsigned char *data, size_t len) {
    if (EVP_DigestUpdate(sctx->ctx, data, len) != 1) return -1;
    return 0;
}

int openssl_shake_done(openssl_shake_ctx *sctx, unsigned char *out, size_t outlen) {
    int ret = EVP_DigestFinalXOF(sctx->ctx, out, outlen) == 1 ? 0 : -1;
    EVP_MD_CTX_free(sctx->ctx);
    return ret;
}

/* ====== OpenSSL cSHAKE using KMAC ====== */

typedef struct {
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
} openssl_cshake_ctx;

int openssl_cshake_init(openssl_cshake_ctx *cctx, int is_cshake128, const char *custom) {
    cctx->mac = EVP_MAC_fetch(NULL, "KMAC", NULL);
    if (!cctx->mac) {
        fprintf(stderr, "KMAC fetch failed\n");
        return -1;
    }

    cctx->ctx = EVP_MAC_CTX_new(cctx->mac);
    if (!cctx->ctx) {
        fprintf(stderr, "KMAC_CTX_new failed\n");
        EVP_MAC_free(cctx->mac);
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", is_cshake128 ? "cshake128" : "cshake256", 0),
        OSSL_PARAM_utf8_string("custom", custom, 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(cctx->ctx, NULL, 0, params) != 1) {
        fprintf(stderr, "KMAC init failed\n");
        EVP_MAC_CTX_free(cctx->ctx);
        EVP_MAC_free(cctx->mac);
        return -1;
    }

    return 0;
}

int openssl_cshake_process(openssl_cshake_ctx *cctx, const unsigned char *data, size_t len) {
    if (EVP_MAC_update(cctx->ctx, data, len) != 1) return -1;
    return 0;
}

int openssl_cshake_done(openssl_cshake_ctx *cctx, unsigned char *out, size_t outlen) {
    size_t outl = 0;
    int ret = EVP_MAC_final(cctx->ctx, out, &outl, outlen) == 1 ? 0 : -1;
    EVP_MAC_CTX_free(cctx->ctx);
    EVP_MAC_free(cctx->mac);
    return ret;
}

/* ====== LibTomCrypt SHA3 ====== */

typedef struct {
    hash_state hs;
    int hash_idx;
} tomcrypt_sha3_ctx;

int tomcrypt_sha3_init(tomcrypt_sha3_ctx *tctx, int sha3_bits) {
    if (sha3_bits == 224)
        tctx->hash_idx = find_hash("sha3-224");
    else if (sha3_bits == 256)
        tctx->hash_idx = find_hash("sha3-256");
    else if (sha3_bits == 384)
        tctx->hash_idx = find_hash("sha3-384");
    else if (sha3_bits == 512)
        tctx->hash_idx = find_hash("sha3-512");
    else
        return -1;
    if (tctx->hash_idx == -1) return -1;
    if (hash_descriptor[tctx->hash_idx].init(&tctx->hs) != CRYPT_OK) return -1;
    return 0;
}

int tomcrypt_sha3_process(tomcrypt_sha3_ctx *tctx, const unsigned char *data, size_t len) {
    if (hash_descriptor[tctx->hash_idx].process(&tctx->hs, data, len) != CRYPT_OK) return -1;
    return 0;
}

int tomcrypt_sha3_done(tomcrypt_sha3_ctx *tctx, unsigned char *out, size_t *outlen) {
    if (hash_descriptor[tctx->hash_idx].done(&tctx->hs, out) != CRYPT_OK) return -1;
    *outlen = hash_descriptor[tctx->hash_idx].hashsize;
    return 0;
}

/* ====== Utility to print in HEX ====== */
void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

/* ====== Main test ====== */
int main() {
    const unsigned char msg1[] = "Hello ";
    const unsigned char msg2[] = "World!";
    unsigned char out[64];
    size_t outlen = sizeof(out);

    /* OpenSSL SHAKE128 test */
    printf("OpenSSL SHAKE128: ");
    openssl_shake_ctx sctx;
    openssl_shake_init(&sctx, 1);
    openssl_shake_process(&sctx, msg1, strlen((char *)msg1));
    openssl_shake_process(&sctx, msg2, strlen((char *)msg2));
    openssl_shake_done(&sctx, out, 32);
    print_hex(out, 32);

    /* OpenSSL cSHAKE128 test */
    printf("OpenSSL cSHAKE128 (\"Cust\"): ");
    openssl_cshake_ctx cctx;
    openssl_cshake_init(&cctx, 1, "Cust");
    openssl_cshake_process(&cctx, msg1, strlen((char *)msg1));
    openssl_cshake_process(&cctx, msg2, strlen((char *)msg2));
    openssl_cshake_done(&cctx, out, 32);
    print_hex(out, 32);

    /* LibTomCrypt SHA3-256 test */
    printf("LibTomCrypt SHA3-256: ");
    register_hash(&sha3_256_desc);
    tomcrypt_sha3_ctx tctx;
    tomcrypt_sha3_init(&tctx, 256);
    tomcrypt_sha3_process(&tctx, msg1, strlen((char *)msg1));
    tomcrypt_sha3_process(&tctx, msg2, strlen((char *)msg2));
    tomcrypt_sha3_done(&tctx, out, &outlen);
    print_hex(out, outlen);

    return 0;
}
