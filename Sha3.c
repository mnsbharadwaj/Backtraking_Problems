/*
 * sha3_tomcrypt_examples.c
 *
 * Compile: link with libtomcrypt (and include headers)
 *   e.g.: gcc sha3_tomcrypt_examples.c -o sha3_example -ltomcrypt
 *
 * Requires libtomcrypt with SHA3 (LTC_SHA3) and HMAC enabled.
 *
 * References: libtomcrypt docs & headers (sha3/hmac APIs).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>

/* ----- Small helpers ----- */

static void print_hex(const unsigned char *buf, unsigned long len)
{
    for (unsigned long i = 0; i < len; i++) printf("%02x", buf[i]);
    putchar('\n');
}

/* ----- Generic SHA3 init/update/done wrappers ----- */

/* bits must be one of: 224, 256, 384, 512 */
int sha3_init_bits(sha3_state *st, int bits)
{
    if (st == NULL) return CRYPT_INVALID_ARG;
    /* Under libtomcrypt: sha3_init(sha3_state *state, int bitlen) */
    return sha3_init(st, bits);
}

int sha3_update(sha3_state *st, const unsigned char *in, unsigned long inlen)
{
    if (st == NULL) return CRYPT_INVALID_ARG;
    return sha3_process(st, in, inlen);
}

int sha3_done_wrap(sha3_state *st, unsigned char *out, unsigned long *outlen)
{
    if (st == NULL) return CRYPT_INVALID_ARG;
    return sha3_done(st, out, outlen);
}

/* One-shot convenience */
int sha3_hash_one_shot(int bits,
                       const unsigned char *in, unsigned long inlen,
                       unsigned char *out, unsigned long *outlen)
{
    sha3_state st;
    int err;

    if ((err = sha3_init_bits(&st, bits)) != CRYPT_OK) return err;
    if ((err = sha3_update(&st, in, inlen)) != CRYPT_OK) return err;
    return sha3_done_wrap(&st, out, outlen);
}

/* ----- HMAC using chosen SHA3 variant ----- */
/* `bits` like 256 -> use "sha3-256" hash name via find_hash */
int hmac_sha3_one_shot(int bits,
                       const unsigned char *key, unsigned long keylen,
                       const unsigned char *in, unsigned long inlen,
                       unsigned char *out, unsigned long *outlen)
{
    hmac_state hmac;
    int hash_idx;
    int err;
    char hashname[32];

    snprintf(hashname, sizeof(hashname), "sha3-%d", bits); /* "sha3-256" etc. */
    hash_idx = find_hash(hashname);
    if (hash_idx == -1) return CRYPT_INVALID_HASH;

    if ((err = hmac_init(&hmac, hash_idx, key, keylen)) != CRYPT_OK) return err;
    if ((err = hmac_process(&hmac, in, inlen)) != CRYPT_OK) return err;
    return hmac_done(&hmac, out, outlen);
}

/* ----- Export / import the raw 200-byte internal Keccak state ----- */
/*
 * Many advanced uses want to snapshot or load the raw 1600-bit Keccak state.
 * In libtomcrypt's sha3_state the internal state array is 200 bytes (25 lanes * 8).
 * Here we provide helpers to export/import that 200-byte array.
 *
 * WARNING: Depending on libtomcrypt version/ABI the sha3_state struct field names
 * may differ; common fields are: s[] (200 bytes), md_len (digest bits/8), pt, rsiz.
 * We operate on s[] directly and set other fields to sensible values.
 */

/* Export the 200-byte raw lane state into user buffer (must be >=200). */
int sha3_export_raw_state(sha3_state *st, unsigned char *out_buf, unsigned long out_buf_len)
{
    if (!st || !out_buf) return CRYPT_INVALID_ARG;
    if (out_buf_len < 200) return CRYPT_BUFFER_OVERFLOW;

    /* st->s is the internal 200 byte state in most libtomcrypt versions */
    memcpy(out_buf, st->s, 200);
    return CRYPT_OK;
}

/* Import the 200-byte raw lane state from user buffer into sha3_state.
 * After importing raw state, user must set md_len to desired digest length in bits,
 * and set rsiz and pt to correct values for continuing hashing.
 *
 * This helper sets:
 *   st->md_len = bits (digest bits)
 *   st->rsiz   = 200 - 2*(bits/8)   (the SHA-3 defined rate)
 *   st->pt     = 0 (assume block boundary; adapt if you have partial buffered bytes)
 */
int sha3_import_raw_state(sha3_state *st, const unsigned char *in_buf, unsigned long in_buf_len, int bits)
{
    if (!st || !in_buf) return CRYPT_INVALID_ARG;
    if (in_buf_len < 200) return CRYPT_INVALID_ARG;

    memcpy(st->s, in_buf, 200);

    /* set md_len (bits) and rate size (rsiz) and pt */
    st->md_len = bits; /* libtomcrypt stores requested digest length in bits here */
    /* compute rate in bytes for SHA-3: r = b - c ; c = 2*d where d is digest length in bytes */
    unsigned long d_bytes = bits / 8;
    st->rsiz = 200 - 2 * d_bytes;
    st->pt = 0; /* assuming we are at block boundary; adjust if necessary */

    return CRYPT_OK;
}

/* ----- Demo / test harness ----- */

int main(void)
{
    const unsigned char msg[] = "The quick brown fox jumps over the lazy dog";
    unsigned char out[64];
    unsigned long outlen;
    int err;

    /* SHA3 variants */
    int sha3_bits[] = {224, 256, 384, 512};
    for (size_t i = 0; i < sizeof(sha3_bits)/sizeof(sha3_bits[0]); i++) {
        int bits = sha3_bits[i];
        outlen = (unsigned long)(bits / 8);
        err = sha3_hash_one_shot(bits, msg, sizeof(msg)-1, out, &outlen);
        if (err == CRYPT_OK) {
            printf("SHA3-%d: ", bits);
            print_hex(out, outlen);
        } else {
            printf("SHA3-%d error: %d\n", bits, err);
        }
    }

    /* HMAC-SHA3-256 example */
    const unsigned char key[] = "secretkey";
    outlen = 64;
    err = hmac_sha3_one_shot(256, key, sizeof(key)-1, msg, sizeof(msg)-1, out, &outlen);
    if (err == CRYPT_OK) {
        printf("HMAC-SHA3-256: ");
        print_hex(out, outlen);
    } else {
        printf("HMAC error: %d\n", err);
    }

    /* Demonstrate export/import raw 200 byte internal state:
     * - do init/update
     * - export raw state
     * - create new sha3_state and import raw state then finish
     */
    {
        sha3_state st;
        unsigned char raw_state[200];
        unsigned long final_len;
        int bits = 256;

        /* init and process some data, but not finish */
        if ((err = sha3_init_bits(&st, bits)) != CRYPT_OK) { printf("init err %d\n", err); return 1; }
        if ((err = sha3_update(&st, msg, 16)) != CRYPT_OK) { printf("proc err %d\n", err); return 1; }

        /* export the raw 200 byte lane state */
        if ((err = sha3_export_raw_state(&st, raw_state, sizeof(raw_state))) != CRYPT_OK) {
            printf("export err %d\n", err);
            return 1;
        }
        printf("Exported raw 200-byte Keccak state (first 16 bytes): ");
        print_hex(raw_state, 16);

        /* Create new state and import */
        sha3_state st2;
        if ((err = sha3_import_raw_state(&st2, raw_state, sizeof(raw_state), bits)) != CRYPT_OK) {
            printf("import err %d\n", err);
            return 1;
        }

        /* Continue hashing (e.g., process more data) or finalize */
        if ((err = sha3_update(&st2, msg+16, sizeof(msg)-1-16)) != CRYPT_OK) { printf("proc2 err %d\n", err); return 1; }

        final_len = bits / 8;
        if ((err = sha3_done_wrap(&st2, out, &final_len)) != CRYPT_OK) {
            printf("done err %d\n", err);
            return 1;
        }
        printf("SHA3-%d after import+finish: ", bits);
        print_hex(out, final_len);
    }

    return 0;
}
