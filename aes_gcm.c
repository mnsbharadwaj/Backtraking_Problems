#include <tomcrypt.h>
#include <stdio.h>
#include <string.h>

#define CHUNK_SIZE 16
#define MAX_TOTAL_LEN 512
#define TAG_LEN 16

// --- Shared Context ---
static gcm_state gcm;
static int cipher_idx;
static unsigned long aad_len = 0, data_len = 0, total_len = 0;
static unsigned long offset = 0;
static unsigned long ct_offset = 0;

static unsigned char key[32] = {0};  // AES-256 key
static unsigned char iv[12]  = {0x01, 0x02, 0x03};  // IV

// --- Init for Encryption ---
void gcm_encrypt_init(unsigned long _aad_len, unsigned long _data_len) {
    aad_len = _aad_len;
    data_len = _data_len;
    total_len = aad_len + data_len;
    offset = ct_offset = 0;

    register_cipher(&aes_desc);
    cipher_idx = find_cipher("aes");

    gcm_init(&gcm, cipher_idx, key, sizeof(key));
    gcm_add_iv(&gcm, iv, sizeof(iv));
}

// --- Chunk for Encryption ---
int gcm_encrypt_chunk(const unsigned char *in, int len, unsigned char *out) {
    int written = 0;

    if (offset + len <= aad_len) {
        gcm_add_aad(&gcm, in, len);
    } else if (offset >= aad_len) {
        gcm_process(&gcm, in, len, out, GCM_ENCRYPT);
        written = len;
        ct_offset += len;
    } else {
        int aad_part = aad_len - offset;
        int pt_part = len - aad_part;
        gcm_add_aad(&gcm, in, aad_part);
        gcm_process(&gcm, in + aad_part, pt_part, out, GCM_ENCRYPT);
        written = pt_part;
        ct_offset += pt_part;
    }

    offset += len;
    return written;
}

int gcm_encrypt_finalize(unsigned char *tag, unsigned long *taglen) {
    return gcm_done(&gcm, tag, taglen);
}

// --- Init for Decryption ---
void gcm_decrypt_init(unsigned long _aad_len, unsigned long _data_len) {
    aad_len = _aad_len;
    data_len = _data_len;
    total_len = aad_len + data_len;
    offset = ct_offset = 0;

    register_cipher(&aes_desc);
    cipher_idx = find_cipher("aes");

    gcm_init(&gcm, cipher_idx, key, sizeof(key));
    gcm_add_iv(&gcm, iv, sizeof(iv));
}

// --- Chunk for Decryption ---
int gcm_decrypt_chunk(const unsigned char *in, int len, unsigned char *out) {
    int written = 0;

    if (offset + len <= aad_len) {
        gcm_add_aad(&gcm, in, len);
    } else if (offset >= aad_len) {
        gcm_process(&gcm, in, len, out, GCM_DECRYPT);
        written = len;
        ct_offset += len;
    } else {
        int aad_part = aad_len - offset;
        int pt_part = len - aad_part;
        gcm_add_aad(&gcm, in, aad_part);
        gcm_process(&gcm, in + aad_part, pt_part, out, GCM_DECRYPT);
        written = pt_part;
        ct_offset += pt_part;
    }

    offset += len;
    return written;
}

int gcm_decrypt_finalize(unsigned char *tag, unsigned long *taglen) {
    return gcm_done(&gcm, tag, taglen);
}

// --- Utility ---
void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) printf("%02x ", buf[i]);
    printf("\n");
}

// --- Demo Main ---
int main() {
    unsigned char input_stream[MAX_TOTAL_LEN];
    unsigned char enc_out[MAX_TOTAL_LEN] = {0};
    unsigned char dec_out[MAX_TOTAL_LEN] = {0};
    unsigned char tag[TAG_LEN], tag2[TAG_LEN];
    unsigned long taglen = TAG_LEN;

    // Test case setup
    int aad_len = 91, pt_len = 51;
    int total_len = aad_len + pt_len;

    for (int i = 0; i < aad_len; ++i) input_stream[i] = 0xA0 + i;
    for (int i = 0; i < pt_len; ++i) input_stream[aad_len + i] = 0xB0 + i;

    // Encrypt
    printf("Encrypting...\n");
    gcm_encrypt_init(aad_len, pt_len);
    for (int i = 0; i < total_len; i += CHUNK_SIZE) {
        int len = (i + CHUNK_SIZE <= total_len) ? CHUNK_SIZE : (total_len - i);
        int written = gcm_encrypt_chunk(&input_stream[i], len, &enc_out[i - aad_len]);
    }

    gcm_encrypt_finalize(tag, &taglen);
    print_hex("Ciphertext", enc_out, pt_len);
    print_hex("Tag", tag, taglen);

    // Prepare decryption input (same stream order)
    memcpy(input_stream + aad_len, enc_out, pt_len);

    // Decrypt
    printf("Decrypting...\n");
    gcm_decrypt_init(aad_len, pt_len);
    for (int i = 0; i < total_len; i += CHUNK_SIZE) {
        int len = (i + CHUNK_SIZE <= total_len) ? CHUNK_SIZE : (total_len - i);
        int written = gcm_decrypt_chunk(&input_stream[i], len, &dec_out[i - aad_len]);
    }

    taglen = TAG_LEN;
    if (gcm_decrypt_finalize(tag2, &taglen) == CRYPT_OK && memcmp(tag, tag2, TAG_LEN) == 0) {
        printf("✅ Decryption and tag verified.\n");
        print_hex("Decrypted", dec_out, pt_len);
    } else {
        printf("❌ Tag mismatch. Decryption failed.\n");
    }

    return 0;
}
