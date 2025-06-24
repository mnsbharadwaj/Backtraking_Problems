#include <tomcrypt.h>
#include <stdio.h>
#include <string.h>

void print_hex(const char *label, const unsigned char *buf, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; ++i) printf("%02x ", buf[i]);
    printf("\n");
}

int main() {
    unsigned char key[32] = {
        0x4c, 0x8e, 0xbf, 0xe1, 0x44, 0x4e, 0xc1, 0xb2,
        0xd5, 0x03, 0xc6, 0x98, 0x66, 0x59, 0xaf, 0x2c,
        0x94, 0xfa, 0xfe, 0x94, 0x5f, 0x72, 0xc1, 0xe8,
        0x48, 0x6a, 0x5a, 0xcf, 0xed, 0xb8, 0xa0, 0xf8
    };

    unsigned char iv[16] = {
        0x47, 0x33, 0x60, 0xe0, 0xad, 0x24, 0x88, 0x99,
        0x59, 0x85, 0x89, 0x95, 0x00, 0x00, 0x00, 0x00
    };

    unsigned char pt[16] = {
        0x77, 0x89, 0xb4, 0x1c, 0xb3, 0xee, 0x54, 0x88,
        0x14, 0xca, 0x0b, 0x38, 0x8c, 0x10, 0xb3, 0x43
    };

    unsigned char ct[64] = {0}, out[64] = {0};
    unsigned char tag[16];
    unsigned long taglen = sizeof(tag);
    int err, idx;

    register_cipher(&aes_desc);
    idx = find_cipher("aes");

    if (idx == -1) {
        printf("AES cipher not found!\n");
        return -1;
    }
    // --- ECB MODE ---

    symmetric_ECB ecb;
    ecb_start(idx, key, 32, 0, &ecb);
    ecb_encrypt(pt, ct, &ecb);
    ecb_decrypt(ct, out, &ecb);
    ecb_done(&ecb);
    print_hex("ECB CT", ct, 16);
    print_hex("ECB PT", out, 16);
    // --- CBC MODE ---

    symmetric_CBC cbc;
    cbc_start(idx, iv, key, 32, 0, &cbc);
    cbc_encrypt(pt, ct, 16, &cbc);
    cbc_decrypt(ct, out, 16, &cbc);
    cbc_done(&cbc);
    print_hex("CBC CT", ct, 16);
    print_hex("CBC PT", out, 16);
    // --- CTR MODE ---

    symmetric_CTR ctr;
    ctr_start(idx, iv, key, 32, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr);
    ctr_encrypt(pt, ct, 16, &ctr);
    ctr_setiv(iv, 16, &ctr); // reset IV for decryption
    ctr_decrypt(ct, out, 16, &ctr);
    ctr_done(&ctr);
    print_hex("CTR CT", ct, 16);
    print_hex("CTR PT", out, 16);
    // --- CFB MODE ---

    symmetric_CFB cfb;
    cfb_start(idx, iv, key, 32, 0, &cfb);
    cfb_encrypt(pt, ct, 16, &cfb);
    cfb_setiv(iv, 16, &cfb);
    cfb_decrypt(ct, out, 16, &cfb);
    cfb_done(&cfb);
    print_hex("CFB CT", ct, 16);
    print_hex("CFB PT", out, 16);
    // --- OFB MODE ---

    symmetric_OFB ofb;
    ofb_start(idx, iv, key, 32, 0, &ofb);
    ofb_encrypt(pt, ct, 16, &ofb);
    ofb_setiv(iv, 16, &ofb);
    ofb_decrypt(ct, out, 16, &ofb);
    ofb_done(&ofb);
    print_hex("OFB CT", ct, 16);
    print_hex("OFB PT", out, 16);
    // --- GCM MODE ---

    gcm_state gcm;
    gcm_init(&gcm, idx, key, 32);
    gcm_add_iv(&gcm, iv, 12);
    gcm_process(&gcm, pt, 16, ct, GCM_ENCRYPT);
    gcm_done(&gcm, tag, &taglen);
    gcm_init(&gcm, idx, key, 32);
    gcm_add_iv(&gcm, iv, 12);
    gcm_process(&gcm, ct, 16, out, GCM_DECRYPT);
    gcm_done(&gcm, tag, &taglen);
    print_hex("GCM CT", ct, 16);
    print_hex("GCM PT", out, 16);
    print_hex("GCM Tag", tag, 16);
    // --- XTS MODE ---

    symmetric_xts xts;
    unsigned char key2[32] = {0};  // second key for XTS
    xts_start(idx, key, key2, 32, &xts);
    xts_encrypt(&xts, pt, ct, 16, 0);
    xts_decrypt(&xts, ct, out, 16, 0);
    xts_done(&xts);
    print_hex("XTS CT", ct, 16);
    print_hex("XTS PT", out, 16);

    return 0;
}
