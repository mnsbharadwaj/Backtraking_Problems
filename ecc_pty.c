#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#define LEN 32 // Adjust for field size in bytes (32 for 256-bit)

unsigned char p_mem[LEN]        = {/* SRAM bytes for P */};
unsigned char a_mem[LEN]        = {/* SRAM bytes for A */};
unsigned char b_mem[LEN]        = {/* SRAM bytes for B */};
unsigned char gx_mem[LEN]       = {/* SRAM bytes for Gx */};
unsigned char gy_mem[LEN]       = {/* SRAM bytes for Gy */};
unsigned char order_mem[LEN]    = {/* SRAM bytes for Order */};
unsigned char r2order_mem[LEN]  = {/* SRAM bytes for R2Order */};
unsigned char r2prime_mem[LEN]  = {/* SRAM bytes for R2Prime */};

void handleErrors() { ERR_print_errors_fp(stderr); abort(); }

BIGNUM* bn_from_buf(const unsigned char* buf, size_t len) {
    return BN_bin2bn(buf, len, NULL);
}

// Print EC point (hex)
void print_point(const EC_GROUP* group, const EC_POINT* pt, const char* label, BN_CTX* ctx) {
    BIGNUM *x = BN_new(), *y = BN_new();
    if (EC_POINT_is_at_infinity(group, pt)) { printf("%s: infinity\n", label); }
    else if (EC_POINT_get_affine_coordinates_GFp(group, pt, x, y, ctx)) {
        char *xs = BN_bn2hex(x), *ys = BN_bn2hex(y);
        printf("%s: X=%s\n   Y=%s\n", label, xs, ys);
        OPENSSL_free(xs); OPENSSL_free(ys);
    }
    BN_free(x); BN_free(y);
}

// ECC OPERATION HELPERS
void ecc_add(const EC_GROUP* group, EC_POINT* r, const EC_POINT* a, const EC_POINT* b, BN_CTX* ctx) {
    if (!EC_POINT_add(group, r, a, b, ctx)) handleErrors();
}
void ecc_double(const EC_GROUP* group, EC_POINT* r, const EC_POINT* a, BN_CTX* ctx) {
    if (!EC_POINT_dbl(group, r, a, ctx)) handleErrors();
}
void ecc_mul(const EC_GROUP* group, EC_POINT* r, const BIGNUM *k, const EC_POINT* a, BN_CTX* ctx) {
    if (!EC_POINT_mul(group, r, NULL, a, k, ctx)) handleErrors();
}
void ecc_neg(const EC_GROUP* group, EC_POINT* r, const EC_POINT* a, BN_CTX* ctx) {
    if (!EC_POINT_copy(r, a) || !EC_POINT_invert(group, r, ctx)) handleErrors();
}
void ecc_sub(const EC_GROUP* group, EC_POINT* r, const EC_POINT* a, const EC_POINT* b, BN_CTX* ctx) {
    EC_POINT* negb = EC_POINT_new(group);
    ecc_neg(group, negb, b, ctx);
    ecc_add(group, r, a, negb, ctx);
    EC_POINT_free(negb);
}
// BIGNUM/MONTGOMERY OPERATION HELPERS
void mod_add(BIGNUM* r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX* ctx) {
    if (!BN_mod_add(r, a, b, m, ctx)) handleErrors();
}
void mod_sub(BIGNUM* r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX* ctx) {
    if (!BN_mod_sub(r, a, b, m, ctx)) handleErrors();
}
void mont_mul(BIGNUM* r, const BIGNUM *a, const BIGNUM *b, BN_MONT_CTX* mont, BN_CTX* ctx) {
    BIGNUM *am = BN_new(), *bm = BN_new(), *rm = BN_new();
    BN_to_montgomery(am, a, mont, ctx);
    BN_to_montgomery(bm, b, mont, ctx);
    BN_mod_mul_montgomery(rm, am, bm, mont, ctx);
    BN_from_montgomery(r, rm, mont, ctx);
    BN_free(am); BN_free(bm); BN_free(rm);
}
void mont_exp(BIGNUM* r, const BIGNUM *a, const BIGNUM *e, const BIGNUM *m, BN_MONT_CTX* mont, BN_CTX* ctx) {
    if(!BN_mod_exp_mont(r, a, e, m, ctx, mont)) handleErrors();
}

int main() {
    ERR_load_crypto_strings();
    BN_CTX *ctx = BN_CTX_new();
    // Load curve and field params from memory
    BIGNUM *p = bn_from_buf(p_mem, LEN), *a = bn_from_buf(a_mem, LEN), *b = bn_from_buf(b_mem, LEN);
    BIGNUM *gx=bn_from_buf(gx_mem, LEN), *gy=bn_from_buf(gy_mem, LEN), *order=bn_from_buf(order_mem, LEN);
    BIGNUM *r2order = bn_from_buf(r2order_mem, LEN), *r2prime = bn_from_buf(r2prime_mem, LEN);

    EC_GROUP* group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
    EC_POINT* G = EC_POINT_new(group); // Generator
    if (!EC_POINT_set_affine_coordinates_GFp(group, G, gx, gy, ctx)) handleErrors();
    if (!EC_GROUP_set_generator(group, G, order, BN_value_one())) handleErrors();

    // -- ECC Operations Demo --
    printf("== ECC Operations ==\n");
    BIGNUM *k = BN_new(); BN_set_word(k, 3);

    EC_POINT *P = EC_POINT_dup(G, group);   // Use G itself for tests
    EC_POINT *Q = EC_POINT_new(group), *R = EC_POINT_new(group);

    // Scalar multiplication Q = k*P
    ecc_mul(group, Q, k, P, ctx);
    print_point(group, Q, "Q = 3*G", ctx);

    // Addition: R = P + Q
    ecc_add(group, R, P, Q, ctx); print_point(group, R, "P + Q", ctx);

    // Doubling: R = 2*P
    ecc_double(group, R, P, ctx); print_point(group, R, "2*P", ctx);

    // Negate: Q = -Q
    ecc_neg(group, Q, Q, ctx); print_point(group, Q, "-Q", ctx);

    // Subtract: R = P - Q
    ecc_sub(group, R, P, Q, ctx); print_point(group, R, "P - Q", ctx);

    // -- Montgomery Modular Operations Demo --
    printf("\n== Montgomery Modular Arithmetic ==\n");
    BN_MONT_CTX *mont = BN_MONT_CTX_new(); BN_MONT_CTX_set(mont, p, ctx);

    BIGNUM *x = BN_new(), *y = BN_new(), *z = BN_new();
    BN_hex2bn(&x, "1234"); BN_hex2bn(&y, "5678");

    // Addition
    mod_add(z, x, y, p, ctx);
    printf("x + y mod p = "); BN_print_fp(stdout, z); printf("\n");
    // Subtraction
    mod_sub(z, x, y, p, ctx);
    printf("x - y mod p = "); BN_print_fp(stdout, z); printf("\n");
    // Montgomery multiplication
    mont_mul(z, x, y, mont, ctx);
    printf("x * y mod p = "); BN_print_fp(stdout, z); printf("\n");
    // Exponentiation
    BN_set_word(y, 10);
    mont_exp(z, x, y, p, mont, ctx);
    printf("x^10 mod p = "); BN_print_fp(stdout, z); printf("\n");

    // Clean up
    EC_POINT_free(P); EC_POINT_free(Q); EC_POINT_free(R); EC_POINT_free(G);
    EC_GROUP_free(group);
    BN_free(p); BN_free(a); BN_free(b); BN_free(gx); BN_free(gy); BN_free(order);
    BN_free(k); BN_free(r2order); BN_free(r2prime); BN_free(x); BN_free(y); BN_free(z);
    BN_MONT_CTX_free(mont); BN_CTX_free(ctx); ERR_free_strings();
    return 0;
}
