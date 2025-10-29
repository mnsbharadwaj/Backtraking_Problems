#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>

// ========== PARAMETERS AREA ==========
// Example SRAM pointers (replace contents with your memory-mapped values)
#define LEN 32 // 256-bit fields, adjust for your curve

unsigned char p_mem[LEN]    = {/* bytes of modulus p */};
unsigned char a_mem[LEN]    = {/* bytes of param a */};
unsigned char b_mem[LEN]    = {/* bytes of param b */};
unsigned char gx_mem[LEN]   = {/* bytes of Gx */};
unsigned char gy_mem[LEN]   = {/* bytes of Gy */};
unsigned char order_mem[LEN]= {/* bytes of order */};

// ========== UTILS ==========
void handleErrors() { ERR_print_errors_fp(stderr); abort(); }
BIGNUM* bn_from_buf(const unsigned char* buf, size_t len) { return BN_bin2bn(buf, len, NULL); }

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

// ========== MONTGOMERY CONSTANT CALCULATION ==========
/*
  Computes R = 2^(chunksize + precision) mod m.
  Useful for custom Montgomery setup (e.g., firmware).
*/
int compute_montgomery_R(BIGNUM *result, int chunksize, int precision, const BIGNUM *mod, BN_CTX *ctx) {
    BIGNUM *exp = BN_new();
    BIGNUM *two = BN_new();
    if (!exp || !two) return 0;
    if (!BN_set_word(exp, chunksize + precision)) goto err;
    if (!BN_set_word(two, 2)) goto err;
    if (!BN_mod_exp(result, two, exp, mod, ctx)) goto err;
    BN_free(exp); BN_free(two); return 1;
err:
    BN_free(exp); BN_free(two); return 0;
}

// ========== ECC OPERATIONS ==========
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

// ========== FIELD AND MONT OPERATIONS ==========
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

// ========== MAIN TEST ==========
int main() {
    ERR_load_crypto_strings();
    BN_CTX *ctx = BN_CTX_new();

    // Curve construction from SRAM/flash/ROM/mem pointers
    BIGNUM *p=bn_from_buf(p_mem, LEN), *a=bn_from_buf(a_mem, LEN), *b=bn_from_buf(b_mem, LEN);
    BIGNUM *gx=bn_from_buf(gx_mem, LEN), *gy=bn_from_buf(gy_mem, LEN), *order=bn_from_buf(order_mem, LEN);

    EC_GROUP* group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
    EC_POINT* G = EC_POINT_new(group);
    if (!EC_POINT_set_affine_coordinates_GFp(group, G, gx, gy, ctx)) handleErrors();
    if (!EC_GROUP_set_generator(group, G, order, BN_value_one())) handleErrors();

    printf("Curve loaded. Montgomery constant calculation:\n");
    
    BIGNUM *R = BN_new();
    int fieldbits = LEN * 8;
    int precision = 32;
    if (!compute_montgomery_R(R, fieldbits, precision, p, ctx)) handleErrors();
    char *r_str = BN_bn2hex(R);
    printf("Montgomery R = %s\n", r_str); OPENSSL_free(r_str);

    BN_MONT_CTX *mont = BN_MONT_CTX_new(); BN_MONT_CTX_set(mont, p, ctx);

    // ECC ops: Scalar multiplication, add, double, sub
    BIGNUM *k = BN_new(); BN_set_word(k, 3);
    EC_POINT *P = EC_POINT_dup(G, group);   // use G for demo
    EC_POINT *Q = EC_POINT_new(group), *Rpt = EC_POINT_new(group);

    ecc_mul(group, Q, k, P, ctx); print_point(group, Q, "3*G", ctx);
    ecc_add(group, Rpt, P, Q, ctx); print_point(group, Rpt, "G + 3G", ctx);
    ecc_double(group, Rpt, P, ctx); print_point(group, Rpt, "2*G", ctx);
    ecc_neg(group, Q, Q, ctx); print_point(group, Q, "-3G", ctx);
    ecc_sub(group, Rpt, P, Q, ctx); print_point(group, Rpt, "G - 3G", ctx);

    // Field/mont ops demo
    BIGNUM *x = BN_new(), *y = BN_new(), *z = BN_new();
    BN_hex2bn(&x, "1234"); BN_hex2bn(&y, "5678");

    mod_add(z, x, y, p, ctx); printf("Field add: "); BN_print_fp(stdout, z); printf("\n");
    mod_sub(z, x, y, p, ctx); printf("Field sub: "); BN_print_fp(stdout, z); printf("\n");
    mont_mul(z, x, y, mont, ctx); printf("Mont mul: "); BN_print_fp(stdout, z); printf("\n");
    BN_set_word(y, 10); mont_exp(z, x, y, p, mont, ctx); printf("Mont exp: "); BN_print_fp(stdout, z); printf("\n");

    // Clean up
    EC_POINT_free(P); EC_POINT_free(Q); EC_POINT_free(Rpt); EC_POINT_free(G);
    EC_GROUP_free(group);
    BN_free(p); BN_free(a); BN_free(b); BN_free(gx); BN_free(gy); BN_free(order); BN_free(R); BN_free(k); BN_free(x); BN_free(y); BN_free(z);
    BN_MONT_CTX_free(mont); BN_CTX_free(ctx); ERR_free_strings();
    return 0;
}
