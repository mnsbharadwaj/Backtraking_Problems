/*
 * OpenSSL BN–based ECC with a memory-mapped "device" interface.
 *
 * Features:
 *  - Field ops: add, sub, mul, div, exp  (mod p)
 *  - Point ops: point_add, point_double, scalar_mul (affine, short-Weierstrass)
 *  - Driver that reads operands from byte buffers, converts to BIGNUM, runs op,
 *    and writes the result back to byte buffers.
 *
 * Curve used in demo: secp256k1
 *
 * Build:
 *   sudo apt-get install -y libssl-dev
 *   gcc ecc_mmio_openssl.c -lcrypto -O3 -Wall -Wextra -o ecc_demo
 * Run:
 *   ./ecc_demo
 */

#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*==========================
  ECC field/curve context
==========================*/
typedef struct {
    BN_CTX     *ctx;    /* scratch space */
    BIGNUM     *p;      /* field prime */
    BIGNUM     *a;      /* curve parameter a */
    BIGNUM     *b;      /* curve parameter b */
    BN_MONT_CTX *mont;  /* Montgomery context for p */
} ECC_CTX;

static void ecc_ctx_init(ECC_CTX *ec,
                         const char *p_hex,
                         const char *a_hex,
                         const char *b_hex)
{
    ec->ctx  = BN_CTX_new();
    BN_CTX_start(ec->ctx);

    ec->p = BN_new();
    ec->a = BN_new();
    ec->b = BN_new();

    BN_hex2bn(&ec->p, p_hex);
    BN_hex2bn(&ec->a, a_hex);
    BN_hex2bn(&ec->b, b_hex);

    ec->mont = BN_MONT_CTX_new();
    BN_MONT_CTX_set(ec->mont, ec->p, ec->ctx);
}

static void ecc_ctx_free(ECC_CTX *ec)
{
    BN_MONT_CTX_free(ec->mont);
    BN_free(ec->p);
    BN_free(ec->a);
    BN_free(ec->b);
    BN_CTX_end(ec->ctx);
    BN_CTX_free(ec->ctx);
}

/*==========================
  Point (affine) structure
==========================*/
typedef struct {
    BIGNUM *x;
    BIGNUM *y;
    int     infinity;   /* 1 if point at infinity */
} EC_POINT_AFFINE;

static void ec_point_init(EC_POINT_AFFINE *P) {
    P->x = BN_new(); P->y = BN_new(); P->infinity = 1;
}
static void ec_point_free(EC_POINT_AFFINE *P) {
    BN_free(P->x); BN_free(P->y);
}
static void ec_point_set_xy(EC_POINT_AFFINE *P, const BIGNUM *x, const BIGNUM *y) {
    BN_copy(P->x, x); BN_copy(P->y, y); P->infinity = 0;
}
static void ec_point_copy(EC_POINT_AFFINE *R, const EC_POINT_AFFINE *P) {
    BN_copy(R->x, P->x); BN_copy(R->y, P->y); R->infinity = P->infinity;
}

/*==========================
  Field (mod p) API (BN)
==========================*/
static void ecc_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const ECC_CTX *ec) {
    BN_mod_add(r, a, b, ec->p, ec->ctx);
}
static void ecc_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const ECC_CTX *ec) {
    BN_mod_sub(r, a, b, ec->p, ec->ctx);
}
static void ecc_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const ECC_CTX *ec) {
    BN_mod_mul(r, a, b, ec->p, ec->ctx);
}
static void ecc_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const ECC_CTX *ec) {
    BIGNUM *binv = BN_new();
    BN_mod_inverse(binv, b, ec->p, ec->ctx);
    BN_mod_mul(r, a, binv, ec->p, ec->ctx);
    BN_free(binv);
}
static void ecc_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, const ECC_CTX *ec) {
    BN_mod_exp_mont(r, a, e, ec->p, ec->ctx, ec->mont);
}

/*==========================
  Point (affine) API
==========================*/

/* R = P + Q */
static void ec_point_add(EC_POINT_AFFINE *R,
                         const EC_POINT_AFFINE *P,
                         const EC_POINT_AFFINE *Q,
                         const ECC_CTX *ec)
{
    if (P->infinity) { ec_point_copy(R, Q); return; }
    if (Q->infinity) { ec_point_copy(R, P); return; }

    BN_CTX *ctx = ec->ctx;
    BN_CTX_start(ctx);
    BIGNUM *lambda = BN_CTX_get(ctx);
    BIGNUM *num    = BN_CTX_get(ctx);
    BIGNUM *den    = BN_CTX_get(ctx);
    BIGNUM *tmp    = BN_CTX_get(ctx);
    BIGNUM *negQy  = BN_CTX_get(ctx);

    /* x1 == x2 and y1 == -y2 -> infinity */
    if (BN_cmp(P->x, Q->x) == 0) {
        BN_mod_sub(negQy, ec->p, Q->y, ec->p, ctx);
        if (BN_cmp(P->y, negQy) == 0) {
            R->infinity = 1;
            BN_CTX_end(ctx);
            return;
        }
        /* If P == Q, doubling will be equivalent; fall through */
    }

    /* lambda = (y2 - y1) / (x2 - x1) mod p */
    BN_mod_sub(num, Q->y, P->y, ec->p, ctx);
    BN_mod_sub(den, Q->x, P->x, ec->p, ctx);
    BN_mod_inverse(den, den, ec->p, ctx);
    BN_mod_mul(lambda, num, den, ec->p, ctx);

    /* x3 = lambda^2 - x1 - x2 */
    BN_mod_sqr(R->x, lambda, ec->p, ctx);
    BN_mod_sub(R->x, R->x, P->x, ec->p, ctx);
    BN_mod_sub(R->x, R->x, Q->x, ec->p, ctx);

    /* y3 = lambda*(x1 - x3) - y1 */
    BN_mod_sub(tmp, P->x, R->x, ec->p, ctx);
    BN_mod_mul(tmp, lambda, tmp, ec->p, ctx);
    BN_mod_sub(R->y, tmp, P->y, ec->p, ctx);

    R->infinity = 0;
    BN_CTX_end(ctx);
}

/* R = 2P */
static void ec_point_double(EC_POINT_AFFINE *R,
                            const EC_POINT_AFFINE *P,
                            const ECC_CTX *ec)
{
    if (P->infinity) { ec_point_copy(R, P); return; }
    if (BN_is_zero(P->y)) { R->infinity = 1; return; }

    BN_CTX *ctx = ec->ctx;
    BN_CTX_start(ctx);
    BIGNUM *lambda = BN_CTX_get(ctx);
    BIGNUM *num    = BN_CTX_get(ctx);
    BIGNUM *den    = BN_CTX_get(ctx);
    BIGNUM *tmp    = BN_CTX_get(ctx);

    /* lambda = (3x^2 + a) / (2y) mod p */
    BN_mod_sqr(num, P->x, ec->p, ctx);   /* x^2 */
    BN_mul_word(num, 3);                 /* 3x^2 */
    BN_mod_add(num, num, ec->a, ec->p, ctx); /* + a */

    BN_mod_lshift1_quick(den, P->y, ec->p);  /* den = 2*y mod p */
    BN_mod_inverse(den, den, ec->p, ctx);
    BN_mod_mul(lambda, num, den, ec->p, ctx);

    /* x3 = lambda^2 - 2x1 */
    BN_mod_sqr(R->x, lambda, ec->p, ctx);
    BN_mod_sub(R->x, R->x, P->x, ec->p, ctx);
    BN_mod_sub(R->x, R->x, P->x, ec->p, ctx);

    /* y3 = lambda*(x1 - x3) - y1 */
    BN_mod_sub(tmp, P->x, R->x, ec->p, ctx);
    BN_mod_mul(tmp, lambda, tmp, ec->p, ctx);
    BN_mod_sub(R->y, tmp, P->y, ec->p, ctx);

    R->infinity = 0;
    BN_CTX_end(ctx);
}

/* R = k * P (simple left-to-right double-and-add) */
static void ec_scalar_mul(EC_POINT_AFFINE *R,
                          const BIGNUM *k,
                          const EC_POINT_AFFINE *P,
                          const ECC_CTX *ec)
{
    EC_POINT_AFFINE Q, N; ec_point_init(&Q); ec_point_init(&N);
    Q.infinity = 1;              /* Q = O (infinity) */
    ec_point_copy(&N, P);

    int bits = BN_num_bits(k);
    for (int i = bits - 1; i >= 0; --i) {
        ec_point_double(&Q, &Q, ec);
        if (BN_is_bit_set(k, i)) {
            ec_point_add(&Q, &Q, &N, ec);
        }
    }
    ec_point_copy(R, &Q);
    ec_point_free(&Q); ec_point_free(&N);
}

/*==========================
  Memory <-> BIGNUM helpers
==========================*/

/* Read little-endian or big-endian buffer into BIGNUM */
static BIGNUM* mem_to_bn(const uint8_t *mem, size_t len, int little_endian)
{
    if (little_endian) return BN_lebin2bn(mem, (int)len, NULL);
    return BN_bin2bn(mem, (int)len, NULL);
}

/* Write BIGNUM into buffer (fixed len), LE or BE */
static void bn_to_mem(const BIGNUM *bn, uint8_t *mem, size_t len, int little_endian)
{
    /* BN_bn2binpad writes big-endian; we may flip for LE */
    uint8_t tmp[512];
    if (len > sizeof(tmp)) len = sizeof(tmp);
    memset(tmp, 0, sizeof(tmp));
    BN_bn2binpad(bn, tmp, (int)len);
    if (little_endian) {
        for (size_t i = 0; i < len; ++i) mem[i] = tmp[len - 1 - i];
    } else {
        memcpy(mem, tmp, len);
    }
}

/*==========================
  MMIO-like Device Layout
==========================*/

enum {
    OP_FIELD_ADD = 1,
    OP_FIELD_SUB,
    OP_FIELD_MUL,
    OP_FIELD_DIV,
    OP_FIELD_EXP,
    OP_POINT_ADD,
    OP_POINT_DOUBLE,
    OP_SCALAR_MUL
};

typedef struct {
    /* Field operand registers (32-byte each for 256-bit curves) */
    uint8_t A[32], B[32], E[32];  /* inputs */
    uint8_t RES[32];              /* result */

    /* Point operand registers (affine X,Y) */
    uint8_t PX[32], PY[32];  /* P */
    uint8_t QX[32], QY[32];  /* Q */
    uint8_t RX[32], RY[32];  /* output R */
    uint8_t P_INF, Q_INF;    /* 1 if point at infinity; else 0 */

    /* Scalar k (for scalar mul) */
    uint8_t K[32];

    /* Opcode register */
    uint32_t OPCODE;

    /* Endianness flag for memory registers (1=LE, 0=BE) */
    int little_endian;
} ecc_device;

/* Execute ECC operation based on device->OPCODE */
static void ecc_dev_execute(ecc_device *dev, const ECC_CTX *ec)
{
    /* Common temporaries */
    BIGNUM *a=NULL, *b=NULL, *e=NULL, *r=NULL;

    switch (dev->OPCODE) {

    case OP_FIELD_ADD:
    case OP_FIELD_SUB:
    case OP_FIELD_MUL:
    case OP_FIELD_DIV:
    case OP_FIELD_EXP:
        a = mem_to_bn(dev->A, sizeof(dev->A), dev->little_endian);
        b = mem_to_bn(dev->B, sizeof(dev->B), dev->little_endian);
        r = BN_new();

        if (dev->OPCODE == OP_FIELD_ADD)      ecc_add(r, a, b, ec);
        else if (dev->OPCODE == OP_FIELD_SUB) ecc_sub(r, a, b, ec);
        else if (dev->OPCODE == OP_FIELD_MUL) ecc_mul(r, a, b, ec);
        else if (dev->OPCODE == OP_FIELD_DIV) ecc_div(r, a, b, ec);
        else {
            /* EXP: uses E as exponent */
            BN_free(b); b = NULL;
            e = mem_to_bn(dev->E, sizeof(dev->E), dev->little_endian);
            ecc_exp(r, a, e, ec);
            BN_free(e);
        }

        bn_to_mem(r, dev->RES, sizeof(dev->RES), dev->little_endian);
        BN_free(a); if (b) BN_free(b); BN_free(r);
        break;

    case OP_POINT_ADD:
    case OP_POINT_DOUBLE:
    case OP_SCALAR_MUL: {
        /* Load points/scalar */
        EC_POINT_AFFINE P, Q, Rpt; ec_point_init(&P); ec_point_init(&Q); ec_point_init(&Rpt);
        BIGNUM *px = mem_to_bn(dev->PX, 32, dev->little_endian);
        BIGNUM *py = mem_to_bn(dev->PY, 32, dev->little_endian);
        BIGNUM *qx = mem_to_bn(dev->QX, 32, dev->little_endian);
        BIGNUM *qy = mem_to_bn(dev->QY, 32, dev->little_endian);
        if (!dev->P_INF) ec_point_set_xy(&P, px, py); else P.infinity = 1;
        if (!dev->Q_INF) ec_point_set_xy(&Q, qx, qy); else Q.infinity = 1;

        if (dev->OPCODE == OP_POINT_ADD) {
            ec_point_add(&Rpt, &P, &Q, ec);
        } else if (dev->OPCODE == OP_POINT_DOUBLE) {
            ec_point_double(&Rpt, &P, ec);
        } else { /* SCALAR_MUL uses P and K; write result to RX/RY */
            BIGNUM *k = mem_to_bn(dev->K, 32, dev->little_endian);
            ec_scalar_mul(&Rpt, k, &P, ec);
            BN_free(k);
        }

        if (Rpt.infinity) {
            memset(dev->RX, 0, 32);
            memset(dev->RY, 0, 32);
        } else {
            bn_to_mem(Rpt.x, dev->RX, 32, dev->little_endian);
            bn_to_mem(Rpt.y, dev->RY, 32, dev->little_endian);
        }

        BN_free(px); BN_free(py); BN_free(qx); BN_free(qy);
        ec_point_free(&P); ec_point_free(&Q); ec_point_free(&Rpt);
        break;
    }

    default:
        /* no-op / invalid opcode */
        break;
    }
}

/*==========================
  Small demo / driver
==========================*/

static void dump_be_hex(const char *label, const uint8_t *buf, size_t n)
{
    printf("%s = 0x", label);
    for (size_t i = 0; i < n; ++i) printf("%02X", buf[i]);
    printf("\n");
}

int main(void)
{
    /* ---- Curve: secp256k1 ----
       p = 2^256 - 2^32 - 977
       a = 0
       b = 7
       Gx = 79BE667E...F81798
       Gy = 483ADA77...B10D4B8
    */
    const char *p_hex =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    const char *a_hex =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const char *b_hex =
        "0000000000000000000000000000000000000000000000000000000000000007";

    ECC_CTX ec; ecc_ctx_init(&ec, p_hex, a_hex, b_hex);

    /* Base point G */
    BIGNUM *Gx = BN_new(), *Gy = BN_new();
    BN_hex2bn(&Gx,
      "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    BN_hex2bn(&Gy,
      "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

    /* Prepare device */
    ecc_device dev; memset(&dev, 0, sizeof(dev));
    dev.little_endian = 1;  /* typical for MMIO buffers; switch to 0 for BE */

    /* ==== Field demo: RES = (A + B) mod p ==== */
    /* A=5, B=7 (little-endian) */
    dev.A[0] = 5;  dev.B[0] = 7;
    dev.OPCODE = OP_FIELD_ADD;
    ecc_dev_execute(&dev, &ec);
    /* Print result in big-endian for readability */
    uint8_t be[32]; for (int i=0;i<32;i++) be[i] = dev.RES[31-i];
    dump_be_hex("add(5,7) mod p", be, 32);

    /* ==== Point demo: R = 5 * G ==== */
    /* Load G into device (LE) */
    uint8_t gx_be[32], gy_be[32];
    BN_bn2binpad(Gx, gx_be, 32);
    BN_bn2binpad(Gy, gy_be, 32);
    for (int i=0;i<32;i++) { dev.PX[i] = gx_be[31-i]; dev.PY[i] = gy_be[31-i]; }
    dev.P_INF = 0;

    /* Q unused for scalar mul */
    dev.Q_INF = 1;
    memset(dev.QX, 0, 32); memset(dev.QY, 0, 32);

    /* k = 5 */
    memset(dev.K, 0, 32); dev.K[0] = 5;

    dev.OPCODE = OP_SCALAR_MUL;
    ecc_dev_execute(&dev, &ec);

    uint8_t rx_be[32], ry_be[32];
    for (int i=0;i<32;i++) { rx_be[i] = dev.RX[31-i]; ry_be[i] = dev.RY[31-i]; }
    dump_be_hex("X(5G)", rx_be, 32);
    dump_be_hex("Y(5G)", ry_be, 32);

    /* ==== Point add demo: check 5G == 2G + 3G ==== */
    /* Compute 2G via driver */
    dev.OPCODE = OP_POINT_DOUBLE;
    ecc_dev_execute(&dev, &ec); /* R <- 2G (since P still holds G) */
    uint8_t G2X_le[32], G2Y_le[32];
    memcpy(G2X_le, dev.RX, 32); memcpy(G2Y_le, dev.RY, 32);

    /* Compute 3G via scalar mul with k=3 */
    for (int i=0;i<32;i++) { dev.PX[i] = gx_be[31-i]; dev.PY[i] = gy_be[31-i]; }
    memset(dev.K, 0, 32); dev.K[0] = 3; dev.P_INF = 0;
    dev.OPCODE = OP_SCALAR_MUL;
    ecc_dev_execute(&dev, &ec);
    uint8_t G3X_le[32], G3Y_le[32];
    memcpy(G3X_le, dev.RX, 32); memcpy(G3Y_le, dev.RY, 32);

    /* Now set P=2G, Q=3G and add */
    memcpy(dev.PX, G2X_le, 32); memcpy(dev.PY, G2Y_le, 32); dev.P_INF = 0;
    memcpy(dev.QX, G3X_le, 32); memcpy(dev.QY, G3Y_le, 32); dev.Q_INF = 0;
    dev.OPCODE = OP_POINT_ADD;
    ecc_dev_execute(&dev, &ec);

    uint8_t sumx_be[32], sumy_be[32];
    for (int i=0;i<32;i++) { sumx_be[i] = dev.RX[31-i]; sumy_be[i] = dev.RY[31-i]; }
    dump_be_hex("X(2G+3G)", sumx_be, 32);
    dump_be_hex("Y(2G+3G)", sumy_be, 32);

    /* Cleanup */
    BN_free(Gx); BN_free(Gy);
    ecc_ctx_free(&ec);
    return 0;
}
