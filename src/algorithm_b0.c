/********************************************************************************
 * Project: Tempo                                                               *
 *                                                                              *
 * Name: Algorithm B0                                                           *
 * Description: CT integer division with remainder,                             *
 *              over 3200-bit integers using OpenSSL                            *
 *              (assuming all calls to OpenSSL execute in CT)                   *
 ********************************************************************************/

/* this version includes an optimization proposed by Michael Rosenberg
 * see PR for more details: https://github.com/afonsoarriaga/ProjectTempo/pull/2
 */

#include <openssl/bn.h>

#include "algorithms.h"
#include "config.h"
#include "fips202.h"

/*
 * Helper to precompute powers of Q: Q^1, Q^2, ..., Q^128.
 * Returns a static array of 8 BIGNUM* (powers[0] = Q^1, ..., powers[7] = Q^128).
 * Only computes once (lazy initialization).
 */
static BIGNUM **get_powers_of_q(BN_CTX *bn_ctx) {
    static BIGNUM *powers[8] = {0};
    static int initialized = 0;
    if (!initialized) {
        BIGNUM *q = BN_new();
        BN_set_word(q, KYBER_Q);

        // Compute Q^1, Q^2, Q^4, ..., Q^128
        powers[0] = BN_new();
        BN_copy(powers[0], q); // Q^1
        BN_set_flags(powers[0], BN_FLG_CONSTTIME);

        for (int i = 1; i < 8; ++i) {
            powers[i] = BN_new();
            BN_sqr(powers[i], powers[i-1], bn_ctx); // Q^{2^i} = (Q^{2^{i-1}})^2
            BN_set_flags(powers[i], BN_FLG_CONSTTIME);
        }
        BN_free(q);
        initialized = 1;
    }
    return powers;
}

/*
 * Recursively splits x_bn into 256 coefficients < Q using powers of Q.
 * out: pointer to output array (int16_t[256])
 * x_bn: input BIGNUM (3200 bits)
 * powers: array of BIGNUM* for Q^128, Q^64, ..., Q^1
 * bn_ctx: BN_CTX*
 * start: start index in out
 * count: number of coefficients to fill
 * depth: current depth (0 for Q^128, 1 for Q^64, ..., 7 for Q^1)
 */
static void split_by_powers_of_q(int16_t *out, BIGNUM *x_bn, BIGNUM **powers, BN_CTX *bn_ctx, int start, int count, int depth) {
    if (count == 1) {
        // Out index is N - start - 1 because the order is reversed compared to the original RMD algorithm
        int out_idx = KYBER_N - start - 1;

        // The original number is slightly bigger than Q^256, so the leftmost element in
        // this recursion, which is the quotient of a quotient, etc, is still slightly
        // larger than Q. Divide it one last time by Q
        if (start == 0) {
            BIGNUM *q = powers[0];

            BIGNUM *quotient = BN_new();
            BIGNUM *remainder = BN_new();
            BN_div(quotient, remainder, x_bn, q, bn_ctx);
            out[out_idx] = (int16_t)BN_get_word(remainder);
            return;
        }

        // Otherwise this number is guaranteed < Q because it's a remainder of a division
        // by Q
        out[out_idx] = (int16_t)BN_get_word(x_bn);
        return;
    }

    int half = count / 2;
    BIGNUM *qpow = powers[7 - depth]; // Q^{count/2}
    BIGNUM *quotient = BN_new();
    BIGNUM *remainder = BN_new();
    BN_div(quotient, remainder, x_bn, qpow, bn_ctx);

    // Recursively split quotient and remainder
    split_by_powers_of_q(out, quotient, powers, bn_ctx, start, half, depth + 1);
    split_by_powers_of_q(out, remainder, powers, bn_ctx, start + half, half, depth + 1);

    BN_free(quotient);
    BN_free(remainder);
}

void algorithmB0(int16_t a[KYBER_N], const uint8_t extseed[KYBER_SYMBYTES + 2]) {
    uint8_t C[400]; // 400 bytes = 3200 bits

    shake128incctx state;
    shake128_inc_init(&state);
    shake128_inc_absorb(&state, extseed, KYBER_SYMBYTES + 2);
    shake128_inc_finalize(&state);
    shake128_inc_squeeze(C, sizeof(C), &state);
    shake128_inc_ctx_release(&state);

    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *x_bn = BN_new();

    BN_lebin2bn(C, sizeof(C), x_bn);

    BIGNUM **powers = get_powers_of_q(bn_ctx);

    split_by_powers_of_q(a, x_bn, powers, bn_ctx, 0, KYBER_N, 0);

    BN_free(x_bn);
    BN_CTX_free(bn_ctx);
}
