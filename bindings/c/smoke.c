/* C-ABI link smoke test for q-periapt-ffi.
 *
 * Verifies the C calling convention end-to-end by actually linking against the built
 * library (cdylib/.dll on Windows-MSVC, or staticlib elsewhere) and calling the exported
 * functions with real inputs. Three independent checks:
 *
 *   A. combine() known-answer  — byte-exact reproduction of a ContextBound reference vector
 *      (the same `bindings/contextbound-vectors.txt` the Swift/Kotlin/WASM faces pin),
 *      proving correctness travels intact across the C ABI.
 *   B. hybrid round-trip       — keypair -> encapsulate -> decapsulate, asserting the two
 *      32-byte secrets match; exercises the widest ABI surface (pointers, size_t lengths,
 *      uint8_t/uint32_t scalars, int32_t status) across four functions.
 *   C. status-code ABI         — a NULL pointer must return Q_PERIAPT_ERR_NULL and a wrong
 *      output length must return Q_PERIAPT_ERR_LENGTH, proving the length-checked,
 *      non-aborting error contract holds across the boundary.
 *
 * Build/run: see bindings/c/README.md. Exit code 0 = all passed, non-zero = a failure.
 */
#include "q_periapt.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex2bin(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > out_cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 0;
}

static int eq(const uint8_t *a, const uint8_t *b, size_t n) { return memcmp(a, b, n) == 0; }

/* Test A: combine() must reproduce a ContextBound reference vector byte-for-byte. */
static int test_combine_kat(void) {
    /* vector #4 from bindings/contextbound-vectors.txt (profile = ContextBound). */
    const char *in_hex =
        "000000000000000153000000000000000400000009000000000000000241420000000000000001"
        "580000000000000001430000000000000001440000000000000001450000000000000001460000"
        "000000000003637478";
    const char *want_hex =
        "572cbe29ec15781bb54103465c551839dffbfa17346f3a679e8f483a2b1d49d6";

    uint8_t in[256], want[Q_PERIAPT_SECRET_LEN], got[Q_PERIAPT_SECRET_LEN];
    size_t in_len = 0, want_len = 0;
    if (hex2bin(in_hex, in, sizeof in, &in_len) != 0) { printf("A: bad input hex\n"); return 1; }
    if (hex2bin(want_hex, want, sizeof want, &want_len) != 0 || want_len != Q_PERIAPT_SECRET_LEN) {
        printf("A: bad want hex\n"); return 1;
    }
    int rc = q_periapt_combine(Q_PERIAPT_PROFILE_CONTEXT_BOUND, in, in_len, got, sizeof got);
    if (rc != Q_PERIAPT_OK) { printf("A: combine rc=%d (want 0)\n", rc); return 1; }
    if (!eq(got, want, Q_PERIAPT_SECRET_LEN)) { printf("A: combine output mismatch\n"); return 1; }
    printf("A: combine() KAT byte-exact ....... PASS\n");
    return 0;
}

/* Test B: keypair -> encapsulate -> decapsulate, secrets must agree. */
static int test_hybrid_roundtrip(void) {
    uint8_t seed[64], scalar[32];
    memset(seed, 0x42, sizeof seed);
    memset(scalar, 0x24, sizeof scalar);

    uint8_t sk_pq[Q_PERIAPT_MLKEM768_SK_LEN], pk_pq[Q_PERIAPT_MLKEM768_PK_LEN];
    uint8_t sk_trad[Q_PERIAPT_X25519_LEN], pk_trad[Q_PERIAPT_X25519_LEN];
    int rc;

    rc = q_periapt_mlkem768_keypair(seed, sizeof seed, sk_pq, sizeof sk_pq, pk_pq, sizeof pk_pq);
    if (rc != Q_PERIAPT_OK) { printf("B: mlkem keypair rc=%d\n", rc); return 1; }
    rc = q_periapt_x25519_keypair(scalar, sizeof scalar, sk_trad, sizeof sk_trad, pk_trad, sizeof pk_trad);
    if (rc != Q_PERIAPT_OK) { printf("B: x25519 keypair rc=%d\n", rc); return 1; }

    const uint8_t suite_id[] = {'S'};
    const uint8_t context[] = {'c', 't', 'x'};
    const uint32_t policy_version = 1;
    uint8_t rand_pq[32], rand_trad[32];
    memset(rand_pq, 0x37, sizeof rand_pq);
    memset(rand_trad, 0x9a, sizeof rand_trad);

    uint8_t ct_pq[Q_PERIAPT_MLKEM768_CT_LEN], ct_trad[Q_PERIAPT_X25519_LEN];
    uint8_t secret_enc[Q_PERIAPT_SECRET_LEN], secret_dec[Q_PERIAPT_SECRET_LEN];

    rc = q_periapt_hybrid_encapsulate(
        Q_PERIAPT_PROFILE_CONTEXT_BOUND, suite_id, sizeof suite_id, policy_version,
        pk_pq, sizeof pk_pq, pk_trad, sizeof pk_trad, context, sizeof context,
        rand_pq, sizeof rand_pq, rand_trad, sizeof rand_trad,
        ct_pq, sizeof ct_pq, ct_trad, sizeof ct_trad, secret_enc, sizeof secret_enc);
    if (rc != Q_PERIAPT_OK) { printf("B: encapsulate rc=%d\n", rc); return 1; }

    rc = q_periapt_hybrid_decapsulate(
        Q_PERIAPT_PROFILE_CONTEXT_BOUND, suite_id, sizeof suite_id, policy_version,
        sk_pq, sizeof sk_pq, ct_pq, sizeof ct_pq, pk_pq, sizeof pk_pq,
        sk_trad, sizeof sk_trad, ct_trad, sizeof ct_trad, pk_trad, sizeof pk_trad,
        context, sizeof context, secret_dec, sizeof secret_dec);
    if (rc != Q_PERIAPT_OK) { printf("B: decapsulate rc=%d\n", rc); return 1; }

    if (!eq(secret_enc, secret_dec, Q_PERIAPT_SECRET_LEN)) {
        printf("B: encap/decap secret mismatch\n"); return 1;
    }
    printf("B: hybrid keypair/encap/decap ..... PASS\n");
    return 0;
}

/* Test C: the status-code contract must hold across the ABI (no aborts). */
static int test_error_codes(void) {
    uint8_t out[Q_PERIAPT_SECRET_LEN];
    uint8_t in[8] = {0};

    int rc_null = q_periapt_combine(Q_PERIAPT_PROFILE_CONTEXT_BOUND, NULL, 8, out, sizeof out);
    if (rc_null != Q_PERIAPT_ERR_NULL) { printf("C: NULL input rc=%d (want %d)\n", rc_null, Q_PERIAPT_ERR_NULL); return 1; }

    int rc_len = q_periapt_combine(Q_PERIAPT_PROFILE_CONTEXT_BOUND, in, sizeof in, out, 16 /* wrong */);
    if (rc_len != Q_PERIAPT_ERR_LENGTH) { printf("C: bad out_len rc=%d (want %d)\n", rc_len, Q_PERIAPT_ERR_LENGTH); return 1; }

    printf("C: status-code ABI (NULL/LENGTH) .. PASS\n");
    return 0;
}

int main(void) {
    int fails = 0;
    printf("q-periapt C-ABI link smoke test\n");
    fails += test_combine_kat();
    fails += test_hybrid_roundtrip();
    fails += test_error_codes();
    if (fails == 0) { printf("ALL PASS\n"); return 0; }
    printf("FAILURES: %d\n", fails);
    return 1;
}
