/* Product C-ABI smoke for Q-Periapt ABI 2.
 *
 * This consumer intentionally exercises only the production surface:
 * signed-policy decision -> OS-random key generation -> OS-random
 * encapsulation -> decapsulation. Deterministic KAT, raw hybrid, X-Wing and
 * combine entry points are internal Rust tests and must not be exported.
 */
#include "q_periapt.h"
#include "signed_policy_fixture.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int equal_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    return memcmp(a, b, len) == 0;
}

static int all_zero(const uint8_t *value, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc |= value[i];
    }
    return acc == 0;
}

static void wipe(void *value, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)value;
    while (len > 0) {
        *p++ = 0;
        len--;
    }
}

static int test_runtime_metadata(void) {
    if (q_periapt_abi_version() != Q_PERIAPT_ABI_VERSION) {
        printf("metadata: ABI mismatch\n");
        return 1;
    }
    if (strcmp(q_periapt_version(), "0.1.0-alpha.2") != 0) {
        printf("metadata: package version mismatch: %s\n", q_periapt_version());
        return 1;
    }
    if (strcmp(q_periapt_fixed_suite_id(), "ML-KEM-768+X25519") != 0 ||
            q_periapt_fixed_suite_id_len() != strlen("ML-KEM-768+X25519")) {
        printf("metadata: fixed suite mismatch\n");
        return 1;
    }
    if (strcmp(q_periapt_status_name(Q_PERIAPT_ERR_ENTROPY), "ERR_ENTROPY") != 0 ||
            strcmp(q_periapt_status_name(12345), "UNKNOWN_STATUS") != 0) {
        printf("metadata: status-name mismatch\n");
        return 1;
    }
    printf("metadata ................................ PASS\n");
    return 0;
}

static int resolve_decision(uint8_t decision[Q_PERIAPT_POLICY_DECISION_LEN]) {
    int32_t rc = q_periapt_decision_from_signed_policy(
            QP_TEST_POLICY_TOML, sizeof(QP_TEST_POLICY_TOML),
            QP_TEST_SIGNATURE, sizeof(QP_TEST_SIGNATURE),
            QP_TEST_VERIFICATION_KEY, sizeof(QP_TEST_VERIFICATION_KEY),
            NULL, 0,
            decision, Q_PERIAPT_POLICY_DECISION_LEN);
    if (rc != Q_PERIAPT_OK) {
        printf("policy: initial decision rc=%d\n", rc);
        return 1;
    }
    if (decision[0] != Q_PERIAPT_POLICY_DECISION_VERSION ||
            decision[1] != Q_PERIAPT_SUITE_MLKEM768_X25519 ||
            decision[2] != Q_PERIAPT_PROFILE_CONTEXT_BOUND ||
            decision[3] != Q_PERIAPT_KEY_FORMAT_EXPANDED ||
            !equal_bytes(decision + 8, QP_TEST_POLICY_DIGEST, sizeof(QP_TEST_POLICY_DIGEST))) {
        printf("policy: decision bytes mismatch\n");
        return 1;
    }
    return 0;
}

static int test_signed_policy_fail_closed(void) {
    uint8_t decision[Q_PERIAPT_POLICY_DECISION_LEN];
    if (resolve_decision(decision) != 0) {
        return 1;
    }

    uint8_t trusted_state[Q_PERIAPT_TRUSTED_POLICY_STATE_LEN];
    memcpy(trusted_state, decision + 4, sizeof(trusted_state));
    int32_t rc = q_periapt_decision_from_signed_policy(
            QP_TEST_POLICY_TOML, sizeof(QP_TEST_POLICY_TOML),
            QP_TEST_SIGNATURE, sizeof(QP_TEST_SIGNATURE),
            QP_TEST_VERIFICATION_KEY, sizeof(QP_TEST_VERIFICATION_KEY),
            trusted_state, sizeof(trusted_state),
            decision, sizeof(decision));
    if (rc != Q_PERIAPT_OK) {
        printf("policy: trusted-state reapply rc=%d\n", rc);
        return 1;
    }

    const uint8_t legacy_abi1_state[4] = {0, 0, 0, 2};
    memset(decision, 0xa5, sizeof(decision));
    rc = q_periapt_decision_from_signed_policy(
            QP_TEST_POLICY_TOML, sizeof(QP_TEST_POLICY_TOML),
            QP_TEST_SIGNATURE, sizeof(QP_TEST_SIGNATURE),
            QP_TEST_VERIFICATION_KEY, sizeof(QP_TEST_VERIFICATION_KEY),
            legacy_abi1_state, sizeof(legacy_abi1_state),
            decision, sizeof(decision));
    if (rc != Q_PERIAPT_ERR_LENGTH || !all_zero(decision, sizeof(decision))) {
        printf("policy: legacy ABI1 state was not fail-closed rc=%d\n", rc);
        return 1;
    }

    uint8_t tampered_signature[sizeof(QP_TEST_SIGNATURE)];
    memcpy(tampered_signature, QP_TEST_SIGNATURE, sizeof(tampered_signature));
    tampered_signature[0] ^= 1;
    memset(decision, 0xa5, sizeof(decision));
    rc = q_periapt_decision_from_signed_policy(
            QP_TEST_POLICY_TOML, sizeof(QP_TEST_POLICY_TOML),
            tampered_signature, sizeof(tampered_signature),
            QP_TEST_VERIFICATION_KEY, sizeof(QP_TEST_VERIFICATION_KEY),
            NULL, 0,
            decision, sizeof(decision));
    wipe(tampered_signature, sizeof(tampered_signature));
    if (rc != Q_PERIAPT_ERR_POLICY || !all_zero(decision, sizeof(decision))) {
        printf("policy: tampered signature was not fail-closed rc=%d\n", rc);
        return 1;
    }

    printf("signed policy / ABI1 hard cut ........... PASS\n");
    return 0;
}

static int test_product_roundtrip_and_atomic_failure(void) {
    uint8_t decision[Q_PERIAPT_POLICY_DECISION_LEN];
    uint8_t sk_pq[Q_PERIAPT_MLKEM768_SK_LEN];
    uint8_t pk_pq[Q_PERIAPT_MLKEM768_PK_LEN];
    uint8_t sk_trad[Q_PERIAPT_X25519_LEN];
    uint8_t pk_trad[Q_PERIAPT_X25519_LEN];
    uint8_t ct_pq[Q_PERIAPT_MLKEM768_CT_LEN];
    uint8_t ct_trad[Q_PERIAPT_X25519_LEN];
    uint8_t enc_secret[Q_PERIAPT_SECRET_LEN];
    uint8_t dec_secret[Q_PERIAPT_SECRET_LEN];
    int failed = 0;

    if (resolve_decision(decision) != 0) {
        return 1;
    }
    int32_t rc = q_periapt_generate_keypair(
            decision, sizeof(decision),
            sk_pq, sizeof(sk_pq), pk_pq, sizeof(pk_pq),
            sk_trad, sizeof(sk_trad), pk_trad, sizeof(pk_trad));
    if (rc != Q_PERIAPT_OK) {
        printf("product: generate keypair rc=%d\n", rc);
        failed = 1;
        goto cleanup;
    }

    const uint8_t context[] = "c-abi2-policy-context";
    rc = q_periapt_encapsulate(
            decision, sizeof(decision),
            pk_pq, sizeof(pk_pq), pk_trad, sizeof(pk_trad),
            context, sizeof(context) - 1,
            ct_pq, sizeof(ct_pq), ct_trad, sizeof(ct_trad),
            enc_secret, sizeof(enc_secret));
    if (rc != Q_PERIAPT_OK) {
        printf("product: encapsulate rc=%d\n", rc);
        failed = 1;
        goto cleanup;
    }
    rc = q_periapt_decapsulate(
            decision, sizeof(decision),
            sk_pq, sizeof(sk_pq), ct_pq, sizeof(ct_pq), pk_pq, sizeof(pk_pq),
            sk_trad, sizeof(sk_trad), ct_trad, sizeof(ct_trad), pk_trad, sizeof(pk_trad),
            context, sizeof(context) - 1,
            dec_secret, sizeof(dec_secret));
    if (rc != Q_PERIAPT_OK || !equal_bytes(enc_secret, dec_secret, sizeof(enc_secret))) {
        printf("product: roundtrip mismatch rc=%d\n", rc);
        failed = 1;
        goto cleanup;
    }

    const uint8_t wrong_context[] = "wrong-context";
    rc = q_periapt_decapsulate(
            decision, sizeof(decision),
            sk_pq, sizeof(sk_pq), ct_pq, sizeof(ct_pq), pk_pq, sizeof(pk_pq),
            sk_trad, sizeof(sk_trad), ct_trad, sizeof(ct_trad), pk_trad, sizeof(pk_trad),
            wrong_context, sizeof(wrong_context) - 1,
            dec_secret, sizeof(dec_secret));
    if (rc != Q_PERIAPT_OK || equal_bytes(enc_secret, dec_secret, sizeof(enc_secret))) {
        printf("product: application context was not bound rc=%d\n", rc);
        failed = 1;
        goto cleanup;
    }

    uint8_t low_order_trad[Q_PERIAPT_X25519_LEN] = {0};
    memset(ct_pq, 0xa5, sizeof(ct_pq));
    memset(ct_trad, 0xa5, sizeof(ct_trad));
    memset(enc_secret, 0xa5, sizeof(enc_secret));
    rc = q_periapt_encapsulate(
            decision, sizeof(decision),
            pk_pq, sizeof(pk_pq), low_order_trad, sizeof(low_order_trad),
            context, sizeof(context) - 1,
            ct_pq, sizeof(ct_pq), ct_trad, sizeof(ct_trad),
            enc_secret, sizeof(enc_secret));
    if (rc != Q_PERIAPT_ERR_INVALID_KEYSHARE ||
            !all_zero(ct_pq, sizeof(ct_pq)) ||
            !all_zero(ct_trad, sizeof(ct_trad)) ||
            !all_zero(enc_secret, sizeof(enc_secret))) {
        printf("product: low-order failure was not atomic rc=%d\n", rc);
        failed = 1;
        goto cleanup;
    }

    printf("OS-random product roundtrip / atomicity .. PASS\n");

cleanup:
    wipe(decision, sizeof(decision));
    wipe(sk_pq, sizeof(sk_pq));
    wipe(pk_pq, sizeof(pk_pq));
    wipe(sk_trad, sizeof(sk_trad));
    wipe(pk_trad, sizeof(pk_trad));
    wipe(ct_pq, sizeof(ct_pq));
    wipe(ct_trad, sizeof(ct_trad));
    wipe(enc_secret, sizeof(enc_secret));
    wipe(dec_secret, sizeof(dec_secret));
    return failed;
}

int main(void) {
    int failures = 0;
    printf("Q-Periapt ABI 2 product C smoke\n");
    failures += test_runtime_metadata();
    failures += test_signed_policy_fail_closed();
    failures += test_product_roundtrip_and_atomic_failure();
    if (failures == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("FAILURES: %d\n", failures);
    return 1;
}
