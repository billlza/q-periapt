/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Diagnostic consumer: same signed policy, key and context, real ABI 2 dylib.
 * Timed calls include output creation, secret export, wiping and owner disposal.
 * Policy verification/import, file I/O, printing and network are not timed. */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#else
#define _POSIX_C_SOURCE 200809L
#endif
#include "q_periapt.h"
#include "signed_policy_fixture.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint64_t runtime, key;
    uint8_t decision[40], pq[2400], trad[32], public_key[1216];
    uint8_t ciphertext[1120], context[65536];
    size_t context_len;
} Bench;

static void wipe(void *buffer, size_t len) {
    volatile uint8_t *bytes = buffer;
    while (len--) *bytes++ = 0;
}
static int status(int32_t value) {
    if (value == Q_PERIAPT_OK) return 0;
    fprintf(stderr, "native failure: %s (%" PRId32 ")\n", q_periapt_status_name(value), value);
    return -1;
}
static QPeriaptInput input(const uint8_t *data, size_t len) {
    return (QPeriaptInput){data, len};
}
static QPeriaptOutput output(uint8_t *data, size_t len) {
    return (QPeriaptOutput){data, len};
}
static int legacy_encapsulate(Bench *b, uint8_t *ct, uint8_t *secret) {
    return status(q_periapt_encapsulate(b->decision, 40, b->public_key, 1184,
        b->public_key + 1184, 32, b->context, b->context_len,
        ct, 1088, ct + 1088, 32, secret, 32));
}
static int legacy_decapsulate(Bench *b, const uint8_t *ct, uint8_t *secret) {
    return status(q_periapt_decapsulate(b->decision, 40, b->pq, 2400, ct, 1088,
        b->public_key, 1184, b->trad, 32, ct + 1088, 32, b->public_key + 1184, 32,
        b->context, b->context_len, secret, 32));
}
static int export_and_close(uint64_t handle, uint8_t *secret) {
    int exported = status(q_periapt_sdk_secret_export(handle, output(secret, 32)));
    int closed = status(q_periapt_sdk_close(handle));
    return exported || closed ? -1 : 0;
}
static int owner_encapsulate(Bench *b, uint8_t *ct, uint8_t *secret) {
    uint64_t handle = 0;
    if (status(q_periapt_sdk_encapsulate(b->runtime, input(b->public_key, 1216),
        input(b->context, b->context_len), output(ct, 1120), &handle))) return -1;
    return export_and_close(handle, secret);
}
static int owner_decapsulate(Bench *b, const uint8_t *ct, uint8_t *secret) {
    uint64_t handle = 0;
    if (status(q_periapt_sdk_decapsulate(b->key, input(ct, 1120),
        input(b->context, b->context_len), &handle))) return -1;
    return export_and_close(handle, secret);
}

enum Operation { GENERATE, ENCAPSULATE, DECAPSULATE };
static int invoke(Bench *b, enum Operation op, int owner) {
    uint8_t secret[32] = {0}, ct[1120], public_key[1216];
    int result;
    if (op == GENERATE && owner) {
        uint64_t key = 0;
        result = status(q_periapt_sdk_key_generate(b->runtime, &key));
        if (!result) {
            result = status(q_periapt_sdk_key_public(key, output(public_key, sizeof(public_key))));
            int closed = status(q_periapt_sdk_close(key));
            if (closed) result = closed;
        }
    } else if (op == GENERATE) {
        uint8_t pq[2400] = {0}, trad[32] = {0};
        result = status(q_periapt_generate_keypair(b->decision, 40, pq, 2400,
            public_key, 1184, trad, 32, public_key + 1184, 32));
        wipe(pq, sizeof(pq)); wipe(trad, sizeof(trad));
    } else if (op == ENCAPSULATE) {
        result = owner ? owner_encapsulate(b, ct, secret) : legacy_encapsulate(b, ct, secret);
    } else {
        result = owner ? owner_decapsulate(b, b->ciphertext, secret)
                       : legacy_decapsulate(b, b->ciphertext, secret);
    }
    wipe(secret, sizeof(secret));
    return result;
}
static int now(uint64_t *result) {
#if defined(__APPLE__)
    /* Darwin CLOCK_MONOTONIC rounds to microseconds. Use the raw uptime clock,
     * matching Swift's uptime basis without quantizing ~50-100 us operations. */
    *result = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    return *result ? 0 : -1;
#else
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) { perror("clock_gettime"); return -1; }
    *result = (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
    return 0;
#endif
}
static int measure(Bench *b, enum Operation op, int owner, uint64_t *elapsed) {
    uint64_t start, end;
    if (now(&start) || invoke(b, op, owner) || now(&end) || end <= start) return -1;
    *elapsed = end - start;
    return 0;
}
static void array(const uint64_t *values, size_t count) {
    putchar('[');
    for (size_t i = 0; i < count; i++) printf("%s%" PRIu64, i ? "," : "", values[i]);
    putchar(']');
}
static int pairs(Bench *b, enum Operation op, size_t count, unsigned phase) {
    uint64_t *legacy = calloc(count, sizeof(*legacy)), *owner = calloc(count, sizeof(*owner));
    if (!legacy || !owner) { free(legacy); free(owner); return -1; }
    int result = -1;
    for (size_t i = 0; i < 64; i++)
        if (invoke(b, op, (int)((i + phase) % 2)) || invoke(b, op, (int)((i + phase + 1) % 2))) goto done;
    for (size_t i = 0; i < count; i++) {
        int first = (int)((i + phase) % 2);
        if (measure(b, op, first, first ? &owner[i] : &legacy[i]) ||
            measure(b, op, !first, first ? &legacy[i] : &owner[i])) goto done;
    }
    const char *names[] = {"generate_key", "encapsulate", "decapsulate"};
    printf("{\"schema\":1,\"surface\":\"c_dynamic\",\"operation\":\"%s\",\"context_bytes\":%zu,\"phase\":%u,\"warmup_pairs\":64,\"legacy_raw_ns\":",
           names[op], op == GENERATE ? 0 : b->context_len, phase);
    array(legacy, count); printf(",\"owner_raw_ns\":"); array(owner, count); puts("}");
    result = ferror(stdout) ? -1 : 0;
done:
    free(legacy); free(owner);
    return result;
}
static int validate(Bench *b) {
    uint8_t left[32] = {0}, right[32] = {0};
    int result = -1;
    if (legacy_encapsulate(b, b->ciphertext, left) ||
        owner_decapsulate(b, b->ciphertext, right) || memcmp(left, right, 32)) goto done;
    if (owner_encapsulate(b, b->ciphertext, left) ||
        legacy_decapsulate(b, b->ciphertext, right) || memcmp(left, right, 32)) goto done;
    result = 0;
done:
    wipe(left, sizeof(left)); wipe(right, sizeof(right));
    return result;
}
static int setup(Bench *b) {
    const QPeriaptRuntimeOptions options = {
        .struct_size = sizeof(QPeriaptRuntimeOptions), .extension_version = Q_PERIAPT_SDK_EXTENSION_VERSION,
        .policy = {QP_TEST_POLICY_TOML, sizeof(QP_TEST_POLICY_TOML)},
        .signature = {QP_TEST_SIGNATURE, sizeof(QP_TEST_SIGNATURE)},
        .trust_root = {QP_TEST_VERIFICATION_KEY, sizeof(QP_TEST_VERIFICATION_KEY)},
        .previous_state = {NULL, 0}, .max_live_keys = 2, .max_in_flight = 1,
    };
    if (q_periapt_abi_version() != 2 || q_periapt_sdk_extension_version() != Q_PERIAPT_SDK_EXTENSION_VERSION) return -1;
    if (status(q_periapt_decision_from_signed_policy(QP_TEST_POLICY_TOML, sizeof(QP_TEST_POLICY_TOML),
        QP_TEST_SIGNATURE, sizeof(QP_TEST_SIGNATURE), QP_TEST_VERIFICATION_KEY, sizeof(QP_TEST_VERIFICATION_KEY),
        NULL, 0, b->decision, sizeof(b->decision))) ||
        status(q_periapt_sdk_runtime_new(&options, &b->runtime)) ||
        status(q_periapt_generate_keypair(b->decision, 40, b->pq, 2400, b->public_key, 1184,
            b->trad, 32, b->public_key + 1184, 32))) return -1;
    uint8_t transfer[2440] = {'Q', 'P', 'K', 1, 1, 2, 1, 0};
    memcpy(transfer + 8, b->pq, 2400); memcpy(transfer + 2408, b->trad, 32);
    int imported = status(q_periapt_sdk_expert_key_import(b->runtime, input(transfer, sizeof(transfer)), &b->key));
    wipe(transfer, sizeof(transfer));
    uint8_t public_key[1216], state[36];
    if (imported || status(q_periapt_sdk_key_public(b->key, output(public_key, sizeof(public_key)))) ||
        memcmp(public_key, b->public_key, sizeof(public_key)) ||
        status(q_periapt_sdk_runtime_state(b->runtime, output(state, sizeof(state)))) ||
        memcmp(state, b->decision + 4, sizeof(state))) return -1;
    memset(b->context, 0x51, sizeof(b->context));
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) { fputs("usage: sdk_path_perf SAMPLES PHASE\n", stderr); return 2; }
    char *end = NULL;
    errno = 0; unsigned long count = strtoul(argv[1], &end, 10);
    if (errno || !argv[1][0] || *end || count < 200 || count > 5000 || count % 2 ||
        (strcmp(argv[2], "0") && strcmp(argv[2], "1"))) return 2;
    unsigned phase = (unsigned)(argv[2][0] - '0');
    Bench b = {0};
    int result = 1;
    if (setup(&b) || pairs(&b, GENERATE, (size_t)count, phase)) goto done;
    const size_t contexts[] = {32, 4096, 65536};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); i++) {
        b.context_len = contexts[i];
        if (validate(&b) || pairs(&b, ENCAPSULATE, (size_t)count, phase) ||
            pairs(&b, DECAPSULATE, (size_t)count, phase) || validate(&b)) goto done;
    }
    result = 0;
done:
    if (b.runtime && status(q_periapt_sdk_close(b.runtime))) result = 1;
    wipe(&b, sizeof(b));
    if (result) fputs("C SDK diagnostic failed\n", stderr);
    if (fflush(stdout)) result = 1;
    return result;
}
