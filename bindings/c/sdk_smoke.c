/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Real C consumer of the additive owner API, linked with the built native library. */
#include "q_periapt.h"
#include "signed_policy_fixture.h"
#include "sdk_policy_update_fixture.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(value) do { if (!(value)) { fprintf(stderr, "SDK C check failed at line %d\n", __LINE__); return 1; } } while (0)

_Static_assert(Q_PERIAPT_ABI_VERSION == 2, "ABI major must remain 2");
_Static_assert(sizeof(QPeriaptInput) == 2 * sizeof(uintptr_t), "input layout");
_Static_assert(sizeof(QPeriaptOutput) == 2 * sizeof(uintptr_t), "output layout");
_Static_assert(offsetof(QPeriaptInput, len) == sizeof(uintptr_t), "input length offset");
_Static_assert(offsetof(QPeriaptRuntimeOptions, policy) == 8, "policy offset");
_Static_assert(offsetof(QPeriaptRuntimeOptions, signature) == 8 + 2 * sizeof(uintptr_t), "signature offset");
_Static_assert(offsetof(QPeriaptRuntimeOptions, trust_root) == 8 + 4 * sizeof(uintptr_t), "root offset");
_Static_assert(offsetof(QPeriaptRuntimeOptions, previous_state) == 8 + 6 * sizeof(uintptr_t), "state offset");
_Static_assert(offsetof(QPeriaptRuntimeOptions, max_live_keys) == 8 + 8 * sizeof(uintptr_t), "limits offset");
_Static_assert(sizeof(QPeriaptRuntimeOptions) == 16 + 8 * sizeof(uintptr_t), "runtime options size");
_Static_assert(offsetof(QPeriaptConnectionOptions, certificate) == 8, "connection certificate offset");
_Static_assert(offsetof(QPeriaptConnectionOptions, private_key) == 8 + 2 * sizeof(uintptr_t), "connection key offset");
_Static_assert(offsetof(QPeriaptConnectionOptions, peer_certificate) == 8 + 4 * sizeof(uintptr_t), "connection peer offset");
_Static_assert(offsetof(QPeriaptConnectionOptions, application_context) == 8 + 6 * sizeof(uintptr_t), "connection context offset");
_Static_assert(offsetof(QPeriaptConnectionOptions, max_connections) == 8 + 8 * sizeof(uintptr_t), "connection limits offset");
_Static_assert(sizeof(QPeriaptConnectionOptions) == 24 + 8 * sizeof(uintptr_t), "connection options size");
_Static_assert(sizeof(QPeriaptConnectionProgress) == 12, "connection progress size");
_Static_assert(offsetof(QPeriaptStoreOptions, path) == 8, "store path offset");
_Static_assert(offsetof(QPeriaptStoreOptions, policy) == 8 + 2 * sizeof(uintptr_t), "store policy offset");
_Static_assert(offsetof(QPeriaptStoreOptions, signature) == 8 + 4 * sizeof(uintptr_t), "store signature offset");
_Static_assert(offsetof(QPeriaptStoreOptions, trust_root) == 8 + 6 * sizeof(uintptr_t), "store root offset");
_Static_assert(offsetof(QPeriaptStoreOptions, max_live_keys) == 8 + 8 * sizeof(uintptr_t), "store limits offset");
_Static_assert(sizeof(QPeriaptStoreOptions) == 16 + 8 * sizeof(uintptr_t), "store options size");
_Static_assert(offsetof(QPeriaptRuntimeOptions, struct_size) == 0 && offsetof(QPeriaptRuntimeOptions, extension_version) == 4, "runtime prefix");
_Static_assert(offsetof(QPeriaptStoreOptions, struct_size) == 0 && offsetof(QPeriaptStoreOptions, extension_version) == 4, "store prefix");
_Static_assert(offsetof(QPeriaptConnectionOptions, struct_size) == 0 && offsetof(QPeriaptConnectionOptions, extension_version) == 4, "connection prefix");
_Static_assert(offsetof(QPeriaptRecoverableStoreOptions, struct_size) == 0 && offsetof(QPeriaptRecoverableStoreOptions, extension_version) == 4, "recoverable store prefix");
_Static_assert(offsetof(QPeriaptRecoverableStoreOptions, path) == 8, "recoverable path offset");
_Static_assert(offsetof(QPeriaptRecoverableStoreOptions, scope) == 8 + 6 * sizeof(uintptr_t), "recoverable scope offset");
_Static_assert(offsetof(QPeriaptRecoverableStoreOptions, enrollment_signature) == 8 + 12 * sizeof(uintptr_t), "recoverable enrollment offset");
_Static_assert(offsetof(QPeriaptRecoverableStoreOptions, max_live_keys) == 8 + 14 * sizeof(uintptr_t), "recoverable limits offset");
_Static_assert(sizeof(QPeriaptRecoverableStoreOptions) == 16 + 14 * sizeof(uintptr_t), "recoverable options size");

static int reject_short_options(void)
{
    /* malloc supplies suitably aligned storage, with no initialized trailing
       options fields. Each unsupported prefix must be rejected without reading
       past this allocation, touching output, or consulting runtime handle 0. */
    for (size_t words = 1; words <= 2; words++) {
        uint32_t *prefix = malloc(words * sizeof(*prefix));
        CHECK(prefix != NULL);
        prefix[0] = words == 1 ? 4 : sizeof(QPeriaptRuntimeOptions);
        if (words == 2) prefix[1] = 0;
        uint64_t output = UINT64_MAX;
        CHECK(q_periapt_sdk_runtime_new((const QPeriaptRuntimeOptions *)prefix, &output) == Q_PERIAPT_ERR_LIMITS);
        CHECK(output == UINT64_MAX);
        if (words == 2) prefix[0] = sizeof(QPeriaptStoreOptions);
        CHECK(q_periapt_sdk_runtime_provision_store((const QPeriaptStoreOptions *)prefix, &output) == Q_PERIAPT_ERR_LIMITS);
        CHECK(output == UINT64_MAX);
        CHECK(q_periapt_sdk_runtime_open_store((const QPeriaptStoreOptions *)prefix, &output) == Q_PERIAPT_ERR_LIMITS);
        CHECK(output == UINT64_MAX);
        if (words == 2) prefix[0] = sizeof(QPeriaptConnectionOptions);
        CHECK(q_periapt_sdk_connection_client_new(0, (const QPeriaptConnectionOptions *)prefix, &output) == Q_PERIAPT_ERR_LIMITS);
        CHECK(output == UINT64_MAX);
        CHECK(q_periapt_sdk_connection_server_new(0, (const QPeriaptConnectionOptions *)prefix, &output) == Q_PERIAPT_ERR_LIMITS);
        CHECK(output == UINT64_MAX);
        if (words == 2) prefix[0] = sizeof(QPeriaptRecoverableStoreOptions);
        uint32_t disposition = UINT32_MAX;
        CHECK(q_periapt_sdk_runtime_provision_recoverable_store((const QPeriaptRecoverableStoreOptions *)prefix, &output) == Q_PERIAPT_ERR_LIMITS);
        CHECK(output == UINT64_MAX);
        CHECK(q_periapt_sdk_runtime_open_recoverable_store((const QPeriaptRecoverableStoreOptions *)prefix, &output) == Q_PERIAPT_ERR_LIMITS);
        CHECK(output == UINT64_MAX);
        CHECK(q_periapt_sdk_runtime_open_recovering_store((const QPeriaptRecoverableStoreOptions *)prefix,
            (QPeriaptInput){NULL, 0}, &output, &disposition) == Q_PERIAPT_ERR_LIMITS);
        CHECK(output == UINT64_MAX && disposition == UINT32_MAX);
        free(prefix);
    }
    return 0;
}

int main(void)
{
    CHECK(reject_short_options() == 0);
    const QPeriaptRuntimeOptions options = {
        .struct_size = sizeof(QPeriaptRuntimeOptions),
        .extension_version = Q_PERIAPT_SDK_EXTENSION_VERSION,
        .policy = {QP_TEST_POLICY_TOML, sizeof(QP_TEST_POLICY_TOML)},
        .signature = {QP_TEST_SIGNATURE, sizeof(QP_TEST_SIGNATURE)},
        .trust_root = {QP_TEST_VERIFICATION_KEY, sizeof(QP_TEST_VERIFICATION_KEY)},
        .previous_state = {NULL, 0},
        .max_live_keys = 1,
        .max_in_flight = 4,
    };
    uint64_t runtime = 0, key = 0, secret = 0, recovered = 0, rejected = 0;
    uint8_t public_key[Q_PERIAPT_SDK_PUBLIC_KEY_LEN];
    uint8_t ciphertext[Q_PERIAPT_SDK_CIPHERTEXT_LEN];
    uint8_t left[32], right[32], state[36];
    const uint8_t context[] = {0x61, 0x62, 0x63};
    CHECK(q_periapt_abi_version() == 2);
    CHECK(q_periapt_sdk_extension_version() == Q_PERIAPT_SDK_EXTENSION_VERSION);
#if defined(_WIN32)
    /* This platform has no reviewed private-store adapter. Valid arguments
       must fail explicitly and clear the output, without creating a store. */
    const uint8_t store_path[] = "C:\\qperiapt-test\\policy.redb";
    const QPeriaptStoreOptions store_options = {
        .struct_size = sizeof(QPeriaptStoreOptions),
        .extension_version = Q_PERIAPT_SDK_EXTENSION_VERSION,
        .path = {store_path, sizeof(store_path) - 1},
        .policy = options.policy,
        .signature = options.signature,
        .trust_root = options.trust_root,
        .max_live_keys = 1,
        .max_in_flight = 4,
    };
    uint64_t store = UINT64_MAX;
    CHECK(q_periapt_sdk_runtime_provision_store(&store_options, &store) == Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM);
    CHECK(store == 0);
    store = UINT64_MAX;
    CHECK(q_periapt_sdk_runtime_open_store(&store_options, &store) == Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM);
    CHECK(store == 0);
#endif
    CHECK(q_periapt_sdk_runtime_new(&options, &runtime) == Q_PERIAPT_OK);
#if defined(_WIN32)
    store = UINT64_MAX;
    CHECK(q_periapt_sdk_runtime_update_store(runtime, options.policy, options.signature, &store) == Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM);
    CHECK(store == 0);
#endif
    CHECK(q_periapt_sdk_runtime_state(runtime, (QPeriaptOutput){state, sizeof(state)}) == Q_PERIAPT_OK);
    CHECK(memcmp(state + 4, QP_TEST_POLICY_DIGEST, 32) == 0);
    CHECK(q_periapt_sdk_key_generate(runtime, &key) == Q_PERIAPT_OK);
    uint8_t private_key[Q_PERIAPT_SDK_EXPANDED_KEY_LEN];
    CHECK(q_periapt_sdk_expert_key_export(key, (QPeriaptOutput){private_key, sizeof(private_key)}) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_close(key) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_expert_key_import(runtime, (QPeriaptInput){private_key, sizeof(private_key)}, &key) == Q_PERIAPT_OK);
    for (size_t i = 0; i < sizeof(private_key); i++) ((volatile uint8_t *)private_key)[i] = 0;
    uint64_t over_budget = UINT64_MAX;
    CHECK(q_periapt_sdk_key_generate(runtime, &over_budget) == Q_PERIAPT_ERR_RESOURCE_LIMIT);
    CHECK(over_budget == 0);
    CHECK(q_periapt_sdk_key_public(key, (QPeriaptOutput){public_key, sizeof(public_key)}) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_encapsulate(runtime, (QPeriaptInput){public_key, sizeof(public_key)},
        (QPeriaptInput){context, sizeof(context)}, (QPeriaptOutput){ciphertext, sizeof(ciphertext)}, &secret) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_decapsulate(key, (QPeriaptInput){ciphertext, sizeof(ciphertext)},
        (QPeriaptInput){context, sizeof(context)}, &recovered) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_secret_export(secret, (QPeriaptOutput){left, sizeof(left)}) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_secret_export(recovered, (QPeriaptOutput){right, sizeof(right)}) == Q_PERIAPT_OK);
    CHECK(memcmp(left, right, 32) == 0);
    const uint8_t label[] = "app/v1/aes256";
    uint64_t derived = 0, peer_derived = 0;
    for (uint32_t purpose = 1; purpose <= 5; purpose++) {
        CHECK(q_periapt_sdk_secret_derive(secret, purpose,
            (QPeriaptInput){label, sizeof(label) - 1}, (QPeriaptInput){context, sizeof(context)}, &derived) == Q_PERIAPT_OK);
        CHECK(q_periapt_sdk_secret_derive(recovered, purpose,
            (QPeriaptInput){label, sizeof(label) - 1}, (QPeriaptInput){context, sizeof(context)}, &peer_derived) == Q_PERIAPT_OK);
        CHECK(q_periapt_sdk_derived_key_export(derived, (QPeriaptOutput){left, sizeof(left)}) == Q_PERIAPT_OK);
        CHECK(q_periapt_sdk_derived_key_export(peer_derived, (QPeriaptOutput){right, sizeof(right)}) == Q_PERIAPT_OK);
        CHECK(memcmp(left, right, 32) == 0);
        CHECK(q_periapt_sdk_secret_export(derived, (QPeriaptOutput){left, sizeof(left)}) == Q_PERIAPT_ERR_CLOSED);
        CHECK(q_periapt_sdk_derived_key_export(secret, (QPeriaptOutput){left, sizeof(left)}) == Q_PERIAPT_ERR_CLOSED);
        CHECK(q_periapt_sdk_close(derived) == Q_PERIAPT_OK);
        CHECK(q_periapt_sdk_close(peer_derived) == Q_PERIAPT_OK);
    }
    CHECK(q_periapt_sdk_secret_derive(secret, 1, (QPeriaptInput){label, sizeof(label) - 1},
        (QPeriaptInput){context, sizeof(context)}, &derived) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_secret_export(secret, (QPeriaptOutput){left, sizeof(left)}) == Q_PERIAPT_OK);
    ciphertext[0] ^= 1;
    CHECK(q_periapt_sdk_decapsulate(key, (QPeriaptInput){ciphertext, sizeof(ciphertext)},
        (QPeriaptInput){context, sizeof(context)}, &rejected) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_secret_export(rejected, (QPeriaptOutput){right, sizeof(right)}) == Q_PERIAPT_OK);
    CHECK(memcmp(left, right, 32) != 0);
    CHECK(q_periapt_sdk_close(key) == Q_PERIAPT_OK);
    uint64_t replacement = 0;
    CHECK(q_periapt_sdk_key_generate(runtime, &replacement) == Q_PERIAPT_OK);
    CHECK(replacement != key);
    uint64_t update = 0, disabled = 0;
    uint32_t enabled = 99;
    uint8_t states[Q_PERIAPT_SDK_POLICY_UPDATE_STATES_LEN];
    CHECK(q_periapt_sdk_runtime_prepare_update(runtime, (QPeriaptInput){QP_REVOKED_POLICY, sizeof(QP_REVOKED_POLICY)},
        (QPeriaptInput){QP_REVOKED_SIGNATURE, sizeof(QP_REVOKED_SIGNATURE)}, &update) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_policy_update_states(update, (QPeriaptOutput){states, sizeof(states)}) == Q_PERIAPT_OK);
    CHECK(memcmp(states, state, 36) == 0);
    CHECK(memcmp(states + 36, QP_REVOKED_STATE, 36) == 0);
    memcpy(state, states + 36, 36); /* Test-only in-memory CAS/persistence. */
    CHECK(q_periapt_sdk_policy_update_activate(update, &disabled) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_close(runtime) == Q_PERIAPT_ERR_CLOSED);
    CHECK(q_periapt_sdk_close(update) == Q_PERIAPT_ERR_CLOSED);
    CHECK(q_periapt_sdk_runtime_enabled(disabled, &enabled) == Q_PERIAPT_OK && enabled == 0);
    CHECK(q_periapt_sdk_key_generate(disabled, &key) == Q_PERIAPT_ERR_POLICY && key == 0);
    memset(left, 0xa5, sizeof(left));
    CHECK(q_periapt_sdk_secret_export(secret, (QPeriaptOutput){left, sizeof(left)}) == Q_PERIAPT_ERR_CLOSED);
    for (size_t i = 0; i < sizeof(left); i++) CHECK(left[i] == 0);
    CHECK(q_periapt_sdk_close(replacement) == Q_PERIAPT_ERR_CLOSED);
    CHECK(q_periapt_sdk_derived_key_export(derived, (QPeriaptOutput){left, sizeof(left)}) == Q_PERIAPT_ERR_CLOSED);
    QPeriaptRuntimeOptions restore = options;
    restore.policy = (QPeriaptInput){QP_REVOKED_POLICY, sizeof(QP_REVOKED_POLICY)};
    restore.signature = (QPeriaptInput){QP_REVOKED_SIGNATURE, sizeof(QP_REVOKED_SIGNATURE)};
    restore.previous_state = (QPeriaptInput){state, sizeof(state)};
    uint64_t recovered_runtime = 0, next_runtime = 0;
    CHECK(q_periapt_sdk_runtime_new(&restore, &recovered_runtime) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_runtime_enabled(recovered_runtime, &enabled) == Q_PERIAPT_OK && enabled == 0);
    CHECK(q_periapt_sdk_runtime_prepare_update(recovered_runtime, (QPeriaptInput){QP_UPDATED_POLICY, sizeof(QP_UPDATED_POLICY)},
        (QPeriaptInput){QP_UPDATED_SIGNATURE, sizeof(QP_UPDATED_SIGNATURE)}, &update) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_policy_update_states(update, (QPeriaptOutput){states, sizeof(states)}) == Q_PERIAPT_OK);
    CHECK(memcmp(states, state, 36) == 0 && memcmp(states + 36, QP_UPDATED_STATE, 36) == 0);
    memcpy(state, states + 36, 36);
    CHECK(q_periapt_sdk_policy_update_activate(update, &next_runtime) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_runtime_enabled(next_runtime, &enabled) == Q_PERIAPT_OK && enabled == 1);
    CHECK(q_periapt_sdk_key_generate(next_runtime, &key) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_close(next_runtime) == Q_PERIAPT_OK);
    CHECK(q_periapt_sdk_close(disabled) == Q_PERIAPT_OK);
    /* Test-only generated secrets are not printed; clear the remaining test copy. */
    for (size_t i = 0; i < sizeof(right); i++) ((volatile uint8_t *)right)[i] = 0;
    puts("SDK_ABI2_C_CONSUMER_PASS");
    return 0;
}
