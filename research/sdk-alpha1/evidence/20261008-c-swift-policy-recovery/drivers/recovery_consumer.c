/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Public C API consumer. Inputs are reproducible PUBLIC test vectors. */
#include "q_periapt.h"
#include "recovery_fixture.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "recovery C check failed: %d\n", __LINE__); return 1; } } while (0)
#define IN(name) ((QPeriaptInput){name, sizeof(name)})
#define OUT(name) ((QPeriaptOutput){name, sizeof(name)})
int main(int argc, char **argv) {
    CHECK(argc == 2);
    uint8_t enrollment_message[Q_PERIAPT_POLICY_RECOVERY_ENROLLMENT_MESSAGE_LEN];
    CHECK(q_periapt_sdk_policy_recovery_enrollment_message(IN(scope), IN(initial_root), IN(recovery_root), OUT(enrollment_message)) == 0);
    CHECK(memcmp(enrollment_message, expected_enrollment_message, sizeof(enrollment_message)) == 0);
    QPeriaptRecoverableStoreOptions options = {
        .struct_size = sizeof(QPeriaptRecoverableStoreOptions), .extension_version = Q_PERIAPT_SDK_EXTENSION_VERSION,
        .path = {(const uint8_t *)argv[1], strlen(argv[1])}, .policy = IN(initial_policy),
        .signature = IN(initial_signature), .scope = IN(scope), .initial_root = IN(initial_root),
        .recovery_root = IN(recovery_root), .enrollment_signature = IN(enrollment_signature),
        .max_live_keys = 2, .max_in_flight = 2
    };
    uint64_t original = 0, next = 0, current = 0, key = 0, successor = 0;
    uint32_t disposition = 0, enabled = 99;
    uint8_t previous_public[Q_PERIAPT_SDK_PUBLIC_KEY_LEN], retained_public[Q_PERIAPT_SDK_PUBLIC_KEY_LEN], state[36];
    CHECK(q_periapt_sdk_runtime_provision_recoverable_store(&options, &original) == 0);
    CHECK(q_periapt_sdk_runtime_state(original, OUT(state)) == 0);
    CHECK(state[0] == 255 && state[1] == 255 && state[2] == 255 && state[3] == 255);
    CHECK(q_periapt_sdk_key_generate(original, &key) == 0);
    CHECK(q_periapt_sdk_key_public(key, OUT(previous_public)) == 0);
    uint8_t statement[Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN];
    CHECK(q_periapt_sdk_runtime_prepare_recovery(original, IN(operation), IN(next_policy), IN(next_signature), IN(incoming_root), OUT(statement)) == 0);
    CHECK(memcmp(statement, request, sizeof(statement)) == 0);
    uint8_t approval_message[Q_PERIAPT_POLICY_RECOVERY_APPROVAL_MESSAGE_LEN];
    uint8_t possession_message[Q_PERIAPT_POLICY_RECOVERY_POSSESSION_MESSAGE_LEN];
    CHECK(q_periapt_sdk_policy_recovery_signing_messages(IN(statement), OUT(approval_message), OUT(possession_message)) == 0);
    CHECK(memcmp(approval_message, expected_approval_message, sizeof(approval_message)) == 0);
    CHECK(memcmp(possession_message, expected_possession_message, sizeof(possession_message)) == 0);
    uint8_t authorization[Q_PERIAPT_POLICY_RECOVERY_AUTHORIZATION_LEN];
    memcpy(authorization, statement, sizeof(statement));
    memcpy(authorization + sizeof(statement), possession_signature, sizeof(possession_signature));
    memcpy(authorization + sizeof(statement) + sizeof(possession_signature), approval_signature, sizeof(approval_signature));
    CHECK(q_periapt_sdk_runtime_recover_authority(original, IN(authorization), IN(next_policy), IN(next_signature), &next, &disposition) == Q_PERIAPT_ERR_POLICY);
    CHECK(next == 0 && disposition == 0);
    CHECK(q_periapt_sdk_key_public(key, OUT(retained_public)) == 0);
    CHECK(memcmp(previous_public, retained_public, sizeof(previous_public)) == 0);
    memcpy(authorization + sizeof(statement), approval_signature, sizeof(approval_signature));
    memcpy(authorization + sizeof(statement) + sizeof(approval_signature), possession_signature, sizeof(possession_signature));
    CHECK(memcmp(authorization, expected_authorization, sizeof(authorization)) == 0);
    CHECK(q_periapt_sdk_runtime_recover_authority(original, IN(authorization), IN(next_policy), IN(next_signature), &next, &disposition) == 0);
    CHECK(next != 0 && disposition == Q_PERIAPT_POLICY_RECOVERY_APPLIED);
    CHECK(q_periapt_sdk_key_public(key, OUT(retained_public)) == Q_PERIAPT_ERR_CLOSED);
    CHECK(q_periapt_sdk_runtime_enabled(next, &enabled) == 0 && enabled == 0);
    CHECK(q_periapt_sdk_runtime_recover_authority(next, IN(authorization), IN(next_policy), IN(next_signature), &successor, &disposition) == 0);
    CHECK(successor == 0 && disposition == Q_PERIAPT_POLICY_RECOVERY_ALREADY_APPLIED);
    CHECK(q_periapt_sdk_runtime_update_store(next, IN(current_policy), IN(current_signature), &current) == 0);
    CHECK(q_periapt_sdk_key_generate(current, &key) == 0);
    CHECK(q_periapt_sdk_key_public(key, OUT(previous_public)) == 0);
    CHECK(q_periapt_sdk_runtime_recover_authority(current, IN(authorization), IN(next_policy), IN(next_signature), &successor, &disposition) == 0);
    CHECK(successor == 0 && disposition == Q_PERIAPT_POLICY_RECOVERY_APPLIED_THEN_ADVANCED);
    CHECK(q_periapt_sdk_key_public(key, OUT(retained_public)) == 0);
    CHECK(memcmp(previous_public, retained_public, sizeof(previous_public)) == 0);
    CHECK(q_periapt_sdk_close(current) == 0);
    options.enrollment_signature = (QPeriaptInput){NULL, 0};
    options.policy = IN(next_policy); options.signature = IN(next_signature);
    CHECK(q_periapt_sdk_runtime_open_recovering_store(&options, IN(authorization), &current, &disposition) == 0);
    CHECK(current != 0 && disposition == Q_PERIAPT_POLICY_RECOVERY_APPLIED_THEN_ADVANCED);
    CHECK(q_periapt_sdk_runtime_state(current, OUT(state)) == 0);
    CHECK(state[0] == 0 && state[1] == 0 && state[2] == 0 && state[3] == 2);
    CHECK(q_periapt_sdk_close(current) == 0);
    options.policy = IN(current_policy); options.signature = IN(current_signature);
    CHECK(q_periapt_sdk_runtime_open_recoverable_store(&options, &current) == 0);
    CHECK(q_periapt_sdk_runtime_enabled(current, &enabled) == 0 && enabled == 1);
    CHECK(q_periapt_sdk_close(current) == 0);
    puts("SDK_POLICY_RECOVERY_C_PASS");
    return 0;
}
