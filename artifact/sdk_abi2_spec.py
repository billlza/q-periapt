"""Closed, reviewed 0.2.0 extension to the retained C ABI major 2.

This does not replace the immutable 0.1.5 nine-symbol contract. Changes to these
declarations/layouts and their machine-readable snapshot require explicit review.
"""

PACKAGE_SEMVER = "0.2.0"
JNI_METHODS = {
    "sdkExtensionVersionNative": "()I",
    "sdkRuntimeNewNative": "([B[B[B[BII)J",
    "sdkRuntimeStateNative": "(J)[B",
    "sdkRuntimeEnabledNative": "(J)Z",
    "sdkRuntimePrepareUpdateNative": "(J[B[B)J",
    "sdkPolicyUpdateStatesNative": "(J)[B",
    "sdkPolicyUpdateActivateNative": "(J)J",
    "sdkExpertKeyImportNative": "(J[B)J",
    "sdkExpertKeyExportNative": "(J)[B",
    "sdkKeyGenerateNative": "(J)J",
    "sdkKeyPublicNative": "(J)[B",
    "sdkEncapsulateNative": "(J[B[B[B)J",
    "sdkDecapsulateNative": "(J[B[B)J",
    "sdkSecretExportNative": "(J)[B",
    "sdkSecretDeriveNative": "(JI[B[B)J",
    "sdkDerivedKeyExportNative": "(J)[B",
    "sdkCloseNative": "(J)V",
}
STATUS_CODES = {
    "Q_PERIAPT_ERR_CLOSED": -9,
    "Q_PERIAPT_ERR_RESOURCE_LIMIT": -10,
    "Q_PERIAPT_ERR_LIMITS": -11,
    "Q_PERIAPT_ERR_PURPOSE": -12,
    "Q_PERIAPT_ERR_INVALID_PRIVATE_KEY": -13,
    "Q_PERIAPT_ERR_TLS": -14,
    "Q_PERIAPT_ERR_TIMEOUT": -15,
    "Q_PERIAPT_ERR_PROTOCOL": -16,
    "Q_PERIAPT_ERR_NOT_READY": -17,
    "Q_PERIAPT_ERR_IO": -18,
    "Q_PERIAPT_ERR_STORAGE": -19,
    "Q_PERIAPT_ERR_STORE_BUSY": -20,
    "Q_PERIAPT_ERR_COMMIT_UNCERTAIN": -21,
    "Q_PERIAPT_ERR_STORE_COMMITTED": -22,
    "Q_PERIAPT_ERR_UNSUPPORTED_PLATFORM": -23,
    "Q_PERIAPT_ERR_STORAGE_REQUIRED": -24,
    "Q_PERIAPT_ERR_RECOVERY_REQUIRED": -25,
}
MACROS = {
    **STATUS_CODES,
    "Q_PERIAPT_SDK_EXTENSION_VERSION": 1,
    "Q_PERIAPT_SDK_MAX_HANDLES": 1024,
    "Q_PERIAPT_SDK_MAX_CALLS": 64,
    "Q_PERIAPT_SDK_PUBLIC_KEY_LEN": 1216,
    "Q_PERIAPT_SDK_CIPHERTEXT_LEN": 1120,
    "Q_PERIAPT_SDK_EXPANDED_KEY_LEN": 2440,
    "Q_PERIAPT_SDK_POLICY_UPDATE_STATES_LEN": 72,
    "Q_PERIAPT_SDK_MAX_PROTOCOL_LABEL_BYTES": 255,
    "Q_PERIAPT_PURPOSE_INITIATOR_TRAFFIC": 1,
    "Q_PERIAPT_PURPOSE_RESPONDER_TRAFFIC": 2,
    "Q_PERIAPT_PURPOSE_INITIATOR_CONFIRMATION": 3,
    "Q_PERIAPT_PURPOSE_RESPONDER_CONFIRMATION": 4,
    "Q_PERIAPT_PURPOSE_EXPORTER": 5,
    "Q_PERIAPT_CONNECTION_MAX_PAYLOAD_BYTES": 65536,
    "Q_PERIAPT_CONNECTION_MAX_TLS_IO_BYTES": 16384,
    "Q_PERIAPT_CONNECTION_HANDSHAKING": 1,
    "Q_PERIAPT_CONNECTION_CONFIRMING": 2,
    "Q_PERIAPT_CONNECTION_READY": 3,
    "Q_PERIAPT_CONNECTION_REQUEST_PENDING": 4,
    "Q_PERIAPT_CONNECTION_REQUEST_READY": 5,
    "Q_PERIAPT_CONNECTION_HANDLING_REQUEST": 6,
    "Q_PERIAPT_CONNECTION_RESPONSE_READY": 7,
    "Q_PERIAPT_CONNECTION_CLOSING": 8,
    "Q_PERIAPT_STORE_MAX_PATH_BYTES": 4096,
    "Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN": 2168,
    "Q_PERIAPT_POLICY_RECOVERY_AUTHORIZATION_LEN": 8786,
    "Q_PERIAPT_POLICY_RECOVERY_ENROLLMENT_MESSAGE_LEN": 3968,
    "Q_PERIAPT_POLICY_RECOVERY_APPROVAL_MESSAGE_LEN": 2203,
    "Q_PERIAPT_POLICY_RECOVERY_POSSESSION_MESSAGE_LEN": 2204,
    "Q_PERIAPT_POLICY_RECOVERY_APPLIED": 1,
    "Q_PERIAPT_POLICY_RECOVERY_ALREADY_APPLIED": 2,
    "Q_PERIAPT_POLICY_RECOVERY_APPLIED_THEN_ADVANCED": 3,
}
EXPORTS = (
    ("q_periapt_sdk_extension_version", "metadata", "uint32_t q_periapt_sdk_extension_version(void);"),
    ("q_periapt_sdk_runtime_new", "runtime", "int32_t q_periapt_sdk_runtime_new(const QPeriaptRuntimeOptions *options, uint64_t *out_runtime);"),
    ("q_periapt_sdk_runtime_state", "runtime", "int32_t q_periapt_sdk_runtime_state(uint64_t handle, QPeriaptOutput output);"),
    ("q_periapt_sdk_runtime_enabled", "runtime", "int32_t q_periapt_sdk_runtime_enabled(uint64_t handle, uint32_t *out_enabled);"),
    ("q_periapt_sdk_runtime_prepare_update", "policy", "int32_t q_periapt_sdk_runtime_prepare_update(uint64_t handle, QPeriaptInput policy, QPeriaptInput signature, uint64_t *out_update);"),
    ("q_periapt_sdk_policy_update_states", "policy", "int32_t q_periapt_sdk_policy_update_states(uint64_t handle, QPeriaptOutput output);"),
    ("q_periapt_sdk_policy_update_activate", "policy", "int32_t q_periapt_sdk_policy_update_activate(uint64_t handle, uint64_t *out_runtime);"),
    ("q_periapt_sdk_expert_key_import", "key_management", "int32_t q_periapt_sdk_expert_key_import(uint64_t handle, QPeriaptInput encoded, uint64_t *out_key);"),
    ("q_periapt_sdk_expert_key_export", "expert_export", "int32_t q_periapt_sdk_expert_key_export(uint64_t handle, QPeriaptOutput output);"),
    ("q_periapt_sdk_key_generate", "key_management", "int32_t q_periapt_sdk_key_generate(uint64_t handle, uint64_t *out_key);"),
    ("q_periapt_sdk_key_public", "key_management", "int32_t q_periapt_sdk_key_public(uint64_t handle, QPeriaptOutput output);"),
    ("q_periapt_sdk_encapsulate", "operation", "int32_t q_periapt_sdk_encapsulate(uint64_t handle, QPeriaptInput peer, QPeriaptInput context, QPeriaptOutput ciphertext, uint64_t *out_secret);"),
    ("q_periapt_sdk_decapsulate", "operation", "int32_t q_periapt_sdk_decapsulate(uint64_t handle, QPeriaptInput ciphertext, QPeriaptInput context, uint64_t *out_secret);"),
    ("q_periapt_sdk_secret_export", "expert_export", "int32_t q_periapt_sdk_secret_export(uint64_t handle, QPeriaptOutput output);"),
    ("q_periapt_sdk_secret_derive", "operation", "int32_t q_periapt_sdk_secret_derive(uint64_t handle, uint32_t purpose, QPeriaptInput protocol_label, QPeriaptInput context, uint64_t *out_key);"),
    ("q_periapt_sdk_derived_key_export", "expert_export", "int32_t q_periapt_sdk_derived_key_export(uint64_t handle, QPeriaptOutput output);"),
    ("q_periapt_sdk_close", "lifecycle", "int32_t q_periapt_sdk_close(uint64_t handle);"),
    ("q_periapt_sdk_connection_client_new", "connection", "int32_t q_periapt_sdk_connection_client_new(uint64_t handle, const QPeriaptConnectionOptions *options, uint64_t *out_endpoint);"),
    ("q_periapt_sdk_connection_server_new", "connection", "int32_t q_periapt_sdk_connection_server_new(uint64_t handle, const QPeriaptConnectionOptions *options, uint64_t *out_endpoint);"),
    ("q_periapt_sdk_connection_connect", "connection", "int32_t q_periapt_sdk_connection_connect(uint64_t handle, QPeriaptInput server_name, uint64_t *out_connection);"),
    ("q_periapt_sdk_connection_accept", "connection", "int32_t q_periapt_sdk_connection_accept(uint64_t handle, uint64_t *out_connection);"),
    ("q_periapt_sdk_connection_progress", "connection", "int32_t q_periapt_sdk_connection_progress(uint64_t handle, QPeriaptConnectionProgress *output);"),
    ("q_periapt_sdk_connection_feed", "connection", "int32_t q_periapt_sdk_connection_feed(uint64_t handle, QPeriaptInput ciphertext, uint32_t *out_consumed);"),
    ("q_periapt_sdk_connection_drain", "connection", "int32_t q_periapt_sdk_connection_drain(uint64_t handle, QPeriaptOutput output, uint32_t *out_written);"),
    ("q_periapt_sdk_connection_end_input", "connection", "int32_t q_periapt_sdk_connection_end_input(uint64_t handle);"),
    ("q_periapt_sdk_connection_send_request", "connection", "int32_t q_periapt_sdk_connection_send_request(uint64_t handle, QPeriaptInput payload, uint64_t *out_request_id);"),
    ("q_periapt_sdk_connection_message_size", "connection", "int32_t q_periapt_sdk_connection_message_size(uint64_t handle, uint32_t *out_length);"),
    ("q_periapt_sdk_connection_take_request", "connection", "int32_t q_periapt_sdk_connection_take_request(uint64_t handle, QPeriaptOutput output, uint32_t *out_length, uint64_t *out_request_id);"),
    ("q_periapt_sdk_connection_take_response", "connection", "int32_t q_periapt_sdk_connection_take_response(uint64_t handle, QPeriaptOutput output, uint32_t *out_length, uint64_t *out_request_id);"),
    ("q_periapt_sdk_connection_send_response", "connection", "int32_t q_periapt_sdk_connection_send_response(uint64_t handle, uint64_t request_id, QPeriaptInput payload);"),
    ("q_periapt_sdk_connection_shutdown", "connection", "int32_t q_periapt_sdk_connection_shutdown(uint64_t handle);"),
    ("q_periapt_sdk_runtime_provision_store", "persistence", "int32_t q_periapt_sdk_runtime_provision_store(const QPeriaptStoreOptions *options, uint64_t *out_runtime);"),
    ("q_periapt_sdk_runtime_open_store", "persistence", "int32_t q_periapt_sdk_runtime_open_store(const QPeriaptStoreOptions *options, uint64_t *out_runtime);"),
    ("q_periapt_sdk_runtime_update_store", "persistence", "int32_t q_periapt_sdk_runtime_update_store(uint64_t handle, QPeriaptInput policy, QPeriaptInput signature, uint64_t *out_runtime);"),
    ("q_periapt_sdk_policy_recovery_enrollment_message", "policy", "int32_t q_periapt_sdk_policy_recovery_enrollment_message(QPeriaptInput scope, QPeriaptInput initial_root, QPeriaptInput recovery_root, QPeriaptOutput output);"),
    ("q_periapt_sdk_runtime_provision_recoverable_store", "persistence", "int32_t q_periapt_sdk_runtime_provision_recoverable_store(const QPeriaptRecoverableStoreOptions *options, uint64_t *out_runtime);"),
    ("q_periapt_sdk_runtime_open_recoverable_store", "persistence", "int32_t q_periapt_sdk_runtime_open_recoverable_store(const QPeriaptRecoverableStoreOptions *options, uint64_t *out_runtime);"),
    ("q_periapt_sdk_runtime_enroll_recovery_store", "persistence", "int32_t q_periapt_sdk_runtime_enroll_recovery_store(const QPeriaptRecoverableStoreOptions *options, uint64_t *out_runtime);"),
    ("q_periapt_sdk_runtime_open_recovering_store", "persistence", "int32_t q_periapt_sdk_runtime_open_recovering_store(const QPeriaptRecoverableStoreOptions *options, QPeriaptInput authorization, uint64_t *out_runtime, uint32_t *out_outcome);"),
    ("q_periapt_sdk_runtime_prepare_recovery", "policy", "int32_t q_periapt_sdk_runtime_prepare_recovery(uint64_t handle, QPeriaptInput operation, QPeriaptInput policy, QPeriaptInput signature, QPeriaptInput incoming_root, QPeriaptOutput output);"),
    ("q_periapt_sdk_policy_recovery_signing_messages", "policy", "int32_t q_periapt_sdk_policy_recovery_signing_messages(QPeriaptInput request, QPeriaptOutput approval, QPeriaptOutput possession);"),
    ("q_periapt_sdk_runtime_recover_authority", "persistence", "int32_t q_periapt_sdk_runtime_recover_authority(uint64_t handle, QPeriaptInput authorization, QPeriaptInput policy, QPeriaptInput signature, uint64_t *out_runtime, uint32_t *out_outcome);"),
)
NATIVE_STRUCTS = {
    "QPeriaptInput": "typedef struct { const uint8_t *data; uintptr_t len; } QPeriaptInput;",
    "QPeriaptOutput": "typedef struct { uint8_t *data; uintptr_t len; } QPeriaptOutput;",
    "QPeriaptRuntimeOptions": (
        "typedef struct { uint32_t struct_size; uint32_t extension_version; "
        "QPeriaptInput policy; QPeriaptInput signature; QPeriaptInput trust_root; "
        "QPeriaptInput previous_state; uint32_t max_live_keys; uint32_t max_in_flight; "
        "} QPeriaptRuntimeOptions;"
    ),
    "QPeriaptConnectionOptions": (
        "typedef struct { uint32_t struct_size; uint32_t extension_version; "
        "QPeriaptInput certificate; QPeriaptInput private_key; QPeriaptInput peer_certificate; "
        "QPeriaptInput application_context; uint32_t max_connections; uint32_t handshake_ms; "
        "uint32_t request_ms; uint32_t idle_ms; } QPeriaptConnectionOptions;"
    ),
    "QPeriaptConnectionProgress": (
        "typedef struct { uint32_t phase; uint32_t wants_write; uint32_t remaining_ms; } QPeriaptConnectionProgress;"
    ),
    "QPeriaptStoreOptions": (
        "typedef struct { uint32_t struct_size; uint32_t extension_version; "
        "QPeriaptInput path; QPeriaptInput policy; QPeriaptInput signature; QPeriaptInput trust_root; "
        "uint32_t max_live_keys; uint32_t max_in_flight; } QPeriaptStoreOptions;"
    ),
    "QPeriaptRecoverableStoreOptions": (
        "typedef struct { uint32_t struct_size; uint32_t extension_version; "
        "QPeriaptInput path; QPeriaptInput policy; QPeriaptInput signature; QPeriaptInput scope; "
        "QPeriaptInput initial_root; QPeriaptInput recovery_root; QPeriaptInput enrollment_signature; "
        "uint32_t max_live_keys; uint32_t max_in_flight; } QPeriaptRecoverableStoreOptions;"
    ),
}
