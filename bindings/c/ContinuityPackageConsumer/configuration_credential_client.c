/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Credential renewal of the original independently configured enrollment. */
_Static_assert(sizeof(qpc_credential_renewal_status_v1) <= sizeof(qpc_policy_renewal_request_v1), "credential status buffer");
_Static_assert(sizeof(qpc_credential_renewal_proposal_v1) <= sizeof(qpc_policy_renewal_request_v1), "credential proposal buffer");
_Static_assert(offsetof(qpc_credential_renewal_status_v1, operation) == 4, "credential operation offset");
_Static_assert(offsetof(qpc_credential_renewal_status_v1, statement) == 36, "credential statement offset");
_Static_assert(offsetof(qpc_credential_renewal_status_v1, checkpoint) == 72, "credential checkpoint offset");
_Static_assert(offsetof(qpc_credential_renewal_status_v1, observed_at) == 112, "credential observation offset");
static int credential_operation(uint64_t enrollment, uint64_t *registry,
                                const char *source, const char *mode,
                                uint8_t *output, size_t *length, qpc_error_v1 *error) {
    qpc_credential_renewal_status_v1 status = {0};
    int32_t code;
    if (!strcmp(mode, "credential-expired-request")) {
        qpc_enrollment_request_v1 request = {0};
        code = qpc_enrollment_v1_request(enrollment, &request, error);
        if (code != QPC_VALIDITY || error->code != QPC_VALIDITY) { (void)checked(code, error); return 1; }
        memcpy(output, &code, sizeof code); *length = sizeof code; return 0;
    }
    if (!strcmp(mode, "credential-activate") || !strcmp(mode, "credential-expired") ||
        !strcmp(mode, "credential-activation-unmanaged")) {
        qpc_enrollment_status_v1 identity = {0};
        if (checked(qpc_enrollment_v1_status(enrollment, &identity, error), error)) return 1;
        code = qpc_enrollment_v1_activate(enrollment, error);
        if (strcmp(mode, "credential-activate")) {
            int32_t expected = !strcmp(mode, "credential-expired") ? QPC_VALIDITY : QPC_SCOPE_CONFLICT;
            if (code != expected || error->code != expected) { (void)checked(code, error); return 1; }
            memcpy(output, &code, sizeof code); *length = sizeof code; return 0;
        }
        if (checked(code, error)) return 1;
        memcpy(output, identity.signing_id, 32); memcpy(output + 32, identity.journal, 32);
        *length = 64; return 0;
    }
    if (!strcmp(mode, "credential-identity")) {
        qpc_enrollment_status_v1 identity = {0};
        if (checked(qpc_enrollment_v1_status(enrollment, &identity, error), error)) return 1;
        memcpy(output, identity.signing_id, 32); memcpy(output + 32, identity.journal, 32);
        *length = 64; return 0;
    }
    if (!strcmp(mode, "credential-prepare")) {
        qpc_credential_renewal_proposal_v1 proposal = {0};
        code = qpc_enrollment_v1_prepare_witnessed_credential_renewal(enrollment, &proposal, error);
        if (checked(code, error)) return 1;
        memcpy(output, proposal.bytes, sizeof proposal.bytes);
        *length = sizeof proposal.bytes;
        return 0;
    }
    qpc_configuration_blob_v1 operation = load(source, "credential-operation", 32);
    if (!exact(operation, 32)) return 1;
    if (!strcmp(mode, "credential-stage") || !strcmp(mode, "credential-stage-refused")) {
        qpc_configuration_blob_v1 wire = load(source, "credential-renewal", 65536);
        qpc_configuration_blob_v1 root = load(source, "enrollment-root", 1985);
        qpc_configuration_blob_v1 account = load(source, "trusted-account", 32);
        qpc_configuration_blob_v1 family = load(source, "family", 32);
        qpc_configuration_blob_v1 version = load(source, "renewal-version", 8);
        qpc_configuration_blob_v1 digest = load(source, "renewal-digest", 32);
        if (!wire.data || !exact(root, 1985) || !exact(account, 32) || !exact(family, 32) ||
            !exact(version, 8) || !exact(digest, 32)) return 1;
        qpc_account_pin_v1 pin = {0};
        pin.root = root.data; pin.root_length = root.length;
        memcpy(pin.account, account.data, 32); memcpy(pin.family, family.data, 32);
        pin.checkpoint.version = be64(version.data); memcpy(pin.checkpoint.digest, digest.data, 32);
        int refused = !strcmp(mode, "credential-stage-refused");
        if (refused) ((uint8_t *)wire.data)[wire.length - 1] ^= 1;
        code = qpc_enrollment_v1_stage_credential_renewal(enrollment, wire.data, wire.length,
                                                        &pin, operation.data, &status, error);
        if (refused) {
            if (code != QPC_AUTHENTICATION || error->code != QPC_AUTHENTICATION) { (void)checked(code, error); return 1; }
            qpc_enrollment_status_v1 disposed = {0};
            if (qpc_enrollment_v1_status(enrollment, &disposed, error) != QPC_CLOSED || error->code != QPC_CLOSED) return 1;
            memcpy(output, &code, sizeof code); *length = sizeof code;
            return 0;
        }
    } else {
        qpc_configuration_blob_v1 statement = load(source, "credential-statement", 32);
        if (!exact(statement, 32)) return 1;
        int closed = !strcmp(mode, "credential-commit-closed");
        int unmanaged = !strcmp(mode, "credential-commit-unmanaged");
        int unknown = !strcmp(mode, "credential-commit-unknown");
        if (closed) {
            if (!*registry || checked(qpc_owner_v1_close(*registry, error), error)) return 1;
            *registry = 0;
        }
        if (!strcmp(mode, "credential-reconcile")) {
            code = qpc_enrollment_v1_reconcile_witnessed_credential_renewal(
                enrollment, operation.data, statement.data, &status, error);
        } else if (!strcmp(mode, "credential-commit") || closed || unmanaged || unknown) {
            qpc_credential_renewal_status_v1 untouched;
            memset(&status, 0xa5, sizeof status); memcpy(&untouched, &status, sizeof status);
            code = qpc_enrollment_v1_commit_witnessed_credential_renewal(
                enrollment, operation.data, statement.data, &status, error);
            if (closed || unmanaged || unknown) {
                int32_t expected = closed ? QPC_DURABLE_CLOSED : unmanaged ? QPC_SCOPE_CONFLICT : QPC_ANCHOR;
                if (code != expected || error->code != expected || memcmp(&status, &untouched, sizeof status)) { (void)checked(code, error); return 1; }
                qpc_enrollment_status_v1 disposed = {0};
                int32_t after = qpc_enrollment_v1_status(enrollment, &disposed, error);
                if (after != QPC_CLOSED || error->code != QPC_CLOSED) return 1;
                memcpy(output, &code, sizeof code); *length = sizeof code;
                return 0;
            }
        } else {
            return 1;
        }
    }
    if (checked(code, error)) return 1;
    /* Serialize named ABI fields; padding is not a public readback. */
    memset(output, 0, sizeof status);
    memcpy(output, &status.phase, 4);
    memcpy(output + 4, status.operation, 32); memcpy(output + 36, status.statement, 32);
    memcpy(output + 72, &status.checkpoint.version, 8);
    memcpy(output + 80, status.checkpoint.digest, 32);
    memcpy(output + 112, &status.observed_at, 8);
    *length = sizeof status;
    return 0;
}
