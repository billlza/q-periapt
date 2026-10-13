/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Included by the qualification consumer; uses existing original enrollment APIs. */
_Static_assert(sizeof(qpc_credential_renewal_request_v1) == 33120, "public G request layout");
static int policy_credential_operation(uint64_t enrollment, const char *source, const char *path,
    int recoverable, unsigned carrier, const char *mode, uint8_t *output, size_t *length, qpc_error_v1 *error) {
    qpc_credential_renewal_status_v1 status = {0}; int32_t code;
    if (!strcmp(mode, "policy-credential-request") || !strcmp(mode, "policy-credential-next-request")) {
        qpc_configuration_blob_v1 operation = load(source,
            !strcmp(mode, "policy-credential-next-request") ? "credential-next-operation" : "credential-operation", 32);
        if (!exact(operation, 32)) return 1;
        qpc_credential_renewal_request_v1 *request = calloc(1, sizeof(*request));
        if (!request) return 1;
        code = carrier ? qpc_enrollment_v1_witnessed_credential_renewal_request(enrollment, operation.data, request, error)
            : qpc_enrollment_v1_credential_renewal_request(enrollment, operation.data, request, error);
        if (!code) { memcpy(output, request, sizeof(*request)); *length = sizeof(*request); }
        free(request); return checked(code, error);
    }
    if (!strcmp(mode, "policy-credential-status")) {
        code = qpc_enrollment_v1_credential_renewal_status(enrollment, &status, error);
    } else {
        int reconcile = !strcmp(mode, "policy-credential-reconcile"), close = !strcmp(mode, "policy-credential-close");
        if (!reconcile && !close && select_policy_target(enrollment, source, path, recoverable, error)) return 1;
        if (!strcmp(mode, "policy-credential-activate")) {
            qpc_enrollment_status_v1 identity = {0};
            if (checked(qpc_enrollment_v1_status(enrollment, &identity, error), error)
                || checked(qpc_enrollment_v1_activate_policy_renewal(enrollment, error), error)) return 1;
            memcpy(output, identity.signing_id, 32); memcpy(output + 32, identity.journal, 32); *length = 64; return 0;
        }
        qpc_configuration_blob_v1 operation = load(source, "credential-operation", 32);
        if (!exact(operation, 32)) return 1;
        if (!strcmp(mode, "policy-credential-stage") || !strcmp(mode, "policy-credential-stage-refused")) {
            qpc_configuration_blob_v1 grant = load(source, "credential-renewal", 65536), root = load(source, "enrollment-root", 1985),
                account = load(source, "trusted-account", 32), family = load(source, "family", 32),
                version = load(source, "renewal-version", 8), digest = load(source, "renewal-digest", 32);
            if (!grant.data || !exact(root, 1985) || !exact(account, 32) || !exact(family, 32) || !exact(version, 8) || !exact(digest, 32)) return 1;
            qpc_account_pin_v1 pin = {0}; pin.root = root.data; pin.root_length = root.length;
            memcpy(pin.account, account.data, 32); memcpy(pin.family, family.data, 32);
            pin.checkpoint.version = be64(version.data); memcpy(pin.checkpoint.digest, digest.data, 32);
            int refused = !strcmp(mode, "policy-credential-stage-refused");
            if (refused) ((uint8_t *)grant.data)[grant.length - 1] ^= 1;
            code = qpc_enrollment_v1_stage_continued_credential_renewal(enrollment, grant.data, grant.length, &pin, operation.data, &status, error);
            if (refused) {
                if (code != QPC_AUTHENTICATION || error->code != QPC_AUTHENTICATION) { (void)checked(code, error); return 1; }
                qpc_enrollment_status_v1 disposed = {0};
                if (qpc_enrollment_v1_status(enrollment, &disposed, error) != QPC_CLOSED || error->code != QPC_CLOSED) return 1;
                memcpy(output, &code, sizeof(code)); *length = sizeof(code); return 0;
            }
        } else if (!strcmp(mode, "policy-credential-prepare")) {
            qpc_policy_renewal_proposal_v1 proposal = {0};
            if (checked(qpc_enrollment_v1_prepare_witnessed_policy_continuation(enrollment, &proposal, error), error)) return 1;
            qpc_configuration_blob_v1 credential = load(source, "credential-statement", 32), policy = load(source, "renewal-statement", 32);
            if (!exact(credential, 32) || !exact(policy, 32) || proposal.length != 329 || memcmp(proposal.bytes, "QPCRNP03", 8)
                || memcmp(proposal.bytes + 136, operation.data, 32) || memcmp(proposal.bytes + 168, credential.data, 32)
                || proposal.bytes[296] || memcmp(proposal.bytes + 297, policy.data, 32)) return 1;
            memcpy(output, proposal.bytes, proposal.length); *length = proposal.length; return 0;
        } else {
            qpc_configuration_blob_v1 statement = load(source, "credential-statement", 32);
            if (!exact(statement, 32)) return 1;
            if (reconcile) code = qpc_enrollment_v1_reconcile_witnessed_credential_renewal(enrollment, operation.data, statement.data, &status, error);
            else if (close) code = qpc_enrollment_v1_close_witnessed_credential_renewal(enrollment, operation.data, statement.data, &status, error);
            else if (!strcmp(mode, "policy-credential-commit") || !strcmp(mode, "policy-credential-commit-unknown")) {
                qpc_credential_renewal_status_v1 untouched;
                memset(&status, 0xa5, sizeof(status)); memcpy(&untouched, &status, sizeof(status));
                code = qpc_enrollment_v1_commit_witnessed_policy_continuation(enrollment, operation.data, statement.data, &status, error);
                if (!strcmp(mode, "policy-credential-commit-unknown")) {
                    if (code != QPC_ANCHOR || error->code != QPC_ANCHOR || memcmp(&untouched, &status, sizeof(status))) { (void)checked(code, error); return 1; }
                    qpc_enrollment_status_v1 disposed = {0};
                    if (qpc_enrollment_v1_status(enrollment, &disposed, error) != QPC_CLOSED || error->code != QPC_CLOSED) return 1;
                    memcpy(output, &code, sizeof(code)); *length = sizeof(code); return 0;
                }
            } else return 1;
        }
    }
    if (checked(code, error)) return 1;
    memset(output, 0, sizeof(status));
    memcpy(output, &status.phase, 4); memcpy(output + 4, status.operation, 32); memcpy(output + 36, status.statement, 32);
    memcpy(output + 72, &status.checkpoint.version, 8); memcpy(output + 80, status.checkpoint.digest, 32);
    memcpy(output + 112, &status.observed_at, 8); *length = sizeof(status); return 0;
}
