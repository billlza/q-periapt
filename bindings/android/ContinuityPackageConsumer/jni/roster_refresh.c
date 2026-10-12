/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "policy_codec.h"
#include <string.h>

enum {
    ROSTER_REFRESH = 1, ROSTER_RESOLVE, ROSTER_PREPARE, ROSTER_PREPARATION,
    ROSTER_PROGRESS, ROSTER_ABANDON, ROSTER_COMMIT, ROSTER_RECONCILE, ROSTER_CLOSE,
    ROSTER_ADMIT_PEER, ROSTER_REFRESH_WITH_POLICY, ROSTER_FIELDS = 9
};
_Static_assert(ROSTER_FIELDS <= QPJ_INPUT_FIELD_LIMIT, "roster fields exceed JNI input capacity");
static void roster_checkpoint(qpc_roster_checkpoint_v1 *out, const uint8_t *in) {
    out->version = qpj_policy_u64(in); memcpy(out->digest, in + 8, 32);
}
static void checkpoint_write(uint8_t *out, uint64_t version, const uint8_t digest[32]) {
    qpj_policy_put64(out, version); memcpy(out + 8, digest, 32);
}
static void scope_write(uint8_t *out, const qpc_roster_refresh_scope_v1 *scope) {
    memcpy(out, scope->operation, 32);
    checkpoint_write(out + 32, scope->previous.version, scope->previous.digest);
    checkpoint_write(out + 72, scope->target.version, scope->target.digest);
    checkpoint_write(out + 112, scope->policy.version, scope->policy.digest);
    memcpy(out + 152, scope->policy_authorization, 32);
    qpj_policy_put32(out + 184, scope->has_policy_authorization); qpj_policy_put32(out + 188, scope->reserved);
}
static void progress_write(uint8_t *out, const qpc_roster_refresh_progress_v1 *progress) {
    qpj_policy_put32(out, progress->phase); qpj_policy_put32(out + 4, progress->retired);
    scope_write(out + 8, &progress->scope); memcpy(out + 200, progress->proposal.bytes, 417);
    memcpy(out + 617, progress->reserved, 7);
}
static void pin_shape(jsize *minimum, jsize *maximum) {
    const jsize sizes[] = {32,1985,32,8,32};
    memcpy(minimum, sizes, sizeof(sizes)); memcpy(maximum, sizes, sizeof(sizes));
}
static int shape(jint command, jsize minimum[ROSTER_FIELDS], jsize maximum[ROSTER_FIELDS], size_t *count, jsize *length) {
    switch (command) {
        case ROSTER_REFRESH:
            *count = 7; *length = 148; minimum[0] = maximum[0] = 40;
            minimum[1] = 1; maximum[1] = 8192; pin_shape(minimum + 2, maximum + 2); return 1;
        case ROSTER_REFRESH_WITH_POLICY:
            *count = 8; *length = 148; minimum[0] = maximum[0] = 40;
            minimum[1] = maximum[1] = 4; minimum[2] = 1; maximum[2] = 8192;
            pin_shape(minimum + 3, maximum + 3); return 1;
        case ROSTER_RESOLVE:
            *count = 2; *length = 168; minimum[0] = maximum[0] = minimum[1] = maximum[1] = 40; return 1;
        case ROSTER_PREPARE:
            *count = 9; *length = 417; minimum[0] = maximum[0] = 32; minimum[1] = maximum[1] = 4;
            minimum[2] = minimum[3] = 1; maximum[2] = maximum[3] = 8192;
            pin_shape(minimum + 4, maximum + 4); return 1;
        case ROSTER_PREPARATION: *count = 0; *length = 424; return 1;
        case ROSTER_PROGRESS: *count = 0; *length = 624; return 1;
        case ROSTER_ABANDON: *count = 1; *length = 624; minimum[0] = maximum[0] = 32; return 1;
        case ROSTER_COMMIT:
            *count = 2; *length = 4; minimum[0] = maximum[0] = 417; minimum[1] = maximum[1] = 4; return 1;
        case ROSTER_RECONCILE: case ROSTER_CLOSE:
            *count = 1; *length = 4; minimum[0] = maximum[0] = 417; return 1;
        case ROSTER_ADMIT_PEER:
            *count = 6; *length = 40; minimum[0] = 1; maximum[0] = 65536;
            pin_shape(minimum + 1, maximum + 1); return 1;
        default: return 0;
    }
}
jbyteArray qpj_roster_command(JNIEnv *env, jclass type, jlong handle, jint command, jobjectArray inputs) {
    (void)type;
    const char *name = "roster-refresh";
    if (!qpj_enter(env, name)) return NULL;
    owned_bytes values[ROSTER_FIELDS] = {{0}};
    jsize minimum[ROSTER_FIELDS] = {0}, maximum[ROSTER_FIELDS] = {0}, length = 0;
    size_t count = 0;
    uint8_t wire[624] = {0};
    jbyteArray output = NULL;
    if (!shape(command, minimum, maximum, &count, &length)) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "roster operation"); goto cleanup;
    }
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, count)) goto cleanup;
    uint32_t policy_source = 0;
    if (command == ROSTER_PREPARE || command == ROSTER_COMMIT || command == ROSTER_REFRESH_WITH_POLICY) {
        policy_source = qpj_policy_u32(values[1].data);
        if (policy_source > QPC_ROSTER_POLICY_SELECTED) {
            qpj_throw_class(env, "java/lang/IllegalArgumentException", "roster policy choice"); goto cleanup;
        }
    }
    output = (*env)->NewByteArray(env, length); if (output == NULL) goto cleanup;
    qpc_error_v1 error = {0};
    qpc_roster_checkpoint_v1 previous = {0}, target = {0};
    qpc_account_pin_v1 pin = {0};
    qpc_roster_refresh_progress_v1 progress = {0};
    qpc_roster_refresh_proposal_v1 proposal = {{0}};
    uint32_t observed = 0;
    int32_t code;
    switch (command) {
        case ROSTER_REFRESH: case ROSTER_REFRESH_WITH_POLICY: {
            size_t offset = command == ROSTER_REFRESH_WITH_POLICY ? 1 : 0;
            qpc_enrollment_status_v1 status = {0};
            roster_checkpoint(&previous, values[0].data); qpj_policy_pin(&pin, values + 2 + offset);
            if (command == ROSTER_REFRESH_WITH_POLICY)
                code = qpc_enrollment_v1_refresh_roster_with_policy((uint64_t)handle, policy_source, &previous, values[2].data, values[2].length, &pin, &status, &error);
            else code = qpc_enrollment_v1_refresh_roster((uint64_t)handle, &previous, values[1].data, values[1].length, &pin, &status, &error);
            if (code == 0) {
                qpj_policy_put32(wire, status.phase); memcpy(wire + 4, status.signing_id, 32); memcpy(wire + 36, status.journal, 32);
                checkpoint_write(wire + 68, status.previous.version, status.previous.digest);
                checkpoint_write(wire + 108, status.next.version, status.next.digest);
            }
            break;
        }
        case ROSTER_RESOLVE: {
            qpc_roster_refresh_resolution_v1 resolution = {0};
            roster_checkpoint(&previous, values[0].data); roster_checkpoint(&target, values[1].data);
            code = qpc_enrollment_v1_resolve_roster_refresh((uint64_t)handle, &previous, &target, &resolution, &error);
            if (code == 0) {
                qpj_policy_put32(wire, resolution.outcome); qpj_policy_put32(wire + 4, resolution.reserved);
                memcpy(wire + 8, resolution.journal, 32);
                checkpoint_write(wire + 40, resolution.previous.version, resolution.previous.digest);
                checkpoint_write(wire + 80, resolution.target.version, resolution.target.digest);
                checkpoint_write(wire + 120, resolution.observed.version, resolution.observed.digest);
                qpj_policy_put64(wire + 160, resolution.observed_at);
            }
            break;
        }
        case ROSTER_PREPARE: {
            qpj_policy_pin(&pin, values + 4);
            qpc_roster_refresh_target_v1 selected = {values[2].data, values[2].length, values[3].data, values[3].length, &pin};
            code = qpc_enrollment_v1_prepare_witnessed_roster_refresh((uint64_t)handle, values[0].data, policy_source, &selected, &proposal, &error);
            if (code == 0) memcpy(wire, proposal.bytes, 417);
            break;
        }
        case ROSTER_PREPARATION: {
            qpc_roster_refresh_preparation_v1 preparation = {0};
            code = qpc_enrollment_v1_recover_witnessed_roster_refresh_preparation((uint64_t)handle, &preparation, &error);
            if (code == 0) {
                qpj_policy_put32(wire, preparation.present); memcpy(wire + 4, preparation.proposal.bytes, 417);
                memcpy(wire + 421, preparation.reserved, 3);
            }
            break;
        }
        case ROSTER_PROGRESS:
            code = qpc_enrollment_v1_witnessed_roster_refresh_progress((uint64_t)handle, &progress, &error); break;
        case ROSTER_ABANDON:
            code = qpc_enrollment_v1_abandon_unprepared_roster_refresh((uint64_t)handle, values[0].data, &progress, &error); break;
        case ROSTER_COMMIT: case ROSTER_RECONCILE: case ROSTER_CLOSE:
            memcpy(proposal.bytes, values[0].data, 417);
            if (command == ROSTER_COMMIT) code = qpc_enrollment_v1_commit_witnessed_roster_refresh((uint64_t)handle, &proposal, policy_source, &observed, &error);
            else if (command == ROSTER_RECONCILE) code = qpc_enrollment_v1_reconcile_witnessed_roster_refresh((uint64_t)handle, &proposal, &observed, &error);
            else code = qpc_enrollment_v1_close_witnessed_roster_refresh((uint64_t)handle, &proposal, &observed, &error);
            if (code == 0) qpj_policy_put32(wire, observed);
            break;
        case ROSTER_ADMIT_PEER:
            qpj_policy_pin(&pin, values + 1);
            code = qpc_device_v1_admit_peer_roster((uint64_t)handle, values[0].data, values[0].length, &pin, &target, &error);
            if (code == 0) checkpoint_write(wire, target.version, target.digest);
            break;
        default: qpj_throw_class(env, "java/lang/IllegalArgumentException", "roster operation"); goto cleanup;
    }
    if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
    if (length == 624) progress_write(wire, &progress);
    (*env)->SetByteArrayRegion(env, output, 0, length, (const jbyte *)wire);
cleanup:
    for (size_t i = 0; i < ROSTER_FIELDS; ++i) qpj_dispose(&values[i]);
    qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}
