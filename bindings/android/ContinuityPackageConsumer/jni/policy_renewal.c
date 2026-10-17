/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "policy_codec.h"
#include <stdlib.h>
#include <string.h>

enum {
    POLICY_REQUEST = 1, POLICY_WITNESSED_REQUEST, POLICY_STATUS, POLICY_RECONCILE,
    POLICY_APPROVAL, POLICY_PREPARE, POLICY_PREPARATION, POLICY_PROGRESS,
    POLICY_COMMIT, POLICY_WITNESS_RECONCILE, POLICY_CLOSE, POLICY_STAGE,
    POLICY_RESOLVE, POLICY_ACTIVATE, POLICY_FIELDS = 17
};
_Static_assert(POLICY_FIELDS <= QPJ_INPUT_FIELD_LIMIT, "policy shape exceeds JNI input capacity");
static void document_shape(jsize *minimum, jsize *maximum) {
    const jsize low[] = {32,1985,8,32,1}, high[] = {32,1985,8,32,8192};
    memcpy(minimum, low, sizeof(low)); memcpy(maximum, high, sizeof(high));
}
static void pin_shape(jsize *minimum, jsize *maximum) {
    const jsize sizes[] = {32,1985,32,8,32};
    memcpy(minimum, sizes, sizeof(sizes)); memcpy(maximum, sizes, sizeof(sizes));
}
static int shape(jint operation, jsize minimum[POLICY_FIELDS], jsize maximum[POLICY_FIELDS], size_t *count, jsize *length) {
    switch (operation) {
        case POLICY_REQUEST: case POLICY_WITNESSED_REQUEST: case POLICY_APPROVAL:
            *count = 1; minimum[0] = maximum[0] = 32;
            *length = operation == POLICY_APPROVAL ? 8196 : QPJ_POLICY_REQUEST_BYTES; return 1;
        case POLICY_STATUS: case POLICY_RECONCILE: *count = 0; *length = 160; return 1;
        case POLICY_PREPARE: *count = 5; *length = 296; document_shape(minimum, maximum); return 1;
        case POLICY_PREPARATION: *count = 0; *length = 304; return 1;
        case POLICY_PROGRESS: *count = 0; *length = 344; return 1;
        case POLICY_COMMIT: case POLICY_WITNESS_RECONCILE: case POLICY_CLOSE:
            *count = 1; minimum[0] = maximum[0] = 296; *length = 4; return 1;
        case POLICY_STAGE:
            *count = 17; *length = 160; minimum[0] = maximum[0] = QPJ_POLICY_REQUEST_BYTES;
            pin_shape(minimum + 1, maximum + 1); pin_shape(minimum + 6, maximum + 6);
            minimum[11] = maximum[11] = QPJ_POLICY_APPROVAL_BYTES;
            document_shape(minimum + 12, maximum + 12); return 1;
        case POLICY_RESOLVE:
            *count = 7; *length = 160; minimum[0] = maximum[0] = minimum[1] = maximum[1] = 32;
            document_shape(minimum + 2, maximum + 2); return 1;
        case POLICY_ACTIVATE: *count = 0; *length = 0; return 1;
        default: return 0;
    }
}

jbyteArray qpj_policy_command(JNIEnv *env, jclass type, jlong handle, jint operation, jobjectArray inputs) {
    (void)type;
    const char *name = "independent-policy-renewal";
    if (!qpj_enter(env, name)) return NULL;
    owned_bytes values[POLICY_FIELDS] = {{0}};
    jsize minimum[POLICY_FIELDS] = {0}, maximum[POLICY_FIELDS] = {0}, length = 0;
    size_t count = 0;
    uint8_t *wire = NULL;
    qpc_policy_renewal_request_v1 *request = NULL;
    qpc_public_record_v1 *approval = NULL;
    jbyteArray output = NULL;
    if (!shape(operation, minimum, maximum, &count, &length)) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "policy operation"); goto cleanup;
    }
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, count)) goto cleanup;
    /* The 33-KiB request and public-record outputs never occupy the ART worker stack.
     * All result allocations precede any call that can mutate or transfer an owner. */
    wire = calloc((size_t)(length == 0 ? 1 : length), 1);
    if (wire == NULL) { qpj_throw_class(env, "java/lang/OutOfMemoryError", "policy result"); goto cleanup; }
    if (operation == POLICY_REQUEST || operation == POLICY_WITNESSED_REQUEST || operation == POLICY_STAGE) {
        request = calloc(1, sizeof(*request));
        if (request == NULL) { qpj_throw_class(env, "java/lang/OutOfMemoryError", "policy request"); goto cleanup; }
    }
    if (operation == POLICY_STAGE && !qpj_policy_request_decode(request, values[0].data)) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "policy request public records"); goto cleanup;
    }
    if (operation == POLICY_APPROVAL) {
        approval = calloc(1, sizeof(*approval));
        if (approval == NULL) { qpj_throw_class(env, "java/lang/OutOfMemoryError", "policy approval"); goto cleanup; }
    }
    output = (*env)->NewByteArray(env, length); if (output == NULL) goto cleanup;
    qpc_policy_renewal_status_v1 status = {0};
    qpc_policy_document_v1 document = {0};
    qpc_independent_policy_proposal_v1 proposal = {{0}};
    qpc_error_v1 error = {0};
    uint32_t observed = 0;
    int32_t code;
    switch (operation) {
        case POLICY_REQUEST:
            code = qpc_enrollment_v1_policy_renewal_request((uint64_t)handle, values[0].data, request, &error);
            if (code == 0) qpj_policy_request_encode(wire, request);
            break;
        case POLICY_WITNESSED_REQUEST:
            code = qpc_enrollment_v1_witnessed_policy_renewal_request((uint64_t)handle, values[0].data, request, &error);
            if (code == 0) qpj_policy_request_encode(wire, request);
            break;
        case POLICY_STATUS: code = qpc_enrollment_v1_policy_renewal_status((uint64_t)handle, &status, &error); break;
        case POLICY_RECONCILE: code = qpc_enrollment_v1_reconcile_policy_renewal((uint64_t)handle, &status, &error); break;
        case POLICY_APPROVAL:
            code = qpc_enrollment_v1_pending_policy_renewal_approval((uint64_t)handle, values[0].data, approval, &error);
            if (code == 0) { qpj_policy_put32(wire, approval->length); memcpy(wire + 4, approval->bytes, 8192); }
            break;
        case POLICY_PREPARE:
            qpj_policy_document(&document, values);
            code = qpc_enrollment_v1_prepare_witnessed_policy_renewal((uint64_t)handle, &document, &proposal, &error);
            if (code == 0) memcpy(wire, proposal.bytes, sizeof(proposal.bytes));
            break;
        case POLICY_PREPARATION: {
            qpc_independent_policy_preparation_v1 preparation = {0};
            code = qpc_enrollment_v1_recover_witnessed_policy_renewal_preparation((uint64_t)handle, &preparation, &error);
            if (code == 0) {
                qpj_policy_put32(wire, preparation.present); qpj_policy_put32(wire + 4, preparation.reserved);
                memcpy(wire + 8, preparation.proposal.bytes, sizeof(preparation.proposal.bytes));
            }
            break;
        }
        case POLICY_PROGRESS: {
            qpc_independent_policy_progress_v1 progress = {0};
            code = qpc_enrollment_v1_witnessed_policy_renewal_progress((uint64_t)handle, &progress, &error);
            if (code == 0) {
                qpj_policy_put32(wire, progress.phase); qpj_policy_put32(wire + 4, progress.retired);
                memcpy(wire + 8, progress.proposal.bytes, sizeof(progress.proposal.bytes));
                qpj_policy_put64(wire + 304, progress.target.version); memcpy(wire + 312, progress.target.digest, 32);
            }
            break;
        }
        case POLICY_COMMIT: case POLICY_WITNESS_RECONCILE: case POLICY_CLOSE:
            memcpy(proposal.bytes, values[0].data, sizeof(proposal.bytes));
            if (operation == POLICY_COMMIT) code = qpc_enrollment_v1_commit_witnessed_policy_renewal((uint64_t)handle, &proposal, &observed, &error);
            else if (operation == POLICY_CLOSE) code = qpc_enrollment_v1_close_witnessed_policy_renewal((uint64_t)handle, &proposal, &observed, &error);
            else code = qpc_enrollment_v1_reconcile_witnessed_policy_renewal((uint64_t)handle, &proposal, &observed, &error);
            if (code == 0) qpj_policy_put32(wire, observed);
            break;
        case POLICY_STAGE: {
            qpc_account_pin_v1 original = {0}, current = {0};
            qpj_policy_pin(&original, values + 1); qpj_policy_pin(&current, values + 6);
            qpj_policy_document(&document, values + 12);
            code = qpc_enrollment_v1_stage_policy_renewal((uint64_t)handle, request, &original, &current,
                values[11].data, values[11].length, &document, &status, &error);
            break;
        }
        case POLICY_RESOLVE:
            qpj_policy_document(&document, values + 2);
            code = qpc_enrollment_v1_resolve_policy_renewal((uint64_t)handle, values[0].data, values[1].data, &document, &status, &error);
            break;
        case POLICY_ACTIVATE: code = qpc_enrollment_v1_activate_policy_renewal((uint64_t)handle, &error); break;
        default: qpj_throw_class(env, "java/lang/IllegalArgumentException", "policy operation"); goto cleanup;
    }
    if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
    if (length == 160) qpj_policy_status_encode(wire, &status);
    if (length != 0) (*env)->SetByteArrayRegion(env, output, 0, length, (const jbyte *)wire);
cleanup:
    for (size_t i = 0; i < POLICY_FIELDS; ++i) qpj_dispose(&values[i]);
    free(request); free(approval); free(wire); qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}

void qpj_select_policy(JNIEnv *env, jclass type, jlong configuration, jlong enrollment) {
    (void)type;
    const char *name = "policy-target-selection";
    if (!qpj_enter(env, name)) return;
    qpc_error_v1 error = {0};
    int32_t code = qpc_configuration_v1_select_continued_policy((uint64_t)configuration, (uint64_t)enrollment, &error);
    if (code != 0) qpj_throw_error(env, name, code, &error);
    qpj_leave();
}
