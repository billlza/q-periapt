/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "credential_codec.h"
#include <stdlib.h>
#include <string.h>

static void put32(uint8_t *output, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) output[i] = (uint8_t)(value >> (24 - 8 * i));
}
static void put64(uint8_t *output, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) output[i] = (uint8_t)(value >> (56 - 8 * i));
}
jbyteArray qpj_credential_command(JNIEnv *env, jclass type, jlong handle, jint operation, jobjectArray inputs, jlong version) {
    (void)type;
    const char *name = operation == 9 ? "peer-credential-admission" : "credential-renewal";
    if (!qpj_enter(env, name)) return NULL;
    owned_bytes values[14] = {{0}};
    jbyteArray output = NULL;
    uint8_t small_wire[333] = {0};
    uint8_t *wire = small_wire;
    qpc_credential_renewal_request_v1 *request = NULL;
    const int grant = operation == 2 || operation == 9 || operation == QPJ_CREDENTIAL_STAGE_CONTINUED;
    if (operation < 1 || operation > QPJ_CREDENTIAL_ACTIVATE_JOINT || (!grant && version != 0)) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "credential operation"); goto cleanup;
    }
    const int historical = operation == QPJ_CREDENTIAL_RECOVER_HISTORICAL;
    const int requesting = operation == QPJ_CREDENTIAL_REQUEST || operation == QPJ_CREDENTIAL_WITNESSED_REQUEST;
    const int joint = operation == QPJ_CREDENTIAL_STAGE_JOINT;
    const int paired = operation == 3 || (operation >= 6 && operation <= 8) || operation == QPJ_CREDENTIAL_COMMIT_CONTINUED;
    const size_t count = joint ? 14 : grant ? 6 : historical ? 7 : requesting ? 1 : paired ? 2 : 0;
    const jsize stage_minimum[6] = {1,32,1985,32,32,32}, stage_maximum[6] = {65536,32,1985,32,32,32};
    const jsize historical_minimum[7] = {32,32,32,1985,8,32,1}, historical_maximum[7] = {32,32,32,1985,8,32,8192};
    const jsize pair[2] = {32,32};
    const jsize joint_minimum[14] = {1,32,1985,32,8,32,32,1,32,1985,8,32,1,0};
    const jsize joint_maximum[14] = {65536,32,1985,32,8,32,32,7746,32,1985,8,32,8192,32};
    if (!qpj_copy_fields(env, inputs, values, joint ? joint_minimum : grant ? stage_minimum : historical ? historical_minimum : pair,
            joint ? joint_maximum : grant ? stage_maximum : historical ? historical_maximum : pair, count)) goto cleanup;
    if (joint && values[13].length != 0 && values[13].length != 32) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "joint policy predecessor width"); goto cleanup;
    }
    const jsize length = operation == QPJ_CREDENTIAL_ACTIVATE_JOINT ? 0 : requesting ? QPJ_CREDENTIAL_REQUEST_BYTES : operation == QPJ_CREDENTIAL_PREPARE_CONTINUED ? 333
        : operation == QPJ_CREDENTIAL_CANCEL_CONTINUED ? 285 : operation == 4 ? 296 : operation == 5 ? 248 : operation == 9 ? 40 : 116;
    output = (*env)->NewByteArray(env, length); if (output == NULL) goto cleanup;
    if (requesting) {
        wire = calloc(1, (size_t)length); request = calloc(1, sizeof(*request));
        if (wire == NULL || request == NULL) {
            qpj_throw_class(env, "java/lang/OutOfMemoryError", "credential request"); goto cleanup;
        }
    }
    qpc_credential_renewal_status_v1 status = {0};
    qpc_error_v1 error = {0};
    int32_t code;
    switch (operation) {
        case 1: code = qpc_enrollment_v1_credential_renewal_status((uint64_t)handle, &status, &error); break;
        case 2:
        case 9:
        case QPJ_CREDENTIAL_STAGE_CONTINUED: {
            qpc_account_pin_v1 pin = {0}; memcpy(pin.account, values[1].data, 32);
            pin.root = values[2].data; pin.root_length = values[2].length; memcpy(pin.family, values[3].data, 32);
            pin.checkpoint.version = (uint64_t)version; memcpy(pin.checkpoint.digest, values[4].data, 32);
            if (operation == 2) {
                code = qpc_enrollment_v1_stage_credential_renewal((uint64_t)handle, values[0].data, values[0].length, &pin, values[5].data, &status, &error);
            } else if (operation == QPJ_CREDENTIAL_STAGE_CONTINUED) {
                code = qpc_enrollment_v1_stage_continued_credential_renewal((uint64_t)handle, values[0].data, values[0].length, &pin, values[5].data, &status, &error);
            } else {
                qpc_roster_checkpoint_v1 checkpoint = {0};
                code = qpc_device_v1_admit_peer_credential_renewal((uint64_t)handle, values[0].data, values[0].length, &pin, values[5].data, &checkpoint, &error);
                if (code == 0) { put64(wire, checkpoint.version); memcpy(wire + 8, checkpoint.digest, 32); }
            }
            break;
        }
        case 3: code = qpc_enrollment_v1_reconcile_expired_credential_renewal((uint64_t)handle, values[0].data, values[1].data, &status, &error); break;
        case 4: {
            qpc_credential_renewal_proposal_v1 proposal = {0};
            code = qpc_enrollment_v1_prepare_witnessed_credential_renewal((uint64_t)handle, &proposal, &error);
            if (code == 0) memcpy(wire, proposal.bytes, sizeof(proposal.bytes));
            break;
        }
        case 5: {
            qpc_credential_renewal_cancellation_v1 cancellation = {0};
            code = qpc_enrollment_v1_prepare_witnessed_credential_cancellation((uint64_t)handle, &cancellation, &error);
            if (code == 0) memcpy(wire, cancellation.bytes, sizeof(cancellation.bytes));
            break;
        }
        case 6: code = qpc_enrollment_v1_commit_witnessed_credential_renewal((uint64_t)handle, values[0].data, values[1].data, &status, &error); break;
        case 7: code = qpc_enrollment_v1_close_witnessed_credential_renewal((uint64_t)handle, values[0].data, values[1].data, &status, &error); break;
        case 8: code = qpc_enrollment_v1_reconcile_witnessed_credential_renewal((uint64_t)handle, values[0].data, values[1].data, &status, &error); break;
        case QPJ_CREDENTIAL_PREPARE_CONTINUED: {
            qpc_policy_renewal_proposal_v1 proposal = {0};
            code = qpc_enrollment_v1_prepare_witnessed_policy_continuation((uint64_t)handle, &proposal, &error);
            if (code == 0) { put32(wire, proposal.length); memcpy(wire + 4, proposal.bytes, sizeof(proposal.bytes)); }
            break;
        }
        case QPJ_CREDENTIAL_CANCEL_CONTINUED: {
            qpc_policy_renewal_cancellation_v1 cancellation = {0};
            code = qpc_enrollment_v1_prepare_witnessed_policy_cancellation((uint64_t)handle, &cancellation, &error);
            if (code == 0) { put32(wire, cancellation.length); memcpy(wire + 4, cancellation.bytes, sizeof(cancellation.bytes)); }
            break;
        }
        case QPJ_CREDENTIAL_COMMIT_CONTINUED:
            code = qpc_enrollment_v1_commit_witnessed_policy_continuation((uint64_t)handle, values[0].data, values[1].data, &status, &error); break;
        case QPJ_CREDENTIAL_RECONCILE_LOCAL:
            code = qpc_enrollment_v1_reconcile_policy_continuation((uint64_t)handle, &status, &error); break;
        case QPJ_CREDENTIAL_RECOVER_HISTORICAL: {
            qpc_policy_document_v1 document = {0}; qpj_policy_document(&document, values + 2);
            code = qpc_enrollment_v1_recover_historical_policy_continuation((uint64_t)handle, values[0].data, values[1].data, &document, &status, &error); break;
        }
        case QPJ_CREDENTIAL_REQUEST:
        case QPJ_CREDENTIAL_WITNESSED_REQUEST:
            code = operation == QPJ_CREDENTIAL_REQUEST
                ? qpc_enrollment_v1_credential_renewal_request((uint64_t)handle, values[0].data, request, &error)
                : qpc_enrollment_v1_witnessed_credential_renewal_request((uint64_t)handle, values[0].data, request, &error);
            if (code == 0) qpj_credential_request_encode(wire, request);
            break;
        case QPJ_CREDENTIAL_STAGE_JOINT: {
            qpc_account_pin_v1 pin = {0}; qpj_policy_pin(&pin, values + 1);
            qpc_policy_document_v1 previous = {0}; qpj_policy_document(&previous, values + 8);
            code = qpc_enrollment_v1_stage_policy_continuation((uint64_t)handle, values[0].data, values[0].length,
                &pin, values[6].data, values[7].data, values[7].length, &previous,
                values[13].length == 0 ? NULL : values[13].data, &status, &error); break;
        }
        case QPJ_CREDENTIAL_ACTIVATE_JOINT:
            code = qpc_enrollment_v1_activate_policy_continuation((uint64_t)handle, &error); break;
        default: qpj_throw_class(env, "java/lang/IllegalArgumentException", "credential operation"); goto cleanup;
    }
    if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
    if (length == 116) {
        put32(wire, status.phase); memcpy(wire + 4, status.operation, 32); memcpy(wire + 36, status.statement, 32);
        put64(wire + 68, status.checkpoint.version); memcpy(wire + 76, status.checkpoint.digest, 32); put64(wire + 108, status.observed_at);
    }
    (*env)->SetByteArrayRegion(env, output, 0, length, (const jbyte *)wire);
cleanup:
    free(request);
    if (wire != small_wire) free(wire);
    for (size_t i = 0; i < 14; ++i) qpj_dispose(&values[i]);
    qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}
