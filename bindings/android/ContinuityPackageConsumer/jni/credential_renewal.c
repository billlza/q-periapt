/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "bridge.h"
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
    owned_bytes values[6] = {{0}};
    jbyteArray output = NULL;
    if (operation < 1 || operation > 9 || (operation != 2 && operation != 9 && version != 0)) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "credential operation"); goto cleanup;
    }
    const int grant = operation == 2 || operation == 9;
    const size_t count = grant ? 6 : (operation == 3 || operation >= 6) ? 2 : 0;
    const jsize stage_minimum[6] = {1,32,1985,32,32,32}, stage_maximum[6] = {65536,32,1985,32,32,32};
    const jsize pair[2] = {32,32};
    if (!qpj_copy_fields(env, inputs, values, grant ? stage_minimum : pair,
            grant ? stage_maximum : pair, count)) goto cleanup;
    const jsize length = operation == 4 ? 296 : operation == 5 ? 248 : operation == 9 ? 40 : 116;
    output = (*env)->NewByteArray(env, length); if (output == NULL) goto cleanup;
    uint8_t wire[296] = {0};
    qpc_credential_renewal_status_v1 status = {0};
    qpc_error_v1 error = {0};
    int32_t code;
    switch (operation) {
        case 1: code = qpc_enrollment_v1_credential_renewal_status((uint64_t)handle, &status, &error); break;
        case 2:
        case 9: {
            qpc_account_pin_v1 pin = {0}; memcpy(pin.account, values[1].data, 32);
            pin.root = values[2].data; pin.root_length = values[2].length; memcpy(pin.family, values[3].data, 32);
            pin.checkpoint.version = (uint64_t)version; memcpy(pin.checkpoint.digest, values[4].data, 32);
            if (operation == 2) {
                code = qpc_enrollment_v1_stage_credential_renewal((uint64_t)handle, values[0].data, values[0].length, &pin, values[5].data, &status, &error);
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
        default: code = qpc_enrollment_v1_reconcile_witnessed_credential_renewal((uint64_t)handle, values[0].data, values[1].data, &status, &error); break;
    }
    if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
    if (length == 116) {
        put32(wire, status.phase); memcpy(wire + 4, status.operation, 32); memcpy(wire + 36, status.statement, 32);
        put64(wire + 68, status.checkpoint.version); memcpy(wire + 76, status.checkpoint.digest, 32); put64(wire + 108, status.observed_at);
    }
    (*env)->SetByteArrayRegion(env, output, 0, length, (const jbyte *)wire);
cleanup:
    for (size_t i = 0; i < 6; ++i) qpj_dispose(&values[i]);
    qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}
