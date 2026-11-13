/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "policy_codec.h"
#include <stdlib.h>
#include <string.h>

enum { RETIRED_INVENTORY = 1, RETIRED_PREPARE_REPORT, RETIRED_REPORT_PROPOSAL,
    RETIRED_LOAD_REPORT, RETIRED_PREPARE_ACK, RETIRED_ACK_PROPOSAL,
    RETIRED_JOURNAL_STATE, RETIRED_ERASE_JOURNAL, RETIRED_PREPARE_SIGNER,
    RETIRED_SIGNER_STATE, RETIRED_ERASE_SIGNER, RETIRED_FIELDS = 9, RETIRED_REPORT_MAX = 8388608 };
_Static_assert(RETIRED_FIELDS <= QPJ_INPUT_FIELD_LIMIT, "retirement fields exceed JNI input capacity");

jlong qpj_prepare_retired(JNIEnv *env, jclass type, jobjectArray inputs, jlongArray numbers) {
    (void)type;
    const char *name = "retired-enrollment-open";
    if (!qpj_enter(env, name)) return 0;
    owned_bytes values[RETIRED_FIELDS] = {{0}};
    uint64_t handle = 0; jlong counters[3] = {0};
    if (numbers == NULL) { qpj_throw_class(env, "java/lang/NullPointerException", "original enrollment counters"); goto cleanup; }
    if ((*env)->GetArrayLength(env, numbers) != 3) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "original counter width"); goto cleanup;
    }
    (*env)->GetLongArrayRegion(env, numbers, 0, 3, counters);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    const jsize minimum[RETIRED_FIELDS] = {1,1985,16,32,32,1985,1,96,3754};
    const jsize maximum[RETIRED_FIELDS] = {4096,1985,16,32,32,1985,57794,96,3754};
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, RETIRED_FIELDS)) goto cleanup;
    qpc_enrollment_intent_v1 intent = {0};
    intent.root = values[1].data; intent.root_length = values[1].length;
    memcpy(intent.device, values[2].data, 16); memcpy(intent.family, values[3].data, 32);
    intent.generation = (uint64_t)counters[0]; intent.valid_from = (uint64_t)counters[1]; intent.valid_until = (uint64_t)counters[2];
    qpc_retired_authority_v1 authority = {0};
    memcpy(authority.witness, values[4].data, 32);
    authority.public_key = values[5].data; authority.public_key_length = values[5].length;
    authority.replacement = values[6].data; authority.replacement_length = values[6].length;
    memcpy(authority.subject, values[7].data, 96);
    authority.receipt = values[8].data; authority.receipt_length = values[8].length;
    qpc_error_v1 error = {0};
    int32_t code = qpc_retired_v1_prepare_open(values[0].data, values[0].length, &intent, &authority, &handle, &error);
    if (code != 0) { qpj_throw_error(env, name, code, &error); handle = 0; }
    else if (handle == 0) qpj_throw_class(env, "java/lang/IllegalStateException", "native retirement returned zero owner");
cleanup:
    for (size_t i = 0; i < RETIRED_FIELDS; ++i) qpj_dispose(&values[i]);
    qpj_leave(); return (jlong)handle;
}

/* load_report authenticates/caches immutable metadata; it performs no host ACK or
 * erasure. Allocate the exact bounded output after reading its authenticated size. */
static jbyteArray load_report(JNIEnv *env, uint64_t handle, const owned_bytes inputs[3]) {
    qpc_retired_report_info_v1 info = {0}; qpc_error_v1 error = {0};
    int32_t code = qpc_retired_v1_load_report(handle, inputs[0].data, inputs[0].length,
        inputs[1].data, inputs[1].length, &info, &error);
    if (code != 0) { qpj_throw_error(env, "retired-report-load", code, &error); return NULL; }
    if (info.length < 323 || info.length > RETIRED_REPORT_MAX || info.views < 1 || info.views > 2 || info.reserved_zero != 0) {
        qpj_throw_class(env, "java/lang/IllegalStateException", "native retirement report bounds"); return NULL;
    }
    jbyteArray output = (*env)->NewByteArray(env, (jsize)(48 + info.length));
    if (output == NULL) return NULL;
    owned_bytes report = {malloc(info.length), info.length};
    if (report.data == NULL) { qpj_throw_class(env, "java/lang/OutOfMemoryError", "retirement report copy"); goto cleanup; }
    code = qpc_retired_v1_copy_report(handle, report.data, report.length, &error);
    if (code != 0) { qpj_throw_error(env, "retired-report-copy", code, &error); goto cleanup; }
    uint8_t header[48] = {0};
    qpj_policy_put64(header, (uint64_t)info.length); qpj_policy_put32(header + 8, info.views);
    memcpy(header + 16, info.report, 32);
    (*env)->SetByteArrayRegion(env, output, 0, 48, (const jbyte *)header);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    (*env)->SetByteArrayRegion(env, output, 48, (jsize)report.length, (const jbyte *)report.data);
cleanup:
    qpj_dispose(&report);
    if ((*env)->ExceptionCheck(env)) { (*env)->DeleteLocalRef(env, output); return NULL; }
    return output;
}

static int shape(jint operation, jsize minimum[3], jsize maximum[3], size_t *count, jsize *length) {
    switch (operation) {
        case RETIRED_INVENTORY: *count = 0; *length = 313; return 1;
        case RETIRED_REPORT_PROPOSAL: case RETIRED_ACK_PROPOSAL: *count = 0; *length = 360; return 1;
        case RETIRED_PREPARE_REPORT:
            *count = 1; *length = 360; minimum[0] = maximum[0] = 3690; return 1;
        case RETIRED_LOAD_REPORT:
            *count = 2; *length = 0; minimum[0] = maximum[0] = 3690; minimum[1] = maximum[1] = 3730; return 1;
        case RETIRED_PREPARE_ACK:
            *count = 3; *length = 360; minimum[0] = maximum[0] = 3690; minimum[1] = maximum[1] = 3730;
            minimum[2] = 1; maximum[2] = RETIRED_REPORT_MAX; return 1;
        case RETIRED_JOURNAL_STATE: case RETIRED_SIGNER_STATE: *count = 0; *length = 4; return 1;
        case RETIRED_ERASE_JOURNAL: case RETIRED_PREPARE_SIGNER:
            *count = 1; *length = 0; minimum[0] = maximum[0] = 3730; return 1;
        case RETIRED_ERASE_SIGNER: *count = 0; *length = 0; return 1;
        default: return 0;
    }
}

jbyteArray qpj_retired_command(JNIEnv *env, jclass type, jlong handle, jint operation, jobjectArray inputs) {
    (void)type;
    const char *name = "retired-enrollment";
    if (!qpj_enter(env, name)) return NULL;
    owned_bytes values[3] = {{0}}; jbyteArray output = NULL;
    jsize minimum[3] = {0}, maximum[3] = {0}, length = 0; size_t count = 0;
    uint8_t wire[360] = {0};
    if (!shape(operation, minimum, maximum, &count, &length)) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "retirement operation"); goto cleanup;
    }
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, count)) goto cleanup;
    if (operation == RETIRED_LOAD_REPORT) { output = load_report(env, (uint64_t)handle, values); goto cleanup; }
    /* Every persistent mutation has its Java output allocated before dispatch. */
    output = (*env)->NewByteArray(env, length); if (output == NULL) goto cleanup;
    qpc_retired_inventory_v1 inventory = {{0}};
    qpc_retired_proposal_v1 proposal = {0}; qpc_error_v1 error = {0};
    uint32_t state = 0; int32_t code;
    switch (operation) {
        case RETIRED_INVENTORY:
            code = qpc_retired_v1_inventory((uint64_t)handle, &inventory, &error);
            if (code == 0) memcpy(wire, inventory.bytes, 313);
            break;
        case RETIRED_PREPARE_REPORT:
            code = qpc_retired_v1_prepare_report((uint64_t)handle, values[0].data, values[0].length, &proposal, &error); break;
        case RETIRED_REPORT_PROPOSAL:
            code = qpc_retired_v1_report_proposal((uint64_t)handle, &proposal, &error); break;
        case RETIRED_PREPARE_ACK:
            code = qpc_retired_v1_prepare_acknowledgement((uint64_t)handle, values[0].data, values[0].length,
                values[1].data, values[1].length, values[2].data, values[2].length, &proposal, &error); break;
        case RETIRED_ACK_PROPOSAL:
            code = qpc_retired_v1_acknowledgement_proposal((uint64_t)handle, &proposal, &error); break;
        case RETIRED_JOURNAL_STATE:
            code = qpc_retired_v1_journal_state((uint64_t)handle, &state, &error); break;
        case RETIRED_SIGNER_STATE:
            code = qpc_retired_v1_signer_state((uint64_t)handle, &state, &error); break;
        case RETIRED_ERASE_JOURNAL:
            code = qpc_retired_v1_erase_journal((uint64_t)handle, values[0].data, values[0].length, &error); break;
        case RETIRED_PREPARE_SIGNER:
            code = qpc_retired_v1_prepare_signer_erasure((uint64_t)handle, values[0].data, values[0].length, &error); break;
        case RETIRED_ERASE_SIGNER:
            code = qpc_retired_v1_erase_signer((uint64_t)handle, &error); break;
        default: qpj_throw_class(env, "java/lang/IllegalArgumentException", "retirement operation"); goto cleanup;
    }
    if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
    if (length == 360) {
        qpj_policy_put32(wire, proposal.present); memcpy(wire + 4, proposal.bytes, 353);
        memcpy(wire + 357, proposal.reserved_zero, 3);
    } else if (length == 4) qpj_policy_put32(wire, state);
    if (length != 0) (*env)->SetByteArrayRegion(env, output, 0, length, (const jbyte *)wire);
cleanup:
    for (size_t i = 0; i < 3; ++i) qpj_dispose(&values[i]);
    qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}
