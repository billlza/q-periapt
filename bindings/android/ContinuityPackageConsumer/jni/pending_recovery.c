/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "policy_codec.h"
#include <stdlib.h>
#include <string.h>

enum { PENDING_INFO_BYTES = 436, PENDING_METADATA_MAX = 8388608, PENDING_SIGNED_MAX = 8192 };
_Static_assert(sizeof(qpc_pending_write_request_info_v1) == PENDING_INFO_BYTES, "pending request layout");
_Static_assert(offsetof(qpc_pending_write_request_info_v1, binding) == 404, "pending request binding");

static jbyteArray request(JNIEnv *env, uint64_t handle) {
    qpc_pending_write_request_info_v1 info = {0}; qpc_error_v1 error = {0};
    int32_t code = qpc_enrollment_v1_pending_write_request(handle, &info, &error);
    if (code != 0) { qpj_throw_error(env, "pending-write-request", code, &error); return NULL; }
    if (info.metadata_length < 569 || info.metadata_length > PENDING_METADATA_MAX ||
        info.signed_request_length == 0 || info.signed_request_length > PENDING_SIGNED_MAX ||
        info.reserved_zero[0] || info.reserved_zero[1] || info.reserved_zero[2]) {
        qpj_throw_class(env, "java/lang/IllegalStateException", "native pending write bounds"); return NULL;
    }
    size_t length = (size_t)info.metadata_length + info.signed_request_length;
    jbyteArray output = (*env)->NewByteArray(env, (jsize)(PENDING_INFO_BYTES + length));
    if (output == NULL) return NULL;
    owned_bytes bytes = {malloc(length), length};
    if (bytes.data == NULL) {
        qpj_throw_class(env, "java/lang/OutOfMemoryError", "pending write metadata copy"); goto cleanup;
    }
    code = qpc_enrollment_v1_copy_pending_write_request(handle, info.binding,
        bytes.data, info.metadata_length, bytes.data + info.metadata_length, info.signed_request_length, &error);
    if (code != 0) { qpj_throw_error(env, "pending-write-copy", code, &error); goto cleanup; }
    uint8_t header[PENDING_INFO_BYTES] = {0};
    qpj_policy_put32(header, info.metadata_length); qpj_policy_put32(header + 4, info.signed_request_length);
    memcpy(header + 8, info.proposal, 393); memcpy(header + 404, info.binding, 32);
    (*env)->SetByteArrayRegion(env, output, 0, PENDING_INFO_BYTES, (const jbyte *)header);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    (*env)->SetByteArrayRegion(env, output, PENDING_INFO_BYTES, (jsize)length, (const jbyte *)bytes.data);
cleanup:
    qpj_dispose(&bytes);
    if ((*env)->ExceptionCheck(env)) { (*env)->DeleteLocalRef(env, output); return NULL; }
    return output;
}

jbyteArray qpj_pending_write_command(JNIEnv *env, jclass type, jlong handle, jint operation, jobjectArray inputs) {
    (void)type;
    const char *name = "pending-write-recovery";
    if (!qpj_enter(env, name)) return NULL;
    owned_bytes values[2] = {{0}}; jbyteArray output = NULL;
    if (operation != 1 && operation != 2) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "pending write operation"); goto cleanup;
    }
    const jsize minimum[2] = {393, 1}, maximum[2] = {393, PENDING_METADATA_MAX};
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, operation == 1 ? 0 : 2)) goto cleanup;
    if (operation == 1) { output = request(env, (uint64_t)handle); goto cleanup; }
    /* Reserve the success output before any persistent mutation. An error never
     * proves non-commit; the same approval and metadata are needed after reopen. */
    output = (*env)->NewByteArray(env, 0); if (output == NULL) goto cleanup;
    qpc_error_v1 error = {0};
    int32_t code = qpc_enrollment_v1_confirm_pending_write_recovery((uint64_t)handle,
        values[0].data, values[0].length, values[1].data, values[1].length, &error);
    if (code != 0) qpj_throw_error(env, name, code, &error);
cleanup:
    for (size_t i = 0; i < 2; ++i) qpj_dispose(&values[i]);
    qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}
