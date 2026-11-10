/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "bridge.h"
#include <string.h>

static void device(qpc_peer_device_v1 *out, const owned_bytes *input, const jlong *numbers) {
    memcpy(out->account.account, input[0].data, 32);
    out->account.root = input[1].data; out->account.root_length = input[1].length;
    memcpy(out->account.family, input[2].data, 32); memcpy(out->account.checkpoint.digest, input[3].data, 32);
    out->account.checkpoint.version = (uint64_t)numbers[0];
    memcpy(out->device, input[4].data, 16); out->generation = (uint64_t)numbers[1];
}
jlong qpj_prepare_peer(JNIEnv *env, jclass type, jlong parent, jobjectArray inputs,
        jlongArray numbers, jint quality, jint role, jboolean reopen) {
    (void)type;
    const char *name = "peer-prepare";
    if (!qpj_enter(env, name)) return 0;
    owned_bytes values[15] = {{0}};
    jlong counters[4] = {0};
    uint64_t handle = 0;
    if (quality < 1 || quality > 4 || role < 1 || role > 2 || (reopen != JNI_FALSE && reopen != JNI_TRUE)) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "peer quality or role"); goto cleanup;
    }
    if (numbers == NULL) { qpj_throw_class(env, "java/lang/NullPointerException", "peer counters"); goto cleanup; }
    if ((*env)->GetArrayLength(env, numbers) != 4) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "peer counter width"); goto cleanup;
    }
    (*env)->GetLongArrayRegion(env, numbers, 0, 4, counters);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    const jsize minimum[15] = {32,1985,32,32,16,32,1985,32,32,16,32,1,1,1,reopen ? 32 : 0};
    const jsize maximum[15] = {32,1985,32,32,16,32,1985,32,32,16,32,65536,8192,128,reopen ? 32 : 0};
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, 15)) goto cleanup;
    qpc_peer_configuration_v1 input = {0};
    input.header.struct_size = (uint32_t)sizeof(input); input.header.version = 1;
    input.quality = (uint32_t)quality; input.role = (uint32_t)role;
    device(&input.initiator, values, counters); device(&input.responder, values + 5, counters + 2);
    memcpy(input.directory, values[10].data, 32); input.bundle = qpj_blob(&values[11]);
    input.tls_peer = qpj_blob(&values[12]); input.tls_name = qpj_blob(&values[13]);
    qpc_error_v1 error = {0};
    int32_t code = !reopen
        ? qpc_peer_v1_prepare_configured((uint64_t)parent, &input, &handle, &error)
        : qpc_peer_v1_prepare_configured_reopen((uint64_t)parent, &input, values[14].data, &handle, &error);
    if (code != 0) { qpj_throw_error(env, name, code, &error); handle = 0; }
    else if (handle == 0) qpj_throw_class(env, "java/lang/IllegalStateException", "zero peer owner");
cleanup:
    for (size_t i = 0; i < 15; ++i) qpj_dispose(&values[i]);
    qpj_leave(); return (jlong)handle;
}
