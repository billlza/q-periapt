/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "bridge.h"
#include <string.h>

jbyteArray qpj_peer_command(JNIEnv *env, jclass type, jlong handle, jint operation, jobjectArray inputs, jlong target) {
    (void)type;
    const char *name = operation == 1 ? "establish" : operation == 2 ? "next-message" : operation == 3 ? "message-status"
        : operation == 4 ? "send" : "rekey";
    if (!qpj_enter(env, name)) return NULL;
    owned_bytes values[5] = {{0}};
    jbyteArray output = NULL;
    size_t count;
    jsize capacity;
    jsize minimum[5] = {0}, maximum[5] = {0};
    if (operation < 1 || operation > 5) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "peer operation"); goto cleanup;
    }
    switch (operation) {
        case 1: case 5:
            count = 2; capacity = operation == 1 ? 34 : 8;
            minimum[0] = 1; maximum[0] = 128; minimum[1] = maximum[1] = 32; break;
        case 2:
            count = 1; capacity = 32; minimum[0] = maximum[0] = 32; break;
        case 3:
            count = 2; capacity = 1; minimum[0] = maximum[0] = minimum[1] = maximum[1] = 32; break;
        default:
            count = 5; capacity = 3; minimum[0] = 1; maximum[0] = 128;
            minimum[1] = maximum[1] = minimum[2] = maximum[2] = 32;
            maximum[3] = 16384; maximum[4] = 1024; break;
    }
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, count)) goto cleanup;
    output = (*env)->NewByteArray(env, capacity);
    if (output == NULL) goto cleanup;
    uint8_t wire[34] = {0};
    qpc_error_v1 error = {0};
    int32_t code;
    uint16_t exchanges = 0;
    if (operation == 1) {
        code = qpc_owner_v1_establish((uint64_t)handle, values[0].data, values[0].length, values[1].data, wire, &exchanges, &error);
        wire[32] = (uint8_t)(exchanges >> 8); wire[33] = (uint8_t)exchanges;
    } else if (operation == 2) {
        code = qpc_owner_v1_next_message((uint64_t)handle, values[0].data, wire, &error);
    } else if (operation == 3) {
        code = qpc_owner_v1_message_status((uint64_t)handle, values[0].data, values[1].data, wire, &error);
    } else if (operation == 4) {
        code = qpc_owner_v1_send((uint64_t)handle, values[0].data, values[0].length, values[1].data, values[2].data,
            values[3].data, values[3].length, values[4].data, values[4].length, wire, &exchanges, &error);
        wire[1] = (uint8_t)(exchanges >> 8); wire[2] = (uint8_t)exchanges;
    } else {
        uint64_t completed = 0;
        code = qpc_owner_v1_rekey((uint64_t)handle, values[0].data, values[0].length, values[1].data, (uint64_t)target, &completed, &error);
        for (size_t i = 0; i < 8; ++i) wire[i] = (uint8_t)(completed >> (56 - 8 * i));
    }
    if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
    (*env)->SetByteArrayRegion(env, output, 0, capacity, (const jbyte *)wire);
cleanup:
    for (size_t i = 0; i < 5; ++i) qpj_dispose(&values[i]);
    qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}
