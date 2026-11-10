/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "bridge.h"
#include <string.h>

enum { ACCOUNT_TARGET_LIMIT = 32, ACCOUNT_FIELDS = 6 };
static void encode_u32(uint8_t *output, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) output[i] = (uint8_t)(value >> (24 - 8 * i));
}
jbyteArray qpj_account_command(JNIEnv *env, jclass type, jlong parent, jint operation,
                               jlongArray peers, jobjectArray inputs, jint selected) {
    (void)type;
    const char *name = operation == 1 ? "next-account" : operation == 2 ? "account-status" : "send-account-member";
    if (!qpj_enter(env, name)) return NULL;
    owned_bytes values[ACCOUNT_FIELDS] = {{0}};
    jbyteArray output = NULL;
    jlong handles[ACCOUNT_TARGET_LIMIT] = {0};
    qpc_account_target_v1 targets[ACCOUNT_TARGET_LIMIT] = {{0}};
    if (operation < 1 || operation > 3) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "account operation"); goto cleanup;
    }
    if (peers == NULL) { qpj_throw_class(env, "java/lang/NullPointerException", "account targets"); goto cleanup; }
    jsize count = (*env)->GetArrayLength(env, peers);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    if ((operation == 3 && (count < 1 || count > ACCOUNT_TARGET_LIMIT || selected < 0 || selected >= count))
            || (operation != 3 && (count != 0 || selected != 0))) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "account target count or selection"); goto cleanup;
    }
    size_t fields = operation == 1 ? 0 : operation == 2 ? 1 : ACCOUNT_FIELDS;
    jsize minimum[ACCOUNT_FIELDS] = {32,32,1,0,0,count * 32};
    jsize maximum[ACCOUNT_FIELDS] = {32,32,128,16384,1024,count * 32};
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, fields)) goto cleanup;
    if (count != 0) {
        (*env)->GetLongArrayRegion(env, peers, 0, count, handles);
        if ((*env)->ExceptionCheck(env)) goto cleanup;
        for (jsize i = 0; i < count; ++i) {
            targets[i].peer = (uint64_t)handles[i];
            memcpy(targets[i].session, values[5].data + (size_t)i * 32, 32);
        }
    }
    jsize capacity = operation == 1 ? 32 : operation == 2 ? 33 : 88;
    output = (*env)->NewByteArray(env, capacity);
    if (output == NULL) goto cleanup;
    uint8_t wire[88] = {0};
    qpc_error_v1 error = {0}; int32_t code;
    if (operation == 1) code = qpc_device_v1_next_account((uint64_t)parent, wire, &error);
    else if (operation == 2) code = qpc_device_v1_account_status((uint64_t)parent, values[0].data, wire, wire + 1, &error);
    else {
        qpc_account_delivered_v1 delivered = {0};
        code = qpc_device_v1_send_account_member((uint64_t)parent, targets, (size_t)count, (size_t)selected,
            values[0].data, values[1].data, values[2].data, values[2].length,
            values[3].data, values[3].length, values[4].data, values[4].length, &delivered, &error);
        memcpy(wire, delivered.device, 16); memcpy(wire + 16, delivered.session, 32); memcpy(wire + 48, delivered.message, 32);
        encode_u32(wire + 80, delivered.outcome); encode_u32(wire + 84, delivered.exchanges);
    }
    if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
    (*env)->SetByteArrayRegion(env, output, 0, capacity, (const jbyte *)wire);
cleanup:
    for (size_t i = 0; i < ACCOUNT_FIELDS; ++i) qpj_dispose(&values[i]);
    qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}
