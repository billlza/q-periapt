/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "bridge.h"
#include <string.h>

typedef struct { JNIEnv *env; jobject invocation; int called; } application;
static int32_t commit(void *context, const uint8_t session[32], const uint8_t message[32],
        const uint8_t *plaintext, size_t length) {
    application *app = context;
    JNIEnv *env = app->env;
    jbyteArray ids = NULL, message_id = NULL, payload = NULL;
    int32_t status = 1;
    if ((*env)->ExceptionCheck(env)) return 1;
    if (app->called || session == NULL || message == NULL || length > 16384 || (length != 0 && plaintext == NULL)) {
        qpj_throw_class(env, "java/lang/IllegalStateException", "invalid native application callback"); return 1;
    }
    app->called = 1;
    /* Reserve all arrays before copying secret data. The Java invocation catches
     * application exceptions and clears payload in finally. A JVM marshalling
     * exception remains pending, but C still returns refusal to the engine. */
    ids = (*env)->NewByteArray(env, 32); if (ids == NULL) goto cleanup;
    message_id = (*env)->NewByteArray(env, 32); if (message_id == NULL) goto cleanup;
    payload = (*env)->NewByteArray(env, (jsize)length); if (payload == NULL) goto cleanup;
    (*env)->SetByteArrayRegion(env, ids, 0, 32, (const jbyte *)session);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    (*env)->SetByteArrayRegion(env, message_id, 0, 32, (const jbyte *)message);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    if (length != 0) (*env)->SetByteArrayRegion(env, payload, 0, (jsize)length, (const jbyte *)plaintext);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    status = qpj_commit(env, app->invocation, ids, message_id, payload);
    if ((*env)->ExceptionCheck(env)) status = 1;
cleanup:
    if (ids != NULL) (*env)->DeleteLocalRef(env, ids);
    if (message_id != NULL) (*env)->DeleteLocalRef(env, message_id);
    if (payload != NULL) (*env)->DeleteLocalRef(env, payload);
    return status;
}
static void put32(uint8_t *output, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) output[i] = (uint8_t)(value >> (24 - 8 * i));
}
jbyteArray qpj_peer_server(JNIEnv *env, jclass type, jlong handle, jint operation, jobjectArray inputs, jobject callback) {
    (void)type;
    const char *name = operation == 1 ? "listen" : operation == 2 ? "serve" : "serve-rekey";
    if (!qpj_enter(env, name)) return NULL;
    owned_bytes value = {0};
    jbyteArray output = NULL;
    if (operation < 1 || operation > 3 || (operation != 2 && callback != NULL)) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "server operation"); goto cleanup;
    }
    if (operation == 2) {
        jboolean valid = qpj_valid_commit(env, callback);
        if ((*env)->ExceptionCheck(env)) goto cleanup;
        if (!valid) { qpj_throw_class(env, "java/lang/IllegalArgumentException", "application transaction"); goto cleanup; }
        if ((*env)->EnsureLocalCapacity(env, 16) < 0) goto cleanup;
    }
    const jsize minimum[1] = {operation == 1 ? 1 : 32};
    const jsize maximum[1] = {operation == 1 ? 128 : 32};
    if (!qpj_copy_fields(env, inputs, &value, minimum, maximum, operation == 2 ? 0 : 1)) goto cleanup;
    jsize capacity = operation == 1 ? 2 : operation == 2 ? 72 : 8;
    output = (*env)->NewByteArray(env, capacity); if (output == NULL) goto cleanup;
    uint8_t wire[72] = {0};
    qpc_error_v1 error = {0};
    int32_t code;
    if (operation == 1) {
        uint16_t port = 0;
        code = qpc_owner_v1_listen((uint64_t)handle, value.data, value.length, &port, &error);
        wire[0] = (uint8_t)(port >> 8); wire[1] = (uint8_t)port;
    } else if (operation == 2) {
        application app = {env, callback, 0};
        qpc_served_v1 event = {0};
        code = qpc_owner_v1_serve((uint64_t)handle, commit, &app, &event, &error);
        put32(wire, event.kind); memcpy(wire + 4, event.session, 32); memcpy(wire + 36, event.message, 32);
        put32(wire + 68, event.duplicate);
    } else {
        uint64_t epoch = 0;
        code = qpc_owner_v1_serve_rekey((uint64_t)handle, value.data, &epoch, &error);
        for (size_t i = 0; i < 8; ++i) wire[i] = (uint8_t)(epoch >> (56 - 8 * i));
    }
    if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    (*env)->SetByteArrayRegion(env, output, 0, capacity, (const jbyte *)wire);
cleanup:
    qpj_dispose(&value); qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}
