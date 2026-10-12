/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "bridge.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* One application class loader and process-lifetime native engine. The one
 * class reference is intentional: an abandoned Java owner cannot unload code
 * still holding its native resource. Explicit close is required. */
static jclass native_class;
static jmethodID fail_method;
static jmethodID valid_commit_method, commit_method;
static atomic_uint ordinary_calls;
enum { INPUT_COUNT = 13, JNI_CALL_LIMIT = 64 };

void qpj_wipe(void *pointer, size_t length) {
    volatile uint8_t *p = pointer;
    while (length != 0) { *p++ = 0; --length; }
}
void qpj_throw_class(JNIEnv *env, const char *name, const char *message) {
    if ((*env)->ExceptionCheck(env)) return;
    jclass type = (*env)->FindClass(env, name);
    if (type != NULL) {
        (void)(*env)->ThrowNew(env, type, message);
        (*env)->DeleteLocalRef(env, type);
    }
}
void qpj_throw_error(JNIEnv *env, const char *operation, int32_t code, const qpc_error_v1 *error) {
    if ((*env)->ExceptionCheck(env)) return;
    if (code == 0 || error->code != code || error->length > sizeof(error->message) || error->truncated > 1) {
        qpj_throw_class(env, "java/lang/IllegalStateException", "malformed Continuity error record");
        return;
    }
    jstring name = (*env)->NewStringUTF(env, operation);
    if (name == NULL) return;
    jbyteArray message = (*env)->NewByteArray(env, (jsize)error->length);
    if (message != NULL) {
        if (error->length != 0) (*env)->SetByteArrayRegion(env, message, 0, (jsize)error->length, (const jbyte *)error->message);
        if (!(*env)->ExceptionCheck(env)) {
            (*env)->CallStaticVoidMethod(env, native_class, fail_method, name, (jint)code, message, (jboolean)error->truncated);
        }
        (*env)->DeleteLocalRef(env, message);
    }
    (*env)->DeleteLocalRef(env, name);
    if (!(*env)->ExceptionCheck(env)) qpj_throw_class(env, "java/lang/IllegalStateException", "native error was not thrown");
}
int qpj_enter(JNIEnv *env, const char *operation) {
    unsigned value = atomic_load_explicit(&ordinary_calls, memory_order_relaxed);
    while (value < JNI_CALL_LIMIT) {
        if (atomic_compare_exchange_weak_explicit(&ordinary_calls, &value, value + 1,
                memory_order_acquire, memory_order_relaxed)) return 1;
    }
    static const char message[] = "JNI call capacity exhausted before input copies";
    qpc_error_v1 error = {0}; error.code = QPC_RESOURCE_LIMIT;
    error.length = (uint32_t)(sizeof(message) - 1);
    memcpy(error.message, message, sizeof(message) - 1);
    qpj_throw_error(env, operation, QPC_RESOURCE_LIMIT, &error);
    return 0;
}
void qpj_leave(void) { atomic_fetch_sub_explicit(&ordinary_calls, 1, memory_order_release); }
void qpj_dispose(owned_bytes *bytes) {
    if (bytes->data != NULL) { qpj_wipe(bytes->data, bytes->length); free(bytes->data); }
    bytes->data = NULL; bytes->length = 0;
}
qpc_configuration_blob_v1 qpj_blob(const owned_bytes *bytes) {
    qpc_configuration_blob_v1 value = {bytes->length == 0 ? NULL : bytes->data, bytes->length};
    return value;
}
jboolean qpj_valid_commit(JNIEnv *env, jobject value) {
    return (*env)->CallStaticBooleanMethod(env, native_class, valid_commit_method, value);
}
jint qpj_commit(JNIEnv *env, jobject value, jbyteArray session, jbyteArray message, jbyteArray plaintext) {
    return (*env)->CallStaticIntMethod(env, native_class, commit_method, value, session, message, plaintext);
}
static jlong prepare_configuration(JNIEnv *env, jclass type, jobjectArray inputs, jint operation,
                                    jint trust, jlong version) {
    (void)type;
    const char *name = operation == 1 ? "configuration-create" : operation == 2 ? "configuration-reconcile" : "configuration-open";
    if (!qpj_enter(env, name)) return 0;
    owned_bytes values[INPUT_COUNT] = {{0}};
    uint64_t handle = 0;
    if ((operation < 1 || operation > 3) || (trust != 1 && trust != 2)) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "configuration selector"); goto cleanup;
    }
    const int create = operation != 3;
    const jsize minimum[INPUT_COUNT] = {1,32,1952,trust == 1 ? 0 : 1952,create ? 1 : 0,
        create ? 3309 : 0,create && trust == 2 ? 3309 : 0,32,1985,32,1,create ? 1 : 0,create ? 1 : 0};
    const jsize maximum[INPUT_COUNT] = {4096,32,1952,trust == 1 ? 0 : 1952,create ? 65536 : 0,
        create ? 3309 : 0,create && trust == 2 ? 3309 : 0,32,1985,32,8192,create ? 8192 : 0,create ? 8192 : 0};
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, INPUT_COUNT)) goto cleanup;
    qpc_configuration_sdk_trust_v1 sdk = {0}; sdk.mode = (uint32_t)trust;
    memcpy(sdk.scope, values[1].data, 32); sdk.initial_root = qpj_blob(&values[2]); sdk.recovery_root = qpj_blob(&values[3]);
    qpc_configuration_protocol_v1 protocol = {0};
    memcpy(protocol.family, values[7].data, 32); protocol.root = qpj_blob(&values[8]);
    protocol.version = (uint64_t)version; memcpy(protocol.digest, values[9].data, 32); protocol.policy = qpj_blob(&values[10]);
    qpc_error_v1 error = {0}; int32_t code;
    if (create) {
        qpc_configuration_create_v1 input = {0};
        input.header.struct_size = (uint32_t)sizeof(input); input.header.version = 1; input.sdk = sdk;
        input.sdk_policy = qpj_blob(&values[4]); input.sdk_signature = qpj_blob(&values[5]); input.recovery_enrollment = qpj_blob(&values[6]);
        input.protocol = protocol; input.tls_certificate = qpj_blob(&values[11]); input.tls_key = qpj_blob(&values[12]);
        code = operation == 1 ? qpc_configuration_v1_prepare_create(values[0].data, values[0].length, &input, &handle, &error)
            : qpc_configuration_v1_prepare_reconcile(values[0].data, values[0].length, &input, &handle, &error);
    } else {
        qpc_configuration_open_v1 input = {0};
        input.header.struct_size = (uint32_t)sizeof(input); input.header.version = 1; input.sdk = sdk; input.protocol = protocol;
        code = qpc_configuration_v1_prepare_open(values[0].data, values[0].length, &input, &handle, &error);
    }
    if (code != 0) { qpj_throw_error(env, name, code, &error); handle = 0; }
    else if (handle == 0) qpj_throw_class(env, "java/lang/IllegalStateException", "native constructor returned zero owner");
cleanup:
    for (size_t i = 0; i < INPUT_COUNT; ++i) {
        qpj_dispose(&values[i]);
    }
    qpj_leave(); return (jlong)handle;
}
static void action(JNIEnv *env, jclass type, jlong handle, jint operation) {
    (void)type;
    if (operation < 1 || operation > 4) { qpj_throw_class(env, "java/lang/IllegalArgumentException", "owner action"); return; }
    const char *name = operation == 1 ? "finish-open" : operation == 2 ? "cancel" : operation == 3 ? "close" : "enrollment-activate";
    const int ordinary = operation == 1 || operation == 4;
    if (ordinary && !qpj_enter(env, name)) return;
    qpc_error_v1 error = {0};
    int32_t code = operation == 1 ? qpc_owner_v1_finish_open((uint64_t)handle, &error)
        : operation == 2 ? qpc_owner_v1_cancel((uint64_t)handle, &error)
        : operation == 3 ? qpc_owner_v1_close((uint64_t)handle, &error) : qpc_enrollment_v1_activate((uint64_t)handle, &error);
    if (code != 0) qpj_throw_error(env, name, code, &error);
    if (ordinary) qpj_leave();
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved; JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass local = (*env)->FindClass(env, "dev/qperiapt/continuity/android/Native");
    if (local == NULL) return JNI_ERR;
    fail_method = (*env)->GetStaticMethodID(env, local, "fail", "(Ljava/lang/String;I[BZ)V");
    if (fail_method == NULL) { (*env)->DeleteLocalRef(env, local); return JNI_ERR; }
    valid_commit_method = (*env)->GetStaticMethodID(env, local, "validCommit", "(Ljava/lang/Object;)Z");
    if (valid_commit_method == NULL) { (*env)->DeleteLocalRef(env, local); return JNI_ERR; }
    commit_method = (*env)->GetStaticMethodID(env, local, "invokeCommit", "(Ljava/lang/Object;[B[B[B)I");
    if (commit_method == NULL) { (*env)->DeleteLocalRef(env, local); return JNI_ERR; }
    native_class = (*env)->NewGlobalRef(env, local);
    if (native_class == NULL) { (*env)->DeleteLocalRef(env, local); return JNI_ERR; }
    const JNINativeMethod methods[] = {
        {"prepareConfiguration", "([[BIIJ)J", (void *)prepare_configuration},
        {"action", "(JI)V", (void *)action},
        {"beginEnrollment", "(J[[B[JIII)V", (void *)qpj_begin_enrollment},
        {"enrollmentQuery", "(JI)[B", (void *)qpj_enrollment_query},
        {"enrollmentAccept", "(J[[BJ)[B", (void *)qpj_enrollment_accept},
        {"preparePeer", "(J[[B[JIIZ)J", (void *)qpj_prepare_peer},
        {"accountCommand", "(JI[J[[BI)[B", (void *)qpj_account_command},
        {"peerCommand", "(JI[[BJ)[B", (void *)qpj_peer_command},
        {"peerServer", "(JI[[BLjava/lang/Object;)[B", (void *)qpj_peer_server},
        {"provisionAuthority", "([[B)V", (void *)qpj_provision_authority},
        {"prepareAuthority", "([[BZ)J", (void *)qpj_prepare_authority},
        {"authorityCommand", "(JI[[BJ)[B", (void *)qpj_authority_command},
        {"selectAuthority", "(JJ[[B)V", (void *)qpj_select_authority},
        {"credentialCommand", "(JI[[BJ)[B", (void *)qpj_credential_command},
        {"rosterCommand", "(JI[[B)[B", (void *)qpj_roster_command},
        {"policyCommand", "(JI[[B)[B", (void *)qpj_policy_command},
        {"selectPolicy", "(JJ)V", (void *)qpj_select_policy},
        {"prepareRetired", "([[B[J)J", (void *)qpj_prepare_retired},
        {"rootCommand", "(JJI[[B[J)[B", (void *)qpj_root_command},
    {"retiredCommand", "(JI[[B)[B", (void *)qpj_retired_command}
    };
    jint result = (*env)->RegisterNatives(env, local, methods, (jint)(sizeof(methods) / sizeof(methods[0])));
    (*env)->DeleteLocalRef(env, local);
    if (result != JNI_OK) { (*env)->DeleteGlobalRef(env, native_class); native_class = NULL; return JNI_ERR; }
    return JNI_VERSION_1_6;
}
