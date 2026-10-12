/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPERIAPT_CONTINUITY_JNI_BRIDGE_H
#define QPERIAPT_CONTINUITY_JNI_BRIDGE_H
#include <jni.h>
#include "qpc_owner.h"

typedef struct { uint8_t *data; size_t length; } owned_bytes;
/* Largest admitted shape: request, two account pins, approvals and previous policy. */
enum { QPJ_INPUT_FIELD_LIMIT = 17 };
void qpj_wipe(void *pointer, size_t length);
void qpj_throw_class(JNIEnv *env, const char *name, const char *message);
void qpj_throw_error(JNIEnv *env, const char *operation, int32_t code, const qpc_error_v1 *error);
int qpj_enter(JNIEnv *env, const char *operation);
void qpj_leave(void);
void qpj_dispose(owned_bytes *bytes);
qpc_configuration_blob_v1 qpj_blob(const owned_bytes *bytes);
/* Every shape is checked before any payload copy. Caller disposes partial copies. */
int qpj_copy_fields(JNIEnv *env, jobjectArray inputs, owned_bytes *values,
    const jsize *minimum, const jsize *maximum, size_t count);
void qpj_begin_enrollment(JNIEnv *, jclass, jlong, jobjectArray, jlongArray, jint, jint, jint);
jbyteArray qpj_enrollment_query(JNIEnv *, jclass, jlong, jint);
jbyteArray qpj_enrollment_accept(JNIEnv *, jclass, jlong, jobjectArray, jlong);
jlong qpj_prepare_peer(JNIEnv *, jclass, jlong, jobjectArray, jlongArray, jint, jint, jboolean);
jbyteArray qpj_peer_command(JNIEnv *, jclass, jlong, jint, jobjectArray, jlong);
jbyteArray qpj_peer_server(JNIEnv *, jclass, jlong, jint, jobjectArray, jobject);
jboolean qpj_valid_commit(JNIEnv *, jobject);
jint qpj_commit(JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);
void qpj_provision_authority(JNIEnv *, jclass, jobjectArray);
jlong qpj_prepare_authority(JNIEnv *, jclass, jobjectArray, jboolean);
jbyteArray qpj_authority_command(JNIEnv *, jclass, jlong, jint, jobjectArray, jlong);
void qpj_select_authority(JNIEnv *, jclass, jlong, jlong, jobjectArray);
jbyteArray qpj_credential_command(JNIEnv *, jclass, jlong, jint, jobjectArray, jlong);
jbyteArray qpj_roster_command(JNIEnv *, jclass, jlong, jint, jobjectArray);
jbyteArray qpj_policy_command(JNIEnv *, jclass, jlong, jint, jobjectArray);
void qpj_select_policy(JNIEnv *, jclass, jlong, jlong);
jlong qpj_prepare_retired(JNIEnv *, jclass, jobjectArray, jlongArray);
jbyteArray qpj_retired_command(JNIEnv *, jclass, jlong, jint, jobjectArray);
#endif
