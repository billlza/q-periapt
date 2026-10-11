/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "bridge.h"
#include <stdlib.h>

int qpj_copy_fields(JNIEnv *env, jobjectArray inputs, owned_bytes *values,
        const jsize *minimum, const jsize *maximum, size_t count) {
    enum { LIMIT = 16 };
    jbyteArray arrays[LIMIT] = {0};
    jsize lengths[LIMIT] = {0};
    int copied = 0;
    if (count > LIMIT) { qpj_throw_class(env, "java/lang/IllegalStateException", "JNI field census capacity"); return 0; }
    if (inputs == NULL) { qpj_throw_class(env, "java/lang/NullPointerException", "native inputs"); return 0; }
    if ((*env)->EnsureLocalCapacity(env, LIMIT + 4) < 0) return 0;
    if ((*env)->GetArrayLength(env, inputs) != (jsize)count) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "native input count"); return 0;
    }
    for (size_t i = 0; i < count; ++i) {
        arrays[i] = (jbyteArray)(*env)->GetObjectArrayElement(env, inputs, (jsize)i);
        if ((*env)->ExceptionCheck(env)) goto cleanup;
        if (arrays[i] == NULL) { qpj_throw_class(env, "java/lang/NullPointerException", "native input field"); goto cleanup; }
        lengths[i] = (*env)->GetArrayLength(env, arrays[i]);
        if ((*env)->ExceptionCheck(env)) goto cleanup;
        if (lengths[i] < minimum[i] || lengths[i] > maximum[i]) {
            qpj_throw_class(env, "java/lang/IllegalArgumentException", "native field width"); goto cleanup;
        }
    }
    for (size_t i = 0; i < count; ++i) {
        values[i].length = (size_t)lengths[i];
        if (lengths[i] == 0) continue;
        values[i].data = malloc((size_t)lengths[i]);
        if (values[i].data == NULL) { qpj_throw_class(env, "java/lang/OutOfMemoryError", "native input copy"); goto cleanup; }
        (*env)->GetByteArrayRegion(env, arrays[i], 0, lengths[i], (jbyte *)values[i].data);
        if ((*env)->ExceptionCheck(env)) goto cleanup;
    }
    copied = 1;
cleanup:
    for (size_t i = 0; i < count; ++i) if (arrays[i] != NULL) (*env)->DeleteLocalRef(env, arrays[i]);
    return copied;
}
