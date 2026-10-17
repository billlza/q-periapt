/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "bridge.h"
#include <string.h>

static void put64(uint8_t *output, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) output[i] = (uint8_t)(value >> (56 - 8 * i));
}
static uint64_t get64(const uint8_t *input) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | input[i];
    return value;
}
void qpj_provision_authority(JNIEnv *env, jclass type, jobjectArray inputs) {
    (void)type;
    const char *name = "authority-provision-key";
    if (!qpj_enter(env, name)) return;
    owned_bytes path = {0};
    const jsize minimum[1] = {1}, maximum[1] = {4096};
    if (!qpj_copy_fields(env, inputs, &path, minimum, maximum, 1)) goto cleanup;
    qpc_error_v1 error = {0};
    int32_t code = qpc_authority_v1_provision_wrapping_key(path.data, path.length, &error);
    if (code != 0) qpj_throw_error(env, name, code, &error);
cleanup:
    qpj_dispose(&path); qpj_leave();
}
jlong qpj_prepare_authority(JNIEnv *env, jclass type, jobjectArray inputs, jboolean create) {
    (void)type;
    const char *name = create ? "authority-create" : "authority-open";
    if (!qpj_enter(env, name)) return 0;
    uint64_t handle = 0;
    owned_bytes values[5] = {{0}};
    if (create != JNI_FALSE && create != JNI_TRUE) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "authority selector"); goto cleanup;
    }
    const jsize minimum[5] = {1,32,32,32,1985}, maximum[5] = {4096,32,32,32,1985};
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, 5)) goto cleanup;
    qpc_authority_options_v1 options = {0}; options.struct_size = (uint32_t)sizeof(options);
    memcpy(options.identity, values[1].data, 32); memcpy(options.family, values[2].data, 32);
    memcpy(options.witness, values[3].data, 32); options.public_key = values[4].data; options.public_key_length = values[4].length;
    qpc_error_v1 error = {0};
    int32_t code = create ? qpc_authority_v1_prepare_create(values[0].data, values[0].length, &options, &handle, &error)
        : qpc_authority_v1_prepare_open(values[0].data, values[0].length, &options, &handle, &error);
    if (code != 0) { qpj_throw_error(env, name, code, &error); handle = 0; }
    else if (handle == 0) qpj_throw_class(env, "java/lang/IllegalStateException", "native authority returned zero owner");
cleanup:
    for (size_t i = 0; i < 5; ++i) qpj_dispose(&values[i]);
    qpj_leave(); return (jlong)handle;
}
jbyteArray qpj_authority_command(JNIEnv *env, jclass type, jlong handle, jint operation, jobjectArray inputs, jlong version) {
    (void)type;
    const char *name = operation == 1 ? "authority-checkpoint" : "authority-associate";
    if (!qpj_enter(env, name)) return NULL;
    owned_bytes values[7] = {{0}};
    jbyteArray output = NULL;
    if ((operation != 1 && operation != 2) || (operation == 1 && version != 0)) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "authority operation"); goto cleanup;
    }
    const jsize minimum[7] = {32,32,1985,32,32,1,1}, maximum[7] = {32,32,1985,32,32,8192,8192};
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, operation == 1 ? 1 : 7)) goto cleanup;
    output = (*env)->NewByteArray(env, 72); if (output == NULL) goto cleanup;
    qpc_authority_checkpoint_v1 checkpoint = {0};
    qpc_error_v1 error = {0};
    int32_t code;
    if (operation == 1) code = qpc_authority_v1_checkpoint((uint64_t)handle, values[0].data, &checkpoint, &error);
    else {
        qpc_account_pin_v1 pin = {0};
        memcpy(pin.account, values[1].data, 32); pin.root = values[2].data; pin.root_length = values[2].length;
        memcpy(pin.family, values[3].data, 32); pin.checkpoint.version = (uint64_t)version;
        memcpy(pin.checkpoint.digest, values[4].data, 32);
        qpc_authority_association_v1 association = {0}; association.struct_size = (uint32_t)sizeof(association);
        memcpy(association.application, values[0].data, 32); association.pin = &pin;
        association.certificate = values[5].data; association.certificate_length = values[5].length;
        association.roster = values[6].data; association.roster_length = values[6].length;
        code = qpc_authority_v1_associate((uint64_t)handle, &association, &checkpoint, &error);
    }
    if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
    uint8_t wire[72] = {0};
    memcpy(wire, checkpoint.application, 32); put64(wire + 32, checkpoint.revision); memcpy(wire + 40, checkpoint.account, 32);
    (*env)->SetByteArrayRegion(env, output, 0, 72, (const jbyte *)wire);
cleanup:
    for (size_t i = 0; i < 7; ++i) qpj_dispose(&values[i]);
    qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}
void qpj_select_authority(JNIEnv *env, jclass type, jlong enrollment, jlong registry, jobjectArray inputs) {
    (void)type;
    const char *name = "authority-select-enrollment";
    if (!qpj_enter(env, name)) return;
    owned_bytes checkpoint = {0};
    const jsize minimum[1] = {72}, maximum[1] = {72};
    if (!qpj_copy_fields(env, inputs, &checkpoint, minimum, maximum, 1)) goto cleanup;
    qpc_authority_enrollment_selection_v1 options = {0}; options.struct_size = (uint32_t)sizeof(options);
    options.registry = (uint64_t)registry; memcpy(options.checkpoint.application, checkpoint.data, 32);
    options.checkpoint.revision = get64(checkpoint.data + 32); memcpy(options.checkpoint.account, checkpoint.data + 40, 32);
    qpc_error_v1 error = {0};
    int32_t code = qpc_authority_v1_select_enrollment((uint64_t)enrollment, &options, &error);
    if (code != 0) qpj_throw_error(env, name, code, &error);
cleanup:
    qpj_dispose(&checkpoint); qpj_leave();
}
