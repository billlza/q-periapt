/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "bridge.h"
#include <stdlib.h>
#include <string.h>

static void put32(uint8_t *output, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) output[i] = (uint8_t)(value >> (24 - 8 * i));
}
static void put64(uint8_t *output, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) output[i] = (uint8_t)(value >> (56 - 8 * i));
}
void qpj_begin_enrollment(JNIEnv *env, jclass type, jlong handle, jobjectArray inputs,
        jlongArray numbers, jint mode, jint carrier, jint timeout) {
    (void)type;
    const char *name = mode == 1 ? "enrollment-create" : "enrollment-resume";
    if (!qpj_enter(env, name)) return;
    owned_bytes values[10] = {{0}};
    jlong counters[3] = {0};
    if ((mode != 1 && mode != 2) || carrier < 0 || carrier > 2
            || (carrier == 0 ? timeout != 0 : (timeout < 1 || timeout > 10000))) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "enrollment selector"); goto cleanup;
    }
    if (numbers == NULL) { qpj_throw_class(env, "java/lang/NullPointerException", "enrollment counters"); goto cleanup; }
    if ((*env)->GetArrayLength(env, numbers) != 3) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "enrollment counter width"); goto cleanup;
    }
    (*env)->GetLongArrayRegion(env, numbers, 0, 3, counters);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    const jsize minimum[10] = {1985,16,32,carrier ? 32 : 0,carrier ? 1985 : 0,carrier ? 1 : 0,
        carrier == 2 ? 1 : 0,carrier == 2 ? 1 : 0,carrier == 2 ? 1 : 0,carrier == 2 ? 1 : 0};
    const jsize maximum[10] = {1985,16,32,carrier ? 32 : 0,carrier ? 1985 : 0,carrier ? 128 : 0,
        carrier == 2 ? 8192 : 0,carrier == 2 ? 8192 : 0,carrier == 2 ? 8192 : 0,carrier == 2 ? 128 : 0};
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, 10)) goto cleanup;
    qpc_enrollment_intent_v1 intent = {0};
    intent.root = values[0].data; intent.root_length = values[0].length;
    memcpy(intent.device, values[1].data, 16); memcpy(intent.family, values[2].data, 32);
    intent.generation = (uint64_t)counters[0]; intent.valid_from = (uint64_t)counters[1]; intent.valid_until = (uint64_t)counters[2];
    qpc_configuration_witness_v1 witness = {0};
    if (carrier != 0) {
        witness.header.struct_size = (uint32_t)sizeof(witness); witness.header.version = 1; witness.carrier = (uint32_t)carrier;
        memcpy(witness.identity, values[3].data, 32); witness.public_key = qpj_blob(&values[4]);
        witness.options.address = values[5].data; witness.options.address_length = values[5].length; witness.options.timeout_ms = (uint32_t)timeout;
        witness.tls_peer = qpj_blob(&values[6]); witness.tls_certificate = qpj_blob(&values[7]);
        witness.tls_key = qpj_blob(&values[8]); witness.tls_name = qpj_blob(&values[9]);
    }
    qpc_error_v1 error = {0};
    int32_t code = qpc_configuration_v1_begin_enrollment((uint64_t)handle, &intent, (uint32_t)mode, carrier == 0 ? NULL : &witness, &error);
    if (code != 0) qpj_throw_error(env, name, code, &error);
cleanup:
    for (size_t i = 0; i < 10; ++i) qpj_dispose(&values[i]);
    qpj_leave();
}

jbyteArray qpj_enrollment_query(JNIEnv *env, jclass type, jlong handle, jint operation) {
    (void)type;
    const char *name = operation == 1 ? "enrollment-status" : operation == 2 ? "enrollment-request" : "enrollment-storage";
    if (!qpj_enter(env, name)) return NULL;
    jbyteArray output = NULL;
    qpc_enrollment_request_v1 *request = NULL;
    if (operation < 1 || operation > 3) {
        qpj_throw_class(env, "java/lang/IllegalArgumentException", "enrollment query"); goto cleanup;
    }
    const jsize capacity = operation == 1 ? 148 : operation == 2 ? 8196 : 164;
    output = (*env)->NewByteArray(env, capacity);
    if (output == NULL) goto cleanup;
    qpc_error_v1 error = {0};
    int32_t code;
    if (operation == 1) {
        qpc_enrollment_status_v1 status = {0};
        uint8_t wire[148] = {0};
        code = qpc_enrollment_v1_status((uint64_t)handle, &status, &error);
        if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
        put32(wire, status.phase); memcpy(wire + 4, status.signing_id, 32); memcpy(wire + 36, status.journal, 32);
        put64(wire + 68, status.previous.version); memcpy(wire + 76, status.previous.digest, 32);
        put64(wire + 108, status.next.version); memcpy(wire + 116, status.next.digest, 32);
        (*env)->SetByteArrayRegion(env, output, 0, capacity, (const jbyte *)wire);
    } else if (operation == 2) {
        request = calloc(1, sizeof(*request));
        if (request == NULL) { qpj_throw_class(env, "java/lang/OutOfMemoryError", "enrollment request"); goto cleanup; }
        code = qpc_enrollment_v1_request((uint64_t)handle, request, &error);
        if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
        if (request->length < 1 || request->length > sizeof(request->bytes)) {
            qpj_throw_class(env, "java/lang/IllegalStateException", "native request length"); goto cleanup;
        }
        uint8_t length[4]; put32(length, request->length);
        (*env)->SetByteArrayRegion(env, output, 0, 4, (const jbyte *)length);
        if ((*env)->ExceptionCheck(env)) goto cleanup;
        (*env)->SetByteArrayRegion(env, output, 4, 8192, (const jbyte *)request->bytes);
    } else {
        qpc_setup_preparation_v1 preparation = {0};
        uint8_t wire[164] = {0};
        code = qpc_enrollment_v1_prepare_storage((uint64_t)handle, &preparation, &error);
        if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
        put32(wire, preparation.protection); memcpy(wire + 4, preparation.journal, 32);
        memcpy(wire + 36, preparation.subject, 96); memcpy(wire + 132, preparation.image_digest, 32);
        (*env)->SetByteArrayRegion(env, output, 0, capacity, (const jbyte *)wire);
    }
cleanup:
    if (request != NULL) { qpj_wipe(request, sizeof(*request)); free(request); }
    qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}

jbyteArray qpj_enrollment_accept(JNIEnv *env, jclass type, jlong handle, jobjectArray inputs, jlong version) {
    (void)type;
    const char *name = "enrollment-accept";
    if (!qpj_enter(env, name)) return NULL;
    owned_bytes values[6] = {{0}};
    jbyteArray output = NULL;
    const jsize minimum[6] = {1,1,32,1985,32,32};
    const jsize maximum[6] = {8192,8192,32,1985,32,32};
    if (!qpj_copy_fields(env, inputs, values, minimum, maximum, 6)) goto cleanup;
    output = (*env)->NewByteArray(env, 32);
    if (output == NULL) goto cleanup;
    qpc_account_pin_v1 pin = {0};
    memcpy(pin.account, values[2].data, 32); pin.root = values[3].data; pin.root_length = values[3].length;
    memcpy(pin.family, values[4].data, 32); pin.checkpoint.version = (uint64_t)version; memcpy(pin.checkpoint.digest, values[5].data, 32);
    uint8_t journal[32] = {0};
    qpc_error_v1 error = {0};
    int32_t code = qpc_enrollment_v1_accept((uint64_t)handle, values[0].data, values[0].length,
        values[1].data, values[1].length, &pin, journal, &error);
    if (code != 0) { qpj_throw_error(env, name, code, &error); goto cleanup; }
    (*env)->SetByteArrayRegion(env, output, 0, 32, (const jbyte *)journal);
cleanup:
    for (size_t i = 0; i < 6; ++i) qpj_dispose(&values[i]);
    qpj_leave();
    if ((*env)->ExceptionCheck(env)) {
        if (output != NULL) (*env)->DeleteLocalRef(env, output);
        return NULL;
    }
    return output;
}
