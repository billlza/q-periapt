/* Executes the real JNI adapter with public bytes and a recording JNI/ABI boundary. */
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jni.h>
#include "q_periapt.h"

struct array { jsize length; jbyte *bytes; };
struct allocation { void *pointer; size_t length; };
static struct allocation allocations[24];
static size_t allocation_count, allocation_calls, copy_calls, output_calls, backend_calls;
static size_t fail_allocation, fail_copy, fail_output;
static int fail_result_array, sdk_live, sdk_status;
static size_t sdk_close_calls;
static int pending, native_code;
static const char *exception_class, *exception_message, *native_operation;
static jbyte public_bytes[65537], result_bytes[Q_PERIAPT_SDK_EXPANDED_KEY_LEN];
static struct array returned_array;
static size_t cases;

static void *record_malloc(size_t length) {
    allocation_calls++;
    if (allocation_calls == fail_allocation) return NULL;
    void *pointer = malloc(length);
    assert(pointer != NULL && allocation_count < 24);
    memset(pointer, 0, length);
    allocations[allocation_count++] = (struct allocation){pointer, length};
    return pointer;
}
static void record_free(void *pointer) {
    if (pointer == NULL) return;
    size_t index = 0;
    while (index < allocation_count && allocations[index].pointer != pointer) index++;
    assert(index < allocation_count);
    const unsigned char *bytes = pointer;
    for (size_t i = 0; i < allocations[index].length; i++) assert(bytes[i] == 0);
    allocations[index] = allocations[--allocation_count];
    free(pointer);
}
static jboolean JNICALL has_exception(JNIEnv *env) { (void)env; return pending ? JNI_TRUE : JNI_FALSE; }
static void JNICALL clear_exception(JNIEnv *env) { (void)env; pending = 0; }
static jsize JNICALL length_of(JNIEnv *env, jarray value) {
    (void)env; assert(!pending && value != NULL); return ((struct array *)value)->length;
}
static void JNICALL copy_region(JNIEnv *env, jbyteArray value, jsize start, jsize length, jbyte *out) {
    (void)env; assert(!pending && start == 0 && length == ((struct array *)value)->length);
    copy_calls++;
    memcpy(out, ((struct array *)value)->bytes, (size_t)length);
    if (copy_calls == fail_copy) {
        pending = 1; exception_class = "java/lang/OutOfMemoryError";
    }
}
static void JNICALL set_region(JNIEnv *env, jbyteArray value, jsize start, jsize length, const jbyte *in) {
    (void)env; assert(!pending && start == 0 && length == ((struct array *)value)->length);
    output_calls++;
    memcpy(((struct array *)value)->bytes, in, (size_t)length);
    if (output_calls == fail_output) {
        pending = 1; exception_class = "java/lang/OutOfMemoryError";
    }
}
static jbyteArray JNICALL new_array(JNIEnv *env, jsize length) {
    (void)env; assert(!pending && length >= 0 && (size_t)length <= sizeof(result_bytes));
    if (fail_result_array) { pending = 1; exception_class = "java/lang/OutOfMemoryError"; return NULL; }
    returned_array = (struct array){length, result_bytes};
    return (jbyteArray)&returned_array;
}
static jclass JNICALL find_class(JNIEnv *env, const char *name) {
    (void)env; assert(!pending); exception_class = name; return (jclass)(uintptr_t)1;
}
static jmethodID JNICALL get_method(JNIEnv *env, jclass cls, const char *name, const char *signature) {
    (void)env; (void)cls; assert(!pending);
    assert(strcmp(name, "<init>") == 0 && strcmp(signature, "(Ljava/lang/String;ILjava/lang/String;)V") == 0);
    return (jmethodID)(uintptr_t)1;
}
static jstring JNICALL new_string(JNIEnv *env, const char *value) { (void)env; assert(!pending); return (jstring)value; }
static const char *status_name(int32_t code);
static jobject JNICALL new_object(JNIEnv *env, jclass cls, jmethodID method, ...) {
    (void)env; (void)method; assert(!pending);
    va_list arguments; va_start(arguments, method);
    native_operation = (const char *)va_arg(arguments, jstring);
    native_code = va_arg(arguments, jint);
    const char *status = (const char *)va_arg(arguments, jstring);
    assert(strcmp(status, status_name(native_code)) == 0);
    va_end(arguments);
    return (jobject)cls;
}
static jint JNICALL throw_object(JNIEnv *env, jthrowable value) { (void)env; (void)value; assert(!pending); pending = 1; return JNI_OK; }
static jint JNICALL throw_string(JNIEnv *env, jclass cls, const char *value) {
    (void)env; (void)cls; assert(!pending); pending = 1; exception_message = value; return JNI_OK;
}
static const char *status_name(int32_t code) {
    switch (code) {
        case Q_PERIAPT_ERR_LENGTH: return "ERR_LENGTH";
        case Q_PERIAPT_ERR_POLICY: return "ERR_POLICY";
        case Q_PERIAPT_ERR_LIMITS: return "ERR_LIMITS";
        case Q_PERIAPT_ERR_CLOSED: return "ERR_CLOSED";
        default: assert(0); return NULL;
    }
}

/* Recording ABI boundary for JNI fault injection, not cryptographic evidence.
 * sdk-jni-host-smoke.sh separately executes this adapter against the real core. */
static int32_t sdk_create(uint64_t *out) {
    backend_calls++;
    assert(!sdk_live);
    if (sdk_status != Q_PERIAPT_OK) { *out = 0; return sdk_status; }
    sdk_live = 1; *out = 100;
    return Q_PERIAPT_OK;
}
uint32_t q_periapt_sdk_extension_version(void) { return 1; }
int32_t q_periapt_sdk_runtime_new(const QPeriaptRuntimeOptions *options, uint64_t *out) {
    assert(options->struct_size == sizeof(*options) && options->extension_version == 1);
    return sdk_create(out);
}
int32_t q_periapt_sdk_key_generate(uint64_t parent, uint64_t *out) { assert(parent == 42); return sdk_create(out); }
int32_t q_periapt_sdk_runtime_state(uint64_t handle, QPeriaptOutput out) {
    assert(handle == 42);
    backend_calls++;
    memset(out.data, sdk_status == Q_PERIAPT_OK ? 0x42 : 0, out.len);
    return sdk_status;
}
int32_t q_periapt_sdk_key_public(uint64_t handle, QPeriaptOutput out) { return q_periapt_sdk_runtime_state(handle, out); }
int32_t q_periapt_sdk_secret_export(uint64_t handle, QPeriaptOutput out) { return q_periapt_sdk_runtime_state(handle, out); }
int32_t q_periapt_sdk_derived_key_export(uint64_t handle, QPeriaptOutput out) { return q_periapt_sdk_runtime_state(handle, out); }
int32_t q_periapt_sdk_policy_update_states(uint64_t handle, QPeriaptOutput out) { return q_periapt_sdk_runtime_state(handle, out); }
int32_t q_periapt_sdk_expert_key_export(uint64_t handle, QPeriaptOutput out) { return q_periapt_sdk_runtime_state(handle, out); }
int32_t q_periapt_sdk_runtime_enabled(uint64_t handle, uint32_t *out) {
    assert(handle == 42); backend_calls++;
    *out = sdk_status == Q_PERIAPT_OK ? 1 : 0;
    return sdk_status;
}
int32_t q_periapt_sdk_policy_update_activate(uint64_t handle, uint64_t *out) { assert(handle == 42); return sdk_create(out); }
int32_t q_periapt_sdk_runtime_prepare_update(uint64_t handle, QPeriaptInput policy, QPeriaptInput signature, uint64_t *out) {
    assert(handle == 42 && policy.len > 0 && policy.len <= 65536 && signature.len == 3309);
    return sdk_create(out);
}
int32_t q_periapt_sdk_expert_key_import(uint64_t handle, QPeriaptInput encoded, uint64_t *out) {
    assert(handle == 42 && encoded.len == Q_PERIAPT_SDK_EXPANDED_KEY_LEN);
    return sdk_create(out);
}
int32_t q_periapt_sdk_secret_derive(uint64_t parent, uint32_t purpose, QPeriaptInput label, QPeriaptInput context, uint64_t *out) {
    assert(parent == 42 && purpose == 1 && label.len > 0 && label.len <= 255 && context.len <= 65536);
    return sdk_create(out);
}
int32_t q_periapt_sdk_encapsulate(uint64_t parent, QPeriaptInput peer, QPeriaptInput context, QPeriaptOutput ct, uint64_t *out) {
    assert(parent == 42 && peer.len == Q_PERIAPT_SDK_PUBLIC_KEY_LEN && context.len <= 65536);
    memset(ct.data, 0x42, ct.len);
    return sdk_create(out);
}
int32_t q_periapt_sdk_decapsulate(uint64_t parent, QPeriaptInput ct, QPeriaptInput context, uint64_t *out) {
    assert(parent == 42 && ct.len == Q_PERIAPT_SDK_CIPHERTEXT_LEN && context.len <= 65536);
    return sdk_create(out);
}
int32_t q_periapt_sdk_close(uint64_t handle) {
    assert(handle == 100 && sdk_live);
    sdk_live = 0; sdk_close_calls++;
    return Q_PERIAPT_OK;
}
static int32_t write_one(uint8_t *out, uintptr_t length) {
    backend_calls++; memset(out, 0x42, length); return Q_PERIAPT_OK;
}
static int32_t write_three(uint8_t *a, uintptr_t al, uint8_t *b, uintptr_t bl, uint8_t *c, uintptr_t cl) {
    memset(b, 0x42, bl); memset(c, 0x42, cl); return write_one(a, al);
}
static int32_t write_four(uint8_t *a, uintptr_t al, uint8_t *b, uintptr_t bl, uint8_t *c, uintptr_t cl, uint8_t *d, uintptr_t dl) {
    memset(d, 0x42, dl); return write_three(a, al, b, bl, c, cl);
}
#define malloc record_malloc
#define free record_free
#define q_periapt_abi_version() Q_PERIAPT_ABI_VERSION
#define q_periapt_version() "0.1.5"
#define q_periapt_fixed_suite_id() "ML-KEM-768+X25519"
#define q_periapt_fixed_suite_id_len() ((uintptr_t)16)
#define q_periapt_status_name(code) status_name(code)
#define q_periapt_decision_from_signed_policy(t,tl,s,sl,v,vl,st,stl,o,ol) write_one(o,ol)
#define q_periapt_generate_keypair(d,dl,a,al,b,bl,c,cl,e,el) write_four(a,al,b,bl,c,cl,e,el)
#define q_periapt_encapsulate(d,dl,p,pl,t,tl,c,cl,a,al,b,bl,e,el) write_three(a,al,b,bl,e,el)
#define q_periapt_decapsulate(d,dl,s,sl,c,cl,p,pl,t,tl,e,el,q,ql,a,al,o,ol) write_one(o,ol)
#include "qperiapt_jni.c"
#undef malloc
#undef free

static const struct JNINativeInterface_ jni = {
    .GetArrayLength = length_of, .GetByteArrayRegion = copy_region,
    .SetByteArrayRegion = set_region, .NewByteArray = new_array,
    .ExceptionCheck = has_exception, .ExceptionClear = clear_exception,
    .FindClass = find_class, .GetMethodID = get_method,
    .NewStringUTF = new_string, .NewObject = new_object,
    .Throw = throw_object, .ThrowNew = throw_string,
};
static JNIEnv environment = &jni;
enum operation { POLICY, KEYPAIR, ENCAP, DECAP };
static const char *operations[] = {
    "q_periapt_decision_from_signed_policy", "q_periapt_generate_keypair",
    "q_periapt_encapsulate", "q_periapt_decapsulate"
};
struct call {
    enum operation operation;
    size_t inputs, outputs;
    struct array arrays[12];
    jbyteArray input[8], output[4];
    jbyte output_bytes[4][Q_PERIAPT_MLKEM768_SK_LEN];
};
static void reset(void) {
    assert(allocation_count == 0);
    assert(!sdk_live);
    allocation_calls = copy_calls = output_calls = backend_calls = 0;
    fail_allocation = fail_copy = fail_output = 0;
    fail_result_array = 0; sdk_status = Q_PERIAPT_OK; sdk_close_calls = 0;
    pending = native_code = 0;
    exception_class = exception_message = native_operation = NULL;
}
static void setup(struct call *call, enum operation operation) {
    memset(call, 0, sizeof(*call));
    call->operation = operation;
    static const jsize input_lengths[4][8] = {
        {1, Q_PERIAPT_POLICY_SIGNATURE_LEN, Q_PERIAPT_POLICY_VERIFICATION_KEY_LEN, Q_PERIAPT_TRUSTED_POLICY_STATE_LEN},
        {Q_PERIAPT_POLICY_DECISION_LEN},
        {Q_PERIAPT_POLICY_DECISION_LEN, Q_PERIAPT_MLKEM768_PK_LEN, Q_PERIAPT_X25519_LEN, 1},
        {Q_PERIAPT_POLICY_DECISION_LEN, Q_PERIAPT_MLKEM768_SK_LEN, Q_PERIAPT_MLKEM768_CT_LEN, Q_PERIAPT_MLKEM768_PK_LEN,
            Q_PERIAPT_X25519_LEN, Q_PERIAPT_X25519_LEN, Q_PERIAPT_X25519_LEN, 1}
    };
    static const size_t input_counts[] = {4, 1, 4, 8}, output_counts[] = {0, 4, 3, 1};
    static const jsize output_lengths[4][4] = {
        {0}, {Q_PERIAPT_MLKEM768_SK_LEN, Q_PERIAPT_MLKEM768_PK_LEN, Q_PERIAPT_X25519_LEN, Q_PERIAPT_X25519_LEN},
        {Q_PERIAPT_MLKEM768_CT_LEN, Q_PERIAPT_X25519_LEN, Q_PERIAPT_SECRET_LEN}, {Q_PERIAPT_SECRET_LEN}
    };
    call->inputs = input_counts[operation]; call->outputs = output_counts[operation];
    for (size_t i = 0; i < call->inputs; i++) {
        call->arrays[i] = (struct array){input_lengths[operation][i], public_bytes};
        call->input[i] = (jbyteArray)&call->arrays[i];
    }
    for (size_t i = 0; i < call->outputs; i++) {
        call->arrays[8+i] = (struct array){output_lengths[operation][i], call->output_bytes[i]};
        call->output[i] = (jbyteArray)&call->arrays[8+i];
    }
    reset();
}
static void invoke(struct call *call) {
    jbyteArray *i = call->input, *o = call->output;
    switch (call->operation) {
        case POLICY: (void)native_decision_from_signed_policy(&environment, NULL, i[0], i[1], i[2], i[3]); break;
        case KEYPAIR: native_generate_keypair(&environment, NULL, i[0], o[0], o[1], o[2], o[3]); break;
        case ENCAP: native_encapsulate(&environment, NULL, i[0], i[1], i[2], i[3], o[0], o[1], o[2]); break;
        case DECAP: native_decapsulate(&environment, NULL, i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], o[0]); break;
    }
    assert(allocation_count == 0);
    cases++;
}
static void expect_native(struct call *call, int code) {
    invoke(call);
    assert(pending && native_code == code);
    assert(strcmp(exception_class, "dev/qperiapt/android/QPeriaptAndroid$QPeriaptException") == 0);
    assert(strcmp(native_operation, operations[call->operation]) == 0);
    assert(allocation_calls == 0 && copy_calls == 0 && backend_calls == 0);
}
static void expect_java(struct call *call, const char *type, const char *message) {
    invoke(call);
    assert(pending && strcmp(exception_class, type) == 0);
    if (message != NULL) assert(strcmp(exception_message, message) == 0);
    assert(allocation_calls == 0 && copy_calls == 0 && backend_calls == 0);
}

static void test_sdk_inputs(void) {
    size_t sdk_cases = 0;
    for (int op = 0; op < 6; op++) {
        const jsize good[6][4] = {{1, 3309, 1952, 36}, {1216, 1, 0, 0}, {1120, 1, 0, 0}, {255, 1, 0, 0}, {1, 3309, 0, 0}, {2440, 0, 0, 0}};
        const size_t count = op == 0 ? 4 : (op == 5 ? 1 : 2);
        // Baseline; malformed shape; each allocation/copy failure; output-copy failure.
        for (int variant = 0; variant < (int)(2 + 3 * count + (op == 1)); variant++) {
            reset();
            struct array arrays[4];
            jbyteArray inputs[4];
            for (size_t i = 0; i < count; i++) {
                arrays[i] = (struct array){good[op][i], public_bytes};
                inputs[i] = (jbyteArray)&arrays[i];
            }
            struct array output = {1120, result_bytes};
            if (variant >= 1 && variant <= (int)count) {
                size_t index = (size_t)variant - 1;
                arrays[index].length = ((op == 0 || op == 4) && index == 0) || (op != 0 && index == 1) ? 65537 : good[op][index] + 1;
            } else if (variant > (int)count && variant <= (int)(2 * count)) {
                fail_allocation = (size_t)variant - count;
            } else if (variant > (int)(2 * count) && variant <= (int)(3 * count)) {
                fail_copy = (size_t)variant - 2 * count;
            } else if (variant == (int)(3 * count + 1)) {
                sdk_status = Q_PERIAPT_ERR_CLOSED;
            } else if (variant != 0) {
                fail_output = 1;
            }
            jlong result;
            if (op == 0) result = native_sdk_runtime_new(&environment, NULL, inputs[0], inputs[1], inputs[2], inputs[3], 1, 1);
            else if (op == 1) result = native_sdk_encapsulate(&environment, NULL, 42, inputs[0], inputs[1], (jbyteArray)&output);
            else if (op == 2) result = native_sdk_decapsulate(&environment, NULL, 42, inputs[0], inputs[1]);
            else if (op == 3) result = native_sdk_secret_derive(&environment, NULL, 42, 1, inputs[0], inputs[1]);
            else if (op == 4) result = native_sdk_runtime_prepare_update(&environment, NULL, 42, inputs[0], inputs[1]);
            else result = native_sdk_expert_key_import(&environment, NULL, 42, inputs[0]);
            assert(allocation_count == 0);
            if (variant == 0) {
                assert(result == 100 && sdk_live && !pending && backend_calls == 1);
                q_periapt_sdk_close(100);
            } else {
                assert(result == 0 && !sdk_live && pending);
                if (variant <= (int)count) assert(native_code == Q_PERIAPT_ERR_LENGTH && allocation_calls == 0 && copy_calls == 0);
                if (variant <= (int)(3 * count)) assert(backend_calls == 0);
                if (fail_output) assert(sdk_close_calls == 1 && backend_calls == 1);
            }
            sdk_cases++;
        }
    }
    for (int op = 0; op < 6; op++) {
        for (int variant = 0; variant < 4; variant++) {
            reset();
            if (variant == 1) fail_result_array = 1;
            if (variant == 2) fail_output = 1;
            if (variant == 3) sdk_status = Q_PERIAPT_ERR_CLOSED;
            jbyteArray result = op == 0 ? native_sdk_runtime_state(&environment, NULL, 42) :
                op == 1 ? native_sdk_key_public(&environment, NULL, 42) :
                op == 2 ? native_sdk_secret_export(&environment, NULL, 42) :
                op == 3 ? native_sdk_derived_key_export(&environment, NULL, 42) :
                op == 4 ? native_sdk_policy_update_states(&environment, NULL, 42) : native_sdk_expert_key_export(&environment, NULL, 42);
            if (variant == 0) assert(result != NULL && !pending);
            else assert(result == NULL && pending);
            assert(backend_calls == (variant == 1 ? 0 : 1) && allocation_count == 0);
            sdk_cases++;
        }
    }
    for (int variant = 0; variant < 2; variant++) {
        reset();
        if (variant) sdk_status = Q_PERIAPT_ERR_CLOSED;
        jboolean enabled = native_sdk_runtime_enabled(&environment, NULL, 42);
        assert(enabled == (variant ? JNI_FALSE : JNI_TRUE));
        assert(pending == variant && backend_calls == 1 && allocation_count == 0);
        reset();
        if (variant) sdk_status = Q_PERIAPT_ERR_CLOSED;
        jlong handle = native_sdk_policy_update_activate(&environment, NULL, 42);
        assert(handle == (variant ? 0 : 100));
        assert(pending == variant && backend_calls == 1 && allocation_count == 0);
        if (!variant) q_periapt_sdk_close(100);
        sdk_cases += 2;
    }
    printf("SDK_JNI_INPUT_SHAPES_PASS cases=%zu\n", sdk_cases);
}
int main(void) {
    memset(public_bytes, 0x42, sizeof(public_bytes));
    struct call call;
    for (enum operation op = POLICY; op <= DECAP; op++) {
        setup(&call, op);
        size_t inputs = call.inputs, outputs = call.outputs;
        for (size_t field = 0; field < inputs; field++) {
            if ((op == POLICY && field == 0) || (op == ENCAP && field == 3) || (op == DECAP && field == 7)) continue;
            jsize exact = call.arrays[field].length;
            jsize lengths[] = {0, exact-1, exact, exact+1, 8192};
            for (size_t value = 0; value < 5; value++) {
                setup(&call, op); call.arrays[field].length = lengths[value];
                if (lengths[value] == exact || (op == POLICY && field == 3 && lengths[value] == 0)) {
                    invoke(&call); assert(!pending && backend_calls == 1 && copy_calls > 0);
                } else {
                    int code = ((op == POLICY && field != 3) || (op != POLICY && field == 0))
                        ? Q_PERIAPT_ERR_POLICY : Q_PERIAPT_ERR_LENGTH;
                    expect_native(&call, code);
                }
            }
        }
        for (size_t field = 0; field < outputs; field++) {
            setup(&call, op); jsize exact = call.arrays[8+field].length;
            jsize lengths[] = {0, exact-1, exact, exact+1, 8192};
            for (size_t value = 0; value < 5; value++) {
                setup(&call, op); call.arrays[8+field].length = lengths[value];
                if (lengths[value] == exact) { invoke(&call); assert(!pending && backend_calls == 1); }
                else expect_java(&call, "java/lang/IllegalArgumentException", "output array length mismatch");
            }
        }
        for (size_t field = 0; field < inputs; field++) {
            setup(&call, op); call.input[field] = NULL;
            expect_java(&call, "java/lang/NullPointerException", NULL);
        }
        for (size_t field = 0; field < outputs; field++) {
            setup(&call, op); call.output[field] = NULL;
            expect_java(&call, "java/lang/NullPointerException", NULL);
        }
        for (size_t failure = 1; failure <= inputs + outputs; failure++) {
            setup(&call, op); fail_allocation = failure; invoke(&call);
            assert(pending && strcmp(exception_class, "java/lang/OutOfMemoryError") == 0 && backend_calls == 0);
        }
        for (size_t failure = 1; failure <= inputs; failure++) {
            setup(&call, op); fail_copy = failure; invoke(&call);
            assert(pending && strcmp(exception_class, "java/lang/OutOfMemoryError") == 0 && backend_calls == 0);
        }
        for (size_t failure = 1; failure <= (outputs ? outputs : 1); failure++) {
            setup(&call, op); fail_output = failure; invoke(&call);
            assert(pending && strcmp(exception_class, "java/lang/OutOfMemoryError") == 0 && backend_calls == 1);
        }
    }
    setup(&call, ENCAP); call.arrays[1].length = 8192; call.input[2] = NULL;
    expect_java(&call, "java/lang/NullPointerException", "pkTrad must not be null");
    setup(&call, ENCAP); call.arrays[0].length = 0; call.arrays[1].length = 0;
    expect_native(&call, Q_PERIAPT_ERR_LENGTH);
    setup(&call, DECAP); call.arrays[0].length = 0; call.arrays[1].length = 0;
    expect_native(&call, Q_PERIAPT_ERR_LENGTH);
    setup(&call, POLICY); call.arrays[1].length = 0; call.arrays[3].length = 4;
    expect_native(&call, Q_PERIAPT_ERR_LENGTH);
    setup(&call, POLICY); call.arrays[1].length = 0; call.input[3] = NULL;
    expect_java(&call, "java/lang/NullPointerException", "lastTrustedState must not be null");
    setup(&call, ENCAP); call.arrays[1].length = 0; call.arrays[3].length = 65537;
    expect_java(&call, "java/lang/IllegalArgumentException", "applicationContext exceeds maximum size");
    setup(&call, ENCAP); call.arrays[8].length = 0; call.arrays[3].length = 65537;
    expect_java(&call, "java/lang/IllegalArgumentException", "output array length mismatch");
    printf("JNI_INPUT_SHAPES_PASS cases=%zu\n", cases);
    test_sdk_inputs();
    return 0;
}
