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
static int pending, native_code;
static const char *exception_class, *exception_message, *native_operation;
static jbyte public_bytes[65537], result_bytes[Q_PERIAPT_POLICY_DECISION_LEN];
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
    (void)env; assert(!pending && length == Q_PERIAPT_POLICY_DECISION_LEN);
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
static jobject JNICALL new_object(JNIEnv *env, jclass cls, jmethodID method, ...) {
    (void)env; (void)method; assert(!pending);
    va_list arguments; va_start(arguments, method);
    native_operation = (const char *)va_arg(arguments, jstring);
    native_code = va_arg(arguments, jint);
    const char *status = (const char *)va_arg(arguments, jstring);
    assert(strcmp(status, native_code == Q_PERIAPT_ERR_LENGTH ? "ERR_LENGTH" : "ERR_POLICY") == 0);
    va_end(arguments);
    return (jobject)cls;
}
static jint JNICALL throw_object(JNIEnv *env, jthrowable value) { (void)env; (void)value; assert(!pending); pending = 1; return JNI_OK; }
static jint JNICALL throw_string(JNIEnv *env, jclass cls, const char *value) {
    (void)env; (void)cls; assert(!pending); pending = 1; exception_message = value; return JNI_OK;
}
static const char *status_name(int32_t code) { return code == Q_PERIAPT_ERR_LENGTH ? "ERR_LENGTH" : "ERR_POLICY"; }
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
    allocation_calls = copy_calls = output_calls = backend_calls = 0;
    fail_allocation = fail_copy = fail_output = 0;
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
    return 0;
}
