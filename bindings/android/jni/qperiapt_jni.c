#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

#include "q_periapt.h"

static void secure_zero(void *ptr, size_t len) {
	if (ptr == NULL) {
		return;
	}
	volatile uint8_t *p = (volatile uint8_t *)ptr;
	while (len > 0) {
		*p = 0;
		p++;
		len--;
	}
}

static void throw_new(JNIEnv *env, const char *class_name, const char *message) {
	/* Almost every JNI call is undefined while an exception is pending, and the
	 * FindClass below is one of them. Callers batch operations that can each
	 * throw -- four allocations in a row, for instance -- so a second failure
	 * would otherwise call into JNI from inside the first throw's aftermath.
	 * Keeping the first exception is also the right outcome: it names the
	 * original cause, and the later failures are usually consequences of it. */
	if ((*env)->ExceptionCheck(env)) {
		return;
	}
	jclass cls = (*env)->FindClass(env, class_name);
	if (cls == NULL) {
		(*env)->ExceptionClear(env);
		cls = (*env)->FindClass(env, "java/lang/RuntimeException");
		if (cls == NULL) {
			return;
		}
	}
	(*env)->ThrowNew(env, cls, message);
}

static void throw_null(JNIEnv *env, const char *label) {
	throw_new(env, "java/lang/NullPointerException", label);
}

static void throw_arg(JNIEnv *env, const char *message) {
	throw_new(env, "java/lang/IllegalArgumentException", message);
}

static void throw_state(JNIEnv *env, const char *message) {
	throw_new(env, "java/lang/IllegalStateException", message);
}

static void throw_oom(JNIEnv *env, const char *message) {
	throw_new(env, "java/lang/OutOfMemoryError", message);
}

static void throw_qperiapt(JNIEnv *env, const char *operation, int32_t rc) {
	/* As in throw_new: this FindClass must not run with an exception pending. */
	if ((*env)->ExceptionCheck(env)) {
		return;
	}
	jclass cls = (*env)->FindClass(env, "dev/qperiapt/android/QPeriaptAndroid$QPeriaptException");
	if (cls == NULL) {
		(*env)->ExceptionClear(env);
		throw_new(env, "java/lang/RuntimeException", "q-periapt exception class not found");
		return;
	}
	jmethodID ctor = (*env)->GetMethodID(env, cls, "<init>", "(Ljava/lang/String;ILjava/lang/String;)V");
	if (ctor == NULL) {
		(*env)->ExceptionClear(env);
		throw_new(env, "java/lang/RuntimeException", "q-periapt exception constructor not found");
		return;
	}
	jstring op = (*env)->NewStringUTF(env, operation);
	if (op == NULL) {
		return;
	}
	const char *status = q_periapt_status_name(rc);
	if (status == NULL) {
		status = "UNKNOWN_STATUS";
	}
	jstring status_name = (*env)->NewStringUTF(env, status);
	if (status_name == NULL) {
		return;
	}
	jobject ex = (*env)->NewObject(env, cls, ctor, op, (jint)rc, status_name);
	if (ex == NULL) {
		return;
	}
	(*env)->Throw(env, (jthrowable)ex);
}

static uint8_t *alloc_bytes(JNIEnv *env, size_t len, const char *label) {
	size_t alloc_len = len == 0 ? 1 : len;
	uint8_t *buf = (uint8_t *)malloc(alloc_len);
	if (buf == NULL) {
		throw_oom(env, label);
		return NULL;
	}
	return buf;
}

/* Preserve input-null precedence while rejecting fixed shapes before any copy. */
static int read_input_lengths(
        JNIEnv *env,
        const jbyteArray *arrays,
        const char *const *labels,
        size_t count,
        uintptr_t *lengths) {
    for (size_t i = 0; i < count; i++) {
        if (arrays[i] == NULL) {
            throw_null(env, labels[i]);
            return 0;
        }
        jsize length = (*env)->GetArrayLength(env, arrays[i]);
        if ((*env)->ExceptionCheck(env)) {
            return 0;
        }
        if (length < 0) {
            throw_arg(env, "negative Java array length");
            return 0;
        }
        lengths[i] = (uintptr_t)length;
    }
    return 1;
}

/* Array lengths are immutable; read_input_lengths admitted this exact extent. */
static uint8_t *copy_input(JNIEnv *env, jbyteArray array, uintptr_t length) {
    uint8_t *buf = alloc_bytes(env, (size_t)length, "native input allocation failed");
    if (buf == NULL) {
        return NULL;
    }
    if (length > 0) {
        (*env)->GetByteArrayRegion(env, array, 0, (jsize)length, (jbyte *)buf);
        if ((*env)->ExceptionCheck(env)) {
            secure_zero(buf, (size_t)length);
            free(buf);
            return NULL;
        }
    }
    return buf;
}

static int copy_inputs(
        JNIEnv *env,
        const jbyteArray *arrays,
        size_t count,
        uint8_t **buffers,
        const uintptr_t *lengths) {
    for (size_t i = 0; i < count; i++) {
        buffers[i] = copy_input(env, arrays[i], lengths[i]);
        if ((*env)->ExceptionCheck(env)) {
            return 0;
        }
    }
    return 1;
}

static void wipe_free_inputs(uint8_t **buffers, const uintptr_t *lengths, size_t count) {
	for (size_t i = 0; i < count; i++) {
		secure_zero(buffers[i], (size_t)lengths[i]);
		free(buffers[i]);
	}
}

static int check_exact_array(JNIEnv *env, jbyteArray array, jsize expected, const char *label) {
	if (array == NULL) {
		throw_null(env, label);
		return 0;
	}
	jsize got = (*env)->GetArrayLength(env, array);
	if (got != expected) {
		throw_arg(env, "output array length mismatch");
		return 0;
	}
	return 1;
}

static int check_max_array(
		JNIEnv *env, jbyteArray array, jsize maximum, const char *null_label, const char *size_label) {
	if (array == NULL) {
		throw_null(env, null_label);
		return 0;
	}
	jsize got = (*env)->GetArrayLength(env, array);
	if (got < 0 || got > maximum) {
		throw_arg(env, size_label);
		return 0;
	}
	return 1;
}

static int set_output(JNIEnv *env, jbyteArray array, const uint8_t *buf, jsize len) {
	(*env)->SetByteArrayRegion(env, array, 0, len, (const jbyte *)buf);
	return !(*env)->ExceptionCheck(env);
}

static jstring new_native_string(JNIEnv *env, const char *value, const char *label) {
	if (value == NULL) {
		throw_state(env, label);
		return NULL;
	}
	return (*env)->NewStringUTF(env, value);
}

static jint native_runtime_abi_version(
		JNIEnv *env, jclass cls) {
	(void)env;
	(void)cls;
	return (jint)q_periapt_abi_version();
}

static jstring native_runtime_version(
		JNIEnv *env, jclass cls) {
	(void)cls;
	return new_native_string(env, q_periapt_version(), "q_periapt_version returned NULL");
}

static jstring native_fixed_suite_id(
		JNIEnv *env, jclass cls) {
	(void)cls;
	return new_native_string(env, q_periapt_fixed_suite_id(), "q_periapt_fixed_suite_id returned NULL");
}

static jlong native_fixed_suite_id_len(
		JNIEnv *env, jclass cls) {
	(void)env;
	(void)cls;
	return (jlong)q_periapt_fixed_suite_id_len();
}

static jstring native_status_name(
		JNIEnv *env, jclass cls, jint code) {
	(void)cls;
	return new_native_string(env, q_periapt_status_name((int32_t)code), "q_periapt_status_name returned NULL");
}

static jbyteArray native_decision_from_signed_policy(
		JNIEnv *env,
		jclass cls,
		jbyteArray toml_array,
		jbyteArray signature_array,
		jbyteArray vk_array,
		jbyteArray last_state_array) {
	(void)cls;
	uintptr_t toml_len = 0;
	uintptr_t signature_len = 0;
	uintptr_t vk_len = 0;
	uintptr_t last_state_len = 0;
	uint8_t *toml = NULL;
	uint8_t *signature = NULL;
	uint8_t *vk = NULL;
	uint8_t *last_state = NULL;
	uint8_t decision[Q_PERIAPT_POLICY_DECISION_LEN] = {0};
	jbyteArray result = NULL;

	if (!check_max_array(
			env, toml_array, Q_PERIAPT_MAX_SIGNED_POLICY_BYTES,
			"toml must not be null", "toml exceeds maximum signed-policy size")) {
		goto cleanup;
	}
    jbyteArray arrays[] = {toml_array, signature_array, vk_array, last_state_array};
    const char *labels[] = {
        "toml must not be null", "signature must not be null",
        "verificationKey must not be null", "lastTrustedState must not be null"
    };
    uintptr_t lengths[4] = {0};
    if (!read_input_lengths(env, arrays, labels, 4, lengths)) {
        goto cleanup;
    }
    toml_len = lengths[0];
    signature_len = lengths[1];
    vk_len = lengths[2];
    last_state_len = lengths[3];
    if (last_state_len != 0 && last_state_len != Q_PERIAPT_TRUSTED_POLICY_STATE_LEN) {
        throw_qperiapt(env, "q_periapt_decision_from_signed_policy", Q_PERIAPT_ERR_LENGTH);
        goto cleanup;
    }
    if (signature_len != Q_PERIAPT_POLICY_SIGNATURE_LEN ||
            vk_len != Q_PERIAPT_POLICY_VERIFICATION_KEY_LEN) {
        throw_qperiapt(env, "q_periapt_decision_from_signed_policy", Q_PERIAPT_ERR_POLICY);
        goto cleanup;
    }
    toml = copy_input(env, toml_array, toml_len);
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	signature = copy_input(env, signature_array, signature_len);
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	vk = copy_input(env, vk_array, vk_len);
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	last_state = copy_input(env, last_state_array, last_state_len);
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}

	int32_t rc = q_periapt_decision_from_signed_policy(
			toml,
			toml_len,
			signature,
			signature_len,
			vk,
			vk_len,
			last_state,
			last_state_len,
			decision,
			Q_PERIAPT_POLICY_DECISION_LEN);
	if (rc != Q_PERIAPT_OK) {
		throw_qperiapt(env, "q_periapt_decision_from_signed_policy", rc);
		goto cleanup;
	}
	result = (*env)->NewByteArray(env, Q_PERIAPT_POLICY_DECISION_LEN);
	if (result == NULL) {
		goto cleanup;
	}
	if (!set_output(env, result, decision, Q_PERIAPT_POLICY_DECISION_LEN)) {
		result = NULL;
	}

cleanup:
	secure_zero(toml, (size_t)toml_len);
	secure_zero(signature, (size_t)signature_len);
	secure_zero(vk, (size_t)vk_len);
	secure_zero(last_state, (size_t)last_state_len);
	secure_zero(decision, sizeof(decision));
	free(toml);
	free(signature);
	free(vk);
	free(last_state);
	return result;
}

static void native_generate_keypair(
        JNIEnv *env,
        jclass cls,
        jbyteArray decision_array,
        jbyteArray out_sk_pq_array,
        jbyteArray out_pk_pq_array,
        jbyteArray out_sk_trad_array,
        jbyteArray out_pk_trad_array) {
    (void)cls;
    if (!check_exact_array(env, out_sk_pq_array, Q_PERIAPT_MLKEM768_SK_LEN, "outSkPq must not be null") ||
            !check_exact_array(env, out_pk_pq_array, Q_PERIAPT_MLKEM768_PK_LEN, "outPkPq must not be null") ||
            !check_exact_array(env, out_sk_trad_array, Q_PERIAPT_X25519_LEN, "outSkTrad must not be null") ||
            !check_exact_array(env, out_pk_trad_array, Q_PERIAPT_X25519_LEN, "outPkTrad must not be null")) {
        return;
    }
    jbyteArray arrays[] = {decision_array};
    const char *labels[] = {"decision must not be null"};
    uintptr_t decision_len = 0;
    if (!read_input_lengths(env, arrays, labels, 1, &decision_len)) {
        return;
    }
    if (decision_len != Q_PERIAPT_POLICY_DECISION_LEN) {
        throw_qperiapt(env, "q_periapt_generate_keypair", Q_PERIAPT_ERR_POLICY);
        return;
    }
    uint8_t *decision = copy_input(env, decision_array, decision_len);
    uint8_t *sk_pq = NULL;
    uint8_t *pk_pq = NULL;
    uint8_t *sk_trad = NULL;
    uint8_t *pk_trad = NULL;
    if ((*env)->ExceptionCheck(env)) {
        goto cleanup;
    }
    sk_pq = alloc_bytes(env, Q_PERIAPT_MLKEM768_SK_LEN, "native ML-KEM secret allocation failed");
    pk_pq = alloc_bytes(env, Q_PERIAPT_MLKEM768_PK_LEN, "native ML-KEM public allocation failed");
    sk_trad = alloc_bytes(env, Q_PERIAPT_X25519_LEN, "native X25519 secret allocation failed");
    pk_trad = alloc_bytes(env, Q_PERIAPT_X25519_LEN, "native X25519 public allocation failed");
    if ((*env)->ExceptionCheck(env)) {
        goto cleanup;
    }

    int32_t rc = q_periapt_generate_keypair(
            decision, decision_len,
            sk_pq, Q_PERIAPT_MLKEM768_SK_LEN,
            pk_pq, Q_PERIAPT_MLKEM768_PK_LEN,
            sk_trad, Q_PERIAPT_X25519_LEN,
            pk_trad, Q_PERIAPT_X25519_LEN);
    if (rc != Q_PERIAPT_OK) {
        throw_qperiapt(env, "q_periapt_generate_keypair", rc);
    } else if (set_output(env, out_sk_pq_array, sk_pq, Q_PERIAPT_MLKEM768_SK_LEN) &&
            set_output(env, out_pk_pq_array, pk_pq, Q_PERIAPT_MLKEM768_PK_LEN) &&
            set_output(env, out_sk_trad_array, sk_trad, Q_PERIAPT_X25519_LEN)) {
        (void)set_output(env, out_pk_trad_array, pk_trad, Q_PERIAPT_X25519_LEN);
    }

cleanup:
    secure_zero(decision, (size_t)decision_len);
    secure_zero(sk_pq, Q_PERIAPT_MLKEM768_SK_LEN);
    secure_zero(pk_pq, Q_PERIAPT_MLKEM768_PK_LEN);
    secure_zero(sk_trad, Q_PERIAPT_X25519_LEN);
    secure_zero(pk_trad, Q_PERIAPT_X25519_LEN);
    free(decision);
    free(sk_pq);
    free(pk_pq);
    free(sk_trad);
    free(pk_trad);
}

static void native_encapsulate(
		JNIEnv *env,
		jclass cls,
		jbyteArray decision_array,
		jbyteArray pk_pq_array,
		jbyteArray pk_trad_array,
        jbyteArray application_context_array,
		jbyteArray out_ct_pq_array,
		jbyteArray out_ct_trad_array,
		jbyteArray out_secret_array) {
	(void)cls;
	if (!check_exact_array(env, out_ct_pq_array, Q_PERIAPT_MLKEM768_CT_LEN, "outCtPq must not be null") ||
			!check_exact_array(env, out_ct_trad_array, Q_PERIAPT_X25519_LEN, "outCtTrad must not be null") ||
			!check_exact_array(env, out_secret_array, Q_PERIAPT_SECRET_LEN, "outSecret must not be null")) {
		return;
	}
    jbyteArray arrays[] = {
        decision_array, pk_pq_array, pk_trad_array, application_context_array
    };
	const char *labels[] = {
        "decision must not be null", "pkPq must not be null", "pkTrad must not be null",
        "applicationContext must not be null"
    };
    uint8_t *inputs[4] = {NULL};
    uintptr_t lengths[4] = {0};
	uint8_t *out_ct_pq = NULL;
	uint8_t *out_ct_trad = NULL;
	uint8_t *out_secret = NULL;
	if (!check_max_array(
			env, application_context_array, Q_PERIAPT_MAX_APPLICATION_CONTEXT_BYTES,
			"applicationContext must not be null", "applicationContext exceeds maximum size")) {
		goto cleanup;
	}
    if (!read_input_lengths(env, arrays, labels, 4, lengths)) {
        goto cleanup;
    }
    if (lengths[1] != Q_PERIAPT_MLKEM768_PK_LEN || lengths[2] != Q_PERIAPT_X25519_LEN) {
        throw_qperiapt(env, "q_periapt_encapsulate", Q_PERIAPT_ERR_LENGTH);
        goto cleanup;
    }
    if (lengths[0] != Q_PERIAPT_POLICY_DECISION_LEN) {
        throw_qperiapt(env, "q_periapt_encapsulate", Q_PERIAPT_ERR_POLICY);
        goto cleanup;
    }
    if (!copy_inputs(env, arrays, 4, inputs, lengths)) {
		goto cleanup;
	}
	out_ct_pq = alloc_bytes(env, Q_PERIAPT_MLKEM768_CT_LEN, "native ct_pq allocation failed");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	out_ct_trad = alloc_bytes(env, Q_PERIAPT_X25519_LEN, "native ct_trad allocation failed");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	out_secret = alloc_bytes(env, Q_PERIAPT_SECRET_LEN, "native secret allocation failed");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}

    int32_t rc = q_periapt_encapsulate(
            inputs[0], lengths[0], inputs[1], lengths[1], inputs[2], lengths[2],
            inputs[3], lengths[3],
			out_ct_pq, Q_PERIAPT_MLKEM768_CT_LEN,
			out_ct_trad, Q_PERIAPT_X25519_LEN,
			out_secret, Q_PERIAPT_SECRET_LEN);
	if (rc != Q_PERIAPT_OK) {
        throw_qperiapt(env, "q_periapt_encapsulate", rc);
	} else if (set_output(env, out_ct_pq_array, out_ct_pq, Q_PERIAPT_MLKEM768_CT_LEN) &&
			set_output(env, out_ct_trad_array, out_ct_trad, Q_PERIAPT_X25519_LEN)) {
		(void)set_output(env, out_secret_array, out_secret, Q_PERIAPT_SECRET_LEN);
	}

cleanup:
    wipe_free_inputs(inputs, lengths, 4);
	secure_zero(out_ct_pq, Q_PERIAPT_MLKEM768_CT_LEN);
	secure_zero(out_ct_trad, Q_PERIAPT_X25519_LEN);
	secure_zero(out_secret, Q_PERIAPT_SECRET_LEN);
	free(out_ct_pq);
	free(out_ct_trad);
	free(out_secret);
}

static void native_decapsulate(
		JNIEnv *env,
		jclass cls,
		jbyteArray decision_array,
		jbyteArray sk_pq_array,
		jbyteArray ct_pq_array,
		jbyteArray pk_pq_array,
		jbyteArray sk_trad_array,
		jbyteArray ct_trad_array,
		jbyteArray pk_trad_array,
		jbyteArray application_context_array,
		jbyteArray out_secret_array) {
	(void)cls;
	if (!check_exact_array(env, out_secret_array, Q_PERIAPT_SECRET_LEN, "outSecret must not be null")) {
		return;
	}
	jbyteArray arrays[] = {
		decision_array, sk_pq_array, ct_pq_array, pk_pq_array, sk_trad_array,
		ct_trad_array, pk_trad_array, application_context_array
	};
	const char *labels[] = {
		"decision must not be null", "skPq must not be null", "ctPq must not be null",
		"pkPq must not be null", "skTrad must not be null", "ctTrad must not be null",
		"pkTrad must not be null", "applicationContext must not be null"
	};
	uint8_t *inputs[8] = {NULL};
	uintptr_t lengths[8] = {0};
	uint8_t *out_secret = NULL;
	if (!check_max_array(
			env, application_context_array, Q_PERIAPT_MAX_APPLICATION_CONTEXT_BYTES,
			"applicationContext must not be null", "applicationContext exceeds maximum size")) {
		goto cleanup;
	}
    if (!read_input_lengths(env, arrays, labels, 8, lengths)) {
        goto cleanup;
    }
    if (lengths[1] != Q_PERIAPT_MLKEM768_SK_LEN ||
            lengths[2] != Q_PERIAPT_MLKEM768_CT_LEN ||
            lengths[3] != Q_PERIAPT_MLKEM768_PK_LEN ||
            lengths[4] != Q_PERIAPT_X25519_LEN ||
            lengths[5] != Q_PERIAPT_X25519_LEN ||
            lengths[6] != Q_PERIAPT_X25519_LEN) {
        throw_qperiapt(env, "q_periapt_decapsulate", Q_PERIAPT_ERR_LENGTH);
        goto cleanup;
    }
    if (lengths[0] != Q_PERIAPT_POLICY_DECISION_LEN) {
        throw_qperiapt(env, "q_periapt_decapsulate", Q_PERIAPT_ERR_POLICY);
        goto cleanup;
    }
    if (!copy_inputs(env, arrays, 8, inputs, lengths)) {
		goto cleanup;
	}
	out_secret = alloc_bytes(env, Q_PERIAPT_SECRET_LEN, "native secret allocation failed");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}

    int32_t rc = q_periapt_decapsulate(
			inputs[0], lengths[0], inputs[1], lengths[1], inputs[2], lengths[2],
			inputs[3], lengths[3], inputs[4], lengths[4], inputs[5], lengths[5],
			inputs[6], lengths[6], inputs[7], lengths[7],
			out_secret, Q_PERIAPT_SECRET_LEN);
	if (rc != Q_PERIAPT_OK) {
        throw_qperiapt(env, "q_periapt_decapsulate", rc);
	} else {
		(void)set_output(env, out_secret_array, out_secret, Q_PERIAPT_SECRET_LEN);
	}

cleanup:
	wipe_free_inputs(inputs, lengths, 8);
	secure_zero(out_secret, Q_PERIAPT_SECRET_LEN);
	free(out_secret);
}

static JNINativeMethod QPERIAPT_METHODS[] = {
	{"runtimeAbiVersionNative", "()I", (void *)native_runtime_abi_version},
	{"runtimeVersionNative", "()Ljava/lang/String;", (void *)native_runtime_version},
	{"fixedSuiteIdNative", "()Ljava/lang/String;", (void *)native_fixed_suite_id},
	{"fixedSuiteIdLenNative", "()J", (void *)native_fixed_suite_id_len},
	{"statusNameNative", "(I)Ljava/lang/String;", (void *)native_status_name},
	{"decisionFromSignedPolicyNative", "([B[B[B[B)[B", (void *)native_decision_from_signed_policy},
    {"generateKeypairNative", "([B[B[B[B[B)V", (void *)native_generate_keypair},
    {"encapsulateNative", "([B[B[B[B[B[B[B)V", (void *)native_encapsulate},
    {"decapsulateNative", "([B[B[B[B[B[B[B[B[B)V", (void *)native_decapsulate},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
	(void)reserved;
	JNIEnv *env = NULL;
	if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
		return JNI_ERR;
	}
	jclass cls = (*env)->FindClass(env, "dev/qperiapt/android/QPeriaptAndroid");
	if (cls == NULL) {
		return JNI_ERR;
	}
	int method_count = (int)(sizeof(QPERIAPT_METHODS) / sizeof(QPERIAPT_METHODS[0]));
	if ((*env)->RegisterNatives(env, cls, QPERIAPT_METHODS, method_count) != JNI_OK) {
		return JNI_ERR;
	}
	return JNI_VERSION_1_6;
}
