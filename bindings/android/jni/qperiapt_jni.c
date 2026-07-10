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

static uint8_t *copy_input(JNIEnv *env, jbyteArray array, uintptr_t *out_len, const char *label) {
	if (array == NULL) {
		throw_null(env, label);
		return NULL;
	}
	jsize len = (*env)->GetArrayLength(env, array);
	if (len < 0) {
		throw_arg(env, "negative Java array length");
		return NULL;
	}
	uint8_t *buf = alloc_bytes(env, (size_t)len, "native input allocation failed");
	if (buf == NULL) {
		return NULL;
	}
	if (len > 0) {
		(*env)->GetByteArrayRegion(env, array, 0, len, (jbyte *)buf);
		if ((*env)->ExceptionCheck(env)) {
			secure_zero(buf, (size_t)len);
			free(buf);
			return NULL;
		}
	}
	*out_len = (uintptr_t)len;
	return buf;
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

static jbyte native_profile_from_signed_policy(
		JNIEnv *env,
		jclass cls,
		jbyteArray toml_array,
		jbyteArray signature_array,
		jbyteArray vk_array,
		jint last_trusted_version) {
	(void)cls;
	uintptr_t toml_len = 0;
	uintptr_t signature_len = 0;
	uintptr_t vk_len = 0;
	uint8_t *toml = NULL;
	uint8_t *signature = NULL;
	uint8_t *vk = NULL;
	uint8_t out_profile = 0;

	toml = copy_input(env, toml_array, &toml_len, "toml must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	signature = copy_input(env, signature_array, &signature_len, "signature must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	vk = copy_input(env, vk_array, &vk_len, "verificationKey must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}

	int32_t rc = q_periapt_profile_from_signed_policy(
			toml,
			toml_len,
			signature,
			signature_len,
			vk,
			vk_len,
			(uint32_t)last_trusted_version,
			&out_profile,
			1);
	if (rc != Q_PERIAPT_OK) {
		throw_qperiapt(env, "q_periapt_profile_from_signed_policy", rc);
	}

cleanup:
	secure_zero(toml, (size_t)toml_len);
	secure_zero(signature, (size_t)signature_len);
	secure_zero(vk, (size_t)vk_len);
	free(toml);
	free(signature);
	free(vk);
	return (jbyte)out_profile;
}

static void keypair_common(
		JNIEnv *env,
		jbyteArray seed_array,
		jbyteArray out_secret_key_array,
		jbyteArray out_public_key_array,
		uintptr_t expected_seed_len,
		uintptr_t expected_secret_key_len,
		uintptr_t expected_public_key_len,
		const char *operation,
		int32_t (*fn)(const uint8_t *, uintptr_t, uint8_t *, uintptr_t, uint8_t *, uintptr_t)) {
	if (!check_exact_array(env, out_secret_key_array, (jsize)expected_secret_key_len, "outSecretKey must not be null") ||
			!check_exact_array(env, out_public_key_array, (jsize)expected_public_key_len, "outPublicKey must not be null")) {
		return;
	}
	uintptr_t seed_len = 0;
	uint8_t *seed = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *public_key = NULL;

	seed = copy_input(env, seed_array, &seed_len, "seed must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	secret_key = alloc_bytes(env, (size_t)expected_secret_key_len, "native secret-key allocation failed");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	public_key = alloc_bytes(env, (size_t)expected_public_key_len, "native public-key allocation failed");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}

	if (seed_len != expected_seed_len) {
		throw_qperiapt(env, operation, Q_PERIAPT_ERR_LENGTH);
	} else {
		int32_t rc = fn(
				seed,
				seed_len,
				secret_key,
				expected_secret_key_len,
				public_key,
				expected_public_key_len);
		if (rc != Q_PERIAPT_OK) {
			throw_qperiapt(env, operation, rc);
		} else if (set_output(env, out_secret_key_array, secret_key, (jsize)expected_secret_key_len)) {
			(void)set_output(env, out_public_key_array, public_key, (jsize)expected_public_key_len);
		}
	}

cleanup:
	secure_zero(seed, (size_t)seed_len);
	secure_zero(secret_key, (size_t)expected_secret_key_len);
	secure_zero(public_key, (size_t)expected_public_key_len);
	free(seed);
	free(secret_key);
	free(public_key);
}

static void native_mlkem768_keypair(
		JNIEnv *env, jclass cls, jbyteArray seed, jbyteArray out_secret_key, jbyteArray out_public_key) {
	(void)cls;
	keypair_common(
			env,
			seed,
			out_secret_key,
			out_public_key,
			64,
			Q_PERIAPT_MLKEM768_SK_LEN,
			Q_PERIAPT_MLKEM768_PK_LEN,
			"q_periapt_mlkem768_keypair",
			q_periapt_mlkem768_keypair);
}

static void native_mlkem768_xwing_keypair(
		JNIEnv *env, jclass cls, jbyteArray seed, jbyteArray out_secret_key, jbyteArray out_public_key) {
	(void)cls;
	keypair_common(
			env,
			seed,
			out_secret_key,
			out_public_key,
			Q_PERIAPT_MLKEM768_XWING_SEED_LEN,
			Q_PERIAPT_MLKEM768_XWING_SEED_LEN,
			Q_PERIAPT_MLKEM768_PK_LEN,
			"q_periapt_mlkem768_xwing_keypair",
			q_periapt_mlkem768_xwing_keypair);
}

static void native_x25519_keypair(
		JNIEnv *env, jclass cls, jbyteArray secret, jbyteArray out_secret_key, jbyteArray out_public_key) {
	(void)cls;
	keypair_common(
			env,
			secret,
			out_secret_key,
			out_public_key,
			Q_PERIAPT_X25519_LEN,
			Q_PERIAPT_X25519_LEN,
			Q_PERIAPT_X25519_LEN,
			"q_periapt_x25519_keypair",
			q_periapt_x25519_keypair);
}

static void native_encapsulate(
		JNIEnv *env,
		jclass cls,
		jbyte profile,
		jbyteArray suite_id_array,
		jint policy_version,
		jbyteArray pk_pq_array,
		jbyteArray pk_trad_array,
		jbyteArray context_array,
		jbyteArray rand_pq_array,
		jbyteArray rand_trad_array,
		jbyteArray out_ct_pq_array,
		jbyteArray out_ct_trad_array,
		jbyteArray out_secret_array) {
	(void)cls;
	if (!check_exact_array(env, out_ct_pq_array, Q_PERIAPT_MLKEM768_CT_LEN, "outCtPq must not be null") ||
			!check_exact_array(env, out_ct_trad_array, Q_PERIAPT_X25519_LEN, "outCtTrad must not be null") ||
			!check_exact_array(env, out_secret_array, Q_PERIAPT_SECRET_LEN, "outSecret must not be null")) {
		return;
	}
	uintptr_t suite_id_len = 0;
	uintptr_t pk_pq_len = 0;
	uintptr_t pk_trad_len = 0;
	uintptr_t context_len = 0;
	uintptr_t rand_pq_len = 0;
	uintptr_t rand_trad_len = 0;
	uint8_t *suite_id = NULL;
	uint8_t *pk_pq = NULL;
	uint8_t *pk_trad = NULL;
	uint8_t *context = NULL;
	uint8_t *rand_pq = NULL;
	uint8_t *rand_trad = NULL;
	uint8_t *out_ct_pq = NULL;
	uint8_t *out_ct_trad = NULL;
	uint8_t *out_secret = NULL;

	suite_id = copy_input(env, suite_id_array, &suite_id_len, "suiteId must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	pk_pq = copy_input(env, pk_pq_array, &pk_pq_len, "pkPq must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	pk_trad = copy_input(env, pk_trad_array, &pk_trad_len, "pkTrad must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	context = copy_input(env, context_array, &context_len, "context must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	rand_pq = copy_input(env, rand_pq_array, &rand_pq_len, "randPq must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	rand_trad = copy_input(env, rand_trad_array, &rand_trad_len, "randTrad must not be null");
	if ((*env)->ExceptionCheck(env)) {
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

	int32_t rc = q_periapt_hybrid_encapsulate(
			(uint8_t)profile,
			suite_id,
			suite_id_len,
			(uint32_t)policy_version,
			pk_pq,
			pk_pq_len,
			pk_trad,
			pk_trad_len,
			context,
			context_len,
			rand_pq,
			rand_pq_len,
			rand_trad,
			rand_trad_len,
			out_ct_pq,
			Q_PERIAPT_MLKEM768_CT_LEN,
			out_ct_trad,
			Q_PERIAPT_X25519_LEN,
			out_secret,
			Q_PERIAPT_SECRET_LEN);
	if (rc != Q_PERIAPT_OK) {
		throw_qperiapt(env, "q_periapt_hybrid_encapsulate", rc);
	} else if (set_output(env, out_ct_pq_array, out_ct_pq, Q_PERIAPT_MLKEM768_CT_LEN) &&
			set_output(env, out_ct_trad_array, out_ct_trad, Q_PERIAPT_X25519_LEN)) {
		(void)set_output(env, out_secret_array, out_secret, Q_PERIAPT_SECRET_LEN);
	}

cleanup:
	secure_zero(suite_id, (size_t)suite_id_len);
	secure_zero(pk_pq, (size_t)pk_pq_len);
	secure_zero(pk_trad, (size_t)pk_trad_len);
	secure_zero(context, (size_t)context_len);
	secure_zero(rand_pq, (size_t)rand_pq_len);
	secure_zero(rand_trad, (size_t)rand_trad_len);
	secure_zero(out_ct_pq, Q_PERIAPT_MLKEM768_CT_LEN);
	secure_zero(out_ct_trad, Q_PERIAPT_X25519_LEN);
	secure_zero(out_secret, Q_PERIAPT_SECRET_LEN);
	free(suite_id);
	free(pk_pq);
	free(pk_trad);
	free(context);
	free(rand_pq);
	free(rand_trad);
	free(out_ct_pq);
	free(out_ct_trad);
	free(out_secret);
}

static void native_decapsulate(
		JNIEnv *env,
		jclass cls,
		jbyte profile,
		jbyteArray suite_id_array,
		jint policy_version,
		jbyteArray sk_pq_array,
		jbyteArray ct_pq_array,
		jbyteArray pk_pq_array,
		jbyteArray sk_trad_array,
		jbyteArray ct_trad_array,
		jbyteArray pk_trad_array,
		jbyteArray context_array,
		jbyteArray out_secret_array) {
	(void)cls;
	if (!check_exact_array(env, out_secret_array, Q_PERIAPT_SECRET_LEN, "outSecret must not be null")) {
		return;
	}
	uintptr_t suite_id_len = 0;
	uintptr_t sk_pq_len = 0;
	uintptr_t ct_pq_len = 0;
	uintptr_t pk_pq_len = 0;
	uintptr_t sk_trad_len = 0;
	uintptr_t ct_trad_len = 0;
	uintptr_t pk_trad_len = 0;
	uintptr_t context_len = 0;
	uint8_t *suite_id = NULL;
	uint8_t *sk_pq = NULL;
	uint8_t *ct_pq = NULL;
	uint8_t *pk_pq = NULL;
	uint8_t *sk_trad = NULL;
	uint8_t *ct_trad = NULL;
	uint8_t *pk_trad = NULL;
	uint8_t *context = NULL;
	uint8_t *out_secret = NULL;

	suite_id = copy_input(env, suite_id_array, &suite_id_len, "suiteId must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	sk_pq = copy_input(env, sk_pq_array, &sk_pq_len, "skPq must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	ct_pq = copy_input(env, ct_pq_array, &ct_pq_len, "ctPq must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	pk_pq = copy_input(env, pk_pq_array, &pk_pq_len, "pkPq must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	sk_trad = copy_input(env, sk_trad_array, &sk_trad_len, "skTrad must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	ct_trad = copy_input(env, ct_trad_array, &ct_trad_len, "ctTrad must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	pk_trad = copy_input(env, pk_trad_array, &pk_trad_len, "pkTrad must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	context = copy_input(env, context_array, &context_len, "context must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	out_secret = alloc_bytes(env, Q_PERIAPT_SECRET_LEN, "native secret allocation failed");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}

	int32_t rc = q_periapt_hybrid_decapsulate(
			(uint8_t)profile,
			suite_id,
			suite_id_len,
			(uint32_t)policy_version,
			sk_pq,
			sk_pq_len,
			ct_pq,
			ct_pq_len,
			pk_pq,
			pk_pq_len,
			sk_trad,
			sk_trad_len,
			ct_trad,
			ct_trad_len,
			pk_trad,
			pk_trad_len,
			context,
			context_len,
			out_secret,
			Q_PERIAPT_SECRET_LEN);
	if (rc != Q_PERIAPT_OK) {
		throw_qperiapt(env, "q_periapt_hybrid_decapsulate", rc);
	} else {
		(void)set_output(env, out_secret_array, out_secret, Q_PERIAPT_SECRET_LEN);
	}

cleanup:
	secure_zero(suite_id, (size_t)suite_id_len);
	secure_zero(sk_pq, (size_t)sk_pq_len);
	secure_zero(ct_pq, (size_t)ct_pq_len);
	secure_zero(pk_pq, (size_t)pk_pq_len);
	secure_zero(sk_trad, (size_t)sk_trad_len);
	secure_zero(ct_trad, (size_t)ct_trad_len);
	secure_zero(pk_trad, (size_t)pk_trad_len);
	secure_zero(context, (size_t)context_len);
	secure_zero(out_secret, Q_PERIAPT_SECRET_LEN);
	free(suite_id);
	free(sk_pq);
	free(ct_pq);
	free(pk_pq);
	free(sk_trad);
	free(ct_trad);
	free(pk_trad);
	free(context);
	free(out_secret);
}

static void native_combine(
		JNIEnv *env,
		jclass cls,
		jbyte profile,
		jbyteArray input_array,
		jbyteArray out_secret_array) {
	(void)cls;
	if (!check_exact_array(env, out_secret_array, Q_PERIAPT_SECRET_LEN, "outSecret must not be null")) {
		return;
	}
	uintptr_t input_len = 0;
	uint8_t *input = NULL;
	uint8_t *out_secret = NULL;

	input = copy_input(env, input_array, &input_len, "input must not be null");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}
	out_secret = alloc_bytes(env, Q_PERIAPT_SECRET_LEN, "native secret allocation failed");
	if ((*env)->ExceptionCheck(env)) {
		goto cleanup;
	}

	int32_t rc = q_periapt_combine(
			(uint8_t)profile,
			input,
			input_len,
			out_secret,
			Q_PERIAPT_SECRET_LEN);
	if (rc != Q_PERIAPT_OK) {
		throw_qperiapt(env, "q_periapt_combine", rc);
	} else {
		(void)set_output(env, out_secret_array, out_secret, Q_PERIAPT_SECRET_LEN);
	}

cleanup:
	secure_zero(input, (size_t)input_len);
	secure_zero(out_secret, Q_PERIAPT_SECRET_LEN);
	free(input);
	free(out_secret);
}

static JNINativeMethod QPERIAPT_METHODS[] = {
	{"runtimeAbiVersionNative", "()I", (void *)native_runtime_abi_version},
	{"runtimeVersionNative", "()Ljava/lang/String;", (void *)native_runtime_version},
	{"fixedSuiteIdNative", "()Ljava/lang/String;", (void *)native_fixed_suite_id},
	{"fixedSuiteIdLenNative", "()J", (void *)native_fixed_suite_id_len},
	{"statusNameNative", "(I)Ljava/lang/String;", (void *)native_status_name},
	{"profileFromSignedPolicyNative", "([B[B[BI)B", (void *)native_profile_from_signed_policy},
	{"mlkem768KeypairNative", "([B[B[B)V", (void *)native_mlkem768_keypair},
	{"mlkem768XWingKeypairNative", "([B[B[B)V", (void *)native_mlkem768_xwing_keypair},
	{"x25519KeypairNative", "([B[B[B)V", (void *)native_x25519_keypair},
	{"encapsulateNative", "(B[BI[B[B[B[B[B[B[B[B)V", (void *)native_encapsulate},
	{"decapsulateNative", "(B[BI[B[B[B[B[B[B[B[B)V", (void *)native_decapsulate},
	{"combineNative", "(B[B[B)V", (void *)native_combine},
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
