#!/bin/sh
# Validate the proof-to-byte evidence manifest and, by default, run the Tier-1 smoke.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

device_result_dir() {
	python3 - "$ROOT" "$1" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
path = pathlib.Path(sys.argv[2]).resolve()
base = root / "artifact" / "device-runs"
try:
    path.relative_to(base.resolve())
except ValueError:
    raise SystemExit(f"error: QPERIAPT_DEVICE_RESULT_DIR must be under {base}: {path}")
print(path)
PY
}

device_proof_max_age_seconds() {
	python3 - "$1" <<'PY'
import sys

value = int(sys.argv[1])
limit = 7 * 24 * 60 * 60
if not 0 < value <= limit:
    raise SystemExit(f"error: QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS must be between 1 and {limit}: {value}")
print(value)
PY
}

android_proof_max_age_seconds() {
	python3 - "$1" <<'PY'
import sys

value = int(sys.argv[1])
limit = 7 * 24 * 60 * 60
if not 0 < value <= limit:
    raise SystemExit(f"error: QPERIAPT_ANDROID_PROOF_MAX_AGE_SECONDS must be between 1 and {limit}: {value}")
print(value)
PY
}

need python3

python3 - <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path.cwd()
manifest = json.loads((root / "artifact/results.json").read_text())
expected = manifest.get("proof_to_byte_inputs")
if not isinstance(expected, dict):
    raise SystemExit("missing proof_to_byte_inputs in artifact/results.json")

paths = {
    "contextbound_vectors_sha256": "bindings/contextbound-vectors.txt",
    "shared_vectors_sha256": "bindings/shared-test-vectors.json",
    "signed_policy_vectors_sha256": "bindings/signed-policy-vectors.json",
    "easycrypt_binding_sha256": "formal/easycrypt/BindingViaCR.ec",
    "tamarin_model_sha256": "formal/tamarin/handshake.spthy",
    "proverif_model_sha256": "formal/proverif/handshake.pv",
    "proof_to_byte_script_sha256": "artifact/proof-to-byte.sh",
    "c_package_script_sha256": "artifact/c-package.sh",
    "swift_xcframework_script_sha256": "artifact/swift-xcframework.sh",
    "local_release_index_script_sha256": "artifact/local-release-index.sh",
    "release_index_verifier_sha256": "artifact/release_index.py",
    "local_release_consumer_smoke_script_sha256": "artifact/local-release-consumer-smoke.sh",
    "release_consumer_smoke_verifier_sha256": "artifact/release_consumer_smoke.py",
    "apple_device_smoke_script_sha256": "artifact/apple-device-smoke.sh",
    "apple_device_matrix_script_sha256": "artifact/apple-device-matrix.sh",
    "apple_device_xcode27_gate_script_sha256": "artifact/apple-device-xcode27-gate.sh",
    "apple_device_proof_verifier_sha256": "artifact/apple_device_proof.py",
    "android_aar_script_sha256": "artifact/android-aar.sh",
    "android_device_smoke_script_sha256": "artifact/android-device-smoke.sh",
    "android_device_proof_verifier_sha256": "artifact/android_device_proof.py",
    "android_device_proof_tests_sha256": "artifact/test_android_device_proof.py",
    "android_facade_sha256": "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java",
    "android_jni_adapter_sha256": "bindings/android/jni/qperiapt_jni.c",
    "c_smoke_sha256": "bindings/c/smoke.c",
    "license_sha256": "LICENSE",
    "license_apache_sha256": "LICENSES/Apache-2.0.txt",
    "license_mit_sha256": "LICENSES/MIT.txt",
    "qperiapt_cli_cargo_sha256": "crates/q-periapt-cli/Cargo.toml",
    "qperiapt_cli_lib_sha256": "crates/q-periapt-cli/src/lib.rs",
    "qperiapt_cli_main_sha256": "crates/q-periapt-cli/src/main.rs",
}
for key, rel in paths.items():
    if key not in expected:
        raise SystemExit(f"missing {key} in artifact/results.json")
    data = (root / rel).read_bytes()
    got = hashlib.sha256(data).hexdigest()
    if got != expected[key]:
        raise SystemExit(f"hash mismatch for {rel}: got {got}, expected {expected[key]}")

print("PROOF_TO_BYTE_MANIFEST_HASHES_PASS")
PY

if [ "${QPERIAPT_SKIP_SMOKE:-0}" != "1" ]; then
	sh artifact/smoke.sh
fi

if [ "${QPERIAPT_REQUIRE_APPLE_DEVICE:-0}" = "1" ]; then
	if [ "${QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX:-0}" = "1" ]; then
		printf 'error: QPERIAPT_REQUIRE_APPLE_DEVICE and QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX are mutually exclusive\n' >&2
		exit 2
	fi
	case "${QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF:-0}" in
		0 | 1) ;;
		*)
			printf 'error: QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF must be 0 or 1\n' >&2
			exit 2
			;;
	esac
	DEVICE_RESULT_DIR=$(device_result_dir "${QPERIAPT_DEVICE_RESULT_DIR:-$ROOT/artifact/device-runs}")
	DEVICE_ARTIFACT_PREFIX=${QPERIAPT_DEVICE_ARTIFACT_PREFIX:-ipad}
	EXPECTED_DEVICE_TYPE=${QPERIAPT_EXPECT_DEVICE_TYPE:-}
	case "$DEVICE_ARTIFACT_PREFIX" in
		*[!A-Za-z0-9._-]* | "")
			printf 'error: invalid QPERIAPT_DEVICE_ARTIFACT_PREFIX: %s\n' "$DEVICE_ARTIFACT_PREFIX" >&2
			exit 2
			;;
	esac
	case "$EXPECTED_DEVICE_TYPE" in
		"" | iPad | iPhone) ;;
		*)
			printf 'error: invalid QPERIAPT_EXPECT_DEVICE_TYPE: %s\n' "$EXPECTED_DEVICE_TYPE" >&2
			exit 2
			;;
	esac
	LOG="$DEVICE_RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-device-launch.log"
	DEVICE_RESULT="$DEVICE_RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-device-result.txt"
	BUILD_LOG="$DEVICE_RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-build.log"
	PROOF_JSON="$DEVICE_RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-device-proof.json"
	MAX_AGE_SECONDS=$(device_proof_max_age_seconds "${QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS:-86400}")
	test -f "$PROOF_JSON" || {
		printf 'error: required Apple device proof JSON missing: %s\n' "$PROOF_JSON" >&2
		exit 1
	}
	test -f "$BUILD_LOG" || {
		printf 'error: required Apple device build log missing: %s\n' "$BUILD_LOG" >&2
		exit 1
	}
	test -f "$LOG" || {
		printf 'error: required Apple device launch log missing: %s\n' "$LOG" >&2
		exit 1
	}
	test -f "$DEVICE_RESULT" || {
		printf 'error: required Apple device result marker missing: %s\n' "$DEVICE_RESULT" >&2
		exit 1
	}
	if [ "${QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF:-0}" = "1" ]; then
		python3 artifact/apple_device_proof.py verify \
			--root "$ROOT" \
			--proof "$PROOF_JSON" \
			--build-log "$BUILD_LOG" \
			--launch-log "$LOG" \
			--device-result "$DEVICE_RESULT" \
			--max-age-seconds "$MAX_AGE_SECONDS" \
			--expected-device-type "$EXPECTED_DEVICE_TYPE" \
			--allow-dirty-proof
	else
		python3 artifact/apple_device_proof.py verify \
			--root "$ROOT" \
			--proof "$PROOF_JSON" \
			--build-log "$BUILD_LOG" \
			--launch-log "$LOG" \
			--device-result "$DEVICE_RESULT" \
			--max-age-seconds "$MAX_AGE_SECONDS" \
			--expected-device-type "$EXPECTED_DEVICE_TYPE"
	fi
fi

if [ "${QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX:-0}" = "1" ]; then
	case "${QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF:-0}" in
		0 | 1) ;;
		*)
			printf 'error: QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF must be 0 or 1\n' >&2
			exit 2
			;;
	esac
	DEVICE_RESULT_DIR=$(device_result_dir "${QPERIAPT_DEVICE_RESULT_DIR:-$ROOT/artifact/device-runs}")
	MATRIX_PROOF="${QPERIAPT_DEVICE_MATRIX_PROOF:-$DEVICE_RESULT_DIR/apple-device-matrix-proof.json}"
	MAX_AGE_SECONDS=$(device_proof_max_age_seconds "${QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS:-86400}")
	test -f "$MATRIX_PROOF" || {
		printf 'error: required Apple device matrix proof JSON missing: %s\n' "$MATRIX_PROOF" >&2
		exit 1
	}
	if [ "${QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF:-0}" = "1" ]; then
		python3 artifact/apple_device_proof.py verify-matrix \
			--root "$ROOT" \
			--matrix-root "$DEVICE_RESULT_DIR" \
			--matrix-proof "$MATRIX_PROOF" \
			--max-age-seconds "$MAX_AGE_SECONDS" \
			--allow-dirty-proof
	else
		python3 artifact/apple_device_proof.py verify-matrix \
			--root "$ROOT" \
			--matrix-root "$DEVICE_RESULT_DIR" \
			--matrix-proof "$MATRIX_PROOF" \
			--max-age-seconds "$MAX_AGE_SECONDS"
	fi
fi

if [ "${QPERIAPT_REQUIRE_ANDROID_RUNTIME:-0}" = "1" ]; then
	ANDROID_PROOF="${QPERIAPT_ANDROID_DEVICE_PROOF:-$ROOT/target/qperiapt-android-device-smoke/proof/qperiapt-android-device-proof.json}"
	MAX_AGE_SECONDS=$(android_proof_max_age_seconds "${QPERIAPT_ANDROID_PROOF_MAX_AGE_SECONDS:-86400}")
	EXPECTED_KIND=${QPERIAPT_ANDROID_EXPECT_DEVICE_KIND:-}
	case "$EXPECTED_KIND" in
		"" | emulator | physical) ;;
		*)
			printf 'error: invalid QPERIAPT_ANDROID_EXPECT_DEVICE_KIND: %s\n' "$EXPECTED_KIND" >&2
			exit 2
			;;
	esac
	test -f "$ANDROID_PROOF" || {
		printf 'error: required Android runtime proof JSON missing: %s\n' "$ANDROID_PROOF" >&2
		exit 1
	}
	if [ "${QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF:-0}" = "1" ]; then
		if [ -n "$EXPECTED_KIND" ]; then
			python3 artifact/android_device_proof.py verify \
				--root "$ROOT" \
				--proof "$ANDROID_PROOF" \
				--max-age-seconds "$MAX_AGE_SECONDS" \
				--expected-device-kind "$EXPECTED_KIND" \
				--allow-dirty-proof
		else
			python3 artifact/android_device_proof.py verify \
				--root "$ROOT" \
				--proof "$ANDROID_PROOF" \
				--max-age-seconds "$MAX_AGE_SECONDS" \
				--allow-dirty-proof
		fi
	else
		if [ -n "$EXPECTED_KIND" ]; then
			python3 artifact/android_device_proof.py verify \
				--root "$ROOT" \
				--proof "$ANDROID_PROOF" \
				--max-age-seconds "$MAX_AGE_SECONDS" \
				--expected-device-kind "$EXPECTED_KIND"
		else
			python3 artifact/android_device_proof.py verify \
				--root "$ROOT" \
				--proof "$ANDROID_PROOF" \
				--max-age-seconds "$MAX_AGE_SECONDS"
		fi
	fi
fi

printf 'PROOF_TO_BYTE_PASS\n'
