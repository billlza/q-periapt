#!/bin/sh
# Validate the proof-to-byte evidence manifest and, by default, run the Tier-1 smoke.
set -eu

ROOT=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

validate_path_text() {
	python3 - "$1" "$2" <<'PY'
import os
import sys

raw_path, label = sys.argv[1:]
max_path_bytes = 4095
if (
    not raw_path
    or not raw_path.isprintable()
    or len(os.fsencode(raw_path)) > max_path_bytes
):
    print(
        f"error: {label} must be a non-empty printable path of at most "
        f"{max_path_bytes} filesystem bytes",
        file=sys.stderr,
    )
    raise SystemExit(2)
PY
}

normalized_path_under() {
	validate_path_text "$1" "$3"
	validate_path_text "$2" "internal base path"
	python3 - "$1" "$2" "$3" "$4" <<'PY'
import os
import pathlib
import sys

raw_path, raw_base, label, allow_base = sys.argv[1:]

def shown(value: str) -> str:
    rendered = repr(value)
    return rendered if len(rendered) <= 160 else rendered[:157] + "..."

def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(2)

try:
    path = pathlib.Path(os.path.abspath(raw_path))
    base = pathlib.Path(os.path.abspath(raw_base))
except (OSError, ValueError) as exc:
    fail(f"cannot normalize {label}: {shown(str(exc))}")
try:
    relative = path.relative_to(base)
except ValueError:
    fail(
        f"{label} must be under {shown(os.fspath(base))}: "
        f"{shown(os.fspath(path))}"
    )
if allow_base == "0" and not relative.parts:
    fail(f"{label} must name a file below {base}: {shown(os.fspath(path))}")
if allow_base not in {"0", "1"}:
    fail(f"internal path policy is invalid for {label}")
current = base
try:
    if current.is_symlink():
        fail(f"{label} base must not be a symlink: {shown(os.fspath(current))}")
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            fail(f"{label} must not traverse a symlink: {shown(os.fspath(current))}")
except OSError as exc:
    fail(
        f"cannot inspect {label} {shown(os.fspath(current))}: "
        f"{shown(str(exc))}"
    )
print(path)
PY
}

device_result_dir() {
	normalized_path_under \
		"$1" \
		"$ROOT/artifact/device-runs" \
		QPERIAPT_DEVICE_RESULT_DIR \
		1
}

proof_max_age_seconds() {
	python3 - "$1" "$2" <<'PY'
import sys

name, raw = sys.argv[1:]
limit = 7 * 24 * 60 * 60
rendered = repr(raw)
shown = rendered if len(rendered) <= 80 else rendered[:77] + "..."
if not raw.isascii() or not raw.isdigit() or len(raw) > len(str(limit)):
    print(
        f"error: {name} must be an ASCII base-10 integer between 1 and {limit}: {shown}",
        file=sys.stderr,
    )
    raise SystemExit(2)
value = int(raw)
if not 0 < value <= limit:
    print(
        f"error: {name} must be an ASCII base-10 integer between 1 and {limit}: {shown}",
        file=sys.stderr,
    )
    raise SystemExit(2)
print(value)
PY
}

proof_path_under() {
	normalized_path_under "$1" "$2" "$3" 0
}

need python3

bool_flag() {
	name=$1
	value=$2
	case "$value" in
		0 | 1) printf '%s\n' "$value" ;;
		*)
			printf 'error: %s must be 0 or 1\n' "$name" >&2
			exit 2
			;;
	esac
}

SKIP_SMOKE=$(bool_flag QPERIAPT_SKIP_SMOKE "${QPERIAPT_SKIP_SMOKE:-0}")
REQUIRE_FORMAL=$(bool_flag QPERIAPT_REQUIRE_FORMAL "${QPERIAPT_REQUIRE_FORMAL:-0}")
RUN_CONTINUITY_DIAGNOSTIC=$(bool_flag QPERIAPT_RUN_CONTINUITY_DIAGNOSTIC "${QPERIAPT_RUN_CONTINUITY_DIAGNOSTIC:-0}")
REQUIRE_APPLE_DEVICE=$(bool_flag QPERIAPT_REQUIRE_APPLE_DEVICE "${QPERIAPT_REQUIRE_APPLE_DEVICE:-0}")
REQUIRE_APPLE_DEVICE_MATRIX=$(bool_flag QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX "${QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX:-0}")
REQUIRE_ANDROID_RUNTIME=$(bool_flag QPERIAPT_REQUIRE_ANDROID_RUNTIME "${QPERIAPT_REQUIRE_ANDROID_RUNTIME:-0}")
REQUIRE_PERFORMANCE=$(bool_flag QPERIAPT_REQUIRE_PERFORMANCE "${QPERIAPT_REQUIRE_PERFORMANCE:-0}")
REQUIRE_CAMERA_READY=$(bool_flag QPERIAPT_REQUIRE_CAMERA_READY "${QPERIAPT_REQUIRE_CAMERA_READY:-0}")
REQUIRE_DEPENDENCY_AUDIT=$(bool_flag QPERIAPT_REQUIRE_DEPENDENCY_AUDIT "${QPERIAPT_REQUIRE_DEPENDENCY_AUDIT:-0}")
ALLOW_DIRTY_APPLE_DEVICE_PROOF=$(bool_flag QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF "${QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF:-0}")
ALLOW_DIRTY_ANDROID_RUNTIME_PROOF=$(bool_flag QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF "${QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF:-0}")
ALLOW_DIRTY_PERFORMANCE_PROOF=$(bool_flag QPERIAPT_ALLOW_DIRTY_PERFORMANCE_PROOF "${QPERIAPT_ALLOW_DIRTY_PERFORMANCE_PROOF:-0}")

EXPECTED_GIT_COMMIT=${QPERIAPT_EXPECTED_GIT_COMMIT:-}
if [ -n "$EXPECTED_GIT_COMMIT" ]; then
	case "$EXPECTED_GIT_COMMIT" in
		*[!0-9a-f]*)
			printf 'error: QPERIAPT_EXPECTED_GIT_COMMIT must be exactly 40 lowercase hexadecimal characters\n' >&2
			exit 2
			;;
	esac
	if [ "${#EXPECTED_GIT_COMMIT}" -ne 40 ]; then
		printf 'error: QPERIAPT_EXPECTED_GIT_COMMIT must be exactly 40 lowercase hexadecimal characters\n' >&2
		exit 2
	fi
fi

if [ "$REQUIRE_APPLE_DEVICE" = "1" ] && [ "$REQUIRE_APPLE_DEVICE_MATRIX" = "1" ]; then
	printf 'error: QPERIAPT_REQUIRE_APPLE_DEVICE and QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX are mutually exclusive\n' >&2
	exit 2
fi

# Normalize every active caller-controlled option before any proof marker is
# emitted. Evidence existence and content are checked later by their gates.
CAMERA_READY_TRANSCRIPT=
CAMERA_READY_BUNDLE=
CAMERA_READY_MAX_AGE_SECONDS=
if [ "$REQUIRE_CAMERA_READY" = "1" ]; then
	if [ "${QPERIAPT_CAMERA_READY_TRANSCRIPT+x}" = "x" ]; then
		CAMERA_READY_TRANSCRIPT=$QPERIAPT_CAMERA_READY_TRANSCRIPT
	else
		CAMERA_READY_TRANSCRIPT=$ROOT/target/camera-ready/transcript.txt
	fi
	CAMERA_READY_BUNDLE=${QPERIAPT_CAMERA_READY_BUNDLE:-}
	if [ -z "$CAMERA_READY_BUNDLE" ]; then
		printf 'error: QPERIAPT_CAMERA_READY_BUNDLE must explicitly name the root-owned run-id bundle emitted by camera-ready-bare-metal.sh\n' >&2
		exit 2
	fi
	validate_path_text "$CAMERA_READY_TRANSCRIPT" QPERIAPT_CAMERA_READY_TRANSCRIPT
	validate_path_text "$CAMERA_READY_BUNDLE" QPERIAPT_CAMERA_READY_BUNDLE
	CAMERA_READY_MAX_AGE_SECONDS=$(proof_max_age_seconds \
		QPERIAPT_CAMERA_READY_MAX_AGE_SECONDS \
		"${QPERIAPT_CAMERA_READY_MAX_AGE_SECONDS:-86400}")
	if [ "$CAMERA_READY_MAX_AGE_SECONDS" != "86400" ]; then
		printf 'error: release verification fixes camera-ready freshness to 86400 seconds\n' >&2
		exit 2
	fi
fi

DEVICE_RESULT_DIR=
APPLE_DEVICE_MAX_AGE_SECONDS=
DEVICE_ARTIFACT_PREFIX=
EXPECTED_DEVICE_TYPE=
LOG=
DEVICE_RESULT=
BUILD_LOG=
PROOF_JSON=
MATRIX_PROOF=
if [ "$REQUIRE_APPLE_DEVICE" = "1" ] || [ "$REQUIRE_APPLE_DEVICE_MATRIX" = "1" ]; then
	if [ "${QPERIAPT_DEVICE_RESULT_DIR+x}" = "x" ]; then
		DEVICE_RESULT_DIR=$(device_result_dir "$QPERIAPT_DEVICE_RESULT_DIR")
	else
		DEVICE_RESULT_DIR=$(device_result_dir "$ROOT/artifact/device-runs")
	fi
	APPLE_DEVICE_MAX_AGE_SECONDS=$(proof_max_age_seconds \
		QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS \
		"${QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS:-86400}")
	if [ "$ALLOW_DIRTY_APPLE_DEVICE_PROOF" = "0" ] && [ "$APPLE_DEVICE_MAX_AGE_SECONDS" != "86400" ]; then
		printf 'error: release verification fixes Apple proof freshness to 86400 seconds\n' >&2
		exit 2
	fi
fi
if [ "$REQUIRE_APPLE_DEVICE" = "1" ]; then
	if [ "${QPERIAPT_DEVICE_ARTIFACT_PREFIX+x}" = "x" ]; then
		DEVICE_ARTIFACT_PREFIX=$QPERIAPT_DEVICE_ARTIFACT_PREFIX
	else
		DEVICE_ARTIFACT_PREFIX=ipad
	fi
	EXPECTED_DEVICE_TYPE=${QPERIAPT_EXPECT_DEVICE_TYPE:-}
	case "$DEVICE_ARTIFACT_PREFIX" in
		*[!A-Za-z0-9._-]* | "")
			printf 'error: invalid QPERIAPT_DEVICE_ARTIFACT_PREFIX\n' >&2
			exit 2
			;;
	esac
	case "$EXPECTED_DEVICE_TYPE" in
		"" | iPad | iPhone) ;;
		*)
			printf 'error: invalid QPERIAPT_EXPECT_DEVICE_TYPE\n' >&2
			exit 2
			;;
	esac
	LOG="$DEVICE_RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-device-launch.log"
	DEVICE_RESULT="$DEVICE_RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-device-result.txt"
	BUILD_LOG="$DEVICE_RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-build.log"
	PROOF_JSON="$DEVICE_RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-device-proof.json"
fi
if [ "$REQUIRE_APPLE_DEVICE_MATRIX" = "1" ]; then
	if [ "${QPERIAPT_DEVICE_MATRIX_PROOF+x}" = "x" ]; then
		DEVICE_MATRIX_PROOF=$QPERIAPT_DEVICE_MATRIX_PROOF
	else
		DEVICE_MATRIX_PROOF=$DEVICE_RESULT_DIR/apple-device-matrix-proof.json
	fi
	MATRIX_PROOF=$(proof_path_under \
		"$DEVICE_MATRIX_PROOF" \
		"$DEVICE_RESULT_DIR" \
		QPERIAPT_DEVICE_MATRIX_PROOF)
fi

ANDROID_PROOF=
ANDROID_MAX_AGE_SECONDS=
EXPECTED_KIND=
if [ "$REQUIRE_ANDROID_RUNTIME" = "1" ]; then
	if [ "${QPERIAPT_ANDROID_DEVICE_PROOF+x}" = "x" ]; then
		ANDROID_DEVICE_PROOF=$QPERIAPT_ANDROID_DEVICE_PROOF
	else
		ANDROID_DEVICE_PROOF=$ROOT/target/qperiapt-android-device-smoke/proof/qperiapt-android-device-proof.json
	fi
	ANDROID_PROOF=$(proof_path_under \
		"$ANDROID_DEVICE_PROOF" \
		"$ROOT/target" \
		QPERIAPT_ANDROID_DEVICE_PROOF)
	ANDROID_MAX_AGE_SECONDS=$(proof_max_age_seconds \
		QPERIAPT_ANDROID_PROOF_MAX_AGE_SECONDS \
		"${QPERIAPT_ANDROID_PROOF_MAX_AGE_SECONDS:-86400}")
	EXPECTED_KIND=${QPERIAPT_ANDROID_EXPECT_DEVICE_KIND:-}
	case "$EXPECTED_KIND" in
		"" | emulator | physical) ;;
		*)
			printf 'error: invalid QPERIAPT_ANDROID_EXPECT_DEVICE_KIND\n' >&2
			exit 2
			;;
	esac
fi

PERFORMANCE_PROOF=
PERFORMANCE_MAX_AGE_SECONDS=
if [ "$REQUIRE_PERFORMANCE" = "1" ]; then
	if [ "${QPERIAPT_PERFORMANCE_PROOF+x}" = "x" ]; then
		PERFORMANCE_PROOF_PATH=$QPERIAPT_PERFORMANCE_PROOF
	else
		PERFORMANCE_PROOF_PATH=$ROOT/target/performance/paired-profile-proof.json
	fi
	PERFORMANCE_PROOF=$(proof_path_under \
		"$PERFORMANCE_PROOF_PATH" \
		"$ROOT/target" \
		QPERIAPT_PERFORMANCE_PROOF)
	PERFORMANCE_MAX_AGE_SECONDS=$(proof_max_age_seconds \
		QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS \
		"${QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS:-86400}")
	if [ "$ALLOW_DIRTY_PERFORMANCE_PROOF" = "0" ] && [ "$PERFORMANCE_MAX_AGE_SECONDS" != "86400" ]; then
		printf 'error: release verification fixes performance proof freshness to 86400 seconds\n' >&2
		exit 2
	fi
fi

if [ "$REQUIRE_DEPENDENCY_AUDIT" = "1" ]; then
	need cargo
	need cargo-audit
fi
if [ "$REQUIRE_FORMAL" = "1" ] || [ "$RUN_CONTINUITY_DIAGNOSTIC" = "1" ]; then
	if [ -n "${HOME:-}" ] && [ -d "$HOME/.opam/default/bin" ]; then
		PATH="$HOME/.opam/default/bin:$PATH"
		export PATH
	fi
	need make
	need easycrypt
fi
if [ "$REQUIRE_FORMAL" = "1" ]; then
	need tamarin-prover
	need proverif
fi
if [ "$RUN_CONTINUITY_DIAGNOSTIC" = "1" ]; then
	need cargo
fi

RESULTS_MANIFEST="$ROOT/artifact/results.json"
RESULTS_MANIFEST_SHA256=$(PYTHONPATH=artifact python3 - "$RESULTS_MANIFEST" <<'PY'
import pathlib
import sys

from proof_manifest import load_results_manifest_snapshot

print(load_results_manifest_snapshot(pathlib.Path(sys.argv[1])).file.sha256)
PY
)

if [ -n "$EXPECTED_GIT_COMMIT" ]; then
	FROZEN_SOURCE_SNAPSHOT=$(python3 artifact/proof_to_byte_finalizer.py freeze \
		--root "$ROOT" \
		--ledger "$ROOT/artifact/claim-ledger.json" \
		--manifest "$RESULTS_MANIFEST" \
		--expected-manifest-sha256 "$RESULTS_MANIFEST_SHA256" \
		--expected-git-commit "$EXPECTED_GIT_COMMIT")
else
	FROZEN_SOURCE_SNAPSHOT=$(python3 artifact/proof_to_byte_finalizer.py freeze \
		--root "$ROOT" \
		--ledger "$ROOT/artifact/claim-ledger.json" \
		--manifest "$RESULTS_MANIFEST" \
		--expected-manifest-sha256 "$RESULTS_MANIFEST_SHA256")
fi
FROZEN_GIT_COMMIT=${FROZEN_SOURCE_SNAPSHOT%%:*}
FROZEN_SOURCE_REMAINDER=${FROZEN_SOURCE_SNAPSHOT#*:}
FROZEN_SOURCE_TREE_SHA256=${FROZEN_SOURCE_REMAINDER%%:*}
FROZEN_SOURCE_TREE_DIRTY=${FROZEN_SOURCE_REMAINDER##*:}
printf 'PROOF_TO_BYTE_SOURCE_SNAPSHOT_PASS commit=%s source_sha256=%s manifest_sha256=%s dirty=%s\n' \
	"$FROZEN_GIT_COMMIT" "$FROZEN_SOURCE_TREE_SHA256" "$RESULTS_MANIFEST_SHA256" \
	"$FROZEN_SOURCE_TREE_DIRTY"

# These values are process-local observations, not caller-supplied claims. An
# environment variable with the same name is deliberately overwritten here.
HOST_SMOKE_PASSED=0
FORMAL_PASSED=0
APPLE_DEVICE_PASSED=0
APPLE_MATRIX_PASSED=0
ANDROID_RUNTIME_PASSED=0
PERFORMANCE_PASSED=0
CAMERA_READY_BUNDLE_PASSED=0
DEPENDENCY_AUDIT_PASSED=0

PYTHONPATH=artifact python3 - "$RESULTS_MANIFEST" "$RESULTS_MANIFEST_SHA256" <<'PY'
import hashlib
import pathlib
import sys

from proof_manifest import load_results_manifest_snapshot

root = pathlib.Path.cwd().resolve()
manifest = load_results_manifest_snapshot(
    pathlib.Path(sys.argv[1]),
    expected_sha256=sys.argv[2],
).value
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
    "proof_to_byte_finalizer_sha256": "artifact/proof_to_byte_finalizer.py",
    "proof_to_byte_release_tests_sha256": "artifact/test_proof_to_byte_release.py",
    "evidence_io_sha256": "artifact/evidence_io.py",
    "evidence_io_tests_sha256": "artifact/test_evidence_io.py",
    "git_provenance_sha256": "artifact/git_provenance.py",
    "git_provenance_tests_sha256": "artifact/test_git_provenance.py",
    "python_bootstrap_sha256": "artifact/python_bootstrap.py",
    "python_env_sha256": "artifact/python-env.sh",
    "python_runner_sha256": "artifact/python-run.sh",
    "proof_manifest_sha256": "artifact/proof_manifest.py",
    "proof_manifest_tests_sha256": "artifact/test_proof_manifest.py",
    "claim_ledger_sha256": "artifact/claim-ledger.json",
    "claim_ledger_verifier_sha256": "artifact/claim_ledger.py",
    "claim_ledger_tests_sha256": "artifact/test_claim_ledger.py",
    "reference_baseline_sha256": "docs/continuity/reference-baseline.json",
    "reference_baseline_verifier_sha256": "artifact/reference_baseline.py",
    "reference_baseline_tests_sha256": "artifact/test_reference_baseline.py",
    "continuity_context_spec_sha256": "docs/continuity/LIFECYCLE_CONTEXT_V1.md",
    "continuity_context_model_sha256": "models/q-periapt-continuity-model/src/context.rs",
    "continuity_context_tests_sha256": "models/q-periapt-continuity-model/tests/context.rs",
    "continuity_context_vectors_sha256": "models/q-periapt-continuity-model/vectors/lifecycle-context-v1.json",
    "continuity_context_vector_emitter_sha256": "models/q-periapt-continuity-model/examples/continuity_context_vectors.rs",
    "continuity_context_verifier_sha256": "artifact/continuity_context.py",
    "continuity_context_verifier_tests_sha256": "artifact/test_continuity_context.py",
    "continuity_prekey_spec_sha256": "docs/continuity/PREKEY_SELECTION_V1.md",
    "continuity_prekey_codec_sha256": "models/q-periapt-continuity-model/src/codec.rs",
    "continuity_prekey_commitments_sha256": "models/q-periapt-continuity-model/src/commitments.rs",
    "continuity_prekey_model_sha256": "models/q-periapt-continuity-model/src/prekey.rs",
    "continuity_prekey_tests_sha256": "models/q-periapt-continuity-model/tests/prekey_selection.rs",
    "continuity_prekey_vectors_sha256": "models/q-periapt-continuity-model/vectors/prekey-selection-v1.json",
    "continuity_prekey_vector_emitter_sha256": "models/q-periapt-continuity-model/examples/prekey_selection_vectors.rs",
    "continuity_prekey_verifier_sha256": "artifact/prekey_selection.py",
    "continuity_prekey_verifier_tests_sha256": "artifact/test_prekey_selection.py",
    "continuity_model_manifest_sha256": "models/q-periapt-continuity-model/Cargo.toml",
    "continuity_model_lib_sha256": "models/q-periapt-continuity-model/src/lib.rs",
    "continuity_model_types_sha256": "models/q-periapt-continuity-model/src/types.rs",
    "continuity_model_state_machine_sha256": "models/q-periapt-continuity-model/src/model.rs",
    "continuity_model_lifecycle_tests_sha256": "models/q-periapt-continuity-model/tests/lifecycle.rs",
    "continuity_model_isolation_tests_sha256": "artifact/test_continuity_model_isolation.py",
    "continuity_effect_lifecycle_spec_sha256": "docs/continuity/G1_EFFECT_LIFECYCLE.md",
    "continuity_easycrypt_model_sha256": "formal/easycrypt/continuity/LifecycleContextV1.ec",
    "continuity_prekey_easycrypt_model_sha256": "formal/easycrypt/continuity/PrekeySelectionV1.ec",
    "continuity_easycrypt_makefile_sha256": "formal/easycrypt/continuity/Makefile",
    "hqc_candidate_readme_sha256": "research/hqc-fips207-candidate/README.md",
    "hqc_candidate_manifest_sha256": "research/hqc-fips207-candidate/Cargo.toml",
    "hqc_candidate_lock_sha256": "research/hqc-fips207-candidate/Cargo.lock",
    "hqc_candidate_adapter_sha256": "research/hqc-fips207-candidate/src/lib.rs",
    "hqc_candidate_tests_sha256": "research/hqc-fips207-candidate/tests/adapter.rs",
    "hqc_candidate_verify_sha256": "research/hqc-fips207-candidate/scripts/verify.sh",
    "rust_publish_dry_run_script_sha256": "artifact/rust-publish-dry-run.sh",
    "rust_publish_contract_sha256": "artifact/rust_publish_contract.py",
    "rust_publish_contract_tests_sha256": "artifact/test_rust_publish_contract.py",
    "c_package_script_sha256": "artifact/c-package.sh",
    "swift_xcframework_script_sha256": "artifact/swift-xcframework.sh",
    "swift_xcframework_release_script_sha256": "artifact/swift-xcframework-release.sh",
    "swift_xcframework_consumer_check_script_sha256": "artifact/swift-xcframework-consumer-check.sh",
    "swift_xcframework_remote_consumer_script_sha256": "artifact/swift-xcframework-remote-consumer.sh",
    "apple_distribution_verifier_sha256": "artifact/apple_distribution.py",
    "apple_distribution_tests_sha256": "artifact/test_apple_distribution.py",
    "swift_binary_consumer_link_probe_sha256": "bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift",
    "swift_binary_consumer_tests_sha256": "bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift",
    "local_release_index_script_sha256": "artifact/local-release-index.sh",
    "release_index_verifier_sha256": "artifact/release_index.py",
    "local_release_consumer_smoke_script_sha256": "artifact/local-release-consumer-smoke.sh",
    "release_consumer_smoke_verifier_sha256": "artifact/release_consumer_smoke.py",
    "apple_device_smoke_script_sha256": "artifact/apple-device-smoke.sh",
    "apple_device_matrix_script_sha256": "artifact/apple-device-matrix.sh",
    "apple_device_xcode27_gate_script_sha256": "artifact/apple-device-xcode27-gate.sh",
    "apple_device_proof_verifier_sha256": "artifact/apple_device_proof.py",
    "apple_device_proof_tests_sha256": "artifact/test_apple_device_proof.py",
    "android_aar_script_sha256": "artifact/android-aar.sh",
    "android_device_smoke_script_sha256": "artifact/android-device-smoke.sh",
    "android_device_proof_verifier_sha256": "artifact/android_device_proof.py",
    "android_device_proof_tests_sha256": "artifact/test_android_device_proof.py",
    "performance_gate_sha256": "artifact/performance_gate.py",
    "performance_gate_tests_sha256": "artifact/test_performance_gate.py",
    "performance_budgets_sha256": "artifact/performance-budgets.json",
    "paired_profile_perf_harness_sha256": "crates/q-periapt-backends/examples/paired_profile_perf.rs",
    "camera_ready_bare_metal_script_sha256": "camera-ready-bare-metal.sh",
    "camera_ready_sandbox_script_sha256": "artifact/camera-ready-sandbox.sh",
    "camera_ready_bare_metal_transcript_sha256": "paper/camera-ready-results.txt",
    "camera_ready_proof_verifier_sha256": "artifact/camera_ready_proof.py",
    "camera_ready_proof_tests_sha256": "artifact/test_camera_ready_proof.py",
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
missing = sorted(set(paths) - set(expected))
extra = sorted(set(expected) - set(paths))
if missing or extra:
    raise SystemExit(
        f"proof_to_byte_inputs key-set mismatch: missing={missing}, extra={extra}"
    )
for key, rel in paths.items():
    data = (root / rel).read_bytes()
    got = hashlib.sha256(data).hexdigest()
    if got != expected[key]:
        raise SystemExit(f"hash mismatch for {rel}: got {got}, expected {expected[key]}")

print("PROOF_TO_BYTE_MANIFEST_HASHES_PASS")
PY

if [ "$REQUIRE_CAMERA_READY" = "1" ]; then
	test -f "$CAMERA_READY_TRANSCRIPT" || {
		printf 'error: required camera-ready transcript missing\n' >&2
		exit 1
	}
	test -d "$CAMERA_READY_BUNDLE" || {
		printf 'error: required camera-ready bundle missing\n' >&2
		exit 1
	}
	PYTHONPATH=artifact python3 artifact/camera_ready_proof.py verify \
		--root "$ROOT" \
		--transcript "$CAMERA_READY_TRANSCRIPT" \
		--bundle "$CAMERA_READY_BUNDLE" \
		--max-age-seconds "$CAMERA_READY_MAX_AGE_SECONDS"
	CAMERA_READY_BUNDLE_PASSED=1
	printf 'PROOF_TO_BYTE_CAMERA_READY_CAPTURE_EVIDENCE_PASS boundary=producer_origin_not_independent_attestation\n'
fi

if [ "$REQUIRE_DEPENDENCY_AUDIT" = "1" ]; then
	cargo audit --deny warnings
	DEPENDENCY_AUDIT_PASSED=1
	printf 'PROOF_TO_BYTE_DEPENDENCY_AUDIT_PASS\n'
fi

if [ "$SKIP_SMOKE" = "0" ]; then
	sh artifact/smoke.sh
	HOST_SMOKE_PASSED=1
	printf 'PROOF_TO_BYTE_TIER1_HOST_PASS\n'
else
	printf 'PROOF_TO_BYTE_MANIFEST_ONLY_PASS\n'
fi

if [ "$REQUIRE_FORMAL" = "1" ]; then
	make -C formal/easycrypt check
	EASYCRYPT=$(command -v easycrypt) sh formal/easycrypt/negative-controls.sh
	make -C formal/tamarin prove
	make -C formal/proverif prove
	FORMAL_PASSED=1
	printf 'PROOF_TO_BYTE_FORMAL_MACHINECHECK_PASS\n'
fi

if [ "$RUN_CONTINUITY_DIAGNOSTIC" = "1" ]; then
	cargo test -p q-periapt-continuity-model --locked
	sh artifact/python-run.sh -m unittest -v \
		artifact/test_continuity_context.py \
		artifact/test_prekey_selection.py \
		artifact/test_continuity_model_isolation.py
	sh artifact/python-run.sh artifact/continuity_context.py verify \
		--vectors models/q-periapt-continuity-model/vectors/lifecycle-context-v1.json
	sh artifact/python-run.sh artifact/prekey_selection.py verify \
		--vectors models/q-periapt-continuity-model/vectors/prekey-selection-v1.json
	EC=$(command -v easycrypt) make -C formal/easycrypt/continuity check
	printf 'PROOF_TO_BYTE_CONTINUITY_MODEL_DIAGNOSTIC_PASS boundary=non_normative_not_release\n'
fi

if [ "$REQUIRE_APPLE_DEVICE" = "1" ]; then
	test -f "$PROOF_JSON" || {
		printf 'error: required Apple device proof JSON missing\n' >&2
		exit 1
	}
	test -f "$BUILD_LOG" || {
		printf 'error: required Apple device build log missing\n' >&2
		exit 1
	}
	test -f "$LOG" || {
		printf 'error: required Apple device launch log missing\n' >&2
		exit 1
	}
	test -f "$DEVICE_RESULT" || {
		printf 'error: required Apple device result marker missing\n' >&2
		exit 1
	}
	if [ "$ALLOW_DIRTY_APPLE_DEVICE_PROOF" = "1" ]; then
		python3 artifact/apple_device_proof.py verify \
			--root "$ROOT" \
			--proof "$PROOF_JSON" \
			--build-log "$BUILD_LOG" \
			--launch-log "$LOG" \
			--device-result "$DEVICE_RESULT" \
			--max-age-seconds "$APPLE_DEVICE_MAX_AGE_SECONDS" \
			--expected-device-type "$EXPECTED_DEVICE_TYPE" \
			--results-manifest "$RESULTS_MANIFEST" \
			--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256" \
			--allow-dirty-proof
	else
		python3 artifact/apple_device_proof.py verify \
			--root "$ROOT" \
			--proof "$PROOF_JSON" \
			--build-log "$BUILD_LOG" \
			--launch-log "$LOG" \
			--device-result "$DEVICE_RESULT" \
			--max-age-seconds "$APPLE_DEVICE_MAX_AGE_SECONDS" \
			--expected-device-type "$EXPECTED_DEVICE_TYPE" \
			--results-manifest "$RESULTS_MANIFEST" \
			--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256"
	fi
	APPLE_DEVICE_PASSED=1
	printf 'PROOF_TO_BYTE_APPLE_DEVICE_PASS\n'
fi

if [ "$REQUIRE_APPLE_DEVICE_MATRIX" = "1" ]; then
	test -f "$MATRIX_PROOF" || {
		printf 'error: required Apple device matrix proof JSON missing\n' >&2
		exit 1
	}
	if [ "$ALLOW_DIRTY_APPLE_DEVICE_PROOF" = "1" ]; then
		python3 artifact/apple_device_proof.py verify-matrix \
			--root "$ROOT" \
			--matrix-root "$DEVICE_RESULT_DIR" \
			--matrix-proof "$MATRIX_PROOF" \
			--max-age-seconds "$APPLE_DEVICE_MAX_AGE_SECONDS" \
			--results-manifest "$RESULTS_MANIFEST" \
			--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256" \
			--allow-dirty-proof
	else
		python3 artifact/apple_device_proof.py verify-matrix \
			--root "$ROOT" \
			--matrix-root "$DEVICE_RESULT_DIR" \
			--matrix-proof "$MATRIX_PROOF" \
			--max-age-seconds "$APPLE_DEVICE_MAX_AGE_SECONDS" \
			--results-manifest "$RESULTS_MANIFEST" \
			--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256"
	fi
	APPLE_MATRIX_PASSED=1
	printf 'PROOF_TO_BYTE_APPLE_MATRIX_PASS\n'
fi

if [ "$REQUIRE_ANDROID_RUNTIME" = "1" ]; then
	test -f "$ANDROID_PROOF" || {
		printf 'error: required Android runtime proof JSON missing\n' >&2
		exit 1
	}
	if [ "$ALLOW_DIRTY_ANDROID_RUNTIME_PROOF" = "1" ]; then
		if [ -n "$EXPECTED_KIND" ]; then
			python3 artifact/android_device_proof.py verify \
				--root "$ROOT" \
				--proof "$ANDROID_PROOF" \
				--max-age-seconds "$ANDROID_MAX_AGE_SECONDS" \
				--expected-device-kind "$EXPECTED_KIND" \
				--results-manifest "$RESULTS_MANIFEST" \
				--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256" \
				--allow-dirty-proof
		else
			python3 artifact/android_device_proof.py verify \
				--root "$ROOT" \
				--proof "$ANDROID_PROOF" \
				--max-age-seconds "$ANDROID_MAX_AGE_SECONDS" \
				--results-manifest "$RESULTS_MANIFEST" \
				--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256" \
				--allow-dirty-proof
		fi
	else
		if [ -n "$EXPECTED_KIND" ]; then
			python3 artifact/android_device_proof.py verify \
				--root "$ROOT" \
				--proof "$ANDROID_PROOF" \
				--max-age-seconds "$ANDROID_MAX_AGE_SECONDS" \
				--expected-device-kind "$EXPECTED_KIND" \
				--results-manifest "$RESULTS_MANIFEST" \
				--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256"
		else
			python3 artifact/android_device_proof.py verify \
				--root "$ROOT" \
				--proof "$ANDROID_PROOF" \
				--max-age-seconds "$ANDROID_MAX_AGE_SECONDS" \
				--results-manifest "$RESULTS_MANIFEST" \
				--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256"
		fi
		fi
	ANDROID_RUNTIME_PASSED=1
	printf 'PROOF_TO_BYTE_ANDROID_RUNTIME_PASS\n'
fi

if [ "$REQUIRE_PERFORMANCE" = "1" ]; then
	test -f "$PERFORMANCE_PROOF" || {
		printf 'error: required performance proof JSON missing\n' >&2
		exit 1
	}
	if [ "$ALLOW_DIRTY_PERFORMANCE_PROOF" = "1" ]; then
		python3 artifact/performance_gate.py verify \
			--root "$ROOT" \
			--proof "$PERFORMANCE_PROOF" \
			--max-age-seconds "$PERFORMANCE_MAX_AGE_SECONDS" \
			--results-manifest "$RESULTS_MANIFEST" \
			--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256" \
			--allow-dirty
	else
		python3 artifact/performance_gate.py verify \
			--root "$ROOT" \
			--proof "$PERFORMANCE_PROOF" \
			--max-age-seconds "$PERFORMANCE_MAX_AGE_SECONDS" \
			--results-manifest "$RESULTS_MANIFEST" \
			--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256"
	fi
	PERFORMANCE_PASSED=1
	printf 'PROOF_TO_BYTE_PERFORMANCE_HOST_PASS\n'
fi

python3 artifact/proof_to_byte_finalizer.py finalize \
	--root "$ROOT" \
	--ledger "$ROOT/artifact/claim-ledger.json" \
	--manifest "$RESULTS_MANIFEST" \
	--expected-manifest-sha256 "$RESULTS_MANIFEST_SHA256" \
	--expected-git-commit "$FROZEN_GIT_COMMIT" \
	--expected-source-sha256 "$FROZEN_SOURCE_TREE_SHA256" \
	--expected-source-dirty "$FROZEN_SOURCE_TREE_DIRTY" \
	"$HOST_SMOKE_PASSED" "$FORMAL_PASSED" "$APPLE_DEVICE_PASSED" \
	"$APPLE_MATRIX_PASSED" "$ANDROID_RUNTIME_PASSED" "$PERFORMANCE_PASSED" \
	"$CAMERA_READY_BUNDLE_PASSED" "$REQUIRE_CAMERA_READY" \
	"$DEPENDENCY_AUDIT_PASSED" "$ALLOW_DIRTY_APPLE_DEVICE_PROOF" \
	"$ALLOW_DIRTY_PERFORMANCE_PROOF"
