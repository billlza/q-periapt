#!/usr/bin/env python3
"""Single authoritative map and stable snapshots for proof-to-byte inputs.

The digests detect accidental source drift on a trusted build host.  They are
not an authentication boundary against the repository owner or another actor
that can replace entries in repository directories while this process runs.
"""

from __future__ import annotations

import os
import pathlib
import re
import stat
from types import MappingProxyType
from typing import Mapping

from evidence_io import (
    EvidenceIOError,
    read_regular_snapshot,
)


MAX_PROOF_INPUT_BYTES = 16 * 1024 * 1024
MAX_PROOF_INPUT_TOTAL_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ProofToByteInputsError(ValueError):
    """The declared proof-input map or one selected source file is invalid."""


PROOF_TO_BYTE_INPUT_PATHS = MappingProxyType({
    "contextbound_vectors_sha256": "bindings/contextbound-vectors.txt",
    "shared_vectors_sha256": "bindings/shared-test-vectors.json",
    "signed_policy_vectors_sha256": "bindings/signed-policy-vectors.json",
    "formal_easycrypt_dockerfile_sha256": "formal/Dockerfile",
    "easycrypt_binding_sha256": "formal/easycrypt/BindingViaCR.ec",
    "easycrypt_migration_v2_sha256": "formal/easycrypt/MigrationBindingV2.ec",
    "easycrypt_makefile_sha256": "formal/easycrypt/Makefile",
    "easycrypt_negative_controls_sha256": "formal/easycrypt/negative-controls.sh",
    "tamarin_model_sha256": "formal/tamarin/handshake.spthy",
    "tamarin_migration_state_v2_sha256": "formal/tamarin/migration_v2.spthy",
    "tamarin_migration_agreement_v2_sha256": "formal/tamarin/migration_v2_agreement.spthy",
    "tamarin_migration_liveness_v2_sha256": "formal/tamarin/migration_v2_liveness.spthy",
    "tamarin_migration_rollback_v2_sha256": "formal/tamarin/migration_v2_rollback.spthy",
    "tamarin_migration_no_witness_v2_sha256": "formal/tamarin/migration_v2_no_witness.spthy",
    "tamarin_migration_negative_controls_v2_sha256": "formal/tamarin/migration_v2_negative_controls.spthy",
    "tamarin_makefile_sha256": "formal/tamarin/Makefile",
    "proverif_model_sha256": "formal/proverif/handshake.pv",
    "proverif_makefile_sha256": "formal/proverif/Makefile",
    "proof_to_byte_script_sha256": "artifact/proof-to-byte.sh",
    "proof_to_byte_finalizer_sha256": "artifact/proof_to_byte_finalizer.py",
    "proof_to_byte_release_tests_sha256": "artifact/test_proof_to_byte_release.py",
    "ci_workflow_sha256": ".github/workflows/ci.yml",
    "formal_tool_asset_sha256": "artifact/formal_tool_asset.py",
    "formal_tool_asset_tests_sha256": "artifact/test_formal_tool_asset.py",
    "formal_toolchain_contract_sha256": "artifact/formal_toolchain_contract.py",
    "formal_toolchain_contract_tests_sha256": "artifact/test_formal_toolchain_contract.py",
    "codeql_workflow_sha256": ".github/workflows/codeql.yml",
    "codeql_rust_quality_gate_sha256": "artifact/codeql_rust_quality.py",
    "codeql_rust_checkout_gate_sha256": "artifact/codeql_rust_checkout.py",
    "codeql_rust_quality_tests_sha256": "artifact/test_codeql_rust_quality.py",
    "codeql_rust_quality_pack_sha256": "artifact/codeql-rust-quality/qlpack.yml",
    "codeql_rust_extracted_paths_query_sha256": "artifact/codeql-rust-quality/ExtractedPaths.ql",
    "codeql_rust_metrics_query_sha256": "artifact/codeql-rust-quality/Metrics.ql",
    "codeql_rust_unresolved_macros_query_sha256": "artifact/codeql-rust-quality/UnresolvedMacros.ql",
    "dependabot_config_sha256": ".github/dependabot.yml",
    "abi2_platform_candidate_workflow_sha256": ".github/workflows/abi2-platform-candidate.yml",
    "abi2_platform_candidate_verifier_script_sha256": "artifact/verify-platform-candidate.sh",
    "abi2_platform_candidate_verifier_tests_sha256": "artifact/test_platform_candidate_verifier.py",
    "platform_candidate_attestation_sha256": "artifact/platform_candidate_attestation.py",
    "platform_candidate_attestation_tests_sha256": "artifact/test_platform_candidate_attestation.py",
    "abi2_platform_release_notes_sha256": "artifact/abi2-platform-release-notes.md",
    "stable_release_notes_sha256": "artifact/stable-release-notes.md",
    "evidence_io_sha256": "artifact/evidence_io.py",
    "evidence_io_tests_sha256": "artifact/test_evidence_io.py",
    "workflow_artifact_extractor_sha256": "artifact/workflow_artifact.py",
    "workflow_artifact_tests_sha256": "artifact/test_workflow_artifact.py",
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
    "migration_contract_v2_spec_sha256": "docs/migration/MIGRATION_CONTRACT_V2.md",
    "migration_model_manifest_sha256": "models/q-periapt-migration/Cargo.toml",
    "migration_model_readme_sha256": "models/q-periapt-migration/README.md",
    "migration_model_lib_sha256": "models/q-periapt-migration/src/lib.rs",
    "migration_model_codec_sha256": "models/q-periapt-migration/src/codec.rs",
    "migration_context_v2_model_sha256": "models/q-periapt-migration/src/context_v2.rs",
    "migration_state_model_sha256": "models/q-periapt-migration/src/state.rs",
    "migration_capability_model_sha256": "models/q-periapt-migration/src/capability.rs",
    "migration_transcript_model_sha256": "models/q-periapt-migration/src/transcript.rs",
    "migration_confirmation_model_sha256": "models/q-periapt-migration/src/confirmation.rs",
    "migration_contract_v2_tests_sha256": "models/q-periapt-migration/tests/contract_v2.rs",
    "migration_contract_v2_vectors_sha256": "models/q-periapt-migration/vectors/migration-contract-v2.json",
    "migration_contract_v2_verifier_sha256": "artifact/migration_contract_v2.py",
    "migration_contract_v2_verifier_tests_sha256": "artifact/test_migration_contract_v2.py",
    "migration_agent_manifest_sha256": "services/q-periapt-policy-agent/Cargo.toml",
    "migration_agent_readme_sha256": "services/q-periapt-policy-agent/README.md",
    "migration_agent_lib_sha256": "services/q-periapt-policy-agent/src/lib.rs",
    "migration_agent_main_sha256": "services/q-periapt-policy-agent/src/main.rs",
    "migration_agent_authentication_sha256": "services/q-periapt-policy-agent/src/authentication.rs",
    "migration_agent_authority_sha256": "services/q-periapt-policy-agent/src/authority.rs",
    "migration_agent_authority_codec_sha256": "services/q-periapt-policy-agent/src/authority_codec.rs",
    "migration_agent_authority_protocol_sha256": "services/q-periapt-policy-agent/src/authority_protocol.rs",
    "migration_agent_authority_store_sha256": "services/q-periapt-policy-agent/src/authority_store.rs",
    "migration_agent_authority_transport_sha256": "services/q-periapt-policy-agent/src/authority_transport.rs",
    "migration_agent_codec_sha256": "services/q-periapt-policy-agent/src/codec.rs",
    "migration_agent_crypto_sha256": "services/q-periapt-policy-agent/src/crypto.rs",
    "migration_agent_filesystem_sha256": "services/q-periapt-policy-agent/src/filesystem.rs",
    "migration_agent_macos_acl_sha256": "services/q-periapt-policy-agent/src/macos_acl.rs",
    "migration_agent_service_sha256": "services/q-periapt-policy-agent/src/service.rs",
    "migration_agent_repository_sha256": "services/q-periapt-policy-agent/src/repository.rs",
    "migration_agent_witness_sha256": "services/q-periapt-policy-agent/src/witness.rs",
    "migration_agent_ipc_sha256": "services/q-periapt-policy-agent/src/ipc.rs",
    "migration_agent_tests_sha256": "services/q-periapt-policy-agent/src/tests.rs",
    "migration_agent_types_sha256": "services/q-periapt-policy-agent/src/types.rs",
    "migration_agent_activation_sha256": "services/q-periapt-policy-agent/src/activation.rs",
    "migration_agent_activation_handoff_sha256": "services/q-periapt-policy-agent/src/activation_handoff.rs",
    "migration_agent_authority_store_tests_sha256": "services/q-periapt-policy-agent/src/authority_store/tests.rs",
    "migration_agent_signals_sha256": "services/q-periapt-policy-agent/src/signals.rs",
    "migration_agent_tests_durable_store_sha256": "services/q-periapt-policy-agent/src/tests/durable_store.rs",
    "migration_agent_tests_ipc_sha256": "services/q-periapt-policy-agent/src/tests/ipc.rs",
    "migration_agent_tests_lease_sha256": "services/q-periapt-policy-agent/src/tests/lease.rs",
    "migration_agent_tests_session_sha256": "services/q-periapt-policy-agent/src/tests/session.rs",
    "migration_agent_tests_transition_sha256": "services/q-periapt-policy-agent/src/tests/transition.rs",
    "migration_agent_tests_witness_protocol_sha256": "services/q-periapt-policy-agent/src/tests/witness_protocol.rs",
    "hqc_candidate_readme_sha256": "research/hqc-fips207-candidate/README.md",
    "hqc_candidate_manifest_sha256": "research/hqc-fips207-candidate/Cargo.toml",
    "hqc_candidate_lock_sha256": "research/hqc-fips207-candidate/Cargo.lock",
    "hqc_candidate_adapter_sha256": "research/hqc-fips207-candidate/src/lib.rs",
    "hqc_candidate_tests_sha256": "research/hqc-fips207-candidate/tests/adapter.rs",
    "hqc_candidate_verify_sha256": "research/hqc-fips207-candidate/scripts/verify.sh",
    "rust_publish_contract_script_sha256": "artifact/rust-publish-contract.sh",
    "rust_publish_contract_sha256": "artifact/rust_publish_contract.py",
    "rust_publish_contract_tests_sha256": "artifact/test_rust_publish_contract.py",
    "rust_package_handoff_sha256": "artifact/rust_package_handoff.py",
    "rust_package_handoff_tests_sha256": "artifact/test_rust_package_handoff.py",
    "crates_io_publication_contract_sha256": "artifact/crates_io_publication_contract.py",
    "crates_io_publication_contract_tests_sha256": "artifact/test_crates_io_publication_contract.py",
    "crates_io_publication_sha256": "artifact/crates_io_publication.py",
    "crates_io_publication_tests_sha256": "artifact/test_crates_io_publication.py",
    "c_package_script_sha256": "artifact/c-package.sh",
    "c_package_manifest_verifier_sha256": "artifact/c_package_manifest.py",
    "c_package_manifest_tests_sha256": "artifact/test_c_package_manifest.py",
    "deterministic_archive_sha256": "artifact/deterministic_archive.py",
    "deterministic_archive_tests_sha256": "artifact/test_deterministic_archive.py",
    "package_bom_sha256": "artifact/package_bom.py",
    "release_binary_scan_sha256": "artifact/release_binary_scan.py",
    "release_binary_scan_tests_sha256": "artifact/test_release_binary_scan.py",
    "security_policy_sha256": "SECURITY.md",
    "third_party_licenses_sha256": "artifact/third_party_licenses.py",
    "third_party_licenses_tests_sha256": "artifact/test_third_party_licenses.py",
    "windows_msvc_version_probe_sha256": "artifact/msvc-version-probe.c",
    "windows_package_script_sha256": "artifact/windows-package.ps1",
    "windows_package_verifier_sha256": "artifact/windows_package.py",
    "windows_package_tests_sha256": "artifact/test_windows_package.py",
    "windows_toolchain_tests_sha256": "artifact/windows-toolchain-tests.ps1",
    "platform_distribution_verifier_sha256": "artifact/platform_distribution.py",
    "platform_distribution_contract_sha256": "artifact/platform_distribution_contract.py",
    "platform_distribution_tests_sha256": "artifact/test_platform_distribution.py",
    "platform_release_contract_sha256": "artifact/platform_release_contract.py",
    "platform_release_contract_tests_sha256": "artifact/test_platform_release_contract.py",
    "platform_stable_publication_contract_sha256": "artifact/platform_stable_publication_contract.py",
    "platform_stable_publication_contract_tests_sha256": "artifact/test_platform_stable_publication_contract.py",
    "platform_stable_publication_sha256": "artifact/platform_stable_publication.py",
    "platform_stable_publication_tests_sha256": "artifact/test_platform_stable_publication.py",
    "platform_publication_contract_sha256": "artifact/platform_publication_contract.py",
    "platform_publication_contract_tests_sha256": "artifact/test_platform_publication_contract.py",
    "release_publication_contract_sha256": "artifact/release_publication_contract.py",
    "release_publication_contract_tests_sha256": "artifact/test_release_publication_contract.py",
    "release_receipt_finalizer_sha256": "artifact/release_receipt_finalizer.py",
    "release_receipt_finalizer_tests_sha256": "artifact/test_release_receipt_finalizer.py",
    "publication_receipt_io_sha256": "artifact/publication_receipt_io.py",
    "publication_receipt_io_tests_sha256": "artifact/test_publication_receipt_io.py",
    "github_release_observation_sha256": "artifact/github_release_observation.py",
    "github_release_observation_tests_sha256": "artifact/test_github_release_observation.py",
    "stable_github_publication_sha256": "artifact/stable_github_publication.py",
    "stable_github_publication_tests_sha256": "artifact/test_stable_github_publication.py",
    "swift_xcframework_script_sha256": "artifact/swift-xcframework.sh",
    "swift_xcframework_release_script_sha256": "artifact/swift-xcframework-release.sh",
    "swift_xcframework_consumer_check_script_sha256": "artifact/swift-xcframework-consumer-check.sh",
    "swift_xcframework_remote_consumer_script_sha256": "artifact/swift-xcframework-remote-consumer.sh",
    "apple_distribution_verifier_sha256": "artifact/apple_distribution.py",
    "apple_distribution_tests_sha256": "artifact/test_apple_distribution.py",
    "apple_release_verification_sha256": "artifact/apple_release_verification.py",
    "apple_release_verification_tests_sha256": "artifact/test_apple_release_verification.py",
    "apple_publication_contract_sha256": "artifact/apple_publication_contract.py",
    "apple_publication_contract_tests_sha256": "artifact/test_apple_publication_contract.py",
    "apple_stable_publication_sha256": "artifact/apple_stable_publication.py",
    "apple_stable_publication_tests_sha256": "artifact/test_apple_stable_publication.py",
    "apple_publication_finalizer_tests_sha256": "artifact/test_apple_publication_finalizer.py",
    "release_publication_proof_manifest_tests_sha256": "artifact/test_release_publication_proof_manifest.py",
    "swift_binary_consumer_link_probe_sha256": "bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift",
    "swift_binary_consumer_tests_sha256": "bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift",
    "local_release_index_script_sha256": "artifact/local-release-index.sh",
    "release_index_verifier_sha256": "artifact/release_index.py",
    "release_index_tests_sha256": "artifact/test_release_index.py",
    "local_release_consumer_smoke_script_sha256": "artifact/local-release-consumer-smoke.sh",
    "release_consumer_smoke_verifier_sha256": "artifact/release_consumer_smoke.py",
    "release_consumer_smoke_tests_sha256": "artifact/test_release_consumer_smoke.py",
    "bounded_process_sha256": "artifact/bounded_process.py",
    "bounded_process_tests_sha256": "artifact/test_bounded_process.py",
    "process_identity_sha256": "artifact/process_identity.py",
    "android_emulator_control_sha256": "artifact/android_emulator_control.py",
    "android_runtime_state_sha256": "artifact/android_runtime_state.py",
    "android_runtime_state_tests_sha256": "artifact/test_android_runtime_state.py",
    "android_bounded_command_sha256": "artifact/android_bounded_command.py",
    "android_bounded_command_tests_sha256": "artifact/test_android_bounded_command.py",
    "apple_device_smoke_script_sha256": "artifact/apple-device-smoke.sh",
    "apple_device_matrix_script_sha256": "artifact/apple-device-matrix.sh",
    "apple_device_xcode27_gate_script_sha256": "artifact/apple-device-xcode27-gate.sh",
    "apple_device_proof_verifier_sha256": "artifact/apple_device_proof.py",
    "apple_device_proof_tests_sha256": "artifact/test_apple_device_proof.py",
    "apple_proof_contract_sha256": "artifact/apple_proof_contract.py",
    "apple_toolchain_verifier_sha256": "artifact/apple_toolchain.py",
    "apple_toolchain_tests_sha256": "artifact/test_apple_toolchain.py",
    "android_aar_script_sha256": "artifact/android-aar.sh",
    "android_device_smoke_script_sha256": "artifact/android-device-smoke.sh",
    "android_device_proof_verifier_sha256": "artifact/android_device_proof.py",
    "android_device_proof_tests_sha256": "artifact/test_android_device_proof.py",
    "android_elf_verifier_sha256": "artifact/android_elf.py",
    "android_elf_tests_sha256": "artifact/test_android_elf.py",
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

    "proof_to_byte_inputs_sha256": "artifact/proof_to_byte_inputs.py",
    "proof_to_byte_inputs_tests_sha256": "artifact/test_proof_to_byte_inputs.py",
    "source_results_assembler_sha256": "artifact/source_results_assembler.py",
    "source_results_assembler_tests_sha256": "artifact/test_source_results_assembler.py",
})


def canonical_input_map() -> dict[str, str]:
    """Return a mutable copy of the exact proof-input key/path contract."""

    return dict(PROOF_TO_BYTE_INPUT_PATHS)


def _root_path(root: pathlib.Path) -> pathlib.Path:
    try:
        spelled = pathlib.Path(os.path.abspath(os.fspath(root)))
        resolved = pathlib.Path(root).resolve(strict=True)
        metadata = resolved.lstat()
    except (OSError, TypeError, ValueError) as exc:
        raise ProofToByteInputsError("cannot resolve repository root") from exc
    if (
        spelled != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and metadata.st_uid != os.geteuid())
    ):
        raise ProofToByteInputsError(
            "repository root must be one canonical owned directory"
        )
    return resolved


def _path_parts(relative: str) -> tuple[str, ...]:
    pure = pathlib.PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or pure.as_posix() != relative
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise ProofToByteInputsError(
            f"proof-input path is not canonical: {relative!r}"
        )
    return pure.parts


def _input_path(root: pathlib.Path, relative: str) -> pathlib.Path:
    return root.joinpath(*_path_parts(relative))


def _validate_input_metadata(
    metadata: os.stat_result,
    *,
    relative: str,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (
            os.name == "posix"
            and (
                metadata.st_mode & 0o022
                or metadata.st_uid != os.geteuid()
            )
        )
    ):
        raise EvidenceIOError(f"proof input metadata is unsafe: {relative}")


def _capture_once(root: pathlib.Path) -> tuple[dict[str, str], int]:
    captured: dict[str, str] = {}
    total_bytes = 0
    relative_paths: set[str] = set()
    for key, relative in PROOF_TO_BYTE_INPUT_PATHS.items():
        if (
            not isinstance(key, str)
            or not key.endswith("_sha256")
            or not isinstance(relative, str)
        ):
            raise ProofToByteInputsError(
                f"proof-input key is not canonical: {key!r}"
            )
        _path_parts(relative)
        if relative in relative_paths:
            raise ProofToByteInputsError(
                f"proof-input path is duplicated: {relative}"
            )
        relative_paths.add(relative)
        try:
            snapshot = read_regular_snapshot(
                _input_path(root, relative),
                maximum=MAX_PROOF_INPUT_BYTES,
                label=f"proof input {relative}",
                validate_metadata=lambda metadata, relative=relative: (
                    _validate_input_metadata(metadata, relative=relative)
                ),
            )
        except EvidenceIOError as exc:
            raise ProofToByteInputsError(str(exc)) from exc
        total_bytes += snapshot.size
        if total_bytes > MAX_PROOF_INPUT_TOTAL_BYTES:
            raise ProofToByteInputsError(
                "proof-input map exceeds the aggregate byte limit"
            )
        captured[key] = snapshot.sha256
    return captured, total_bytes


def capture_proof_input_digests(root: pathlib.Path) -> dict[str, str]:
    """Cross-platform stable digest capture for read-only proof verification."""

    canonical_root = _root_path(root)
    before, before_bytes = _capture_once(canonical_root)
    after, after_bytes = _capture_once(canonical_root)
    if before != after or before_bytes != after_bytes:
        changed = sorted(
            key for key in set(before) | set(after) if before.get(key) != after.get(key)
        )
        raise ProofToByteInputsError(
            "proof inputs changed while they were captured: " + ", ".join(changed[:8])
        )
    return after


def verify_proof_input_digests(
    root: pathlib.Path,
    expected: Mapping[str, object],
) -> dict[str, str]:
    """Require an exact declared map and verify it against stable source bytes."""

    if not isinstance(expected, Mapping) or any(
        not isinstance(key, str) for key in expected
    ):
        raise ProofToByteInputsError(
            "proof_to_byte_inputs must be an object with string keys"
        )
    required = set(PROOF_TO_BYTE_INPUT_PATHS)
    actual_keys = set(expected)
    if actual_keys != required:
        raise ProofToByteInputsError(
            "proof_to_byte_inputs key-set mismatch: "
            f"missing={sorted(required - actual_keys)}, "
            f"extra={sorted(actual_keys - required)}"
        )
    for key, value in expected.items():
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ProofToByteInputsError(
                f"proof_to_byte_inputs digest is malformed: {key}"
            )
    captured = capture_proof_input_digests(root)
    mismatched = sorted(
        key for key in required if expected[key] != captured[key]
    )
    if mismatched:
        key = mismatched[0]
        relative = PROOF_TO_BYTE_INPUT_PATHS[key]
        raise ProofToByteInputsError(
            f"hash mismatch for {relative}: got {captured[key]}, expected {expected[key]}"
        )
    return captured
