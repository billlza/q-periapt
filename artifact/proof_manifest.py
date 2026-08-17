#!/usr/bin/env python3
"""Strict results-manifest loading and atomic selected-proof binding."""

from __future__ import annotations

import datetime as dt
import os
import pathlib
import re
from dataclasses import dataclass
from types import MappingProxyType

from apple_proof_contract import (
    APPLE_DEVICE_PROOF_SCHEMA_VERSION,
    APPLE_MATRIX_PROOF_SCHEMA_VERSION,
)
import rust_package_handoff
from evidence_io import (
    EvidenceIOError,
    JsonObjectSnapshot,
    load_json_object_snapshot,
)
from platform_distribution_contract import (
    ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
)
from release_publication_contract import (
    ReleasePublicationContractError,
    validate_release_publications,
)
from git_provenance import (
    GitProvenanceError,
    require_commit_or_evidence_successor,
    run_git_text,
)
from rust_publish_contract import (
    RUST_CRATES_IO_SPARSE_INDEX,
    RUST_SPARSE_MAX_REGISTRY_PACKAGES,
    RustPackageContractReceipt,
)


MAX_RESULTS_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SELECTED_PROOF_BYTES = 16 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
ANDROID_BUILD_TOOLS_RE = re.compile(
    r"^[1-9][0-9]*\.[0-9]+\.[0-9]+(?:-rc[1-9][0-9]*)?$"
)
_CANONICAL_PATH_ASCII = MappingProxyType(
    {
        character: character
        for character in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._+/-"
    }
)
PERFORMANCE_SOURCE_STATUSES = {
    "current_controlled_pass",
    "stale_requires_rerun",
}
PERFORMANCE_PROOF_SCHEMA_VERSION = 8
APPLE_SOURCE_STATUSES = {
    "current_clean_tree_physical_pass",
    "current_dirty_diagnostic_pass",
    "stale_requires_rerun",
}
ANDROID_SOURCE_STATUSES = {
    "current_clean_tree_emulator_pass",
    "stale_requires_rerun",
}
ANDROID_PHYSICAL_SOURCE_STATUSES = {
    "current_clean_tree_physical_pass",
    "stale_requires_rerun",
}
ANDROID_AAR_SOURCE_STATUSES = {
    "current_clean_tree_package_pass",
    "stale_requires_rerun",
}
LOCAL_RELEASE_INDEX_SOURCE_STATUSES = {
    "current_clean_tree_local_index_consumer_pass",
    "stale_requires_rerun",
}
RUST_PACKAGE_SOURCE_STATUSES = {
    "current_clean_tree_rust_package_contract_pass",
    "stale_requires_rerun",
}
RUST_PACKAGE_COMMAND = "sh artifact/rust-publish-contract.sh"
RUST_PACKAGE_DIRTY_COMMAND = (
    "QPERIAPT_ALLOW_DIRTY_RUST_PACKAGE_CONTRACT=1 "
    "sh artifact/rust-publish-contract.sh"
)
RUST_PACKAGE_MODE = (
    "registry-bound cargo package, exact sparse-lock verification, and "
    "normalized-graph advisory audit no-upload contract"
)
RUST_PACKAGE_ADVISORY_DB_MODE = "fresh_owned_cargo_home_fetch"
RUST_PACKAGE_ADVISORY_DB_URL = "https://github.com/RustSec/advisory-db.git"
RUST_PACKAGE_CRATES_IO_INDEX_PROTOCOL = "sparse-https"
RUST_PACKAGE_BOUNDARY = (
    "Current clean-tree source-bound Rust registry-targeted package and normalized "
    "dependency-graph audit receipt. It proves warning-free cargo package "
    "construction and rebuilt-archive verification for the exact ten classified "
    "crates, plus exact locked name, version, checksum, and non-yanked verification "
    "against the official crates.io sparse HTTPS index, with no upload attempted. "
    "A manifest-last private handoff binds the retained transcript and exact ten "
    ".crate archive bytes consumed by the registry transaction. "
    "It does not prove upload API acceptance, "
    "crate-name ownership, publishing credentials or authorization, server-side "
    "registry policy, or a registry receipt. The selected transcript hash detects "
    "an accidentally mismatched retained local transcript; it is not independent "
    "hostile-builder attestation."
)
RUST_PACKAGE_CURRENT_SECTION_FIELDS = frozenset(
    {
        "advisory_db_clean",
        "advisory_db_commit",
        "advisory_db_mode",
        "advisory_db_url",
        "boundary",
        "cargo_audit_version",
        "cargo_home_isolated",
        "cargo_version",
        "cargo_warning_free",
        "command",
        "completed_at",
        "crates_io_index_protocol",
        "crates_io_index_url",
        "crates_io_registry_package_count",
        "crates_io_sparse_lock_verification_pass",
        "current_local_status",
        "current_source_status",
        "dirty_diagnostic_command",
        "evidence_schema",
        "handoff_manifest_path",
        "handoff_manifest_sha256",
        "mode",
        "nonpublishable_crates",
        "normalized_cargo_lock_sha256",
        "normalized_dependency_audit_pass",
        "package_list_pass_crates",
        "package_verification_pass_crates",
        "proof_source_tree_sha256",
        "publishable_crates",
        "registry",
        "rustc_version",
        "source_commit",
        "source_tree_dirty",
        "status",
        "transcript_path",
        "transcript_sha256",
        "upload_attempted",
    }
)
RUST_PACKAGE_PUBLISHABLE_CRATES = (
    "q-periapt-mlkem-native-sys",
    "q-periapt-core",
    "q-periapt-kem",
    "q-periapt-sig",
    "q-periapt-backends",
    "q-periapt-policy",
    "q-periapt-ffi",
    "q-periapt-wasm",
    "q-periapt-rustls",
    "q-periapt-cli",
)
RUST_PACKAGE_NONPUBLISHABLE_CRATES = (
    "q-periapt-tls-demo",
    "q-periapt-ctstats",
    "q-periapt-continuity-model",
    "q-periapt-migration",
    "q-periapt-policy-agent",
)
ANDROID_ABIS = ("arm64-v8a", "x86_64", "armeabi-v7a", "x86")
ANDROID_EXPECTED_TESTS = (
    "runtimeMetadataMatches",
    "signedPolicyDecisionIsExactAndFailClosed",
    "osRandomPolicyRoundtripAndWipes",
)
ANDROID_RELEASE_ABI = "arm64-v8a"
ANDROID_RELEASE_PAGE_SIZE = 16_384
ANDROID_RELEASE_SDK = 35
ANDROID_RELEASE_BUILD_TOOLS = "36.0.0"
ANDROID_AAR_PATH = (
    "target/qperiapt-android-aar/q-periapt-android-0.1.0/"
    "q-periapt-android-0.1.0.aar"
)
ANDROID_AAR_MANIFEST_PATH = (
    "target/qperiapt-android-aar/q-periapt-android-0.1.0/MANIFEST.json"
)
LOCAL_RELEASE_INDEX_SCHEMA_VERSION = 5
LOCAL_RELEASE_CONSUMER_RECEIPT_SCHEMA_VERSION = 1


class ProofManifestError(ValueError):
    """A results manifest or selected-proof binding is invalid."""


@dataclass(frozen=True, slots=True)
class BindingSpec:
    section: str
    path_key: str
    hash_key: str
    status_key: str
    admitted_current_statuses: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FileBindingDeclaration:
    """One canonical manifest-selected local file and its expected digest."""

    path: pathlib.Path
    sha256: str


@dataclass(frozen=True, slots=True)
class AndroidRuntimeBindingSpec:
    """One non-interchangeable results section and its admitted runtime kind."""

    binding: str
    section: str
    current_status: str
    device_kind: str
    canonical_release: bool


ANDROID_RUNTIME_BINDING_SPECS = MappingProxyType(
    {
        "android_runtime": AndroidRuntimeBindingSpec(
            binding="android_runtime",
            section="android_device_runtime",
            current_status="current_clean_tree_emulator_pass",
            device_kind="emulator",
            canonical_release=True,
        ),
        "android_physical_runtime": AndroidRuntimeBindingSpec(
            binding="android_physical_runtime",
            section="android_physical_runtime",
            current_status="current_clean_tree_physical_pass",
            device_kind="physical",
            canonical_release=False,
        ),
    }
)
ANDROID_RUNTIME_BINDING_CHOICES = tuple(ANDROID_RUNTIME_BINDING_SPECS)


BINDINGS = {
    "apple_device": BindingSpec(
        section="apple_device",
        path_key="current_proof_path",
        hash_key="current_proof_sha256",
        status_key="current_source_status",
        admitted_current_statuses=(
            "current_clean_tree_physical_pass",
            "current_dirty_diagnostic_pass",
        ),
    ),
    "apple_matrix": BindingSpec(
        section="apple_device",
        path_key="matrix_proof_path",
        hash_key="matrix_proof_sha256",
        status_key="matrix_source_status",
        admitted_current_statuses=(
            "current_clean_tree_physical_pass",
            "current_dirty_diagnostic_pass",
        ),
    ),
    "android_runtime": BindingSpec(
        section="android_device_runtime",
        path_key="proof_path",
        hash_key="proof_sha256",
        status_key="current_source_status",
        admitted_current_statuses=("current_clean_tree_emulator_pass",),
    ),
    "android_physical_runtime": BindingSpec(
        section="android_physical_runtime",
        path_key="proof_path",
        hash_key="proof_sha256",
        status_key="current_source_status",
        admitted_current_statuses=("current_clean_tree_physical_pass",),
    ),
    "performance": BindingSpec(
        section="performance",
        path_key="proof_path",
        hash_key="proof_sha256",
        status_key="current_source_status",
        admitted_current_statuses=("current_controlled_pass",),
    ),
    "android_aar": BindingSpec(
        section="android_aar",
        path_key="aar_path",
        hash_key="aar_sha256",
        status_key="current_source_status",
        admitted_current_statuses=("current_clean_tree_package_pass",),
    ),
    "android_aar_manifest": BindingSpec(
        section="android_aar",
        path_key="manifest_path",
        hash_key="manifest_sha256",
        status_key="current_source_status",
        admitted_current_statuses=("current_clean_tree_package_pass",),
    ),
    "local_release_index": BindingSpec(
        section="local_release_index",
        path_key="index_path",
        hash_key="index_sha256",
        status_key="current_source_status",
        admitted_current_statuses=(
            "current_clean_tree_local_index_consumer_pass",
        ),
    ),
    "local_release_consumer": BindingSpec(
        section="local_release_index",
        path_key="consumer_receipt_path",
        hash_key="consumer_receipt_sha256",
        status_key="current_source_status",
        admitted_current_statuses=(
            "current_clean_tree_local_index_consumer_pass",
        ),
    ),
    "rust_package_transcript": BindingSpec(
        section="rust_publish",
        path_key="transcript_path",
        hash_key="transcript_sha256",
        status_key="current_source_status",
        admitted_current_statuses=(
            "current_clean_tree_rust_package_contract_pass",
        ),
    ),
    "rust_package_handoff_manifest": BindingSpec(
        section="rust_publish",
        path_key="handoff_manifest_path",
        hash_key="handoff_manifest_sha256",
        status_key="current_source_status",
        admitted_current_statuses=(
            "current_clean_tree_rust_package_contract_pass",
        ),
    ),
}


def select_android_runtime_results_binding(
    binding: str,
) -> AndroidRuntimeBindingSpec:
    """Select one fixed Android runtime binding without cross-section fallback."""

    selection = ANDROID_RUNTIME_BINDING_SPECS.get(binding)
    if selection is None:
        raise ProofManifestError(f"unknown Android runtime results binding: {binding!r}")
    return selection


def _validate_binding_declaration(section: dict[str, object], binding: str) -> None:
    spec = BINDINGS[binding]
    relative = section.get(spec.path_key)
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ProofManifestError(
            f"current {binding} status requires a canonical selected-proof path"
        )
    pure = pathlib.PurePosixPath(relative)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or not pure.parts
        or pure.as_posix() != relative
        or any(part in ("", ".") for part in pure.parts)
    ):
        raise ProofManifestError(
            f"current {binding} status requires a canonical selected-proof path"
        )
    digest = section.get(spec.hash_key)
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise ProofManifestError(
            f"current {binding} status requires a selected-proof SHA-256"
        )


def _validate_optional_status(
    section: dict[str, object],
    key: str,
    allowed: set[str],
) -> None:
    value = section.get(key)
    if value is not None and value not in allowed:
        raise ProofManifestError(
            f"results manifest {key} has unknown status: {value!r}"
        )


def _require_manifest_source_commit(manifest: dict[str, object]) -> str:
    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict):
        raise ProofManifestError("current source status requires provenance metadata")
    source_commit = provenance.get("snapshot_commit")
    if not isinstance(source_commit, str) or COMMIT_RE.fullmatch(source_commit) is None:
        raise ProofManifestError(
            "current source status requires a canonical provenance snapshot commit"
        )
    return source_commit


def _require_current_source_identity(
    section: dict[str, object],
    *,
    root_digest: object,
    source_commit: str,
    label: str,
) -> None:
    if root_digest is None or section.get("proof_source_tree_sha256") != root_digest:
        raise ProofManifestError(
            f"current {label} status does not match the manifest source digest"
        )
    if section.get("source_commit") != source_commit:
        raise ProofManifestError(
            f"current {label} status does not match the manifest source commit"
        )
    if section.get("source_tree_dirty") is not False:
        raise ProofManifestError(
            f"current {label} status requires clean source provenance"
        )


def _require_nonempty_string(value: object, message: str) -> None:
    if not isinstance(value, str) or not value:
        raise ProofManifestError(message)


def rust_package_current_local_status(
    *,
    source_commit: str,
    source_digest: str,
    completed_at: str,
    advisory_commit: str,
    registry_package_count: int,
    normalized_lock_sha256: str,
) -> str:
    """Return the single current-status sentence for a selected Rust handoff."""

    return (
        "Current clean-tree Rust no-upload package contract passed at source commit "
        f"{source_commit} and canonical source digest {source_digest}, completed at "
        f"{completed_at}, using RustSec advisory database commit {advisory_commit} "
        "fetched into a fresh owned Cargo home. Exact sparse-index lock verification "
        f"passed for {registry_package_count} crates.io package records from normalized "
        f"Cargo.lock SHA-256 {normalized_lock_sha256}. The retained manifest-last "
        "handoff, transcript, and exact ten rebuilt .crate archives are selected by "
        "canonical paths and SHA-256 for accidental mismatch detection; they are "
        "not an independent attestation."
    )


def _validate_current_android_aar(
    manifest: dict[str, object],
    section: dict[str, object],
    *,
    root_digest: object,
    source_commit: str,
) -> None:
    _require_current_source_identity(
        section,
        root_digest=root_digest,
        source_commit=source_commit,
        label="Android AAR",
    )
    for binding in ("android_aar", "android_aar_manifest"):
        _validate_binding_declaration(section, binding)
    if section.get("aar_path") != ANDROID_AAR_PATH:
        raise ProofManifestError("current Android AAR path is not canonical")
    if section.get("manifest_path") != ANDROID_AAR_MANIFEST_PATH:
        raise ProofManifestError("current Android AAR manifest path is not canonical")
    if type(section.get("manifest_schema")) is not int or section.get(
        "manifest_schema"
    ) != 4:
        raise ProofManifestError("current Android AAR status requires manifest schema 4")
    if section.get("status") != "pass":
        raise ProofManifestError("current Android AAR status requires a passing package")
    if section.get("targets") != list(ANDROID_ABIS):
        raise ProofManifestError("current Android AAR status requires the exact four ABI targets")
    _require_nonempty_string(
        section.get("manifest_generated_at"),
        "current Android AAR status requires manifest generation time",
    )


def _validate_current_rust_package_contract(
    manifest: dict[str, object],
    section: dict[str, object],
    *,
    root_digest: object,
    source_commit: str,
) -> None:
    expected_fields = RUST_PACKAGE_CURRENT_SECTION_FIELDS
    if set(section) != expected_fields:
        raise ProofManifestError(
            "current Rust package contract field set differs: "
            f"missing={sorted(expected_fields - set(section))}, "
            f"extra={sorted(set(section) - expected_fields)}"
        )
    _require_current_source_identity(
        section,
        root_digest=root_digest,
        source_commit=source_commit,
        label="Rust package contract",
    )
    exact_fields: tuple[tuple[str, object], ...] = (
        ("evidence_schema", 2),
        ("status", "pass"),
        ("command", RUST_PACKAGE_COMMAND),
        ("dirty_diagnostic_command", RUST_PACKAGE_DIRTY_COMMAND),
        ("mode", RUST_PACKAGE_MODE),
        ("boundary", RUST_PACKAGE_BOUNDARY),
        ("registry", "crates-io"),
        ("upload_attempted", False),
        ("rustc_version", "1.96.1"),
        ("cargo_version", "1.96.1"),
        ("cargo_audit_version", "0.22.2"),
        ("crates_io_index_protocol", RUST_PACKAGE_CRATES_IO_INDEX_PROTOCOL),
        ("crates_io_index_url", RUST_CRATES_IO_SPARSE_INDEX),
        ("crates_io_sparse_lock_verification_pass", True),
        ("advisory_db_mode", RUST_PACKAGE_ADVISORY_DB_MODE),
        ("advisory_db_url", RUST_PACKAGE_ADVISORY_DB_URL),
        ("advisory_db_clean", True),
        ("cargo_home_isolated", True),
        ("cargo_warning_free", True),
        ("normalized_dependency_audit_pass", True),
        ("publishable_crates", list(RUST_PACKAGE_PUBLISHABLE_CRATES)),
        ("nonpublishable_crates", list(RUST_PACKAGE_NONPUBLISHABLE_CRATES)),
        ("package_list_pass_crates", list(RUST_PACKAGE_PUBLISHABLE_CRATES)),
        (
            "package_verification_pass_crates",
            list(RUST_PACKAGE_PUBLISHABLE_CRATES),
        ),
    )
    for field, expected in exact_fields:
        actual = section.get(field)
        if type(actual) is not type(expected) or actual != expected:
            raise ProofManifestError(
                f"current Rust package contract requires exact {field}"
            )
    advisory_commit = section.get("advisory_db_commit")
    if not isinstance(advisory_commit, str) or re.fullmatch(
        r"[0-9a-f]{40}", advisory_commit
    ) is None:
        raise ProofManifestError(
            "current Rust package contract requires an advisory DB commit"
        )
    registry_package_count = section.get("crates_io_registry_package_count")
    if (
        type(registry_package_count) is not int
        or registry_package_count < 1
        or registry_package_count > RUST_SPARSE_MAX_REGISTRY_PACKAGES
    ):
        raise ProofManifestError(
            "current Rust package contract requires a bounded crates.io registry "
            "package count"
        )
    normalized_lock_sha256 = section.get("normalized_cargo_lock_sha256")
    if not isinstance(normalized_lock_sha256, str) or SHA256_RE.fullmatch(
        normalized_lock_sha256
    ) is None:
        raise ProofManifestError(
            "current Rust package contract requires a normalized Cargo.lock SHA-256"
        )
    completed_at = section.get("completed_at")
    if not isinstance(completed_at, str):
        raise ProofManifestError(
            "current Rust package contract requires an RFC3339 UTC completion time"
        )
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", completed_at) is None:
        raise ProofManifestError(
            "current Rust package contract requires an RFC3339 UTC completion time"
        )
    try:
        parsed_completed_at = dt.datetime.strptime(completed_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ProofManifestError(
            "current Rust package contract requires an RFC3339 UTC completion time"
        ) from exc
    if parsed_completed_at.strftime("%Y-%m-%dT%H:%M:%SZ") != completed_at:
        raise ProofManifestError(
            "current Rust package contract requires an RFC3339 UTC completion time"
        )
    for binding in (
        "rust_package_handoff_manifest",
        "rust_package_transcript",
    ):
        _validate_binding_declaration(section, binding)
    manifest_path = pathlib.PurePosixPath(
        str(section.get("handoff_manifest_path"))
    )
    transcript_path = pathlib.PurePosixPath(str(section.get("transcript_path")))
    if not (
        len(manifest_path.parts) == 4
        and manifest_path.parts[:2]
        == ("target", "qperiapt-rust-package-handoffs")
        and rust_package_handoff.RUST_PACKAGE_HANDOFF_TRANSACTION_RE.fullmatch(
            manifest_path.parts[2]
        )
        is not None
        and manifest_path.name
        == rust_package_handoff.RUST_PACKAGE_HANDOFF_MANIFEST_NAME
    ):
        raise ProofManifestError(
            "current Rust package handoff manifest path is not canonical"
        )
    if not (
        transcript_path.parent == manifest_path.parent
        and transcript_path.name
        == rust_package_handoff.RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME
    ):
        raise ProofManifestError(
            "current Rust package contract transcript path is not canonical"
        )
    expected_status = rust_package_current_local_status(
        source_commit=source_commit,
        source_digest=str(root_digest),
        completed_at=completed_at,
        advisory_commit=advisory_commit,
        registry_package_count=registry_package_count,
        normalized_lock_sha256=normalized_lock_sha256,
    )
    if section.get("current_local_status") != expected_status:
        raise ProofManifestError(
            "current Rust package contract requires exact current_local_status"
        )


def _validate_current_android_runtime(
    manifest: dict[str, object],
    section: dict[str, object],
    *,
    selection: AndroidRuntimeBindingSpec,
    root_digest: object,
    source_commit: str,
) -> None:
    status = section.get("current_source_status")
    if status != selection.current_status:
        raise ProofManifestError(
            f"current {selection.section} status is not selectable for "
            f"{selection.binding}"
        )
    _require_current_source_identity(
        section,
        root_digest=root_digest,
        source_commit=source_commit,
        label=selection.section,
    )
    _validate_binding_declaration(section, selection.binding)
    if type(section.get("proof_schema")) is not int or section.get(
        "proof_schema"
    ) != ANDROID_DEVICE_PROOF_SCHEMA_VERSION:
        raise ProofManifestError(
            "current Android runtime status requires proof schema "
            f"{ANDROID_DEVICE_PROOF_SCHEMA_VERSION}"
        )
    if section.get("status") != "pass":
        raise ProofManifestError("current Android runtime status requires a passing proof")
    _require_nonempty_string(
        section.get("proof_generated_at"),
        "current Android runtime status requires proof generation time",
    )
    run_id = section.get("run_id")
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise ProofManifestError("current Android runtime status requires a canonical run id")
    expected_path = (
        f"target/qperiapt-android-device-smoke-runs/{run_id}/proof/"
        "qperiapt-android-device-proof.json"
    )
    if section.get("proof_path") != expected_path:
        raise ProofManifestError("current Android runtime proof path does not match its run id")
    if section.get("device_kind") != selection.device_kind:
        raise ProofManifestError(
            f"current {selection.section} status does not match its declared device kind"
        )
    device_abi = section.get("device_abi")
    if device_abi not in ANDROID_ABIS:
        raise ProofManifestError("current Android runtime device ABI is invalid")
    page_size = section.get("page_size")
    if type(page_size) is not int or page_size not in {4_096, 16_384}:
        raise ProofManifestError("current Android runtime page size is invalid")
    android_sdk = section.get("android_sdk")
    if type(android_sdk) is not int or not 1 <= android_sdk <= 999:
        raise ProofManifestError("current Android runtime SDK is invalid")
    if type(section.get("release_candidate_mode")) is not bool:
        raise ProofManifestError("current Android runtime release mode is invalid")
    build_tools = section.get("build_tools")
    if (
        not isinstance(build_tools, str)
        or ANDROID_BUILD_TOOLS_RE.fullmatch(build_tools) is None
    ):
        raise ProofManifestError("current Android runtime build-tools version is invalid")
    if section.get("covered_tests") != list(ANDROID_EXPECTED_TESTS):
        raise ProofManifestError(
            "current Android runtime status requires the exact runtime test set"
        )
    if selection.canonical_release and (
        device_abi != ANDROID_RELEASE_ABI
        or page_size != ANDROID_RELEASE_PAGE_SIZE
        or android_sdk != ANDROID_RELEASE_SDK
        or section.get("release_candidate_mode") is not True
        or build_tools != ANDROID_RELEASE_BUILD_TOOLS
    ):
        raise ProofManifestError(
            "current Android emulator status requires the canonical release runtime"
        )
    aar = manifest.get("android_aar")
    if (
        not isinstance(aar, dict)
        or aar.get("current_source_status") != "current_clean_tree_package_pass"
    ):
        raise ProofManifestError(
            "current Android runtime status requires a current Android AAR"
        )


def _validate_current_local_release_index(
    manifest: dict[str, object],
    section: dict[str, object],
    *,
    root_digest: object,
    source_commit: str,
) -> None:
    _require_current_source_identity(
        section,
        root_digest=root_digest,
        source_commit=source_commit,
        label="local release index",
    )
    for binding in ("local_release_index", "local_release_consumer"):
        _validate_binding_declaration(section, binding)
    if section.get("status") != "pass":
        raise ProofManifestError("current local release index status requires pass")
    if section.get("channel") != "release":
        raise ProofManifestError("current local release index must use the release channel")
    if type(section.get("index_schema")) is not int or section.get(
        "index_schema"
    ) != LOCAL_RELEASE_INDEX_SCHEMA_VERSION:
        raise ProofManifestError(
            "current local release index status requires index schema "
            f"{LOCAL_RELEASE_INDEX_SCHEMA_VERSION}"
        )
    expected_index_path = (
        "target/qperiapt-local-release/release/0.1.0/"
        f"{source_commit}/index.json"
    )
    if section.get("index_path") != expected_index_path:
        raise ProofManifestError("current local release index path is not canonical")
    _require_nonempty_string(
        section.get("generated_at"),
        "current local release index status requires generation time",
    )
    receipt_run_id = section.get("consumer_receipt_run_id")
    if not isinstance(receipt_run_id, str) or RUN_ID_RE.fullmatch(receipt_run_id) is None:
        raise ProofManifestError(
            "current local release consumer status requires a canonical receipt run id"
        )
    expected_receipt_path = (
        "target/qperiapt-release-consumer-smoke/receipts/"
        f"{receipt_run_id}/qperiapt-release-consumer-receipt.json"
    )
    if section.get("consumer_receipt_path") != expected_receipt_path:
        raise ProofManifestError("current local release consumer receipt path is not canonical")
    if type(section.get("consumer_receipt_schema")) is not int or section.get(
        "consumer_receipt_schema"
    ) != LOCAL_RELEASE_CONSUMER_RECEIPT_SCHEMA_VERSION:
        raise ProofManifestError(
            "current local release consumer status requires receipt schema "
            f"{LOCAL_RELEASE_CONSUMER_RECEIPT_SCHEMA_VERSION}"
        )
    if section.get("consumer_status") != "pass":
        raise ProofManifestError("current local release consumer status requires pass")
    _require_nonempty_string(
        section.get("consumer_receipt_generated_at"),
        "current local release consumer status requires generation time",
    )
    android = manifest.get("android_device_runtime")
    if (
        not isinstance(android, dict)
        or android.get("current_source_status")
        != "current_clean_tree_emulator_pass"
    ):
        raise ProofManifestError(
            "current local release index requires the canonical Android runtime"
        )
    if (
        section.get("android_runtime_run_id") != android.get("run_id")
        or section.get("android_runtime_proof_sha256")
        != android.get("proof_sha256")
    ):
        raise ProofManifestError(
            "current local release index Android runtime selection differs"
        )


def validate_declared_currentness(manifest: dict[str, object]) -> None:
    """Prevent prose/status fields from promoting stale selected evidence."""

    root_digest = manifest.get("proof_source_tree_sha256")
    if root_digest is not None and (
        not isinstance(root_digest, str) or SHA256_RE.fullmatch(root_digest) is None
    ):
        raise ProofManifestError("results manifest canonical source digest is malformed")

    android_aar = manifest.get("android_aar")
    if isinstance(android_aar, dict):
        _validate_optional_status(
            android_aar,
            "current_source_status",
            ANDROID_AAR_SOURCE_STATUSES,
        )
    if (
        isinstance(android_aar, dict)
        and android_aar.get("current_source_status")
        == "current_clean_tree_package_pass"
    ):
        _validate_current_android_aar(
            manifest,
            android_aar,
            root_digest=root_digest,
            source_commit=_require_manifest_source_commit(manifest),
        )

    rust_package = manifest.get("rust_publish")
    if rust_package is not None and not isinstance(rust_package, dict):
        raise ProofManifestError("results manifest rust_publish must be an object")
    if isinstance(rust_package, dict):
        _validate_optional_status(
            rust_package,
            "current_source_status",
            RUST_PACKAGE_SOURCE_STATUSES,
        )
    if (
        isinstance(rust_package, dict)
        and rust_package.get("current_source_status")
        == "current_clean_tree_rust_package_contract_pass"
    ):
        _validate_current_rust_package_contract(
            manifest,
            rust_package,
            root_digest=root_digest,
            source_commit=_require_manifest_source_commit(manifest),
        )

    performance = manifest.get("performance")
    if isinstance(performance, dict):
        _validate_optional_status(
            performance,
            "current_source_status",
            PERFORMANCE_SOURCE_STATUSES,
        )
    if isinstance(performance, dict) and performance.get("current_source_status") == "current_controlled_pass":
        _validate_binding_declaration(performance, "performance")
        if performance.get("proof_schema") != PERFORMANCE_PROOF_SCHEMA_VERSION:
            raise ProofManifestError(
                "current performance status requires proof schema "
                f"{PERFORMANCE_PROOF_SCHEMA_VERSION}"
            )
        if root_digest is None or performance.get("proof_source_tree_sha256") != root_digest:
            raise ProofManifestError("current performance status does not match the manifest source digest")
        if performance.get("status") != "pass":
            raise ProofManifestError("current performance status requires a passing proof")
        if not isinstance(performance.get("proof_generated_at"), str):
            raise ProofManifestError("current performance status requires proof generation time")

    apple = manifest.get("apple_device")
    if isinstance(apple, dict):
        _validate_optional_status(
            apple,
            "current_source_status",
            APPLE_SOURCE_STATUSES,
        )
        _validate_optional_status(
            apple,
            "matrix_source_status",
            APPLE_SOURCE_STATUSES,
        )
    if isinstance(apple, dict) and apple.get("current_source_status") in {
        "current_clean_tree_physical_pass",
        "current_dirty_diagnostic_pass",
    }:
        _validate_binding_declaration(apple, "apple_device")
        if apple.get("current_proof_schema") != APPLE_DEVICE_PROOF_SCHEMA_VERSION:
            raise ProofManifestError(
                "current Apple device status requires proof schema "
                f"{APPLE_DEVICE_PROOF_SCHEMA_VERSION}"
            )
        if root_digest is None or apple.get("proof_source_tree_sha256") != root_digest:
            raise ProofManifestError("current Apple device status does not match the manifest source digest")
        attempt = apple.get("current_attempt")
        if not isinstance(attempt, dict) or attempt.get("status") != "pass" or attempt.get("proof_emitted") is not True:
            raise ProofManifestError("current Apple device status requires a passing emitted-proof attempt")
        if not isinstance(apple.get("current_proof_generated_at"), str):
            raise ProofManifestError("current Apple device status requires proof generation time")
        expected_dirty = apple.get("current_source_status") == "current_dirty_diagnostic_pass"
        if apple.get("current_proof_source_tree_dirty") is not expected_dirty:
            raise ProofManifestError("current Apple device status has inconsistent source-tree cleanliness")

    if isinstance(apple, dict) and apple.get("matrix_source_status") in {
        "current_clean_tree_physical_pass",
        "current_dirty_diagnostic_pass",
    }:
        _validate_binding_declaration(apple, "apple_matrix")
        if apple.get("matrix_proof_schema") != APPLE_MATRIX_PROOF_SCHEMA_VERSION:
            raise ProofManifestError(
                "current Apple matrix requires proof schema "
                f"{APPLE_MATRIX_PROOF_SCHEMA_VERSION}"
            )
        if root_digest is None or apple.get("proof_source_tree_sha256") != root_digest:
            raise ProofManifestError("current Apple matrix does not match the manifest source digest")
        if apple.get("matrix_status") != "pass":
            raise ProofManifestError("current Apple matrix requires a passing proof")
        if not isinstance(apple.get("matrix_generated_at"), str):
            raise ProofManifestError("current Apple matrix requires proof generation time")
        expected_dirty = apple.get("matrix_source_status") == "current_dirty_diagnostic_pass"
        if apple.get("matrix_source_tree_dirty") is not expected_dirty:
            raise ProofManifestError("current Apple matrix has inconsistent source-tree cleanliness")

    android = manifest.get("android_device_runtime")
    if isinstance(android, dict):
        _validate_optional_status(
            android,
            "current_source_status",
            ANDROID_SOURCE_STATUSES,
        )
    if (
        isinstance(android, dict)
        and android.get("current_source_status")
        == "current_clean_tree_emulator_pass"
    ):
        _validate_current_android_runtime(
            manifest,
            android,
            selection=ANDROID_RUNTIME_BINDING_SPECS["android_runtime"],
            root_digest=root_digest,
            source_commit=_require_manifest_source_commit(manifest),
        )

    physical_android = manifest.get("android_physical_runtime")
    if isinstance(physical_android, dict):
        _validate_optional_status(
            physical_android,
            "current_source_status",
            ANDROID_PHYSICAL_SOURCE_STATUSES,
        )
    if (
        isinstance(physical_android, dict)
        and physical_android.get("current_source_status")
        == "current_clean_tree_physical_pass"
    ):
        _validate_current_android_runtime(
            manifest,
            physical_android,
            selection=ANDROID_RUNTIME_BINDING_SPECS["android_physical_runtime"],
            root_digest=root_digest,
            source_commit=_require_manifest_source_commit(manifest),
        )

    local_index = manifest.get("local_release_index")
    if isinstance(local_index, dict):
        _validate_optional_status(
            local_index,
            "current_source_status",
            LOCAL_RELEASE_INDEX_SOURCE_STATUSES,
        )
    if (
        isinstance(local_index, dict)
        and local_index.get("current_source_status")
        == "current_clean_tree_local_index_consumer_pass"
    ):
        _validate_current_local_release_index(
            manifest,
            local_index,
            root_digest=root_digest,
            source_commit=_require_manifest_source_commit(manifest),
        )

    try:
        validate_release_publications(manifest)
    except ReleasePublicationContractError as exc:
        raise ProofManifestError(str(exc)) from exc


def load_results_manifest_snapshot(
    path: pathlib.Path,
    *,
    expected_sha256: str | None = None,
) -> JsonObjectSnapshot:
    """Strict-load results.json and optionally pin it to a startup digest."""

    try:
        snapshot = load_json_object_snapshot(
            path,
            maximum=MAX_RESULTS_MANIFEST_BYTES,
            label="results manifest",
        )
    except EvidenceIOError as exc:
        raise ProofManifestError(str(exc)) from exc
    validate_declared_currentness(snapshot.value)
    if expected_sha256 is not None:
        if SHA256_RE.fullmatch(expected_sha256) is None:
            raise ProofManifestError("expected results manifest SHA-256 is malformed")
        if snapshot.file.sha256 != expected_sha256:
            raise ProofManifestError(
                "results manifest changed during proof-to-byte run: "
                f"got {snapshot.file.sha256}, expected {expected_sha256}"
            )
    return snapshot


def current_android_runtime_section(
    manifest: dict[str, object],
    *,
    binding: str = "android_runtime",
) -> dict[str, object]:
    """Return a validated current Android runtime declaration or fail stale."""

    selection = select_android_runtime_results_binding(binding)
    validate_declared_currentness(manifest)
    section = manifest.get(selection.section)
    if not isinstance(section, dict):
        raise ProofManifestError(f"results manifest lacks {selection.section}")
    if section.get("current_source_status") != selection.current_status:
        raise ProofManifestError(
            "manifest-bound Android verification requires a current "
            f"{selection.device_kind} runtime status in {selection.section}"
        )
    return section


def expected_android_runtime_device_kind(
    manifest: dict[str, object],
    *,
    binding: str = "android_runtime",
) -> str:
    """Derive the only admitted device kind from a validated current status."""

    selection = select_android_runtime_results_binding(binding)
    current_android_runtime_section(manifest, binding=binding)
    return selection.device_kind


def _safe_declared_path(root: pathlib.Path, relative: object) -> pathlib.Path:
    if not isinstance(relative, str) or not relative or len(relative) > 4096:
        raise ProofManifestError("results manifest proof path is missing")
    rebuilt: list[str] = []
    for character in relative:
        canonical = _CANONICAL_PATH_ASCII.get(character)
        if canonical is None:
            raise ProofManifestError(
                "results manifest proof path contains an unsupported character"
            )
        rebuilt.append(canonical)
    canonical_relative = "".join(rebuilt)
    pure = pathlib.PurePosixPath(canonical_relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ProofManifestError(
            f"unsafe results manifest proof path: {canonical_relative}"
        )
    if pure.as_posix() != canonical_relative or any(
        part in ("", ".") for part in pure.parts
    ):
        raise ProofManifestError(
            f"non-canonical results manifest proof path: {canonical_relative}"
        )
    declared = root.joinpath(*pure.parts)
    lexical = pathlib.Path(os.path.abspath(declared))
    root_lexical = pathlib.Path(os.path.abspath(root))
    try:
        lexical.relative_to(root_lexical)
    except ValueError as exc:
        raise ProofManifestError(
            f"results manifest proof path escapes repository: {canonical_relative}"
        ) from exc
    return lexical


def resolve_bound_file_declaration(
    root: pathlib.Path,
    manifest: JsonObjectSnapshot,
    *,
    binding: str,
) -> FileBindingDeclaration:
    """Resolve one validated manifest path/hash pair without reading the target."""

    spec = BINDINGS.get(binding)
    if spec is None:
        raise ProofManifestError(f"unknown proof binding: {binding}")
    section = manifest.value.get(spec.section)
    if not isinstance(section, dict):
        raise ProofManifestError(f"results manifest lacks section {spec.section}")
    status = section.get(spec.status_key)
    if status not in spec.admitted_current_statuses:
        admitted = ", ".join(spec.admitted_current_statuses)
        raise ProofManifestError(
            f"manifest-bound {binding} selection requires current status "
            f"{spec.section}.{spec.status_key} in {{{admitted}}}"
        )
    declared = _safe_declared_path(root, section.get(spec.path_key))
    expected_sha256 = section.get(spec.hash_key)
    if (
        not isinstance(expected_sha256, str)
        or SHA256_RE.fullmatch(expected_sha256) is None
    ):
        raise ProofManifestError(
            f"results manifest has invalid {spec.section}.{spec.hash_key}"
        )
    return FileBindingDeclaration(path=declared, sha256=expected_sha256)


def load_bound_json_snapshot(
    root: pathlib.Path,
    manifest: JsonObjectSnapshot,
    *,
    binding: str,
    maximum: int = MAX_SELECTED_PROOF_BYTES,
    label: str,
) -> JsonObjectSnapshot:
    """Load the proof path and digest declared by one validated manifest binding."""

    declaration = resolve_bound_file_declaration(root, manifest, binding=binding)
    try:
        snapshot = load_json_object_snapshot(
            declaration.path,
            maximum=maximum,
            label=label,
        )
    except EvidenceIOError as exc:
        raise ProofManifestError(str(exc)) from exc
    if snapshot.file.sha256 != declaration.sha256:
        raise ProofManifestError(
            "selected proof hash differs from results manifest: "
            f"got={snapshot.file.sha256} expected={declaration.sha256}"
        )
    return snapshot


def load_current_rust_package_contract_receipt(
    root: pathlib.Path,
    manifest: JsonObjectSnapshot,
    *,
    frozen_commit: str,
    frozen_source_sha256: str,
) -> RustPackageContractReceipt:
    """Load and verify the exact current Rust package transcript and source binding."""

    if COMMIT_RE.fullmatch(frozen_commit) is None:
        raise ProofManifestError("frozen Rust package source commit is malformed")
    if SHA256_RE.fullmatch(frozen_source_sha256) is None:
        raise ProofManifestError("frozen Rust package source digest is malformed")
    section = manifest.value.get("rust_publish")
    if not isinstance(section, dict):
        raise ProofManifestError("results manifest lacks rust_publish")
    provenance = manifest.value.get("provenance")
    selected_source_commit = (
        provenance.get("snapshot_commit")
        if isinstance(provenance, dict)
        else None
    )
    if (
        not isinstance(selected_source_commit, str)
        or COMMIT_RE.fullmatch(selected_source_commit) is None
    ):
        raise ProofManifestError(
            "selected Rust package source commit is malformed"
        )
    handoff_declaration = resolve_bound_file_declaration(
        root,
        manifest,
        binding="rust_package_handoff_manifest",
    )
    transcript_declaration = resolve_bound_file_declaration(
        root,
        manifest,
        binding="rust_package_transcript",
    )
    try:
        source_tree = run_git_text(
            root,
            [
                "rev-parse",
                "--verify",
                f"{selected_source_commit}^{{tree}}",
            ],
        )
        handoff = rust_package_handoff.load_rust_package_handoff_snapshot(
            handoff_declaration.path,
            handoff_declaration.sha256,
            rust_package_handoff.RustPackageHandoffSource(
                source_commit=selected_source_commit,
                source_tree=source_tree,
                canonical_source_tree_sha256=frozen_source_sha256,
            ),
            handoff_root=(
                root / "target" / "qperiapt-rust-package-handoffs"
            ),
        )
    except (
        rust_package_handoff.RustPackageHandoffError,
        GitProvenanceError,
    ) as exc:
        raise ProofManifestError(str(exc)) from exc
    if not (
        handoff.transcript.path == transcript_declaration.path
        and handoff.transcript.sha256 == transcript_declaration.sha256
    ):
        raise ProofManifestError(
            "selected Rust package transcript differs from its handoff transaction"
        )
    receipt = handoff.package_contract
    if receipt.completed_at != section.get("completed_at"):
        raise ProofManifestError(
            "selected Rust package transcript completion time differs from results manifest"
        )
    if receipt.advisory_db_commit != section.get("advisory_db_commit"):
        raise ProofManifestError(
            "selected Rust package transcript advisory DB commit differs from results manifest"
        )
    if receipt.registry_package_count != section.get(
        "crates_io_registry_package_count"
    ):
        raise ProofManifestError(
            "selected Rust package transcript crates.io package count differs from "
            "results manifest"
        )
    if receipt.normalized_cargo_lock_sha256 != section.get(
        "normalized_cargo_lock_sha256"
    ):
        raise ProofManifestError(
            "selected Rust package transcript normalized Cargo.lock SHA-256 differs "
            "from results manifest"
        )
    if not (
        receipt.source_commit
        == section.get("source_commit")
        == selected_source_commit
    ):
        raise ProofManifestError(
            "selected Rust package transcript source commit differs from manifest provenance"
        )
    try:
        current_commit = require_commit_or_evidence_successor(
            root,
            receipt.source_commit,
        )
    except GitProvenanceError as exc:
        raise ProofManifestError(str(exc)) from exc
    if current_commit != frozen_commit:
        raise ProofManifestError(
            "selected Rust package receipt evidence successor differs from the frozen commit"
        )
    if section.get("proof_source_tree_sha256") != frozen_source_sha256:
        raise ProofManifestError(
            "selected Rust package receipt source digest differs from the frozen source"
        )
    return receipt


def select_bound_json_snapshot(
    root: pathlib.Path,
    manifest: JsonObjectSnapshot,
    *,
    binding: str,
    selected_path: pathlib.Path,
    maximum: int = MAX_SELECTED_PROOF_BYTES,
    label: str,
) -> JsonObjectSnapshot:
    """Hash-check and strict-parse one selected proof from the same bytes."""

    declaration = resolve_bound_file_declaration(root, manifest, binding=binding)
    declared = declaration.path

    if any(part in {"", ".", ".."} for part in selected_path.parts):
        raise ProofManifestError("selected proof path is not canonically spelled")
    selected = selected_path if selected_path.is_absolute() else root / selected_path
    selected_lexical = pathlib.Path(os.path.abspath(selected))
    if selected_path.is_absolute() and selected_path != selected_lexical:
        raise ProofManifestError("selected proof path is not canonically spelled")
    if selected_lexical != declared:
        raise ProofManifestError(
            "selected proof differs from results manifest: "
            f"selected={selected_lexical} declared={declared}"
        )
    return load_bound_json_snapshot(
        root,
        manifest,
        binding=binding,
        maximum=maximum,
        label=label,
    )
