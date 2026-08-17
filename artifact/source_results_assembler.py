#!/usr/bin/env python3
"""Assemble the initial source-bound 0.1.0 stable results-only successor.

This module consumes fixed local producer outputs plus short run selectors.  It
never edits ``artifact/results.json``.  A successful finalize operation emits a
private, no-replace ``target/source-results-successors/transaction.*/results.json``
candidate for an explicit results-only commit.

The finalize command is deliberately a one-time 190-to-237 proof-input
migration.  Once that successor is installed, this entrypoint must be retired
or replaced by an explicitly reviewed current-to-current state machine; it is
not a general-purpose release finalizer.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import hashlib
import os
import pathlib
import re
import stat
import sys
from collections.abc import Callable
from typing import Any, Never, TypeVar

import android_device_proof
import android_elf
import apple_device_proof
import apple_publication_contract
import performance_gate
import platform_publication_contract
import release_consumer_smoke
import release_index
import rust_package_handoff
import rust_publish_contract
from claim_ledger import LedgerError, canonical_tree_digest, repository_paths
from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    JsonObjectSnapshot,
    load_json_object_snapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from git_provenance import (
    GitProvenanceError,
    inspect_worktree,
    require_direct_results_only_successor,
    run_git_bytes,
    run_git_text,
)
from proof_manifest import (
    ANDROID_AAR_PATH,
    ANDROID_AAR_MANIFEST_PATH,
    ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
    ANDROID_EXPECTED_TESTS,
    APPLE_DEVICE_PROOF_SCHEMA_VERSION,
    APPLE_MATRIX_PROOF_SCHEMA_VERSION,
    LOCAL_RELEASE_CONSUMER_RECEIPT_SCHEMA_VERSION,
    LOCAL_RELEASE_INDEX_SCHEMA_VERSION,
    MAX_RESULTS_MANIFEST_BYTES,
    ProofManifestError,
    RUST_PACKAGE_ADVISORY_DB_MODE,
    RUST_PACKAGE_ADVISORY_DB_URL,
    RUST_PACKAGE_BOUNDARY,
    RUST_PACKAGE_COMMAND,
    RUST_PACKAGE_CURRENT_SECTION_FIELDS,
    RUST_PACKAGE_CRATES_IO_INDEX_PROTOCOL,
    RUST_PACKAGE_DIRTY_COMMAND,
    RUST_PACKAGE_MODE,
    RUST_PACKAGE_NONPUBLISHABLE_CRATES,
    RUST_PACKAGE_PUBLISHABLE_CRATES,
    RUST_CRATES_IO_SPARSE_INDEX,
    rust_package_current_local_status,
    validate_declared_currentness,
)
from proof_to_byte_finalizer import (
    FinalizerError,
    load_footprint_manifest_section,
)
from proof_to_byte_inputs import (
    PROOF_TO_BYTE_INPUT_PATHS,
    ProofToByteInputsError,
    capture_proof_input_digests,
    verify_proof_input_digests,
)
from publication_receipt_io import (
    PUBLIC_FILE_MODE,
    PublicationReceiptCommittedError,
    PublicationReceiptIOError,
    canonical_json_bytes,
    create_private_transaction_json,
)
from release_publication_contract import (
    ReleasePublicationContractError,
    neutral_swift_selector,
    validate_release_publication_transition,
    validate_release_publications,
    validate_stable_source_currentness,
)


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS_PATH = REPOSITORY_ROOT / "artifact" / "results.json"
RESULTS_OBJECT_PATH = "artifact/results.json"
SOURCE_RESULTS_ROOT = REPOSITORY_ROOT / "target" / "source-results-successors"
SOURCE_RESULTS_LEAF = "results.json"
ANDROID_AAR_FILE = REPOSITORY_ROOT / ANDROID_AAR_PATH
ANDROID_AAR_MANIFEST_FILE = REPOSITORY_ROOT / ANDROID_AAR_MANIFEST_PATH
ANDROID_RUNS_ROOT = (
    REPOSITORY_ROOT / "target" / android_device_proof.ANDROID_RUNS_ROOT_LEAF
)
APPLE_RUNS_ROOT = REPOSITORY_ROOT / "artifact" / "device-runs"
CONSUMER_RECEIPTS_ROOT = (
    REPOSITORY_ROOT / "target" / "qperiapt-release-consumer-smoke" / "receipts"
)
FOOTPRINT_PATH = REPOSITORY_ROOT / "paper" / "footprint.csv"

RESULTS_MAX_BYTES = 16 * 1024 * 1024
ANDROID_PROOF_MAX_BYTES = 4 * 1024 * 1024
PROOF_MAX_AGE_SECONDS = 24 * 60 * 60
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SAFE_SELECTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_MUTABLE_TOP_LEVEL = frozenset(
    {
        "android_aar",
        "android_device_runtime",
        "android_physical_runtime",
        "apple_device",
        "footprint_bytes",
        "local_release_index",
        "performance",
        "proof_source_tree_sha256",
        "proof_to_byte_inputs",
        "provenance",
        "rust_publish",
        "swift_xcframework",
    }
)

INITIAL_BASELINE_MISSING_PROOF_INPUT_KEYS = frozenset(
    {
        "stable_release_notes_sha256",
        "rust_package_handoff_sha256",
        "rust_package_handoff_tests_sha256",
        "apple_stable_publication_sha256",
        "apple_stable_publication_tests_sha256",
        "apple_publication_contract_sha256",
        "apple_publication_contract_tests_sha256",
        "apple_publication_finalizer_tests_sha256",
        "apple_release_verification_sha256",
        "apple_release_verification_tests_sha256",
        "github_release_observation_sha256",
        "github_release_observation_tests_sha256",
        "stable_github_publication_sha256",
        "stable_github_publication_tests_sha256",
        "platform_stable_publication_contract_sha256",
        "platform_stable_publication_contract_tests_sha256",
        "platform_stable_publication_sha256",
        "platform_stable_publication_tests_sha256",
        "crates_io_publication_contract_sha256",
        "crates_io_publication_contract_tests_sha256",
        "crates_io_publication_sha256",
        "crates_io_publication_tests_sha256",
        "platform_candidate_attestation_sha256",
        "platform_candidate_attestation_tests_sha256",
        "platform_distribution_contract_sha256",
        "platform_publication_contract_sha256",
        "platform_publication_contract_tests_sha256",
        "proof_to_byte_inputs_sha256",
        "proof_to_byte_inputs_tests_sha256",
        "publication_receipt_io_sha256",
        "publication_receipt_io_tests_sha256",
        "release_publication_contract_sha256",
        "release_publication_contract_tests_sha256",
        "release_publication_proof_manifest_tests_sha256",
        "release_receipt_finalizer_sha256",
        "release_receipt_finalizer_tests_sha256",
        "source_results_assembler_sha256",
        "source_results_assembler_tests_sha256",
        "formal_toolchain_contract_sha256",
        "formal_toolchain_contract_tests_sha256",
        "formal_easycrypt_dockerfile_sha256",
        "proverif_makefile_sha256",
        "migration_agent_authority_sha256",
        "migration_agent_authority_codec_sha256",
        "migration_agent_authority_protocol_sha256",
        "migration_agent_authority_store_sha256",
        "migration_agent_authority_transport_sha256",
    }
)

# One-shot Level-1 integrity pin for the only authorized 190-key migration
# baseline. It detects an unintended or unauthorized results-baseline change;
# installed 237-key successors are intentionally not constrained by this value.
INITIAL_RESULTS_SHA256 = (
    "c156244c7a2d6819277f3ae0ecda79f6b3b5032d37f781777c6fb2e52f0a3a50"
)

ANDROID_AAR_SECTION_FIELDS = frozenset(
    {
        "aar_path",
        "aar_sha256",
        "current_source_status",
        "manifest_generated_at",
        "manifest_path",
        "manifest_schema",
        "manifest_sha256",
        "proof_source_tree_sha256",
        "source_commit",
        "source_tree_dirty",
        "status",
        "targets",
    }
)
ANDROID_RUNTIME_SECTION_FIELDS = frozenset(
    {
        "android_sdk",
        "build_tools",
        "covered_tests",
        "current_source_status",
        "device_abi",
        "device_kind",
        "page_size",
        "proof_generated_at",
        "proof_path",
        "proof_schema",
        "proof_sha256",
        "proof_source_tree_sha256",
        "release_candidate_mode",
        "run_id",
        "source_commit",
        "source_tree_dirty",
        "status",
    }
)
APPLE_SECTION_FIELDS = frozenset(
    {
        "current_attempt",
        "current_proof_generated_at",
        "current_proof_path",
        "current_proof_schema",
        "current_proof_sha256",
        "current_proof_source_tree_dirty",
        "current_source_status",
        "matrix_generated_at",
        "matrix_proof_path",
        "matrix_proof_schema",
        "matrix_proof_sha256",
        "matrix_source_status",
        "matrix_source_tree_dirty",
        "matrix_status",
        "proof_source_tree_sha256",
    }
)
LOCAL_INDEX_SECTION_FIELDS = frozenset(
    {
        "android_runtime_proof_sha256",
        "android_runtime_run_id",
        "channel",
        "consumer_receipt_generated_at",
        "consumer_receipt_path",
        "consumer_receipt_run_id",
        "consumer_receipt_schema",
        "consumer_receipt_sha256",
        "consumer_status",
        "current_source_status",
        "generated_at",
        "index_path",
        "index_schema",
        "index_sha256",
        "proof_source_tree_sha256",
        "source_commit",
        "source_tree_dirty",
        "status",
    }
)
PERFORMANCE_SECTION_FIELDS = frozenset(
    {
        "current_source_status",
        "proof_generated_at",
        "proof_path",
        "proof_schema",
        "proof_sha256",
        "proof_source_tree_sha256",
        "source_commit",
        "source_tree_dirty",
        "status",
    }
)

NDK_PROPERTIES_MAX_BYTES = 64 * 1024
NDK_TOOL_MAX_BYTES = 512 * 1024 * 1024


class SourceResultsAssemblerError(ValueError):
    """The baseline, source identity, or selected evidence is invalid."""


class CommittedSourceResultsError(SourceResultsAssemblerError):
    """A candidate committed, but a post-commit source recheck failed."""

    def __init__(self, path: pathlib.Path, digest: str, stage: str):
        if stage != "postcommit_recheck":
            raise ValueError("committed source-results failure stage is invalid")
        super().__init__(
            "source results candidate committed but is not eligible for use"
        )
        self.path = path
        self.digest = digest
        self.stage = stage


@dataclasses.dataclass(frozen=True, slots=True)
class SourceIdentity:
    commit: str
    digest: str


@dataclasses.dataclass(frozen=True, slots=True)
class EvidencePin:
    path: pathlib.Path
    sha256: str
    maximum: int
    label: str


@dataclasses.dataclass(frozen=True, slots=True)
class NdkInputSnapshot:
    path: pathlib.Path
    device: int
    inode: int
    mode: int
    uid: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class NdkToolLinkSnapshot:
    path: pathlib.Path
    device: int
    inode: int
    mode: int
    uid: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    target: str


@dataclasses.dataclass(frozen=True, slots=True)
class AndroidProjection:
    snapshot: JsonObjectSnapshot
    section: dict[str, object]


@dataclasses.dataclass(frozen=True, slots=True)
class AppleProjection:
    matrix: JsonObjectSnapshot
    child: JsonObjectSnapshot
    section: dict[str, object]


@dataclasses.dataclass(frozen=True, slots=True)
class IndexProjection:
    verified: release_index.VerifiedReleaseIndex
    file: FileSnapshot
    receipt: JsonObjectSnapshot
    section: dict[str, object]


@dataclasses.dataclass(frozen=True, slots=True)
class SourceEvidenceSelectors:
    rust_handoff_manifest: str
    rust_handoff_sha256: str
    android_runtime_run: str
    apple_matrix_run: str
    consumer_run: str
    android_physical_run: str
    performance_proof: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedSourceDomains:
    rust_section: dict[str, object]
    rust_handoff: rust_package_handoff.RustPackageHandoffSnapshot
    aar_section: dict[str, object]
    android: AndroidProjection
    apple: AppleProjection
    index: IndexProjection
    physical: AndroidProjection
    performance_section: dict[str, object]
    pins: tuple[EvidencePin, ...]


T = TypeVar("T")


def _fail(message: str) -> Never:
    raise SourceResultsAssemblerError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, Any]:
    _require(
        isinstance(value, dict)
        and all(isinstance(key, str) for key in value),
        f"{label} must be a JSON object with string keys",
    )
    return value


def _json_equal(left: object, right: object) -> bool:
    try:
        return canonical_json_bytes(left) == canonical_json_bytes(right)
    except (TypeError, ValueError) as exc:
        raise SourceResultsAssemblerError(
            "results transition contains a non-JSON value"
        ) from exc


def _short_selector(value: str, label: str) -> str:
    _require(
        isinstance(value, str)
        and SAFE_SELECTOR_RE.fullmatch(value) is not None
        and value not in {".", ".."},
        f"{label} is not one safe short selector",
    )
    return value


def _run_id(value: str, label: str) -> str:
    _require(
        isinstance(value, str) and RUN_ID_RE.fullmatch(value) is not None,
        f"{label} must be 32 lowercase hexadecimal characters",
    )
    return value


def _relative(path: pathlib.Path) -> str:
    try:
        return path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError as exc:
        raise SourceResultsAssemblerError(
            f"selected evidence escaped the repository: {path}"
        ) from exc


def _domain_call(label: str, operation: Callable[[], T]) -> T:
    """Translate only the CLI-style SystemExit used by legacy verifiers."""

    try:
        return operation()
    except SystemExit as exc:
        raise SourceResultsAssemblerError(
            f"{label} verifier rejected the selected evidence"
        ) from exc


def _load_git_results_bytes(commitish: str, *, label: str) -> bytes:
    object_name = f"{commitish}:{RESULTS_OBJECT_PATH}"
    try:
        object_type = run_git_text(REPOSITORY_ROOT, ["cat-file", "-t", object_name])
        raw_size = run_git_text(REPOSITORY_ROOT, ["cat-file", "-s", object_name])
        _require(object_type == "blob", f"{label} is not one Git blob")
        _require(
            re.fullmatch(r"(?:0|[1-9][0-9]*)", raw_size) is not None,
            f"{label} size is malformed",
        )
        size = int(raw_size, 10)
        _require(
            0 < size <= MAX_RESULTS_MANIFEST_BYTES,
            f"{label} size is outside the supported bound",
        )
        data = run_git_bytes(REPOSITORY_ROOT, ["cat-file", "blob", object_name])
    except GitProvenanceError as exc:
        raise SourceResultsAssemblerError(
            f"cannot read {label}"
        ) from exc
    _require(len(data) == size, f"{label} size changed while reading")
    return data


def _load_head_results_bytes() -> bytes:
    return _load_git_results_bytes("HEAD", label="HEAD results baseline")


def _owned_results_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != PUBLIC_FILE_MODE
        or metadata.st_nlink != 1
    ):
        raise EvidenceIOError("current results manifest metadata differs")


def _load_pinned_baseline(expected_results_sha256: str) -> dict[str, Any]:
    """Load strict worktree results bytes only when they equal the HEAD blob."""

    _require(
        isinstance(expected_results_sha256, str)
        and SHA256_RE.fullmatch(expected_results_sha256) is not None,
        "expected results SHA-256 is malformed",
    )
    try:
        snapshot = read_regular_snapshot(
            RESULTS_PATH,
            maximum=RESULTS_MAX_BYTES,
            label="current results baseline",
            validate_metadata=_owned_results_metadata,
        )
        parsed = parse_strict_json_bytes(
            snapshot.data,
            label="current results baseline",
        )
    except EvidenceIOError as exc:
        raise SourceResultsAssemblerError(
            "cannot safely read the current results baseline"
        ) from exc
    _require(
        snapshot.sha256 == expected_results_sha256,
        "worktree results baseline differs from its startup pin",
    )
    baseline = _object(parsed, "current results baseline")
    head_bytes = _load_head_results_bytes()
    _require(
        snapshot.data == head_bytes
        and hashlib.sha256(head_bytes).hexdigest() == expected_results_sha256,
        "worktree results baseline is not byte-identical to HEAD",
    )
    return baseline


def validate_baseline(
    expected_results_sha256: str,
    *,
    require_initial: bool = True,
) -> dict[str, Any]:
    """Pin the baseline and require the exact initial or installed contract."""

    if require_initial:
        _require(
            expected_results_sha256 == INITIAL_RESULTS_SHA256,
            "initial source successor baseline differs from the frozen byte authority",
        )
    baseline = _load_pinned_baseline(expected_results_sha256)
    _validate_baseline_document_shape(
        baseline,
        require_initial=require_initial,
    )
    try:
        if require_initial:
            validate_release_publications(baseline)
        else:
            validate_declared_currentness(baseline)
    except (ProofManifestError, ReleasePublicationContractError) as exc:
        raise SourceResultsAssemblerError(str(exc)) from exc
    return baseline


def source_ci_gate(
    expected_results_sha256: str,
    expected_commit: str,
) -> tuple[str, SourceIdentity]:
    """Select only the exact initial-readiness or full installed CI state."""

    _require(
        isinstance(expected_commit, str)
        and COMMIT_RE.fullmatch(expected_commit) is not None,
        "expected CI source commit is malformed",
    )
    baseline = _load_pinned_baseline(expected_results_sha256)
    baseline_inputs = _object(
        baseline.get("proof_to_byte_inputs"),
        "baseline proof_to_byte_inputs",
    )
    current_keys = set(PROOF_TO_BYTE_INPUT_PATHS)
    baseline_keys = set(baseline_inputs)
    initial_keys = current_keys - set(INITIAL_BASELINE_MISSING_PROOF_INPUT_KEYS)

    if baseline_keys == initial_keys:
        validate_baseline(expected_results_sha256, require_initial=True)
        source = _source_identity()
        _require(
            source.commit == expected_commit,
            "CI source identity differs from the expected commit",
        )
        authority = capture_proof_input_digests(REPOSITORY_ROOT)
        _require(
            len(authority) == 237
            and set(authority) == current_keys
            and len(current_keys - baseline_keys) == 47,
            "source transition proof-input authority differs",
        )
        _require(
            capture_proof_input_digests(REPOSITORY_ROOT) == authority,
            "source transition proof-input authority changed during readiness",
        )
        validate_baseline(expected_results_sha256, require_initial=True)
        _require(
            capture_proof_input_digests(REPOSITORY_ROOT) == authority,
            "source transition proof-input authority changed after baseline recheck",
        )
        final_source = _source_identity()
        _require(
            final_source == source and final_source.commit == expected_commit,
            "CI source identity changed after readiness closure",
        )
        return "initial", source

    if baseline_keys == current_keys:
        for key, digest in baseline_inputs.items():
            _require(
                isinstance(key, str)
                and key.endswith("_sha256")
                and isinstance(digest, str)
                and SHA256_RE.fullmatch(digest) is not None,
                "installed CI proof-input map is malformed",
            )
        source = _source_identity()
        _require(
            source.commit == expected_commit,
            "CI source identity differs from the expected commit",
        )
        _load_pinned_baseline(expected_results_sha256)
        final_source = _source_identity()
        _require(
            final_source == source and final_source.commit == expected_commit,
            "CI source identity changed before installed proof dispatch",
        )
        return "installed", source

    raise SourceResultsAssemblerError(
        "CI results proof-input state is neither exact initial nor installed"
    )


def _validate_baseline_document_shape(
    baseline: dict[str, Any],
    *,
    require_initial: bool,
) -> None:
    """Require the exact initial or installed proof-map migration shape."""

    _validate_initial_publication_state(baseline)
    baseline_inputs = _object(
        baseline.get("proof_to_byte_inputs"),
        "baseline proof_to_byte_inputs",
    )
    current_keys = set(PROOF_TO_BYTE_INPUT_PATHS)
    baseline_keys = set(baseline_inputs)
    if require_initial:
        _require(
            not (baseline_keys - current_keys)
            and current_keys - baseline_keys
            == set(INITIAL_BASELINE_MISSING_PROOF_INPUT_KEYS),
            "initial source successor requires the exact one-time proof-input migration",
        )
    else:
        _require(
            baseline_keys == current_keys,
            "installed source successor must contain the canonical proof-input keys",
        )
    for key, digest in baseline_inputs.items():
        _require(
            isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
            f"baseline proof-input digest is malformed: {key}",
        )


def _validate_initial_publication_state(baseline: dict[str, Any]) -> None:
    publications = _object(
        baseline.get("release_publications"), "release_publications"
    )
    required = {
        apple_publication_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
        platform_publication_contract.PLATFORM_R2_PUBLICATION_KEY,
    }
    _require(
        set(publications) == required,
        "initial source successor requires exactly the frozen alpha.2 and platform-r2 leaves",
    )
    swift = _object(baseline.get("swift_xcframework"), "swift_xcframework")
    apple_alpha2 = _object(
        publications[apple_publication_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY],
        "Apple alpha.2 publication",
    )
    _require(
        _json_equal(swift.get("distribution"), apple_alpha2.get("distribution")),
        "initial source successor baseline has a non-alpha.2 Swift selector",
    )


def _source_identity() -> SourceIdentity:
    try:
        inspection = inspect_worktree(REPOSITORY_ROOT)
        _require(
            not inspection.dirty,
            "source results assembly requires a clean worktree: "
            + "; ".join(inspection.reasons[:4]),
        )
        digest = canonical_tree_digest(
            REPOSITORY_ROOT,
            repository_paths(REPOSITORY_ROOT),
        )
    except (GitProvenanceError, LedgerError) as exc:
        raise SourceResultsAssemblerError(
            "cannot establish the canonical source identity"
        ) from exc
    _require(
        COMMIT_RE.fullmatch(inspection.commit) is not None,
        "current source commit is malformed",
    )
    _require(SHA256_RE.fullmatch(digest) is not None, "source digest is malformed")
    return SourceIdentity(commit=inspection.commit, digest=digest)


def _stable_source_identity(expected: SourceIdentity) -> None:
    observed = _source_identity()
    _require(
        observed == expected,
        "source identity changed while results were assembled: "
        f"before={expected} after={observed}",
    )


def _pin(snapshot: FileSnapshot, *, maximum: int, label: str) -> EvidencePin:
    return EvidencePin(
        path=snapshot.path,
        sha256=snapshot.sha256,
        maximum=maximum,
        label=label,
    )


def _resample_pins(pins: list[EvidencePin]) -> None:
    for pin in pins:
        try:
            observed = read_regular_snapshot(
                pin.path,
                maximum=pin.maximum,
                label=pin.label,
            )
        except EvidenceIOError as exc:
            raise SourceResultsAssemblerError(str(exc)) from exc
        _require(
            observed.sha256 == pin.sha256,
            f"selected evidence changed while results were assembled: {pin.label}",
        )


def _resample_verified_domains(domains: VerifiedSourceDomains) -> None:
    """Reopen every byte pin and the complete fixed Rust handoff transaction."""

    _resample_pins(list(domains.pins))
    handoff = domains.rust_handoff
    _require(
        isinstance(handoff, rust_package_handoff.RustPackageHandoffSnapshot),
        "verified Rust package handoff is missing",
    )
    try:
        current = rust_package_handoff.load_rust_package_handoff_snapshot(
            handoff.manifest.path,
            handoff.manifest.sha256,
            handoff.source,
            handoff_root=handoff.handoff_root,
        )
    except rust_package_handoff.RustPackageHandoffError as exc:
        raise SourceResultsAssemblerError(str(exc)) from exc
    _require(
        current.manifest.data == handoff.manifest.data
        and current.transcript.data == handoff.transcript.data
        and len(current.crates) == len(handoff.crates)
        and all(
            observed.file.data == selected.file.data
            for observed, selected in zip(current.crates, handoff.crates)
        ),
        "Rust package handoff changed while results were assembled",
    )


def _rust_handoff_manifest_path(value: str) -> pathlib.Path:
    _require(
        isinstance(value, str)
        and value
        and "\\" not in value
        and len(value) <= 4096,
        "Rust package handoff manifest path is malformed",
    )
    pure = pathlib.PurePosixPath(value)
    expected_root = pathlib.PurePosixPath(
        "target/qperiapt-rust-package-handoffs"
    )
    _require(
        not pure.is_absolute()
        and pure.as_posix() == value
        and len(pure.parts) == 4
        and pure.parts[:2] == expected_root.parts
        and rust_package_handoff.RUST_PACKAGE_HANDOFF_TRANSACTION_RE.fullmatch(
            pure.parts[2]
        )
        is not None
        and pure.name
        == rust_package_handoff.RUST_PACKAGE_HANDOFF_MANIFEST_NAME,
        "Rust package handoff manifest path differs from the fixed transaction shape",
    )
    return REPOSITORY_ROOT.joinpath(*pure.parts)


def _rust_projection(
    source: SourceIdentity,
    handoff_manifest: str,
    handoff_sha256: str,
) -> tuple[
    dict[str, object],
    tuple[EvidencePin, ...],
    rust_package_handoff.RustPackageHandoffSnapshot,
]:
    _require(
        isinstance(handoff_sha256, str)
        and SHA256_RE.fullmatch(handoff_sha256) is not None,
        "Rust package handoff manifest digest is malformed",
    )
    handoff_path = _rust_handoff_manifest_path(handoff_manifest)
    try:
        source_tree = run_git_text(
            REPOSITORY_ROOT,
            ["rev-parse", "--verify", f"{source.commit}^{{tree}}"],
        )
        handoff = rust_package_handoff.load_rust_package_handoff_snapshot(
            handoff_path,
            handoff_sha256,
            rust_package_handoff.RustPackageHandoffSource(
                source_commit=source.commit,
                source_tree=source_tree,
                canonical_source_tree_sha256=source.digest,
            ),
        )
    except (
        rust_package_handoff.RustPackageHandoffError,
        GitProvenanceError,
    ) as exc:
        raise SourceResultsAssemblerError(str(exc)) from exc
    receipt = handoff.package_contract
    _require(
        receipt.source_commit == source.commit,
        "Rust package transcript source commit differs from HEAD",
    )
    current_status = rust_package_current_local_status(
        source_commit=source.commit,
        source_digest=source.digest,
        completed_at=receipt.completed_at,
        advisory_commit=receipt.advisory_db_commit,
        registry_package_count=receipt.registry_package_count,
        normalized_lock_sha256=receipt.normalized_cargo_lock_sha256,
    )
    section: dict[str, object] = {
        "advisory_db_clean": True,
        "advisory_db_commit": receipt.advisory_db_commit,
        "advisory_db_mode": RUST_PACKAGE_ADVISORY_DB_MODE,
        "advisory_db_url": RUST_PACKAGE_ADVISORY_DB_URL,
        "boundary": RUST_PACKAGE_BOUNDARY,
        "cargo_audit_version": "0.22.2",
        "cargo_home_isolated": True,
        "cargo_version": "1.96.1",
        "cargo_warning_free": True,
        "command": RUST_PACKAGE_COMMAND,
        "completed_at": receipt.completed_at,
        "crates_io_index_protocol": RUST_PACKAGE_CRATES_IO_INDEX_PROTOCOL,
        "crates_io_index_url": RUST_CRATES_IO_SPARSE_INDEX,
        "crates_io_registry_package_count": receipt.registry_package_count,
        "crates_io_sparse_lock_verification_pass": True,
        "current_local_status": current_status,
        "current_source_status": "current_clean_tree_rust_package_contract_pass",
        "dirty_diagnostic_command": RUST_PACKAGE_DIRTY_COMMAND,
        "evidence_schema": 2,
        "handoff_manifest_path": _relative(handoff.manifest.path),
        "handoff_manifest_sha256": handoff.manifest.sha256,
        "mode": RUST_PACKAGE_MODE,
        "nonpublishable_crates": list(RUST_PACKAGE_NONPUBLISHABLE_CRATES),
        "normalized_cargo_lock_sha256": receipt.normalized_cargo_lock_sha256,
        "normalized_dependency_audit_pass": True,
        "package_list_pass_crates": list(receipt.package_list_crates),
        "package_verification_pass_crates": list(
            receipt.package_verification_crates
        ),
        "proof_source_tree_sha256": source.digest,
        "publishable_crates": list(RUST_PACKAGE_PUBLISHABLE_CRATES),
        "registry": "crates-io",
        "rustc_version": "1.96.1",
        "source_commit": source.commit,
        "source_tree_dirty": False,
        "status": "pass",
        "transcript_path": _relative(handoff.transcript.path),
        "transcript_sha256": handoff.transcript.sha256,
        "upload_attempted": False,
    }
    pins = [
        _pin(
            handoff.manifest,
            maximum=rust_package_handoff.MAX_HANDOFF_MANIFEST_BYTES,
            label="Rust package handoff manifest",
        ),
        _pin(
            handoff.transcript,
            maximum=rust_package_handoff.MAX_TRANSCRIPT_BYTES,
            label="Rust package contract transcript",
        ),
    ]
    pins.extend(
        _pin(
            crate.file,
            maximum=rust_package_handoff.MAX_CRATE_BYTES,
            label=f"{crate.name} handoff .crate archive",
        )
        for crate in handoff.crates
    )
    return section, tuple(pins), handoff


def _android_ndk() -> pathlib.Path:
    """Derive the fixed r29 installation without accepting a CLI path."""

    def environment_path(value: str, label: str) -> pathlib.Path:
        try:
            encoded_size = len(os.fsencode(value))
        except (TypeError, UnicodeError, ValueError) as exc:
            raise SourceResultsAssemblerError(
                f"{label} is not one valid filesystem path"
            ) from exc
        _require(
            bool(value)
            and value.isprintable()
            and encoded_size <= 4095,
            f"{label} must be one printable bounded path",
        )
        return pathlib.Path(value)

    explicit_name = None
    explicit = os.environ.get("QPERIAPT_ANDROID_NDK_HOME")
    if explicit:
        explicit_name = "QPERIAPT_ANDROID_NDK_HOME"
    else:
        explicit = os.environ.get("ANDROID_NDK_HOME")
        if explicit:
            explicit_name = "ANDROID_NDK_HOME"
    if explicit:
        selected = environment_path(explicit, str(explicit_name))
    else:
        sdk_name = None
        sdk = os.environ.get("QPERIAPT_ANDROID_SDK_ROOT")
        if sdk:
            sdk_name = "QPERIAPT_ANDROID_SDK_ROOT"
        else:
            for candidate_name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
                sdk = os.environ.get(candidate_name)
                if sdk:
                    sdk_name = candidate_name
                    break
        if sdk:
            sdk_root = environment_path(sdk, str(sdk_name))
        else:
            home = os.environ.get("HOME")
            _require(bool(home), "cannot derive the fixed Android SDK root")
            sdk_root = environment_path(str(home), "HOME") / "Library" / "Android" / "sdk"
        selected = sdk_root / "ndk" / "29.0.14206865"
    _require(selected.is_absolute(), "derived Android NDK path must be absolute")
    try:
        resolved = selected.resolve(strict=True)
    except OSError as exc:
        raise SourceResultsAssemblerError(
            "cannot resolve the fixed Android NDK r29 installation"
        ) from exc
    _require(
        resolved == selected,
        "derived Android NDK path must be canonically spelled",
    )
    try:
        metadata = resolved.lstat()
    except OSError as exc:
        raise SourceResultsAssemblerError(
            "cannot inspect the fixed Android NDK r29 installation"
        ) from exc
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid(),
        "fixed Android NDK r29 must be an owned directory",
    )
    return resolved


def _ndk_input_snapshot(
    path: pathlib.Path,
    *,
    maximum: int,
    label: str,
    executable: bool,
) -> tuple[NdkInputSnapshot, FileSnapshot]:
    """Snapshot one fixed NDK input to detect drift during AAR verification."""

    try:
        canonical = path.resolve(strict=True)
        before = path.lstat()
    except OSError as exc:
        raise SourceResultsAssemblerError(
            f"cannot inspect fixed {label}"
        ) from exc
    _require(canonical == path, f"fixed {label} path must be canonical")
    _require(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == os.geteuid()
        and before.st_nlink == 1
        and (not executable or stat.S_IMODE(before.st_mode) & 0o111 != 0)
        and (not executable or os.access(path, os.X_OK)),
        f"fixed {label} metadata is unsafe",
    )

    identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )

    def validate_opened(opened: os.stat_result) -> None:
        observed = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if observed != identity:
            raise EvidenceIOError(f"fixed {label} identity changed while opening")

    try:
        snapshot = read_regular_snapshot(
            path,
            maximum=maximum,
            label=f"fixed {label}",
            validate_metadata=validate_opened,
        )
        after = path.lstat()
    except (EvidenceIOError, OSError) as exc:
        raise SourceResultsAssemblerError(
            f"cannot stably snapshot fixed {label}"
        ) from exc
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    _require(
        after_identity == identity,
        f"fixed {label} identity changed while it was sampled",
    )
    return (
        NdkInputSnapshot(
            path=path,
            device=after.st_dev,
            inode=after.st_ino,
            mode=after.st_mode,
            uid=after.st_uid,
            links=after.st_nlink,
            size=after.st_size,
            mtime_ns=after.st_mtime_ns,
            ctime_ns=after.st_ctime_ns,
            sha256=snapshot.sha256,
        ),
        snapshot,
    )


def _resolve_ndk_tool(
    path: pathlib.Path,
    *,
    ndk: pathlib.Path,
    label: str,
) -> tuple[pathlib.Path, NdkToolLinkSnapshot | None]:
    """Resolve only a fixed leaf symlink and pin its link identity and target."""

    try:
        link_metadata = path.lstat()
    except OSError as exc:
        raise SourceResultsAssemblerError(f"cannot inspect fixed {label}") from exc
    if not stat.S_ISLNK(link_metadata.st_mode):
        _require(
            stat.S_ISREG(link_metadata.st_mode),
            f"fixed {label} must be a regular file or one fixed leaf symlink",
        )
        return path, None
    _require(
        link_metadata.st_uid == os.geteuid()
        and link_metadata.st_nlink == 1,
        f"fixed {label} symlink metadata is unsafe",
    )
    try:
        target = os.readlink(path)
    except OSError as exc:
        raise SourceResultsAssemblerError(
            f"cannot read fixed {label} symlink"
        ) from exc
    target_path = pathlib.PurePath(target)
    _require(
        bool(target)
        and target.isprintable()
        and not target_path.is_absolute()
        and len(target_path.parts) == 1
        and target_path.parts[0] not in {"", ".", ".."},
        f"fixed {label} symlink target is unsafe",
    )
    resolved = path.parent / target_path.parts[0]
    try:
        canonical = resolved.resolve(strict=True)
        canonical.relative_to(ndk)
    except (OSError, ValueError) as exc:
        raise SourceResultsAssemblerError(
            f"fixed {label} symlink escapes the selected NDK"
        ) from exc
    _require(
        canonical == resolved,
        f"fixed {label} symlink target must resolve to one canonical file",
    )
    return (
        canonical,
        NdkToolLinkSnapshot(
            path=path,
            device=link_metadata.st_dev,
            inode=link_metadata.st_ino,
            mode=link_metadata.st_mode,
            uid=link_metadata.st_uid,
            links=link_metadata.st_nlink,
            size=link_metadata.st_size,
            mtime_ns=link_metadata.st_mtime_ns,
            ctime_ns=link_metadata.st_ctime_ns,
            target=target,
        ),
    )


def _aar_projection(
    source: SourceIdentity,
) -> tuple[dict[str, object], list[EvidencePin]]:
    try:
        aar = read_regular_snapshot(
            ANDROID_AAR_FILE,
            maximum=android_elf.MAX_ARCHIVE_BYTES,
            label="Android 0.1.0 stable AAR",
        )
        manifest_snapshot = load_json_object_snapshot(
            ANDROID_AAR_MANIFEST_FILE,
            maximum=16 * 1024 * 1024,
            label="Android 0.1.0 stable AAR manifest",
        )
        ndk = _android_ndk()
        properties_path = ndk / "source.properties"
        properties_before, properties_file = _ndk_input_snapshot(
            properties_path,
            maximum=NDK_PROPERTIES_MAX_BYTES,
            label="Android NDK source.properties",
            executable=False,
        )
        revision = android_elf.verify_ndk_r29(ndk)
        _require(
            revision == "29.0.14206865",
            "source results assembly requires Android NDK 29.0.14206865",
        )
        toolchain = android_elf.find_ndk_toolchain(ndk)
        try:
            toolchain_resolved = toolchain.resolve(strict=True)
            toolchain_metadata = toolchain.lstat()
            toolchain_resolved.relative_to(ndk)
        except (OSError, ValueError) as exc:
            raise SourceResultsAssemblerError(
                "fixed Android NDK toolchain path is unsafe"
            ) from exc
        _require(
            toolchain_resolved == toolchain
            and stat.S_ISDIR(toolchain_metadata.st_mode)
            and toolchain_metadata.st_uid == os.geteuid(),
            "fixed Android NDK toolchain must be one owned canonical directory",
        )
        llvm_nm_link = toolchain / "bin" / "llvm-nm"
        llvm_readelf_link = toolchain / "bin" / "llvm-readelf"
        llvm_nm, nm_link_before = _resolve_ndk_tool(
            llvm_nm_link,
            ndk=ndk,
            label="Android NDK llvm-nm",
        )
        llvm_readelf, readelf_link_before = _resolve_ndk_tool(
            llvm_readelf_link,
            ndk=ndk,
            label="Android NDK llvm-readelf",
        )
        nm_before, nm_file = _ndk_input_snapshot(
            llvm_nm,
            maximum=NDK_TOOL_MAX_BYTES,
            label="Android NDK llvm-nm",
            executable=True,
        )
        readelf_before, readelf_file = _ndk_input_snapshot(
            llvm_readelf,
            maximum=NDK_TOOL_MAX_BYTES,
            label="Android NDK llvm-readelf",
            executable=True,
        )
        manifest = android_elf.verify_aar(
            ANDROID_AAR_FILE,
            # Preserve LLVM's argv[0]-selected readelf personality.  The fixed
            # leaves and their resolved same-bin targets are pinned above and
            # reverified below to detect accidental drift during this Level-1
            # local verification window; this is not hostile-host authentication.
            llvm_nm=llvm_nm_link,
            llvm_readelf=llvm_readelf_link,
            manifest=ANDROID_AAR_MANIFEST_FILE,
            expected_aar_sha256=aar.sha256,
            expected_manifest_sha256=manifest_snapshot.file.sha256,
            require_release_manifest=True,
            forbidden_text=(str(REPOSITORY_ROOT),),
            source_root=REPOSITORY_ROOT,
        )
        properties_after, _ = _ndk_input_snapshot(
            properties_path,
            maximum=NDK_PROPERTIES_MAX_BYTES,
            label="Android NDK source.properties",
            executable=False,
        )
        nm_after, _ = _ndk_input_snapshot(
            llvm_nm,
            maximum=NDK_TOOL_MAX_BYTES,
            label="Android NDK llvm-nm",
            executable=True,
        )
        readelf_after, _ = _ndk_input_snapshot(
            llvm_readelf,
            maximum=NDK_TOOL_MAX_BYTES,
            label="Android NDK llvm-readelf",
            executable=True,
        )
        llvm_nm_after, nm_link_after = _resolve_ndk_tool(
            llvm_nm_link,
            ndk=ndk,
            label="Android NDK llvm-nm",
        )
        llvm_readelf_after, readelf_link_after = _resolve_ndk_tool(
            llvm_readelf_link,
            ndk=ndk,
            label="Android NDK llvm-readelf",
        )
        _require(
            properties_after == properties_before
            and nm_after == nm_before
            and readelf_after == readelf_before,
            "fixed Android NDK verification inputs changed during AAR verification",
        )
        _require(
            llvm_nm_after == llvm_nm
            and llvm_readelf_after == llvm_readelf
            and nm_link_after == nm_link_before
            and readelf_link_after == readelf_link_before,
            "fixed Android NDK tool selection changed during AAR verification",
        )
        _require(
            isinstance(manifest, dict),
            "Android AAR deep verification returned no manifest",
        )
    except (EvidenceIOError, android_elf.AndroidVerificationError) as exc:
        raise SourceResultsAssemblerError(str(exc)) from exc
    _require(
        manifest.get("git_commit") == source.commit
        and manifest.get("source_tree_sha256") == source.digest
        and manifest.get("git_dirty") is False,
        "Android AAR source identity differs from HEAD",
    )
    android = _object(manifest.get("android"), "Android AAR metadata")
    artifacts = _object(manifest.get("artifacts"), "Android AAR artifacts")
    section: dict[str, object] = {
        "aar_path": ANDROID_AAR_PATH,
        "aar_sha256": aar.sha256,
        "current_source_status": "current_clean_tree_package_pass",
        "manifest_generated_at": manifest.get("generated_at"),
        "manifest_path": ANDROID_AAR_MANIFEST_PATH,
        "manifest_schema": manifest.get("schema_version"),
        "manifest_sha256": manifest_snapshot.file.sha256,
        "proof_source_tree_sha256": source.digest,
        "source_commit": source.commit,
        "source_tree_dirty": False,
        "status": "pass",
        "targets": list(android.get("abis", [])),
    }
    _require(
        artifacts.get("aar_sha256") == aar.sha256,
        "Android AAR manifest artifact digest differs",
    )
    return section, [
        _pin(
            aar,
            maximum=android_elf.MAX_ARCHIVE_BYTES,
            label="Android 0.1.0 stable AAR",
        ),
        _pin(
            manifest_snapshot.file,
            maximum=16 * 1024 * 1024,
            label="Android 0.1.0 stable AAR manifest",
        ),
        _pin(
            properties_file,
            maximum=NDK_PROPERTIES_MAX_BYTES,
            label="fixed Android NDK source.properties",
        ),
        _pin(
            nm_file,
            maximum=NDK_TOOL_MAX_BYTES,
            label="fixed Android NDK llvm-nm",
        ),
        _pin(
            readelf_file,
            maximum=NDK_TOOL_MAX_BYTES,
            label="fixed Android NDK llvm-readelf",
        ),
    ]


def _android_proof_path(run_id: str) -> pathlib.Path:
    return (
        ANDROID_RUNS_ROOT
        / run_id
        / "proof"
        / android_device_proof.ANDROID_PROOF_LEAF
    )


def _android_projection(
    run_id: str,
    source: SourceIdentity,
    *,
    physical: bool,
) -> AndroidProjection:
    run_id = _run_id(
        run_id,
        "physical Android run" if physical else "canonical Android run",
    )
    proof_path = _android_proof_path(run_id)
    try:
        snapshot = load_json_object_snapshot(
            proof_path,
            maximum=ANDROID_PROOF_MAX_BYTES,
            label="physical Android proof" if physical else "canonical Android proof",
        )
    except EvidenceIOError as exc:
        raise SourceResultsAssemblerError(str(exc)) from exc
    proof = snapshot.value

    def verify() -> None:
        android_device_proof.verify_proof_schema(proof)
        android_device_proof.verify_proof_freshness(
            proof, PROOF_MAX_AGE_SECONDS
        )
        paths = android_device_proof.proof_paths(REPOSITORY_ROOT, proof)
        android_device_proof.validate_selected_run_layout(
            REPOSITORY_ROOT,
            proof_path,
            proof,
            paths,
            require_unique_run=not physical,
        )
        android_device_proof.verify_proof_contents(
            REPOSITORY_ROOT,
            proof,
            paths,
            expected_device_kind="physical" if physical else "emulator",
            expected_device_abi="arm64-v8a",
            expected_page_size=None if physical else 16_384,
            expected_device_sdk=None if physical else 35,
            require_release_mode=True,
            allow_dirty_proof=False,
        )

    _domain_call(
        "physical Android proof" if physical else "canonical Android proof",
        verify,
    )
    _require(
        proof.get("schema") == ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
        "Android proof schema is not current",
    )
    _require(
        proof.get("git_commit") == source.commit
        and proof.get("proof_source_tree_sha256") == source.digest
        and proof.get("source_tree_dirty") is False,
        "Android proof source identity differs from HEAD",
    )
    device = _object(proof.get("device"), "Android proof device")
    android = _object(proof.get("android"), "Android proof toolchain")
    result = _object(proof.get("result"), "Android proof result")
    status = (
        "current_clean_tree_physical_pass"
        if physical
        else "current_clean_tree_emulator_pass"
    )
    section: dict[str, object] = {
        "android_sdk": device.get("sdk"),
        "build_tools": android.get("build_tools"),
        "covered_tests": list(result.get("passed_tests", [])),
        "current_source_status": status,
        "device_abi": device.get("abi"),
        "device_kind": device.get("kind"),
        "page_size": device.get("page_size"),
        "proof_generated_at": proof.get("generated_at"),
        "proof_path": _relative(proof_path),
        "proof_schema": proof.get("schema"),
        "proof_sha256": snapshot.file.sha256,
        "proof_source_tree_sha256": source.digest,
        "release_candidate_mode": proof.get("release_candidate_mode"),
        "run_id": run_id,
        "source_commit": source.commit,
        "source_tree_dirty": False,
        "status": result.get("status"),
    }
    _require(
        section["covered_tests"] == list(ANDROID_EXPECTED_TESTS),
        "Android proof test set differs from the release contract",
    )
    return AndroidProjection(snapshot=snapshot, section=section)


def _apple_projection(
    run_selector: str,
    source: SourceIdentity,
) -> AppleProjection:
    run_selector = _short_selector(run_selector, "Apple matrix run")
    matrix_root = APPLE_RUNS_ROOT / run_selector
    matrix_path = matrix_root / "apple-device-matrix-proof.json"
    try:
        matrix = load_json_object_snapshot(
            matrix_path,
            maximum=apple_device_proof.MAX_APPLE_PROOF_BYTES,
            label="Apple device matrix proof",
        )
    except EvidenceIOError as exc:
        raise SourceResultsAssemblerError(str(exc)) from exc
    _domain_call(
        "Apple device matrix proof",
        lambda: apple_device_proof.verify_matrix_snapshot(
            REPOSITORY_ROOT,
            matrix,
            matrix_root,
            PROOF_MAX_AGE_SECONDS,
            False,
        ),
    )
    proof = matrix.value
    _require(
        proof.get("schema_version") == APPLE_MATRIX_PROOF_SCHEMA_VERSION
        and proof.get("status") == "pass",
        "Apple matrix proof is not a passing current schema",
    )
    _require(
        proof.get("git_commit") == source.commit
        and proof.get("proof_source_tree_sha256") == source.digest
        and proof.get("source_tree_dirty") is False,
        "Apple matrix source identity differs from HEAD",
    )
    devices = proof.get("devices")
    _require(isinstance(devices, list), "Apple matrix devices are malformed")
    ipad_entries = [
        entry
        for entry in devices
        if isinstance(entry, dict) and entry.get("label") == "ipad"
    ]
    _require(len(ipad_entries) == 1, "Apple matrix must select exactly one ipad child")
    ipad = ipad_entries[0]
    child_relative = ipad.get("proof")
    _require(
        isinstance(child_relative, str)
        and pathlib.PurePosixPath(child_relative).as_posix() == child_relative
        and not pathlib.PurePosixPath(child_relative).is_absolute()
        and ".." not in pathlib.PurePosixPath(child_relative).parts,
        "Apple ipad child proof path is not canonical",
    )
    child_path = matrix_root.joinpath(*pathlib.PurePosixPath(child_relative).parts)
    try:
        child = load_json_object_snapshot(
            child_path,
            maximum=apple_device_proof.MAX_APPLE_PROOF_BYTES,
            label="Apple ipad child proof",
        )
    except EvidenceIOError as exc:
        raise SourceResultsAssemblerError(str(exc)) from exc
    child_value = child.value
    _require(
        child.file.sha256 == ipad.get("proof_sha256"),
        "Apple ipad child hash differs from the matrix",
    )
    _require(
        child_value.get("schema_version") == APPLE_DEVICE_PROOF_SCHEMA_VERSION
        and child_value.get("status") == "pass"
        and child_value.get("git_commit") == source.commit
        and child_value.get("proof_source_tree_sha256") == source.digest
        and child_value.get("source_tree_dirty") is False,
        "Apple ipad child proof identity differs",
    )
    section: dict[str, object] = {
        "current_attempt": {"proof_emitted": True, "status": "pass"},
        "current_proof_generated_at": child_value.get("generated_at"),
        "current_proof_path": _relative(child_path),
        "current_proof_schema": child_value.get("schema_version"),
        "current_proof_sha256": child.file.sha256,
        "current_proof_source_tree_dirty": False,
        "current_source_status": "current_clean_tree_physical_pass",
        "matrix_generated_at": proof.get("generated_at"),
        "matrix_proof_path": _relative(matrix_path),
        "matrix_proof_schema": proof.get("schema_version"),
        "matrix_proof_sha256": matrix.file.sha256,
        "matrix_source_status": "current_clean_tree_physical_pass",
        "matrix_source_tree_dirty": False,
        "matrix_status": "pass",
        "proof_source_tree_sha256": source.digest,
    }
    return AppleProjection(matrix=matrix, child=child, section=section)


def _index_path(source: SourceIdentity) -> pathlib.Path:
    return (
        REPOSITORY_ROOT
        / "target"
        / "qperiapt-local-release"
        / "release"
        / "0.1.0"
        / source.commit
        / "index.json"
    )


def _index_projection(
    source: SourceIdentity,
    consumer_run_id: str,
    android: AndroidProjection,
    apple: AppleProjection,
    aar_section: dict[str, object],
) -> IndexProjection:
    consumer_run_id = _run_id(consumer_run_id, "release consumer run")
    index_path = _index_path(source)
    verified = _domain_call(
        "local release index",
        lambda: release_index.verify_release_index_snapshot(
            index_path,
            REPOSITORY_ROOT,
            allow_diagnostic=False,
        ),
    )
    try:
        index_file = read_regular_snapshot(
            index_path,
            maximum=release_index.MAX_TEXT_BYTES,
            label="local release index",
        )
    except EvidenceIOError as exc:
        raise SourceResultsAssemblerError(
            "cannot stably snapshot the local release index"
        ) from exc
    _require(
        index_file.sha256 == verified.sha256,
        "local release index changed after deep verification",
    )
    index = verified.value
    _require(
        index.get("schema_version") == LOCAL_RELEASE_INDEX_SCHEMA_VERSION
        and index.get("channel") == "release"
        and index.get("diagnostic_only") is False,
        "local release index is not a schema-5 release index",
    )
    git = _object(index.get("git"), "local release index Git identity")
    _require(
        git.get("commit") == source.commit
        and git.get("source_tree_dirty") is False,
        "local release index source identity differs from HEAD",
    )
    summaries = _object(index.get("proof_summaries"), "release proof summaries")
    _require(
        set(summaries) == {"android_runtime", "apple_matrix"},
        "release index must contain exactly Android runtime and Apple matrix summaries",
    )
    android_summary = _object(
        summaries.get("android_runtime"), "Android runtime summary"
    )
    apple_summary = _object(summaries.get("apple_matrix"), "Apple matrix summary")
    _require(
        android_summary.get("sha256") == android.snapshot.file.sha256
        and apple_summary.get("sha256") == apple.matrix.file.sha256,
        "release index selected proof summaries differ from the source results",
    )
    indexed_runtime_id, indexed_runtime_sha256 = (
        release_consumer_smoke.android_runtime_summary_identity(index)
    )
    _require(
        indexed_runtime_id == android.section["run_id"]
        and indexed_runtime_sha256 == android.snapshot.file.sha256,
        "release index Android runtime identity differs",
    )
    indexed_aar_sha256 = release_consumer_smoke.indexed_android_aar_sha256(index)
    _require(
        indexed_aar_sha256 == aar_section["aar_sha256"],
        "release index Android AAR differs from the selected package",
    )
    receipt_path = (
        CONSUMER_RECEIPTS_ROOT
        / consumer_run_id
        / release_consumer_smoke.CONSUMER_RECEIPT_LEAF
    )
    receipt = _domain_call(
        "local release consumer receipt",
        lambda: release_consumer_smoke.load_private_consumer_receipt(receipt_path),
    )
    archives = _domain_call(
        "local release C archive selection",
        lambda: release_consumer_smoke.c_archive_entries(
            index, verified.path.parent
        ),
    )
    _require(len(archives) == 1, "local release index must select one C archive")
    _domain_call(
        "local release consumer receipt",
        lambda: release_consumer_smoke.validate_consumer_receipt(
            receipt.value,
            root=REPOSITORY_ROOT,
            expected_run_id=consumer_run_id,
            expected_source_commit=source.commit,
            expected_source_tree_dirty=False,
            expected_source_tree_sha256=source.digest,
            expected_index_path=_relative(index_path),
            expected_index_sha256=verified.sha256,
            expected_index_generated_at=index["generated_at"],
            expected_c_archive=archives[0],
            expected_android_aar_sha256=indexed_aar_sha256,
            expected_android_runtime_run_id=indexed_runtime_id,
            expected_android_runtime_proof_sha256=indexed_runtime_sha256,
        ),
    )
    section: dict[str, object] = {
        "android_runtime_proof_sha256": android.snapshot.file.sha256,
        "android_runtime_run_id": android.section["run_id"],
        "channel": "release",
        "consumer_receipt_generated_at": receipt.value.get("generated_at"),
        "consumer_receipt_path": _relative(receipt_path),
        "consumer_receipt_run_id": consumer_run_id,
        "consumer_receipt_schema": LOCAL_RELEASE_CONSUMER_RECEIPT_SCHEMA_VERSION,
        "consumer_receipt_sha256": receipt.file.sha256,
        "consumer_status": receipt.value.get("status"),
        "current_source_status": "current_clean_tree_local_index_consumer_pass",
        "generated_at": index.get("generated_at"),
        "index_path": _relative(index_path),
        "index_schema": index.get("schema_version"),
        "index_sha256": verified.sha256,
        "proof_source_tree_sha256": source.digest,
        "source_commit": source.commit,
        "source_tree_dirty": False,
        "status": "pass",
    }
    return IndexProjection(
        verified=verified,
        file=index_file,
        receipt=receipt,
        section=section,
    )


def _performance_projection(
    selector: str,
    source: SourceIdentity,
) -> tuple[dict[str, object], EvidencePin]:
    selector = _short_selector(selector, "performance proof")
    proof_path = REPOSITORY_ROOT / "target" / "performance" / selector
    try:
        snapshot = load_json_object_snapshot(
            proof_path,
            maximum=performance_gate.MAX_PERFORMANCE_PROOF_BYTES,
            label="performance proof",
        )
    except EvidenceIOError as exc:
        raise SourceResultsAssemblerError(str(exc)) from exc
    args = argparse.Namespace(
        root=REPOSITORY_ROOT,
        proof=proof_path,
        max_age_seconds=PROOF_MAX_AGE_SECONDS,
        allow_dirty=False,
        allow_uncontrolled=False,
        results_manifest="",
        expected_results_manifest_sha256="",
    )
    _domain_call("performance proof", lambda: performance_gate.verify(args))
    proof = snapshot.value
    _require(
        proof.get("git_commit") == source.commit
        and proof.get("proof_source_tree_sha256") == source.digest
        and proof.get("source_tree_dirty") is False,
        "performance proof source identity differs from HEAD",
    )
    section: dict[str, object] = {
        "current_source_status": "current_controlled_pass",
        "proof_generated_at": proof.get("generated_at"),
        "proof_path": _relative(proof_path),
        "proof_schema": proof.get("schema_version"),
        "proof_sha256": snapshot.file.sha256,
        "proof_source_tree_sha256": source.digest,
        "source_commit": source.commit,
        "source_tree_dirty": False,
        "status": "pass",
    }
    return section, _pin(
        snapshot.file,
        maximum=performance_gate.MAX_PERFORMANCE_PROOF_BYTES,
        label="performance proof",
    )


def _verify_source_domains(
    source: SourceIdentity,
    selectors: SourceEvidenceSelectors,
) -> VerifiedSourceDomains:
    """Deep-verify every domain required by the stable source successor."""

    pins: list[EvidencePin] = []
    rust_section, rust_pins, rust_handoff = _rust_projection(
        source,
        selectors.rust_handoff_manifest,
        selectors.rust_handoff_sha256,
    )
    pins.extend(rust_pins)
    aar_section, aar_pins = _aar_projection(source)
    pins.extend(aar_pins)
    android = _android_projection(
        selectors.android_runtime_run,
        source,
        physical=False,
    )
    pins.append(
        _pin(
            android.snapshot.file,
            maximum=ANDROID_PROOF_MAX_BYTES,
            label="canonical Android proof",
        )
    )
    apple = _apple_projection(selectors.apple_matrix_run, source)
    pins.extend(
        (
            _pin(
                apple.matrix.file,
                maximum=apple_device_proof.MAX_APPLE_PROOF_BYTES,
                label="Apple matrix proof",
            ),
            _pin(
                apple.child.file,
                maximum=apple_device_proof.MAX_APPLE_PROOF_BYTES,
                label="Apple ipad child proof",
            ),
        )
    )
    physical = _android_projection(
        selectors.android_physical_run,
        source,
        physical=True,
    )
    pins.append(
        _pin(
            physical.snapshot.file,
            maximum=ANDROID_PROOF_MAX_BYTES,
            label="physical Android proof",
        )
    )
    index = _index_projection(
        source,
        selectors.consumer_run,
        android,
        apple,
        aar_section,
    )
    pins.extend(
        (
            _pin(
                index.file,
                maximum=release_index.MAX_TEXT_BYTES,
                label="local release index",
            ),
            _pin(
                index.receipt.file,
                maximum=release_consumer_smoke.MAX_CONSUMER_RECEIPT_BYTES,
                label="local release consumer receipt",
            ),
        )
    )
    performance_section, performance_pin = _performance_projection(
        selectors.performance_proof,
        source,
    )
    pins.append(performance_pin)
    return VerifiedSourceDomains(
        rust_section=rust_section,
        aar_section=aar_section,
        android=android,
        apple=apple,
        index=index,
        physical=physical,
        performance_section=performance_section,
        pins=tuple(pins),
        rust_handoff=rust_handoff,
    )


def plan_authorized_mutations(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> None:
    """Prove that assembly touched only source-bound result sections."""

    allowed_added = {"android_physical_runtime"} - set(previous)
    _require(
        set(current) == set(previous) | allowed_added,
        "source results assembly added or removed an unauthorized top-level section",
    )
    for key in previous:
        if key not in _MUTABLE_TOP_LEVEL:
            _require(
                _json_equal(previous[key], current[key]),
                f"source results assembly changed forbidden section {key!r}",
            )
    previous_provenance = _object(previous.get("provenance"), "previous provenance")
    current_provenance = _object(current.get("provenance"), "current provenance")
    _require(
        previous_provenance.keys() == current_provenance.keys(),
        "source results assembly changed provenance fields",
    )
    for key in previous_provenance:
        if key != "snapshot_commit":
            _require(
                _json_equal(previous_provenance[key], current_provenance[key]),
                f"source results assembly changed forbidden provenance field {key!r}",
            )
    exact_sections = (
        ("android_aar", ANDROID_AAR_SECTION_FIELDS),
        ("android_device_runtime", ANDROID_RUNTIME_SECTION_FIELDS),
        ("apple_device", APPLE_SECTION_FIELDS),
        ("local_release_index", LOCAL_INDEX_SECTION_FIELDS),
        ("rust_publish", RUST_PACKAGE_CURRENT_SECTION_FIELDS),
    )
    for section_name, expected_fields in exact_sections:
        section = _object(current.get(section_name), section_name)
        _require(
            set(section) == set(expected_fields),
            f"source results {section_name} projection fields differ: "
            f"missing={sorted(set(expected_fields) - set(section))}, "
            f"extra={sorted(set(section) - set(expected_fields))}",
        )
    physical = _object(
        current.get("android_physical_runtime"),
        "android_physical_runtime",
    )
    _require(
        set(physical) == set(ANDROID_RUNTIME_SECTION_FIELDS),
        "physical Android projection fields differ",
    )
    _require(
        physical.get("current_source_status")
        == "current_clean_tree_physical_pass",
        "stable source results require current physical Android evidence",
    )
    performance = _object(current.get("performance"), "performance")
    _require(
        set(performance) == set(PERFORMANCE_SECTION_FIELDS),
        "performance projection fields differ",
    )
    _require(
        performance.get("current_source_status") == "current_controlled_pass",
        "stable source results require current performance evidence",
    )
    proof_inputs = _object(
        current.get("proof_to_byte_inputs"),
        "proof_to_byte_inputs",
    )
    _require(
        set(proof_inputs) == set(PROOF_TO_BYTE_INPUT_PATHS),
        "source results proof-input projection is not the canonical map",
    )
    for key, digest in proof_inputs.items():
        _require(
            isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
            f"source results proof-input digest is malformed: {key}",
        )
    _require(
        _json_equal(
            current.get("swift_xcframework"),
            neutral_swift_selector(previous),
        ),
        "source results did not perform the exact one-time Swift selector migration",
    )


def assemble_source_results_document(
    previous: dict[str, Any],
    *,
    source: SourceIdentity,
    proof_inputs: dict[str, str],
    footprint: dict[str, object],
    rust_section: dict[str, object],
    aar_section: dict[str, object],
    android_section: dict[str, object],
    apple_section: dict[str, object],
    index_section: dict[str, object],
    physical_section: dict[str, object],
    performance_section: dict[str, object],
) -> dict[str, Any]:
    """Purely apply verified projections to one immutable baseline document."""

    current = copy.deepcopy(previous)
    current["proof_source_tree_sha256"] = source.digest
    current["proof_to_byte_inputs"] = copy.deepcopy(proof_inputs)
    provenance = _object(current.get("provenance"), "provenance")
    provenance["snapshot_commit"] = source.commit
    current["footprint_bytes"] = copy.deepcopy(footprint)
    current["rust_publish"] = copy.deepcopy(rust_section)
    current["android_aar"] = copy.deepcopy(aar_section)
    current["android_device_runtime"] = copy.deepcopy(android_section)
    current["apple_device"] = copy.deepcopy(apple_section)
    current["local_release_index"] = copy.deepcopy(index_section)
    current["swift_xcframework"] = neutral_swift_selector(previous)
    current["android_physical_runtime"] = copy.deepcopy(physical_section)
    current["performance"] = copy.deepcopy(performance_section)
    plan_authorized_mutations(previous, current)
    _validate_initial_publication_state(current)
    try:
        validate_declared_currentness(current)
        validate_stable_source_currentness(current)
        validate_release_publications(current)
        validate_release_publication_transition(previous, current)
    except (ProofManifestError, ReleasePublicationContractError) as exc:
        raise SourceResultsAssemblerError(str(exc)) from exc
    return current


def _validate_assembled_results(
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    android: AndroidProjection,
    physical: AndroidProjection,
) -> None:
    plan_authorized_mutations(previous, current)
    android_elf.verify_results_aar_projection(
        current,
        load_json_object_snapshot(
            ANDROID_AAR_MANIFEST_FILE,
            maximum=16 * 1024 * 1024,
            label="Android 0.1.0 stable AAR manifest projection",
        ).value,
    )
    _domain_call(
        "canonical Android results projection",
        lambda: android_device_proof.verify_results_manifest_projection(
            current,
            android.snapshot.value,
            results_binding="android_runtime",
        ),
    )
    _domain_call(
        "physical Android results projection",
        lambda: android_device_proof.verify_results_manifest_projection(
            current,
            physical.snapshot.value,
            results_binding="android_physical_runtime",
        ),
    )


def _validate_verified_domain_projections(
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    verified: VerifiedSourceDomains,
) -> None:
    """Match one already deep-verified domain closure to its pure projections."""

    expected_sections: tuple[tuple[str, object, object], ...] = (
        ("Rust package", current.get("rust_publish"), verified.rust_section),
        ("Android AAR", current.get("android_aar"), verified.aar_section),
        (
            "canonical Android",
            current.get("android_device_runtime"),
            verified.android.section,
        ),
        ("Apple matrix", current.get("apple_device"), verified.apple.section),
        (
            "local release index",
            current.get("local_release_index"),
            verified.index.section,
        ),
    )
    for label, selected, rechecked in expected_sections:
        _require(
            _json_equal(selected, rechecked),
            f"{label} projection changed during full domain revalidation",
        )
    _require(
        _json_equal(
            current.get("android_physical_runtime"),
            verified.physical.section,
        ),
        "physical Android projection changed during full domain revalidation",
    )
    _require(
        _json_equal(
            current.get("performance"),
            verified.performance_section,
        ),
        "performance projection changed during full domain revalidation",
    )
    _validate_assembled_results(
        previous,
        current,
        android=verified.android,
        physical=verified.physical,
    )


def _verify_domain_closure(
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    source: SourceIdentity,
    selectors: SourceEvidenceSelectors,
) -> tuple[EvidencePin, ...]:
    """Deep-reopen the complete raw evidence closure and match every projection."""

    verified = _verify_source_domains(source, selectors)
    _validate_verified_domain_projections(
        previous,
        current,
        verified=verified,
    )
    _resample_verified_domains(verified)
    return verified.pins


def _assemble_source_results(
    expected_results_sha256: str,
    *,
    proof_inputs: dict[str, str],
    rust_handoff_manifest: str,
    rust_handoff_sha256: str,
    android_runtime_run: str,
    apple_matrix_run: str,
    consumer_run: str,
    android_physical_run: str,
    performance_proof: str,
) -> tuple[dict[str, Any], SourceIdentity, VerifiedSourceDomains]:
    """Build and validate one complete initial source-bound successor value."""

    previous = validate_baseline(expected_results_sha256)
    source = _source_identity()
    selectors = SourceEvidenceSelectors(
        rust_handoff_manifest=rust_handoff_manifest,
        rust_handoff_sha256=rust_handoff_sha256,
        android_runtime_run=android_runtime_run,
        apple_matrix_run=apple_matrix_run,
        consumer_run=consumer_run,
        android_physical_run=android_physical_run,
        performance_proof=performance_proof,
    )
    domains = _verify_source_domains(source, selectors)
    footprint, footprint_sha256 = load_footprint_manifest_section(FOOTPRINT_PATH)

    current = assemble_source_results_document(
        previous,
        source=source,
        proof_inputs=proof_inputs,
        footprint=footprint,
        rust_section=domains.rust_section,
        aar_section=domains.aar_section,
        android_section=domains.android.section,
        apple_section=domains.apple.section,
        index_section=domains.index.section,
        physical_section=domains.physical.section,
        performance_section=domains.performance_section,
    )
    _validate_verified_domain_projections(
        previous,
        current,
        verified=domains,
    )
    _resample_verified_domains(domains)
    _stable_source_identity(source)
    verified_footprint, verified_footprint_sha256 = load_footprint_manifest_section(
        FOOTPRINT_PATH
    )
    _require(
        footprint_sha256 == verified_footprint_sha256
        and _json_equal(footprint, verified_footprint),
        "footprint CSV changed while results were assembled",
    )
    _require(
        validate_baseline(expected_results_sha256) is not None,
        "results baseline changed while results were assembled",
    )
    return current, source, domains


def assemble_source_results(
    expected_results_sha256: str,
    *,
    rust_handoff_manifest: str,
    rust_handoff_sha256: str,
    android_runtime_run: str,
    apple_matrix_run: str,
    consumer_run: str,
    android_physical_run: str,
    performance_proof: str,
) -> tuple[dict[str, Any], SourceIdentity, list[EvidencePin]]:
    """Build one successor between two bounded full proof-input snapshots."""

    proof_inputs = capture_proof_input_digests(REPOSITORY_ROOT)
    current, source, domains = _assemble_source_results(
        expected_results_sha256,
        proof_inputs=proof_inputs,
        rust_handoff_manifest=rust_handoff_manifest,
        rust_handoff_sha256=rust_handoff_sha256,
        android_runtime_run=android_runtime_run,
        apple_matrix_run=apple_matrix_run,
        consumer_run=consumer_run,
        android_physical_run=android_physical_run,
        performance_proof=performance_proof,
    )
    _require(
        capture_proof_input_digests(REPOSITORY_ROOT) == proof_inputs,
        "proof inputs changed while source results were assembled",
    )
    return current, source, list(domains.pins)


def finalize_source_results(
    expected_results_sha256: str,
    *,
    rust_handoff_manifest: str,
    rust_handoff_sha256: str,
    android_runtime_run: str,
    apple_matrix_run: str,
    consumer_run: str,
    android_physical_run: str,
    performance_proof: str,
) -> tuple[pathlib.Path, str, SourceIdentity]:
    """Publish one complete source successor candidate without replacement."""

    path: pathlib.Path | None = None
    digest: str | None = None
    try:
        proof_inputs = capture_proof_input_digests(REPOSITORY_ROOT)
        current, source, domains = _assemble_source_results(
            expected_results_sha256,
            proof_inputs=proof_inputs,
            rust_handoff_manifest=rust_handoff_manifest,
            rust_handoff_sha256=rust_handoff_sha256,
            android_runtime_run=android_runtime_run,
            apple_matrix_run=apple_matrix_run,
            consumer_run=consumer_run,
            android_physical_run=android_physical_run,
            performance_proof=performance_proof,
        )
        _require(
            capture_proof_input_digests(REPOSITORY_ROOT) == proof_inputs,
            "proof inputs changed before candidate publication",
        )
        path, digest = create_private_transaction_json(
            safe_root=SOURCE_RESULTS_ROOT,
            transaction_prefix="transaction.",
            expected_leaf=SOURCE_RESULTS_LEAF,
            value=current,
            label="source results successor",
            maximum=RESULTS_MAX_BYTES,
        )
        try:
            previous = validate_baseline(expected_results_sha256)
            _validate_verified_domain_projections(
                previous,
                current,
                verified=domains,
            )
            _resample_verified_domains(domains)
            verified_footprint, _ = load_footprint_manifest_section(
                FOOTPRINT_PATH
            )
            _require(
                _json_equal(current.get("footprint_bytes"), verified_footprint),
                "footprint changed after candidate publication",
            )
            _require(
                capture_proof_input_digests(REPOSITORY_ROOT) == proof_inputs,
                "proof inputs changed after candidate publication",
            )
            _stable_source_identity(source)
            validate_baseline(expected_results_sha256)
        except BaseException as exc:
            raise CommittedSourceResultsError(
                path,
                digest,
                "postcommit_recheck",
            ) from exc
        _require(
            path is not None and digest is not None,
            "publication returned no candidate",
        )
        return path, digest, source
    except (PublicationReceiptCommittedError, CommittedSourceResultsError):
        raise


def _installed_selectors(current: dict[str, Any]) -> SourceEvidenceSelectors:
    rust = _object(current.get("rust_publish"), "installed Rust package contract")
    rust_handoff_manifest = rust.get("handoff_manifest_path")
    rust_handoff_sha256 = rust.get("handoff_manifest_sha256")
    _require(
        isinstance(rust_handoff_manifest, str)
        and isinstance(rust_handoff_sha256, str)
        and SHA256_RE.fullmatch(rust_handoff_sha256) is not None,
        "installed Rust package handoff selector is malformed",
    )
    _rust_handoff_manifest_path(rust_handoff_manifest)

    android = _object(
        current.get("android_device_runtime"),
        "installed Android runtime",
    )
    android_run = _run_id(android.get("run_id"), "installed Android runtime run")
    _require(
        android.get("proof_path") == _relative(_android_proof_path(android_run)),
        "installed Android runtime proof path differs from its run identity",
    )

    apple = _object(current.get("apple_device"), "installed Apple matrix")
    matrix_path = apple.get("matrix_proof_path")
    _require(isinstance(matrix_path, str), "installed Apple matrix path is malformed")
    matrix_parts = pathlib.PurePosixPath(matrix_path).parts
    _require(
        len(matrix_parts) == 4
        and matrix_parts[:2] == ("artifact", "device-runs")
        and matrix_parts[3] == "apple-device-matrix-proof.json",
        "installed Apple matrix path differs from the fixed evidence root",
    )
    apple_run = _short_selector(matrix_parts[2], "installed Apple matrix run")

    index = _object(current.get("local_release_index"), "installed local index")
    consumer_run = _run_id(
        index.get("consumer_receipt_run_id"),
        "installed consumer receipt run",
    )
    expected_receipt = (
        CONSUMER_RECEIPTS_ROOT
        / consumer_run
        / release_consumer_smoke.CONSUMER_RECEIPT_LEAF
    )
    _require(
        index.get("consumer_receipt_path") == _relative(expected_receipt),
        "installed consumer receipt path differs from its run identity",
    )

    physical_section = _object(
        current.get("android_physical_runtime"),
        "installed physical Android runtime",
    )
    physical_status = physical_section.get("current_source_status")
    _require(
        physical_status == "current_clean_tree_physical_pass",
        "installed stable source results require current physical Android evidence",
    )
    physical_run = _run_id(
        physical_section.get("run_id"),
        "installed physical Android run",
    )
    _require(
        physical_section.get("proof_path")
        == _relative(_android_proof_path(physical_run)),
        "installed physical Android proof path differs from its run identity",
    )

    performance = _object(current.get("performance"), "installed performance")
    performance_status = performance.get("current_source_status")
    _require(
        performance_status == "current_controlled_pass",
        "installed stable source results require current performance evidence",
    )
    performance_path = performance.get("proof_path")
    _require(
        isinstance(performance_path, str),
        "installed performance proof path is malformed",
    )
    performance_parts = pathlib.PurePosixPath(performance_path).parts
    _require(
        len(performance_parts) == 3
        and performance_parts[:2] == ("target", "performance"),
        "installed performance proof path differs from the fixed evidence root",
    )
    performance_selector = _short_selector(
        performance_parts[2],
        "installed performance proof",
    )
    return SourceEvidenceSelectors(
        rust_handoff_manifest=rust_handoff_manifest,
        rust_handoff_sha256=rust_handoff_sha256,
        android_runtime_run=android_run,
        apple_matrix_run=apple_run,
        consumer_run=consumer_run,
        android_physical_run=physical_run,
        performance_proof=performance_selector,
    )


def _installed_worktree_identity(
    results_commit: str,
    source_digest: str,
) -> None:
    try:
        inspection = inspect_worktree(REPOSITORY_ROOT)
        digest = canonical_tree_digest(
            REPOSITORY_ROOT,
            repository_paths(REPOSITORY_ROOT),
        )
    except (GitProvenanceError, LedgerError) as exc:
        raise SourceResultsAssemblerError(
            "cannot establish the installed source-results identity"
        ) from exc
    _require(
        not inspection.dirty
        and inspection.commit == results_commit
        and digest == source_digest,
        "installed source-results worktree identity is not stable",
    )


def verify_installed_source_successor(expected_results_sha256: str) -> str:
    """Verify that HEAD is the exact installed S-to-R results-only commit."""

    current = validate_baseline(
        expected_results_sha256,
        require_initial=False,
    )
    provenance = _object(current.get("provenance"), "source results provenance")
    source_commit = provenance.get("snapshot_commit")
    source_digest = current.get("proof_source_tree_sha256")
    _require(
        isinstance(source_commit, str)
        and COMMIT_RE.fullmatch(source_commit) is not None
        and isinstance(source_digest, str)
        and SHA256_RE.fullmatch(source_digest) is not None,
        "installed source results identity is malformed",
    )
    try:
        results_commit = require_direct_results_only_successor(
            REPOSITORY_ROOT,
            source_commit,
        )
        source_bytes = _load_git_results_bytes(
            source_commit,
            label="source-parent results baseline",
        )
    except GitProvenanceError as exc:
        raise SourceResultsAssemblerError(
            "installed results-only Git transition is invalid"
        ) from exc
    try:
        previous_value = parse_strict_json_bytes(
            source_bytes,
            label="source-parent results baseline",
        )
    except EvidenceIOError as exc:
        raise SourceResultsAssemblerError(
            "source-parent results baseline is not strict JSON"
        ) from exc
    previous = _object(previous_value, "source-parent results baseline")
    _validate_baseline_document_shape(previous, require_initial=True)
    plan_authorized_mutations(previous, current)
    try:
        validate_declared_currentness(current)
        validate_stable_source_currentness(current)
        validate_release_publications(current)
        validate_release_publication_transition(previous, current)
    except (ProofManifestError, ReleasePublicationContractError) as exc:
        raise SourceResultsAssemblerError(
            "installed source-results contract is invalid"
        ) from exc
    source = SourceIdentity(commit=source_commit, digest=source_digest)
    _installed_worktree_identity(results_commit, source.digest)
    selectors = _installed_selectors(current)
    _verify_domain_closure(
        previous,
        current,
        source=source,
        selectors=selectors,
    )
    proof_inputs = current.get("proof_to_byte_inputs")
    _require(
        isinstance(proof_inputs, dict),
        "installed source results lacks proof_to_byte_inputs",
    )
    verify_proof_input_digests(REPOSITORY_ROOT, proof_inputs)
    footprint, _footprint_sha256 = load_footprint_manifest_section(FOOTPRINT_PATH)
    _require(
        _json_equal(current.get("footprint_bytes"), footprint),
        "installed source results footprint differs from the canonical CSV",
    )
    _installed_worktree_identity(results_commit, source.digest)
    validate_baseline(expected_results_sha256, require_initial=False)
    return results_commit


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    finalize = commands.add_parser("finalize")
    finalize.add_argument("expected_results_sha256")
    finalize.add_argument("--rust-handoff-manifest", required=True)
    finalize.add_argument("--rust-handoff-sha256", required=True)
    finalize.add_argument("--android-runtime-run", required=True)
    finalize.add_argument("--apple-matrix-run", required=True)
    finalize.add_argument("--consumer-run", required=True)
    finalize.add_argument("--android-physical-run", required=True)
    finalize.add_argument("--performance-proof", required=True)
    verify = commands.add_parser("verify-installed")
    verify.add_argument("expected_results_sha256")
    ci_gate = commands.add_parser("ci-source-gate")
    ci_gate.add_argument("expected_results_sha256")
    ci_gate.add_argument("expected_commit")
    return parser


def run(args: argparse.Namespace) -> None:
    if args.command == "ci-source-gate":
        mode, source = source_ci_gate(
            args.expected_results_sha256,
            args.expected_commit,
        )
        if mode == "initial":
            print(
                "SOURCE_TRANSITION_READINESS_PASS mode=initial "
                f"commit={source.commit} results_sha256={args.expected_results_sha256} "
                "proof_inputs=237 declared_delta=47"
            )
        else:
            print(
                "SOURCE_CI_GATE_MODE mode=installed "
                f"commit={source.commit} results_sha256={args.expected_results_sha256} "
                "proof_inputs=237"
            )
        return
    if args.command == "verify-installed":
        commit = verify_installed_source_successor(args.expected_results_sha256)
        print(f"SOURCE_RESULTS_INSTALLED_VERIFY_PASS commit={commit}")
        return
    path, digest, source = finalize_source_results(
        args.expected_results_sha256,
        rust_handoff_manifest=args.rust_handoff_manifest,
        rust_handoff_sha256=args.rust_handoff_sha256,
        android_runtime_run=args.android_runtime_run,
        apple_matrix_run=args.apple_matrix_run,
        consumer_run=args.consumer_run,
        android_physical_run=args.android_physical_run,
        performance_proof=args.performance_proof,
    )
    print(
        "SOURCE_RESULTS_SUCCESSOR_PASS "
        f"path={_relative(path)} sha256={digest} "
        f"source_commit={source.commit} source_sha256={source.digest}"
    )


def _safe_marker_leaf(value: object) -> str:
    if (
        isinstance(value, str)
        and SAFE_SELECTOR_RE.fullmatch(value) is not None
        and value not in {".", ".."}
    ):
        return value
    return "-"


def _safe_marker_digest(value: object) -> str:
    return value if isinstance(value, str) and SHA256_RE.fullmatch(value) else "-"


def _safe_candidate_marker_path(path: object) -> str:
    if not isinstance(path, pathlib.Path):
        return "-"
    try:
        relative = path.relative_to(SOURCE_RESULTS_ROOT)
    except ValueError:
        return "-"
    if (
        len(relative.parts) != 2
        or not relative.parts[0].startswith("transaction.")
        or SAFE_SELECTOR_RE.fullmatch(relative.parts[0]) is None
        or relative.parts[1] != SOURCE_RESULTS_LEAF
    ):
        return "-"
    return (
        "target/source-results-successors/"
        f"{relative.parts[0]}/{SOURCE_RESULTS_LEAF}"
    )


def _cli_error_category(exc: BaseException) -> str:
    if isinstance(exc, ProofToByteInputsError):
        return "proof_inputs_invalid"
    if isinstance(exc, PublicationReceiptIOError):
        return "publication_io_invalid"
    if isinstance(exc, EvidenceIOError):
        return "evidence_invalid"
    if isinstance(exc, FinalizerError):
        return "baseline_invalid"
    if isinstance(exc, OSError):
        return "filesystem_error"
    return "source_results_invalid"


def main() -> int:
    try:
        run(_parser().parse_args())
    except PublicationReceiptCommittedError as exc:
        print(
            "SOURCE_RESULTS_PUBLICATION_COMMITTED_ERROR "
            f"visibility={exc.visibility} leaf={_safe_marker_leaf(exc.leaf)} "
            f"path={_safe_candidate_marker_path(exc.path)} "
            f"sha256={_safe_marker_digest(exc.digest)}",
            file=sys.stderr,
        )
        return 125
    except CommittedSourceResultsError as exc:
        print(
            "SOURCE_RESULTS_POSTCOMMIT_RECHECK_ERROR "
            f"stage={exc.stage} path={_safe_candidate_marker_path(exc.path)} "
            f"sha256={_safe_marker_digest(exc.digest)}",
            file=sys.stderr,
        )
        return 125
    except (
        SourceResultsAssemblerError,
        ProofToByteInputsError,
        PublicationReceiptIOError,
        EvidenceIOError,
        FinalizerError,
        android_elf.AndroidVerificationError,
        performance_gate.GateError,
        rust_publish_contract.RustPublishContractError,
        OSError,
    ) as exc:
        print(
            f"SOURCE_RESULTS_ERROR category={_cli_error_category(exc)}",
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        print("SOURCE_RESULTS_ERROR category=interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
