#!/usr/bin/env python3
"""Assemble and promote the exact Apple 0.1.3 stable publication receipt.

The pending producer consumes only the completed credentialed-build ledger and
the fixed public distribution copy.  Promotion consumes the pending results
snapshot, one sanitized GitHub projection, and one structured fresh-consumer
receipt.  Neither CLI accepts a status or an output path.
"""

from __future__ import annotations

import contextlib
import copy
import datetime as dt
import os
import pathlib
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Never

import apple_distribution
import apple_publication_contract as apple_contract
from bounded_process import BoundedProcessError, capture_stdout
from claim_ledger import LedgerError, canonical_tree_digest, repository_paths
from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    consume_regular_snapshot_at,
    load_json_object_snapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from git_provenance import (
    GitProvenanceError,
    inspect_worktree,
    require_direct_results_only_child,
    require_commit_or_evidence_successor,
    run_git_text,
)
from publication_receipt_io import (
    PRIVATE_FILE_MODE,
    PUBLIC_FILE_MODE,
    PrivateDirectoryHandle,
    PublicationReceiptCommittedError,
    PublicationReceiptIOError,
    create_private_transaction_json,
    normalize_safe_root,
    open_private_direct_child_handle,
    open_private_directory_at,
    prepare_private_json_noreplace_at,
    read_fixed_file_snapshot,
    read_fixed_json_snapshot,
    verify_exact_directory_inventory_at,
    verify_private_directory_handle_identity,
    sync_private_directory_parent,
)


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS_PATH = REPOSITORY_ROOT / "artifact" / "results.json"
APPLE_COMPLETION_ROOT = (
    REPOSITORY_ROOT / "target" / "qperiapt-apple-release-worktrees"
)
APPLE_PUBLIC_ROOT = REPOSITORY_ROOT / "target" / "qperiapt-swift-xcframework"
APPLE_PUBLIC_DISTRIBUTION_NAME = "q-periapt-swift-0.1.3"
APPLE_PUBLIC_DISTRIBUTION = APPLE_PUBLIC_ROOT / APPLE_PUBLIC_DISTRIBUTION_NAME
APPLE_PUBLICATION_RECEIPT_ROOT = (
    REPOSITORY_ROOT / "target" / "qperiapt-apple-publication-receipts"
)
APPLE_PUBLICATION_RECEIPT_NAME = "apple-v0.1.3-publication-receipt.json"
APPLE_RELEASE_PROJECTION_ROOT = (
    REPOSITORY_ROOT
    / "target"
    / "qperiapt-apple-release-verification"
    / "projections"
)
APPLE_RELEASE_PROJECTION_NAME = "apple-github-release-verification.json"
APPLE_RELEASE_PROJECTION_KIND = "qperiapt.apple_github_release_verification"
APPLE_RELEASE_PROJECTION_SCHEMA_VERSION = 1
APPLE_RELEASE_REPOSITORY = "billlza/q-periapt"
APPLE_RELEASE_TIMESTAMP_AUTHORITY_TYPE = "TimestampAuthority"
APPLE_RELEASE_TIMESTAMP_AUTHORITY_URI = "timestamp.githubapp.com"
REMOTE_CONSUMER_RUNS_ROOT = (
    REPOSITORY_ROOT / "target" / "qperiapt-swift-remote-consumer-runs"
)
REMOTE_CONSUMER_TRANSACTION = re.compile(
    r"^transaction\.[0-9A-Za-z][0-9A-Za-z._-]{5,127}$"
)
REMOTE_CONSUMER_RECEIPT_NAME = "apple-remote-consumer-receipt.json"
REMOTE_CONSUMER_LOG_NAME = "swift-url-binary-consumer.log"
REMOTE_CONSUMER_RELEASE_ASSETS_NAME = "release-assets"
REMOTE_CONSUMER_RESULTS_RELATIVE = pathlib.PurePosixPath(
    "verifier-inputs/artifact/results.json"
)

COMPLETION_LEDGER_NAME = "completed.json"
COMPLETION_LEDGER_KIND = "qperiapt.apple_static_xcframework_release_completion"
COMPLETION_LEDGER_SCHEMA_VERSION = 2
REMOTE_CONSUMER_RECEIPT_KIND = "qperiapt.apple_remote_consumer_receipt"
REMOTE_CONSUMER_RECEIPT_SCHEMA_VERSION = 1
REMOTE_CONSUMER_BOUNDARY = (
    "Atomic evidence commit for one fresh Apple 0.1.3 stable URL binary consumer "
    "run: four exact downloaded assets, deep distribution and code-signature "
    "verification, three passing Swift tests without warning/error diagnostics, "
    "the pinned pending results bytes, artifact source commit, and clean verifier "
    "commit. Post-commit snapshot and lock cleanup are outside this receipt."
)
APPLE_EXPECTED_TEAM_ID = "YKUPL7Z869"
APPLE_EXPECTED_CERTIFICATE_SHA256 = (
    "806673908a3ddcd558dcc8d3ef055085f1fff100bda0acfb2e1315afd652ac8d"
)
APPLE_PUBLIC_DIRECTORY_ENTRIES = frozenset(
    {*apple_contract.APPLE_PUBLIC_ASSET_NAMES, "CQPeriapt.xcframework"}
)

MAX_LEDGER_BYTES = 1024 * 1024
MAX_PROJECTION_BYTES = 4 * 1024 * 1024
MAX_REMOTE_RECEIPT_BYTES = 1024 * 1024
MAX_REMOTE_LOG_BYTES = 16 * 1024 * 1024
MAX_RESULTS_BYTES = 16 * 1024 * 1024
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
WARNING_OR_ERROR = re.compile(r"(^|[^A-Za-z])(warning|error):", re.IGNORECASE)
# XCTest prints the grand-total "Executed N tests, with 0 failures" line once per
# suite level (the bundle suite, the test-class suite, and the outer "All tests"
# suite), so a clean three-test run emits the passing summary two or three times,
# never exactly once. Require at least one exact three-test pass and reject any
# summary that reports a nonzero failure count.
THREE_TEST_PASS = "Executed 3 tests, with 0 failures"
TEST_FAILURE_SUMMARY = re.compile(r"Executed \d+ tests?, with [1-9][0-9]* failures?")

Clock = Callable[[], dt.datetime]


class AppleStablePublicationError(ValueError):
    """Apple 0.1.3 stable receipt evidence or state transition is invalid."""


@dataclass(frozen=True, slots=True)
class _RemoteConsumerLayout:
    verifier_source: PrivateDirectoryHandle
    verifier_artifact: PrivateDirectoryHandle
    verifier_target: PrivateDirectoryHandle
    release_assets: PrivateDirectoryHandle
    extracted: PrivateDirectoryHandle
    extracted_xcframework: PrivateDirectoryHandle


def _fail(message: str) -> Never:
    raise AppleStablePublicationError(message)


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


def _exact_keys(
    value: Mapping[str, object],
    expected: frozenset[str],
    label: str,
) -> None:
    actual = frozenset(value)
    _require(
        actual == expected,
        f"{label} keys differ: missing={sorted(expected - actual)!r} "
        f"extra={sorted(actual - expected)!r}",
    )


def _sha1(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and HEX_40.fullmatch(value) is not None,
        f"{label} must be a lowercase SHA-1",
    )
    return value


def _sha256(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and HEX_64.fullmatch(value) is not None,
        f"{label} must be a lowercase SHA-256",
    )
    return value


def _public_asset_sha256s(
    distribution: dict[str, object],
) -> dict[str, str]:
    try:
        return apple_contract.apple_public_asset_sha256s(distribution)
    except apple_contract.ApplePublicationContractError as exc:
        raise AppleStablePublicationError(
            f"Apple public asset digest projection failed: {exc}"
        ) from exc


def _timestamp(value: object, label: str) -> dt.datetime:
    _require(isinstance(value, str), f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise AppleStablePublicationError(
            f"{label} must be an RFC3339 UTC timestamp"
        ) from exc
    return parsed.replace(tzinfo=dt.UTC)


def _system_clock() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _owned_file_metadata(
    metadata: os.stat_result,
    *,
    mode: int,
    label: str,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != 1
    ):
        raise EvidenceIOError(f"{label} metadata differs")


def _read_results_snapshot(expected_sha256: str) -> tuple[dict[str, Any], str]:
    """Read and validate the one fixed current results snapshot exactly once."""

    expected_sha256 = _sha256(expected_sha256, "expected results snapshot")
    try:
        snapshot = read_regular_snapshot(
            RESULTS_PATH,
            maximum=MAX_RESULTS_BYTES,
            label="current results manifest",
            validate_metadata=lambda metadata: _owned_file_metadata(
                metadata,
                mode=PUBLIC_FILE_MODE,
                label="current results manifest",
            ),
        )
        value = parse_strict_json_bytes(
            snapshot.data,
            label="current results manifest",
        )
    except EvidenceIOError as exc:
        raise AppleStablePublicationError(
            "cannot safely read current results manifest"
        ) from exc
    _require(
        snapshot.sha256 == expected_sha256,
        "current results manifest differs from its startup SHA-256 pin",
    )
    manifest = _object(value, "current results manifest")
    from proof_manifest import ProofManifestError, validate_declared_currentness
    from release_publication_contract import (
        ReleasePublicationContractError,
        validate_release_publications,
        validate_stable_source_currentness,
    )

    try:
        validate_declared_currentness(manifest)
        validate_stable_source_currentness(manifest)
        validate_release_publications(manifest)
    except (ProofManifestError, ReleasePublicationContractError) as exc:
        raise AppleStablePublicationError(str(exc)) from exc
    return manifest, snapshot.sha256


def _source_identity_from_results(
    manifest: dict[str, Any],
) -> tuple[str, str]:
    provenance = _object(
        manifest.get("provenance"), "current results provenance"
    )
    source_parent_commit = _sha1(
        provenance.get("snapshot_commit"), "current results source parent"
    )
    canonical_source_tree_sha256 = _sha256(
        manifest.get("proof_source_tree_sha256"),
        "current results canonical source tree",
    )
    return source_parent_commit, canonical_source_tree_sha256


def _validate_clean_annotated_tag(
    source_parent_commit: str,
    canonical_source_tree_sha256: str,
) -> dict[str, str]:
    """Bind source parent S to clean results-only tagged commit R."""

    tag = apple_contract.APPLE_V0_1_3_IDENTITY["release_tag"]
    try:
        inspection = inspect_worktree(REPOSITORY_ROOT)
        tag_type = run_git_text(
            REPOSITORY_ROOT,
            ["cat-file", "-t", f"refs/tags/{tag}"],
        )
        tag_commit = run_git_text(
            REPOSITORY_ROOT,
            ["rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
        )
        tag_object = run_git_text(
            REPOSITORY_ROOT,
            ["rev-parse", "--verify", f"refs/tags/{tag}"],
        )
        tag_tree = run_git_text(
            REPOSITORY_ROOT,
            ["rev-parse", "--verify", f"refs/tags/{tag}^{{tree}}"],
        )
        require_direct_results_only_child(
            REPOSITORY_ROOT,
            source_parent_commit,
            tag_commit,
        )
        actual_source_digest = canonical_tree_digest(
            REPOSITORY_ROOT,
            repository_paths(REPOSITORY_ROOT),
        )
    except (GitProvenanceError, LedgerError, ValueError) as exc:
        raise AppleStablePublicationError(
            "cannot establish the Apple 0.1.3 stable source/tag boundary"
        ) from exc
    _require(not inspection.dirty, "Apple pending receipt requires a clean worktree")
    _require(
        inspection.commit == tag_commit,
        "Apple clean HEAD and release tag commit differ",
    )
    _require(
        tag_type == "tag"
        and HEX_40.fullmatch(tag_commit) is not None
        and HEX_40.fullmatch(tag_object) is not None
        and HEX_40.fullmatch(tag_tree) is not None
        and tag_object != tag_commit,
        "Apple 0.1.3 stable release tag must be one annotated tag object",
    )
    _require(
        source_parent_commit != tag_commit,
        "Apple tag commit must differ from its source parent",
    )
    _require(
        actual_source_digest == canonical_source_tree_sha256,
        "Apple tagged checkout canonical source digest differs from results",
    )
    return {
        "canonical_source_tree_sha256": canonical_source_tree_sha256,
        "source_parent_commit": source_parent_commit,
        "tag_commit": tag_commit,
        "tag_object": tag_object,
        "tag_tree": tag_tree,
    }


def _load_completion_ledger(path: pathlib.Path) -> tuple[dict[str, Any], str]:
    try:
        snapshot = read_fixed_json_snapshot(
            path,
            safe_root=APPLE_COMPLETION_ROOT,
            expected_leaf=COMPLETION_LEDGER_NAME,
            label="Apple release completion ledger",
            parent_depth=1,
            maximum=MAX_LEDGER_BYTES,
            file_mode=PRIVATE_FILE_MODE,
            expected_parent_entries=frozenset({COMPLETION_LEDGER_NAME}),
        )
    except PublicationReceiptIOError as exc:
        raise AppleStablePublicationError(
            "cannot safely read the Apple release completion ledger"
        ) from exc
    parent = snapshot.file.path.parent
    _require(
        HEX_40.fullmatch(parent.name) is not None,
        "Apple completion transaction directory name is malformed",
    )
    ledger = snapshot.value
    _exact_keys(
        ledger,
        frozenset(
            {
                "kind",
                "public_assets_sha256",
                "release_identity",
                "schema_version",
                "source_commit",
            }
        ),
        "Apple completion ledger",
    )
    _require(
        ledger["kind"] == COMPLETION_LEDGER_KIND
        and type(ledger["schema_version"]) is int
        and ledger["schema_version"] == COMPLETION_LEDGER_SCHEMA_VERSION,
        "Apple completion ledger discriminant differs",
    )
    source_commit = _sha1(
        ledger["source_commit"], "Apple completion source commit"
    )
    _require(
        source_commit == parent.name,
        "Apple completion directory/source binding differs",
    )
    _require(
        ledger["release_identity"]
        == {
            "product_version": apple_distribution.PRODUCT_VERSION,
            "revision": apple_distribution.RELEASE_REVISION,
            "tag": apple_distribution.RELEASE_TAG,
        },
        "Apple completion release identity differs",
    )
    hashes = _object(
        ledger["public_assets_sha256"],
        "Apple completion public asset hashes",
    )
    _exact_keys(
        hashes,
        frozenset(apple_contract.APPLE_PUBLIC_ASSET_NAMES),
        "Apple completion public asset hashes",
    )
    for name in apple_contract.APPLE_PUBLIC_ASSET_NAMES:
        _sha256(hashes[name], f"Apple completion asset digest for {name}")
    return ledger, source_commit


def _public_distribution_entries() -> frozenset[str]:
    root = normalize_safe_root(
        APPLE_PUBLIC_ROOT,
        label="Apple public distribution root",
        required_mode=0o755,
    )
    _require(
        APPLE_PUBLIC_DISTRIBUTION.parent == root,
        "Apple public distribution path differs",
    )
    try:
        metadata = APPLE_PUBLIC_DISTRIBUTION.lstat()
        entries = frozenset(os.listdir(APPLE_PUBLIC_DISTRIBUTION))
    except OSError as exc:
        raise AppleStablePublicationError(
            "cannot inspect Apple public distribution"
        ) from exc
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and not APPLE_PUBLIC_DISTRIBUTION.is_symlink()
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o755,
        "Apple public distribution must be an owned mode-0755 directory",
    )
    _require(
        entries == APPLE_PUBLIC_DIRECTORY_ENTRIES,
        "Apple public distribution entry set differs",
    )
    xcframework = APPLE_PUBLIC_DISTRIBUTION / "CQPeriapt.xcframework"
    try:
        xcframework_metadata = xcframework.lstat()
    except OSError as exc:
        raise AppleStablePublicationError(
            "cannot inspect Apple public XCFramework"
        ) from exc
    _require(
        stat.S_ISDIR(xcframework_metadata.st_mode)
        and not xcframework.is_symlink()
        and xcframework_metadata.st_uid == os.geteuid()
        and stat.S_IMODE(xcframework_metadata.st_mode) == 0o755,
        "Apple public XCFramework directory metadata differs",
    )
    return entries


def _load_public_distribution(
    expected_hashes: Mapping[str, object],
    source_commit: str,
) -> dict[str, object]:
    entries_before = _public_distribution_entries()
    snapshots: dict[str, FileSnapshot] = {}
    for name in apple_contract.APPLE_PUBLIC_ASSET_NAMES:
        maximum = (
            apple_distribution.MAX_ARTIFACT_BYTES
            if name == apple_distribution.XCFRAMEWORK_ZIP_NAME
            else apple_distribution.MAX_TEXT_BYTES
        )
        snapshots[name] = read_fixed_file_snapshot(
            APPLE_PUBLIC_DISTRIBUTION / name,
            safe_root=APPLE_PUBLIC_ROOT,
            expected_leaf=name,
            label=f"Apple public asset {name}",
            parent_depth=1,
            maximum=maximum,
            file_mode=PUBLIC_FILE_MODE,
            root_mode=0o755,
            parent_mode=0o755,
        )
        _require(
            snapshots[name].sha256 == expected_hashes[name],
            f"Apple public asset digest differs for {name}",
        )
    try:
        distribution = (
            apple_distribution.project_trusted_results_candidate_distribution(
                zip_data=snapshots[
                    apple_distribution.XCFRAMEWORK_ZIP_NAME
                ].data,
                apple_distribution_data=snapshots[
                    apple_distribution.APPLE_DISTRIBUTION_NAME
                ].data,
                manifest_data=snapshots[apple_distribution.MANIFEST_NAME].data,
                checksums_data=snapshots[
                    apple_distribution.SHA256SUMS_NAME
                ].data,
                expected_asset_sha256={
                    name: snapshots[name].sha256
                    for name in apple_contract.APPLE_PUBLIC_ASSET_NAMES
                },
                expected_source_commit=source_commit,
                expected_team_id=APPLE_EXPECTED_TEAM_ID,
                expected_certificate_sha256=(
                    APPLE_EXPECTED_CERTIFICATE_SHA256
                ),
            )
        )
    except (apple_distribution.AppleDistributionError, EvidenceIOError) as exc:
        raise AppleStablePublicationError(
            "Apple public distribution deep validation failed"
        ) from exc
    entries_after = _public_distribution_entries()
    _require(
        entries_after == entries_before,
        "Apple public distribution changed while assembling its receipt",
    )
    return distribution


def _snapshot_public_asset_files() -> tuple[FileSnapshot, ...]:
    entries_before = _public_distribution_entries()
    snapshots = tuple(
        read_fixed_file_snapshot(
            APPLE_PUBLIC_DISTRIBUTION / name,
            safe_root=APPLE_PUBLIC_ROOT,
            expected_leaf=name,
            label=f"Apple stable publication asset {name}",
            parent_depth=1,
            maximum=(
                apple_distribution.MAX_ARTIFACT_BYTES
                if name == apple_distribution.XCFRAMEWORK_ZIP_NAME
                else apple_distribution.MAX_TEXT_BYTES
            ),
            file_mode=PUBLIC_FILE_MODE,
            root_mode=0o755,
            parent_mode=0o755,
        )
        for name in apple_contract.APPLE_PUBLIC_ASSET_NAMES
    )
    _require(
        all(snapshot.size > 0 for snapshot in snapshots),
        "Apple stable publication asset is empty",
    )
    _require(
        _public_distribution_entries() == entries_before,
        "Apple public distribution changed during asset snapshot",
    )
    return snapshots


def load_pending_publication_assets(
    pending_receipt: object,
) -> tuple[FileSnapshot, ...]:
    """Return the fixed four Apple files selected by the pending P receipt."""

    try:
        manifest = {
            "release_publications": {
                apple_contract.APPLE_V0_1_3_PUBLICATION_KEY: pending_receipt
            }
        }
        apple_contract.validate_apple_publications(manifest)
    except apple_contract.ApplePublicationContractError as exc:
        raise AppleStablePublicationError(str(exc)) from exc
    pending = _object(pending_receipt, "pending Apple stable receipt")
    _require(
        pending.get("status") == apple_contract.APPLE_STATUS_PENDING,
        "Apple asset selection requires the pending stable receipt",
    )
    distribution = _object(
        pending.get("distribution"),
        "pending Apple stable distribution",
    )
    source = _object(pending.get("source"), "pending Apple stable source")
    expected_hashes = _public_asset_sha256s(distribution)
    before = _snapshot_public_asset_files()
    rebuilt = _load_public_distribution(
        expected_hashes,
        _sha1(source.get("source_parent_commit"), "Apple source parent"),
    )
    _require(
        apple_contract.publication_values_equal(rebuilt, distribution),
        "Apple fixed distribution differs from the selected pending receipt",
    )
    after = _snapshot_public_asset_files()
    _require(
        before == after,
        "Apple stable publication assets changed while loading",
    )
    return before


def build_pending_receipt(
    completion_ledger: pathlib.Path,
    expected_results_sha256: str,
) -> dict[str, object]:
    """Build the exact pending leaf from a completed signed distribution."""

    manifest, _results_sha256 = _read_results_snapshot(expected_results_sha256)
    source_parent_commit, source_digest = _source_identity_from_results(manifest)
    ledger, completion_source_commit = _load_completion_ledger(completion_ledger)
    _require(
        completion_source_commit == source_parent_commit,
        "Apple completion source differs from current results provenance",
    )
    source = _validate_clean_annotated_tag(source_parent_commit, source_digest)
    hashes = _object(
        ledger["public_assets_sha256"],
        "Apple completion public asset hashes",
    )
    distribution = _load_public_distribution(hashes, source_parent_commit)
    receipt: dict[str, object] = {
        "boundary": apple_contract.APPLE_V0_1_3_BOUNDARY,
        "distribution": distribution,
        "identity": copy.deepcopy(apple_contract.APPLE_V0_1_3_IDENTITY),
        "kind": apple_contract.APPLE_PUBLICATION_KIND,
        "schema_version": apple_contract.APPLE_PUBLICATION_SCHEMA_VERSION,
        "source": source,
        "status": apple_contract.APPLE_STATUS_PENDING,
    }
    try:
        apple_contract.validate_apple_publications(
            {
                "release_publications": {
                    apple_contract.APPLE_V0_1_3_PUBLICATION_KEY: receipt
                }
            }
        )
    except apple_contract.ApplePublicationContractError as exc:
        raise AppleStablePublicationError(str(exc)) from exc
    return receipt


def _load_release_projection(path: pathlib.Path) -> dict[str, Any]:
    snapshot = read_fixed_json_snapshot(
        path,
        safe_root=APPLE_RELEASE_PROJECTION_ROOT,
        expected_leaf=APPLE_RELEASE_PROJECTION_NAME,
        label="Apple GitHub release projection",
        parent_depth=1,
        maximum=MAX_PROJECTION_BYTES,
        file_mode=PRIVATE_FILE_MODE,
    )
    projection = snapshot.value
    _exact_keys(
        projection,
        frozenset(
            {
                "assets",
                "kind",
                "publication",
                "release_identity",
                "schema_version",
                "timestamp_authority",
            }
        ),
        "Apple GitHub release projection",
    )
    _require(
        projection["kind"] == APPLE_RELEASE_PROJECTION_KIND
        and type(projection["schema_version"]) is int
        and projection["schema_version"]
        == APPLE_RELEASE_PROJECTION_SCHEMA_VERSION,
        "Apple GitHub release projection discriminant differs",
    )
    _require(
        projection["release_identity"]
        == {
            "repository": APPLE_RELEASE_REPOSITORY,
            "tag": apple_distribution.RELEASE_TAG,
            "url": apple_distribution.RELEASE_URL,
            "visibility": "PUBLIC",
        },
        "Apple GitHub release projection identity differs",
    )
    timestamp_authority = _object(
        projection["timestamp_authority"],
        "Apple GitHub release timestamp authority",
    )
    _exact_keys(
        timestamp_authority,
        frozenset({"timestamp", "type", "uri"}),
        "Apple GitHub release timestamp authority",
    )
    _require(
        timestamp_authority["type"]
        == APPLE_RELEASE_TIMESTAMP_AUTHORITY_TYPE
        and timestamp_authority["uri"]
        == APPLE_RELEASE_TIMESTAMP_AUTHORITY_URI,
        "Apple GitHub release timestamp authority differs",
    )
    _timestamp(
        timestamp_authority["timestamp"],
        "Apple GitHub release timestamp authority time",
    )
    return projection


def _validate_remote_receipt(value: object) -> dict[str, Any]:
    receipt = _object(value, "Apple remote consumer receipt")
    _exact_keys(
        receipt,
        frozenset(
            {
                "assets_sha256",
                "boundary",
                "kind",
                "log_sha256",
                "release_identity",
                "results_sha256",
                "schema_version",
                "source_commit",
                "swiftpm_checksum",
                "verification",
                "verified_at",
                "verifier_commit",
            }
        ),
        "Apple remote consumer receipt",
    )
    _require(
        receipt["kind"] == REMOTE_CONSUMER_RECEIPT_KIND
        and type(receipt["schema_version"]) is int
        and receipt["schema_version"] == REMOTE_CONSUMER_RECEIPT_SCHEMA_VERSION,
        "Apple remote consumer receipt discriminant differs",
    )
    _require(
        receipt["boundary"] == REMOTE_CONSUMER_BOUNDARY,
        "Apple remote consumer boundary differs",
    )
    _require(
        receipt["release_identity"]
        == apple_contract.APPLE_V0_1_3_IDENTITY,
        "Apple remote consumer release identity differs",
    )
    _sha1(receipt["source_commit"], "Apple remote artifact source commit")
    _sha1(receipt["verifier_commit"], "Apple remote verifier commit")
    for key in ("log_sha256", "results_sha256", "swiftpm_checksum"):
        _sha256(receipt[key], f"Apple remote consumer {key}")
    _timestamp(receipt["verified_at"], "Apple remote consumer verified_at")
    assets = _object(
        receipt["assets_sha256"],
        "Apple remote consumer asset hashes",
    )
    _exact_keys(
        assets,
        frozenset(apple_contract.APPLE_PUBLIC_ASSET_NAMES),
        "Apple remote consumer asset hashes",
    )
    for name in apple_contract.APPLE_PUBLIC_ASSET_NAMES:
        _sha256(assets[name], f"Apple remote asset digest for {name}")
    verification = _object(
        receipt["verification"],
        "Apple remote consumer verification",
    )
    _exact_keys(
        verification,
        frozenset(
            {
                "deep_distribution_verified",
                "codesign_verified",
                "swift_test_count",
                "url_binary_target",
            }
        ),
        "Apple remote consumer verification",
    )
    _require(
        verification
        == {
            "codesign_verified": True,
            "deep_distribution_verified": True,
            "swift_test_count": 3,
            "url_binary_target": True,
        },
        "Apple remote consumer verification facts differ",
    )
    return receipt


def _load_remote_receipt(path: pathlib.Path) -> dict[str, Any]:
    snapshot = read_fixed_json_snapshot(
        path,
        safe_root=REMOTE_CONSUMER_RUNS_ROOT,
        expected_leaf=REMOTE_CONSUMER_RECEIPT_NAME,
        label="Apple remote consumer receipt",
        parent_depth=1,
        maximum=MAX_REMOTE_RECEIPT_BYTES,
        file_mode=PRIVATE_FILE_MODE,
    )
    return _validate_remote_receipt(snapshot.value)


def _pending_leaf_from_results(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Return the stable pending leaf from a composite-validated manifest.

    ``_read_results_snapshot`` has already required the coordinated pending
    cohort and its still-active historical Apple selector.  Promotion consumes
    the stable leaf by publication key; the selector moves only in the later
    all-domain verified results transition.
    """

    publications = _object(
        manifest.get("release_publications"),
        "current release_publications",
    )
    pending = _object(
        publications.get(apple_contract.APPLE_V0_1_3_PUBLICATION_KEY),
        "current Apple 0.1.3 stable publication receipt",
    )
    _require(
        pending.get("status") == apple_contract.APPLE_STATUS_PENDING,
        "Apple promotion requires a current pending 0.1.3 stable receipt",
    )
    return pending


def verify_pending_release_assets(
    *,
    release_directory: pathlib.Path,
    results_manifest: pathlib.Path,
    expected_source_commit: str,
    expected_zip_sha256: str,
    expected_apple_distribution_sha256: str,
    expected_manifest_sha256: str,
    expected_sha256sums_sha256: str,
    expected_swiftpm_checksum: str,
) -> dict[str, str]:
    """Select the stable leaf from a valid P, then run the leaf byte gate."""

    try:
        snapshot = load_json_object_snapshot(
            results_manifest,
            maximum=MAX_RESULTS_BYTES,
            label="trusted pending release results manifest",
        )
    except EvidenceIOError as exc:
        raise AppleStablePublicationError(
            "cannot safely read trusted pending release results"
        ) from exc
    results = _object(snapshot.value, "trusted pending release results")
    from release_publication_contract import (
        PUBLICATION_STATE_PENDING,
        ReleasePublicationContractError,
        publication_state,
        validate_release_publications,
    )

    try:
        validate_release_publications(results)
        state = publication_state(results)
    except ReleasePublicationContractError as exc:
        raise AppleStablePublicationError(str(exc)) from exc
    _require(
        state == PUBLICATION_STATE_PENDING,
        "Apple release assets require the coordinated pending publication state",
    )
    pending = _pending_leaf_from_results(results)
    try:
        return apple_distribution.verify_release_assets(
            release_directory=release_directory,
            trusted_distribution=pending["distribution"],
            trusted_results_sha256=snapshot.file.sha256,
            expected_source_commit=expected_source_commit,
            expected_zip_sha256=expected_zip_sha256,
            expected_apple_distribution_sha256=(
                expected_apple_distribution_sha256
            ),
            expected_manifest_sha256=expected_manifest_sha256,
            expected_sha256sums_sha256=expected_sha256sums_sha256,
            expected_swiftpm_checksum=expected_swiftpm_checksum,
        )
    except apple_distribution.AppleDistributionError as exc:
        raise AppleStablePublicationError(str(exc)) from exc


def promote_receipt(
    expected_results_sha256: str,
    release_projection_path: pathlib.Path,
    remote_receipt_path: pathlib.Path,
) -> dict[str, object]:
    """Promote the current pending leaf using two fresh safe projections."""

    manifest, results_sha256 = _read_results_snapshot(expected_results_sha256)
    pending = _pending_leaf_from_results(manifest)
    distribution = _object(
        pending["distribution"], "pending Apple 0.1.3 stable distribution"
    )
    projection = _load_release_projection(release_projection_path)
    remote = _load_remote_receipt(remote_receipt_path)

    _require(
        remote["results_sha256"] == results_sha256,
        "Apple remote consumer did not verify the pinned pending results",
    )
    _require(
        remote["source_commit"] == distribution["source_commit"],
        "Apple remote consumer source differs from the signed candidate",
    )
    expected_assets = _public_asset_sha256s(distribution)
    _require(
        remote["assets_sha256"] == expected_assets
        and remote["swiftpm_checksum"] == distribution["swiftpm_checksum"],
        "Apple remote consumer asset/checksum binding differs",
    )
    try:
        inspection = inspect_worktree(REPOSITORY_ROOT)
        current_commit = require_commit_or_evidence_successor(
            REPOSITORY_ROOT,
            distribution["source_commit"],
        )
    except GitProvenanceError as exc:
        raise AppleStablePublicationError(
            "cannot establish Apple promotion source provenance"
        ) from exc
    _require(not inspection.dirty, "Apple promotion requires a clean worktree")
    _require(
        current_commit == inspection.commit == remote["verifier_commit"],
        "Apple remote verifier differs from the clean promotion checkout",
    )

    assets_value = projection["assets"]
    _require(
        isinstance(assets_value, list)
        and len(assets_value)
        == len(apple_contract.APPLE_PUBLIC_ASSET_NAMES),
        "Apple GitHub release projection asset count differs",
    )
    for index, name in enumerate(apple_contract.APPLE_PUBLIC_ASSET_NAMES):
        asset = _object(
            assets_value[index], f"Apple GitHub release asset {index}"
        )
        _exact_keys(
            asset,
            frozenset({"bytes", "name", "sha256"}),
            f"Apple GitHub release asset {index}",
        )
        _require(
            asset["name"] == name
            and asset["sha256"] == expected_assets[name]
            and type(asset["bytes"]) is int
            and asset["bytes"] > 0,
            f"Apple GitHub release asset binding differs for {name}",
        )
        if name == apple_distribution.XCFRAMEWORK_ZIP_NAME:
            _require(
                asset["bytes"] == distribution["artifact_size"],
                "Apple GitHub release ZIP size differs from the candidate",
            )

    publication = _object(
        projection["publication"], "Apple GitHub release publication"
    )
    attestation = _object(
        publication.get("release_attestation"),
        "Apple GitHub release attestation",
    )
    timestamp_authority = _object(
        projection["timestamp_authority"],
        "Apple GitHub release timestamp authority",
    )
    _require(
        timestamp_authority["timestamp"] == attestation.get("verified_at"),
        "Apple GitHub release timestamp authority differs from attestation",
    )

    verified = copy.deepcopy(pending)
    verified["status"] = apple_contract.APPLE_STATUS_VERIFIED
    verified_distribution = _object(
        verified["distribution"], "verified Apple 0.1.3 stable distribution"
    )
    verified_distribution["public_release"] = True
    verified_distribution["immutable_release"] = True
    verified_distribution["remote_consumer_verified"] = True
    verified_distribution["remote_verification"] = {
        "log_sha256": remote["log_sha256"],
        "verified_at": remote["verified_at"],
        "verifier_commit": remote["verifier_commit"],
    }
    verified["publication"] = copy.deepcopy(publication)
    try:
        apple_contract.validate_apple_publications(
            {
                "release_publications": {
                    apple_contract.APPLE_V0_1_3_PUBLICATION_KEY: verified
                }
            }
        )
        apple_contract.validate_apple_publication_transition(
            {
                "release_publications": {
                    apple_contract.APPLE_V0_1_3_PUBLICATION_KEY: pending
                }
            },
            {
                "release_publications": {
                    apple_contract.APPLE_V0_1_3_PUBLICATION_KEY: verified
                }
            },
        )
    except apple_contract.ApplePublicationContractError as exc:
        raise AppleStablePublicationError(str(exc)) from exc
    return verified


def _private_runtime_snapshot_at(
    directory: PrivateDirectoryHandle,
    name: str,
    *,
    maximum: int,
    label: str,
) -> FileSnapshot:
    chunks: list[bytes] = []
    try:
        digest = consume_regular_snapshot_at(
            directory.descriptor,
            name,
            display_path=directory.path / name,
            maximum=maximum,
            label=label,
            consume=chunks.append,
            validate_metadata=lambda metadata: _owned_file_metadata(
                metadata,
                mode=PRIVATE_FILE_MODE,
                label=label,
            ),
        )
    except EvidenceIOError as exc:
        raise AppleStablePublicationError(
            f"cannot safely read {label}"
        ) from exc
    data = b"".join(chunks)
    _require(
        len(data) == digest.size,
        f"{label} consumer byte count changed unexpectedly",
    )
    return FileSnapshot(
        path=digest.path,
        data=data,
        size=digest.size,
        sha256=digest.sha256,
    )


def _remote_runtime_from_verifier_snapshot(
    run_directory_name: str,
) -> tuple[pathlib.Path, str]:
    """Derive the outer checkout from this run's fixed verifier snapshot layout."""

    _require(
        isinstance(run_directory_name, str)
        and REMOTE_CONSUMER_TRANSACTION.fullmatch(run_directory_name)
        is not None,
        "remote consumer run directory name is malformed",
    )
    source_supplied = os.fspath(REPOSITORY_ROOT)
    source_absolute = os.path.abspath(source_supplied)
    source_text = os.path.realpath(source_supplied)
    _require(
        source_text == source_absolute,
        "remote consumer verifier source root must be canonical",
    )
    source_root = pathlib.Path(source_text)
    _require(
        source_root.name == "verifier-inputs",
        "remote consumer verifier source root has the wrong fixed leaf",
    )
    run_directory = source_root.parent
    safe_run_directory_name = run_directory.name
    _require(
        REMOTE_CONSUMER_TRANSACTION.fullmatch(safe_run_directory_name)
        is not None
        and safe_run_directory_name == run_directory_name,
        "remote consumer verifier source/run binding differs",
    )
    runs_root = run_directory.parent
    _require(
        runs_root.name == "qperiapt-swift-remote-consumer-runs",
        "remote consumer verifier source runs-root binding differs",
    )
    target_root = runs_root.parent
    _require(
        target_root.name == "target",
        "remote consumer verifier source target-root binding differs",
    )
    runtime_root = target_root.parent
    runtime_prefix = os.fspath(runtime_root) + os.sep
    if not source_text.startswith(runtime_prefix):
        raise AppleStablePublicationError(
            "remote consumer verifier source escaped its runtime checkout"
        )
    expected_source = (
        runtime_root
        / "target"
        / "qperiapt-swift-remote-consumer-runs"
        / safe_run_directory_name
        / "verifier-inputs"
    )
    _require(
        source_root == expected_source,
        "remote consumer verifier source hierarchy differs",
    )
    for directory, label in (
        (runs_root, "remote consumer runs root"),
        (run_directory, "remote consumer run directory"),
        (source_root, "remote consumer verifier source root"),
    ):
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise AppleStablePublicationError(f"cannot inspect {label}") from exc
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and not directory.is_symlink()
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            f"{label} must be an owned mode-0700 non-symlink directory",
        )
    return runtime_root, safe_run_directory_name


@contextlib.contextmanager
def _open_remote_consumer_layout(
    output_root: PrivateDirectoryHandle,
) -> Iterator[_RemoteConsumerLayout]:
    """Pin the fixed evidence hierarchy below one held remote run."""

    with contextlib.ExitStack() as resources:
        verifier_source = resources.enter_context(
            open_private_directory_at(
                parent=output_root,
                direct_child_name="verifier-inputs",
                label="remote consumer verifier source",
            )
        )
        verifier_artifact = resources.enter_context(
            open_private_directory_at(
                parent=verifier_source,
                direct_child_name="artifact",
                label="remote consumer verifier artifact directory",
            )
        )
        verifier_target = resources.enter_context(
            open_private_directory_at(
                parent=verifier_source,
                direct_child_name="target",
                label="remote consumer verifier target directory",
            )
        )
        release_assets = resources.enter_context(
            open_private_directory_at(
                parent=output_root,
                direct_child_name=REMOTE_CONSUMER_RELEASE_ASSETS_NAME,
                label="remote consumer downloaded asset directory",
            )
        )
        extracted = resources.enter_context(
            open_private_directory_at(
                parent=verifier_target,
                direct_child_name="extracted",
                label="remote consumer extraction directory",
            )
        )
        extracted_xcframework = resources.enter_context(
            open_private_directory_at(
                parent=extracted,
                direct_child_name="CQPeriapt.xcframework",
                label="remote consumer extracted XCFramework",
                required_mode=0o755,
            )
        )
        yield _RemoteConsumerLayout(
            verifier_source=verifier_source,
            verifier_artifact=verifier_artifact,
            verifier_target=verifier_target,
            release_assets=release_assets,
            extracted=extracted,
            extracted_xcframework=extracted_xcframework,
        )


def emit_remote_consumer_receipt(
    *,
    runtime_repository_root: pathlib.Path,
    run_directory_name: str,
    startup_results_sha256: str,
    clock: Clock = _system_clock,
) -> tuple[pathlib.Path, str]:
    """Pin the complete remote-consumer layout and emit its structured receipt."""

    _require(
        runtime_repository_root.is_absolute()
        and os.path.realpath(runtime_repository_root)
        == os.path.abspath(runtime_repository_root),
        "remote consumer repository root must be canonical",
    )
    runtime_root = pathlib.Path(os.path.realpath(runtime_repository_root))
    _require(
        isinstance(run_directory_name, str)
        and REMOTE_CONSUMER_TRANSACTION.fullmatch(run_directory_name)
        is not None,
        "remote consumer run directory name is malformed",
    )
    runs_root = (
        runtime_root / "target" / "qperiapt-swift-remote-consumer-runs"
    )
    normalized_runs_root = normalize_safe_root(
        runs_root,
        label="remote consumer runs root",
    )
    try:
        with open_private_direct_child_handle(
            safe_root=normalized_runs_root,
            direct_child_name=run_directory_name,
            label="remote consumer run",
            sync_safe_root_parent=True,
        ) as output_root:
            sync_private_directory_parent(
                output_root,
                label="remote consumer run",
            )
            with _open_remote_consumer_layout(output_root) as layout:
                receipt = _emit_remote_consumer_receipt_pinned(
                    runtime_root=runtime_root,
                    output_root=output_root,
                    verifier_source=layout.verifier_source,
                    verifier_artifact=layout.verifier_artifact,
                    verifier_target=layout.verifier_target,
                    release_assets=layout.release_assets,
                    extracted=layout.extracted,
                    extracted_xcframework=layout.extracted_xcframework,
                    startup_results_sha256=startup_results_sha256,
                    clock=clock,
                )
        return _commit_remote_consumer_receipt(
            runtime_root=runtime_root,
            normalized_runs_root=normalized_runs_root,
            run_directory_name=run_directory_name,
            startup_results_sha256=startup_results_sha256,
            receipt=receipt,
        )
    except PublicationReceiptCommittedError:
        raise
    except PublicationReceiptIOError as exc:
        raise AppleStablePublicationError(str(exc)) from exc


def _commit_remote_consumer_receipt(
    *,
    runtime_root: pathlib.Path,
    normalized_runs_root: pathlib.Path,
    run_directory_name: str,
    startup_results_sha256: str,
    receipt: dict[str, object],
) -> tuple[pathlib.Path, str]:
    """Re-pin, rebuild, and atomically commit one already-validated receipt."""

    verified_at = _timestamp(
        receipt.get("verified_at"),
        "remote consumer receipt verified_at",
    )
    with open_private_direct_child_handle(
        safe_root=normalized_runs_root,
        direct_child_name=run_directory_name,
        label="remote consumer run",
        sync_safe_root_parent=True,
    ) as output_root:
        sync_private_directory_parent(
            output_root,
            label="remote consumer run",
        )
        with prepare_private_json_noreplace_at(
            output_root,
            REMOTE_CONSUMER_RECEIPT_NAME,
            receipt,
            label="Apple remote consumer receipt",
            maximum=MAX_REMOTE_RECEIPT_BYTES,
        ) as prepared:
            with _open_remote_consumer_layout(output_root) as layout:
                rebuilt = _emit_remote_consumer_receipt_pinned(
                    runtime_root=runtime_root,
                    output_root=output_root,
                    verifier_source=layout.verifier_source,
                    verifier_artifact=layout.verifier_artifact,
                    verifier_target=layout.verifier_target,
                    release_assets=layout.release_assets,
                    extracted=layout.extracted,
                    extracted_xcframework=layout.extracted_xcframework,
                    startup_results_sha256=startup_results_sha256,
                    clock=lambda: verified_at,
                )
                _require(
                    rebuilt == receipt,
                    "remote consumer facts changed before receipt commit",
                )
            digest = prepared.commit_after_revalidation()
        return output_root.path / REMOTE_CONSUMER_RECEIPT_NAME, digest


def _emit_remote_consumer_receipt_pinned(
    *,
    runtime_root: pathlib.Path,
    output_root: PrivateDirectoryHandle,
    verifier_source: PrivateDirectoryHandle,
    verifier_artifact: PrivateDirectoryHandle,
    verifier_target: PrivateDirectoryHandle,
    release_assets: PrivateDirectoryHandle,
    extracted: PrivateDirectoryHandle,
    extracted_xcframework: PrivateDirectoryHandle,
    startup_results_sha256: str,
    clock: Clock,
) -> dict[str, object]:
    """Consume one fully pinned remote-consumer transaction."""

    transaction_handles = (
        (output_root, "remote consumer run"),
        (verifier_source, "remote consumer verifier source"),
        (verifier_artifact, "remote consumer verifier artifact directory"),
        (verifier_target, "remote consumer verifier target directory"),
        (release_assets, "remote consumer downloaded asset directory"),
        (extracted, "remote consumer extraction directory"),
        (extracted_xcframework, "remote consumer extracted XCFramework"),
    )

    def verify_transaction_handles() -> None:
        for handle, label in transaction_handles:
            try:
                verify_private_directory_handle_identity(handle, label=label)
            except PublicationReceiptIOError as exc:
                raise AppleStablePublicationError(str(exc)) from exc

    verify_transaction_handles()
    startup_results_sha256 = _sha256(
        startup_results_sha256,
        "remote consumer startup results SHA-256",
    )

    results_before = _private_runtime_snapshot_at(
        verifier_artifact,
        "results.json",
        maximum=MAX_RESULTS_BYTES,
        label="remote consumer verifier results snapshot",
    )
    _require(
        results_before.sha256 == startup_results_sha256,
        "remote consumer verifier results changed after startup",
    )
    try:
        results_value = parse_strict_json_bytes(
            results_before.data,
            label="remote consumer verifier results snapshot",
        )
    except EvidenceIOError as exc:
        raise AppleStablePublicationError(
            "remote consumer verifier results are not strict JSON"
        ) from exc
    results = _object(results_value, "remote consumer verifier results")
    from release_publication_contract import (
        PUBLICATION_STATE_PENDING,
        ReleasePublicationContractError,
        publication_state,
        validate_release_publications,
    )

    try:
        validate_release_publications(results)
        state = publication_state(results)
    except ReleasePublicationContractError as exc:
        raise AppleStablePublicationError(str(exc)) from exc
    _require(
        state == PUBLICATION_STATE_PENDING,
        "remote consumer receipt requires the coordinated pending publication state",
    )
    pending = _pending_leaf_from_results(results)
    distribution = _object(
        pending["distribution"], "remote consumer pending distribution"
    )
    expected_assets = _public_asset_sha256s(distribution)
    try:
        verify_exact_directory_inventory_at(
            release_assets.descriptor,
            frozenset(apple_contract.APPLE_PUBLIC_ASSET_NAMES),
            label="remote consumer downloaded assets before snapshot",
        )
    except PublicationReceiptIOError as exc:
        raise AppleStablePublicationError(
            "cannot inspect remote consumer downloaded assets"
        ) from exc
    downloaded: dict[str, FileSnapshot] = {}
    for name in apple_contract.APPLE_PUBLIC_ASSET_NAMES:
        downloaded[name] = _private_runtime_snapshot_at(
            release_assets,
            name,
            maximum=(
                apple_distribution.MAX_ARTIFACT_BYTES
                if name == apple_distribution.XCFRAMEWORK_ZIP_NAME
                else apple_distribution.MAX_TEXT_BYTES
            ),
            label=f"remote consumer downloaded asset {name}",
        )
    try:
        verify_exact_directory_inventory_at(
            release_assets.descriptor,
            frozenset(apple_contract.APPLE_PUBLIC_ASSET_NAMES),
            label="remote consumer downloaded assets after snapshot",
        )
    except PublicationReceiptIOError as exc:
        raise AppleStablePublicationError(
            "remote consumer downloaded asset directory changed"
        ) from exc
    verify_transaction_handles()
    normalized_assets = {
        name: downloaded[name].sha256
        for name in apple_contract.APPLE_PUBLIC_ASSET_NAMES
    }
    _require(
        normalized_assets == expected_assets,
        "remote consumer downloaded assets differ from the pending selector",
    )
    source_commit = _sha1(
        distribution["source_commit"], "remote consumer source commit"
    )
    try:
        downloaded_distribution = (
            apple_distribution.project_trusted_results_candidate_distribution(
                zip_data=downloaded[
                    apple_distribution.XCFRAMEWORK_ZIP_NAME
                ].data,
                apple_distribution_data=downloaded[
                    apple_distribution.APPLE_DISTRIBUTION_NAME
                ].data,
                manifest_data=downloaded[
                    apple_distribution.MANIFEST_NAME
                ].data,
                checksums_data=downloaded[
                    apple_distribution.SHA256SUMS_NAME
                ].data,
                expected_asset_sha256=normalized_assets,
                expected_source_commit=source_commit,
                expected_team_id=APPLE_EXPECTED_TEAM_ID,
                expected_certificate_sha256=(
                    APPLE_EXPECTED_CERTIFICATE_SHA256
                ),
            )
        )
    except (apple_distribution.AppleDistributionError, EvidenceIOError) as exc:
        raise AppleStablePublicationError(
            "remote consumer downloaded asset deep validation failed"
        ) from exc
    _require(
        apple_contract.publication_values_equal(
            downloaded_distribution,
            distribution,
        ),
        "remote consumer downloaded distribution differs from pending facts",
    )
    swiftpm_checksum = normalized_assets[
        apple_distribution.XCFRAMEWORK_ZIP_NAME
    ]
    _require(
        swiftpm_checksum == distribution["swiftpm_checksum"],
        "remote consumer downloaded SwiftPM checksum differs",
    )
    verify_transaction_handles()
    try:
        codesign_result = capture_stdout(
            [
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "--verbose=4",
                os.fspath(extracted_xcframework.path),
            ],
            timeout_seconds=60,
            maximum_bytes=1024 * 1024,
            stderr=subprocess.STDOUT,
            environment={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except BoundedProcessError as exc:
        raise AppleStablePublicationError(
            "remote consumer code-signature verification could not complete"
        ) from exc
    _require(
        codesign_result.returncode == 0,
        "remote consumer extracted XCFramework code signature is invalid",
    )
    verify_transaction_handles()
    try:
        inspection = inspect_worktree(runtime_root)
        verifier_commit = require_commit_or_evidence_successor(
            runtime_root,
            source_commit,
        )
    except GitProvenanceError as exc:
        raise AppleStablePublicationError(
            "cannot establish remote consumer checkout provenance"
        ) from exc
    _require(
        not inspection.dirty and inspection.commit == verifier_commit,
        "remote consumer receipt requires its clean verifier checkout",
    )
    verify_transaction_handles()

    log = _private_runtime_snapshot_at(
        output_root,
        REMOTE_CONSUMER_LOG_NAME,
        maximum=MAX_REMOTE_LOG_BYTES,
        label="remote consumer test log",
    )
    try:
        log_text = log.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppleStablePublicationError(
            "remote consumer test log is not UTF-8"
        ) from exc
    _require(
        WARNING_OR_ERROR.search(log_text) is None,
        "remote consumer test log contains warning/error diagnostics",
    )
    _require(
        log_text.count(THREE_TEST_PASS) >= 1,
        "remote consumer test log does not contain a three-test pass",
    )
    _require(
        TEST_FAILURE_SUMMARY.search(log_text) is None,
        "remote consumer test log reports test failures",
    )
    observed = clock()
    _require(
        isinstance(observed, dt.datetime)
        and observed.tzinfo is not None
        and observed.utcoffset() is not None,
        "remote consumer clock must return a timezone-aware datetime",
    )
    verified_at = observed.astimezone(dt.UTC).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    receipt: dict[str, object] = {
        "assets_sha256": normalized_assets,
        "boundary": REMOTE_CONSUMER_BOUNDARY,
        "kind": REMOTE_CONSUMER_RECEIPT_KIND,
        "log_sha256": log.sha256,
        "release_identity": copy.deepcopy(
            apple_contract.APPLE_V0_1_3_IDENTITY
        ),
        "results_sha256": startup_results_sha256,
        "schema_version": REMOTE_CONSUMER_RECEIPT_SCHEMA_VERSION,
        "source_commit": source_commit,
        "swiftpm_checksum": swiftpm_checksum,
        "verification": {
            "codesign_verified": True,
            "deep_distribution_verified": True,
            "swift_test_count": 3,
            "url_binary_target": True,
        },
        "verified_at": verified_at,
        "verifier_commit": verifier_commit,
    }
    _validate_remote_receipt(receipt)
    results_after = _private_runtime_snapshot_at(
        verifier_artifact,
        "results.json",
        maximum=MAX_RESULTS_BYTES,
        label="remote consumer verifier results resample",
    )
    _require(
        results_after.sha256 == results_before.sha256
        and results_after.data == results_before.data,
        "remote consumer verifier results changed before receipt publication",
    )
    verify_transaction_handles()
    return receipt


def _publish_receipt(receipt: object) -> tuple[pathlib.Path, str]:
    return create_private_transaction_json(
        safe_root=APPLE_PUBLICATION_RECEIPT_ROOT,
        transaction_prefix="transaction.",
        expected_leaf=APPLE_PUBLICATION_RECEIPT_NAME,
        value=receipt,
        label="Apple 0.1.3 stable publication receipt",
        maximum=MAX_REMOTE_RECEIPT_BYTES,
    )


def _success_marker(path: pathlib.Path, digest: str, status: str) -> str:
    try:
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError as exc:
        raise AppleStablePublicationError(
            "Apple receipt output escaped the repository"
        ) from exc
    return (
        "APPLE_V0_1_3_PUBLICATION_RECEIPT_PASS "
        f"status={status} path={relative} sha256={digest}"
    )


def _remote_success_marker(
    path: pathlib.Path,
    digest: str,
    runtime_repository_root: pathlib.Path,
) -> str:
    try:
        relative = path.relative_to(runtime_repository_root).as_posix()
    except ValueError as exc:
        raise AppleStablePublicationError(
            "remote consumer receipt escaped its runtime repository"
        ) from exc
    return (
        "APPLE_REMOTE_CONSUMER_RECEIPT_PASS "
        f"path={relative} sha256={digest}"
    )


def _usage() -> str:
    return (
        "usage: apple_stable_publication.py pending COMPLETION_LEDGER "
        "EXPECTED_RESULTS_SHA256 | "
        "promote EXPECTED_PENDING_RESULTS_SHA256 RELEASE_PROJECTION "
        "REMOTE_CONSUMER_RECEIPT | emit-remote-consumer "
        "RUN_DIRECTORY_NAME STARTUP_RESULTS_SHA256 | verify-release-assets "
        "RESULTS_MANIFEST RELEASE_DIRECTORY SOURCE_COMMIT ZIP_SHA256 "
        "APPLE_DISTRIBUTION_SHA256 MANIFEST_SHA256 SHA256SUMS_SHA256 "
        "SWIFTPM_CHECKSUM"
    )


def _main(arguments: Sequence[str]) -> int:
    if len(arguments) == 3 and arguments[0] == "pending":
        receipt = build_pending_receipt(
            pathlib.Path(arguments[1]), arguments[2]
        )
        path, digest = _publish_receipt(receipt)
        print(_success_marker(path, digest, apple_contract.APPLE_STATUS_PENDING))
        return 0
    if len(arguments) == 4 and arguments[0] == "promote":
        receipt = promote_receipt(
            arguments[1],
            pathlib.Path(arguments[2]),
            pathlib.Path(arguments[3]),
        )
        path, digest = _publish_receipt(receipt)
        print(_success_marker(path, digest, apple_contract.APPLE_STATUS_VERIFIED))
        return 0
    if len(arguments) == 3 and arguments[0] == "emit-remote-consumer":
        runtime_root, run_directory_name = _remote_runtime_from_verifier_snapshot(
            arguments[1]
        )
        path, digest = emit_remote_consumer_receipt(
            runtime_repository_root=runtime_root,
            run_directory_name=run_directory_name,
            startup_results_sha256=arguments[2],
        )
        print(_remote_success_marker(path, digest, runtime_root))
        return 0
    if len(arguments) == 9 and arguments[0] == "verify-release-assets":
        verified = verify_pending_release_assets(
            results_manifest=pathlib.Path(arguments[1]),
            release_directory=pathlib.Path(arguments[2]),
            expected_source_commit=arguments[3],
            expected_zip_sha256=arguments[4],
            expected_apple_distribution_sha256=arguments[5],
            expected_manifest_sha256=arguments[6],
            expected_sha256sums_sha256=arguments[7],
            expected_swiftpm_checksum=arguments[8],
        )
        print(
            "APPLE_RELEASE_ASSETS_PASS "
            + " ".join(f"{name}={value}" for name, value in verified.items())
        )
        return 0
    print(f"error: {_usage()}", file=sys.stderr)
    return 2


def main() -> int:
    try:
        return _main(sys.argv[1:])
    except PublicationReceiptCommittedError as exc:
        if exc.leaf is not None and exc.digest is not None:
            print(
                "PUBLICATION_RECEIPT_COMMITTED_ERROR "
                f"visibility={exc.visibility} leaf={exc.leaf} "
                f"sha256={exc.digest}"
            )
        else:
            print(
                "error: publication receipt committed with incomplete durability",
                file=sys.stderr,
            )
        return 125
    except (
        AppleStablePublicationError,
        PublicationReceiptIOError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
