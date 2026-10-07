#!/usr/bin/env python3
"""Read the committed, source-bound Rust package handoff transaction.

This module owns only the immutable handoff schema and its descriptor-safe
loader.  Package production, staging, Git S/R transitions, registry
observations, uploads, journals, and publication receipts belong to their
respective adapters.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import re
from typing import Never

from crates_io_publication_contract import (
    CRATE_PUBLICATION_TOPOLOGY,
    MAX_CRATE_SIZE_BYTES,
    MAX_TOTAL_CRATE_SIZE_BYTES,
    PRODUCT_VERSION,
)
from evidence_io import FileSnapshot
from publication_receipt_io import (
    PRIVATE_DIRECTORY_MODE,
    PRIVATE_FILE_MODE,
    PublicationReceiptIOError,
    normalize_safe_root,
    read_fixed_file_snapshot,
    read_fixed_json_snapshot,
)
from rust_publish_contract import (
    RustPackageContractReceipt,
    RustPublishContractError,
    validate_rust_package_contract_transcript,
)


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
RUST_PACKAGE_HANDOFF_ROOT = (
    REPOSITORY_ROOT / "target" / "qperiapt-rust-package-handoffs"
)
RUST_PACKAGE_HANDOFF_MANIFEST_NAME = "rust-package-handoff.json"
RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME = "rust-package-contract.log"

MAX_HANDOFF_MANIFEST_BYTES = 1024 * 1024
MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024
MAX_CRATE_BYTES = MAX_CRATE_SIZE_BYTES
MAX_TOTAL_CRATE_BYTES = MAX_TOTAL_CRATE_SIZE_BYTES

RUST_PACKAGE_HANDOFF_SCHEMA_VERSION = 1
RUST_PACKAGE_HANDOFF_KIND = "qperiapt.rust_package_handoff"
RUST_PACKAGE_HANDOFF_BOUNDARY = (
    "Exact Cargo-produced archives from one complete clean no-upload Rust "
    "package contract. The final manifest is the transaction commit leaf; "
    "an incomplete sibling directory is never registry input."
)

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUST_PACKAGE_HANDOFF_TRANSACTION_RE = re.compile(
    r"^transaction\.[1-9][0-9]*-[0-9a-f]{32}$"
)


class RustPackageHandoffError(ValueError):
    """The committed Rust package handoff is malformed or changed."""


def _fail(message: str) -> Never:
    raise RustPackageHandoffError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


@dataclasses.dataclass(frozen=True, slots=True)
class RustPackageHandoffSource:
    source_commit: str
    source_tree: str
    canonical_source_tree_sha256: str

    def document(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class RustPackageHandoffCrateSnapshot:
    name: str
    version: str
    dependencies: tuple[str, ...]
    file: FileSnapshot


@dataclasses.dataclass(frozen=True, slots=True)
class RustPackageHandoffSnapshot:
    handoff_root: pathlib.Path
    inventory: frozenset[str]
    source: RustPackageHandoffSource
    manifest: FileSnapshot
    transcript: FileSnapshot
    package_contract: RustPackageContractReceipt
    crates: tuple[RustPackageHandoffCrateSnapshot, ...]


def expected_crate_files() -> tuple[str, ...]:
    """Return the exact topology-ordered archive leaf names."""

    return tuple(
        f"{name}-{PRODUCT_VERSION}.crate"
        for name, _dependencies in CRATE_PUBLICATION_TOPOLOGY
    )


def handoff_inventory() -> frozenset[str]:
    """Return the exact twelve-leaf committed transaction inventory."""

    return frozenset(
        {
            RUST_PACKAGE_HANDOFF_MANIFEST_NAME,
            RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
            *expected_crate_files(),
        }
    )


def validate_rust_package_handoff_source(
    value: object,
) -> RustPackageHandoffSource:
    _require(
        isinstance(value, dict) and all(isinstance(key, str) for key in value),
        "Rust package handoff source must be an object with string keys",
    )
    _require(
        set(value)
        == {
            "canonical_source_tree_sha256",
            "source_commit",
            "source_tree",
        },
        "Rust package handoff source keys differ",
    )
    source_commit = value["source_commit"]
    source_tree = value["source_tree"]
    canonical_digest = value["canonical_source_tree_sha256"]
    _require(
        isinstance(source_commit, str)
        and SHA1_RE.fullmatch(source_commit) is not None,
        "Rust package handoff source commit is malformed",
    )
    _require(
        isinstance(source_tree, str) and SHA1_RE.fullmatch(source_tree) is not None,
        "Rust package handoff source tree is malformed",
    )
    _require(
        isinstance(canonical_digest, str)
        and SHA256_RE.fullmatch(canonical_digest) is not None,
        "Rust package handoff canonical source digest is malformed",
    )
    return RustPackageHandoffSource(
        source_commit=source_commit,
        source_tree=source_tree,
        canonical_source_tree_sha256=canonical_digest,
    )


def validate_rust_package_handoff_crates(
    value: object,
    *,
    label: str,
) -> tuple[dict[str, object], ...]:
    _require(
        isinstance(value, list) and len(value) == len(CRATE_PUBLICATION_TOPOLOGY),
        f"{label} must contain exactly ten crate records",
    )
    records: list[dict[str, object]] = []
    total_size = 0
    for index, ((name, dependencies), crate_file) in enumerate(
        zip(CRATE_PUBLICATION_TOPOLOGY, expected_crate_files())
    ):
        record = value[index]
        _require(
            isinstance(record, dict)
            and all(isinstance(key, str) for key in record),
            f"{label} crate {index} must be an object with string keys",
        )
        _require(
            set(record)
            == {
                "crate_file",
                "crate_sha256",
                "crate_size",
                "dependencies",
                "name",
                "version",
            },
            f"{label} crate {index} keys differ",
        )
        _require(record["name"] == name, f"{label} crate order differs")
        _require(
            record["version"] == PRODUCT_VERSION,
            f"{label} version differs for {name}",
        )
        _require(
            record["crate_file"] == crate_file,
            f"{label} archive name differs for {name}",
        )
        _require(
            record["dependencies"] == list(dependencies),
            f"{label} dependencies differ for {name}",
        )
        size = record["crate_size"]
        digest = record["crate_sha256"]
        _require(
            type(size) is int and 0 < size <= MAX_CRATE_BYTES,
            f"{label} archive size is invalid for {name}",
        )
        _require(
            isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
            f"{label} archive digest is malformed for {name}",
        )
        total_size += size
        _require(
            total_size <= MAX_TOTAL_CRATE_BYTES,
            f"{label} aggregate archive size exceeds the limit",
        )
        records.append(record)
    return tuple(records)


def validate_rust_package_handoff_manifest(
    value: object,
) -> tuple[
    RustPackageHandoffSource,
    dict[str, object],
    tuple[dict[str, object], ...],
]:
    _require(
        isinstance(value, dict) and all(isinstance(key, str) for key in value),
        "Rust package handoff manifest must be an object with string keys",
    )
    _require(
        set(value)
        == {
            "boundary",
            "crates",
            "kind",
            "schema_version",
            "source",
            "transcript",
            "upload_attempted",
        },
        "Rust package handoff manifest keys differ",
    )
    _require(
        value["schema_version"] == RUST_PACKAGE_HANDOFF_SCHEMA_VERSION,
        "Rust package handoff manifest schema differs",
    )
    _require(
        value["kind"] == RUST_PACKAGE_HANDOFF_KIND,
        "Rust package handoff manifest kind differs",
    )
    _require(
        value["boundary"] == RUST_PACKAGE_HANDOFF_BOUNDARY,
        "Rust package handoff boundary differs",
    )
    _require(
        value["upload_attempted"] is False,
        "Rust package handoff must record upload_attempted=false",
    )
    source = validate_rust_package_handoff_source(value["source"])
    transcript = value["transcript"]
    _require(
        isinstance(transcript, dict)
        and all(isinstance(key, str) for key in transcript)
        and set(transcript) == {"file", "sha256", "size"},
        "Rust package handoff transcript record differs",
    )
    _require(
        transcript["file"] == RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
        "Rust package handoff transcript name differs",
    )
    _require(
        type(transcript["size"]) is int
        and 0 < transcript["size"] <= MAX_TRANSCRIPT_BYTES,
        "Rust package handoff transcript size is invalid",
    )
    _require(
        isinstance(transcript["sha256"], str)
        and SHA256_RE.fullmatch(transcript["sha256"]) is not None,
        "Rust package handoff transcript digest is malformed",
    )
    crates = validate_rust_package_handoff_crates(
        value["crates"], label="Rust package handoff manifest"
    )
    return source, transcript, crates


def _canonical_handoff_manifest_path(path: pathlib.Path) -> pathlib.Path:
    _require(
        isinstance(path, pathlib.Path) and path.is_absolute(),
        "Rust package handoff manifest path must be an absolute pathlib.Path",
    )
    supplied = os.fspath(path)
    _require(
        os.path.abspath(supplied) == supplied
        and all(part not in {"", ".", ".."} for part in path.parts[1:]),
        "Rust package handoff manifest path must be canonically spelled",
    )
    return path


def load_rust_package_handoff_snapshot(
    handoff_manifest_path: pathlib.Path,
    handoff_manifest_sha256: str,
    expected_source: RustPackageHandoffSource,
    *,
    handoff_root: pathlib.Path = RUST_PACKAGE_HANDOFF_ROOT,
) -> RustPackageHandoffSnapshot:
    """Load and resample one explicit fixed-shape committed handoff."""

    _require(
        isinstance(expected_source, RustPackageHandoffSource),
        "expected Rust package handoff source type differs",
    )
    validate_rust_package_handoff_source(expected_source.document())
    _require(
        isinstance(handoff_manifest_sha256, str)
        and SHA256_RE.fullmatch(handoff_manifest_sha256) is not None,
        "Rust package handoff manifest digest is malformed",
    )
    try:
        normalized_root = normalize_safe_root(
            handoff_root,
            label="Rust package handoff root",
            required_mode=PRIVATE_DIRECTORY_MODE,
        )
    except PublicationReceiptIOError as exc:
        raise RustPackageHandoffError(str(exc)) from exc
    manifest_path = _canonical_handoff_manifest_path(handoff_manifest_path)
    _require(
        manifest_path.parent.parent == normalized_root
        and manifest_path.name == RUST_PACKAGE_HANDOFF_MANIFEST_NAME
        and RUST_PACKAGE_HANDOFF_TRANSACTION_RE.fullmatch(
            manifest_path.parent.name
        )
        is not None,
        "Rust package handoff manifest path differs from the fixed transaction shape",
    )
    inventory = handoff_inventory()
    try:
        manifest = read_fixed_json_snapshot(
            manifest_path,
            safe_root=normalized_root,
            expected_leaf=RUST_PACKAGE_HANDOFF_MANIFEST_NAME,
            label="Rust package handoff manifest",
            parent_depth=1,
            maximum=MAX_HANDOFF_MANIFEST_BYTES,
            expected_parent_entries=inventory,
        )
    except PublicationReceiptIOError as exc:
        raise RustPackageHandoffError(str(exc)) from exc
    _require(
        manifest.file.sha256 == handoff_manifest_sha256,
        "Rust package handoff manifest digest differs from the explicit marker",
    )
    handoff_source, transcript_record, crate_records = (
        validate_rust_package_handoff_manifest(manifest.value)
    )
    _require(
        handoff_source == expected_source,
        "Rust package handoff source identity differs",
    )
    try:
        transcript = read_fixed_file_snapshot(
            manifest_path.parent / RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
            safe_root=normalized_root,
            expected_leaf=RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
            label="Rust package handoff transcript",
            parent_depth=1,
            maximum=MAX_TRANSCRIPT_BYTES,
            file_mode=PRIVATE_FILE_MODE,
            expected_parent_entries=inventory,
        )
    except PublicationReceiptIOError as exc:
        raise RustPackageHandoffError(str(exc)) from exc
    _require(
        transcript.size == transcript_record["size"]
        and transcript.sha256 == transcript_record["sha256"],
        "Rust package handoff transcript differs from its manifest",
    )
    try:
        package_contract = validate_rust_package_contract_transcript(
            transcript.data
        )
    except RustPublishContractError as exc:
        raise RustPackageHandoffError(str(exc)) from exc
    _require(
        package_contract.source_commit == expected_source.source_commit,
        "Rust package transcript source differs from handoff source S",
    )

    crate_snapshots: list[RustPackageHandoffCrateSnapshot] = []
    total_size = 0
    for (name, dependencies), record in zip(
        CRATE_PUBLICATION_TOPOLOGY, crate_records
    ):
        crate_file = record["crate_file"]
        _require(isinstance(crate_file, str), f"{name} archive name type differs")
        try:
            archive = read_fixed_file_snapshot(
                manifest_path.parent / crate_file,
                safe_root=normalized_root,
                expected_leaf=crate_file,
                label=f"{name} handoff .crate archive",
                parent_depth=1,
                maximum=MAX_CRATE_BYTES,
                file_mode=PRIVATE_FILE_MODE,
                expected_parent_entries=inventory,
            )
        except PublicationReceiptIOError as exc:
            raise RustPackageHandoffError(str(exc)) from exc
        _require(archive.size > 0, f"{name} .crate archive must not be empty")
        _require(
            archive.size == record["crate_size"]
            and archive.sha256 == record["crate_sha256"],
            f"{name} handoff archive differs from its manifest",
        )
        total_size += archive.size
        _require(
            total_size <= MAX_TOTAL_CRATE_BYTES,
            "aggregate .crate input exceeds the byte limit",
        )
        crate_snapshots.append(
            RustPackageHandoffCrateSnapshot(
                name=name,
                version=PRODUCT_VERSION,
                dependencies=dependencies,
                file=archive,
            )
        )
    try:
        final_manifest = read_fixed_json_snapshot(
            manifest_path,
            safe_root=normalized_root,
            expected_leaf=RUST_PACKAGE_HANDOFF_MANIFEST_NAME,
            label="resampled Rust package handoff manifest",
            parent_depth=1,
            maximum=MAX_HANDOFF_MANIFEST_BYTES,
            expected_parent_entries=inventory,
        )
    except PublicationReceiptIOError as exc:
        raise RustPackageHandoffError(str(exc)) from exc
    _require(
        final_manifest.file.data == manifest.file.data,
        "Rust package handoff manifest changed while loading",
    )
    return RustPackageHandoffSnapshot(
        handoff_root=normalized_root,
        inventory=inventory,
        source=handoff_source,
        manifest=manifest.file,
        transcript=transcript,
        package_contract=package_contract,
        crates=tuple(crate_snapshots),
    )
