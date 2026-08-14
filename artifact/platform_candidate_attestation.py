#!/usr/bin/env python3
"""Verify one fixed alpha.3 platform-candidate provenance transaction.

The shell entrypoint owns only Git and ``gh`` orchestration.  This module owns
the candidate byte snapshot, strict GitHub verification-result parsing, the
pre/post candidate comparison, and publication of one PII-safe projection.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from dataclasses import dataclass
from collections.abc import Iterator
from typing import Any, NoReturn, Sequence

from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from publication_receipt_io import (
    PublicationReceiptIOError,
    write_private_json_noreplace_at,
)
from platform_distribution_contract import (
    PLATFORM_CANDIDATE_ASSETS,
    PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS,
    RELEASE_TAG,
)


MAX_ATTESTATION_BYTES = 16 * 1024 * 1024
MAX_ASSET_BYTES = 512 * 1024 * 1024
MAX_CHECKSUM_BYTES = 1024 * 1024
MAX_PRIVATE_STDERR_BYTES = 1024 * 1024
MAX_SNAPSHOT_BYTES = 1024 * 1024
MAX_RUN_ID = (1 << 63) - 1
MAX_RUN_ATTEMPT = (1 << 31) - 1
REPOSITORY = "billlza/q-periapt"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
REPOSITORY_OWNER_URL = "https://github.com/billlza"
WORKFLOW_PATH = ".github/workflows/abi2-platform-candidate.yml"
RELEASE_REF = f"refs/tags/{RELEASE_TAG}"
WORKFLOW_URI = f"{REPOSITORY_URL}/{WORKFLOW_PATH}@{RELEASE_REF}"
RUN_URI_PREFIX = f"{REPOSITORY_URL}/actions/runs/"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
VERIFICATION_MEDIA_TYPE = (
    "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
)
CANDIDATE_SNAPSHOT_NAME = "candidate-snapshot.json"
PROJECTION_NAME = "candidate-attestation-projection.json"
REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
CANDIDATE_INPUT_ROOT = REPOSITORY_ROOT / "target" / "abi2-platform-candidate-inputs"
CANDIDATE_VERIFICATION_ROOT = (
    REPOSITORY_ROOT
    / "target"
    / "abi2-platform-candidate-verification"
)
CANDIDATE_RAW_ROOT = CANDIDATE_VERIFICATION_ROOT / "raw"
CANDIDATE_PROJECTION_ROOT = (
    REPOSITORY_ROOT / "target" / "abi2-platform-candidate-projections"
)
SNAPSHOT_SCHEMA_VERSION = 1
SNAPSHOT_KIND = "qperiapt.platform_candidate_snapshot"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_SUBJECT_NAME = re.compile(r"^[A-Za-z0-9._+-]+$")
SAFE_DIRECTORY_LEAF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
STRICT_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


class CandidateAttestationError(ValueError):
    """Candidate bytes or one verification result violates release policy."""


@dataclass(frozen=True, slots=True)
class CandidateFile:
    """One exact candidate subject sampled from a regular file."""

    name: str
    size: int
    sha256: str

    def record(self) -> dict[str, object]:
        """Return the PII-safe snapshot record."""

        return {"bytes": self.size, "name": self.name, "sha256": self.sha256}

    def subject(self) -> dict[str, object]:
        """Return the in-toto subject projection."""

        return {"digest": {"sha256": self.sha256}, "name": self.name}


@dataclass(frozen=True, slots=True)
class CandidateSnapshot:
    """The exact six-file CI candidate sampled at one point in time."""

    files: tuple[CandidateFile, ...]

    def document(self) -> dict[str, object]:
        """Return the canonical private snapshot document."""

        return {
            "files": [item.record() for item in self.files],
            "kind": SNAPSHOT_KIND,
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
        }

    def subjects(self) -> list[dict[str, object]]:
        """Return subjects in the workflow's fixed attestation order."""

        return [item.subject() for item in self.files]


@dataclass(frozen=True, slots=True)
class VerifiedRecord:
    """Canonicalized policy fields from one exact verification result."""

    statement: bytes
    record: bytes
    run_id: int
    run_attempt: int
    verified_at: str


def _fail(message: str) -> NoReturn:
    raise CandidateAttestationError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, Any]:
    _require(
        isinstance(value, dict) and all(isinstance(key, str) for key in value),
        f"{label} must be an object",
    )
    return value


def _exact_keys(
    value: dict[str, Any], expected: frozenset[str], label: str
) -> None:
    _require(frozenset(value) == expected, f"{label} fields differ")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise CandidateAttestationError(
            "verification result is not canonical JSON"
        ) from exc


def _private_file_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise EvidenceIOError("private evidence file metadata differs")


def _snapshot_file(
    path: pathlib.Path,
    *,
    maximum: int,
    label: str,
    private: bool = False,
) -> FileSnapshot:
    try:
        return read_regular_snapshot(
            path,
            maximum=maximum,
            label=label,
            validate_metadata=_private_file_metadata if private else None,
        )
    except EvidenceIOError as exc:
        raise CandidateAttestationError(f"cannot safely read {label}") from exc


def _validate_contract_names() -> None:
    expected = (*PLATFORM_CANDIDATE_ASSETS, "CANDIDATE_SHA256SUMS")
    _require(
        PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS == expected,
        "candidate subject contract order differs",
    )
    _require(
        len(expected) == 6
        and len(set(expected)) == 6
        and all(SAFE_SUBJECT_NAME.fullmatch(name) is not None for name in expected),
        "candidate subject names are not six exact shell-safe leaves",
    )


def _normalized_safe_root(
    safe_root: pathlib.Path,
    *,
    label: str,
    required_mode: int | None = None,
) -> pathlib.Path:
    """Return one fixed, owned, canonical directory used as an I/O boundary."""

    root_text = os.path.realpath(os.fspath(safe_root))
    _require(
        safe_root.is_absolute()
        and root_text == os.path.abspath(os.fspath(safe_root)),
        f"{label} safe root must be canonical",
    )
    root = pathlib.Path(root_text)
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise CandidateAttestationError(f"cannot inspect {label} safe root") from exc
    valid = (
        stat.S_ISDIR(metadata.st_mode)
        and not root.is_symlink()
        and metadata.st_uid == os.geteuid()
    )
    if required_mode is not None:
        valid = valid and stat.S_IMODE(metadata.st_mode) == required_mode
    _require(valid, f"{label} safe root is not an owned non-symlink directory")
    return root


def _normalize_path_under_root(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path,
    label: str,
    required_root_mode: int | None = None,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Resolve a CLI path once and prove containment below one fixed root."""

    if not path.is_absolute():
        raise CandidateAttestationError(f"{label} must be absolute")
    root = _normalized_safe_root(
        safe_root,
        label=label,
        required_mode=required_root_mode,
    )
    supplied_text = os.fspath(path)
    normalized_text = os.path.realpath(supplied_text)
    root_text = os.fspath(root)
    if not normalized_text.startswith(root_text + os.sep):
        raise CandidateAttestationError(
            f"{label} is outside its fixed safe root"
        )
    if normalized_text != os.path.abspath(supplied_text):
        raise CandidateAttestationError(
            f"{label} must contain no symlink or traversal aliases"
        )
    return pathlib.Path(normalized_text), root


def _candidate_directory(path: pathlib.Path) -> pathlib.Path:
    normalized, _root = _normalize_path_under_root(
        path,
        safe_root=CANDIDATE_INPUT_ROOT,
        label="candidate directory",
        required_root_mode=0o700,
    )
    try:
        metadata = normalized.lstat()
    except OSError as exc:
        raise CandidateAttestationError("cannot inspect candidate directory") from exc
    _require(
        stat.S_ISDIR(metadata.st_mode) and not normalized.is_symlink(),
        "candidate directory must be a non-symlink directory",
    )
    return normalized


def _snapshot_candidate_root(root: pathlib.Path) -> CandidateSnapshot:
    """Sample an already-normalized candidate directory."""

    _validate_contract_names()
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise CandidateAttestationError("cannot enumerate candidate directory") from exc
    actual: set[str] = set()
    for entry_path in entries:
        try:
            metadata = entry_path.lstat()
        except OSError as exc:
            raise CandidateAttestationError("cannot inspect candidate entry") from exc
        _require(
            stat.S_ISREG(metadata.st_mode) and not entry_path.is_symlink(),
            "candidate directory contains a non-regular entry",
        )
        actual.add(entry_path.name)
    expected = set(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS)
    _require(actual == expected, "candidate asset set differs")

    sums_name = "CANDIDATE_SHA256SUMS"
    sums_snapshot = _snapshot_file(
        root / sums_name,
        maximum=MAX_CHECKSUM_BYTES,
        label="candidate checksums",
    )
    try:
        sums_text = sums_snapshot.data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CandidateAttestationError("candidate checksums are not ASCII") from exc
    _require(sums_text.endswith("\n"), "candidate checksums lack final newline")
    parsed: dict[str, str] = {}
    for line in sums_text.splitlines():
        parts = line.split("  ", 1)
        _require(len(parts) == 2, "candidate checksum line is malformed")
        digest, name = parts
        _require(
            HEX_64.fullmatch(digest) is not None
            and name in PLATFORM_CANDIDATE_ASSETS
            and name not in parsed,
            "candidate checksum entry is invalid",
        )
        parsed[name] = digest
    _require(
        list(parsed) == sorted(parsed)
        and set(parsed) == set(PLATFORM_CANDIDATE_ASSETS),
        "candidate checksums are incomplete or not canonical",
    )

    files: list[CandidateFile] = []
    for name in PLATFORM_CANDIDATE_ASSETS:
        asset = _snapshot_file(
            root / name,
            maximum=MAX_ASSET_BYTES,
            label=f"candidate asset {name}",
        )
        _require(asset.size > 0, f"candidate asset is empty: {name}")
        _require(parsed[name] == asset.sha256, f"candidate checksum differs: {name}")
        files.append(CandidateFile(name, asset.size, asset.sha256))
    _require(sums_snapshot.size > 0, "candidate checksums are empty")
    files.append(CandidateFile(sums_name, sums_snapshot.size, sums_snapshot.sha256))
    return CandidateSnapshot(tuple(files))


def snapshot_candidate(path: pathlib.Path) -> CandidateSnapshot:
    """Sample and fully checksum the fixed candidate set."""

    return _snapshot_candidate_root(_candidate_directory(path))


def _parse_snapshot_document(value: object) -> CandidateSnapshot:
    document = _object(value, "candidate snapshot")
    _exact_keys(
        document,
        frozenset({"files", "kind", "schema_version"}),
        "candidate snapshot",
    )
    _require(
        type(document["schema_version"]) is int
        and document["schema_version"] == SNAPSHOT_SCHEMA_VERSION
        and document["kind"] == SNAPSHOT_KIND,
        "candidate snapshot identity differs",
    )
    raw_files = document["files"]
    _require(isinstance(raw_files, list), "candidate snapshot files are not a list")
    _require(
        len(raw_files) == len(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS),
        "candidate snapshot file count differs",
    )
    files: list[CandidateFile] = []
    for index, raw_file in enumerate(raw_files):
        record = _object(raw_file, "candidate snapshot file")
        _exact_keys(
            record,
            frozenset({"bytes", "name", "sha256"}),
            "candidate snapshot file",
        )
        expected_name = PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS[index]
        _require(record["name"] == expected_name, "candidate snapshot order differs")
        _require(
            type(record["bytes"]) is int and record["bytes"] > 0,
            "candidate snapshot size is invalid",
        )
        _require(
            isinstance(record["sha256"], str)
            and HEX_64.fullmatch(record["sha256"]) is not None,
            "candidate snapshot digest is invalid",
        )
        files.append(
            CandidateFile(expected_name, record["bytes"], record["sha256"])
        )
    return CandidateSnapshot(tuple(files))


def load_candidate_snapshot(path: pathlib.Path) -> CandidateSnapshot:
    """Load one private preflight snapshot through strict JSON parsing."""

    path = _normalize_fixed_output_path(
        path,
        safe_root=CANDIDATE_RAW_ROOT,
        expected_name=CANDIDATE_SNAPSHOT_NAME,
        label="candidate preflight snapshot",
    )
    raw = _snapshot_file(
        path,
        maximum=MAX_SNAPSHOT_BYTES,
        label="candidate preflight snapshot",
        private=True,
    )
    try:
        value = parse_strict_json_bytes(raw.data, label="candidate preflight snapshot")
    except EvidenceIOError as exc:
        raise CandidateAttestationError("candidate snapshot JSON is invalid") from exc
    return _parse_snapshot_document(value)


def _private_directory(path: pathlib.Path, label: str) -> int:
    _require(path.is_absolute(), f"{label} must be absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CandidateAttestationError(f"cannot inspect {label}") from exc
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        f"{label} is not a private non-symlink directory",
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CandidateAttestationError(f"cannot open {label}") from exc
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or opened.st_dev != metadata.st_dev
        or opened.st_ino != metadata.st_ino
    ):
        os.close(descriptor)
        _fail(f"{label} identity changed")
    return descriptor


@contextlib.contextmanager
def _private_directory_handle(path: pathlib.Path, label: str) -> Iterator[int]:
    """Close a pinned directory without replacing the primary exception."""

    descriptor = _private_directory(path, label)
    primary: BaseException | None = None
    try:
        yield descriptor
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            detail = f"cannot close {label}"
            if primary is not None:
                primary.add_note(detail)
            else:
                raise CandidateAttestationError(detail) from exc


def _normalize_fixed_output_path(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path,
    expected_name: str,
    label: str,
) -> pathlib.Path:
    """Normalize one absent fixed-leaf output below a private direct child."""

    _require(path.is_absolute(), f"{label} must be absolute")
    _require(path.name == expected_name, f"{label} leaf differs")
    parent, root = _normalize_path_under_root(
        path.parent,
        safe_root=safe_root,
        label=f"{label} parent",
        required_root_mode=0o700,
    )
    _require(parent.parent == root, f"{label} parent must be a direct safe-root child")
    normalized = parent / expected_name
    if os.path.realpath(os.fspath(normalized)) != os.fspath(normalized):
        raise CandidateAttestationError(
            f"{label} must contain no symlink aliases"
        )
    return normalized


def _validate_output_absent(
    path: pathlib.Path,
    *,
    expected_name: str,
    label: str,
) -> None:
    with _private_directory_handle(
        path.parent, f"{label} parent"
    ) as parent_fd:
        try:
            os.stat(expected_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise CandidateAttestationError(f"cannot inspect {label}") from exc
        _fail(f"{label} already exists")


def _validate_projection_target(
    candidate: pathlib.Path, projection_path: pathlib.Path
) -> tuple[pathlib.Path, pathlib.Path]:
    """Require the projection tree to be disjoint from candidate source bytes."""

    candidate_root = _candidate_directory(candidate)
    normalized_projection = _normalize_fixed_output_path(
        projection_path,
        safe_root=CANDIDATE_PROJECTION_ROOT,
        expected_name=PROJECTION_NAME,
        label="candidate projection",
    )
    projection_parent = normalized_projection.parent
    try:
        projection_parent.relative_to(candidate_root)
    except ValueError:
        pass
    else:
        _fail("candidate projection parent is inside the candidate directory")
    _validate_output_absent(
        normalized_projection,
        expected_name=PROJECTION_NAME,
        label="candidate projection",
    )
    return candidate_root, normalized_projection


def _write_private_json(
    path: pathlib.Path, expected_name: str, value: object, label: str
) -> str:
    _validate_output_absent(path, expected_name=expected_name, label=label)
    with _private_directory_handle(
        path.parent, f"{label} parent"
    ) as parent_fd:
        try:
            return write_private_json_noreplace_at(
                parent_fd,
                expected_name,
                value,
                label=label,
                maximum=MAX_SNAPSHOT_BYTES,
            )
        except PublicationReceiptIOError as exc:
            raise CandidateAttestationError(str(exc)) from exc


def write_candidate_snapshot(
    candidate: pathlib.Path,
    snapshot_path: pathlib.Path,
    projection_path: pathlib.Path,
) -> None:
    """Capture preflight bytes and prevalidate the explicit projection target."""

    candidate_root, projection_path = _validate_projection_target(
        candidate,
        projection_path,
    )
    snapshot_path = _normalize_fixed_output_path(
        snapshot_path,
        safe_root=CANDIDATE_RAW_ROOT,
        expected_name=CANDIDATE_SNAPSHOT_NAME,
        label="candidate snapshot",
    )
    _validate_output_absent(
        snapshot_path,
        expected_name=CANDIDATE_SNAPSHOT_NAME,
        label="candidate snapshot",
    )
    snapshot = _snapshot_candidate_root(candidate_root)
    _write_private_json(
        snapshot_path,
        CANDIDATE_SNAPSHOT_NAME,
        snapshot.document(),
        "candidate snapshot",
    )


def preflight_candidate_paths(
    candidate: pathlib.Path,
    projection_path: pathlib.Path,
) -> None:
    """Validate caller-controlled paths before the shell invokes Git or GitHub."""

    _validate_projection_target(candidate, projection_path)


def _utc_timestamp(value: object) -> str:
    _require(
        isinstance(value, str) and STRICT_TIMESTAMP.fullmatch(value) is not None,
        "verified timestamp is malformed",
    )
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CandidateAttestationError("verified timestamp is malformed") from exc
    _require(parsed.tzinfo is not None, "verified timestamp lacks a timezone")
    return parsed.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bounded_positive_decimal(value: str, *, maximum: int, label: str) -> int:
    """Parse a positive decimal without exposing Python's unbounded-int limit."""

    maximum_text = str(maximum)
    _require(
        len(value) <= len(maximum_text)
        and re.fullmatch(r"[1-9][0-9]*", value) is not None
        and (len(value) < len(maximum_text) or value <= maximum_text),
        f"{label} is out of range",
    )
    return int(value)


def _verification_record(
    path: pathlib.Path,
    *,
    asset: str,
    expected_commit: str,
    expected_subjects: list[dict[str, object]],
) -> VerifiedRecord:
    raw = _snapshot_file(
        path,
        maximum=MAX_ATTESTATION_BYTES,
        label=f"raw attestation for {asset}",
        private=True,
    )
    try:
        value = parse_strict_json_bytes(raw.data, label=f"attestation for {asset}")
    except EvidenceIOError as exc:
        raise CandidateAttestationError(
            f"attestation JSON is invalid for {asset}"
        ) from exc
    _require(
        isinstance(value, list) and len(value) == 1,
        f"attestation result count differs for {asset}",
    )
    envelope = _object(value[0], f"attestation envelope for {asset}")
    _exact_keys(
        envelope,
        frozenset({"attestation", "verificationResult"}),
        "attestation envelope",
    )
    _require(
        isinstance(envelope["attestation"], dict),
        "attestation bundle is not an object",
    )
    result = _object(envelope["verificationResult"], "verification result")
    _exact_keys(
        result,
        frozenset(
            {
                "mediaType",
                "signature",
                "statement",
                "verifiedIdentity",
                "verifiedTimestamps",
            }
        ),
        "verification result",
    )
    _require(
        result["mediaType"] == VERIFICATION_MEDIA_TYPE,
        "verification result media type differs",
    )

    statement = _object(result["statement"], "attestation statement")
    _exact_keys(
        statement,
        frozenset({"_type", "predicate", "predicateType", "subject"}),
        "attestation statement",
    )
    _require(statement["_type"] == STATEMENT_TYPE, "attestation statement type differs")
    _require(
        statement["predicateType"] == PREDICATE_TYPE,
        "attestation predicate type differs",
    )
    _require(
        statement["subject"] == expected_subjects,
        "attestation subjects differ from candidate bytes",
    )

    predicate = _object(statement["predicate"], "attestation predicate")
    _exact_keys(
        predicate,
        frozenset({"buildDefinition", "runDetails"}),
        "attestation predicate",
    )
    build = _object(predicate["buildDefinition"], "attestation build definition")
    _exact_keys(
        build,
        frozenset(
            {
                "buildType",
                "externalParameters",
                "internalParameters",
                "resolvedDependencies",
            }
        ),
        "attestation build definition",
    )
    _require(
        build["buildType"] == "https://actions.github.io/buildtypes/workflow/v1",
        "attestation build type differs",
    )
    _require(
        build["externalParameters"]
        == {
            "workflow": {
                "path": WORKFLOW_PATH,
                "ref": RELEASE_REF,
                "repository": REPOSITORY_URL,
            }
        },
        "attestation workflow parameters differ",
    )
    internal = _object(build["internalParameters"], "attestation internal parameters")
    _exact_keys(
        internal, frozenset({"github"}), "attestation internal parameters"
    )
    github = _object(internal["github"], "attestation GitHub parameters")
    _exact_keys(
        github,
        frozenset(
            {
                "event_name",
                "repository_id",
                "repository_owner_id",
                "runner_environment",
            }
        ),
        "attestation GitHub parameters",
    )
    _require(
        github["event_name"] == "push"
        and github["runner_environment"] == "github-hosted"
        and isinstance(github["repository_id"], str)
        and re.fullmatch(r"[1-9][0-9]*", github["repository_id"]) is not None
        and isinstance(github["repository_owner_id"], str)
        and re.fullmatch(r"[1-9][0-9]*", github["repository_owner_id"]) is not None,
        "attestation GitHub execution identity differs",
    )
    _require(
        build["resolvedDependencies"]
        == [
            {
                "digest": {"gitCommit": expected_commit},
                "uri": f"git+{REPOSITORY_URL}@{RELEASE_REF}",
            }
        ],
        "attestation source dependency differs",
    )

    signature = _object(result["signature"], "attestation signature")
    _exact_keys(signature, frozenset({"certificate"}), "attestation signature")
    certificate = _object(signature["certificate"], "attestation certificate")
    certificate_keys = frozenset(
        {
            "buildConfigDigest",
            "buildConfigURI",
            "buildSignerDigest",
            "buildSignerURI",
            "buildTrigger",
            "certificateIssuer",
            "githubWorkflowName",
            "githubWorkflowRef",
            "githubWorkflowRepository",
            "githubWorkflowSHA",
            "githubWorkflowTrigger",
            "issuer",
            "runInvocationURI",
            "runnerEnvironment",
            "sourceRepositoryDigest",
            "sourceRepositoryIdentifier",
            "sourceRepositoryOwnerIdentifier",
            "sourceRepositoryOwnerURI",
            "sourceRepositoryRef",
            "sourceRepositoryURI",
            "sourceRepositoryVisibilityAtSigning",
            "subjectAlternativeName",
        }
    )
    _exact_keys(certificate, certificate_keys, "attestation certificate")
    fixed_certificate = {
        "buildConfigDigest": expected_commit,
        "buildConfigURI": WORKFLOW_URI,
        "buildSignerDigest": expected_commit,
        "buildSignerURI": WORKFLOW_URI,
        "buildTrigger": "push",
        "certificateIssuer": "https://token.actions.githubusercontent.com",
        "githubWorkflowName": "ABI2 platform release candidate",
        "githubWorkflowRef": RELEASE_REF,
        "githubWorkflowRepository": REPOSITORY,
        "githubWorkflowSHA": expected_commit,
        "githubWorkflowTrigger": "push",
        "issuer": "https://fulcio.sigstore.dev",
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryDigest": expected_commit,
        "sourceRepositoryIdentifier": github["repository_id"],
        "sourceRepositoryOwnerIdentifier": github["repository_owner_id"],
        "sourceRepositoryOwnerURI": REPOSITORY_OWNER_URL,
        "sourceRepositoryRef": RELEASE_REF,
        "sourceRepositoryURI": REPOSITORY_URL,
        "sourceRepositoryVisibilityAtSigning": "public",
        "subjectAlternativeName": WORKFLOW_URI,
    }
    for key, expected in fixed_certificate.items():
        _require(certificate[key] == expected, f"attestation certificate {key} differs")
    run_uri = certificate["runInvocationURI"]
    _require(isinstance(run_uri, str), "attestation run URI is not a string")
    run_match = re.fullmatch(
        re.escape(RUN_URI_PREFIX)
        + r"([1-9][0-9]*)/attempts/([1-9][0-9]*)",
        run_uri,
    )
    _require(run_match is not None, "attestation run URI is malformed")
    run_id = _bounded_positive_decimal(
        run_match.group(1),
        maximum=MAX_RUN_ID,
        label="attestation run ID",
    )
    run_attempt = _bounded_positive_decimal(
        run_match.group(2),
        maximum=MAX_RUN_ATTEMPT,
        label="attestation run attempt",
    )

    run_details = _object(predicate["runDetails"], "attestation run details")
    _require(
        run_details
        == {
            "builder": {"id": WORKFLOW_URI},
            "metadata": {"invocationId": run_uri},
        },
        "attestation run details differ",
    )
    _require(
        result["verifiedIdentity"]
        == {
            "issuer": {"issuer": "", "regexp": ".*"},
            "runnerEnvironment": "github-hosted",
            "subjectAlternativeName": {
                "regexp": f"^{REPOSITORY_URL}/{WORKFLOW_PATH}",
                "subjectAlternativeName": "",
            },
        },
        "verified attestation identity differs",
    )
    timestamps = result["verifiedTimestamps"]
    _require(
        isinstance(timestamps, list) and len(timestamps) == 1,
        "verified timestamp count differs",
    )
    timestamp = _object(timestamps[0], "verified timestamp")
    _require(
        timestamp.get("type") == "Tlog"
        and timestamp.get("uri") == "https://rekor.sigstore.dev"
        and frozenset(timestamp) == frozenset({"timestamp", "type", "uri"}),
        "verified timestamp identity differs",
    )
    verified_at = _utc_timestamp(timestamp["timestamp"])
    timestamp["timestamp"] = verified_at
    return VerifiedRecord(
        statement=_canonical_json(statement),
        record=_canonical_json(result),
        run_id=run_id,
        run_attempt=run_attempt,
        verified_at=verified_at,
    )


def _raw_attestation_directory(path: pathlib.Path) -> pathlib.Path:
    normalized, root = _normalize_path_under_root(
        path,
        safe_root=CANDIDATE_RAW_ROOT,
        label="candidate attestation directory",
        required_root_mode=0o700,
    )
    _require(
        normalized.parent == root,
        "candidate attestation directory must be a direct safe-root child",
    )
    _require(
        SAFE_DIRECTORY_LEAF.fullmatch(normalized.name) is not None,
        "candidate attestation directory leaf is unsafe",
    )
    expected = {CANDIDATE_SNAPSHOT_NAME}
    for subject in PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS:
        expected.add(f"{subject}.json")
        expected.add(f"{subject}.stderr")
    with _private_directory_handle(
        normalized, "candidate attestation directory"
    ) as descriptor:
        try:
            actual = set(os.listdir(descriptor))
        except OSError as exc:
            raise CandidateAttestationError(
                "cannot enumerate candidate attestation directory"
            ) from exc
    _require(actual == expected, "candidate attestation file set differs")
    for subject in PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS:
        _snapshot_file(
            normalized / f"{subject}.stderr",
            maximum=MAX_PRIVATE_STDERR_BYTES,
            label=f"candidate attestation stderr for {subject}",
            private=True,
        )
    return normalized


def verify_candidate_attestations(
    candidate: pathlib.Path,
    expected_commit: str,
    projection_path: pathlib.Path,
    attestation_dir: pathlib.Path,
    preflight_snapshot_path: pathlib.Path,
) -> tuple[str, int]:
    """Re-snapshot candidate bytes, verify six records, and publish projection."""

    _require(HEX_40.fullmatch(expected_commit) is not None, "expected commit is malformed")
    candidate, projection_path = _validate_projection_target(
        candidate,
        projection_path,
    )
    attestation_dir = _raw_attestation_directory(attestation_dir)
    preflight_snapshot_path = _normalize_fixed_output_path(
        preflight_snapshot_path,
        safe_root=CANDIDATE_RAW_ROOT,
        expected_name=CANDIDATE_SNAPSHOT_NAME,
        label="candidate preflight snapshot",
    )
    _require(
        preflight_snapshot_path == attestation_dir / CANDIDATE_SNAPSHOT_NAME,
        "candidate preflight snapshot path differs",
    )
    preflight = load_candidate_snapshot(preflight_snapshot_path)
    post_gh = _snapshot_candidate_root(candidate)
    _require(
        post_gh.document() == preflight.document(),
        "candidate bytes changed during GitHub verification",
    )
    expected_subjects = preflight.subjects()

    shared: VerifiedRecord | None = None
    for asset in PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS:
        record = _verification_record(
            attestation_dir / f"{asset}.json",
            asset=asset,
            expected_commit=expected_commit,
            expected_subjects=expected_subjects,
        )
        if shared is None:
            shared = record
        else:
            _require(record.statement == shared.statement, "candidate statements differ")
            _require(record.record == shared.record, "candidate records differ")
            _require(record.run_id == shared.run_id, "candidate run IDs differ")
            _require(
                record.run_attempt == shared.run_attempt,
                "candidate run attempts differ",
            )
            _require(
                record.verified_at == shared.verified_at,
                "candidate verification timestamps differ",
            )
    _require(shared is not None, "candidate verification result set is empty")

    projection: dict[str, object] = {
        "certificate_san": WORKFLOW_URI,
        "predicate_type": PREDICATE_TYPE,
        "signer_workflow": WORKFLOW_URI,
        "source_digest": expected_commit,
        "source_ref": RELEASE_REF,
        "subjects": expected_subjects,
        "verification_record_sha256": hashlib.sha256(shared.record).hexdigest(),
        "verified": True,
        "verified_at": shared.verified_at,
        "workflow_run_attempt": shared.run_attempt,
        "workflow_run_id": shared.run_id,
    }
    projection_sha256 = _write_private_json(
        projection_path,
        PROJECTION_NAME,
        projection,
        "candidate projection",
    )
    return projection_sha256, shared.run_id


def _usage() -> str:
    return (
        "usage: platform_candidate_attestation.py release-tag | subject-names | "
        "validate-raw-root | "
        "preflight CANDIDATE_DIRECTORY PROJECTION_OUTPUT | "
        "snapshot CANDIDATE_DIRECTORY SNAPSHOT_OUTPUT PROJECTION_OUTPUT | "
        "verify CANDIDATE_DIRECTORY EXPECTED_COMMIT PROJECTION_OUTPUT "
        "RAW_ATTESTATION_DIRECTORY SNAPSHOT_INPUT"
    )


def _main(arguments: Sequence[str]) -> int:
    if list(arguments) == ["release-tag"]:
        print(RELEASE_TAG)
        return 0
    if list(arguments) == ["subject-names"]:
        print("\n".join(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS))
        return 0
    if list(arguments) == ["validate-raw-root"]:
        _normalized_safe_root(
            CANDIDATE_VERIFICATION_ROOT,
            label="candidate verification",
            required_mode=0o700,
        )
        _normalized_safe_root(
            CANDIDATE_RAW_ROOT,
            label="candidate attestation",
            required_mode=0o700,
        )
        return 0
    if len(arguments) == 3 and arguments[0] == "preflight":
        preflight_candidate_paths(
            pathlib.Path(arguments[1]),
            pathlib.Path(arguments[2]),
        )
        return 0
    if len(arguments) == 4 and arguments[0] == "snapshot":
        write_candidate_snapshot(
            pathlib.Path(arguments[1]),
            pathlib.Path(arguments[2]),
            pathlib.Path(arguments[3]),
        )
        return 0
    if len(arguments) == 6 and arguments[0] == "verify":
        digest, run_id = verify_candidate_attestations(
            pathlib.Path(arguments[1]),
            arguments[2],
            pathlib.Path(arguments[3]),
            pathlib.Path(arguments[4]),
            pathlib.Path(arguments[5]),
        )
        print(
            "ABI2_PLATFORM_CANDIDATE_ATTESTATION_VERIFY_PASS "
            f"assets=6 commit={arguments[2]} "
            f"projection_sha256={digest} run_id={run_id}"
        )
        return 0
    print(f"error: {_usage()}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(_main(sys.argv[1:]))
    except CandidateAttestationError as exc:
        raise SystemExit(f"error: {exc}") from None
