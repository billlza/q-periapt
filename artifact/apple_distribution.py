#!/usr/bin/env python3
"""Fail-closed evidence validation for Apple XCFramework distribution releases."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import uuid
import zipfile
from dataclasses import dataclass
from typing import Any, NoReturn

from evidence_io import (
    EvidenceIOError,
    load_json_object_snapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)


MAX_TEXT_BYTES = 256 * 1024
MAX_CERTIFICATE_BYTES = 1024 * 1024
MAX_NOTARY_JSON_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_SOURCE_TREE_ENTRIES = 8_192
MAX_SOURCE_TREE_REGULAR_BYTES = 1024 * 1024 * 1024
MAX_RELEASE_TREE_ENTRIES = 65_536
MAX_RELEASE_TREE_REGULAR_BYTES = 8 * 1024 * 1024 * 1024
MAX_MAIN_GIT_TREE_ENTRIES = 65_536
MAX_MAIN_GIT_TREE_REGULAR_BYTES = 4 * 1024 * 1024 * 1024
MAX_TREE_DEPTH = 64
EXPECTED_IDENTITY_CLASS = "Developer ID Application"
EXPECTED_XCFRAMEWORK_LIBRARIES = frozenset(
    {
        "ios-arm64/libq_periapt_ffi_abi2.a",
        "ios-arm64_x86_64-simulator/libq_periapt_ffi_abi2.a",
        "macos-arm64_x86_64/libq_periapt_ffi_abi2.a",
    }
)
HEX_40 = re.compile(r"^[0-9A-Fa-f]{40}$")
HEX_64 = re.compile(r"^[0-9A-Fa-f]{64}$")
TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")

StatSignature = tuple[int, int, int, int, int, int, int]
RelativePath = tuple[str, ...]


@dataclass(frozen=True)
class _SynchronizedDirectoryTree:
    snapshots: dict[RelativePath, StatSignature]
    directory_children: dict[RelativePath, tuple[str, ...]]
    symlink_targets: dict[RelativePath, tuple[str, RelativePath]]
    excluded_root_entries: frozenset[str]
    reject_other_writable: bool


@dataclass
class _TreeTraversalBudget:
    label: str
    maximum_entries: int
    maximum_regular_bytes: int
    maximum_depth: int
    entries: int = 0
    regular_bytes: int = 0

    def record(self, state: os.stat_result, relative: RelativePath) -> None:
        if len(relative) > self.maximum_depth:
            _fail(f"{self.label} exceeds maximum directory depth {self.maximum_depth}")
        self.entries += 1
        if self.entries > self.maximum_entries:
            _fail(f"{self.label} exceeds maximum entry count {self.maximum_entries}")
        if stat.S_ISREG(state.st_mode):
            self.regular_bytes += state.st_size
            if self.regular_bytes > self.maximum_regular_bytes:
                _fail(
                    f"{self.label} exceeds maximum regular-file bytes "
                    f"{self.maximum_regular_bytes}"
                )


class AppleDistributionError(ValueError):
    """Apple distribution evidence violates the release contract."""


def _fail(message: str) -> NoReturn:
    raise AppleDistributionError(message)


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _require_uuid(value: Any, label: str) -> str:
    text = _require_string(value, label)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise AppleDistributionError(f"{label} is not a UUID: {text}") from exc
    canonical = str(parsed)
    if text != canonical:
        _fail(f"{label} must use canonical lowercase UUID form: {text}")
    return canonical


def _require_sha256(value: Any, label: str) -> str:
    text = _require_string(value, label)
    if not HEX_64.fullmatch(text):
        _fail(f"{label} must be a 64-digit SHA-256 hex digest")
    return text.lower()


def _require_git_commit(value: Any, label: str) -> str:
    text = _require_string(value, label)
    if not GIT_COMMIT.fullmatch(text):
        _fail(f"{label} must be a lowercase 40-digit Git commit")
    return text


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        _fail(
            f"{label} fields differ from the release schema: "
            f"missing={sorted(expected - actual)} unknown={sorted(actual - expected)}"
        )


def _json_document_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _json_document_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(_json_document_bytes(value)).hexdigest()


def _require_timestamp(value: Any, label: str) -> str:
    text = _require_string(value, label)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AppleDistributionError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        _fail(f"{label} must include a timezone")
    return text


def _single_field(fields: dict[str, list[str]], key: str) -> str:
    values = fields.get(key, [])
    if len(values) != 1 or not values[0]:
        _fail(f"codesign display must contain exactly one non-empty {key} field")
    return values[0]


def parse_codesign_display(text: str, *, expected_team_id: str) -> dict[str, Any]:
    """Parse the stable key/value subset of ``codesign --display --verbose=4``."""

    if not TEAM_ID.fullmatch(expected_team_id):
        _fail("expected Team ID must be ten uppercase alphanumeric characters")
    fields: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        fields.setdefault(key, []).append(value)

    authorities = fields.get("Authority", [])
    if len(authorities) < 3 or any(not authority for authority in authorities):
        _fail("codesign display must contain a complete non-empty authority chain")
    identity = authorities[0]
    if not identity.startswith(f"{EXPECTED_IDENTITY_CLASS}:"):
        _fail(f"unexpected leaf signing authority: {identity}")
    if not any(value == "Developer ID Certification Authority" for value in authorities[1:]):
        _fail("codesign authority chain lacks Developer ID Certification Authority")
    if not any(value == "Apple Root CA" for value in authorities[1:]):
        _fail("codesign authority chain lacks Apple Root CA")

    team_id = _single_field(fields, "TeamIdentifier")
    if team_id != expected_team_id:
        _fail(f"codesign TeamIdentifier {team_id} does not match {expected_team_id}")
    if fields.get("Signature") == ["adhoc"]:
        _fail("ad-hoc signatures are forbidden for Apple distribution")
    if "Runtime Version" in fields:
        _fail("static XCFramework signature unexpectedly enables hardened runtime")

    signature_size = _single_field(fields, "Signature size")
    if not signature_size.isdecimal() or int(signature_size) <= 0:
        _fail("codesign Signature size must be a positive integer")
    code_directories = re.findall(
        r"^CodeDirectory\b.*\bflags=0x([0-9A-Fa-f]+)\(([^)]*)\)",
        text,
        flags=re.MULTILINE,
    )
    if code_directories != [("0", "none")]:
        _fail(f"static XCFramework CodeDirectory flags are not exactly none: {code_directories}")

    cdhash = _single_field(fields, "CDHash")
    if not HEX_40.fullmatch(cdhash):
        _fail("codesign CDHash must be a 40-digit hex digest")

    timestamp = _single_field(fields, "Timestamp")
    return {
        "identity_class": EXPECTED_IDENTITY_CLASS,
        "authority": identity,
        "authority_chain": authorities,
        "team_id": team_id,
        "identifier": _single_field(fields, "Identifier"),
        "format": _single_field(fields, "Format"),
        "cdhash": cdhash.lower(),
        "secure_timestamp": timestamp,
        "hardened_runtime": False,
        "code_directory_flags": "none",
        "strict_verification": True,
    }


def _stream_sha256_regular_file(path: pathlib.Path, *, maximum: int, label: str) -> tuple[int, str]:
    lexical = pathlib.Path(path)
    if ".." in lexical.parts:
        _fail(f"{label} path must not contain '..': {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lexical, flags)
    except OSError as exc:
        raise AppleDistributionError(f"cannot open {label}: {path}: {exc}") from exc
    primary: BaseException | None = None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail(f"{label} is not a regular file: {path}")
        if before.st_size > maximum:
            _fail(f"{label} exceeds {maximum} bytes: {path}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                _fail(f"{label} exceeds {maximum} bytes while reading: {path}")
            digest.update(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or size != before.st_size:
            _fail(f"{label} changed while it was hashed: {path}")
        return size, digest.hexdigest()
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            if primary is not None:
                primary.add_note(f"closing {label} also failed: {exc}")
            else:
                raise AppleDistributionError(f"cannot close {label}: {exc}") from exc


def validate_xcframework_zip(path: pathlib.Path, *, require_signature: bool) -> None:
    """Validate the exact archive layout before any extractor sees it."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    primary: BaseException | None = None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail(f"XCFramework ZIP is not a regular file: {path}")
        if before.st_size > MAX_ARTIFACT_BYTES:
            _fail(f"XCFramework ZIP exceeds {MAX_ARTIFACT_BYTES} bytes: {path}")
        seen: set[str] = set()
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            try:
                with zipfile.ZipFile(stream) as archive:
                    for info in archive.infolist():
                        name = info.filename
                        pure = pathlib.PurePosixPath(name)
                        if name in seen:
                            _fail(f"duplicate XCFramework ZIP entry: {name}")
                        seen.add(name)
                        if (
                            not name
                            or name.startswith("/")
                            or "\\" in name
                            or ".." in pure.parts
                            or not pure.parts
                            or pure.parts[0] != "CQPeriapt.xcframework"
                        ):
                            _fail(f"unsafe or unexpected XCFramework ZIP entry: {name}")
                        if any(part in ("__MACOSX", ".DS_Store") for part in pure.parts):
                            _fail(f"Apple metadata leaked into XCFramework ZIP: {name}")
                        mode = (info.external_attr >> 16) & 0o170000
                        if mode in (
                            stat.S_IFLNK,
                            stat.S_IFCHR,
                            stat.S_IFBLK,
                            stat.S_IFIFO,
                            stat.S_IFSOCK,
                        ):
                            _fail(f"unsupported XCFramework ZIP entry type: {name}")
            except zipfile.BadZipFile as exc:
                raise AppleDistributionError(f"invalid XCFramework ZIP: {path}") from exc
        required = {"CQPeriapt.xcframework/Info.plist"}
        if require_signature:
            required.add("CQPeriapt.xcframework/_CodeSignature/CodeResources")
        missing = required - seen
        if missing:
            _fail(f"XCFramework ZIP lacks required entries: {sorted(missing)}")
        libraries = {
            name.removeprefix("CQPeriapt.xcframework/")
            for name in seen
            if name.endswith(".a")
        }
        if libraries != EXPECTED_XCFRAMEWORK_LIBRARIES:
            _fail(f"unexpected XCFramework ZIP library set: {sorted(libraries)}")
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            _fail(f"XCFramework ZIP changed while it was validated: {path}")
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            if primary is not None:
                primary.add_note(f"closing XCFramework ZIP also failed: {exc}")
            else:
                raise AppleDistributionError(f"cannot close XCFramework ZIP: {exc}") from exc


def _openssl_certificate_metadata(certificate: bytes) -> dict[str, str]:
    try:
        completed = subprocess.run(
            [
                "openssl",
                "x509",
                "-inform",
                "DER",
                "-noout",
                "-subject",
                "-issuer",
                "-serial",
                "-dates",
            ],
            input=certificate,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AppleDistributionError(f"cannot inspect leaf signing certificate: {exc}") from exc
    try:
        text = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppleDistributionError("openssl certificate metadata is not UTF-8") from exc
    metadata: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        metadata[key.strip()] = value.strip()
    required = ("subject", "issuer", "serial", "notBefore", "notAfter")
    for key in required:
        _require_string(metadata.get(key), f"certificate {key}")
    if EXPECTED_IDENTITY_CLASS not in metadata["subject"]:
        _fail("leaf certificate subject is not a Developer ID Application identity")
    return {key: metadata[key] for key in required}


def build_signing_evidence(
    *,
    xcframework: pathlib.Path,
    codesign_display: pathlib.Path,
    certificate: pathlib.Path,
    expected_team_id: str,
    expected_identity_sha1: str,
    expected_certificate_sha256: str,
) -> dict[str, Any]:
    if not HEX_40.fullmatch(expected_identity_sha1):
        _fail("expected identity SHA-1 must contain 40 hex digits")
    expected_certificate_sha256 = _require_sha256(
        expected_certificate_sha256, "expected certificate SHA-256"
    )
    display_snapshot = read_regular_snapshot(
        codesign_display,
        maximum=MAX_TEXT_BYTES,
        label="codesign display",
    )
    try:
        display_text = display_snapshot.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppleDistributionError("codesign display is not UTF-8") from exc
    signature = parse_codesign_display(display_text, expected_team_id=expected_team_id)

    certificate_snapshot = read_regular_snapshot(
        certificate,
        maximum=MAX_CERTIFICATE_BYTES,
        label="leaf signing certificate",
    )
    certificate_sha1 = hashlib.sha1(certificate_snapshot.data, usedforsecurity=False).hexdigest()
    if certificate_sha1 != expected_identity_sha1.lower():
        _fail("embedded leaf certificate SHA-1 does not match the pinned signing identity")
    if certificate_snapshot.sha256 != expected_certificate_sha256:
        _fail("embedded leaf certificate SHA-256 does not match the pinned certificate")
    certificate_metadata = _openssl_certificate_metadata(certificate_snapshot.data)

    xcframework = pathlib.Path(xcframework)
    if xcframework.name != "CQPeriapt.xcframework" or not xcframework.is_dir():
        _fail(f"unexpected XCFramework path: {xcframework}")
    libraries: dict[str, str] = {}
    for library in sorted(xcframework.rglob("*.a")):
        relative = library.relative_to(xcframework).as_posix()
        _, digest = _stream_sha256_regular_file(
            library,
            maximum=MAX_ARTIFACT_BYTES,
            label=f"XCFramework slice {relative}",
        )
        libraries[relative] = digest
    if frozenset(libraries) != EXPECTED_XCFRAMEWORK_LIBRARIES:
        _fail(f"unexpected signed XCFramework library set: {sorted(libraries)}")

    code_resources = xcframework / "_CodeSignature" / "CodeResources"
    _, code_resources_sha256 = _stream_sha256_regular_file(
        code_resources,
        maximum=MAX_TEXT_BYTES,
        label="XCFramework CodeResources",
    )
    return {
        "schema_version": 1,
        "kind": "qperiapt.apple_xcframework_signature",
        "signature": signature,
        "certificate": {
            "sha1": certificate_sha1,
            "sha256": certificate_snapshot.sha256,
            **certificate_metadata,
        },
        "sealed_resources": {
            "code_resources_sha256": code_resources_sha256,
            "static_libraries": libraries,
        },
    }


def submission_id_from_document(document: dict[str, Any]) -> str:
    """Return the strict UUID from a notarytool submit document."""

    return _require_uuid(document.get("id"), "notary submit id")


def _artifact_binding(artifact: pathlib.Path, *, label: str) -> dict[str, Any]:
    artifact_size, artifact_sha256 = _stream_sha256_regular_file(
        artifact,
        maximum=MAX_ARTIFACT_BYTES,
        label=label,
    )
    return {
        "path": pathlib.Path(artifact).name,
        "size": artifact_size,
        "sha256": artifact_sha256,
    }


def _validate_artifact_binding(
    binding: Any,
    *,
    artifact: pathlib.Path,
    label: str,
) -> None:
    if not isinstance(binding, dict):
        _fail(f"{label} artifact must be an object")
    _require_exact_keys(binding, {"path", "size", "sha256"}, f"{label} artifact")
    current = _artifact_binding(artifact, label=f"{label} XCFramework ZIP")
    if binding.get("path") != current["path"]:
        _fail(f"{label} artifact name does not match")
    if type(binding.get("size")) is not int or binding["size"] != current["size"]:
        _fail(f"{label} artifact size does not match")
    if _require_sha256(binding.get("sha256"), f"{label} artifact SHA-256") != current[
        "sha256"
    ]:
        _fail(f"{label} artifact SHA-256 does not match")


def build_prepared_submission_state(
    *,
    artifact: pathlib.Path,
    signing_evidence_sha256: str,
    source_commit: str,
) -> dict[str, Any]:
    """Describe the exact immutable inputs before any notary submission occurs."""

    return {
        "schema_version": 1,
        "kind": "qperiapt.apple_notary_submission_prepared",
        "source_commit": _require_git_commit(source_commit, "prepared source commit"),
        "artifact": _artifact_binding(
            artifact,
            label="prepared XCFramework ZIP",
        ),
        "signing_evidence_sha256": _require_sha256(
            signing_evidence_sha256, "signing evidence SHA-256"
        ),
    }


def validate_prepared_submission_state(
    *,
    prepared_state: dict[str, Any],
    artifact: pathlib.Path,
    signing_evidence_sha256: str,
    expected_source_commit: str,
) -> None:
    """Validate the durable pre-submission binding against current release inputs."""

    _require_exact_keys(
        prepared_state,
        {
            "schema_version",
            "kind",
            "source_commit",
            "artifact",
            "signing_evidence_sha256",
        },
        "prepared notary submission state",
    )
    if prepared_state.get("schema_version") != 1:
        _fail("prepared notary submission state schema_version is not 1")
    if prepared_state.get("kind") != "qperiapt.apple_notary_submission_prepared":
        _fail("prepared notary submission state kind is invalid")
    source_commit = _require_git_commit(
        prepared_state.get("source_commit"), "prepared state source commit"
    )
    if source_commit != _require_git_commit(
        expected_source_commit, "expected prepared source commit"
    ):
        _fail("prepared notary submission source commit does not match the release source")
    _validate_artifact_binding(
        prepared_state.get("artifact"),
        artifact=artifact,
        label="prepared state",
    )
    if _require_sha256(
        prepared_state.get("signing_evidence_sha256"),
        "prepared state signing evidence SHA-256",
    ) != _require_sha256(signing_evidence_sha256, "current signing evidence SHA-256"):
        _fail("prepared state signing evidence SHA-256 does not match")


def _build_bound_submission_state(
    *,
    prepared_state: dict[str, Any],
    prepared_state_sha256: str,
    artifact: pathlib.Path,
    signing_evidence_sha256: str,
    source_commit: str,
    submission_id: str,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    validate_prepared_submission_state(
        prepared_state=prepared_state,
        artifact=artifact,
        signing_evidence_sha256=signing_evidence_sha256,
        expected_source_commit=source_commit,
    )
    prepared_state_sha256 = _require_sha256(
        prepared_state_sha256, "prepared state SHA-256"
    )
    if prepared_state_sha256 != _json_document_sha256(prepared_state):
        _fail("prepared state SHA-256 does not match its canonical document")
    _submission_provenance_kind(provenance)
    return {
        "schema_version": 1,
        "kind": "qperiapt.apple_notary_submission_state",
        "source_commit": _require_git_commit(source_commit, "submission source commit"),
        "submission_id": _require_uuid(submission_id, "notary submission id"),
        "artifact": dict(prepared_state["artifact"]),
        "signing_evidence_sha256": _require_sha256(
            signing_evidence_sha256, "signing evidence SHA-256"
        ),
        "prepared_state_sha256": prepared_state_sha256,
        "submission_id_provenance": provenance,
    }


def build_submission_state(
    *,
    prepared_state: dict[str, Any],
    prepared_state_sha256: str,
    artifact: pathlib.Path,
    submit_document: dict[str, Any],
    submit_response_sha256: str,
    signing_evidence_sha256: str,
    source_commit: str,
) -> dict[str, Any]:
    """Bind a normal notarytool submit response to its prepared release inputs."""

    return _build_bound_submission_state(
        prepared_state=prepared_state,
        prepared_state_sha256=prepared_state_sha256,
        artifact=artifact,
        signing_evidence_sha256=signing_evidence_sha256,
        source_commit=source_commit,
        submission_id=submission_id_from_document(submit_document),
        provenance={
            "kind": "notarytool_submit_response",
            "response_sha256": _require_sha256(
                submit_response_sha256, "notary submit response SHA-256"
            ),
        },
    )


def _invalid_submit_capture_evidence(data: bytes) -> dict[str, Any]:
    parsed: Any | None = None
    try:
        parsed = parse_strict_json_bytes(data, label="notary submit stdout capture")
    except EvidenceIOError:
        pass
    if isinstance(parsed, dict):
        try:
            submission_id_from_document(parsed)
        except AppleDistributionError:
            pass
        else:
            _fail(
                "notary submit stdout capture contains a valid submission UUID; "
                "use the normal submit-response path"
            )
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "parse_status": "invalid_or_truncated_json",
    }


def build_recovered_submission_state(
    *,
    prepared_state: dict[str, Any],
    prepared_state_sha256: str,
    artifact: pathlib.Path,
    submission_id: str,
    submit_capture: bytes,
    signing_evidence_sha256: str,
    source_commit: str,
) -> dict[str, Any]:
    """Bind an operator-supplied UUID without fabricating a submit response."""

    return _build_bound_submission_state(
        prepared_state=prepared_state,
        prepared_state_sha256=prepared_state_sha256,
        artifact=artifact,
        signing_evidence_sha256=signing_evidence_sha256,
        source_commit=source_commit,
        submission_id=submission_id,
        provenance={
            "kind": "explicit_uuid_recovery",
            "captured_stdout": _invalid_submit_capture_evidence(submit_capture),
        },
    )


def _submission_provenance_kind(provenance: Any) -> str:
    if not isinstance(provenance, dict):
        _fail("notary submission provenance must be an object")
    kind = provenance.get("kind")
    if kind == "notarytool_submit_response":
        _require_exact_keys(
            provenance,
            {"kind", "response_sha256"},
            "notary submit response provenance",
        )
        _require_sha256(
            provenance.get("response_sha256"), "bound submit response SHA-256"
        )
        return kind
    if kind == "explicit_uuid_recovery":
        _require_exact_keys(
            provenance,
            {"kind", "captured_stdout"},
            "explicit UUID recovery provenance",
        )
        captured = provenance.get("captured_stdout")
        if not isinstance(captured, dict):
            _fail("explicit UUID recovery captured_stdout must be an object")
        _require_exact_keys(
            captured,
            {"size", "sha256", "parse_status"},
            "explicit UUID recovery captured_stdout",
        )
        size = captured.get("size")
        if type(size) is not int or size < 0 or size > MAX_NOTARY_JSON_BYTES:
            _fail(
                "explicit UUID recovery captured_stdout size must be an integer "
                f"between zero and {MAX_NOTARY_JSON_BYTES}"
            )
        _require_sha256(
            captured.get("sha256"),
            "explicit UUID recovery captured_stdout SHA-256",
        )
        if captured.get("parse_status") != "invalid_or_truncated_json":
            _fail("explicit UUID recovery captured_stdout parse_status is invalid")
        return kind
    _fail(f"unknown notary submission provenance kind: {kind!r}")


def submission_state_provenance(state: dict[str, Any]) -> str:
    """Return the strictly validated provenance discriminator from a bound state."""

    _require_exact_keys(
        state,
        {
            "schema_version",
            "kind",
            "source_commit",
            "submission_id",
            "artifact",
            "signing_evidence_sha256",
            "prepared_state_sha256",
            "submission_id_provenance",
        },
        "notary submission state",
    )
    if state.get("schema_version") != 1:
        _fail("notary submission state schema_version is not 1")
    if state.get("kind") != "qperiapt.apple_notary_submission_state":
        _fail("notary submission state kind is invalid")
    _require_git_commit(state.get("source_commit"), "state source commit")
    _require_uuid(state.get("submission_id"), "state submission id")
    artifact = state.get("artifact")
    if not isinstance(artifact, dict):
        _fail("notary submission state artifact must be an object")
    _require_exact_keys(artifact, {"path", "size", "sha256"}, "state artifact")
    artifact_path = _require_string(artifact.get("path"), "state artifact path")
    if (
        artifact_path in (".", "..")
        or "/" in artifact_path
        or "\\" in artifact_path
        or pathlib.PurePosixPath(artifact_path).name != artifact_path
    ):
        _fail("state artifact path must be a basename")
    artifact_size = artifact.get("size")
    if type(artifact_size) is not int or artifact_size < 0 or artifact_size > MAX_ARTIFACT_BYTES:
        _fail(
            "state artifact size must be an integer between zero and "
            f"{MAX_ARTIFACT_BYTES}"
        )
    _require_sha256(artifact.get("sha256"), "state artifact SHA-256")
    _require_sha256(
        state.get("signing_evidence_sha256"), "state signing evidence SHA-256"
    )
    _require_sha256(state.get("prepared_state_sha256"), "bound prepared state SHA-256")
    return _submission_provenance_kind(state.get("submission_id_provenance"))


def _validate_submission_provenance(
    *,
    provenance: Any,
    submission_id: str,
    submit_document: dict[str, Any] | None,
    submit_response_sha256: str | None,
    submit_capture: bytes | None,
) -> str:
    kind = _submission_provenance_kind(provenance)
    if kind == "notarytool_submit_response":
        if submit_document is None or submit_response_sha256 is None:
            _fail("normal notary submission state requires its submit response")
        if submit_capture is not None:
            _fail("normal notary submission state must not use a recovery stdout capture")
        if submission_id_from_document(submit_document) != submission_id:
            _fail("notary submit response UUID does not match the bound submission UUID")
        if _require_sha256(
            provenance.get("response_sha256"), "bound submit response SHA-256"
        ) != _require_sha256(submit_response_sha256, "current submit response SHA-256"):
            _fail("notary submit response SHA-256 does not match the bound state")
        return kind
    if kind == "explicit_uuid_recovery":
        if submit_document is not None or submit_response_sha256 is not None:
            _fail("explicit UUID recovery must not claim a notarytool submit response")
        if submit_capture is None:
            _fail("explicit UUID recovery requires its preserved submit stdout capture")
        captured = _invalid_submit_capture_evidence(submit_capture)
        if provenance.get("captured_stdout") != captured:
            _fail("explicit UUID recovery captured_stdout differs from the preserved capture")
        return kind
    raise AssertionError("validated provenance kind is unreachable")


def validate_submission_state(
    *,
    prepared_state: dict[str, Any],
    prepared_state_sha256: str,
    state: dict[str, Any],
    artifact: pathlib.Path,
    signing_evidence_sha256: str,
    expected_submission_id: str,
    expected_source_commit: str,
    submit_document: dict[str, Any] | None = None,
    submit_response_sha256: str | None = None,
    submit_capture: bytes | None = None,
) -> str:
    """Validate that a resume uses the exact prepared source, signature, ZIP, and UUID."""

    validate_prepared_submission_state(
        prepared_state=prepared_state,
        artifact=artifact,
        signing_evidence_sha256=signing_evidence_sha256,
        expected_source_commit=expected_source_commit,
    )
    prepared_state_sha256 = _require_sha256(
        prepared_state_sha256, "current prepared state SHA-256"
    )
    if prepared_state_sha256 != _json_document_sha256(prepared_state):
        _fail("current prepared state SHA-256 does not match its canonical document")
    submission_state_provenance(state)
    if _require_sha256(
        state.get("prepared_state_sha256"), "bound prepared state SHA-256"
    ) != prepared_state_sha256:
        _fail("prepared state SHA-256 does not match the bound submission state")
    source_commit = _require_git_commit(state.get("source_commit"), "state source commit")
    if source_commit != _require_git_commit(
        expected_source_commit, "expected submission source commit"
    ):
        _fail("notary submission state source commit does not match the release source")
    submission_id = _require_uuid(state.get("submission_id"), "state submission id")
    if submission_id != _require_uuid(expected_submission_id, "expected submission id"):
        _fail("notary submission state UUID does not match the requested resume UUID")

    _validate_artifact_binding(
        state.get("artifact"),
        artifact=artifact,
        label="bound state",
    )
    if _require_sha256(
        state.get("signing_evidence_sha256"), "state signing evidence SHA-256"
    ) != _require_sha256(signing_evidence_sha256, "current signing evidence SHA-256"):
        _fail("notary submission state signing evidence SHA-256 does not match")
    if state.get("artifact") != prepared_state.get("artifact"):
        _fail("bound submission artifact differs from the prepared state")
    if state.get("source_commit") != prepared_state.get("source_commit"):
        _fail("bound submission source commit differs from the prepared state")
    if state.get("signing_evidence_sha256") != prepared_state.get(
        "signing_evidence_sha256"
    ):
        _fail("bound submission signing evidence differs from the prepared state")
    _validate_submission_provenance(
        provenance=state.get("submission_id_provenance"),
        submission_id=submission_id,
        submit_document=submit_document,
        submit_response_sha256=submit_response_sha256,
        submit_capture=submit_capture,
    )
    return submission_id


def build_notarization_evidence(
    *,
    artifact: pathlib.Path,
    submission_id: str,
    prepared_state: dict[str, Any],
    prepared_state_sha256: str,
    submission_state: dict[str, Any],
    submission_state_sha256: str,
    source_commit: str,
    submit_document: dict[str, Any] | None,
    submit_capture: bytes | None,
    info_document: dict[str, Any],
    log_document: dict[str, Any],
    submit_sha256: str | None,
    info_sha256: str,
    log_sha256: str,
    signing_evidence: dict[str, Any],
    signing_evidence_sha256: str,
) -> dict[str, Any]:
    submission_id = _require_uuid(submission_id, "notary submission id")
    validate_submission_state(
        prepared_state=prepared_state,
        prepared_state_sha256=prepared_state_sha256,
        state=submission_state,
        artifact=artifact,
        signing_evidence_sha256=signing_evidence_sha256,
        expected_submission_id=submission_id,
        expected_source_commit=source_commit,
        submit_document=submit_document,
        submit_response_sha256=submit_sha256,
        submit_capture=submit_capture,
    )
    provenance = submission_state.get("submission_id_provenance")
    if not isinstance(provenance, dict):
        _fail("notary submission provenance must be an object")
    provenance_kind = _require_string(provenance.get("kind"), "submission provenance kind")
    submission_state_sha256 = _require_sha256(
        submission_state_sha256, "submission state SHA-256"
    )
    if submission_state_sha256 != _json_document_sha256(submission_state):
        _fail("submission state SHA-256 does not match its canonical document")

    info_id = _require_uuid(info_document.get("id"), "notary info id")
    if info_id != submission_id:
        _fail("notary info id does not match the tracked submission id")
    if info_document.get("status") != "Accepted":
        _fail(f"notary info status is not Accepted: {info_document.get('status')!r}")
    created_date = _require_timestamp(info_document.get("createdDate"), "notary info createdDate")
    artifact_name = pathlib.Path(artifact).name
    if info_document.get("name") != artifact_name:
        _fail("notary info archive name does not match the release artifact")

    log_id = _require_uuid(log_document.get("jobId"), "notary log jobId")
    if log_id != submission_id:
        _fail("notary log jobId does not match the tracked submission id")
    if log_document.get("status") != "Accepted":
        _fail(f"notary log status is not Accepted: {log_document.get('status')!r}")
    if type(log_document.get("statusCode")) is not int or log_document["statusCode"] != 0:
        _fail(f"notary log statusCode is not zero: {log_document.get('statusCode')!r}")
    if log_document.get("archiveFilename") != artifact_name:
        _fail("notary log archiveFilename does not match the release artifact")
    upload_date = _require_timestamp(log_document.get("uploadDate"), "notary log uploadDate")

    artifact_size, artifact_sha256 = _stream_sha256_regular_file(
        artifact,
        maximum=MAX_ARTIFACT_BYTES,
        label="notarized XCFramework ZIP",
    )
    log_artifact_sha256 = _require_sha256(log_document.get("sha256"), "notary log sha256")
    if log_artifact_sha256 != artifact_sha256:
        _fail("notary log SHA-256 does not match the release artifact")

    if log_document.get("logFormatVersion") != 1:
        _fail("notary log format version is not 1")
    if "issues" not in log_document:
        _fail("notary log lacks the required issues field")
    issues = log_document.get("issues")
    if issues not in (None, []):
        _fail("notary log contains issues; warning-bearing Accepted submissions are rejected")
    tickets = log_document.get("ticketContents")
    if not isinstance(tickets, list) or not tickets:
        _fail("Accepted notary log contains no ticket contents")
    if len(tickets) != 1:
        _fail(f"Accepted notary log must contain exactly one ticket, got {len(tickets)}")
    if signing_evidence.get("kind") != "qperiapt.apple_xcframework_signature":
        _fail("signing evidence has the wrong kind")
    if signing_evidence.get("schema_version") != 1:
        _fail("signing evidence schema_version is not 1")
    signature = signing_evidence.get("signature")
    certificate = signing_evidence.get("certificate")
    if not isinstance(signature, dict) or not isinstance(certificate, dict):
        _fail("signing evidence lacks signature or certificate objects")
    if signature.get("identity_class") != EXPECTED_IDENTITY_CLASS:
        _fail("signing evidence identity class is not Developer ID Application")
    signer_team_id = _require_string(signature.get("team_id"), "signing evidence Team ID")
    if not TEAM_ID.fullmatch(signer_team_id):
        _fail("signing evidence Team ID is invalid")
    signer_cdhash = _require_string(signature.get("cdhash"), "signing evidence CDHash")
    if not HEX_40.fullmatch(signer_cdhash):
        _fail("signing evidence CDHash is invalid")
    signer_cdhash = signer_cdhash.lower()
    signer_certificate_sha256 = _require_sha256(
        certificate.get("sha256"), "signing evidence certificate SHA-256"
    )

    expected_ticket_path = f"{artifact_name}/CQPeriapt.xcframework"
    matching_tickets = 0
    for index, ticket in enumerate(tickets):
        if not isinstance(ticket, dict):
            _fail("notary ticketContents entries must be JSON objects")
        path = _require_string(ticket.get("path"), f"notary ticket {index} path")
        pure_path = pathlib.PurePosixPath(path)
        if path.startswith("/") or ".." in pure_path.parts:
            _fail(f"notary ticket {index} path is unsafe")
        if path != expected_ticket_path:
            _fail(
                f"notary ticket {index} path must be exactly {expected_ticket_path}: {path}"
            )
        if ticket.get("digestAlgorithm") != "SHA-256":
            _fail(f"notary ticket {index} digestAlgorithm is not SHA-256")
        ticket_cdhash = _require_string(ticket.get("cdhash"), f"notary ticket {index} CDHash")
        if not HEX_40.fullmatch(ticket_cdhash):
            _fail(f"notary ticket {index} CDHash is invalid")
        arch = ticket.get("arch")
        if arch is not None and (not isinstance(arch, str) or not arch):
            _fail(f"notary ticket {index} arch must be a non-empty string when present")
        if ticket_cdhash.lower() == signer_cdhash:
            matching_tickets += 1
    if matching_tickets != 1:
        _fail(
            "notary tickets must contain exactly one binding for the signed "
            f"CQPeriapt.xcframework CDHash, got {matching_tickets}"
        )

    ticket_canonical = json.dumps(
        tickets,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")

    raw_evidence_sha256 = {
        "prepared_state": _require_sha256(
            prepared_state_sha256, "prepared state SHA-256"
        ),
        "submission_state": _require_sha256(
            submission_state_sha256, "submission state SHA-256"
        ),
        "signing_evidence": _require_sha256(
            signing_evidence_sha256, "signing evidence SHA-256"
        ),
        "info": _require_sha256(info_sha256, "notary info SHA-256"),
        "log": _require_sha256(log_sha256, "notary log SHA-256"),
    }
    if provenance_kind == "notarytool_submit_response":
        if submit_sha256 is None:
            _fail("normal notary submission lacks its submit response SHA-256")
        raw_evidence_sha256["submit"] = _require_sha256(
            submit_sha256, "notary submit response SHA-256"
        )

    return {
        "schema_version": 1,
        "kind": "qperiapt.apple_notarization",
        "scope": {
            "macos": "distributed_static_sdk_archive",
            "ios": "not_an_ios_app_notarization",
        },
        "artifact": {
            "path": artifact_name,
            "size": artifact_size,
            "sha256": artifact_sha256,
        },
        "signer": {
            "identity_class": signature.get("identity_class"),
            "team_id": signer_team_id,
            "certificate_sha256": signer_certificate_sha256,
        },
        "submission": {
            "id": submission_id,
            "id_provenance": provenance_kind,
            "status": "Accepted",
            "created_date": created_date,
            "upload_date": upload_date,
            "status_summary": _require_string(
                log_document.get("statusSummary"), "notary log statusSummary"
            ),
            "issue_count": 0,
            "ticket_count": len(tickets),
            "matching_signer_ticket_count": matching_tickets,
            "ticket_contents_sha256": hashlib.sha256(ticket_canonical).hexdigest(),
        },
        "raw_evidence_sha256": raw_evidence_sha256,
        "stapling": {
            "performed": False,
            "supported": False,
            "reason": "zip_archives_are_not_supported_by_stapler",
        },
    }


def _directory_open_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_real_directory(path: pathlib.Path, *, label: str) -> int:
    try:
        descriptor = os.open(path, _directory_open_flags())
    except OSError as exc:
        raise AppleDistributionError(f"cannot open {label}: {path}: {exc}") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        _fail(f"{label} is not a directory: {path}")
    return descriptor


def _fsync_directory_and_parent(directory: pathlib.Path, *, label: str) -> None:
    """Persist directory contents and the directory's own parent entry."""

    directory = pathlib.Path(directory)
    parent = directory.parent if directory.parent != pathlib.Path("") else pathlib.Path(".")
    for path, description in (
        (directory, f"{label} directory"),
        (parent, f"{label} parent directory"),
    ):
        descriptor = _open_real_directory(path, label=description)
        try:
            os.fsync(descriptor)
        except OSError as exc:
            raise AppleDistributionError(f"cannot sync {description}: {path}: {exc}") from exc
        finally:
            os.close(descriptor)


def _durability_barrier(descriptor: int, *, label: str) -> None:
    """Flush the device write cache on Darwin after ordinary file/directory fsyncs."""

    try:
        if sys.platform == "darwin":
            command = getattr(fcntl, "F_FULLFSYNC", None)
            if command is None:
                _fail("Darwin release durability requires F_FULLFSYNC support")
            fcntl.fcntl(descriptor, command)
        else:
            os.fsync(descriptor)
    except OSError as exc:
        raise AppleDistributionError(
            f"cannot complete full durability barrier for {label}: {exc}"
        ) from exc


def _full_fsync_directory(directory: pathlib.Path, *, label: str) -> None:
    descriptor = _open_real_directory(directory, label=label)
    try:
        _durability_barrier(descriptor, label=label)
    finally:
        os.close(descriptor)


def _stat_signature(value: os.stat_result) -> StatSignature:
    return (
        value.st_mode,
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _release_tree_label(relative: tuple[str, ...]) -> str:
    return "." if not relative else "./" + "/".join(relative)


def _require_owned_release_entry(
    state: os.stat_result,
    *,
    relative: tuple[str, ...],
    root_device: int,
    reject_other_writable: bool = False,
) -> None:
    label = _release_tree_label(relative)
    if state.st_uid != os.geteuid():
        _fail(f"release tree entry is not owned by the current user: {label}")
    if state.st_dev != root_device:
        _fail(f"release tree entry crosses a filesystem boundary: {label}")
    if reject_other_writable and state.st_mode & 0o022:
        _fail(f"release tree entry is writable by another principal: {label}")


def _normalize_release_symlink(
    directory_relative: tuple[str, ...],
    target: str,
    *,
    relative: tuple[str, ...],
) -> tuple[str, ...]:
    if not target or pathlib.PurePath(target).is_absolute():
        _fail(
            "release tree symlink target must be non-empty and relative: "
            f"{_release_tree_label(relative)}"
        )
    normalized = list(directory_relative)
    for component in target.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not normalized:
                _fail(
                    "release tree symlink escapes the synchronized root: "
                    f"{_release_tree_label(relative)}"
                )
            normalized.pop()
        else:
            normalized.append(component)
    return tuple(normalized)


def _sync_release_directory(
    descriptor: int,
    *,
    relative: tuple[str, ...],
    root_device: int,
    snapshots: dict[RelativePath, StatSignature],
    directory_children: dict[RelativePath, tuple[str, ...]],
    symlink_targets: dict[RelativePath, tuple[str, RelativePath]],
    budget: _TreeTraversalBudget,
    excluded_root_entries: frozenset[str] = frozenset(),
    reject_other_writable: bool = False,
) -> None:
    before = os.fstat(descriptor)
    if not relative:
        budget.record(before, relative)
    _require_owned_release_entry(
        before,
        relative=relative,
        root_device=root_device,
        reject_other_writable=reject_other_writable,
    )
    if not stat.S_ISDIR(before.st_mode):
        _fail(f"release tree entry is not a directory: {_release_tree_label(relative)}")
    snapshots[relative] = _stat_signature(before)

    try:
        collected_names: list[str] = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                collected_names.append(entry.name)
                if len(collected_names) > budget.maximum_entries:
                    _fail(
                        f"{budget.label} directory exceeds maximum entry count "
                        f"{budget.maximum_entries}"
                    )
        names = tuple(sorted(collected_names))
    except OSError as exc:
        raise AppleDistributionError(
            f"cannot list release tree directory {_release_tree_label(relative)}: {exc}"
        ) from exc
    directory_children[relative] = names

    regular_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for name in names:
        if not relative and name in excluded_root_entries:
            continue
        child_relative = relative + (name,)
        child_label = _release_tree_label(child_relative)
        try:
            child_before = os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise AppleDistributionError(
                f"cannot inspect release tree entry {child_label}: {exc}"
            ) from exc
        _require_owned_release_entry(
            child_before,
            relative=child_relative,
            root_device=root_device,
            reject_other_writable=reject_other_writable,
        )
        budget.record(child_before, child_relative)

        if stat.S_ISREG(child_before.st_mode):
            try:
                child_descriptor = os.open(name, regular_flags, dir_fd=descriptor)
            except OSError as exc:
                raise AppleDistributionError(
                    f"cannot open release tree file {child_label}: {exc}"
                ) from exc
            try:
                opened = os.fstat(child_descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or _stat_signature(opened) != _stat_signature(child_before)
                ):
                    _fail(f"release tree file changed while it was opened: {child_label}")
                os.fsync(child_descriptor)
                after = os.fstat(child_descriptor)
                if _stat_signature(after) != _stat_signature(opened):
                    _fail(f"release tree file changed while it was synchronized: {child_label}")
            except OSError as exc:
                raise AppleDistributionError(
                    f"cannot synchronize release tree file {child_label}: {exc}"
                ) from exc
            finally:
                os.close(child_descriptor)
            snapshots[child_relative] = _stat_signature(child_before)
            continue

        if stat.S_ISDIR(child_before.st_mode):
            directory_flags = _directory_open_flags()
            try:
                child_descriptor = os.open(
                    name,
                    directory_flags,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise AppleDistributionError(
                    f"cannot open release tree directory {child_label}: {exc}"
                ) from exc
            try:
                opened = os.fstat(child_descriptor)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or _stat_signature(opened) != _stat_signature(child_before)
                ):
                    _fail(
                        f"release tree directory changed while it was opened: {child_label}"
                    )
                _sync_release_directory(
                    child_descriptor,
                    relative=child_relative,
                    root_device=root_device,
                    snapshots=snapshots,
                    directory_children=directory_children,
                    symlink_targets=symlink_targets,
                    excluded_root_entries=excluded_root_entries,
                    reject_other_writable=reject_other_writable,
                    budget=budget,
                )
            finally:
                os.close(child_descriptor)
            continue

        if stat.S_ISLNK(child_before.st_mode):
            try:
                target_before = os.readlink(name, dir_fd=descriptor)
                child_after = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                target_after = os.readlink(name, dir_fd=descriptor)
            except OSError as exc:
                raise AppleDistributionError(
                    f"cannot inspect release tree symlink {child_label}: {exc}"
                ) from exc
            if (
                _stat_signature(child_after) != _stat_signature(child_before)
                or target_after != target_before
            ):
                _fail(f"release tree symlink changed during inspection: {child_label}")
            normalized_target = _normalize_release_symlink(
                relative,
                target_before,
                relative=child_relative,
            )
            snapshots[child_relative] = _stat_signature(child_before)
            symlink_targets[child_relative] = (target_before, normalized_target)
            continue

        _fail(f"release tree contains an unsupported file type: {child_label}")

    try:
        os.fsync(descriptor)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise AppleDistributionError(
            f"cannot synchronize release tree directory {_release_tree_label(relative)}: {exc}"
        ) from exc
    if _stat_signature(after) != _stat_signature(before):
        _fail(
            "release tree directory changed while it was synchronized: "
            f"{_release_tree_label(relative)}"
        )


def _sync_regular_file_at(
    parent_descriptor: int,
    name: str,
    *,
    label: str,
    root_device: int,
    maximum: int,
) -> tuple[bytes, tuple[int, int, int, int, int, int, int]]:
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise AppleDistributionError(f"cannot inspect {label}: {exc}") from exc
    _require_owned_release_entry(before, relative=(label,), root_device=root_device)
    if not stat.S_ISREG(before.st_mode):
        _fail(f"{label} is not a regular file")
    if before.st_mode & 0o022:
        _fail(f"{label} is writable by another principal")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise AppleDistributionError(f"cannot open {label}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stat_signature(opened) != _stat_signature(before)
        ):
            _fail(f"{label} changed while it was opened")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                _fail(f"{label} exceeds {maximum} bytes")
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if _stat_signature(after) != _stat_signature(opened):
            _fail(f"{label} changed while it was synchronized")
        return b"".join(chunks), _stat_signature(before)
    except OSError as exc:
        raise AppleDistributionError(f"cannot synchronize {label}: {exc}") from exc
    finally:
        os.close(descriptor)


def _sync_worktree_git_metadata(
    *,
    anchor_descriptor: int,
    repository_descriptor: int,
    anchor_root: pathlib.Path,
    repository_root: pathlib.Path,
    root_device: int,
    expected_source_commit: str,
) -> None:
    """Persist the linked-worktree pointer and its exact main-repository admin tree."""

    pointer, pointer_signature = _sync_regular_file_at(
        repository_descriptor,
        ".git",
        label="detached worktree .git pointer",
        root_device=root_device,
        maximum=4096,
    )
    try:
        pointer_text = pointer.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppleDistributionError("detached worktree .git pointer is not UTF-8") from exc
    match = re.fullmatch(r"gitdir: (/[^\r\n]+)\n", pointer_text)
    if match is None:
        _fail("detached worktree .git pointer has a noncanonical format")
    admin_path = pathlib.Path(match.group(1))
    if pathlib.Path(os.path.abspath(admin_path)) != admin_path:
        _fail("detached worktree Git admin path is not lexically canonical")
    worktrees_root = anchor_root / ".git" / "worktrees"
    try:
        admin_relative = admin_path.relative_to(worktrees_root)
    except ValueError as exc:
        raise AppleDistributionError(
            "detached worktree Git admin path escapes the main repository"
        ) from exc
    if len(admin_relative.parts) != 1 or admin_relative.parts[0] in ("", ".", ".."):
        _fail("detached worktree Git admin path must use one worktree name")

    chain: list[
        tuple[
            int,
            tuple[int, int, int, int, int, int, int],
            str,
            str,
        ]
    ] = []
    current_descriptor = anchor_descriptor
    current_label = anchor_root
    try:
        for component in (".git", "worktrees", admin_relative.parts[0]):
            current_label /= component
            before = os.stat(
                component,
                dir_fd=current_descriptor,
                follow_symlinks=False,
            )
            _require_release_ancestor(
                before,
                label=str(current_label),
                root_device=root_device,
            )
            next_descriptor: int | None = None
            try:
                next_descriptor = os.open(
                    component,
                    _directory_open_flags(),
                    dir_fd=current_descriptor,
                )
                opened = os.fstat(next_descriptor)
                if _stat_signature(opened) != _stat_signature(before):
                    _fail(f"Git admin directory changed while opened: {current_label}")
            except BaseException:
                if next_descriptor is not None:
                    os.close(next_descriptor)
                raise
            chain.append(
                (
                    next_descriptor,
                    _stat_signature(opened),
                    str(current_label),
                    component,
                )
            )
            current_descriptor = next_descriptor

        admin_state = _synchronize_directory_tree(
            chain[-1][0],
            root_device=root_device,
            label="linked-worktree Git admin tree",
            maximum_entries=MAX_SOURCE_TREE_ENTRIES,
            maximum_regular_bytes=MAX_SOURCE_TREE_REGULAR_BYTES,
        )
        admin_head, _ = _sync_regular_file_at(
            chain[-1][0],
            "HEAD",
            label="linked-worktree Git admin HEAD",
            root_device=root_device,
            maximum=128,
        )
        if admin_head != (expected_source_commit + "\n").encode("ascii"):
            _fail("linked-worktree Git admin HEAD does not match the release source commit")
        admin_gitdir, _ = _sync_regular_file_at(
            chain[-1][0],
            "gitdir",
            label="linked-worktree Git admin backpointer",
            root_device=root_device,
            maximum=4096,
        )
        expected_backpointer = (str(repository_root / ".git") + "\n").encode("utf-8")
        if admin_gitdir != expected_backpointer:
            _fail("linked-worktree Git admin backpointer does not match the release worktree")
        common_directory, _ = _sync_regular_file_at(
            chain[-1][0],
            "commondir",
            label="linked-worktree common Git directory pointer",
            root_device=root_device,
            maximum=4096,
        )
        if common_directory != b"../..\n":
            _fail("linked-worktree common Git directory pointer is not canonical")
        _revalidate_directory_tree(
            chain[-1][0],
            root_device=root_device,
            state=admin_state,
        )
        for descriptor, expected, label, _ in reversed(chain):
            os.fsync(descriptor)
            if _stat_signature(os.fstat(descriptor)) != expected:
                _fail(f"Git admin directory changed during synchronization: {label}")
        parent_descriptor = anchor_descriptor
        for descriptor, expected, label, component in chain:
            current = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if _stat_signature(current) != expected:
                _fail(f"Git admin directory entry changed: {label}")
            parent_descriptor = descriptor
        pointer_after = os.stat(
            ".git",
            dir_fd=repository_descriptor,
            follow_symlinks=False,
        )
        if _stat_signature(pointer_after) != pointer_signature:
            _fail("detached worktree .git pointer changed during synchronization")
    except OSError as exc:
        raise AppleDistributionError(
            f"cannot synchronize detached worktree Git metadata: {exc}"
        ) from exc
    finally:
        for descriptor, _, _, _ in reversed(chain):
            os.close(descriptor)


def _validate_synchronized_release_tree(
    descriptor: int,
    *,
    relative: tuple[str, ...],
    root_device: int,
    snapshots: dict[RelativePath, StatSignature],
    directory_children: dict[RelativePath, tuple[str, ...]],
    symlink_targets: dict[RelativePath, tuple[str, RelativePath]],
    excluded_root_entries: frozenset[str] = frozenset(),
    reject_other_writable: bool = False,
) -> None:
    current = os.fstat(descriptor)
    _require_owned_release_entry(
        current,
        relative=relative,
        root_device=root_device,
        reject_other_writable=reject_other_writable,
    )
    if _stat_signature(current) != snapshots.get(relative):
        _fail(f"synchronized release directory changed: {_release_tree_label(relative)}")
    expected_names = directory_children.get(relative)
    if expected_names is None:
        raise AssertionError("synchronized directory lacks its captured child inventory")
    try:
        collected_names: list[str] = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                collected_names.append(entry.name)
                if len(collected_names) > len(expected_names):
                    _fail(
                        "release tree directory contents changed during synchronization: "
                        f"{_release_tree_label(relative)}"
                    )
        names = tuple(sorted(collected_names))
    except OSError as exc:
        raise AppleDistributionError(
            f"cannot re-list release tree directory {_release_tree_label(relative)}: {exc}"
        ) from exc
    if names != expected_names:
        _fail(
            "release tree directory contents changed during synchronization: "
            f"{_release_tree_label(relative)}"
        )

    for name in names:
        if not relative and name in excluded_root_entries:
            continue
        child_relative = relative + (name,)
        child_label = _release_tree_label(child_relative)
        try:
            child_state = os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise AppleDistributionError(
                f"cannot revalidate release tree entry {child_label}: {exc}"
            ) from exc
        _require_owned_release_entry(
            child_state,
            relative=child_relative,
            root_device=root_device,
            reject_other_writable=reject_other_writable,
        )
        if _stat_signature(child_state) != snapshots.get(child_relative):
            _fail(f"synchronized release tree entry changed: {child_label}")
        if stat.S_ISDIR(child_state.st_mode):
            try:
                child_descriptor = os.open(
                    name,
                    _directory_open_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise AppleDistributionError(
                    f"cannot reopen release tree directory {child_label}: {exc}"
                ) from exc
            try:
                _validate_synchronized_release_tree(
                    child_descriptor,
                    relative=child_relative,
                    root_device=root_device,
                    snapshots=snapshots,
                    directory_children=directory_children,
                    symlink_targets=symlink_targets,
                    excluded_root_entries=excluded_root_entries,
                    reject_other_writable=reject_other_writable,
                )
            finally:
                os.close(child_descriptor)
        elif stat.S_ISLNK(child_state.st_mode):
            try:
                current_target = os.readlink(name, dir_fd=descriptor)
            except OSError as exc:
                raise AppleDistributionError(
                    f"cannot revalidate release tree symlink {child_label}: {exc}"
                ) from exc
            expected_target, _ = symlink_targets[child_relative]
            if current_target != expected_target:
                _fail(f"synchronized release tree symlink changed: {child_label}")


def _validate_release_symlink_graph(
    *,
    snapshots: dict[RelativePath, StatSignature],
    symlink_targets: dict[RelativePath, tuple[str, RelativePath]],
) -> None:
    """Resolve only captured in-tree link metadata; never follow a live symlink."""

    for child_relative, (_, normalized_target) in symlink_targets.items():
        visited = {child_relative}
        current = normalized_target
        while current in symlink_targets:
            if current in visited:
                _fail(
                    "release tree symlink cycle is not supported: "
                    f"{_release_tree_label(child_relative)}"
                )
            visited.add(current)
            current = symlink_targets[current][1]
        if current not in snapshots:
            _fail(
                "release tree symlink target is not inside the synchronized tree: "
                f"{_release_tree_label(child_relative)}"
            )


def _synchronize_directory_tree(
    descriptor: int,
    *,
    root_device: int,
    label: str,
    maximum_entries: int,
    maximum_regular_bytes: int,
    excluded_root_entries: frozenset[str] = frozenset(),
    reject_other_writable: bool = False,
) -> _SynchronizedDirectoryTree:
    snapshots: dict[RelativePath, StatSignature] = {}
    directory_children: dict[RelativePath, tuple[str, ...]] = {}
    symlink_targets: dict[RelativePath, tuple[str, RelativePath]] = {}
    budget = _TreeTraversalBudget(
        label=label,
        maximum_entries=maximum_entries,
        maximum_regular_bytes=maximum_regular_bytes,
        maximum_depth=MAX_TREE_DEPTH,
    )
    _sync_release_directory(
        descriptor,
        relative=(),
        root_device=root_device,
        snapshots=snapshots,
        directory_children=directory_children,
        symlink_targets=symlink_targets,
        budget=budget,
        excluded_root_entries=excluded_root_entries,
        reject_other_writable=reject_other_writable,
    )
    _validate_release_symlink_graph(
        snapshots=snapshots,
        symlink_targets=symlink_targets,
    )
    synchronized = _SynchronizedDirectoryTree(
        snapshots=snapshots,
        directory_children=directory_children,
        symlink_targets=symlink_targets,
        excluded_root_entries=excluded_root_entries,
        reject_other_writable=reject_other_writable,
    )
    _revalidate_directory_tree(descriptor, root_device=root_device, state=synchronized)
    return synchronized


def _revalidate_directory_tree(
    descriptor: int,
    *,
    root_device: int,
    state: _SynchronizedDirectoryTree,
) -> None:
    _validate_synchronized_release_tree(
        descriptor,
        relative=(),
        root_device=root_device,
        snapshots=state.snapshots,
        directory_children=state.directory_children,
        symlink_targets=state.symlink_targets,
        excluded_root_entries=state.excluded_root_entries,
        reject_other_writable=state.reject_other_writable,
    )


def _release_tree_location(
    anchor_root: pathlib.Path,
    repository_root: pathlib.Path,
    release_root: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, str, tuple[str, ...]]:
    anchor_root = pathlib.Path(anchor_root)
    repository_root = pathlib.Path(repository_root)
    release_root = pathlib.Path(release_root)
    for label, path in (
        ("durability anchor", anchor_root),
        ("repository root", repository_root),
        ("release tree root", release_root),
    ):
        if not path.is_absolute():
            _fail(f"{label} must be an absolute path")
        if pathlib.Path(os.path.abspath(path)) != path:
            _fail(f"{label} must be a lexically canonical path")
    try:
        repository_relative = repository_root.relative_to(anchor_root)
    except ValueError as exc:
        raise AppleDistributionError(
            f"release repository must be below durability anchor {anchor_root}"
        ) from exc
    expected_prefix = (
        "target",
        "qperiapt-apple-release-worktrees",
    )
    if (
        len(repository_relative.parts) != 4
        or repository_relative.parts[:2] != expected_prefix
        or repository_relative.parts[3] != "source"
    ):
        _fail("release repository path does not match the private detached-worktree layout")
    source_commit = _require_git_commit(
        repository_relative.parts[2],
        "release repository source commit",
    )
    target_root = repository_root / "target"
    try:
        relative = release_root.relative_to(target_root)
    except ValueError as exc:
        raise AppleDistributionError(
            f"release tree root must be below {target_root}: {release_root}"
        ) from exc
    if relative == pathlib.Path(".") or ".." in relative.parts:
        _fail("release tree root must be a proper descendant of the repository target directory")

    return anchor_root, repository_root, release_root, source_commit, relative.parts


def _require_release_ancestor(
    state: os.stat_result,
    *,
    label: str,
    root_device: int,
) -> None:
    if not stat.S_ISDIR(state.st_mode):
        _fail(f"release tree ancestor is not a real directory: {label}")
    if state.st_uid != os.geteuid():
        _fail(f"release tree ancestor is not owned by the current user: {label}")
    if state.st_dev != root_device:
        _fail(f"release tree ancestor crosses a filesystem boundary: {label}")
    if state.st_mode & 0o022:
        _fail(f"release tree ancestor is writable by another principal: {label}")


def _open_release_tree_parent(
    anchor_root: pathlib.Path,
    source_commit: str,
    relative: tuple[str, ...],
) -> tuple[
    list[
        tuple[
            int,
            tuple[int, int, int, int, int, int, int],
            pathlib.Path,
            str | None,
        ]
    ],
    int,
]:
    """Retain a no-follow fd chain from the stable main worktree to release parent."""

    anchor_descriptor = _open_real_directory(
        anchor_root,
        label="Apple release durability anchor",
    )
    anchor_state = os.fstat(anchor_descriptor)
    root_device = anchor_state.st_dev
    _require_release_ancestor(
        anchor_state,
        label=str(anchor_root),
        root_device=root_device,
    )
    chain = [
        (
            anchor_descriptor,
            _stat_signature(anchor_state),
            anchor_root,
            None,
        )
    ]
    components = (
        "target",
        "qperiapt-apple-release-worktrees",
        source_commit,
        "source",
        "target",
    ) + relative[:-1]
    private_root_relative = (
        "target",
        "qperiapt-apple-release-worktrees",
        source_commit,
    )
    traversed: tuple[str, ...] = ()

    try:
        for component in components:
            current_descriptor = chain[-1][0]
            traversed += (component,)
            current_label = anchor_root.joinpath(*traversed)
            try:
                before = os.stat(
                    component,
                    dir_fd=current_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise AppleDistributionError(
                    f"cannot inspect release tree ancestor {current_label}: {exc}"
                ) from exc
            _require_release_ancestor(
                before,
                label=str(current_label),
                root_device=root_device,
            )
            if (
                traversed == private_root_relative
                and stat.S_IMODE(before.st_mode) != 0o700
            ):
                _fail(
                    "private Apple release root must have mode 0700: "
                    f"{current_label}"
                )

            next_descriptor: int | None = None
            try:
                next_descriptor = os.open(
                    component,
                    _directory_open_flags(),
                    dir_fd=current_descriptor,
                )
                opened = os.fstat(next_descriptor)
                if _stat_signature(opened) != _stat_signature(before):
                    _fail(
                        "release tree ancestor changed while it was opened: "
                        f"{current_label}"
                    )
            except BaseException as exc:
                if next_descriptor is not None:
                    os.close(next_descriptor)
                if not isinstance(exc, OSError):
                    raise
                raise AppleDistributionError(
                    f"cannot open release tree ancestor {current_label}: {exc}"
                ) from exc
            chain.append(
                (
                    next_descriptor,
                    _stat_signature(opened),
                    current_label,
                    component,
                )
            )
        return chain, root_device
    except BaseException:
        for descriptor, _, _, _ in reversed(chain):
            os.close(descriptor)
        raise


def durably_sync_release_tree(
    *,
    anchor_root: pathlib.Path,
    repository_root: pathlib.Path,
    release_root: pathlib.Path,
    expected_source_commit: str,
) -> None:
    """Synchronize every release byte before publishing an immutable submit ledger."""

    anchor_root, repository_root, release_root, source_commit, relative = (
        _release_tree_location(
            anchor_root,
            repository_root,
            release_root,
        )
    )
    if source_commit != _require_git_commit(
        expected_source_commit,
        "expected release source commit",
    ):
        _fail("release repository path does not match the expected source commit")
    ancestor_chain, root_device = _open_release_tree_parent(
        anchor_root,
        source_commit,
        relative,
    )
    parent_descriptor = ancestor_chain[-1][0]
    root_descriptor: int | None = None
    main_git_descriptor: int | None = None
    try:
        root_before = os.stat(
            relative[-1],
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _require_release_ancestor(
            root_before,
            label=str(release_root),
            root_device=root_device,
        )
        root_descriptor = os.open(
            relative[-1],
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
        opened_root = os.fstat(root_descriptor)
        if _stat_signature(opened_root) != _stat_signature(root_before):
            _fail("release tree root changed while it was opened")

        repository_descriptor = next(
            descriptor
            for descriptor, _, label, _ in ancestor_chain
            if label == repository_root
        )
        source_state = _synchronize_directory_tree(
            repository_descriptor,
            root_device=root_device,
            label="detached source tree",
            maximum_entries=MAX_SOURCE_TREE_ENTRIES,
            maximum_regular_bytes=MAX_SOURCE_TREE_REGULAR_BYTES,
            excluded_root_entries=frozenset({"target"}),
        )
        release_state = _synchronize_directory_tree(
            root_descriptor,
            root_device=root_device,
            label="Apple release output tree",
            maximum_entries=MAX_RELEASE_TREE_ENTRIES,
            maximum_regular_bytes=MAX_RELEASE_TREE_REGULAR_BYTES,
        )

        anchor_descriptor = ancestor_chain[0][0]
        main_git_before = os.stat(
            ".git",
            dir_fd=anchor_descriptor,
            follow_symlinks=False,
        )
        _require_release_ancestor(
            main_git_before,
            label=str(anchor_root / ".git"),
            root_device=root_device,
        )
        main_git_descriptor = os.open(
            ".git",
            _directory_open_flags(),
            dir_fd=anchor_descriptor,
        )
        opened_main_git = os.fstat(main_git_descriptor)
        if _stat_signature(opened_main_git) != _stat_signature(main_git_before):
            _fail("main Git directory changed while it was opened")
        main_git_state = _synchronize_directory_tree(
            main_git_descriptor,
            root_device=root_device,
            label="main Git metadata tree",
            maximum_entries=MAX_MAIN_GIT_TREE_ENTRIES,
            maximum_regular_bytes=MAX_MAIN_GIT_TREE_REGULAR_BYTES,
            reject_other_writable=True,
        )
        for external_object_source in (
            ("objects", "info", "alternates"),
            ("objects", "info", "http-alternates"),
        ):
            if external_object_source in main_git_state.snapshots:
                _fail("main Git object database must not use external alternates")

        _sync_worktree_git_metadata(
            anchor_descriptor=anchor_descriptor,
            repository_descriptor=repository_descriptor,
            anchor_root=anchor_root,
            repository_root=repository_root,
            root_device=root_device,
            expected_source_commit=source_commit,
        )
        for descriptor, expected, label, _ in reversed(ancestor_chain):
            os.fsync(descriptor)
            if _stat_signature(os.fstat(descriptor)) != expected:
                _fail(f"release tree ancestor changed during synchronization: {label}")

        def revalidate_complete_transaction() -> None:
            _revalidate_directory_tree(
                repository_descriptor,
                root_device=root_device,
                state=source_state,
            )
            _revalidate_directory_tree(
                root_descriptor,
                root_device=root_device,
                state=release_state,
            )
            _revalidate_directory_tree(
                main_git_descriptor,
                root_device=root_device,
                state=main_git_state,
            )
            for parent_entry, child_entry in zip(
                ancestor_chain,
                ancestor_chain[1:],
            ):
                parent_fd = parent_entry[0]
                child_expected = child_entry[1]
                child_label = child_entry[2]
                child_name = child_entry[3]
                if child_name is None:
                    raise AssertionError(
                        "non-anchor release directory must have an entry name"
                    )
                current_child = os.stat(
                    child_name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if _stat_signature(current_child) != child_expected:
                    _fail(f"release tree ancestor entry changed: {child_label}")
            root_after = os.stat(
                relative[-1],
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if _stat_signature(root_after) != _stat_signature(root_before):
                _fail("release tree root changed while its parent was synchronized")
            main_git_after = os.stat(
                ".git",
                dir_fd=anchor_descriptor,
                follow_symlinks=False,
            )
            if _stat_signature(main_git_after) != _stat_signature(main_git_before):
                _fail("main Git directory changed during release synchronization")

        revalidate_complete_transaction()
        _durability_barrier(
            anchor_descriptor,
            label="complete Apple release and source transaction",
        )
        revalidate_complete_transaction()
    except OSError as exc:
        raise AppleDistributionError(
            f"cannot durably synchronize release tree {release_root}: {exc}"
        ) from exc
    finally:
        if main_git_descriptor is not None:
            os.close(main_git_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
        for descriptor, _, _, _ in reversed(ancestor_chain):
            os.close(descriptor)


def prepare_submit_capture(path: pathlib.Path) -> None:
    """Durably create one empty private submit capture before network I/O."""

    path = pathlib.Path(path)
    if path.name in ("", ".", ".."):
        _fail(f"submit capture must have a filename: {path}")
    directory = path.parent if path.parent != pathlib.Path("") else pathlib.Path(".")
    directory_descriptor = _open_real_directory(directory, label="submit capture directory")
    descriptor: int | None = None
    try:
        directory_state = os.fstat(directory_descriptor)
        if directory_state.st_uid != os.geteuid() or directory_state.st_mode & 0o077:
            _fail("submit capture directory must be private and owned by the current user")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path.name, flags, 0o600, dir_fd=directory_descriptor)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.fsync(directory_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_descriptor)
    _fsync_directory_and_parent(directory, label="submit capture")
    _full_fsync_directory(
        directory,
        label="prepared notary submission state and capture",
    )


def finalize_submit_capture(path: pathlib.Path) -> None:
    """Flush an existing submit capture and its directory without changing bytes."""

    path = pathlib.Path(path)
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AppleDistributionError(f"cannot open notary submit stdout capture: {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail(f"notary submit stdout capture is not a regular file: {path}")
        if before.st_uid != os.geteuid() or before.st_mode & 0o077:
            _fail("notary submit stdout capture must be private and owned by the current user")
        if before.st_size > MAX_NOTARY_JSON_BYTES:
            _fail(
                f"notary submit stdout capture exceeds {MAX_NOTARY_JSON_BYTES} bytes: {path}"
            )
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            _fail(f"notary submit stdout capture changed while it was synchronized: {path}")
    finally:
        os.close(descriptor)
    directory = path.parent if path.parent != pathlib.Path("") else pathlib.Path(".")
    _fsync_directory_and_parent(directory, label="submit capture")
    _full_fsync_directory(
        directory,
        label="finalized notary submit response capture",
    )


def _write_new_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    """Atomically publish one immutable JSON document without replacing a path."""

    data = _json_document_bytes(value)
    path = pathlib.Path(path)
    if path.name in ("", ".", ".."):
        _fail(f"evidence output must have a filename: {path}")
    directory = path.parent if path.parent != pathlib.Path("") else pathlib.Path(".")
    directory_descriptor = _open_real_directory(directory, label="evidence output parent")

    temporary_name = f".{path.name}.tmp.{uuid.uuid4()}"
    file_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    )
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    primary: BaseException | None = None
    try:
        descriptor = os.open(
            temporary_name,
            file_flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _fail(f"cannot write evidence file: {path}")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(
            temporary_name,
            path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        # Persist the no-clobber publication before removing the temporary name.
        os.fsync(directory_descriptor)
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        temporary_name = ""
        os.fsync(directory_descriptor)
        _fsync_directory_and_parent(directory, label="evidence output")
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as exc:
                if primary is not None:
                    primary.add_note(f"closing temporary evidence output also failed: {exc}")
                else:
                    primary = exc
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
                os.fsync(directory_descriptor)
            except FileNotFoundError:
                pass
            except OSError as exc:
                if primary is not None:
                    primary.add_note(f"removing temporary evidence output also failed: {exc}")
                else:
                    primary = exc
        try:
            os.close(directory_descriptor)
        except OSError as exc:
            if primary is not None:
                primary.add_note(f"closing evidence output directory also failed: {exc}")
            else:
                primary = exc
        if primary is not None and sys.exc_info()[0] is None:
            raise AppleDistributionError(f"cannot finalize evidence output {path}: {primary}") from primary


def _load_json(path: pathlib.Path, label: str) -> tuple[dict[str, Any], str]:
    snapshot = load_json_object_snapshot(
        path,
        maximum=MAX_NOTARY_JSON_BYTES,
        label=label,
    )
    return snapshot.value, snapshot.file.sha256


def _command_submission_id(args: argparse.Namespace) -> None:
    document, _ = _load_json(args.submit, "notary submit response")
    print(submission_id_from_document(document))


def _command_submission_state_provenance(args: argparse.Namespace) -> None:
    state, _ = _load_json(args.state, "notary submission state")
    print(submission_state_provenance(state))


def _command_validate_submission_id(args: argparse.Namespace) -> None:
    print(_require_uuid(args.submission_id, "notary submission id"))


def _command_validate_zip(args: argparse.Namespace) -> None:
    validate_xcframework_zip(args.artifact, require_signature=args.require_signature)
    print("SWIFT_XCFRAMEWORK_ZIP_PASS")


def _command_sync_release_tree(args: argparse.Namespace) -> None:
    durably_sync_release_tree(
        anchor_root=args.anchor_root,
        repository_root=args.repository_root,
        release_root=args.root,
        expected_source_commit=args.source_commit,
    )
    print("APPLE_RELEASE_TREE_SYNC_PASS")


def _command_prepare_submit_capture(args: argparse.Namespace) -> None:
    prepare_submit_capture(args.capture)


def _command_finalize_submit_capture(args: argparse.Namespace) -> None:
    finalize_submit_capture(args.capture)


def _command_prepared_state(args: argparse.Namespace) -> None:
    signing_snapshot = read_regular_snapshot(
        args.signing_evidence,
        maximum=MAX_TEXT_BYTES,
        label="Apple signing evidence",
    )
    state = build_prepared_submission_state(
        artifact=args.artifact,
        signing_evidence_sha256=signing_snapshot.sha256,
        source_commit=args.source_commit,
    )
    _write_new_json(args.output, state)


def _command_submission_state(args: argparse.Namespace) -> None:
    prepared_state, prepared_state_sha256 = _load_json(
        args.prepared, "prepared notary submission state"
    )
    submit_document, submit_response_sha256 = _load_json(
        args.submit, "notary submit response"
    )
    signing_snapshot = read_regular_snapshot(
        args.signing_evidence,
        maximum=MAX_TEXT_BYTES,
        label="Apple signing evidence",
    )
    state = build_submission_state(
        prepared_state=prepared_state,
        prepared_state_sha256=prepared_state_sha256,
        artifact=args.artifact,
        submit_document=submit_document,
        submit_response_sha256=submit_response_sha256,
        signing_evidence_sha256=signing_snapshot.sha256,
        source_commit=args.source_commit,
    )
    _write_new_json(args.output, state)


def _command_recover_submission_state(args: argparse.Namespace) -> None:
    prepared_state, prepared_state_sha256 = _load_json(
        args.prepared, "prepared notary submission state"
    )
    signing_snapshot = read_regular_snapshot(
        args.signing_evidence,
        maximum=MAX_TEXT_BYTES,
        label="Apple signing evidence",
    )
    submit_capture = read_regular_snapshot(
        args.submit_capture,
        maximum=MAX_NOTARY_JSON_BYTES,
        label="notary submit stdout capture",
    )
    state = build_recovered_submission_state(
        prepared_state=prepared_state,
        prepared_state_sha256=prepared_state_sha256,
        artifact=args.artifact,
        submission_id=args.submission_id,
        submit_capture=submit_capture.data,
        signing_evidence_sha256=signing_snapshot.sha256,
        source_commit=args.source_commit,
    )
    _write_new_json(args.output, state)


def _command_validate_submission_state(args: argparse.Namespace) -> None:
    prepared_state, prepared_state_sha256 = _load_json(
        args.prepared, "prepared notary submission state"
    )
    state, _ = _load_json(args.state, "notary submission state")
    submit_document: dict[str, Any] | None = None
    submit_response_sha256: str | None = None
    if args.submit is not None:
        submit_document, submit_response_sha256 = _load_json(
            args.submit, "notary submit response"
        )
    submit_capture: bytes | None = None
    if args.submit_capture is not None:
        submit_capture = read_regular_snapshot(
            args.submit_capture,
            maximum=MAX_NOTARY_JSON_BYTES,
            label="notary submit stdout capture",
        ).data
    signing_snapshot = read_regular_snapshot(
        args.signing_evidence,
        maximum=MAX_TEXT_BYTES,
        label="Apple signing evidence",
    )
    print(
        validate_submission_state(
            prepared_state=prepared_state,
            prepared_state_sha256=prepared_state_sha256,
            state=state,
            artifact=args.artifact,
            signing_evidence_sha256=signing_snapshot.sha256,
            expected_submission_id=args.submission_id,
            expected_source_commit=args.source_commit,
            submit_document=submit_document,
            submit_response_sha256=submit_response_sha256,
            submit_capture=submit_capture,
        )
    )


def _command_signing_evidence(args: argparse.Namespace) -> None:
    evidence = build_signing_evidence(
        xcframework=args.xcframework,
        codesign_display=args.codesign_display,
        certificate=args.certificate,
        expected_team_id=args.expected_team_id,
        expected_identity_sha1=args.expected_identity_sha1,
        expected_certificate_sha256=args.expected_certificate_sha256,
    )
    _write_new_json(args.output, evidence)


def _command_notarization_evidence(args: argparse.Namespace) -> None:
    prepared_state, prepared_state_sha256 = _load_json(
        args.prepared, "prepared notary submission state"
    )
    submission_state, submission_state_sha256 = _load_json(
        args.state, "notary submission state"
    )
    submit_document: dict[str, Any] | None = None
    submit_sha256: str | None = None
    if args.submit is not None:
        submit_document, submit_sha256 = _load_json(args.submit, "notary submit response")
    submit_capture: bytes | None = None
    if args.submit_capture is not None:
        submit_capture = read_regular_snapshot(
            args.submit_capture,
            maximum=MAX_NOTARY_JSON_BYTES,
            label="notary submit stdout capture",
        ).data
    info_document, info_sha256 = _load_json(args.info, "notary info response")
    log_document, log_sha256 = _load_json(args.log, "notary log response")
    signing_evidence, signing_evidence_sha256 = _load_json(
        args.signing_evidence, "Apple signing evidence"
    )
    evidence = build_notarization_evidence(
        artifact=args.artifact,
        submission_id=args.submission_id,
        prepared_state=prepared_state,
        prepared_state_sha256=prepared_state_sha256,
        submission_state=submission_state,
        submission_state_sha256=submission_state_sha256,
        source_commit=args.source_commit,
        submit_document=submit_document,
        submit_capture=submit_capture,
        info_document=info_document,
        log_document=log_document,
        submit_sha256=submit_sha256,
        info_sha256=info_sha256,
        log_sha256=log_sha256,
        signing_evidence=signing_evidence,
        signing_evidence_sha256=signing_evidence_sha256,
    )
    _write_new_json(args.output, evidence)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    submission = subparsers.add_parser("submission-id")
    submission.add_argument("--submit", type=pathlib.Path, required=True)
    submission.set_defaults(handler=_command_submission_id)

    state_provenance = subparsers.add_parser("submission-state-provenance")
    state_provenance.add_argument("--state", type=pathlib.Path, required=True)
    state_provenance.set_defaults(handler=_command_submission_state_provenance)

    validate_submission = subparsers.add_parser("validate-submission-id")
    validate_submission.add_argument("--submission-id", required=True)
    validate_submission.set_defaults(handler=_command_validate_submission_id)

    validate_zip = subparsers.add_parser("validate-zip")
    validate_zip.add_argument("--artifact", type=pathlib.Path, required=True)
    validate_zip.add_argument("--require-signature", action="store_true")
    validate_zip.set_defaults(handler=_command_validate_zip)

    sync_release_tree = subparsers.add_parser("sync-release-tree")
    sync_release_tree.add_argument("--anchor-root", type=pathlib.Path, required=True)
    sync_release_tree.add_argument(
        "--repository-root", type=pathlib.Path, required=True
    )
    sync_release_tree.add_argument("--root", type=pathlib.Path, required=True)
    sync_release_tree.add_argument("--source-commit", required=True)
    sync_release_tree.set_defaults(handler=_command_sync_release_tree)

    prepare_capture = subparsers.add_parser("prepare-submit-capture")
    prepare_capture.add_argument("--capture", type=pathlib.Path, required=True)
    prepare_capture.set_defaults(handler=_command_prepare_submit_capture)

    finalize_capture = subparsers.add_parser("finalize-submit-capture")
    finalize_capture.add_argument("--capture", type=pathlib.Path, required=True)
    finalize_capture.set_defaults(handler=_command_finalize_submit_capture)

    prepared_state = subparsers.add_parser("prepared-state")
    prepared_state.add_argument("--artifact", type=pathlib.Path, required=True)
    prepared_state.add_argument("--signing-evidence", type=pathlib.Path, required=True)
    prepared_state.add_argument("--source-commit", required=True)
    prepared_state.add_argument("--output", type=pathlib.Path, required=True)
    prepared_state.set_defaults(handler=_command_prepared_state)

    submission_state = subparsers.add_parser("submission-state")
    submission_state.add_argument("--prepared", type=pathlib.Path, required=True)
    submission_state.add_argument("--artifact", type=pathlib.Path, required=True)
    submission_state.add_argument("--submit", type=pathlib.Path, required=True)
    submission_state.add_argument("--signing-evidence", type=pathlib.Path, required=True)
    submission_state.add_argument("--source-commit", required=True)
    submission_state.add_argument("--output", type=pathlib.Path, required=True)
    submission_state.set_defaults(handler=_command_submission_state)

    recover_state = subparsers.add_parser("recover-submission-state")
    recover_state.add_argument("--prepared", type=pathlib.Path, required=True)
    recover_state.add_argument("--artifact", type=pathlib.Path, required=True)
    recover_state.add_argument("--signing-evidence", type=pathlib.Path, required=True)
    recover_state.add_argument("--source-commit", required=True)
    recover_state.add_argument("--submission-id", required=True)
    recover_state.add_argument("--submit-capture", type=pathlib.Path, required=True)
    recover_state.add_argument("--output", type=pathlib.Path, required=True)
    recover_state.set_defaults(handler=_command_recover_submission_state)

    validate_state = subparsers.add_parser("validate-submission-state")
    validate_state.add_argument("--prepared", type=pathlib.Path, required=True)
    validate_state.add_argument("--state", type=pathlib.Path, required=True)
    validate_state.add_argument("--artifact", type=pathlib.Path, required=True)
    validate_state.add_argument("--signing-evidence", type=pathlib.Path, required=True)
    validate_state.add_argument("--submit", type=pathlib.Path)
    validate_state.add_argument("--submit-capture", type=pathlib.Path)
    validate_state.add_argument("--submission-id", required=True)
    validate_state.add_argument("--source-commit", required=True)
    validate_state.set_defaults(handler=_command_validate_submission_state)

    signing = subparsers.add_parser("signing-evidence")
    signing.add_argument("--xcframework", type=pathlib.Path, required=True)
    signing.add_argument("--codesign-display", type=pathlib.Path, required=True)
    signing.add_argument("--certificate", type=pathlib.Path, required=True)
    signing.add_argument("--expected-team-id", required=True)
    signing.add_argument("--expected-identity-sha1", required=True)
    signing.add_argument("--expected-certificate-sha256", required=True)
    signing.add_argument("--output", type=pathlib.Path, required=True)
    signing.set_defaults(handler=_command_signing_evidence)

    notarization = subparsers.add_parser("notarization-evidence")
    notarization.add_argument("--artifact", type=pathlib.Path, required=True)
    notarization.add_argument("--submission-id", required=True)
    notarization.add_argument("--prepared", type=pathlib.Path, required=True)
    notarization.add_argument("--state", type=pathlib.Path, required=True)
    notarization.add_argument("--source-commit", required=True)
    notarization.add_argument("--submit", type=pathlib.Path)
    notarization.add_argument("--submit-capture", type=pathlib.Path)
    notarization.add_argument("--info", type=pathlib.Path, required=True)
    notarization.add_argument("--log", type=pathlib.Path, required=True)
    notarization.add_argument("--signing-evidence", type=pathlib.Path, required=True)
    notarization.add_argument("--output", type=pathlib.Path, required=True)
    notarization.set_defaults(handler=_command_notarization_evidence)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        args.handler(args)
    except (AppleDistributionError, EvidenceIOError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
