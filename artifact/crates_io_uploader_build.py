#!/usr/bin/env python3
"""Materialize a release-pinned crates.io exact-byte uploader from the template.

The exact-byte uploader that :mod:`crates_io_publication` drives embeds, per
crate, the registry metadata JSON, the ``.crate`` size, and its sha256, plus the
cohort's total dependency count and a handoff-manifest digest. Producing that
uploader for a new release used to be a manual reconstruction; this module makes
it deterministic and reviewable.

Given a legacy Rust package handoff or an explicitly selected SDK package report
and the exact ``.crate`` files it pins, this tool derives registry metadata with
:mod:`crates_io_registry_metadata` (proven byte-identical to cargo's output),
binds every crate to the handoff by size and sha256, compresses the cohort
contract table, and substitutes the template's placeholders. The result is a
single mode-0700 uploader identical in logic to the reviewed template and
distinguished only by its embedded, release-pinned data.

It refuses on any inconsistency -- a crate absent from the handoff, a size/sha
mismatch, a version that is not uniform across the cohort, an unmodeled manifest
construct surfaced by the derivation, or a leftover placeholder -- rather than
emit an uploader that could diverge from the packaged bytes.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import lzma
import os
import pathlib
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from typing import Any

import crates_io_registry_metadata as registry_metadata
import evidence_io
from publication_receipt_io import normalize_safe_root, open_private_directory, write_private_bytes_noreplace_at
from rust_publish_contract import RUST_PUBLISHABLE_CRATES
import rust_sdk_profile as sdk

HANDOFF_KIND = "qperiapt.rust_package_handoff"
UPLOADER_MODE = 0o700
LEGACY_PROFILE = "abi2-legacy"
PROFILES = (LEGACY_PROFILE, sdk.PROFILE)
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_CRATE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_CRATE_BYTES = 512 * 1024 * 1024
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_PLACEHOLDER_RE = re.compile(r"@[A-Z0-9_]+@")
# A version token is embedded into a Python string literal in the emitted
# uploader; restrict it to the characters a semver/cargo version can contain so
# no crate-supplied or operator-supplied value can break out of the literal.
_VERSION_TOKEN_RE = re.compile(r"\A[0-9A-Za-z.+_-]{1,64}\Z")
_TEMPLATE_BANNER_RE = re.compile(
    r"# GENERATED TEMPLATE -- .*?rust package handoff\.\n", re.S
)


class UploaderBuildError(RuntimeError):
    """The template could not be materialized from the supplied inputs."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise UploaderBuildError(message)


def _safe_relative_name(value: object, label: str) -> str:
    """Return value only if it is a bare, traversal-free filename component.

    The handoff's crate_file names come from external JSON; constraining each to
    a single path component (no separators, ``.``/``..``, NUL, or absolute form)
    keeps ``crate_dir / crate_file`` inside crate_dir -- external data cannot be
    steered to an arbitrary filesystem location.
    """

    _require(
        isinstance(value, str)
        and value not in ("", ".", "..")
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
        and not pathlib.PurePosixPath(value).is_absolute()
        and pathlib.PurePosixPath(value).name == value,
        f"{label} is not a bare filename: {value!r}",
    )
    # Retain the refusal above: basename is a canonical leaf, not a repair of
    # traversal input. The returned value cannot address a sibling directory.
    return os.path.basename(value)


def _sub1(pattern: str, replacement: str, text: str, *, flags: int = 0) -> str:
    materialized, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    _require(count == 1, f"template anchor matched {count} times: {pattern!r}")
    return materialized


def _chunk_blob(blob: str, width: int = 100) -> str:
    chunks = [blob[i:i + width] for i in range(0, len(blob), width)]
    body = "".join(f'    "{chunk}"\n' for chunk in chunks)
    return "_FIXED_CONTRACT_B85 = (\n" + body + ")\n"


def _identities_block(contracts: Mapping[str, Mapping[str, Any]]) -> str:
    lines = ["EXPECTED_CRATE_IDENTITIES = MappingProxyType(\n", "    {\n"]
    for name in sorted(contracts):
        lines.append(f'        "{name}": (\n')
        lines.append(f"            {contracts[name]['size']:_},\n")
        lines.append(f'            "{contracts[name]["sha256"]}",\n')
        lines.append("        ),\n")
    lines.append("    }\n)\n")
    return "".join(lines)


def _cohort_entries(handoff: Mapping[str, Any], profile: str) -> list:
    _require(profile in PROFILES, "unknown publication input profile")
    if profile == LEGACY_PROFILE:
        _require(handoff.get("kind") == HANDOFF_KIND, "handoff kind is not a rust package handoff")
        crates = handoff.get("crates")
    else:
        _require(type(handoff.get("schema_version")) is int and handoff["schema_version"] == 1
                 and handoff.get("profile") == sdk.PROFILE and handoff.get("version") == sdk.VERSION
                 and type(handoff.get("native_abi_major")) is int and handoff["native_abi_major"] == 2,
                 "SDK package report identity differs")
        _require(all(handoff.get(key) is False for key in
                     ("git_dirty", "diagnostic_only", "publication_performed", "release_claim_eligible"))
                 and handoff.get("sources_unchanged") is True
                 and handoff.get("cargo_home_isolated") is True,
                 "SDK package report must describe a complete clean no-upload candidate")
        source = handoff.get("base_commit")
        _require(isinstance(source, str) and re.fullmatch(r"[0-9a-f]{40}", source) is not None,
                 "SDK package source commit is malformed")
        records = handoff.get("crates")
        _require(isinstance(records, Mapping) and set(records) == set(sdk.COHORT),
                 "SDK package cohort differs from the canonical publishable crate set")
        crates = []
        for name in sdk.COHORT:
            record = records[name]
            _require(isinstance(record, Mapping), f"{name}: SDK archive record is not a table")
            crates.append({"name": name, "version": sdk.VERSION, "crate_file": record.get("file"),
                           "crate_size": record.get("bytes"), "crate_sha256": record.get("sha256")})
    _require(isinstance(crates, list) and crates, "handoff has no crates")
    return crates


def _validate_sdk_archive(files: Mapping[str, bytes], name: str, report: Mapping, metadata: Mapping) -> None:
    record = report["crates"][name]
    _require(type(record.get("members")) is int and record["members"] == len(files)
             and record.get("files") == sorted(files), f"{name}: SDK archive inventory differs")
    _require(metadata["vers"] == sdk.VERSION, f"{name}: SDK packaged version differs")
    _require(".cargo_vcs_info.json" in files, f"{name}: SDK archive has no Cargo source identity")
    vcs = evidence_io.parse_strict_json_bytes(files[".cargo_vcs_info.json"], label=f"{name} Cargo source identity")
    _require(isinstance(vcs, Mapping) and isinstance(vcs.get("git"), Mapping)
             and vcs["git"].get("sha1") == report["base_commit"] and vcs["git"].get("dirty", False) is False,
             f"{name}: SDK archive source identity differs")
    for dependency in metadata["deps"]:
        other = dependency["name"]
        if not other.startswith("q-periapt"):
            continue
        _require(other in sdk.COHORT and dependency["version_req"] == f"={sdk.VERSION}",
                 f"{name}: SDK internal dependency differs: {other}")
        if dependency["kind"] != "dev":
            _require(sdk.COHORT.index(other) < sdk.COHORT.index(name),
                     f"{name}: SDK production dependency is not earlier in the cohort: {other}")


def build_contracts(
    handoff: Mapping[str, Any], crate_dir: pathlib.Path, *, profile: str = LEGACY_PROFILE,
) -> tuple[dict[str, dict[str, Any]], str, int]:
    """Return exact contracts for the explicitly selected input profile."""

    crates = _cohort_entries(handoff, profile)
    cohort = RUST_PUBLISHABLE_CRATES if profile == LEGACY_PROFILE else sdk.COHORT
    handoff_by_name = {}
    for entry in crates:
        _require(isinstance(entry, Mapping), "handoff crate entry is not a table")
        name = entry.get("name")
        _require(isinstance(name, str) and name in cohort, "handoff crate name is outside the cohort")
        _require(name not in handoff_by_name, "handoff has a duplicate crate record")
        handoff_by_name[name] = entry
    _require(
        set(handoff_by_name) == set(cohort),
        "handoff cohort differs from the canonical publishable crate set",
    )

    versions: set[str] = set()
    contracts: dict[str, dict[str, Any]] = {}
    dependency_count = 0
    total_size = 0
    for name in cohort:
        entry = handoff_by_name[name]
        crate_file = _safe_relative_name(entry.get("crate_file"), f"{name} crate_file")
        if profile == sdk.PROFILE:
            _require(crate_file == f"{name}-{sdk.VERSION}.crate", f"{name}: SDK archive name differs")
        crate_path = crate_dir / crate_file
        maximum = MAX_CRATE_BYTES if profile == LEGACY_PROFILE else sdk.MAX_ARCHIVE
        _require(type(entry.get("crate_size")) is int and 0 < entry["crate_size"] <= maximum
                 and isinstance(entry.get("crate_sha256"), str)
                 and _SHA256_RE.fullmatch(entry["crate_sha256"]) is not None,
                 f"{name}: archive size/digest is invalid")
        snapshot = evidence_io.read_regular_snapshot(crate_path, maximum=maximum, label=f"{name} archive")
        crate_bytes, size, sha256 = snapshot.data, snapshot.size, snapshot.sha256
        total_size += size
        _require(total_size <= MAX_TOTAL_CRATE_BYTES, "aggregate crate size exceeds its bound")
        _require(
            size == entry["crate_size"] and sha256 == entry["crate_sha256"],
            f"{name}: packaged bytes differ from the handoff (size/sha256)",
        )
        # Apply the SDK's bounded archive parser before metadata reconstruction,
        # which expects an already-validated Cargo archive.
        sdk_files = sdk.archive_files(crate_bytes, name) if profile == sdk.PROFILE else None
        metadata = registry_metadata.registry_metadata(crate_bytes)
        _require(metadata["name"] == name, f"{name}: crate manifest name differs")
        if sdk_files is not None:
            _validate_sdk_archive(sdk_files, name, handoff, metadata)
        versions.add(metadata["vers"])
        metadata_json = registry_metadata.serialize_metadata(metadata)
        contracts[name] = {
            "metadata_json": metadata_json,
            "metadata_sha256": hashlib.sha256(metadata_json.encode("utf-8")).hexdigest(),
            "sha256": sha256,
            "size": size,
        }
        dependency_count += len(metadata["deps"])

    _require(len(versions) == 1, f"crate versions are not uniform: {sorted(versions)}")
    product_version = versions.pop()
    _require(
        _VERSION_TOKEN_RE.match(product_version) is not None,
        f"packaged version is not a safe version token: {product_version!r}",
    )
    _require(
        all(entry.get("version") == product_version for entry in handoff_by_name.values()),
        "handoff version differs from packaged version",
    )
    return contracts, product_version, dependency_count


def materialize(
    template: str,
    contracts: Mapping[str, Mapping[str, Any]],
    *,
    product_version: str,
    dependency_count: int,
    cargo_version: str,
    handoff_sha256: str,
) -> str:
    _require(
        _VERSION_TOKEN_RE.match(product_version) is not None,
        f"product version is not a safe version token: {product_version!r}",
    )
    _require(
        _VERSION_TOKEN_RE.match(cargo_version) is not None,
        f"cargo version is not a safe version token: {cargo_version!r}",
    )
    expected_placeholders = set(_PLACEHOLDER_RE.findall(template))
    document = {name: dict(contract) for name, contract in contracts.items()}
    blob_json = json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    compressed = lzma.compress(
        blob_json.encode("utf-8"), format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME
    )
    xz_sha256 = hashlib.sha256(compressed).hexdigest()
    blob_b85 = base64.b85encode(compressed).decode("ascii")

    materialized = template
    materialized = _sub1(
        _TEMPLATE_BANNER_RE.pattern,
        f"# MATERIALIZED by crates_io_uploader_build.py from "
        f"crates_io_uploader_template.py.in\n"
        f"# for release {product_version}; handoff sha256 {handoff_sha256}. "
        f"Do not edit by hand.\n",
        materialized,
        flags=re.S,
    )
    materialized = _sub1(r"version @PRODUCT_VERSION@\.",
                         f"version {product_version}.", materialized)
    materialized = _sub1(r'PRODUCT_VERSION = "@PRODUCT_VERSION@"',
                         f'PRODUCT_VERSION = "{product_version}"', materialized)
    materialized = _sub1(
        r'USER_AGENT = "qperiapt-crates-io-uploader/@PRODUCT_VERSION@"',
        f'USER_AGENT = "qperiapt-crates-io-uploader/{product_version}"', materialized)
    materialized = _sub1(r'FIXED_CARGO_VERSION = "@CARGO_VERSION@"',
                         f'FIXED_CARGO_VERSION = "{cargo_version}"', materialized)
    materialized = _sub1(
        r'FIXED_HANDOFF_MANIFEST_SHA256 = \(\n    "@HANDOFF_SHA256@"\n\)',
        f'FIXED_HANDOFF_MANIFEST_SHA256 = (\n    "{handoff_sha256}"\n)', materialized)
    materialized = _sub1(r"_FIXED_DEPENDENCY_COUNT = -1",
                         f"_FIXED_DEPENDENCY_COUNT = {dependency_count}", materialized)
    materialized = _sub1(r'_FIXED_CONTRACT_XZ_SHA256 = "@CONTRACT_XZ_SHA256@"',
                         f'_FIXED_CONTRACT_XZ_SHA256 = "{xz_sha256}"', materialized)
    materialized = _sub1(r'_FIXED_CONTRACT_B85 = \(\n    "@CONTRACT_B85@",\n\)\n',
                         _chunk_blob(blob_b85), materialized, flags=re.S)
    materialized = _sub1(
        r"EXPECTED_CRATE_IDENTITIES = MappingProxyType\(\n    \{\}\n\)\n",
        _identities_block(contracts), materialized, flags=re.S)

    # Assert every placeholder that WAS in the template is now gone. Scoping to
    # the template's own placeholder tokens avoids false positives from the b85
    # blob, whose alphabet includes '@', while still catching a template
    # placeholder that no substitution filled.
    leftover = sorted(p for p in expected_placeholders if p in materialized)
    _require(not leftover, f"unmaterialized placeholders remain: {leftover}")
    return materialized


def _write_uploader(path: pathlib.Path, text: str) -> None:
    # Grant one existing private directory, then address only a validated leaf
    # through its descriptor. Reuse the same durable no-replace writer as the
    # publication receipts instead of reopening mutable pathname ancestors.
    parent = normalize_safe_root(path.parent.absolute(), label="uploader output directory", required_mode=0o700)
    leaf = _safe_relative_name(path.name, "uploader output leaf")
    payload = text.encode("utf-8")
    directory = open_private_directory(parent, label="uploader output directory")
    descriptor = -1
    primary: BaseException | None = None
    try:
        digest = write_private_bytes_noreplace_at(directory, leaf, payload, label="exact-byte uploader", maximum=MAX_INPUT_BYTES)
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        opened = os.fstat(descriptor)
        _require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid()
                 and opened.st_nlink == 1 and stat.S_IMODE(opened.st_mode) == 0o600,
                 "new uploader file identity differs")
        def same_file(metadata: os.stat_result, mode: int) -> None:
            _require((metadata.st_dev, metadata.st_ino) == (opened.st_dev, opened.st_ino)
                     and stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                     and metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == mode,
                     "new uploader executable identity differs")

        before = evidence_io.consume_regular_snapshot_at(
            directory, leaf, display_path=pathlib.Path(leaf), maximum=MAX_INPUT_BYTES,
            label="new uploader bytes before executable mode", consume=lambda _chunk: None,
            validate_metadata=lambda metadata: same_file(metadata, 0o600))
        _require(before.sha256 == digest and before.size == len(payload), "new uploader bytes changed before executable mode")
        os.fchmod(descriptor, UPLOADER_MODE)
        os.fsync(descriptor)
        final = evidence_io.consume_regular_snapshot_at(
            directory, leaf, display_path=pathlib.Path(leaf), maximum=MAX_INPUT_BYTES,
            label="new uploader executable", consume=lambda _chunk: None,
            validate_metadata=lambda metadata: same_file(metadata, UPLOADER_MODE))
        _require(final.sha256 == digest and final.size == len(payload), "new uploader bytes changed")
        check_directory = open_private_directory(parent, label="uploader output directory after publication")
        try:
            current, held = os.fstat(check_directory), os.fstat(directory)
            _require((current.st_dev, current.st_ino) == (held.st_dev, held.st_ino),
                     "uploader output directory changed during publication")
        finally:
            os.close(check_directory)
        os.fsync(directory)
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_errors = []
        for owned in (descriptor, directory):
            if owned >= 0:
                try:
                    os.close(owned)
                except OSError as error:
                    cleanup_errors.append(error)
        if cleanup_errors:
            if primary is not None:
                for error in cleanup_errors:
                    primary.add_note(f"uploader descriptor close also failed: {error}")
            else:
                raise cleanup_errors[0]


def build(
    handoff_path: pathlib.Path,
    template_path: pathlib.Path,
    output_path: pathlib.Path,
    *,
    crate_dir: pathlib.Path | None,
    cargo_version: str,
    profile: str = LEGACY_PROFILE,
    input_sha256: str | None = None,
) -> dict[str, Any]:
    _require(profile in PROFILES, "unknown publication input profile")
    if profile == sdk.PROFILE or input_sha256 is not None:
        _require(isinstance(input_sha256, str) and _SHA256_RE.fullmatch(input_sha256) is not None,
                 "input manifest SHA-256 must be explicitly pinned")
    handoff_snapshot = evidence_io.read_regular_snapshot(
        handoff_path, maximum=MAX_INPUT_BYTES, label="publication input manifest")
    handoff_bytes, handoff_sha256 = handoff_snapshot.data, handoff_snapshot.sha256
    _require(input_sha256 is None or input_sha256 == handoff_sha256, "input manifest SHA-256 differs")
    handoff = evidence_io.parse_strict_json_bytes(
        handoff_bytes, label="rust package handoff"
    )
    _require(isinstance(handoff, Mapping), "handoff is not a JSON object")
    resolved_crate_dir = crate_dir if crate_dir is not None else (
        handoff_path.parent if profile == LEGACY_PROFILE else handoff_path.parent / "crates")
    contracts, product_version, dependency_count = build_contracts(
        handoff, resolved_crate_dir, profile=profile,
    )
    if profile == sdk.PROFILE:
        _require(isinstance(handoff.get("cargo"), str)
                 and re.fullmatch(r"cargo " + re.escape(cargo_version) + r" \([^\r\n]+\)", handoff["cargo"]) is not None,
                 "SDK packaging Cargo version differs")
    template_snapshot = evidence_io.read_regular_snapshot(
        template_path, maximum=MAX_INPUT_BYTES, label="uploader template")
    template = template_snapshot.data.decode("utf-8")
    materialized = materialize(
        template,
        contracts,
        product_version=product_version,
        dependency_count=dependency_count,
        cargo_version=cargo_version,
        handoff_sha256=handoff_sha256,
    )
    # Refuse a moving input set before exposing the generated uploader.
    input_files = {entry["name"]: _safe_relative_name(entry["crate_file"], "final archive leaf")
                   for entry in _cohort_entries(handoff, profile)}
    for name, contract in contracts.items():
        current = evidence_io.read_regular_snapshot(
            resolved_crate_dir / input_files[name], maximum=MAX_CRATE_BYTES,
            label=f"{name} final archive")
        _require((current.size, current.sha256) == (contract["size"], contract["sha256"]),
                 f"{name}: archive changed during materialization")
    for prior in (handoff_snapshot, template_snapshot):
        current = evidence_io.read_regular_snapshot(prior.path, maximum=MAX_INPUT_BYTES, label="final materialization input")
        _require(current.sha256 == prior.sha256, "materialization input changed")
    _write_uploader(output_path, materialized)
    return {
        "product_version": product_version,
        "dependency_count": dependency_count,
        "handoff_sha256": handoff_sha256,
        "crates": len(contracts),
        "output": str(output_path),
        "profile": profile,
    }


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Materialize the release-pinned crates.io exact-byte uploader."
    )
    parser.add_argument("handoff_manifest", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--profile", choices=PROFILES, default=LEGACY_PROFILE)
    parser.add_argument("--input-sha256", help="explicit input digest (required for sdk-020)")
    parser.add_argument(
        "--template",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent
        / "crates_io_uploader_template.py.in",
    )
    parser.add_argument(
        "--crate-dir",
        type=pathlib.Path,
        help="directory holding the packaged .crate files "
        "(default: the handoff manifest's directory)",
    )
    parser.add_argument(
        "--cargo-version",
        required=True,
        help="cargo version that packaged the crates (embedded for provenance)",
    )
    namespace = parser.parse_args(argv)
    try:
        summary = build(
            namespace.handoff_manifest,
            namespace.template,
            namespace.output,
            crate_dir=namespace.crate_dir,
            cargo_version=namespace.cargo_version,
            profile=namespace.profile,
            input_sha256=namespace.input_sha256,
        )
    except (UploaderBuildError, registry_metadata.RegistryMetadataError, evidence_io.EvidenceIOError,
            OSError, ValueError) as error:
        sys.stderr.write(f"error: uploader materialization failed: {error}\n")
        return 1
    sys.stdout.write(
        "materialized {output} for {product_version}: {crates} crates, "
        "{dependency_count} deps, handoff {handoff_sha256}\n".format(**summary)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
