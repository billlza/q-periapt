#!/usr/bin/env python3
"""Materialize a release-pinned crates.io exact-byte uploader from the template.

The exact-byte uploader that :mod:`crates_io_publication` drives embeds, per
crate, the registry metadata JSON, the ``.crate`` size, and its sha256, plus the
cohort's total dependency count and a handoff-manifest digest. Producing that
uploader for a new release used to be a manual reconstruction; this module makes
it deterministic and reviewable.

Given a rust package handoff and the ten packaged ``.crate`` files it pins, this
tool derives each crate's registry metadata with
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
from types import MappingProxyType
from typing import Any

import crates_io_registry_metadata as registry_metadata
import evidence_io
from rust_publish_contract import RUST_PUBLISHABLE_CRATES

HANDOFF_KIND = "qperiapt.rust_package_handoff"
UPLOADER_MODE = 0o700
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
    return value


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


def build_contracts(
    handoff: Mapping[str, Any], crate_dir: pathlib.Path
) -> tuple[dict[str, dict[str, Any]], str, int]:
    """Return (contracts, product_version, dependency_count)."""

    _require(handoff.get("kind") == HANDOFF_KIND, "handoff kind is not a rust package handoff")
    crates = handoff.get("crates")
    _require(isinstance(crates, list) and crates, "handoff has no crates")
    handoff_by_name = {}
    for entry in crates:
        _require(isinstance(entry, Mapping), "handoff crate entry is not a table")
        handoff_by_name[entry["name"]] = entry
    _require(
        set(handoff_by_name) == set(RUST_PUBLISHABLE_CRATES),
        "handoff cohort differs from the canonical publishable crate set",
    )

    versions: set[str] = set()
    contracts: dict[str, dict[str, Any]] = {}
    dependency_count = 0
    for name in RUST_PUBLISHABLE_CRATES:
        entry = handoff_by_name[name]
        crate_file = _safe_relative_name(entry["crate_file"], f"{name} crate_file")
        crate_path = crate_dir / crate_file
        _require(crate_path.is_file(), f"packaged crate is missing: {crate_path}")
        crate_bytes = crate_path.read_bytes()
        size = len(crate_bytes)
        sha256 = hashlib.sha256(crate_bytes).hexdigest()
        _require(
            size == entry["crate_size"] and sha256 == entry["crate_sha256"],
            f"{name}: packaged bytes differ from the handoff (size/sha256)",
        )
        metadata = registry_metadata.registry_metadata(crate_bytes)
        _require(metadata["name"] == name, f"{name}: crate manifest name differs")
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
        all(entry["version"] == product_version for entry in handoff_by_name.values()),
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
    temporary = path.with_name(path.name + ".materializing")
    if temporary.exists():
        temporary.unlink()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, UPLOADER_MODE)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    os.chmod(path, UPLOADER_MODE)


def build(
    handoff_path: pathlib.Path,
    template_path: pathlib.Path,
    output_path: pathlib.Path,
    *,
    crate_dir: pathlib.Path | None,
    cargo_version: str,
) -> dict[str, Any]:
    handoff_bytes = handoff_path.read_bytes()
    handoff_sha256 = hashlib.sha256(handoff_bytes).hexdigest()
    handoff = evidence_io.parse_strict_json_bytes(
        handoff_bytes, label="rust package handoff"
    )
    _require(isinstance(handoff, Mapping), "handoff is not a JSON object")
    resolved_crate_dir = crate_dir if crate_dir is not None else handoff_path.parent
    contracts, product_version, dependency_count = build_contracts(
        handoff, resolved_crate_dir
    )
    template = template_path.read_text(encoding="utf-8")
    materialized = materialize(
        template,
        contracts,
        product_version=product_version,
        dependency_count=dependency_count,
        cargo_version=cargo_version,
        handoff_sha256=handoff_sha256,
    )
    _write_uploader(output_path, materialized)
    return {
        "product_version": product_version,
        "dependency_count": dependency_count,
        "handoff_sha256": handoff_sha256,
        "crates": len(contracts),
        "output": str(output_path),
    }


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Materialize the release-pinned crates.io exact-byte uploader."
    )
    parser.add_argument("handoff_manifest", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
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
        )
    except (UploaderBuildError, registry_metadata.RegistryMetadataError) as error:
        sys.stderr.write(f"error: uploader materialization failed: {error}\n")
        return 1
    sys.stdout.write(
        "materialized {output} for {product_version}: {crates} crates, "
        "{dependency_count} deps, handoff {handoff_sha256}\n".format(**summary)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
