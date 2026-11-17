#!/usr/bin/env python3
"""Closed 0.2.0 GitHub publication policy, separate from legacy receipts.

The admission document is an explicitly selected, committed release decision.
It pins the original qualification records and public assets. It does not turn
the package identity verifier into a qualification runner or a security proof.
"""
from __future__ import annotations

import enum
from pathlib import Path
import re

import continuity_release_manifest as manifest


class SdkReleaseProfile(enum.Enum):
    SDK_020 = "sdk-020"

    @property
    def is_maintenance(self) -> bool:
        return False


PROFILE = SdkReleaseProfile.SDK_020
PLAN_KIND = "qperiapt.sdk_github_publication_plan"
PLAN_SCHEMA = 1
ADMISSION_KIND = "qperiapt.sdk_release_admission"
ADMISSION_PATH = "release/0.2.0/ADMISSION.json"
MANIFEST_PATH = "release/0.2.0/RELEASE_MANIFEST.json"
EVIDENCE_PREFIX = "release/0.2.0/"
PREDECESSOR_TAG = "v0.1.5"
TAGS = ("v0.2.0", "abi2-platforms-v0.2.0")
MAX_ASSETS = 80
MAX_ASSET_BYTES = 256 * 1024 * 1024
MAX_ADMISSION_BYTES = 1024 * 1024
BOUNDARY = (
    "One source-bound Q-Periapt 0.2.0 SDK and Continuity publication. The "
    "reviewed admission commit adds only release evidence to the qualified "
    "source. Both drafts precede all uploads; complete Apple and platform "
    "asset inventories precede publication. Every mutation uses the shared "
    "durable journal and exact remote reconciliation; unknown outcomes are "
    "never retried automatically. Original releases remain unchanged."
)
RELEASE_TEXT = {
    "apple": (
        "Q-Periapt 0.2.0 Apple SDK",
        "Q-Periapt 0.2.0 ABI 2 Apple SDK, including the signed XCFramework and "
        "complete Swift package. Verify the asset hashes, Apple signing "
        "record and immutable GitHub release attestation. The companion "
        "platform release contains the coordinated Continuity distributions "
        "and source-bound qualification evidence.",
    ),
    "platform": (
        "Q-Periapt 0.2.0 SDK and Continuity distributions",
        "Coordinated Q-Periapt 0.2.0 SDK and Continuity distributions. SDK C "
        "ABI 2 and Continuity qpc-owner/1 remain separate. Verify the release "
        "manifest, selected-source qualification records, asset hashes and "
        "immutable GitHub release attestation. Supported platforms and "
        "conditional protocol guarantees are recorded in the bundled admission.",
    ),
}
APPLE_ASSET_NAMES = (
    "APPLE_DISTRIBUTION.json", "CQPeriapt.xcframework.zip", "MANIFEST.json",
    "QPeriapt-Swift-SDK-0.2.0.zip", "SHA256SUMS",
)
REQUIRED_QUALIFICATIONS = frozenset({
    "ci", "codeql", "internal_review", "apple_signing", "windows_lifecycle",
    "services", "independent", "installed_coverage", "package_readback",
})
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}")


def content_type(name: str) -> str:
    manifest.require(type(name) is str and SAFE_NAME.fullmatch(name) is not None,
                     "SDK public asset name is not a bounded leaf")
    if name.endswith(".json"):
        return "application/json"
    if name.endswith(".zip"):
        return "application/zip"
    if name.endswith((".tar.gz", ".tgz", ".crate")):
        return "application/gzip"
    if name.endswith((".aar", ".whl")):
        return "application/zip"
    if name == "SHA256SUMS" or name.endswith((".txt", ".md")):
        return "text/plain"
    raise ValueError("SDK public asset has no selected media type")


def parse_admission(value: object) -> dict:
    """Check a finite admission inventory; execution is verified separately."""
    d = manifest.object_with_keys(value, {
        "schema_version", "kind", "product_version", "source", "manifest",
        "qualifications", "assets", "boundary",
    }, "SDK release admission")
    manifest.require(type(d["schema_version"]) is int and d["schema_version"] == 1
                     and d["kind"] == ADMISSION_KIND and d["product_version"] == "0.2.0"
                     and d["boundary"] == BOUNDARY, "SDK admission discriminant differs")
    source = manifest.object_with_keys(d["source"], {"commit", "tree"}, "SDK source")
    for field in source:
        manifest.digest(source[field], 40, f"SDK source {field}")
    selected = manifest.file_ref(d["manifest"], maximum=manifest.MAX_MANIFEST)
    manifest.require(selected["path"] == MANIFEST_PATH, "SDK release manifest path differs")
    qualifications = manifest.object_with_keys(d["qualifications"], REQUIRED_QUALIFICATIONS,
                                              "SDK qualification inventory")
    for role, ref in qualifications.items():
        manifest.file_ref(ref, maximum=manifest.MAX_ASSESSMENT)
        manifest.require(ref["path"].startswith(EVIDENCE_PREFIX + "qualification/"),
                         f"{role} qualification is outside the committed evidence inventory")
    assets = manifest.object_with_keys(d["assets"], {"apple", "platform"}, "SDK assets")
    paths: set[str] = set()
    for domain, rows in assets.items():
        manifest.require(type(rows) is list and 1 <= len(rows) <= MAX_ASSETS,
                         f"{domain} asset inventory is empty or exceeds its bound")
        names = []
        for row in rows:
            manifest.object_with_keys(row, {"name", "file"}, "SDK public asset")
            content_type(row["name"])
            ref = manifest.file_ref(row["file"], maximum=MAX_ASSET_BYTES)
            manifest.require(ref["path"].startswith(EVIDENCE_PREFIX + "assets/"),
                             "SDK asset is outside its selected publication inventory")
            manifest.require(Path(ref["path"]).name == row["name"] and ref["path"] not in paths,
                             "SDK asset path is repeated or differs from its public name")
            paths.add(ref["path"])
            names.append(row["name"])
        manifest.require(names == sorted(set(names)), "SDK assets are not unique and sorted")
        if domain == "apple":
            manifest.require(tuple(names) == APPLE_ASSET_NAMES, "Apple SDK asset inventory differs")
        else:
            manifest.require("RELEASE_EVIDENCE.zip" in names and "SHA256SUMS" in names,
                             "platform inventory omits the admission evidence or checksum list")
    return d


def parse_qualification(value: object, *, role: str, source: dict) -> dict:
    record = manifest.object_with_keys(value, {"schema_version", "kind", "role", "source",
                                       "completed", "scope", "records"}, "SDK qualification")
    manifest.require(type(record["schema_version"]) is int and record["schema_version"] == 1
                     and record["kind"] == "qperiapt.sdk_release_qualification"
                     and record["role"] == role and record["source"] == source
                     and record["completed"] is True and type(record["scope"]) is str
                     and 1 <= len(record["scope"]) <= 16384
                     and type(record["records"]) is list and 1 <= len(record["records"]) <= 256,
                     f"{role} qualification is incomplete or names another source")
    for ref in record["records"]:
        manifest.file_ref(ref, maximum=manifest.MAX_ASSESSMENT)
        manifest.require(ref["path"].startswith(EVIDENCE_PREFIX),
                         "qualification record is outside the committed evidence inventory")
    return record


def verify_admission_inputs(root: Path, admission: dict) -> dict:
    """Reopen actual manifest, qualifications and artifacts before staging.

    Qualification documents are retained decisions from the original runners
    and readback process. Their individual raw reports stay in the evidence
    archive; this function checks their declared source and byte bindings.
    """
    d = parse_admission(admission)
    inputs = manifest.Inputs(root)
    selected = d["manifest"]
    result = manifest.verify_manifest(root, selected["path"], expected_sha256=selected["sha256"],
                                      source_commit=d["source"]["commit"],
                                      source_tree=d["source"]["tree"], stage="release")
    selected_manifest = inputs.json(selected, maximum=manifest.MAX_MANIFEST)
    public_files = {manifest.canonical_digest(row["file"])
                    for rows in d["assets"].values() for row in rows}
    manifest.require(all(manifest.canonical_digest(ref) in public_files
                         for package in selected_manifest["packages"] for ref in package["artifacts"]),
                     "a selected package artifact is absent from the public asset inventory")
    for role, ref in d["qualifications"].items():
        record = parse_qualification(inputs.json(ref, maximum=manifest.MAX_ASSESSMENT),
                                     role=role, source=d["source"])
        for original in record["records"]:
            inputs.read(original, maximum=manifest.MAX_ASSESSMENT, binary=True)
    for rows in d["assets"].values():
        for row in rows:
            inputs.read(row["file"], maximum=MAX_ASSET_BYTES, binary=True)
    inputs.unchanged()
    return result
