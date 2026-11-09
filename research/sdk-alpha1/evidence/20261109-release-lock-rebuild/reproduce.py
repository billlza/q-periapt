#!/usr/bin/env python3
"""Reproduce the schema-1 rebuild failure and schema-2 stable-lock result.

This uses the manifest verifier's synthetic identity fixtures. No binary build,
platform qualification, security assessment or release is performed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "artifact"))

import continuity_release_manifest as manifest
import test_continuity_release_manifest as fixtures


def exercise(version: int) -> dict:
    fixture = fixtures.ContinuityReleaseManifestTests()
    fixture.setUp()
    try:
        fixture.release_fixture()
        fixture.lock["schema_version"] = version
        fixture.save()
        before = fixture.verify()
        lock_before = (fixture.root / "SPEC_LOCK.json").read_bytes()
        normative_refs = list(fixture.lock["normative_files"].values())
        normative_before = {ref["path"]: (fixture.root / ref["path"]).read_bytes()
                            for ref in normative_refs}
        interfaces_before = manifest.canonical_json_bytes(fixture.document["interfaces"])
        fixture.replace_distribution_build()
        failure = None
        after = None
        try:
            after = fixture.verify()
        except ValueError as error:
            if version != 1 or str(error) != "package graph differs from the specification lock":
                raise
            failure = str(error)
        lock_equal = lock_before == (fixture.root / "SPEC_LOCK.json").read_bytes()
        normative_equal = all(data == (fixture.root / path).read_bytes()
                              for path, data in normative_before.items())
        interface_equal = interfaces_before == manifest.canonical_json_bytes(fixture.document["interfaces"])
        if not (lock_equal and normative_equal and interface_equal):
            raise ValueError("rebuild changed a normative fixture input")
        if version == 1 and failure is None:
            raise ValueError("schema 1 no longer reproduces its original graph commitment")
        if version == 2 and (after is None or before["spec_lock_sha256"] != after["spec_lock_sha256"]
                            or before["source"] == after["source"]
                            or before["manifest_sha256"] == after["manifest_sha256"]):
            raise ValueError("schema 2 did not bind a distinct build under the same normative lock")
        return {
            "lock_schema_version": version,
            "before_completed": before["completed"],
            "after_completed": after is not None and after["completed"],
            "source_changed": before["source"] != fixture.source,
            "manifest_changed": before["manifest_sha256"] != fixture.selected["sha256"],
            "normative_lock_bytes_unchanged": lock_equal,
            "normative_document_bytes_unchanged": normative_equal,
            "interface_identity_unchanged": interface_equal,
            "before_graph_sha256": before["package_graph_sha256"],
            "after_graph_sha256": manifest.package_graph_digest(
                fixture.document["packages"], schema_version=version),
            "observed_failure": failure,
        }
    finally:
        fixture.doCleanups()


def main() -> None:
    paths = ("artifact/continuity_release_manifest.py", "artifact/test_continuity_release_manifest.py",
             "docs/continuity/BUDGETS_V1.json")
    result = {
        "kind": "qperiapt.continuity_spec_lock_rebuild_controls",
        "scope": "Synthetic file/identity controls; no product qualification or publication",
        "source_inputs": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths},
        "controls": [exercise(1), exercise(2)],
        "completed": True,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
