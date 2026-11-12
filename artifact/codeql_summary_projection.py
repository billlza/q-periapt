"""Admit the fixed Stage3/Stage4 projected and fused forward closure.

Only the full SummaryStats QLX and its closed stage capsule use this plan. The
single vendor patch is applied to the query pack's actual embedded dependency,
after checking all 1,175 dependency files. Every root query, the other 38 QLX
files, and the query pack's local support sources stay fixed. Installation does
not compile, download, or evaluate a query. The controller authenticates the
original tool archive before calling this module and requires zero implicit
compilations during evaluation.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re

import codeql_summary_plan as capsule
from evidence_io import parse_strict_json_bytes, read_regular_snapshot


MANIFEST = Path(__file__).with_name("codeql_summary_projection.json")
MANIFEST_SHA256 = "aff9e8e5138909da53acc5f75c774e7bb31e1f0d4281546015f6ffb3ae4f9a6d"
CAPSULE = Path(__file__).with_name("codeql-summary-projection-plan.zip")
PATCH = Path(__file__).with_name("codeql_summary_projection.patch")
DEPENDENCIES = Path(__file__).with_name("codeql_summary_projection_dependencies.json.gz")
QUERY_MANIFEST = Path(__file__).with_name("codeql-fixtures") / "rust-queries-2.27.2.json"
COMPILER_INPUTS_DIGEST = "fcbc88b667fe0122ca51593e2594a017"
COMPILED_INVENTORY_SHA256 = "05ad87c50bd75afc23cdc425e70128b7b6f16f26908fa35fed42e80f31d138d4"
PLAN_SHA256 = "0c7f6af923a661310e801c7cf8990288c7c8edb9de5fb3027a1d5cb79afb7a03"
DEPENDENCY_PATH = "codeql/dataflow/2.1.15/codeql/dataflow/internal/DataFlowImpl.qll"
PATCH_PATH = "codeql/dataflow/internal/DataFlowImpl.qll"
PLAN_PATH = capsule.PLAN_PATH
SOURCE_PATH = str(PurePosixPath(PLAN_PATH).with_suffix(".ql"))
MAX_INPUT_BYTES = 2 * 1024**2

require = capsule.require


def canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def manifest() -> dict:
    snapshot = read_regular_snapshot(MANIFEST, maximum=64 * 1024, label="projection plan manifest")
    require(snapshot.sha256 == MANIFEST_SHA256, "projection plan manifest digest differs")
    value = parse_strict_json_bytes(snapshot.data, label="projection plan manifest")
    require(isinstance(value, dict) and type(value.get("schema")) is int and value["schema"] == 1
            and value.get("kind") == "qperiapt.codeql_summary_projection_plan"
            and value.get("mode") == "projection" and value.get("dynamic_join_order_mode") == "all"
            and value.get("compiler_inputs_digest") == COMPILER_INPUTS_DIGEST
            and value.get("compiled_inventory_sha256") == COMPILED_INVENTORY_SHA256
            and value.get("query_source_sha256") == capsule.SOURCE_SHA256
            and value.get("bundled_plan_sha256") == capsule.BUNDLED_PLAN_SHA256
            and value.get("plan_path") == PLAN_PATH and value.get("stage_count") == capsule.STAGES
            and value.get("query_count") == 39 and value.get("unchanged_other_compiled_queries") == 38,
            "projection plan manifest identity differs")
    files = value["files"]
    require(len(files) == capsule.STAGES + 1 and files[PLAN_PATH]["sha256"] == PLAN_SHA256
            and all(name == PLAN_PATH or re.fullmatch(
                r"\.codeql/precompiled/[a-z0-9]+\.bytes\.qlx", name) for name in files)
            and sum(item["bytes"] for item in files.values()) == value["expanded_bytes"],
            "projection plan capsule closure differs")
    require(value["vendor_patch"]["path"] == PATCH.name
            and value["vendor_patch"]["dependency_path"] == DEPENDENCY_PATH
            and value["dependency_inventory"]["path"] == DEPENDENCIES.name
            and value["dependency_inventory"]["root"] == ".codeql/libraries"
            and value["dependency_inventory"]["file_count"] == 1175,
            "projection vendor source identity differs")
    return value


def expected_identity() -> dict:
    """Portable identity shared by both arms and independently pinned comparison."""
    value = manifest()
    return {**value, "manifest_sha256": MANIFEST_SHA256,
            "effective_plan_sha256": PLAN_SHA256, "source_sha256": value["query_source_sha256"]}


def read_fixed_asset(path: Path, expected: dict, *, maximum: int, label: str) -> bytes:
    snapshot = read_regular_snapshot(path, maximum=maximum, label=label)
    require(snapshot.size == expected["bytes"] and snapshot.sha256 == expected["sha256"], label + " differs")
    return snapshot.data


def source_inputs(value: dict) -> tuple[dict, bytes, bytes]:
    """Validate the separately pinned vendor patch and complete source inventories."""
    patch = read_fixed_asset(PATCH, value["vendor_patch"], maximum=64 * 1024, label="projection vendor patch")
    identity = value["dependency_inventory"]
    compressed = read_fixed_asset(DEPENDENCIES, identity, maximum=256 * 1024,
                                 label="projection dependency inventory")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(identity["expanded_bytes"] + 1)
    require(len(raw) == identity["expanded_bytes"], "projection dependency inventory expanded size differs")
    inventory = parse_strict_json_bytes(raw, label="projection dependency inventory")
    require(isinstance(inventory, dict) and set(inventory) == {"original", "candidate"},
            "projection dependency inventory sides differ")
    original, candidate = inventory["original"], inventory["candidate"]
    require(isinstance(original, dict) and isinstance(candidate, dict)
            and set(original) == set(candidate) and len(original) == identity["file_count"]
            and canonical_sha(original) == identity["upstream_inventory_sha256"]
            and canonical_sha(candidate) == identity["effective_inventory_sha256"],
            "projection dependency inventory census or digest differs")
    require({name for name in original if original[name] != candidate[name]} == {DEPENDENCY_PATH}
            and original[DEPENDENCY_PATH] == value["vendor_patch"]["upstream"]
            and candidate[DEPENDENCY_PATH] == value["vendor_patch"]["effective"],
            "projection must change exactly the admitted vendor source")
    return inventory, patch, compressed


def apply_vendor_patch(original: bytes, patch: bytes) -> bytes:
    """Apply this single-file unified patch exactly, without fuzz or a subprocess."""
    lines = patch.splitlines(keepends=True)
    require(lines[:2] == [("--- a/" + PATCH_PATH + "\n").encode(),
                          ("+++ b/" + PATCH_PATH + "\n").encode()],
            "projection patch file headers differ")
    source = original.splitlines(keepends=True)
    output: list[bytes] = []
    cursor, index, hunks = 0, 2, 0
    while index < len(lines):
        match = re.fullmatch(rb"@@ -([0-9]+),([0-9]+) \+([0-9]+),([0-9]+) @@\n", lines[index])
        require(match is not None, "projection patch hunk header differs")
        start, removed, new_start, added = map(int, match.groups())
        start -= 1
        require(cursor <= start <= len(source) and new_start == len(output) + start - cursor + 1,
                "projection patch hunk position differs")
        index += 1
        before: list[bytes] = []
        after: list[bytes] = []
        while index < len(lines) and not lines[index].startswith(b"@@ "):
            line = lines[index]
            require(line[:1] in (b" ", b"-", b"+") and line.endswith(b"\n"),
                    "projection patch hunk line differs")
            if line[:1] != b"+":
                before.append(line[1:])
            if line[:1] != b"-":
                after.append(line[1:])
            index += 1
        require(len(before) == removed and len(after) == added
                and source[start:start + removed] == before, "projection patch source context differs")
        output.extend(source[cursor:start])
        output.extend(after)
        cursor = start + removed
        hunks += 1
    require(hunks > 0, "projection patch has no hunks")
    output.extend(source[cursor:])
    return b"".join(output)


def verify_files(root: Path, expected: dict, *, label: str) -> None:
    for name, identity in expected.items():
        read_fixed_asset(capsule.member_path(root, name), identity, maximum=MAX_INPUT_BYTES,
                         label=label + ": " + name)


def verify_dependencies(pack: Path, expected: dict) -> None:
    """Bounded exact tree census; safe snapshots reject special files and links."""
    root = capsule.member_path(pack, ".codeql/libraries")
    directories: dict[str, set[str]] = {"": set()}
    for name in expected:
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts
                and str(relative) == name and "\\" not in name,
                "projection dependency path is not canonical")
        parent = ""
        for index, part in enumerate(relative.parts):
            directories.setdefault(parent, set()).add(part)
            if index < len(relative.parts) - 1:
                parent = (parent + "/" if parent else "") + part

    def census() -> None:
        for name, children in sorted(directories.items()):
            directory = root / name
            require(directory.is_dir() and not directory.is_symlink(),
                    "projection dependency directory is not regular: " + name)
            observed: set[str] = set()
            with os.scandir(directory) as entries:
                for entry in entries:
                    require(entry.name in children and entry.name not in observed,
                            "projection dependency entry census differs: " + name)
                    observed.add(entry.name)
            require(observed == children, "projection dependency entry census differs: " + name)

    census()
    verify_files(root, expected, label="projection dependency source")
    census()


def verify_queries(pack: Path, value: dict, *, installed: bool) -> None:
    raw = read_regular_snapshot(QUERY_MANIFEST, maximum=64 * 1024, label="projection root query manifest")
    require(raw.sha256 == value["query_manifest_sha256"], "projection root query manifest differs")
    queries = parse_strict_json_bytes(raw.data, label="projection root query manifest")
    require(queries["codeql_version"] == value["codeql_version"]
            and queries["query_pack"] == value["query_pack"]
            and len(queries["queries"]) == value["query_count"]
            and queries["queries"][SOURCE_PATH] == value["query_source_sha256"],
            "projection root query census or tool identity differs")
    compiled = {}
    for name, digest in queries["queries"].items():
        path = capsule.member_path(pack, name)
        source = read_regular_snapshot(path, maximum=MAX_INPUT_BYTES, label="projection root query")
        require(source.sha256 == digest, "projection root query source changed: " + name)
        compiled[name] = read_regular_snapshot(path.with_suffix(".qlx"), maximum=MAX_INPUT_BYTES,
                                               label="projection compiled query").sha256
    pin = value["compiled_inventory_sha256" if installed else "bundled_compiled_inventory_sha256"]
    require(canonical_sha(compiled) == pin, "projection compiled query inventory differs")
    verify_files(pack, value["query_pack_support_files"], label="projection query pack support source")


def validate(pack: Path) -> dict:
    """Recheck the effective patch, all sources, all QLX, and the full stage closure."""
    value = manifest()
    inventory, _, _ = source_inputs(value)
    verify_dependencies(pack, inventory["candidate"])
    verify_queries(pack, value, installed=True)
    capsule.validate_members(pack, value["files"], compiler_inputs_digest=COMPILER_INPUTS_DIGEST)
    return expected_identity()


def install(pack: Path, evidence: Path) -> dict:
    """Install only after complete source/capsule admission over an original pack."""
    value = manifest()
    inventory, patch, compressed = source_inputs(value)
    verify_dependencies(pack, inventory["original"])
    verify_queries(pack, value, installed=False)
    vendor = capsule.member_path(pack, ".codeql/libraries/" + DEPENDENCY_PATH)
    original_source = read_fixed_asset(vendor, value["vendor_patch"]["upstream"],
                                      maximum=MAX_INPUT_BYTES, label="projection original vendor source")
    patched = apply_vendor_patch(original_source, patch)
    effective = value["vendor_patch"]["effective"]
    require(len(patched) == effective["bytes"] and hashlib.sha256(patched).hexdigest() == effective["sha256"],
            "projection patched source differs")
    plan = capsule.member_path(pack, PLAN_PATH)
    original_plan = read_regular_snapshot(plan, maximum=MAX_INPUT_BYTES, label="projection original query plan")
    require(original_plan.sha256 == value["bundled_plan_sha256"], "projection original bundled plan differs")
    payloads = capsule.read_capsule(pack, CAPSULE, size=value["capsule_bytes"], digest=value["capsule_sha256"],
                                    files=value["files"], compiler_inputs_digest=COMPILER_INPUTS_DIGEST)
    stages = {name: data for name, data in payloads.items() if name != PLAN_PATH}
    pending_source = vendor.with_name(".DataFlowImpl.qll.projection-incoming")
    pending_plan = plan.with_name(".SummaryStats.qlx.projection-incoming")
    for path in [pending_source, pending_plan, *(capsule.member_path(pack, name) for name in stages)]:
        require(not path.exists() and not path.is_symlink(), "projection candidate destination already exists")

    # Everything above is read-only. Keep original bytes and exact source inputs
    # before creating stages. Replace the full QLX last, then recheck the whole
    # admitted state before the controller can start an evaluator. An I/O failure
    # aborts installation; a partial pack is never reused as a fresh baseline.
    for name, data in (("SUMMARY_PLAN_ORIGINAL.qlx", original_plan.data),
                       ("SUMMARY_PLAN_VENDOR_ORIGINAL.qll", original_source),
                       ("SUMMARY_PLAN_VENDOR_PATCH.patch", patch),
                       ("SUMMARY_PLAN_DEPENDENCIES.json.gz", compressed)):
        capsule.write_exclusive(evidence / name, data)
    capsule.write_exclusive(pending_source, patched)
    capsule.write_exclusive(pending_plan, payloads[PLAN_PATH])
    for name, data in stages.items():
        capsule.write_exclusive(capsule.member_path(pack, name), data)
    pending_source.replace(vendor)
    pending_plan.replace(plan)
    identity = validate(pack)
    capsule.write_exclusive(evidence / "SUMMARY_PLAN.json", (json.dumps(identity, indent=2, sort_keys=True) + "\n").encode())
    return identity
