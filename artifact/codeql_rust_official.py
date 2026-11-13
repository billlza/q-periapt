"""Admit the complete unmodified official Rust query pack before and after analysis."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from evidence_io import consume_regular_snapshot, parse_strict_json_bytes, read_regular_snapshot
from codeql_summary_plan import require, write_exclusive


MANIFEST = Path(__file__).with_suffix(".json")
MANIFEST_SHA256 = "b3d7ac6d9af40a5eac40cac6f1ab8c59e77349f71e9e3612386f7546c7de6a5e"
QUERY_MANIFEST = Path(__file__).with_name("codeql_rust_queries.json")
MAX_PACK_FILES = 2500
MAX_PACK_BYTES = 64 * 1024**2
MAX_FILE_BYTES = 16 * 1024**2


def canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def expected_identity() -> dict:
    snapshot = read_regular_snapshot(MANIFEST, maximum=64 * 1024, label="official query plan manifest")
    require(snapshot.sha256 == MANIFEST_SHA256, "official query plan manifest differs")
    value = parse_strict_json_bytes(snapshot.data, label="official query plan manifest")
    require(isinstance(value, dict) and value.get("schema") == 1
            and value.get("kind") == "qperiapt.codeql_official_query_plan",
            "official query plan manifest schema differs")
    return {**value, "manifest_sha256": snapshot.sha256}


def validate(pack: Path) -> dict:
    identity = expected_identity()
    require(pack.is_absolute() and pack.resolve(strict=True) == pack and not pack.is_symlink(),
            "official query pack root is not canonical")
    files = {}
    total_bytes = directories = 0
    for parent, children, names in os.walk(pack, followlinks=False):
        directory = Path(parent)
        directories += 1
        require(directories <= MAX_PACK_FILES, "official query directory census exceeds its bound")
        for name in children:
            child = directory / name
            require(child.is_dir() and not child.is_symlink(), "official query directory is nonregular")
        for name in sorted(names):
            path = directory / name
            require(len(files) < MAX_PACK_FILES, "official query file census exceeds its bound")
            modes = []

            def metadata(value: os.stat_result) -> None:
                require(value.st_uid == os.geteuid() and value.st_nlink == 1,
                        "official query file ownership or links differ")
                modes.append(stat.S_IMODE(value.st_mode))

            snapshot = consume_regular_snapshot(path, maximum=MAX_FILE_BYTES,
                                                label="official query pack member", validate_metadata=metadata)
            total_bytes += snapshot.size
            require(total_bytes <= MAX_PACK_BYTES and modes[0] & 0o022 == 0,
                    "official query pack size or writable mode differs")
            files[path.relative_to(pack).as_posix()] = {
                "bytes": snapshot.size, "sha256": snapshot.sha256, "mode": modes[0]}
    require(len(files) == identity["pack_file_count"] and total_bytes == identity["pack_total_bytes"]
            and canonical_sha(files) == identity["pack_inventory_sha256"],
            "complete official query pack inventory differs")
    manifest = read_regular_snapshot(QUERY_MANIFEST, maximum=64 * 1024, label="official root query manifest")
    require(manifest.sha256 == identity["query_manifest_sha256"], "official root query manifest differs")
    queries = parse_strict_json_bytes(manifest.data, label="official root query manifest")
    require(queries["codeql_version"] == identity["codeql_version"]
            and queries["query_pack"] == identity["query_pack"]
            and len(queries["queries"]) == identity["query_count"] == 39
            and queries["queries"].get("queries/summary/SummaryStats.ql") == identity["query_source_sha256"],
            "official full query census differs")
    compiled = {}
    for name, digest in queries["queries"].items():
        require(name in files and files[name]["sha256"] == digest, "official query source differs: " + name)
        compiled_name = str(Path(name).with_suffix(".qlx"))
        require(compiled_name in files, "official precompiled query is missing: " + name)
        compiled[name] = files[compiled_name]["sha256"]
    require(canonical_sha(compiled) == identity["compiled_inventory_sha256"],
            "official compiled query inventory differs")
    return identity


def admit(pack: Path, evidence: Path) -> dict:
    """Record admission without replacing any source, query plan, or library."""
    identity = validate(pack)
    write_exclusive(evidence / "SUMMARY_PLAN.json", (json.dumps(identity, indent=2, sort_keys=True) + "\n").encode())
    return identity
