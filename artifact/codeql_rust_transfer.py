"""Bind a macOS extraction to a fresh Linux query worker in the same workflow."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

import codeql_rust_quality as quality
from evidence_io import consume_regular_snapshot, parse_strict_json_bytes
import rust_sdk_profile as sdk

VERSION = "2.27.4"
COMPILER = "1.99.0"
TARGET = "aarch64-apple-darwin"
MAX_BUNDLE = 2 * 1024**3
MAX_EXPANDED = 16 * 1024**3
MAX_MEMBER = 4 * 1024**3
MAX_MEMBERS = 100000
MAX_EVIDENCE = 64 * 1024**2
REQUIRED_EVIDENCE = {"EXTRACTION_INPUTS.json"}
FORBIDDEN_EVIDENCE = {"ANALYSIS.json", "QUERY_INVENTORY.json", "QUERY_MEMORY.json",
                      "ANALYSIS_RUNTIME.json", "TRANSFER.json", "results.sarif",
                      "PROFILE.json", "Metrics.json", "MacroCalls.json", "ExtractedPaths.json"}


def read_json(path: Path):
    return parse_strict_json_bytes(sdk.snapshot(path, maximum=MAX_EVIDENCE).data,
                                   label="Rust database transfer record")


def _sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _attempt(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value) is not None


def _file_record(value: object, maximum: int, *, nonempty: bool = False) -> bool:
    return (isinstance(value, dict) and set(value) == {"bytes", "sha256"}
            and type(value.get("bytes")) is int
            and (1 if nonempty else 0) <= value["bytes"] <= maximum and _sha(value.get("sha256")))


def _evidence_name(name: object) -> bool:
    return (isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) is not None
            and name not in FORBIDDEN_EVIDENCE and not name.startswith(("analyze.", "resolve-suite.",
                "resolve-analysis-ram.", "transfer-", "ANALYSIS_PLAN", "SUMMARY_PLAN", "plan-")))


def validate_transfer_record(record: object, profile: object, extraction_inputs_sha256: str, *,
                             expected_commit: str, run_id: str, analysis_attempt: int) -> None:
    keys = {"schema", "profile", "target", "source_commit", "run_id", "origin_attempt", "origin_host",
            "compiler_host", "compiler", "codeql_version", "extraction_inputs_sha256", "database",
            "database_inventory_sha256", "database_members", "database_expanded_bytes", "evidence"}
    sdk.require(isinstance(record, dict) and set(record) == keys
                and type(record.get("schema")) is int and record["schema"] == 2,
                "invalid database transfer schema")
    sdk.require(isinstance(profile, dict) and type(profile.get("schema")) is int and profile["schema"] == 1,
                "invalid extraction profile for database transfer")
    sdk.require(isinstance(expected_commit, str) and re.fullmatch(r"[0-9a-f]{40}", expected_commit) is not None
                and _attempt(run_id) and type(analysis_attempt) is int and analysis_attempt > 0,
                "invalid transfer workflow expectation")
    sdk.require(record["profile"] == profile.get("profile") == "macos"
                and record["target"] == profile.get("target") == TARGET
                and record["source_commit"] == profile.get("source_commit") == expected_commit
                and record["run_id"] == profile.get("run_id") == run_id
                and _attempt(record["origin_attempt"])
                and record["origin_attempt"] == profile.get("run_attempt")
                and int(record["origin_attempt"]) <= analysis_attempt,
                "database transfer source, target or attempt differs")
    sdk.require(record["origin_host"] == "darwin"
                and record["compiler_host"] == profile.get("compiler_host") == TARGET
                and record["compiler"] == profile.get("compiler") == COMPILER
                and record["codeql_version"] == profile.get("codeql_version") == VERSION
                and type(profile.get("query_threads")) is int and profile["query_threads"] == 2
                and type(profile.get("query_ram_mb")) is int and profile["query_ram_mb"] == 5500,
                "database transfer origin host or preparation budget differs")
    sdk.require(profile.get("active_target_quality_passed") is False
                and profile.get("paired_target_quality_passed") is False
                and _sha(extraction_inputs_sha256) and record["extraction_inputs_sha256"] == extraction_inputs_sha256,
                "database transfer must bind an extraction awaiting quality validation")
    database = record["database"]
    sdk.require(isinstance(database, dict) and set(database) == {"file", "bytes", "sha256"}
                and database["file"] == "database.zip"
                and _file_record({key: database[key] for key in ("bytes", "sha256")}, MAX_BUNDLE, nonempty=True)
                and _sha(record["database_inventory_sha256"])
                and type(record["database_members"]) is int and 1 <= record["database_members"] <= MAX_MEMBERS
                and type(record["database_expanded_bytes"]) is int
                and 1 <= record["database_expanded_bytes"] <= MAX_EXPANDED,
                "database transfer archive inventory is invalid")
    evidence = record["evidence"]
    sdk.require(isinstance(evidence, dict) and REQUIRED_EVIDENCE <= evidence.keys() and len(evidence) <= 256
                and all(_evidence_name(name) and _file_record(value, MAX_EVIDENCE)
                        for name, value in evidence.items())
                and evidence["EXTRACTION_INPUTS.json"]["sha256"] == extraction_inputs_sha256,
                "database transfer evidence inventory is invalid")


def bundle_inventory(path: Path) -> dict:
    """Check extraction bounds before handing an archive to the pinned CLI."""
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        sdk.require(0 < len(members) <= MAX_MEMBERS, "database archive member count is outside its bound")
        names = set()
        canonical_names = set()
        files = set()
        expanded = 0
        inventory = []
        for member in members:
            name = member.filename
            selected = PurePosixPath(name.rstrip("/"))
            sdk.require(bool(name) and member.orig_filename == name and "\x00" not in name and "\\" not in name
                        and not selected.is_absolute() and ".." not in selected.parts
                        and name.rstrip("/") == str(selected) and selected.parts[0] == "rust"
                        and name not in names and str(selected) not in canonical_names and not member.flag_bits & 1,
                        "unsafe or duplicate database archive member")
            names.add(name)
            canonical_names.add(str(selected))
            kind = stat.S_IFMT(member.external_attr >> 16)
            sdk.require(kind in (0, stat.S_IFREG, stat.S_IFDIR)
                        and (kind != stat.S_IFDIR or member.is_dir())
                        and (kind != stat.S_IFREG or not member.is_dir())
                        and 0 <= member.file_size <= MAX_MEMBER,
                        "non-regular or oversized database archive member")
            sdk.require(not str(selected).startswith("rust/results/")
                        and str(selected) != "rust/results",
                        "transferred extraction must not contain previous query results")
            if not member.is_dir():
                files.add(str(selected))
            expanded += member.file_size
            inventory.append([name, member.file_size, member.CRC, kind])
        sdk.require(expanded <= MAX_EXPANDED
                    and {"rust/codeql-database.yml", "rust/src.zip", "rust/db-rust/rust.dbscheme"} <= files,
                    "database archive is incomplete or exceeds its expanded bound")
        sdk.require(all(not any(str(parent) in files for parent in PurePosixPath(name).parents)
                        for name in names), "database archive has a file/directory collision")
    raw = json.dumps(sorted(inventory), separators=(",", ":")).encode()
    return {"database_inventory_sha256": hashlib.sha256(raw).hexdigest(),
            "database_members": len(members), "database_expanded_bytes": expanded}


def _file_identity(path: Path, *, maximum=MAX_BUNDLE) -> dict:
    value = consume_regular_snapshot(path, maximum=maximum, label="Rust transfer input")
    return {"bytes": value.size, "sha256": value.sha256}


def _copy_verified(source: Path, destination: Path, expected: dict, *, maximum: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        value = consume_regular_snapshot(source, maximum=maximum, label="Rust transferred file", consume=output.write)
    sdk.require({"bytes": value.size, "sha256": value.sha256} == expected, "transferred file bytes differ")
    destination.chmod(0o444)


def transfer_directory(configuration) -> Path:
    return configuration.runner_temp / "qperiapt-codeql-macos-transfer"


def export_database(run) -> None:
    sdk.require(run.configuration.platform == "darwin", "database export requires the macOS origin")
    profile_path = run.evidence / "EXTRACTION_INPUTS.json"
    profile_file = sdk.snapshot(profile_path)
    profile = parse_strict_json_bytes(profile_file.data, label="macOS extraction profile")
    quality.require_clean_checkout(os.environ.get("CODEQL_EXPECTED_COMMIT", ""))
    output = transfer_directory(run.configuration)
    sdk.require(not output.exists() and not output.is_symlink(), "transfer output must be fresh")
    output.mkdir(mode=0o700)
    archive = output / "database.zip"
    run.command("transfer-bundle", [str(run.codeql), "database", "bundle", str(run.configuration.database),
                "--output=" + str(archive), "--name=rust", "--include-diagnostics", "--no-include-results",
                "--no-include-logs", "--no-include-temp", "--cache-cleanup=clear"], seconds=600)
    inventory = bundle_inventory(archive)
    files = {}
    for path in sorted(run.evidence.iterdir()):
        # The bundle command's diagnostics stay on the origin. Only extraction
        # evidence enters the transfer namespace; import writes its own logs.
        if path.name.startswith("transfer-"):
            continue
        sdk.require(_evidence_name(path.name), "unexpected extraction evidence name")
        identity = _file_identity(path, maximum=MAX_EVIDENCE)
        _copy_verified(path, output / "evidence" / path.name, identity, maximum=MAX_EVIDENCE)
        files[path.name] = identity
    record = {"schema": 2, "profile": "macos", "target": TARGET,
              "source_commit": profile.get("source_commit"), "run_id": profile.get("run_id"),
              "origin_attempt": profile.get("run_attempt"), "origin_host": "darwin",
              "compiler_host": TARGET, "compiler": COMPILER, "codeql_version": VERSION,
              "extraction_inputs_sha256": profile_file.sha256,
              "database": {"file": "database.zip", **_file_identity(archive)},
              **inventory, "evidence": files}
    validate_transfer_record(record, profile, profile_file.sha256,
                             expected_commit=os.environ.get("CODEQL_EXPECTED_COMMIT", ""),
                             run_id=os.environ.get("GITHUB_RUN_ID", ""),
                             analysis_attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")))
    sdk.require(sdk.snapshot(profile_path).sha256 == profile_file.sha256, "extraction profile changed during export")
    sdk.write_json(output / "TRANSFER.json", record)


def validate_transfer_anchor(directory: Path, *, expected_commit: str,
                             run_id: str, analysis_attempt: int) -> dict:
    value = sdk.snapshot(directory / "TRANSFER.json", maximum=MAX_EVIDENCE)
    expected = os.environ.get("CODEQL_TRANSFER_SHA256", "")
    origin_attempt = os.environ.get("CODEQL_TRANSFER_ATTEMPT", "")
    sdk.require(_sha(expected) and value.sha256 == expected, "database transfer differs from the origin job output")
    record = parse_strict_json_bytes(value.data, label="anchored database transfer")
    inputs_snapshot = sdk.snapshot(directory / "EXTRACTION_INPUTS.json")
    profile = parse_strict_json_bytes(inputs_snapshot.data, label="anchored extraction inputs")
    validate_transfer_record(record, profile, inputs_snapshot.sha256,
                             expected_commit=expected_commit, run_id=run_id, analysis_attempt=analysis_attempt)
    sdk.require(_attempt(origin_attempt) and record["origin_attempt"] == origin_attempt,
                "database transfer differs from the selected origin attempt")
    return record


def validate_qualified_profile(directory: Path, profile: dict, *, analysis_attempt: int) -> None:
    """Require Linux quality results to extend the exact pending origin record."""
    snapshot = sdk.snapshot(directory / "EXTRACTION_INPUTS.json")
    inputs = parse_strict_json_bytes(snapshot.data, label="macOS extraction inputs")
    sdk.require(isinstance(inputs, dict) and isinstance(profile, dict)
                and inputs.get("active_target_quality_passed") is False
                and inputs.get("paired_target_quality_passed") is False
                and profile.get("active_target_quality_passed") is True
                and profile.get("extraction_inputs_sha256") == snapshot.sha256
                and all(profile.get(key) == value for key, value in inputs.items()
                        if key != "active_target_quality_passed"),
                "qualified profile differs from its pending extraction inputs")
    attempt = profile.get("quality_run_attempt")
    sdk.require(profile.get("quality_host") == "linux"
                and type(profile.get("quality_threads")) is int and profile["quality_threads"] == 4
                and type(profile.get("quality_ram_mb")) is int and profile["quality_ram_mb"] == 14000
                and _attempt(attempt) and _attempt(inputs.get("run_attempt"))
                and int(inputs["run_attempt"]) <= int(attempt) <= analysis_attempt,
                "macOS quality host, budget or attempt differs")


def import_database(run) -> None:
    sdk.require(run.configuration.platform == "linux", "database import requires the Linux query worker")
    incoming = transfer_directory(run.configuration)
    sdk.require(incoming.is_dir() and not incoming.is_symlink() and incoming.resolve() == incoming,
                "transfer input must be a canonical directory")
    value = sdk.snapshot(incoming / "TRANSFER.json", maximum=MAX_EVIDENCE)
    sdk.require(_sha(os.environ.get("CODEQL_TRANSFER_SHA256", ""))
                and value.sha256 == os.environ["CODEQL_TRANSFER_SHA256"],
                "database transfer differs from the origin job output")
    record = parse_strict_json_bytes(value.data, label="incoming database transfer")
    profile_file = sdk.snapshot(incoming / "evidence/EXTRACTION_INPUTS.json")
    profile = parse_strict_json_bytes(profile_file.data, label="transferred extraction profile")
    expected_commit = os.environ.get("CODEQL_EXPECTED_COMMIT", "")
    validate_transfer_record(record, profile, profile_file.sha256, expected_commit=expected_commit,
                             run_id=os.environ.get("GITHUB_RUN_ID", ""),
                             analysis_attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")))
    sdk.require(record["origin_attempt"] == os.environ.get("CODEQL_TRANSFER_ATTEMPT"),
                "database transfer differs from the selected origin attempt")
    sdk.require({path.name for path in incoming.iterdir()} == {"database.zip", "TRANSFER.json", "evidence"}
                and {path.name for path in (incoming / "evidence").iterdir()} == set(record["evidence"]),
                "database transfer has extra or missing files")
    quality.require_clean_checkout(expected_commit)
    source = {path: sdk.snapshot(run.root / path, maximum=5 * 1024**2).sha256
              for path in sorted(quality.tracked_rust_paths(run.root))}
    sdk.require(profile.get("source_sha256") == source, "transferred extraction source bytes differ")
    sdk.require(not run.configuration.database.exists() and not run.configuration.database.is_symlink(),
                "database import destination must be fresh")
    archive = run.output / "transferred-database.zip"
    expected_archive = {key: record["database"][key] for key in ("bytes", "sha256")}
    _copy_verified(incoming / "database.zip", archive, expected_archive, maximum=MAX_BUNDLE)
    sdk.require(bundle_inventory(archive) == {key: record[key] for key in
                ("database_inventory_sha256", "database_members", "database_expanded_bytes")},
                "database archive inventory changed")
    for name, identity in sorted(record["evidence"].items()):
        _copy_verified(incoming / "evidence" / name, run.evidence / name, identity, maximum=MAX_EVIDENCE)
    run.configuration.database.parent.mkdir(parents=True, exist_ok=True)
    run.command("transfer-unbundle", [str(run.codeql), "database", "unbundle", str(archive),
                "--target=" + str(run.configuration.database.parent), "--name=rust"], seconds=600)
    sdk.snapshot(run.configuration.database / "codeql-database.yml", maximum=1024**2)
    sdk.require((run.configuration.database / "db-rust").is_dir()
                and not (run.configuration.database / "db-rust").is_symlink(), "imported Rust dataset is missing")
    sdk.require(_file_identity(archive) == expected_archive, "database archive changed during import")
    with (run.evidence / "TRANSFER.json").open("xb") as output:
        output.write(value.data)
    validate_transfer_anchor(run.evidence, expected_commit=expected_commit,
                             run_id=os.environ["GITHUB_RUN_ID"],
                             analysis_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("identity",))
    parser.parse_args()
    configuration = quality.hosted_configuration("darwin")
    sdk.require(sys.platform == "darwin" and os.environ.get("RUNNER_TEMP") == str(configuration.runner_temp),
                "transfer identity requires its fixed macOS origin")
    directory = transfer_directory(configuration)
    value = sdk.snapshot(directory / "TRANSFER.json", maximum=MAX_EVIDENCE)
    record = parse_strict_json_bytes(value.data, label="exported transfer identity")
    profile_file = sdk.snapshot(directory / "evidence/EXTRACTION_INPUTS.json")
    profile = parse_strict_json_bytes(profile_file.data, label="exported extraction profile")
    validate_transfer_record(record, profile, profile_file.sha256,
                             expected_commit=os.environ.get("CODEQL_EXPECTED_COMMIT", ""),
                             run_id=os.environ.get("GITHUB_RUN_ID", ""),
                             analysis_attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")))
    print("transfer_sha256=" + value.sha256)
    print("origin_attempt=" + record["origin_attempt"])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        sys.exit("error: Rust database transfer: " + str(exc))
