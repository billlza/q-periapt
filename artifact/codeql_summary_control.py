"""Paired evaluator allocation control over one authenticated macOS-origin database.

This diagnostic restores the same retained database/cache for both profiles.
It executes all 39 pinned queries, requires fresh complete results, and never
publishes SARIF or changes the production analysis configuration.
"""

from __future__ import annotations

import argparse
import calendar
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import BinaryIO

from bounded_process import BoundedProcessError, TimeoutPolicy, capture_output
from codeql_process_resources import ProcessResourceSampler
import codeql_evaluator_logs as evaluator_logs
import codeql_summary_plan as summary_plan
import codeql_summary_projection as summary_projection
from evidence_io import (EvidenceIOError, consume_regular_snapshot, fresh_output_directory,
                         parse_strict_json_bytes, read_regular_snapshot)
import codeql_log_recovery as retained


CLI_VERSION = "2.27.2"
QUERY_VERSION = "0.1.44"
# The extra profile is an isolated capacity experiment, never a production receipt.
PROFILES = {"heap-2048": (2048, 10643), "heap-1536": (1536, 11155),
            "memory-56000": (4096, 50595)}
RAM_MB = 14000
RESERVED_MB = 1309
THREADS = 4
EVALUATION_SECONDS = 18000
INNER_MEMBER = "qperiapt-codeql-macos/diagnostics/database.zip"
MAX_DATABASE_ZIP_BYTES = 300 * 1024**2
MAX_DATABASE_MEMBERS = 3000
MAX_DATABASE_MEMBER_BYTES = 512 * 1024**2
MAX_DATABASE_BYTES = 1200 * 1024**2
MIN_FREE_BYTES = 2 * 1024**3
EXTRACTION_SECONDS = 900
DIRECTORY_EPOCH = 946684800
TOOL_BUNDLE_BYTES = 98247028
TOOL_BUNDLE_SHA256 = "acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea"
CODEQL_LAUNCHER_SHA256 = "5010324098d11f9e2d34e0fcf53bb44e40e8e3ffc8aecefe695269b54edaa413"
COMPILED_INVENTORY_SHA256 = "f5d87c717575c9243272e3b1c8abdc1f5f12d93a193ffd2d3b1ba10df6de43d9"
MANIFEST_SHA256 = "eb54654d668bfafc45f785427158a97e378791b20f9cb374d97301e7c296039b"
QUERY_MANIFEST = Path(__file__).with_name("codeql_rust_queries.json")
SOURCE = {"artifact_id": 13677417145, "artifact_bytes": 288417501,
          "artifact_sha256": "cb0bd89478b9a8d0f635a9ffa2156a06e3fbbf81b0054b8a1a474c045711d43d",
          "source_head": "3254c81066af26cd23a2881198010fb616ce6b7a",
          "analyzed_commit": "56f191f04a57806869b8a03078ee4d27ffe900ab", "source_run": 42554273879}
INNER_BYTES = 269008328
INNER_SHA256 = "c8bdc47f5cbb0b6d83c0d60c63e8ff9f80ad63683c58cdf32311dd8bb6c9dbf1"
FULL_SUMMARY = "queries/summary/SummaryStats.ql"
SOURCE_ALLOCATION = ["-J-Xmx3362M", "--off-heap-ram=9329"]
TRANSFER_SECONDS = 600
OBSERVATION_SECONDS = 120
PARTIAL_RESULT_SECONDS = 120
MAX_PARTIAL_RESULT_BYTES = 512 * 1024**2
MAX_EVALUATOR_LOG_BYTES = 2 * 1024**3
MAX_EVALUATOR_TOTAL_BYTES = 4 * 1024**3
CACHE_SCOPE = "Warm-cache control: exact retained database/cache; fresh common cache and all 39 output BQRS."
SUMMARY_PLANS = {"none": None, "all": summary_plan, "projection": summary_projection}
# Filled from the authenticated archive, independent of either experiment arm.
INPUT_IDENTITY = {'cache_file_count': 1437,
 'cache_inventory_sha256': '2e972c45962dc468698ac7db6cf3fcde6a17bb3b3bc954af06a9166eab3bdbe0',
 'database_inventory_sha256': 'aafbc13d377d69fa4428ffd705a08eb77cfe40f2d4fe3fae02995fe9f839d33d',
 'inner_bytes': 269008328,
 'inner_sha256': 'c8bdc47f5cbb0b6d83c0d60c63e8ff9f80ad63683c58cdf32311dd8bb6c9dbf1',
 'metadata_git_sha': '56f191f04a57806869b8a03078ee4d27ffe900ab',
 'metadata_sha256': '909ce48c7a00cebdbea45235e30a26d6c3b321f3dbf12b68bbca48323b6bee7b',
 'retained_result_count': 38,
 'retained_results_inventory_sha256': '4eb77cdb48e39a811a6f4844705400f10cf3b44113e5f58e0c8b748adec0d63b'}



class ControlError(ValueError):
    """An experiment identity, boundary, or completion condition differs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ControlError(message)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    temporary.replace(path)


def read_json(path: Path) -> object:
    return parse_strict_json_bytes(read_regular_snapshot(
        path, maximum=64 * 1024**2, label="experiment JSON").data, label="experiment JSON")


def database_archive_root(members: list[zipfile.ZipInfo]) -> PurePosixPath:
    metadata = [member for member in members if PurePosixPath(member.filename).name == "codeql-database.yml"]
    require(len(metadata) == 1 and not metadata[0].is_dir(), "database metadata root is missing or ambiguous")
    root = PurePosixPath(metadata[0].filename).parent
    require(len(root.parts) <= 1, "database archive must have a flat root or one directory prefix")
    return root


def select_database_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    require(0 < len(members) <= MAX_DATABASE_MEMBERS
            and len(members) == len({member.filename for member in members}),
            "database archive member count or uniqueness differs")
    for member in members:
        try:
            retained.safe_member(member)
        except retained.RecoveryError as error:
            raise ControlError(str(error)) from error
        require(member.file_size <= MAX_DATABASE_MEMBER_BYTES, "database member exceeds its size bound")
    require(sum(member.file_size for member in members) <= MAX_DATABASE_BYTES,
            "database archive exceeds its total size bound")
    root = database_archive_root(members)
    normalized: dict[PurePosixPath, zipfile.ZipInfo] = {}
    for member in members:
        try:
            relative = PurePosixPath(member.filename).relative_to(root)
        except ValueError as error:
            raise ControlError("database archive contains a member outside its metadata root") from error
        require(relative not in normalized and (relative.parts or member.is_dir()),
                "database archive has duplicate normalized members or a non-directory root")
        normalized[relative] = member
    files = {path for path, member in normalized.items() if not member.is_dir()}
    require(all(not any(parent in files for parent in path.parents) for path in normalized),
            "database archive has a file/directory ancestor conflict")
    require(any(path.parts and path.parts[0] == "db-rust" and len(path.parts) > 1 for path in normalized)
            and PurePosixPath("db-rust") not in files, "archive does not contain a Rust database")
    return sorted(members, key=lambda member: member.filename)


def record_database_archive(inner: Path, evidence: Path) -> None:
    """Retain bounded read-only shape evidence before any restoration rejection."""
    with zipfile.ZipFile(inner) as archive:
        members = archive.infolist()
        candidates = [member for member in members if PurePosixPath(member.filename).name == "codeql-database.yml"]
        metadata = []
        for member in candidates[:4]:
            entry = {"path": member.filename[:512], "declared_bytes": member.file_size, "is_directory": member.is_dir()}
            if not member.is_dir():
                try:
                    with archive.open(member) as stream:
                        data = stream.read(32769)
                    entry.update(text=data[:32768].decode("utf-8", errors="replace"), truncated=len(data) > 32768)
                except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
                    entry["read_error"] = type(error).__name__
            metadata.append(entry)
        names = []
        for member in members[:32]:
            try:
                names.append({"path": str(retained.safe_member(member))[:512], "safe": True})
            except retained.RecoveryError:
                names.append({"path": member.filename[:512], "safe": False})
        components = sorted({PurePosixPath(member.filename).parts[0]
                             for member in members if PurePosixPath(member.filename).parts})
        write_json(evidence / "DATABASE_ARCHIVE.json", {
            "schema": 1, "inner_bytes": inner.stat().st_size, "inner_sha256": sha(inner),
            "member_count": len(members), "declared_total_bytes": sum(member.file_size for member in members),
            "top_level_components": [name[:512] for name in components[:32]],
            "top_level_component_count": len(components), "metadata_candidate_count": len(candidates),
            "metadata_candidates": metadata, "first_members": names})


def metadata_root_fields(text: str) -> dict[str, list[str]]:
    try:
        return summary_plan.database_metadata_fields(text)
    except summary_plan.PlanError as error:
        raise ControlError(str(error)) from None


def restore_database(inner_zip: Path | BinaryIO, destination: Path) -> dict:
    require(not destination.exists() and not destination.is_symlink(), "database destination must be fresh")
    deadline = time.monotonic() + EXTRACTION_SECONDS
    files: dict[str, dict] = {}
    directories: dict[str, dict] = {".": {"mode": 0o700, "mtime": DIRECTORY_EPOCH}}
    with zipfile.ZipFile(inner_zip) as archive:
        members = select_database_members(archive)
        require(shutil.disk_usage(destination.parent).free
                >= sum(member.file_size for member in members) + MIN_FREE_BYTES,
                "insufficient free disk for the complete database and evaluator reserve")
        archive_root = database_archive_root(members)
        metadata_info = archive.getinfo(str(archive_root / "codeql-database.yml"))
        require(metadata_info.file_size <= 128 * 1024, "database metadata exceeds its bound")
        metadata = archive.read(metadata_info)
        text = metadata.decode("utf-8-sig")
        fields = metadata_root_fields(text)
        scalar = lambda pattern: [value.strip() for value in re.findall(pattern, text)]
        quoted = lambda value: {value, "'" + value + "'", '"' + value + '"'}
        language = fields.get("primaryLanguage", [])
        finalized = fields.get("finalised", [])
        version = scalar(r"(?m)^[ \t]+cliVersion:[ \t]*([^\r\n]*)$")
        require(len(language) == 1 and language[0] in quoted("rust")
                and "inProgress" not in fields and (not finalized or finalized == ["true"])
                and len(version) == 1 and version[0] in quoted(CLI_VERSION),
                "database language, finalization, or CLI identity differs")
        git_shas = scalar(r"(?m)^[ \t]+sha:[ \t]*([^\r\n]*)$")
        require(len(git_shas) == 1 and git_shas[0] in quoted(SOURCE["analyzed_commit"]),
                "database creation commit differs")
        destination.mkdir(mode=0o700)
        for member in members:
            require(time.monotonic() <= deadline, "database restoration exceeded its time bound")
            relative = retained.safe_member(member).relative_to(archive_root)
            path = destination / relative
            for parent in relative.parents:
                directories.setdefault(str(parent), {"mode": 0o700, "mtime": DIRECTORY_EPOCH})
            mtime = calendar.timegm((*member.date_time, 0, 0, 0))
            mode = stat.S_IMODE(member.external_attr >> 16) & 0o777
            if member.is_dir():
                directories[str(relative)] = {"mode": mode or 0o700, "mtime": mtime}
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            count, digest = 0, hashlib.sha256()
            with archive.open(member) as source, path.open("xb") as output:
                while block := source.read(1024 * 1024):
                    require(time.monotonic() <= deadline, "database restoration exceeded its time bound")
                    count += len(block)
                    require(count <= member.file_size, "database member exceeds its declared size")
                    digest.update(block)
                    output.write(block)
            require(count == member.file_size, "database member differs from its declared size")
            os.chmod(path, mode or 0o600)
            os.utime(path, (mtime, mtime))
            files[str(relative)] = {"bytes": count, "sha256": digest.hexdigest(),
                                    "mode": mode or 0o600, "mtime": mtime}
        for relative, identity in sorted(directories.items(), key=lambda item: len(PurePosixPath(item[0]).parts), reverse=True):
            directory = destination / relative
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(directory, identity["mode"])
            os.utime(directory, (identity["mtime"], identity["mtime"]))
    cache = {name: identity for name, identity in files.items() if name.startswith("db-rust/default/cache/")}
    require(cache, "retained evaluator cache is absent")
    return {"files": files, "directories": directories, "archive_root": str(archive_root),
            "database_inventory_sha256": canonical_sha({"files": files, "directories": directories}),
            "cache_inventory_sha256": canonical_sha(cache), "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
            "metadata_git_sha": SOURCE["analyzed_commit"]}


def download(path: Path) -> None:
    """Fetch one fixed artifact; do not forward its API credential to a redirect."""
    deadline = time.monotonic() + TRANSFER_SECONDS
    opener = urllib.request.build_opener(retained.NoRedirect)
    request = urllib.request.Request(
        f"https://api.github.com/repos/billlza/q-periapt/actions/artifacts/{SOURCE['artifact_id']}/zip",
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"]})
    try:
        with opener.open(request, timeout=30):
            raise ControlError("artifact API did not return its expected redirect")
    except urllib.error.HTTPError as error:
        with error:
            require(error.code == 302, "artifact API returned an unexpected status")
            url = error.headers.get("Location", "")
    target = urllib.parse.urlsplit(url)
    require(target.scheme == "https" and bool(target.hostname)
            and target.username is None and target.password is None,
            "artifact redirect must be HTTPS without embedded credentials")
    count, digest = 0, hashlib.sha256()
    with opener.open(url, timeout=45) as response, path.open("xb") as output:
        while block := response.read(1024 * 1024):
            count += len(block)
            require(count <= SOURCE["artifact_bytes"] and time.monotonic() <= deadline,
                    "retained artifact transfer exceeded its bound")
            digest.update(block)
            output.write(block)
    require(time.monotonic() <= deadline and count == SOURCE["artifact_bytes"]
            and digest.hexdigest() == SOURCE["artifact_sha256"], "outer artifact identity differs")


@contextmanager
def verified_source(path: Path, *, size: int, digest: str, label: str):
    """Parse the private copy of the exact bytes hashed through one descriptor."""
    deadline = time.monotonic() + EXTRACTION_SECONDS
    with tempfile.TemporaryFile(mode="w+b", dir=path.parent) as source:
        def capture(chunk: bytes) -> None:
            require(time.monotonic() <= deadline, "archive snapshot exceeded its time bound")
            require(source.write(chunk) == len(chunk), "archive snapshot write was incomplete")
        try:
            snapshot = consume_regular_snapshot(path, maximum=size, label=label, consume=capture)
        except EvidenceIOError as error:
            raise ControlError(label + " identity differs") from error
        require(snapshot.size == size and snapshot.sha256 == digest, label + " identity differs")
        source.seek(0)
        yield source


def input_identity(inventory: dict) -> dict:
    retained_results = {name: identity for name, identity in inventory["files"].items()
                        if name.startswith("results/codeql/rust-queries/") and name.endswith(".bqrs")}
    cache = {name: identity for name, identity in inventory["files"].items()
             if name.startswith("db-rust/default/cache/")}
    identity = {name: inventory[name] for name in
                ("database_inventory_sha256", "cache_inventory_sha256", "metadata_sha256", "metadata_git_sha")}
    identity.update(inner_bytes=INNER_BYTES, inner_sha256=INNER_SHA256,
                    retained_result_count=len(retained_results), cache_file_count=len(cache),
                    retained_results_inventory_sha256=canonical_sha(retained_results))
    return identity


def prepare_database(root: Path, *, retained_archive: Path | None = None) -> tuple[Path, dict]:
    """Restore the same pinned input from its API transfer or a local archive.

    A local archive is an explicit transport choice. Both routes pass through
    the same descriptor-bound size/digest check before any ZIP parsing, then
    the same complete database/cache/result inventory admission.
    """
    inner = root / "retained-database.zip"
    if retained_archive is None:
        outer = root / "diagnostics.zip"
        download(outer)
    else:
        outer = retained_archive
    with verified_source(outer, size=SOURCE["artifact_bytes"], digest=SOURCE["artifact_sha256"],
                         label="outer artifact") as source, zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        require(len(members) <= retained.MAX_MEMBERS and len(members) == len({m.filename for m in members}),
                "outer artifact inventory differs")
        for member in members:
            retained.safe_member(member)
        info = archive.getinfo(INNER_MEMBER)
        require(not info.is_dir() and info.file_size == INNER_BYTES, "retained database ZIP size differs")
        deadline, count, digest = time.monotonic() + EXTRACTION_SECONDS, 0, hashlib.sha256()
        with archive.open(info) as source, inner.open("xb") as output:
            while block := source.read(1024 * 1024):
                count += len(block)
                require(count <= info.file_size and time.monotonic() <= deadline,
                        "retained database transfer exceeded its bound")
                digest.update(block)
                output.write(block)
        require(count == INNER_BYTES and digest.hexdigest() == INNER_SHA256,
                "retained database ZIP identity differs")
    database = root / "database"
    record_database_archive(inner, root / "evidence")
    with verified_source(inner, size=INNER_BYTES, digest=INNER_SHA256, label="inner database") as source:
        inventory = restore_database(source, database)
    write_json(root / "evidence/DATABASE_INPUTS.json", inventory)
    identity = input_identity(inventory)
    require(identity == INPUT_IDENTITY, "retained database/cache/result inventory differs")
    write_json(root / "evidence/SOURCE_TRANSPORT.json", {
        "schema": 1,
        "transport": "github_artifact" if retained_archive is None else "local_archive",
        "artifact_id": SOURCE["artifact_id"],
        "archive_bytes": SOURCE["artifact_bytes"],
        "archive_sha256": SOURCE["artifact_sha256"],
        "input_identity": identity,
    })
    return database, identity


def validate_query_inventory(observed: dict, pinned: dict) -> None:
    require(pinned.get("codeql_version") == CLI_VERSION and pinned.get("query_pack") == QUERY_VERSION,
            "pinned query tool identity differs")
    expected = pinned.get("queries")
    require(isinstance(expected, dict) and len(expected) == 39 and observed == expected,
            "full 39-query identity differs")
    require(expected.get("queries/summary/SummaryStats.ql")
            == "7278d53373afb4f8069122e287c9c036a959ba0d167c152d67cd0de885881d67",
            "full SummaryStats query differs")


def small_command(command: list[str], prefix: Path, environment: dict[str, str], *,
                  timeout_seconds: int = 120) -> bytes:
    with prefix.with_suffix(".stdout").open("xb") as stdout, prefix.with_suffix(".stderr").open("xb") as stderr:
        result = capture_output(command, timeout_seconds=timeout_seconds, maximum_stdout_bytes=32 * 1024**2,
                                maximum_stderr_bytes=8 * 1024**2, environment=environment,
                                stdout_sink=stdout.write, stderr_sink=stderr.write)
    write_json(prefix.with_suffix(".json"), {"command": command, "returncode": result.returncode})
    require(result.returncode == 0, "CodeQL admission or result decoding failed")
    return result.stdout


def admit_tool(codeql: Path, bundle: Path, database: Path, root: Path, environment: dict) -> tuple[dict, dict, dict, dict, list]:
    require(bundle.stat().st_size == TOOL_BUNDLE_BYTES and sha(bundle) == TOOL_BUNDLE_SHA256,
            "CodeQL bundle size or SHA-256 differs")
    version = small_command([str(codeql), "version", "--format=terse"], root / "evidence/version", environment)
    require(version.strip() == CLI_VERSION.encode(), "CodeQL version differs")
    # Internal option visibility is not a stable help-text interface.  Retain a
    # successful exact-version help invocation; admission below fixes the actual
    # allocation, bundle and queries, and query_command fixes every evaluator arg.
    small_command([str(codeql), "execute", "queries", "--help"], root / "evidence/execute-help", environment)
    ram = parse_strict_json_bytes(small_command(
        [str(codeql), "resolve", "ram", "--ram=14000", "--off-heap-ram=9329", "--format=json",
         "--dataset=" + str(database / "db-rust")],
        root / "evidence/resolve-ram", environment), label="CodeQL RAM allocation")
    require(ram == SOURCE_ALLOCATION, "retained source allocation differs")
    require(sha(QUERY_MANIFEST) == MANIFEST_SHA256, "pinned query manifest differs")
    pinned = read_json(QUERY_MANIFEST)
    require(isinstance(pinned, dict), "query manifest is not an object")
    pack = codeql.parent / "qlpacks/codeql/rust-queries" / QUERY_VERSION
    queries = {relative: pack / relative for relative in pinned["queries"]}
    query_hashes = {relative: sha(path) for relative, path in queries.items()}
    validate_query_inventory(query_hashes, pinned)
    compiled_hashes = {relative: sha(path.with_suffix(".qlx")) for relative, path in queries.items()}
    require(len(compiled_hashes) == 39 and canonical_sha(compiled_hashes) == COMPILED_INVENTORY_SHA256,
            "authenticated compiled query plan inventory differs")
    require(sha(codeql) == CODEQL_LAUNCHER_SHA256, "authenticated CodeQL launcher differs")
    with (root / "frozen.qls").open("x", encoding="utf-8") as stream:
        stream.write("".join("- query: " + json.dumps(str(queries[relative])) + "\n" for relative in sorted(queries)))
    tool = {"codeql_version": CLI_VERSION, "query_pack": QUERY_VERSION,
            "tool_bundle_sha256": TOOL_BUNDLE_SHA256, "tool_bundle_bytes": TOOL_BUNDLE_BYTES,
            "codeql_sha256": sha(codeql)}
    return queries, tool, query_hashes, compiled_hashes, ram


def jvm_probe(codeql: Path, root: Path, environment: dict, profile: str) -> dict:
    """Validate JVM flag passthrough against this exact bundle before any long query."""
    heap, _ = PROFILES[profile]
    stdout = small_command([str(codeql), "version", f"-J-Xmx{heap}M", "-J-XX:+PrintFlagsFinal", "--format=terse"],
                           root / "evidence/jvm-admission", environment)
    observed = [int(value) for value in re.findall(
        rb"(?m)^\s*(?:size_t|uintx) MaxHeapSize\s*:?=\s*([0-9]+)\s", stdout)]
    require(observed == [heap * 1024**2] and stdout.splitlines().count(CLI_VERSION.encode()) == 1,
            "actual bundle JVM flag or version admission differs")
    return {"max_heap_bytes_observed": observed, "codeql_version": CLI_VERSION}


def query_command(codeql: Path, database: Path, root: Path, profile: str,
                  summary_plan_mode: str = "none") -> list[str]:
    require(profile in PROFILES, "unknown allocation profile")
    require(summary_plan_mode in SUMMARY_PLANS, "unknown summary plan mode")
    heap, native = PROFILES[profile]
    join_mode = "none" if SUMMARY_PLANS[summary_plan_mode] is None else "all"
    return [str(codeql), "execute", "queries", f"-J-Xmx{heap}M", f"--off-heap-ram={native}", "-J-XX:+PrintFlagsFinal",
            "--threads=4", "--threat-model=local", "--warnings=show", "--dynamic-join-order-mode=" + join_mode,
            "--no-rerun", "--verbosity=progress", "--evaluator-log-level=5",
            "--evaluator-log=" + str(root / "evidence/evaluator-events.jsonl"),
            "--evaluator-log-minify", "--tuple-counting",
            "--common-caches=" + str(root / "cache"), "--logdir=" + str(root / "evidence/evaluator"),
            "--output=" + str(root / "results"), "--", str(database / "db-rust"), "path:" + str(root / "frozen.qls")]


def run_queries(command: list[str], evidence: Path, environment: dict, seconds: int = EVALUATION_SECONDS,
                *, progress_queries: dict | None = None) -> dict:
    start = time.monotonic()
    report = {"command": command, "returncode": None, "stopped": None}
    sampler = None
    try:
        try:
            sampler = ProcessResourceSampler(evidence)
            sampler.start()
        except Exception as error:
            report["resource_observation"] = {"status": "unavailable", "failure_type": type(error).__name__}
        # Expose each bounded chunk while the evaluator is still running.
        with (evidence / "query.stdout").open("xb", buffering=0) as stdout, \
                (evidence / "query.stderr").open("xb", buffering=0) as stderr:
            result = capture_output(command, timeout_seconds=seconds, timeout_policy=TimeoutPolicy.LONG_ANALYSIS,
                                    maximum_stdout_bytes=32 * 1024**2, maximum_stderr_bytes=16 * 1024**2,
                                    stdout_sink=stdout.write,
                                    stderr_sink=(evaluator_logs.QueryCompletionSink(stderr.write, progress_queries)
                                                 if progress_queries is not None else stderr.write),
                                    environment=environment)
        report["returncode"] = result.returncode
        return report
    except BoundedProcessError as error:
        report.update(stopped=error.kind, cleanup_ambiguous=error.cleanup_ambiguous)
        raise
    finally:
        report["seconds"] = time.monotonic() - start
        try:
            if sampler is not None:
                report["resource_observation"] = {**sampler.stop(), **report.get("resource_observation", {})}
            write_json(evidence / "PROCESS_RESOURCES.json", report["resource_observation"])
        except Exception as error:
            report["resource_observation_failure"] = {"type": type(error).__name__}
        write_json(evidence / "query.json", report)


def result_semantic_sha(decoded: bytes) -> str:
    data = parse_strict_json_bytes(decoded, label="CodeQL result")
    require(isinstance(data, dict) and data, "query result is malformed")
    for table in data.values():
        require(isinstance(table, dict) and isinstance(table.get("tuples"), list), "query result table differs")
        table["tuples"].sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))
    return canonical_sha(data)


def decode_query_results(codeql: Path, queries: dict[str, Path], result_root: Path,
                         evidence: Path, environment: dict, prefix: str) -> dict:
    expected = {Path(query).with_suffix(".bqrs").as_posix() for query in queries}
    require(result_root.is_dir() and not result_root.is_symlink(), "query output directory is missing")
    observed = {path.relative_to(result_root).as_posix() for path in result_root.rglob("*.bqrs")}
    require(observed == expected, "complete exact query result census is required")
    results = {}
    for relative in sorted(queries):
        bqrs = result_root / Path(relative).with_suffix(".bqrs")
        require(bqrs.is_file() and not bqrs.is_symlink(), "required query result missing: " + relative)
        # Decode and retain the same private bytes that supplied the BQRS digest.
        admitted = evidence / (prefix + "bqrs") / Path(relative).with_suffix(".bqrs")
        admitted.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with admitted.open("xb") as output:
            snapshot = consume_regular_snapshot(bqrs, maximum=64 * 1024**2,
                                                label="CodeQL BQRS", consume=output.write)
        os.chmod(admitted, 0o400)
        decoded = small_command([str(codeql), "bqrs", "decode", "--format=json", str(admitted)],
                                evidence / (prefix + Path(relative).stem + "-decoded"), environment)
        results[relative] = {"bqrs_sha256": snapshot.sha256, "semantic_sha256": result_semantic_sha(decoded)}
    return results


def decode_results(codeql: Path, queries: dict[str, Path], root: Path, environment: dict) -> dict:
    require(len(queries) == 39, "full query census is required")
    return decode_query_results(codeql, queries, root / "results/codeql/rust-queries",
                                root / "evidence", environment, "fresh-")


def decode_retained_results(codeql: Path, queries: dict[str, Path], root: Path, environment: dict) -> dict:
    require(len(queries) == 39 and FULL_SUMMARY in queries, "full original query census is required")
    original = {query: path for query, path in queries.items() if query != FULL_SUMMARY}
    return decode_query_results(codeql, original, root / "database/results/codeql/rust-queries",
                                root / "evidence", environment, "retained-")


def retain_partial_results(codeql: Path, queries: dict[str, Path], root: Path, environment: dict,
                           original: dict, *, cleanup_ambiguous: bool) -> dict:
    """Keep failure evidence from pinned fresh paths, without admitting completion."""
    start = time.monotonic()
    deadline = start + PARTIAL_RESULT_SECONDS
    evidence = root / "evidence"
    report = {"schema": 1, "kind": "qperiapt.codeql_summary_control_partial_results",
              "status": "partial", "analysis_completed": False, "budget_seconds": PARTIAL_RESULT_SECONDS,
              "budget_exhausted": False, "byte_budget_exhausted": False,
              "expected_query_count": len(queries), "results": {},
              "missing_queries": [], "capture_errors": {}, "all_expected_bqrs_captured": False}
    consumed = 0

    def capture_block(block: bytes, output: BinaryIO) -> None:
        nonlocal consumed
        consumed += len(block)
        report["byte_budget_exhausted"] = consumed > MAX_PARTIAL_RESULT_BYTES
        require(consumed <= MAX_PARTIAL_RESULT_BYTES, "partial BQRS capture exceeds its byte bound")
        require(time.monotonic() < deadline, "partial result capture exhausted its time budget")
        output.write(block)

    try:
        require(len(queries) == 39 and FULL_SUMMARY in queries, "full original query census is required")
        if cleanup_ambiguous:
            report.update(status="skipped", reason="evaluator cleanup is ambiguous")
            return report
        # Copy every available authenticated output path before starting any
        # decoder. The snapshot reader rejects symlinks and non-regular files,
        # including in parents; old database/results are never a fallback.
        for relative in sorted(queries):
            if report["byte_budget_exhausted"]:
                break
            if time.monotonic() >= deadline:
                report["budget_exhausted"] = True
                break
            source = root / "results/codeql/rust-queries" / Path(relative).with_suffix(".bqrs")
            admitted = evidence / "partial-fresh-bqrs" / Path(relative).with_suffix(".bqrs")
            created = False
            try:
                source.lstat()
                admitted.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with admitted.open("xb") as output:
                    created = True
                    snapshot = consume_regular_snapshot(source, maximum=64 * 1024**2,
                        label="partial fresh CodeQL BQRS", consume=lambda block: capture_block(block, output))
                os.chmod(admitted, 0o400)
                report["results"][relative] = {"path": admitted.relative_to(evidence).as_posix(),
                    "bytes": snapshot.size, "bqrs_sha256": snapshot.sha256, "decode_status": "not_attempted"}
            except FileNotFoundError:
                report["missing_queries"].append(relative)
            except (ValueError, OSError) as error:
                report["capture_errors"][relative] = {"type": type(error).__name__}
            finally:
                if created and relative not in report["results"]:
                    admitted.unlink(missing_ok=True)
        report["all_expected_bqrs_captured"] = set(report["results"]) == set(queries)
        for relative, record in report["results"].items():
            remaining = int(deadline - time.monotonic())
            if remaining < 1:
                report["budget_exhausted"] = True
                break
            record["decode_timeout_seconds"] = remaining
            try:
                decoded = small_command([str(codeql), "bqrs", "decode", "--format=json",
                                         str(evidence / record["path"])],
                    evidence / ("partial-fresh-" + Path(relative).stem + "-decoded"), environment,
                    timeout_seconds=remaining)
                record.update(semantic_sha256=result_semantic_sha(decoded), decode_status="decoded")
                if relative in original:
                    record["retained_semantics_equal"] = (
                        record["semantic_sha256"] == original[relative]["semantic_sha256"])
            except (ValueError, OSError, BoundedProcessError) as error:
                record.update(decode_status="failed", decode_error={"type": type(error).__name__})
                if isinstance(error, BoundedProcessError):
                    record["decode_error"].update(stopped=error.kind, cleanup_ambiguous=error.cleanup_ambiguous)
                    if error.cleanup_ambiguous:
                        report["decode_stop_reason"] = "decoder cleanup is ambiguous"
                        break
    except BaseException as error:
        report["capture_failure"] = {"type": type(error).__name__}
    finally:
        report["seconds"] = time.monotonic() - start
        report["budget_exhausted"] |= report["seconds"] >= PARTIAL_RESULT_SECONDS
        report["captured_query_count"] = len(report["results"])
        report["decoded_query_count"] = sum(value["decode_status"] == "decoded" for value in report["results"].values())
        report["uncaptured_queries"] = sorted(set(queries) - set(report["results"]))
        write_json(evidence / "PARTIAL_RESULTS.json", report)
    return report


def validate_retained_results(original: dict, fresh: dict, queries: dict) -> None:
    require(isinstance(original, dict) and set(original) == set(queries) - {FULL_SUMMARY},
            "retained 38-query result census differs")
    require(isinstance(fresh, dict) and set(fresh) == set(queries), "fresh 39-query result census differs")
    for query, value in original.items():
        require(isinstance(value, dict) and is_sha256(value.get("bqrs_sha256"))
                and is_sha256(value.get("semantic_sha256")), "retained result digest is malformed")
        require(isinstance(fresh[query], dict)
                and value["semantic_sha256"] == fresh[query].get("semantic_sha256"),
                "fresh result semantics differ from the retained result: " + query)


def evaluator_observations(evidence: Path) -> dict:
    try:
        return evaluator_logs.observe(
            evidence, seconds=OBSERVATION_SECONDS, maximum_log_bytes=MAX_EVALUATOR_LOG_BYTES,
            maximum_total_bytes=MAX_EVALUATOR_TOTAL_BYTES, maximum_line_bytes=retained.MAX_LINE_BYTES)
    except evaluator_logs.ObservationError as error:
        raise ControlError(str(error)) from None


def validate_observations(record: dict, profile: str) -> None:
    heap, native = PROFILES[profile]
    require(isinstance(record, dict) and record.get("schema") == 1
            and record.get("max_heap_bytes_observed") == [heap * 1024**2]
            and record.get("off_heap_mb_observed") == [native]
            and record.get("evaluator_start_lines") == 1,
            "actual JVM heap or accepted evaluator off-heap differs")
    require(type(record.get("pause_count")) is int and type(record.get("eviction_pause_count")) is int
            and 0 <= record["eviction_pause_count"] <= record["pause_count"],
            "evaluator pause observations are missing or malformed")


def configuration(profile: str) -> dict:
    heap, native = PROFILES[profile]
    return {"requested_ram_mb": heap + native + RESERVED_MB, "heap_mb": heap, "native_mb": native,
            "reserved_mb": RESERVED_MB, "threads": THREADS, "deadline_seconds": EVALUATION_SECONDS}


def validate_candidate_loads(record: dict, codeql: Path, query_hashes: dict) -> None:
    pack = codeql.parent / "qlpacks/codeql/rust-queries" / QUERY_VERSION
    expected = sorted(str((pack / query).with_suffix(".qlx")) for query in query_hashes)
    try:
        evaluator_logs.validate_loads(record, expected)
    except evaluator_logs.ObservationError as error:
        raise ControlError(str(error)) from None


def validate_plan_tool(plan, tool: dict) -> None:
    """Keep a fixed capsule bound to the controller's authenticated tool inputs."""
    try:
        summary_plan.validate_tool_identity(plan.manifest(), tool, query_manifest_sha256=MANIFEST_SHA256)
    except summary_plan.PlanError as error:
        raise ControlError(str(error)) from None


def compare_reports(baseline: dict, candidate: dict, summary_plan_mode: str = "none") -> dict:
    require(summary_plan_mode in SUMMARY_PLANS, "unknown comparison summary plan mode")
    plan = SUMMARY_PLANS[summary_plan_mode]
    for profile, report in (("heap-2048", baseline), ("heap-1536", candidate)):
        require(report.get("schema") == 1 and report.get("kind") == "qperiapt.codeql_summary_control"
                and report.get("profile") == profile, "comparison report identity differs")
        require(report.get("release_claim_eligible") is False and report.get("sarif_published") is False,
                "diagnostic report made a publication claim")
        require(report.get("configuration") == configuration(profile), "comparison allocation differs")
        require(report.get("summary_plan_mode", "none") == summary_plan_mode,
                "comparison summary plan mode differs")
        if plan is not None:
            expected_plan = plan.expected_identity()
            require(report.get("summary_plan") == expected_plan
                    and report.get("summary_plan_after") == expected_plan
                    and "summary_plan_after_failure" not in report,
                    "candidate summary plan identity or post-evaluation check differs")
    for key in ("source", "input_identity", "tool_identity", "query_hashes", "compiled_query_hashes", "ram_resolution",
                "experiment_commit", "retained_results", "cache_scope"):
        require(key in baseline and baseline[key] == candidate.get(key), "paired starting identity differs: " + key)
    require(baseline["source"] == SOURCE and baseline["ram_resolution"] == SOURCE_ALLOCATION,
            "paired source or historical allocation differs")
    commit = baseline["experiment_commit"]
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "paired experiment commit is missing or malformed")
    inputs = baseline["input_identity"]
    require(inputs == INPUT_IDENTITY and baseline["cache_scope"] == CACHE_SCOPE,
            "paired input or cache scope differs from the authenticated retained database")
    require(isinstance(inputs, dict) and all(is_sha256(inputs.get(key)) for key in
            ("inner_sha256", "database_inventory_sha256", "cache_inventory_sha256", "metadata_sha256")),
            "paired input digests are missing or malformed")
    require(type(inputs.get("inner_bytes")) is int and 0 < inputs["inner_bytes"] <= MAX_DATABASE_ZIP_BYTES,
            "paired database ZIP size differs from its bound")
    tool = baseline["tool_identity"]
    require(isinstance(tool, dict) and tool.get("codeql_version") == CLI_VERSION and tool.get("query_pack") == QUERY_VERSION
            and tool.get("tool_bundle_sha256") == TOOL_BUNDLE_SHA256
            and tool.get("tool_bundle_bytes") == TOOL_BUNDLE_BYTES
            and tool.get("codeql_sha256") == CODEQL_LAUNCHER_SHA256,
            "paired tool identity differs from the authenticated bundle")
    if plan is not None:
        validate_plan_tool(plan, tool)
    require(sha(QUERY_MANIFEST) == MANIFEST_SHA256, "pinned query manifest differs")
    pinned = read_json(QUERY_MANIFEST)
    validate_query_inventory(baseline["query_hashes"], pinned)
    compiled = baseline["compiled_query_hashes"]
    compiled_pin = (plan.COMPILED_INVENTORY_SHA256 if plan is not None
                    else COMPILED_INVENTORY_SHA256)
    require(isinstance(compiled, dict) and set(compiled) == set(baseline["query_hashes"])
            and all(is_sha256(value) for value in compiled.values())
            and canonical_sha(compiled) == compiled_pin, "compiled plan census or digest differs")
    for profile, report in (("heap-2048", baseline), ("heap-1536", candidate)):
        command = report.get("query_command")
        require(isinstance(command, list) and command and all(isinstance(arg, str) for arg in command),
                "recorded evaluator command is malformed")
        outputs = [arg.removeprefix("--output=") for arg in command if arg.startswith("--output=")]
        require(len(outputs) == 1, "recorded evaluator output is ambiguous")
        executable, output = Path(command[0]), Path(outputs[0])
        require(executable.is_absolute() and output.is_absolute() and output.name == "results"
                and ".." not in executable.parts and ".." not in output.parts,
                "recorded evaluator paths differ from the fixed layout")
        root = output.parent
        require(command == query_command(executable, root / "database", root, profile, summary_plan_mode),
                "recorded evaluator command differs from the complete specification")
    strip_memory = lambda command: [arg for arg in command if not arg.startswith(("-J-Xmx", "--off-heap-ram="))]
    require(strip_memory(baseline["query_command"]) == strip_memory(candidate["query_command"]),
            "paired commands differ beyond the allocation")
    for profile, report in (("heap-2048", baseline), ("heap-1536", candidate)):
        heap, native = PROFILES[profile]
        memory_arguments = [arg for arg in report["query_command"]
                            if arg.startswith(("-J-Xmx", "--off-heap-ram="))]
        require(memory_arguments == [f"-J-Xmx{heap}M", f"--off-heap-ram={native}"],
                "recorded command allocation differs")
        require(report.get("jvm_admission") == {"max_heap_bytes_observed": [heap * 1024**2],
                                                "codeql_version": CLI_VERSION},
                "actual bundle JVM admission is missing or malformed")
        validate_observations(report.get("observations"), profile)
        if plan is not None:
            validate_candidate_loads(report["observations"], Path(report["query_command"][0]), baseline["query_hashes"])
        validate_retained_results(report.get("retained_results"), report.get("results"), baseline["query_hashes"])
        evaluation = report.get("evaluation", {})
        require(report.get("completed") is True and evaluation.get("returncode") == 0
                and evaluation.get("stopped") is None and not evaluation.get("cleanup_ambiguous", False)
                and evaluation.get("command") == report["query_command"], "paired query evaluation is incomplete")
        elapsed = evaluation.get("seconds")
        require(type(elapsed) in (int, float) and math.isfinite(elapsed)
                and 0 <= elapsed <= EVALUATION_SECONDS + 30,
                "paired evaluator wall time is missing or exceeds its supervised boundary")
        results = report.get("results")
        require(isinstance(results, dict) and set(results) == set(baseline["query_hashes"]), "fresh result census differs")
        require(all(isinstance(value, dict) and is_sha256(value.get("semantic_sha256"))
                    and is_sha256(value.get("bqrs_sha256")) for value in results.values()),
                "fresh result digests are missing or malformed")
    require(all(baseline["results"][query]["semantic_sha256"] == candidate["results"][query]["semantic_sha256"]
                for query in baseline["query_hashes"]), "paired query semantics differ")
    return {"schema": 1, "kind": "qperiapt.codeql_summary_control_comparison", "completed": True,
            "source": SOURCE, "input_identity": baseline["input_identity"], "query_count": 39,
            "experiment_commit": baseline["experiment_commit"],
            "summary_plan_mode": summary_plan_mode,
            "semantic_results_equal": True, "retained_result_count": 38, "cache_scope": CACHE_SCOPE,
            "retained_semantic_results_equal": True, "production_default_validated": False, "sarif_published": False, "release_claim_eligible": False,
            "heap_2048_seconds": baseline["evaluation"].get("seconds"),
            "heap_1536_seconds": candidate["evaluation"].get("seconds"),
            "host_records_equal": baseline.get("host") == candidate.get("host"),
            "observations": {"heap-2048": baseline["observations"], "heap-1536": candidate["observations"]}}


def evaluate(codeql: Path, bundle: Path, output: Path, profile: str,
             summary_plan_mode: str = "none", *, retained_archive: Path | None = None) -> None:
    require(profile in PROFILES and platform.system() == "Linux" and platform.machine() == "x86_64",
            "requires a supported Linux x86_64 allocation profile")
    require(summary_plan_mode in SUMMARY_PLANS, "unknown summary plan mode")
    plan = SUMMARY_PLANS[summary_plan_mode]
    root = fresh_output_directory(output, within=Path(os.environ["RUNNER_TEMP"]).resolve(),
                                  label="retained SummaryStats allocation control")
    root.mkdir(mode=0o700, parents=True)
    evidence = root / "evidence"
    evidence.mkdir(mode=0o700)
    report = {"schema": 1, "kind": "qperiapt.codeql_summary_control", "profile": profile,
              "completed": False, "sarif_published": False, "release_claim_eligible": False,
              "source": SOURCE, "configuration": configuration(profile), "experiment_commit": os.environ.get("GITHUB_SHA"),
              "summary_plan_mode": summary_plan_mode,
              "cache_scope": CACHE_SCOPE,
              "host": {"kernel": platform.release(), "architecture": platform.machine(), "cpus": os.cpu_count(),
                       "meminfo": Path("/proc/meminfo").read_text(), "cpuinfo": Path("/proc/cpuinfo").read_text()}}
    phase = "prepare_database"
    write_json(evidence / "RESULT.json", report)
    try:
        database, report["input_identity"] = prepare_database(root, retained_archive=retained_archive)
        for name in ("home", "tmp", "cache", "results"):
            (root / name).mkdir(mode=0o700)
        (evidence / "evaluator").mkdir(mode=0o700)
        environment = {"HOME": str(root / "home"), "TMPDIR": str(root / "tmp"), "PATH": "/usr/bin:/bin",
                       "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}
        if "RUNNER_TRACKING_ID" in os.environ:
            environment["RUNNER_TRACKING_ID"] = os.environ["RUNNER_TRACKING_ID"]
        phase = "admit_tool"
        codeql = codeql.absolute()
        queries, report["tool_identity"], report["query_hashes"], report["compiled_query_hashes"], report["ram_resolution"] = \
            admit_tool(codeql, bundle, database, root, environment)
        if plan is not None:
            phase = "install_summary_plan"
            validate_plan_tool(plan, report["tool_identity"])
            pack = codeql.parent / "qlpacks/codeql/rust-queries" / QUERY_VERSION
            report["summary_plan"] = plan.install(pack, evidence)
            effective = {relative: sha(path.with_suffix(".qlx")) for relative, path in queries.items()}
            require(canonical_sha(effective) == plan.COMPILED_INVENTORY_SHA256,
                    "candidate changed another compiled query or did not install the fixed full summary")
            validate_query_inventory({relative: sha(path) for relative, path in queries.items()},
                                     read_json(QUERY_MANIFEST))
            report["compiled_query_hashes"] = effective
        phase = "jvm_admission"
        report["jvm_admission"] = jvm_probe(codeql, root, environment, profile)
        phase = "decode_retained_results"
        report["retained_results"] = decode_retained_results(codeql, queries, root, environment)
        command = query_command(codeql, database, root, profile, summary_plan_mode)
        report["query_command"] = command
        write_json(evidence / "RESULT.json", report)
        require(not any((root / "results").iterdir()), "query output is not fresh")
        phase = "evaluate"
        try:
            report["evaluation"] = run_queries(command, evidence, environment, progress_queries=queries)
        finally:
            # The bounded process supervisor has already stopped/reaped children.
            try:
                report["observations"] = evaluator_observations(evidence)
                write_json(evidence / "EVALUATOR_OBSERVATIONS.json", report["observations"])
            except (ValueError, OSError) as error:
                report["observation_failure"] = {"type": type(error).__name__}
            if plan is not None:
                # Always recheck effective bytes after the stopped evaluator.
                # Retain a secondary integrity failure without replacing the
                # evaluator's original exception or timeout.
                try:
                    require({relative: sha(path) for relative, path in queries.items()} == report["query_hashes"],
                            "query source changed during candidate evaluation")
                    require({relative: sha(path.with_suffix(".qlx")) for relative, path in queries.items()}
                            == report["compiled_query_hashes"], "compiled query changed during candidate evaluation")
                    report["summary_plan_after"] = plan.validate(pack)
                    write_json(evidence / "SUMMARY_PLAN_AFTER.json", report["summary_plan_after"])
                except (ValueError, OSError) as error:
                    report["summary_plan_after_failure"] = {"type": type(error).__name__, "message": str(error)}
                    try:
                        write_json(evidence / "SUMMARY_PLAN_AFTER_FAILURE.json", report["summary_plan_after_failure"])
                    except (ValueError, OSError) as retention_error:
                        report["summary_plan_failure_retention_error"] = {"type": type(retention_error).__name__}
        validate_observations(report.get("observations"), profile)
        require(report["evaluation"]["returncode"] == 0, "query evaluation did not complete")
        if plan is not None:
            require(report.get("summary_plan_after") == report["summary_plan"]
                    and "summary_plan_after_failure" not in report, "candidate effective plan changed during evaluation")
            validate_candidate_loads(report["observations"], codeql, report["query_hashes"])
        phase = "decode_results"
        report["results"] = decode_results(codeql, queries, root, environment)
        validate_retained_results(report["retained_results"], report["results"], queries)
        report["completed"] = True
    except BaseException as error:
        report["failure"] = {"phase": phase, "type": type(error).__name__,
                             "message": str(error) if isinstance(error, (ControlError, summary_plan.PlanError))
                             else "operation failed; inspect retained command receipts and logs"}
        try:
            if (evidence / "query.json").is_file():
                report["evaluation"] = read_json(evidence / "query.json")
            if phase in ("evaluate", "decode_results") and isinstance(report.get("evaluation"), dict):
                report["partial_results"] = retain_partial_results(codeql, queries, root, environment,
                    report["retained_results"], cleanup_ambiguous=report["evaluation"].get("cleanup_ambiguous", False))
        except BaseException as capture_error:
            # Secondary retention failures must not replace the evaluator failure.
            report["partial_result_failure"] = {"type": type(capture_error).__name__}
        raise RuntimeError("Retained SummaryStats control failed; inspect evidence/RESULT.json") from None
    finally:
        write_json(evidence / "RESULT.json", report)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    run = commands.add_parser("run")
    run.add_argument("--codeql", type=Path, required=True)
    run.add_argument("--tool-archive", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--profile", choices=tuple(PROFILES), required=True)
    run.add_argument("--retained-archive", type=Path,
                     help="Read the exact pinned artifact from this local file instead of downloading it")
    run.add_argument("--summary-plan-mode", choices=tuple(SUMMARY_PLANS), default="none")
    compare = commands.add_parser("compare")
    compare.add_argument("--baseline", type=Path, required=True)
    compare.add_argument("--candidate", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    compare.add_argument("--summary-plan-mode", choices=tuple(SUMMARY_PLANS), default="none")
    args = parser.parse_args()
    if args.action == "run":
        evaluate(args.codeql, args.tool_archive, args.output, args.profile, args.summary_plan_mode,
                 retained_archive=args.retained_archive)
    else:
        result = {"schema": 1, "kind": "qperiapt.codeql_summary_control_comparison", "completed": False,
                  "sarif_published": False, "release_claim_eligible": False}
        try:
            result = compare_reports(read_json(args.baseline), read_json(args.candidate), args.summary_plan_mode)
        except BaseException as error:
            result["failure"] = {"type": type(error).__name__, "message": str(error) if isinstance(error, ControlError)
                                 else "comparison input could not be admitted"}
            raise RuntimeError("Paired memory comparison is incomplete; inspect its receipt") from None
        finally:
            write_json(args.output, result)


if __name__ == "__main__":
    main()

