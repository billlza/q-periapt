"""Paired evaluator allocation control over one authenticated WASM database.

This diagnostic restores the same retained database/cache for both profiles.
It executes all 39 pinned queries, requires fresh complete results, and never
publishes SARIF or changes the production analysis configuration.
"""

from __future__ import annotations

import argparse
import calendar
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import time
import zipfile

from bounded_process import BoundedProcessError, TimeoutPolicy, capture_output
from evidence_io import fresh_output_directory, parse_strict_json_bytes, read_regular_snapshot
import codeql_log_recovery as retained


CLI_VERSION = "2.27.2"
QUERY_VERSION = "0.1.44"
PROFILES = {"baseline": (5668, 6733), "native-heavy": (3072, 9329)}
RAM_MB = 14000
RESERVED_MB = 1599
THREADS = 4
EVALUATION_SECONDS = 18000
INNER_MEMBER = "qperiapt-codeql-wasm/diagnostics/database.zip"
MAX_DATABASE_ZIP_BYTES = 768 * 1024**2
MAX_DATABASE_MEMBERS = 100000
MAX_DATABASE_MEMBER_BYTES = 8 * 1024**3
MAX_DATABASE_BYTES = 20 * 1024**3
MIN_FREE_BYTES = 2 * 1024**3
EXTRACTION_SECONDS = 900
DIRECTORY_EPOCH = 946684800
TOOL_BUNDLE_BYTES = 98247028
TOOL_BUNDLE_SHA256 = "acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea"
MANIFEST_SHA256 = "eb54654d668bfafc45f785427158a97e378791b20f9cb374d97301e7c296039b"
QUERY_MANIFEST = Path(__file__).with_name("codeql_rust_queries.json")
SOURCE = {"artifact_id": 13609897355, "artifact_bytes": 600073757,
          "artifact_sha256": "68fc0a7e8f3fc02d9f072acc7eaa457d8e9174ab597d888ca632330ea6ba86c9",
          "source_head": "72acaaccde1ca9ea27e5af022da5fbce932ed4e9",
          "analyzed_commit": "cf5bf0195936c2f38197aa571c452a216c757abe", "source_run": 42439010975}


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
    names = {member.filename for member in members}
    require("codeql-database.yml" in names and any(name.startswith("db-rust/") for name in names),
            "archive does not contain a Rust database")
    return sorted(members, key=lambda member: member.filename)


def restore_database(inner_zip: Path, destination: Path) -> dict:
    require(not destination.exists() and not destination.is_symlink(), "database destination must be fresh")
    deadline = time.monotonic() + EXTRACTION_SECONDS
    files: dict[str, dict] = {}
    directories: dict[str, dict] = {".": {"mode": 0o700, "mtime": DIRECTORY_EPOCH}}
    with zipfile.ZipFile(inner_zip) as archive:
        members = select_database_members(archive)
        require(shutil.disk_usage(destination.parent).free
                >= sum(member.file_size for member in members) + MIN_FREE_BYTES,
                "insufficient free disk for the complete database and evaluator reserve")
        metadata_info = archive.getinfo("codeql-database.yml")
        require(metadata_info.file_size <= 128 * 1024, "database metadata exceeds its bound")
        metadata = archive.read(metadata_info)
        text = metadata.decode("utf-8")
        require(re.search(r"(?m)^primaryLanguage: rust\s*$", text) is not None
                and re.search(r"(?m)^finalised: true\s*$", text) is not None
                and re.search(r"(?m)^\s+cliVersion: ['\"]?2\.27\.2['\"]?\s*$", text) is not None,
                "database language, finalization, or CLI identity differs")
        git_shas = re.findall(r"(?m)^\s+sha: ['\"]?([0-9a-f]{40})['\"]?\s*$", text)
        require(not git_shas or git_shas == [SOURCE["analyzed_commit"]], "database creation commit differs")
        destination.mkdir(mode=0o700)
        for member in members:
            require(time.monotonic() <= deadline, "database restoration exceeded its time bound")
            relative = retained.safe_member(member)
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
    return {"files": files, "directories": directories,
            "database_inventory_sha256": canonical_sha({"files": files, "directories": directories}),
            "cache_inventory_sha256": canonical_sha(cache), "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
            "metadata_git_sha": git_shas[0] if git_shas else None}


def prepare_database(root: Path) -> tuple[Path, dict]:
    require((retained.ARTIFACT_ID, retained.ARCHIVE_BYTES, retained.ARCHIVE_SHA256)
            == (SOURCE["artifact_id"], SOURCE["artifact_bytes"], SOURCE["artifact_sha256"]),
            "retained artifact downloader identity differs")
    outer, inner = root / "diagnostics.zip", root / "retained-database.zip"
    retained.download(outer)
    require(outer.stat().st_size == SOURCE["artifact_bytes"] and sha(outer) == SOURCE["artifact_sha256"],
            "outer artifact identity differs")
    with zipfile.ZipFile(outer) as archive:
        members = archive.infolist()
        require(len(members) <= retained.MAX_MEMBERS and len(members) == len({m.filename for m in members}),
                "outer artifact inventory differs")
        for member in members:
            retained.safe_member(member)
        info = archive.getinfo(INNER_MEMBER)
        require(not info.is_dir() and 0 < info.file_size <= MAX_DATABASE_ZIP_BYTES,
                "retained database ZIP size differs")
        deadline, count = time.monotonic() + EXTRACTION_SECONDS, 0
        with archive.open(info) as source, inner.open("xb") as output:
            while block := source.read(1024 * 1024):
                count += len(block)
                require(count <= info.file_size and time.monotonic() <= deadline,
                        "retained database transfer exceeded its bound")
                output.write(block)
        require(count == info.file_size, "retained database ZIP is truncated")
    database = root / "database"
    inventory = restore_database(inner, database)
    write_json(root / "evidence/DATABASE_INPUTS.json", inventory)
    identity = {name: inventory[name] for name in
                ("database_inventory_sha256", "cache_inventory_sha256", "metadata_sha256")}
    identity.update(inner_bytes=inner.stat().st_size, inner_sha256=sha(inner))
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


def small_command(command: list[str], prefix: Path, environment: dict[str, str]) -> bytes:
    with prefix.with_suffix(".stdout").open("xb") as stdout, prefix.with_suffix(".stderr").open("xb") as stderr:
        result = capture_output(command, timeout_seconds=120, maximum_stdout_bytes=32 * 1024**2,
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
        [str(codeql), "resolve", "ram", "--ram=14000", "--format=json", "--dataset=" + str(database / "db-rust")],
        root / "evidence/resolve-ram", environment), label="CodeQL RAM allocation")
    require(ram == ["-J-Xmx5668M", "--off-heap-ram=6733"], "pinned baseline allocation differs")
    require(sha(QUERY_MANIFEST) == MANIFEST_SHA256, "pinned query manifest differs")
    pinned = read_json(QUERY_MANIFEST)
    require(isinstance(pinned, dict), "query manifest is not an object")
    pack = codeql.parent / "qlpacks/codeql/rust-queries" / QUERY_VERSION
    queries = {relative: pack / relative for relative in pinned["queries"]}
    query_hashes = {relative: sha(path) for relative, path in queries.items()}
    validate_query_inventory(query_hashes, pinned)
    compiled_hashes = {relative: sha(path.with_suffix(".qlx")) for relative, path in queries.items()}
    require(len(compiled_hashes) == 39, "compiled query plan census differs")
    with (root / "frozen.qls").open("x", encoding="utf-8") as stream:
        stream.write("".join("- query: " + json.dumps(str(queries[relative])) + "\n" for relative in sorted(queries)))
    tool = {"codeql_version": CLI_VERSION, "query_pack": QUERY_VERSION,
            "tool_bundle_sha256": TOOL_BUNDLE_SHA256, "tool_bundle_bytes": TOOL_BUNDLE_BYTES,
            "codeql_sha256": sha(codeql)}
    return queries, tool, query_hashes, compiled_hashes, ram


def query_command(codeql: Path, database: Path, root: Path, profile: str) -> list[str]:
    require(profile in PROFILES, "unknown allocation profile")
    heap, native = PROFILES[profile]
    return [str(codeql), "execute", "queries", f"-J-Xmx{heap}M", f"--off-heap-ram={native}",
            "--threads=4", "--threat-model=local", "--warnings=show", "--dynamic-join-order-mode=none",
            "--no-rerun", "--verbosity=progress", "--evaluator-log-level=5",
            "--common-caches=" + str(root / "cache"), "--logdir=" + str(root / "evidence/evaluator"),
            "--output=" + str(root / "results"), "--", str(database / "db-rust"), "path:" + str(root / "frozen.qls")]


def run_queries(command: list[str], evidence: Path, environment: dict, seconds: int = EVALUATION_SECONDS) -> dict:
    start = time.monotonic()
    report = {"command": command, "returncode": None, "stopped": None}
    try:
        with (evidence / "query.stdout").open("xb") as stdout, (evidence / "query.stderr").open("xb") as stderr:
            result = capture_output(command, timeout_seconds=seconds, timeout_policy=TimeoutPolicy.LONG_ANALYSIS,
                                    maximum_stdout_bytes=32 * 1024**2, maximum_stderr_bytes=16 * 1024**2,
                                    stdout_sink=stdout.write, stderr_sink=stderr.write, environment=environment)
        report["returncode"] = result.returncode
        return report
    except BoundedProcessError as error:
        report.update(stopped=error.kind, cleanup_ambiguous=error.cleanup_ambiguous)
        raise
    finally:
        report["seconds"] = time.monotonic() - start
        write_json(evidence / "query.json", report)


def decode_results(codeql: Path, queries: dict[str, Path], root: Path, environment: dict) -> dict:
    require(len(queries) == 39, "full query census is required")
    results = {}
    for relative in sorted(queries):
        bqrs = root / "results/codeql/rust-queries" / Path(relative).with_suffix(".bqrs")
        require(bqrs.is_file() and not bqrs.is_symlink(), "required fresh query result missing: " + relative)
        decoded = small_command([str(codeql), "bqrs", "decode", "--format=json", str(bqrs)],
                                root / "evidence" / (Path(relative).stem + "-decoded"), environment)
        data = parse_strict_json_bytes(decoded, label="fresh CodeQL result")
        require(isinstance(data, dict) and data, "fresh query result is malformed")
        for table in data.values():
            require(isinstance(table, dict) and isinstance(table.get("tuples"), list), "query result table differs")
            table["tuples"].sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))
        results[relative] = {"bqrs_sha256": sha(bqrs), "semantic_sha256": canonical_sha(data)}
    return results


def configuration(profile: str) -> dict:
    heap, native = PROFILES[profile]
    return {"requested_ram_mb": RAM_MB, "heap_mb": heap, "native_mb": native,
            "reserved_mb": RESERVED_MB, "threads": THREADS, "deadline_seconds": EVALUATION_SECONDS}


def compare_reports(baseline: dict, candidate: dict) -> dict:
    for profile, report in (("baseline", baseline), ("native-heavy", candidate)):
        require(report.get("schema") == 1 and report.get("kind") == "qperiapt.codeql_current_memory"
                and report.get("profile") == profile, "comparison report identity differs")
        require(report.get("release_claim_eligible") is False and report.get("sarif_published") is False,
                "diagnostic report made a publication claim")
        require(report.get("configuration") == configuration(profile), "comparison allocation differs")
    for key in ("source", "input_identity", "tool_identity", "query_hashes", "compiled_query_hashes", "ram_resolution",
                "experiment_commit"):
        require(key in baseline and baseline[key] == candidate.get(key), "paired starting identity differs: " + key)
    require(baseline["source"] == SOURCE and baseline["ram_resolution"] == ["-J-Xmx5668M", "--off-heap-ram=6733"],
            "paired source or baseline allocation differs")
    commit = baseline["experiment_commit"]
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "paired experiment commit is missing or malformed")
    inputs = baseline["input_identity"]
    require(isinstance(inputs, dict) and all(is_sha256(inputs.get(key)) for key in
            ("inner_sha256", "database_inventory_sha256", "cache_inventory_sha256", "metadata_sha256")),
            "paired input digests are missing or malformed")
    require(type(inputs.get("inner_bytes")) is int and 0 < inputs["inner_bytes"] <= MAX_DATABASE_ZIP_BYTES,
            "paired database ZIP size differs from its bound")
    tool = baseline["tool_identity"]
    require(isinstance(tool, dict) and tool.get("codeql_version") == CLI_VERSION and tool.get("query_pack") == QUERY_VERSION
            and tool.get("tool_bundle_sha256") == TOOL_BUNDLE_SHA256
            and tool.get("tool_bundle_bytes") == TOOL_BUNDLE_BYTES and is_sha256(tool.get("codeql_sha256")),
            "paired tool identity differs from the authenticated bundle")
    require(sha(QUERY_MANIFEST) == MANIFEST_SHA256, "pinned query manifest differs")
    pinned = read_json(QUERY_MANIFEST)
    validate_query_inventory(baseline["query_hashes"], pinned)
    compiled = baseline["compiled_query_hashes"]
    require(isinstance(compiled, dict) and set(compiled) == set(baseline["query_hashes"])
            and all(is_sha256(value) for value in compiled.values()), "compiled plan census or digest differs")
    for profile, report in (("baseline", baseline), ("native-heavy", candidate)):
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
        require(command == query_command(executable, root / "database", root, profile),
                "recorded evaluator command differs from the complete specification")
    strip_memory = lambda command: [arg for arg in command if not arg.startswith(("-J-Xmx", "--off-heap-ram="))]
    require(strip_memory(baseline["query_command"]) == strip_memory(candidate["query_command"]),
            "paired commands differ beyond the allocation")
    for profile, report in (("baseline", baseline), ("native-heavy", candidate)):
        heap, native = PROFILES[profile]
        memory_arguments = [arg for arg in report["query_command"]
                            if arg.startswith(("-J-Xmx", "--off-heap-ram="))]
        require(memory_arguments == [f"-J-Xmx{heap}M", f"--off-heap-ram={native}"],
                "recorded command allocation differs")
        require(report.get("completed") is True and report.get("evaluation", {}).get("returncode") == 0
                and report["evaluation"].get("stopped") is None, "paired query evaluation is incomplete")
        results = report.get("results")
        require(isinstance(results, dict) and set(results) == set(baseline["query_hashes"]), "fresh result census differs")
        require(all(isinstance(value, dict) and is_sha256(value.get("semantic_sha256"))
                    and is_sha256(value.get("bqrs_sha256")) for value in results.values()),
                "fresh result digests are missing or malformed")
    require(all(baseline["results"][query]["semantic_sha256"] == candidate["results"][query]["semantic_sha256"]
                for query in baseline["query_hashes"]), "paired query semantics differ")
    return {"schema": 1, "kind": "qperiapt.codeql_current_memory_comparison", "completed": True,
            "source": SOURCE, "input_identity": baseline["input_identity"], "query_count": 39,
            "experiment_commit": baseline["experiment_commit"],
            "semantic_results_equal": True, "sarif_published": False, "release_claim_eligible": False,
            "baseline_seconds": baseline["evaluation"].get("seconds"),
            "candidate_seconds": candidate["evaluation"].get("seconds"),
            "host_records_equal": baseline.get("host") == candidate.get("host")}


def evaluate(codeql: Path, bundle: Path, output: Path, profile: str) -> None:
    require(profile in PROFILES and platform.system() == "Linux" and platform.machine() == "x86_64",
            "requires a supported Linux x86_64 allocation profile")
    root = fresh_output_directory(output, within=Path(os.environ["RUNNER_TEMP"]).resolve(),
                                  label="current CodeQL memory control")
    root.mkdir(mode=0o700, parents=True)
    evidence = root / "evidence"
    evidence.mkdir(mode=0o700)
    report = {"schema": 1, "kind": "qperiapt.codeql_current_memory", "profile": profile,
              "completed": False, "sarif_published": False, "release_claim_eligible": False,
              "source": SOURCE, "configuration": configuration(profile), "experiment_commit": os.environ.get("GITHUB_SHA"),
              "cache_scope": "Identical authenticated bundle after recorded disposable-cache trimming; fresh common cache/results.",
              "host": {"kernel": platform.release(), "architecture": platform.machine(), "cpus": os.cpu_count(),
                       "meminfo": Path("/proc/meminfo").read_text(), "cpuinfo": Path("/proc/cpuinfo").read_text()}}
    phase = "prepare_database"
    write_json(evidence / "RESULT.json", report)
    try:
        database, report["input_identity"] = prepare_database(root)
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
        command = query_command(codeql, database, root, profile)
        report["query_command"] = command
        write_json(evidence / "RESULT.json", report)
        require(not any((root / "results").iterdir()), "query output is not fresh")
        phase = "evaluate"
        report["evaluation"] = run_queries(command, evidence, environment)
        require(report["evaluation"]["returncode"] == 0, "query evaluation did not complete")
        phase = "decode_results"
        report["results"] = decode_results(codeql, queries, root, environment)
        report["completed"] = True
    except BaseException as error:
        if (evidence / "query.json").is_file():
            report["evaluation"] = read_json(evidence / "query.json")
        report["failure"] = {"phase": phase, "type": type(error).__name__,
                             "message": str(error) if isinstance(error, ControlError)
                             else "operation failed; inspect retained command receipts and logs"}
        raise RuntimeError("Current memory control failed; inspect evidence/RESULT.json") from None
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
    compare = commands.add_parser("compare")
    compare.add_argument("--baseline", type=Path, required=True)
    compare.add_argument("--candidate", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "run":
        evaluate(args.codeql, args.tool_archive, args.output, args.profile)
    else:
        result = {"schema": 1, "kind": "qperiapt.codeql_current_memory_comparison", "completed": False,
                  "sarif_published": False, "release_claim_eligible": False}
        try:
            result = compare_reports(read_json(args.baseline), read_json(args.candidate))
        except BaseException as error:
            result["failure"] = {"type": type(error).__name__, "message": str(error) if isinstance(error, ControlError)
                                 else "comparison input could not be admitted"}
            raise RuntimeError("Paired memory comparison is incomplete; inspect its receipt") from None
        finally:
            write_json(args.output, result)


if __name__ == "__main__":
    main()
