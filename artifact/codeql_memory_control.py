"""Bounded memory-allocation control over the retained 3b Rust database.

This is a diagnostic experiment, never a replacement for current-source CI.
Both profiles retain the original 39 queries and the same total evaluator RAM.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

from bounded_process import BoundedProcessError, capture_output, write_stdout_at
from evidence_io import fresh_output_directory, parse_strict_json_bytes


ARTIFACT_ID = 11699924502
ARCHIVE_BYTES = 712661923
ARCHIVE_SHA = "bc69588523d9e5d05d300caac226121efe95db99968489261d451ddc6a629920"
DB_BYTES = 724803663
DB_SHA = "73e1a231c11a3c920d8348dcfa7ef792e66b756b486af49012b98ceafa8f2096"
MERGE_SHA = "49a76aa0ecc788bdbd886c27e46fe93bff5affb6"
SOURCE_HEAD = "3b6547715ad69208d889be19a6e3e4852daef08c"
SUITE_SHA = "db39d1bd280a14c89e0719e561922b13c21d7f03180db7c192d021010ed0e416"
QUERY_PREFIX = "/opt/hostedtoolcache/CodeQL/2.27.1/x64/codeql/"
QUERY_MANIFEST = Path(__file__).with_name("codeql_memory_queries.json")
PROFILES = {"baseline": (5788, 6898), "more-native": (3072, 9614)}
EVALUATION_SECONDS = 900


class ControlError(ValueError):
    """The experiment no longer matches its admitted inputs or completed result."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ControlError(message)


def sha(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def safe_name(info: zipfile.ZipInfo) -> PurePosixPath:
    value = info.filename
    path = PurePosixPath(value)
    require(bool(value) and not path.is_absolute() and ".." not in path.parts
            and "\\" not in value and "\0" not in value
            and value.rstrip("/") == str(path), "unsafe archive member")
    require(stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR),
            "archive contains a non-regular member")
    require(info.file_size < 384 * 1024 * 1024, "archive member exceeds bound")
    return path


def inspect_database(path: Path) -> list[str]:
    require(path.stat().st_size == DB_BYTES and sha(path) == DB_SHA,
            "retained database archive identity differs")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        require(len(members) == len({m.filename for m in members}) == 25256
                and sum(m.file_size for m in members) == 6833539370,
                "retained database inventory differs")
        for member in members:
            safe_name(member)
        metadata = archive.read("codeql-database.yml").decode()
        require("\nfinalised: true\n" in metadata and f"  sha: {MERGE_SHA}\n" in metadata
                and "  cliVersion: 2.27.1\n" in metadata
                and "primaryLanguage: rust\n" in metadata, "database metadata differs")
        require(parse_strict_json_bytes(archive.read("temp/analysisConfig.json"), label="frozen analysis config")
                == {"extensionPacks": [], "threatModels": ["local"]},
                "database threat model or extensions differ")
        suite = archive.read("temp/config-queries.qls")
        require(hashlib.sha256(suite).hexdigest() == SUITE_SHA, "query suite differs")
        queries = re.findall(r"^\s+query: (.+\.ql)$", suite.decode(), re.MULTILINE)
        expected = parse_strict_json_bytes(QUERY_MANIFEST.read_bytes(), label="frozen query manifest")["query_hashes"]
        require(len(queries) == len(set(queries)) == len(expected) == 39
                and {q.removeprefix(QUERY_PREFIX) for q in queries} == set(expected),
                "query census differs")
        require(sum(m.filename.endswith(".bqrs") for m in members) == 38,
                "retained result census differs")
    return queries


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def download(path: Path) -> None:
    request = urllib.request.Request(
        f"https://api.github.com/repos/billlza/q-periapt/actions/artifacts/{ARTIFACT_ID}/zip",
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"]})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30):
            raise ControlError("artifact redirect missing")
    except urllib.error.HTTPError as error:
        with error:
            require(error.code == 302, f"artifact API status {error.code}")
            url = error.headers["Location"]
    # The bearer token is sent only to the fixed API host, never to the redirect.
    require(url.startswith("https://"), "artifact redirect is not HTTPS")
    start, count = time.monotonic(), 0
    with urllib.request.urlopen(url, timeout=45) as response, path.open("xb") as output:
        while block := response.read(2 * 1024 * 1024):
            count += len(block)
            require(count <= ARCHIVE_BYTES and time.monotonic() - start < 900,
                    "artifact transfer exceeded size/time bound")
            output.write(block)
    require(count == ARCHIVE_BYTES and sha(path) == ARCHIVE_SHA, "artifact digest differs")


def prepare_database(root: Path) -> tuple[Path, list[str]]:
    outer, inner = root / "diagnostics.zip", root / "db.zip"
    download(outer)
    with zipfile.ZipFile(outer) as archive:
        member = archive.getinfo("db-rust-partial.zip")
        require(member.file_size == DB_BYTES, "inner archive size differs")
        with archive.open(member) as source, inner.open("xb") as destination:
            shutil.copyfileobj(source, destination, 2 * 1024 * 1024)
    queries = inspect_database(inner)
    database = root / "database"
    database.mkdir(mode=0o700)
    with zipfile.ZipFile(inner) as archive:
        for member in archive.infolist():
            destination = database / safe_name(member)
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output, 2 * 1024 * 1024)
    return database, queries


def small_command(command: list[str], prefix: Path, env: dict[str, str]) -> bytes:
    result = capture_output(command, timeout_seconds=120, environment=env,
                            maximum_stdout_bytes=32 * 1024**2,
                            maximum_stderr_bytes=4 * 1024**2)
    prefix.with_suffix(".stdout").write_bytes(result.stdout)
    prefix.with_suffix(".stderr").write_bytes(result.stderr)
    write(prefix.with_suffix(".json"), {"command": command, "returncode": result.returncode})
    require(result.returncode == 0, f"{prefix.name} failed")
    return result.stdout


def admit_tool(codeql: Path, queries: list[str], evidence: Path,
               env: dict[str, str]) -> list[Path]:
    version = small_command([str(codeql), "version", "--format=terse"], evidence / "version", env)
    require(version.strip() == b"2.27.1", "CodeQL version differs")
    small_command([str(codeql), "execute", "queries", "--help"], evidence / "execute-help", env)
    selected = [codeql.parent / q.removeprefix(QUERY_PREFIX) for q in queries]
    manifest = parse_strict_json_bytes(QUERY_MANIFEST.read_bytes(), label="frozen query manifest")
    observed = {"query_hashes": {}, "compiled_query_hashes": {}}
    for q, path in zip(queries, selected):
        key = q.removeprefix(QUERY_PREFIX)
        observed["query_hashes"][key] = sha(path)
        observed["compiled_query_hashes"][key] = sha(path.with_suffix(".qlx"))
    write(evidence / "query-hashes.json", observed)
    require(observed == {k: manifest[k] for k in observed}, "query text or compiled plan differs")
    return selected


def query_command(codeql: Path, database: Path, root: Path, profile: str) -> list[str]:
    heap, native = PROFILES[profile]
    return [str(codeql), "execute", "queries", f"-J-Xmx{heap}M", f"--off-heap-ram={native}",
            "--threads=4", "--expect-discarded-cache", "--min-disk-free=1024",
            "--threat-model=local", "--warnings=show", "--dynamic-join-order-mode=none",
            "--verbosity=progress+", "--evaluator-log-level=5",
            f"--logdir={root / 'evidence/evaluator'}", f"--output={root / 'results'}",
            "--", str(database / "db-rust"), "path:" + str(root / "frozen.qls")]


def run_queries(command: list[str], evidence: Path, env: dict[str, str],
                seconds: int = EVALUATION_SECONDS) -> dict:
    start = time.monotonic()
    result = {"command": command, "returncode": None, "stopped": None}
    descriptor = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY)
    try:
        completed = write_stdout_at(command, output_directory_fd=descriptor,
                                    output_name="query.console", timeout_seconds=seconds,
                                    maximum_bytes=512 * 1024**2, stderr=subprocess.STDOUT,
                                    environment=env, retain_nonzero=True)
        result["returncode"] = completed.returncode
    except BoundedProcessError as error:
        result.update(stopped=error.kind, cleanup_ambiguous=error.cleanup_ambiguous)
        raise
    finally:
        os.close(descriptor)
        result["seconds"] = time.monotonic() - start
        write(evidence / "query.json", result)
    return result


def decode_results(codeql: Path, queries: list[str], root: Path, env: dict[str, str]) -> dict:
    results = {}
    # Output is fresh; none of the 38 pre-existing BQRS files can satisfy this check.
    for query in queries:
        relative = query.split("/0.1.43/", 1)[1]
        bqrs = root / "results/codeql/rust-queries" / Path(relative).with_suffix(".bqrs")
        require(bqrs.is_file(), f"required fresh query result missing: {relative}")
        decoded = small_command([str(codeql), "bqrs", "decode", "--format=json", str(bqrs)],
                                root / "evidence" / (Path(relative).stem + "-decoded"), env)
        data = parse_strict_json_bytes(decoded, label="decoded CodeQL result")
        for table in data.values():
            require(isinstance(table, dict) and isinstance(table.get("tuples"), list),
                    "result table shape differs")
            table["tuples"].sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        results[relative] = {"bqrs_sha256": sha(bqrs), "semantic_sha256": hashlib.sha256(canonical).hexdigest()}
    require(len(results) == 39, "incomplete query results")
    return results


def evaluate(codeql: Path, output: Path, profile: str) -> None:
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "requires Linux x86_64")
    root = fresh_output_directory(output, within=Path(os.environ["RUNNER_TEMP"]).resolve(),
                                  label="CodeQL memory control")
    root.mkdir(mode=0o700, parents=True)
    evidence = root / "evidence"
    evidence.mkdir(mode=0o700)
    report = {"kind": "qperiapt.codeql_memory_control", "completed": False,
              "release_claim_eligible": False, "profile": profile, "threads": 4,
              "heap_MB": PROFILES[profile][0], "off_heap_MB": PROFILES[profile][1],
              "evaluation_seconds_bound": EVALUATION_SECONDS,
              "artifact_sha256": ARCHIVE_SHA, "database_zip_sha256": DB_SHA,
              "database_creation_sha": MERGE_SHA, "source_branch_head": SOURCE_HEAD,
              "cache_scope": "Identical retained cache; not cold extraction or current-source CI.",
              "host": {"uname": list(os.uname()), "cpus": os.cpu_count(),
                       "meminfo": Path("/proc/meminfo").read_text()},
              "experiment_commit": os.environ.get("GITHUB_SHA")}
    write(evidence / "RESULT.json", report)
    phase = "prepare_database"
    try:
        database, queries = prepare_database(root)
        phase = "admit_tool"
        codeql = codeql.resolve(strict=True)
        env = {k: v for k, v in os.environ.items() if k in
               ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "TZ", "RUNNER_TRACKING_ID")}
        selected = admit_tool(codeql, queries, evidence, env)
        # Capture the pinned CLI's own RAM heuristic as well as its help text.
        ram = small_command([str(codeql), "resolve", "ram", "--ram=14575", "--format=json",
                             f"--dataset={database / 'db-rust'}"], evidence / "resolve-ram", env)
        report["resolved_ram"] = parse_strict_json_bytes(ram, label="CodeQL RAM allocation")
        require(any(value.startswith("--off-heap-ram=") for value in report["resolved_ram"]),
                "pinned CLI does not expose the expected native memory control")
        (root / "frozen.qls").write_text("\n".join("- query: " + json.dumps(str(p)) for p in selected) + "\n")
        (root / "results").mkdir()
        (evidence / "evaluator").mkdir()
        phase = "evaluate"
        report["evaluation"] = run_queries(query_command(codeql, database, root, profile), evidence, env)
        require(report["evaluation"]["returncode"] == 0, "query evaluation did not complete")
        phase = "decode_results"
        report.update(results=decode_results(codeql, queries, root, env), completed=True)
    except BaseException as error:
        # Do not retain exception text containing signed URLs or bearer credentials.
        report["failure"] = {"phase": phase, "type": type(error).__name__,
                             "message": str(error) if isinstance(error, ControlError)
                             else "operation failed; inspect retained command receipts and evaluator logs"}
        raise RuntimeError("Memory control failed; inspect evidence/RESULT.json") from None
    finally:
        write(evidence / "RESULT.json", report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect", type=Path)
    parser.add_argument("--codeql", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--profile", choices=tuple(PROFILES))
    args = parser.parse_args()
    if args.inspect:
        print(json.dumps({"queries": len(inspect_database(args.inspect)), "queries_executed": False}))
    else:
        require(args.codeql is not None and args.output is not None and args.profile is not None,
                "codeql, output and profile required")
        evaluate(args.codeql, args.output, args.profile)
