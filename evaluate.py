"""Bounded evaluator experiment over one immutable, previously failed database."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

ARTIFACT_ID = 11487635292
ARCHIVE_BYTES = 605657034
ARCHIVE_SHA = "1d190f653fdb1317786ba0d5e6bf00b51702df3a4c810b89f9a544c90beef839"
DB_BYTES = 614781717
DB_SHA = "6cdecae63baa75c0c9755938d030f2439c5f5d991ef66281ce493f5904dfee23"
MERGE_SHA = "309cc4d6d2c8aa7deba23f4f1a81b23c327b956a"
TREE_SHA = "a7fb99aaae9de721983413665241af47d7206167"
QUERY_PREFIX = "/opt/hostedtoolcache/CodeQL/2.27.1/x64/codeql/"
SUITE_SHA = "db39d1bd280a14c89e0719e561922b13c21d7f03180db7c192d021010ed0e416"
EVALUATION_SECONDS = 85 * 60


class ControlError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise ControlError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(2 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def write(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def safe_name(info):
    value = info.filename
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and ".." not in path.parts
            and "\\" not in value and "\0" not in value
            and value.rstrip("/") == str(path), "unsafe archive member")
    require(stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR),
            "archive contains a non-regular member")
    require(info.file_size < 384 * 1024 * 1024, "archive member exceeds bound")
    return path


def inspect_database(path):
    require(path.stat().st_size == DB_BYTES and sha(path) == DB_SHA,
            "retained database archive identity differs")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        require(len(members) == 16723 and len({m.filename for m in members}) == 16723
                and sum(m.file_size for m in members) == 5570882960,
                "retained database inventory differs")
        for member in members:
            safe_name(member)
        metadata = archive.read("codeql-database.yml").decode()
        require("\nfinalised: true\n" in metadata and f"  sha: {MERGE_SHA}\n" in metadata
                and "  cliVersion: 2.27.1\n" in metadata
                and "primaryLanguage: rust\n" in metadata, "database metadata differs")
        config = json.loads(archive.read("temp/analysisConfig.json"))
        require(config == {"extensionPacks": [], "threatModels": ["local"]},
                "database threat model or extensions differ")
        suite = archive.read("temp/config-queries.qls")
        require(hashlib.sha256(suite).hexdigest() == SUITE_SHA, "query suite differs")
        queries = re.findall(r"^\s+query: (.+\.ql)$", suite.decode(), re.MULTILINE)
        require(len(queries) == len(set(queries)) == 39, "query census differs")
        require(all(q.startswith(QUERY_PREFIX + "qlpacks/codeql/rust-queries/0.1.43/queries/")
                    for q in queries), "query pack differs")
        require(any(q.endswith("/summary/SummaryStats.ql") for q in queries),
                "full SummaryStats is missing")
        initial = {m.filename: hashlib.sha256(archive.read(m)).hexdigest()
                   for m in members if m.filename.endswith(".bqrs")}
        require(len(initial) == 38, "retained result census differs")
    return queries, initial


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def download(path):
    token = os.environ["GH_TOKEN"]
    request = urllib.request.Request(
        f"https://api.github.com/repos/billlza/q-periapt/actions/artifacts/{ARTIFACT_ID}/zip",
        headers={"Authorization": "Bearer " + token})
    try:
        urllib.request.build_opener(NoRedirect).open(request, timeout=30)
    except urllib.error.HTTPError as error:
        require(error.code == 302, f"artifact API status {error.code}")
        url = error.headers["Location"]
    else:
        raise ValueError("artifact redirect missing")
    start = time.monotonic()
    count = 0
    with urllib.request.urlopen(url, timeout=45) as response, path.open("xb") as output:
        while block := response.read(2 * 1024 * 1024):
            count += len(block)
            require(count <= ARCHIVE_BYTES and time.monotonic() - start < 900,
                    "artifact transfer exceeded size/time bound")
            output.write(block)
    require(count == ARCHIVE_BYTES and sha(path) == ARCHIVE_SHA, "artifact digest differs")


def run_command(command, prefix, environment, seconds):
    start = time.monotonic()
    stopped = None
    with prefix.with_suffix(".stdout").open("xb") as output, prefix.with_suffix(".stderr").open("xb") as error:
        process = subprocess.Popen(command, stdout=output, stderr=error,
                                   env=environment, start_new_session=True)
        try:
            while process.poll() is None:
                if time.monotonic() - start >= seconds:
                    stopped = "deadline"
                elif output.tell() + error.tell() > 1024 ** 3:
                    stopped = "log_bound"
                if stopped:
                    break
                time.sleep(2)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=30)
    result = {"command": command, "returncode": process.returncode,
              "seconds": time.monotonic() - start, "stopped": stopped,
              "stdout_sha256": sha(prefix.with_suffix(".stdout")),
              "stderr_sha256": sha(prefix.with_suffix(".stderr"))}
    write(prefix.with_suffix(".json"), result)
    return result


def evaluate(args):
    root = args.output.resolve()
    require(not root.exists() and platform.system() == "Linux"
            and platform.machine() == "x86_64", "requires a fresh Linux x86_64 output")
    root.mkdir(mode=0o700, parents=True)
    evidence = root / "evidence"
    evidence.mkdir(mode=0o700)
    report = {"kind": "qperiapt.codeql_query_resource_control", "completed": False,
              "release_claim_eligible": False, "threads": args.threads, "ram_MB": 14575,
              "evaluation_seconds_bound": EVALUATION_SECONDS, "artifact_sha256": ARCHIVE_SHA,
              "database_zip_sha256": DB_SHA, "database_creation_sha": MERGE_SHA,
              "source_tree": TREE_SHA, "source_branch_head": "fe06176bc6c30c8cda45707fc1208b91b70b507d",
              "cache_scope": "Identical retained cache from failed evaluation; not cold extraction.",
              "host": {"uname": list(os.uname()), "cpus": os.cpu_count(),
                       "meminfo": Path("/proc/meminfo").read_text()},
              "experiment_commit": os.environ.get("GITHUB_SHA")}
    write(evidence / "RESULT.json", report)
    phase = "download"
    try:
        outer = root / "diagnostics.zip"
        download(outer)
        database_zip = root / "db.zip"
        with zipfile.ZipFile(outer) as archive:
            member = archive.getinfo("db-rust-partial.zip")
            require(member.file_size == DB_BYTES, "inner archive size differs")
            with archive.open(member) as source, database_zip.open("xb") as destination:
                shutil.copyfileobj(source, destination, 2 * 1024 * 1024)
        phase = "admit_database"
        queries, initial = inspect_database(database_zip)
        write(evidence / "initial-results.json", initial)
        database = root / "database"
        database.mkdir(mode=0o700)
        with zipfile.ZipFile(database_zip) as archive:
            for member in archive.infolist():
                destination = database / safe_name(member)
                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, destination.open("xb") as output:
                        shutil.copyfileobj(source, output, 2 * 1024 * 1024)
        phase = "admit_tool"
        codeql = args.codeql.resolve(strict=True)
        env = {k: v for k, v in os.environ.items() if k in
               ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "TZ", "RUNNER_TRACKING_ID")}
        version = run_command([str(codeql), "version", "--format=terse"], evidence / "version", env, 60)
        require(version["returncode"] == 0 and (evidence / "version.stdout").read_text().strip() == "2.27.1",
                "CodeQL version differs")
        selected = [codeql.parent / q.removeprefix(QUERY_PREFIX) for q in queries]
        require(all(p.is_file() for p in selected), "frozen query is unavailable")
        report["codeql"] = {"path": str(codeql), "sha256": sha(codeql), "version": "2.27.1"}
        report["query_hashes"] = {q.removeprefix(QUERY_PREFIX): sha(p) for q, p in zip(queries, selected)}
        require(all(p.with_suffix(".qlx").is_file() for p in selected), "linked compiled query missing")
        report["compiled_query_hashes"] = {q.removeprefix(QUERY_PREFIX): sha(p.with_suffix(".qlx")) for q, p in zip(queries, selected)}
        suite = root / "frozen.qls"
        suite.write_text("\n".join("- query: " + json.dumps(str(p)) for p in selected) + "\n")
        phase = "evaluate"
        command = [str(codeql), "database", "run-queries", "--ram=14575", f"--threads={args.threads}",
                   "--expect-discarded-cache", "--min-disk-free=1024", "--threat-model=local", "-v",
                   str(database), "path:" + str(suite)]
        report["evaluation"] = run_command(command, evidence / "query", env, EVALUATION_SECONDS)
        write(evidence / "RESULT.json", report)
        # Preserve only evaluator logs from this process, excluding the input logs.
        for log in (database / "log").glob("*.log"):
            if log.name in {"database-run-queries-20261007.122444.078.log",
                            "execute-queries-20261007.122444.757.log"}:
                continue
            if log.name.startswith(("database-run-queries-", "execute-queries-")):
                require(log.stat().st_size < 1024 ** 3, "evaluator log exceeds bound")
                shutil.copyfile(log, evidence / log.name)
        require(report["evaluation"]["returncode"] == 0 and not report["evaluation"]["stopped"],
                "query evaluation did not complete")
        phase = "decode_results"
        result_hashes = {}
        for q in queries:
            relative = q.split("/0.1.43/", 1)[1]
            bqrs = database / "results/codeql/rust-queries" / Path(relative).with_suffix(".bqrs")
            require(bqrs.is_file(), "required query result missing")
            prefix = evidence / (Path(relative).stem + "-decoded")
            decoded = run_command([str(codeql), "bqrs", "decode", "--format=json", str(bqrs)], prefix, env, 120)
            require(decoded["returncode"] == 0 and prefix.with_suffix(".stdout").stat().st_size <= 32 * 1024**2,
                    "query result decoding failed or exceeded bound")
            data = json.loads(prefix.with_suffix(".stdout").read_text())
            for table in data.values():
                require(isinstance(table, dict) and isinstance(table.get("tuples"), list), "result table shape differs")
                table["tuples"].sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))
            result_hashes[relative] = {"bqrs_sha256": sha(bqrs), "semantic_sha256": hashlib.sha256(
                json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        require(len(result_hashes) == 39, "incomplete query results")
        report.update(completed=True, results=result_hashes)
    except BaseException as error:
        # A signed download URL or bearer credential must never enter retained diagnostics.
        report["failure"] = {"phase": phase, "type": type(error).__name__,
                             "message": str(error) if isinstance(error, ControlError)
                             else "operation failed; inspect bounded command logs"}
        raise RuntimeError("Resource control failed; inspect evidence/RESULT.json") from None
    finally:
        write(evidence / "RESULT.json", report)


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise InterruptedError("owned resource experiment interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inspect", "run"))
    parser.add_argument("--database-zip", type=Path)
    parser.add_argument("--codeql", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--threads", type=int, choices=(1, 4))
    args = parser.parse_args()
    if args.mode == "inspect":
        require(args.database_zip is not None, "database zip required")
        queries, initial = inspect_database(args.database_zip)
        print(json.dumps({"preflight_verified": True, "queries": len(queries), "initial_results": len(initial),
                          "database_creation_sha": MERGE_SHA, "source_tree": TREE_SHA, "queries_executed": False}))
    else:
        require(args.codeql is not None and args.output is not None and args.threads is not None,
                "codeql, output and threads required")
        evaluate(args)
