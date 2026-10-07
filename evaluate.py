"""Bounded replay of unchanged quality queries on the failed run's immutable database."""
from pathlib import Path
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
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import PurePosixPath

ARTIFACT_ID = 11515742809
ARCHIVE_BYTES = 371808439
ARCHIVE_SHA = "85559c1778f4d43bedb889a6184a86d4a8fd5d4facdddd467519caa19dcbc3a6"
DB_BYTES = 348024890
MERGE_SHA = "605de309dbcf5ebdca6652e1487e9425c6e38a4b"
TREE_SHA = "b4226f96ac064e099b3c71392b2700d481ba7449"
EVALUATION_SECONDS = 1200
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "artifact"))
import codeql_rust_quality as quality


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


def inspect_database(path):
    require(path.stat().st_size == DB_BYTES, "database archive size differs")
    # Called only after the complete enclosing archive's pinned digest is verified.
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        require(0 < len(members) < 25000 and len({m.filename for m in members}) == len(members)
                and sum(m.file_size for m in members) < 12 * 1024**3,
                "database inventory exceeds bounds or contains duplicates")
        for member in members:
            safe_name(member)
        metadata = archive.read("codeql-database.yml").decode()
        require("\nfinalised: true\n" in metadata and f"  sha: {MERGE_SHA}\n" in metadata
                and "  cliVersion: 2.27.1\n" in metadata
                and "primaryLanguage: rust\n" in metadata, "database metadata differs")
        config = json.loads(archive.read("temp/analysisConfig.json"))
        require(config == {"extensionPacks": [], "threatModels": ["local"]},
                "database threat model or extensions differ")
        return {"sha256": sha(path), "members": len(members),
                "expanded_bytes": sum(m.file_size for m in members),
                "metadata": metadata, "analysis_config": config,
                "initial_results": {m.filename: hashlib.sha256(archive.read(m)).hexdigest()
                                    for m in members if m.filename.endswith(".bqrs")},
                "cache_members": [{"path": m.filename, "bytes": m.file_size}
                                  for m in members if m.filename.startswith("db-rust/default/cache/")]}


def evaluate(args):
    root = args.output.resolve()
    require(not root.exists() and platform.system() == "Linux"
            and platform.machine() == "x86_64", "requires a fresh Linux x86_64 output")
    root.mkdir(mode=0o700, parents=True)
    evidence = root / "evidence"
    evidence.mkdir(mode=0o700)
    report = {"kind": "qperiapt.codeql_quality_resource_control", "completed": False,
              "release_claim_eligible": False, "current_product_ci_qualified": False,
              "threads": 4, "ram_MB": 14000, "query_seconds_bound": EVALUATION_SECONDS,
              "artifact_id": ARTIFACT_ID, "artifact_sha256": ARCHIVE_SHA,
              "database_creation_sha": MERGE_SHA, "source_tree": TREE_SHA,
              "source_branch_head": "4fc8412a02084bb6d5de003d99eeaab2aa79079b",
              "cache_scope": "Frozen diagnostic bundle, retained prior results/cache if present; not cold extraction.",
              "host": {"uname": list(os.uname()), "cpus": os.cpu_count(),
                       "meminfo": Path("/proc/meminfo").read_text()},
              "experiment_commit": os.environ.get("GITHUB_SHA"), "queries": {}}
    write(evidence / "RESULT.json", report)
    phase = "source_admission"
    database = root / "database"
    initial_logs = set()
    try:
        manifest = json.loads((ROOT / "source-inputs.json").read_text())
        for relative, expected in manifest.items():
            require(sha(ROOT / relative) == expected["sha256"], "source input hash differs")
        tracked = json.loads((ROOT / "tracked-rust.json").read_text())
        require(tracked["commit"] == MERGE_SHA and tracked["tree"] == TREE_SHA
                and len(tracked["paths"]) == len(set(tracked["paths"])) == 418,
                "frozen tracked Rust inventory differs")
        report["source_inputs"] = manifest
        report["tracked_inventory_sha256"] = sha(ROOT / "tracked-rust.json")
        phase = "download"
        outer = root / "diagnostics.zip"
        download(outer)
        database_zip = root / "db.zip"
        with zipfile.ZipFile(outer) as archive:
            members = [m for m in archive.infolist() if m.filename == "db-rust.zip"]
            require(len(members) == 1 and members[0].file_size == DB_BYTES,
                    "inner archive size or multiplicity differs")
            with archive.open(members[0]) as source, database_zip.open("xb") as destination:
                shutil.copyfileobj(source, destination, 2 * 1024 * 1024)
        phase = "admit_database"
        inventory = inspect_database(database_zip)
        write(evidence / "database-inventory.json", inventory)
        report["database_zip_sha256"] = inventory["sha256"]
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
        initial_logs = {p.name for p in (database / "log").glob("*.log")}
        phase = "admit_tool"
        codeql = args.codeql.resolve(strict=True)
        env = {k: v for k, v in os.environ.items() if k in
               ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "TZ", "RUNNER_TRACKING_ID")}
        version = run_command([str(codeql), "version", "--format=terse"], evidence / "version", env, 60)
        require(version["returncode"] == 0 and (evidence / "version.stdout").read_text().strip() == "2.27.1",
                "CodeQL version differs")
        report["codeql"] = {"path": str(codeql), "sha256": sha(codeql), "version": "2.27.1"}
        decoded_rows = {}
        for name in ("ExtractedPaths", "Metrics", "UnresolvedMacros"):
            phase = name
            query = ROOT / "artifact/codeql-rust-quality" / (name + ".ql")
            output = evidence / (name + ".bqrs")
            command = [str(codeql), "query", "run", "--warnings=error", "--threads=4", "--ram=14000",
                       "--database=" + str(database), "--output=" + str(output), "--", str(query)]
            result = run_command(command, evidence / (name + "-run"), env, EVALUATION_SECONDS)
            report["queries"][name] = result
            write(evidence / "RESULT.json", report)
            require(result["returncode"] == 0 and not result["stopped"], "quality query did not complete: " + name)
            require(output.is_file(), "quality result missing")
            prefix = evidence / (name + "-decoded")
            decoded = run_command([str(codeql), "bqrs", "decode", "--format=json", str(output)], prefix, env, 300)
            require(decoded["returncode"] == 0 and not decoded["stopped"]
                    and prefix.with_suffix(".stdout").stat().st_size <= 16 * 1024**2,
                    "quality decoding failed or exceeded bound")
            value = quality.parse_strict_json_bytes(prefix.with_suffix(".stdout").read_bytes(), label=name)
            require(isinstance(value, dict) and set(value) == {"#select"}
                    and isinstance(value["#select"].get("tuples"), list), "result schema differs")
            decoded_rows[name] = value["#select"]["tuples"]
        phase = "validate_quality"
        metrics = quality._parse_metrics(decoded_rows["Metrics"])
        extracted = quality._parse_extracted_paths(decoded_rows["ExtractedPaths"])
        unresolved = quality._parse_unresolved_macros(decoded_rows["UnresolvedMacros"])
        report["metrics"] = metrics
        report["extracted_paths"] = sorted(extracted)
        report["unresolved_macros"] = unresolved
        quality.validate_unresolved_detail_count(metrics["unresolved_source_macro_calls"], unresolved)
        quality.validate_quality(frozenset(tracked["paths"]), extracted, metrics)
        report.update(completed=True, all_original_quality_assertions_pass=True)
    except BaseException as error:
        report["failure"] = {"phase": phase, "type": type(error).__name__,
                             "message": str(error) if isinstance(error, (ControlError, quality.CodeQLRustQualityError))
                             else "operation failed; inspect bounded command logs"}
        raise RuntimeError("Quality control failed; inspect evidence/RESULT.json") from None
    finally:
        write(evidence / "RESULT.json", report)
        # Preserve this attempt's evaluator logs even when a query times out.
        for log in (database / "log").glob("*.log"):
            if log.name not in initial_logs:
                require(log.stat().st_size < 1024**3, "evaluator log exceeds bound")
                shutil.copyfile(log, evidence / log.name)


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise InterruptedError("owned quality experiment interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codeql", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    evaluate(parser.parse_args())
