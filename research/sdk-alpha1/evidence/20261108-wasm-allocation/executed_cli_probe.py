"""Exercise the pinned CLI's high-level memory propagation on a synthetic dataset.

The fixture contains one files() TRAP tuple. Its results establish command
propagation and interpretation behavior, not repository extraction or security.
"""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import re
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "tool/codeql"
CLI = TOOL / "codeql"
PACK = TOOL / "qlpacks/codeql/rust-queries/0.1.44"
FIXTURE = ROOT / "cli-propagation/minimal-database"
QUERY_MANIFEST = ROOT.parent / "qperiapt-ci-memory/artifact/codeql_rust_queries.json"
OUTPUT = ROOT / "high-level-control"
OUTPUT.mkdir()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(args, record, seconds=120):
    start = time.monotonic()
    result = subprocess.run([str(CLI), *map(str, args)], capture_output=True, timeout=seconds)
    record.with_suffix(".stdout").write_bytes(result.stdout)
    record.with_suffix(".stderr").write_bytes(result.stderr)
    write(record.with_suffix(".json"), {"argv": [str(CLI), *map(str, args)],
          "returncode": result.returncode, "seconds": time.monotonic() - start})
    if result.returncode:
        raise RuntimeError(f"CLI operation failed: {record.name}: {result.stderr[-4000:]!r}")
    return result.stdout


pinned = json.loads(QUERY_MANIFEST.read_text())
if pinned["queries"] != {name: digest(PACK / name) for name in pinned["queries"]}:
    raise RuntimeError("Pinned 39-query inventory differs")
receipts = {}
for case, options in (("baseline", ["--ram=14000"]),
                      ("native-heavy", ["--ram=14000", "--off-heap-ram=9329"])):
    directory = OUTPUT / case
    directory.mkdir()
    database = directory / "database"
    shutil.copytree(FIXTURE, database)
    if (database / "results").exists():
        raise RuntimeError("Fixture already contains query results")
    resolved = json.loads(command(["resolve", "ram", *options,
        "--dataset=" + str(database / "db-rust"), "--format=json"], directory / "resolve"))
    sarif = directory / "results.sarif"
    command(["database", "analyze", database, PACK / "codeql-suites/rust-security-extended.qls",
             "--format=sarif-latest", "--output=" + str(sarif), "--threads=4", *options,
             "--threat-model=local", "--no-download", "--common-caches=" + str(directory / "cache"),
             "--sarif-category=/language:rust/target:wasm"], directory / "analyze", seconds=180)
    logs = list((database / "log").glob("execute-queries-*.log"))
    if len(logs) != 1:
        raise RuntimeError("Expected one new evaluator log")
    with logs[0].open() as stream:
        invocation = stream.readline().strip()
    actual = re.findall(r"(?<!\S)(?:-J-Xmx[0-9]+M|--off-heap-ram=[0-9]+)(?!\S)", invocation)
    if actual != resolved:
        raise RuntimeError(f"High-level command did not propagate memory resolution: {actual} != {resolved}")

    def decode(name):
        bqrs = database / "results/codeql/rust-queries" / Path(name).with_suffix(".bqrs")
        data = json.loads(command(["bqrs", "decode", "--format=json", bqrs],
                          directory / (Path(name).stem + "-decoded")))
        for table in data.values():
            table["tuples"].sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        return name, {"semantic_sha256": hashlib.sha256(canonical).hexdigest(), "bqrs_sha256": digest(bqrs)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = dict(executor.map(decode, sorted(pinned["queries"])))
    data = json.loads(sarif.read_text())
    if not all(invocation["executionSuccessful"] for run in data["runs"] for invocation in run["invocations"]):
        raise RuntimeError("Interpretation did not succeed")
    receipts[case] = {"options": options, "resolved": resolved, "actual_evaluator_memory": actual,
                      "evaluator_invocation": invocation, "query_count": len(results), "results": results,
                      "sarif_automation_details": data["runs"][0]["automationDetails"],
                      "sarif_result_count": len(data["runs"][0]["results"])}
    print(case, resolved, len(results), flush=True)
if any(receipts["baseline"]["results"][query]["semantic_sha256"] !=
       receipts["native-heavy"]["results"][query]["semantic_sha256"] for query in pinned["queries"]):
    raise RuntimeError("Synthetic-fixture result semantics differ")
report = {"schema": 1, "completed": True,
          "scope": "Actual CodeQL 2.27.2 high-level memory propagation and interpretation on a synthetic one-file TRAP fixture.",
          "repository_extraction_qualification": False, "repository_performance_measurement": False,
          "tool_archive_sha256": digest(ROOT / "tool/codeql-bundle-rust-linux64.tar.zst"),
          "tool_archive_bytes": (ROOT / "tool/codeql-bundle-rust-linux64.tar.zst").stat().st_size,
          "codeql_sha256": digest(CLI), "query_manifest_sha256": digest(QUERY_MANIFEST),
          "fixture_metadata_sha256": digest(FIXTURE / "codeql-database.yml"),
          "all_39_semantic_results_equal": True, "cases": receipts}
write(OUTPUT / "CLI_HIGH_LEVEL_CONTROL.json", report)
print("High-level propagation and 39-result equivalence passed", flush=True)
