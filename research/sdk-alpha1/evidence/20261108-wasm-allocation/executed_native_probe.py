"""Check the Linux native memory policy with the pinned CLI on a tiny fixture."""
from pathlib import Path
import dataclasses
import hashlib
import json
import os
import re
import shutil
import sys

BASE = Path(__file__).resolve().parent
WORKSPACE = BASE.parents[1]
SOURCE = WORKSPACE / "qperiapt-ci-followup"
sys.path.insert(0, str(SOURCE / "artifact"))
import codeql_rust_profile as profile

TOOL = WORKSPACE / "ci-memory/tool/codeql"
CLI = TOOL / "codeql"
PACK = TOOL / "qlpacks/codeql/rust-queries/0.1.44"
FIXTURE = WORKSPACE / "ci-memory/cli-propagation/minimal-database"
OUTPUT = BASE / "cli-native"
OUTPUT.mkdir()
DATABASE = OUTPUT / "database"
shutil.copytree(FIXTURE, DATABASE)
assert not (DATABASE / "results").exists()


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


manifest = json.loads((SOURCE / "artifact/codeql_rust_queries.json").read_text())
assert len(manifest["queries"]) == 39
assert manifest["queries"] == {name: digest(PACK / name) for name in manifest["queries"]}
run = profile.ProfileRun(SOURCE, OUTPUT / "profile-run", CLI, dict(os.environ))
run.configuration = dataclasses.replace(run.configuration, database=DATABASE)
assert run.command("version", [str(CLI), "version", "--format=terse"]).strip() == b"2.27.2"
arguments = profile.analysis_memory_arguments(run, "native")
memory = json.loads((run.evidence / "QUERY_MEMORY.json").read_text())
profile.validate_linux_query_memory(memory, "native")
sarif = OUTPUT / "results.sarif"
run.command("native-fixture-analyze", [str(CLI), "database", "analyze", str(DATABASE),
            str(PACK / "codeql-suites/rust-security-extended.qls"),
            "--format=sarif-latest", "--output=" + str(sarif),
            "--threads=4", *arguments, "--threat-model=local", "--no-download",
            "--common-caches=" + str(OUTPUT / "cache"),
            "--sarif-category=" + profile.sarif_category("native")], seconds=120)
logs = list((DATABASE / "log").glob("execute-queries-*.log"))
assert len(logs) == 1
with logs[0].open() as log:
    invocation = log.readline().strip()
actual = re.findall(r"(?<!\S)(?:-J-Xmx[0-9]+M|--off-heap-ram=[0-9]+)(?!\S)", invocation)
assert actual == memory["resolved_arguments"]
results = {}
for query in manifest["queries"]:
    result = DATABASE / "results/codeql/rust-queries" / Path(query).with_suffix(".bqrs")
    assert result.is_file() and result.stat().st_size > 0
    results[query] = digest(result)
sarif_data = json.loads(sarif.read_text())
profile.validate_sarif(sarif_data, "native")
receipt = {
    "schema": 1, "completed": True,
    "scope": "CodeQL 2.27.2 native high-level argument propagation and interpretation on a synthetic one-file TRAP fixture.",
    "repository_extraction_qualification": False,
    "repository_performance_measurement": False,
    "profile": "native", "arguments": arguments, "memory_receipt": memory,
    "actual_evaluator_memory": actual, "actual_evaluator_launch": invocation,
    "source_profile_sha256": digest(SOURCE / "artifact/codeql_rust_profile.py"),
    "probe_script_sha256": digest(Path(__file__)),
    "codeql_launcher_sha256": digest(CLI),
    "query_manifest_sha256": digest(SOURCE / "artifact/codeql_rust_queries.json"),
    "fixture_metadata_sha256": digest(FIXTURE / "codeql-database.yml"),
    "query_count": len(results), "query_result_sha256": results,
    "sarif_automation_details": sarif_data["runs"][0]["automationDetails"],
    "sarif_sha256": digest(sarif),
    "analysis": json.loads((run.evidence / "native-fixture-analyze.json").read_text()),
}
(BASE / "NATIVE_CLI_PROPAGATION.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps({key: receipt[key] for key in ("completed", "profile", "actual_evaluator_memory", "query_count", "sarif_automation_details")}))
