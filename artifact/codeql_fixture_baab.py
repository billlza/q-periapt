#!/usr/bin/env python3
"""One-shot B-A-A-B fixture control; no production entrypoint or mode changes."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
DIAGNOSTIC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DIAGNOSTIC / "artifact"))
import codeql_wrapper_fixture as fixture

require, save, inventory = fixture.require, fixture.save, fixture.inventory
read_json, canonical, identity = fixture.read_json, fixture.canonical, fixture.identity
SOURCES = {
    "A": ("b5185165283880527a54289b47397fde78ddf553",
          "2cb1739ba0f0aeeb00e8a017b7cd0218a0a7519771a58dd47cb7f89a8813ca91",
          "13705d5f8b164bd69a12219c41a7fe8ba7e304247a4b78d0150c4dd36882d441"),
    "B": ("ed38e305552db2825d90622c130973df87e16d50",
          "efd65ee72a4f966620a3d9bd6ac97b0a6d8ef5567017f3c342f654c4e1f55873",
          "332897d1bbd8506384f3788f1e27635593b815e7a7e739154e6b340885e726be"),
}
ORDER = ("B1", "A2", "A3", "B4")


def workflow_identity():
    head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"],
                                   cwd=DIAGNOSTIC, text=True).strip()
    require(head == os.environ["GITHUB_SHA"], "diagnostic workflow HEAD differs")
    return head


def prepare_sources(run):
    """Snapshot both exact Git artifacts before the first measured analysis."""
    root = run.output / "comparison"
    root.mkdir(mode=0o700)
    (root / "evidence").mkdir()
    (root / "runs").mkdir()
    (root / "sources").mkdir()
    run.command("pair-fetch", ["/usr/bin/git", "-C", str(DIAGNOSTIC), "fetch",
                "--no-tags", "--depth=1", "origin", *[item[0] for item in SOURCES.values()]],
                seconds=180)
    records = {}
    for side, (commit, manifest, _) in SOURCES.items():
        destination = root / "sources" / side
        destination.mkdir()
        archive = root / "sources" / (side + ".tar")
        run.command("pair-archive-" + side, ["/usr/bin/git", "-C", str(DIAGNOSTIC),
                    "archive", "--format=tar", "--output=" + str(archive), commit, "artifact"])
        listing = run.command("pair-tree-" + side, ["/usr/bin/git", "-C", str(DIAGNOSTIC),
                              "ls-tree", "-rz", commit, "artifact"])
        entries = {}
        for item in listing.rstrip(b"\0").split(b"\0"):
            header, path = item.split(b"\t", 1)
            mode, kind, digest = header.decode().split()
            name = path.decode()
            require(mode in ("100644", "100755") and kind == "blob"
                    and name.startswith("artifact/") and name not in entries,
                    "source snapshot contains a nonregular or duplicate member")
            entries[name] = {"mode": mode, "git_blob": digest}
        run.command("pair-unpack-" + side, ["/usr/bin/tar", "--extract", "--file=" + str(archive),
                    "--no-same-owner", "--directory=" + str(destination)])
        files = inventory(destination)
        require(set(files) == set(entries), "source snapshot file census differs")
        for name, expected in entries.items():
            data = (destination / name).read_bytes()
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            require(blob == expected["git_blob"], "source snapshot Git bytes differ: " + name)
        require(identity(destination / "artifact/codeql_summary_projection.json")["sha256"] == manifest,
                "source snapshot plan manifest differs")
        records[side] = {"commit": commit, "git_entries": entries, "files": files,
                         "inventory_sha256": canonical(files), "archive": identity(archive)}
    save(root / "evidence/SOURCES.json", {
        "workflow_source_commit": workflow_identity(), "production_sources": records,
        "helper": identity(Path(__file__)), "order": list(ORDER)})


def run_remaining(run):
    """Called after B1 sampling/validation and before the first BQRS decode."""
    environment = run.environment
    try:
        run.environment = {**environment, "GITHUB_SHA": os.environ["GITHUB_SHA"],
                           "RUNNER_TEMP": os.environ["RUNNER_TEMP"]}
        for arm in ORDER[1:]:
            run.command("pair-" + arm, ["/usr/bin/timeout", "--signal=TERM", "--kill-after=15s",
                        "850s", "/usr/bin/python3", "-I", "-S", "-B", str(Path(__file__)),
                        "--output", str(run.output), "--worker", arm], seconds=900)
    finally:
        run.environment = environment


def source_run(output, side, evidence):
    source = output / "comparison/sources" / side
    record = read_json((output / "comparison/evidence/SOURCES.json").read_bytes())
    require(record["workflow_source_commit"] == workflow_identity()
            and record["production_sources"][side]["commit"] == SOURCES[side][0]
            and inventory(source) == record["production_sources"][side]["files"],
            "production source snapshot changed")
    sys.path.insert(0, str(source / "artifact"))
    import codeql_rust_plan as plan
    import codeql_rust_profile as profile
    import codeql_summary_projection as projection
    require(Path(plan.__file__).resolve() == source / "artifact/codeql_rust_plan.py"
            and projection.MANIFEST_SHA256 == SOURCES[side][1], "imported production source differs")
    environment = {**os.environ, "CODEQL_EXPECTED_COMMIT": SOURCES[side][0]}
    run = SimpleNamespace(root=source, output=evidence.parent, evidence=evidence,
                          environment=plan.controlled_environment(environment, evidence.parent / "tmp"))
    def command(label, argv, **kwargs):
        kwargs.setdefault("seconds", 180)
        return profile.ProfileRun.command(run, label, argv, **kwargs)
    run.command = command
    return run, plan, profile, record


def analyze(output, arm):
    side = arm[0]
    target = output / "comparison/runs" / arm
    target.mkdir(mode=0o700)
    (target / "evidence").mkdir()
    (target / "tmp").mkdir()
    run, plan, profile, sources = source_run(output, side, target / "evidence")
    import codeql_evaluator_logs as evaluator
    from codeql_process_resources import ProcessResourceSampler
    from bounded_process import TimeoutPolicy

    initial = read_json(gzip.decompress((output / "evidence/INITIAL_DATABASE_FILES.json.gz").read_bytes()))
    extracted = output / "database-extracted"
    require(inventory(extracted) == initial and not any(n.endswith(".bqrs") for n in initial),
            "shared extraction differs or contains query results")
    shutil.copytree(extracted, target / "database")
    require(inventory(target / "database") == initial, "fresh database copy differs")
    save(run.evidence / "INPUT.json", {"workflow_source_commit": workflow_identity(),
         "production_source_commit": SOURCES[side][0], "arm": arm,
         "database_inventory_sha256": canonical(initial), "source_inventory_sha256":
         sources["production_sources"][side]["inventory_sha256"]})
    run.configuration = SimpleNamespace(platform="linux", database=target / "database",
                                         ram_mb=14000, threads=4)
    downloads = read_json((output / "evidence/OFFICIAL_DOWNLOADS.json").read_bytes())
    archive = Path(downloads["codeql"]["path"])
    require(identity(archive) == {key: downloads["codeql"][key] for key in ("bytes", "sha256")},
            "authenticated official archive changed")
    context = plan.prepare(run, archive)
    before = inventory(context.pack)
    require(len(before) == 1357 and canonical(before) == SOURCES[side][2],
            "complete production pack inventory differs")
    query_bytes = (run.root / "artifact/codeql_rust_queries.json").read_bytes()
    require(query_bytes == (DIAGNOSTIC / "artifact/codeql_rust_queries.json").read_bytes(),
            "arms do not use the same frozen query manifest")
    queries = read_json(query_bytes)["queries"]
    require(len(queries) == 39 and not inventory(context.root / "cache"), "suite/cache differs")
    save(run.evidence / "PACK_BEFORE.json", before)
    with plan.guard(run, context):
        memory_args = profile.analysis_memory_arguments(run, "native")
        memory = read_json((run.evidence / "QUERY_MEMORY.json").read_bytes())
        profile.validate_linux_query_memory(memory, "native")
        require(not inventory(context.root / "cache"), "query cache is not fresh before analysis")
        command = plan.analysis_command(context, run.configuration.database, run.evidence,
                                        "native", memory_args)
        sampler = ProcessResourceSampler(run.evidence)
        sampler.start()
        try:
            run.command("analyze", command, seconds=600, timeout_policy=TimeoutPolicy.STANDARD,
                        progress_queries=queries)
        finally:
            save(run.evidence / "RESOURCE_OBSERVATION_STATUS.json", sampler.stop())
        observations = evaluator.observe(context.root, pattern="execute-queries-*.log",
                                         stdio_prefix=None, capture_invocation=True)
        observed = {key: observations[key] for key in plan.OBSERVATION_FIELDS}
        completion = evaluator.read_completion_receipt(run.evidence / "analyze.stderr", queries)
        save(run.evidence / "EVALUATOR_OBSERVATIONS.json", observed)
        save(run.evidence / "QUERY_COMPLETIONS.json", completion)
        plan.validate_observations(observed, context.pack, queries, memory["heap_mb"],
                                   completion=completion)
        results = run.configuration.database / "results/codeql/rust-queries"
        expected = {str(Path(q).with_suffix(".bqrs")) for q in queries}
        found = {p.relative_to(results).as_posix() for p in results.rglob("*.bqrs")}
        require(found == expected and len(list(run.configuration.database.rglob("*.bqrs"))) == 39,
                "fresh full-query result census differs")
        shutil.copytree(results, run.evidence / "results")
        save(run.evidence / "FRESH_RESULTS.json", inventory(run.evidence / "results"))
        profile.validate_sarif(read_json((run.evidence / "results.sarif").read_bytes()), "native")
        require(inventory(context.pack) == before and inventory(extracted) == initial,
                "production pack or shared extraction changed")
    require(context.after == context.before == plan.expected_identity(), "postcheck incomplete")
    require(inventory(run.root) == sources["production_sources"][side]["files"],
            "production source snapshot changed during analysis")
    save(run.evidence / "ANALYSIS_RESULT.json", {
        "arm": arm, "state": "analysis_complete_pending_semantic_comparison",
        "workflow_source_commit": workflow_identity(), "production_source_commit": SOURCES[side][0],
        "input_inventory_before_sha256": canonical(initial),
        "input_inventory_after_sha256": canonical(inventory(extracted)),
        "fresh_result_count": 39, "summary_plan": context.after, "query_memory": memory,
        "pack_and_runtime_postchecks_passed": True, "new_private_cache": True})


def compare(output):
    destination = output / "comparison/evidence"
    (destination / "decode").mkdir()
    (destination / "tmp").mkdir()
    run, plan, _, sources = source_run(output, "B", destination / "decode")
    import codeql_summary_control as control

    evidence = {"B1": output / "evidence", **{
        arm: output / "comparison/runs" / arm / "evidence" for arm in ORDER[1:]}}
    first = read_json((evidence["B1"] / "FIXTURE_WRAPPER_RESULT.json").read_bytes())
    require(first["production_source_commit"] == SOURCES["B"][0]
            and first["status"] == "complete_equal_summary_valid_sarif", "B1 fixture incomplete")
    timings = {arm: read_json((root / "analyze.json").read_bytes()) for arm, root in evidence.items()}
    for index, arm in enumerate(ORDER):
        require(timings[arm]["returncode"] == 0, "analysis did not complete")
        if index:
            require(timings[ORDER[index - 1]]["finished_at_utc"] <= timings[arm]["invoked_at_utc"],
                    "analyses overlapped or ran out of order")
    summary_started = read_json((evidence["B1"] / "decode-summary.started.json").read_bytes())
    require(timings["B4"]["finished_at_utc"] <= summary_started["invoked_at_utc"],
            "result decoding preceded completion of all measured analyses")
    initial = read_json(gzip.decompress((output / "evidence/INITIAL_DATABASE_FILES.json.gz").read_bytes()))
    require(inventory(output / "database-extracted") == initial, "shared input changed")
    queries = read_json((run.root / "artifact/codeql_rust_queries.json").read_bytes())["queries"]
    require(len(queries) == 39, "full query inventory differs")
    run.codeql = output / "analysis-plan/tool/codeql/codeql"
    memories = [read_json((root / "QUERY_MEMORY.json").read_bytes()) for root in evidence.values()]
    require(all(value == memories[0] for value in memories), "resolved allocation changed between arms")
    baseline = read_json(subprocess.check_output(["/usr/bin/git", "-C", str(DIAGNOSTIC), "show",
                        fixture.EVIDENCE_COMMIT + ":" + fixture.BASELINE_PATH]))
    require(canonical(baseline) == fixture.BASELINE_SEMANTIC, "frozen summary baseline differs")
    memo, results = {}, {}
    for arm, root in evidence.items():
        files = read_json((root / "FRESH_RESULTS.json").read_bytes())
        require(set(files) == {str(Path(q).with_suffix(".bqrs")) for q in queries},
                "retained result file census differs")
        require(files == inventory(root / "results"), "retained BQRS bytes changed")
        results[arm] = {}
        for query in sorted(queries):
            relative = str(Path(query).with_suffix(".bqrs"))
            data = files[relative]
            key = (query, data["bytes"], data["sha256"])
            decoded_by = None
            if key not in memo:
                if arm == "B1" and query == fixture.SUMMARY:
                    decoded = (root / "decode-summary.stdout").read_bytes()
                else:
                    decoded = run.command(arm + "-" + Path(query).stem, [
                        str(run.codeql), "bqrs", "decode", "--format=json", "-J-Xmx512M",
                        str(root / "results" / relative)], seconds=120)
                memo[key] = (control.result_semantic_sha(decoded), read_json(decoded), arm)
                decoded_by = arm
            semantic, decoded, original_arm = memo[key]
            if query == fixture.SUMMARY:
                require(decoded == baseline, "complete retained 29-row summary differs: " + arm)
            results[arm][query] = {**data, "semantic_sha256": semantic,
                "decoded_by_arm": original_arm, "decode_reused_identical_bytes": decoded_by is None}
        require(len(results[arm]) == 39, "incomplete semantic result census")
    require(all(results[arm][q]["semantic_sha256"] == results["B1"][q]["semantic_sha256"]
                for arm in ORDER[1:] for q in queries), "full 39-query semantics differ")
    for side in SOURCES:
        require(inventory(output / "comparison/sources" / side)
                == sources["production_sources"][side]["files"], "source snapshot changed")
    require(inventory(output / "database-extracted") == initial, "shared input changed during decode")
    require(plan.runtime_inventory(run.codeql.parent) == read_json(
        (evidence["B1"] / "ANALYSIS_RUNTIME.json").read_bytes())["files"],
        "decoder runtime changed")
    require(inventory(run.codeql.parent / plan.PACK_RELATIVE) == read_json(
        (evidence["B1"] / "PACK_BEFORE.json").read_bytes()), "decoder pack changed")
    save(destination / "RESULT.json", {
        "schema": 1, "kind": "qperiapt.same_runner_fixture_baab",
        "status": "four_analyses_complete_all_39_semantics_equal_retained_29_equal",
        "workflow_source_commit": workflow_identity(),
        "production_sources": {side: pin[0] for side, pin in SOURCES.items()},
        "order": list(ORDER), "query_count": 39, "query_memory": memories[0],
        "database_inventory_sha256": canonical(initial), "timings": timings, "results": results,
        "all_decoding_after_measured_analyses": True, "distinct_decoded_results": len(memo),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "comparison_scope": "One newly extracted nonempty fixture on one runner; two observations per source"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--worker", choices=ORDER[1:])
    mode.add_argument("--compare", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve(strict=True)
    require(output.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)),
            "comparison output is outside RUNNER_TEMP")
    try:
        analyze(output, args.worker) if args.worker else compare(output)
    except BaseException as error:
        name = args.worker or "compare"
        save(output / "comparison/evidence" / (name + "-FAILURE.json"),
             {"type": type(error).__name__, "message": str(error),
              "recorded_utc": datetime.now(timezone.utc).isoformat()})
        raise


if __name__ == "__main__":
    main()
