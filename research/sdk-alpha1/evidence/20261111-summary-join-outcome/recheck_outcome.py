#!/usr/bin/env python3
"""Read existing workflow archives; never execute CodeQL or change receipts."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import zipfile


def require(value, description):
    if not value:
        raise ValueError(description)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path(__file__).parent)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--baseline-ref", default="1b47a1931cab2a944902316619cdcf479bd64ab0")
    args = parser.parse_args()
    root = args.directory.resolve()
    sys.path.insert(0, str(root / "source"))
    import codeql_summary_control as control

    source_identity = json.loads((root / "SOURCE_IDENTITY.json").read_bytes())
    require(source_identity["commit"] == "e54c9d12223a72973b956acb15ff7b1597140e4f", "experiment source differs")
    for record in source_identity["files"].values():
        data = (root / "source" / PurePosixPath(record["path"]).name).read_bytes()
        require(len(data) == record["bytes"] and sha(data) == record["sha256"], "analysis source identity differs")

    def strict(data):
        return control.parse_strict_json_bytes(data, label="retained workflow artifact")

    output = {
        "schema": 1,
        "kind": "qperiapt.codeql_summary_join_outcome_readback",
        "workflow_run": 42956070561,
        "experiment_commit": source_identity["commit"],
        "baseline_run": 42822797947,
        "baseline_evidence_ref": args.baseline_ref,
        "method": "Local byte and decoded-semantics verification of existing archives; no CodeQL execution",
        "arms": {},
    }
    reports = {}
    expected_plan = control.summary_plan.expected_identity()
    manifest = strict((root / "source" / "codeql_rust_queries.json").read_bytes())
    retained_keys = ("source", "input_identity", "tool_identity", "query_hashes", "ram_resolution", "retained_results", "cache_scope")

    for identity in json.loads((root / "ARTIFACT_IDENTITIES.json").read_bytes()):
        arm, artifact = identity["arm"], root / (str(identity["id"]) + ".zip")
        archive_bytes = artifact.read_bytes()
        require(len(archive_bytes) == identity["bytes"] and sha(archive_bytes) == identity["sha256"], "archive identity differs")
        with zipfile.ZipFile(artifact) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), "duplicate archive member")
            for name in names:
                path = PurePosixPath(name)
                require(not path.is_absolute() and ".." not in path.parts and "\\" not in name, "noncanonical archive member")
            report = strict(archive.read("RESULT.json"))
            reports[arm] = report
            query = strict(archive.read("query.json"))
            partial = strict(archive.read("PARTIAL_RESULTS.json"))
            observations = strict(archive.read("EVALUATOR_OBSERVATIONS.json"))
            require(query == report["evaluation"], "query receipt differs")
            require(report["completed"] is False and query["stopped"] == "timeout" and query["returncode"] is None and query["cleanup_ambiguous"] is False, "original evaluator outcome differs")
            require(partial == report["partial_results"], "partial receipt differs")
            require(observations == report["observations"], "observation receipt differs")
            require(strict(archive.read("PROCESS_RESOURCES.json")) == query["resource_observation"], "resource receipt differs")
            require(report["summary_plan"] == report["summary_plan_after"] == expected_plan, "fixed plan identity differs")
            require(strict(archive.read("SUMMARY_PLAN.json")) == expected_plan, "plan receipt differs")
            require(strict(archive.read("SUMMARY_PLAN_AFTER.json")) == expected_plan, "post-plan receipt differs")
            require(report["profile"] == arm and report["configuration"] == control.configuration(arm), "arm configuration differs")
            require(report["experiment_commit"] == source_identity["commit"], "experiment commit differs")
            require(report["source"] == control.SOURCE and report["input_identity"] == control.INPUT_IDENTITY, "retained input pins differ")
            require(report["cache_scope"] == control.CACHE_SCOPE, "cache scope differs")
            control.validate_query_inventory(report["query_hashes"], manifest)
            require(control.canonical_sha(report["compiled_query_hashes"]) == control.summary_plan.COMPILED_INVENTORY_SHA256, "compiled inventory differs")
            control.validate_observations(observations, arm)
            control.validate_candidate_loads(observations, Path(report["query_command"][0]), report["query_hashes"])
            require(query["command"] == report["query_command"], "evaluator command differs")
            result_root = Path(next(x.removeprefix("--output=") for x in query["command"] if x.startswith("--output="))).parent
            require(query["command"] == control.query_command(Path(query["command"][0]), result_root / "database", result_root, arm, "all"), "full command differs")

            baseline_path = "research/sdk-alpha1/evidence/20261111-codeql-summary-resources/" + arm + "/RESULT.json"
            baseline_data = subprocess.check_output(["git", "show", args.baseline_ref + ":" + baseline_path], cwd=args.repository)
            baseline = strict(baseline_data)
            same_keys = {key: report[key] == baseline[key] for key in retained_keys}
            require(all(same_keys.values()), "historical input identity differs")
            changed_plans = sorted(key for key in report["compiled_query_hashes"] if report["compiled_query_hashes"][key] != baseline["compiled_query_hashes"][key])
            require(changed_plans == [control.FULL_SUMMARY], "other compiled query changed")
            require(report["configuration"] == baseline["configuration"], "historical configuration differs")

            rechecked = {}
            for relative, record in partial["results"].items():
                stem = PurePosixPath(relative).stem
                expected_bqrs = "partial-fresh-bqrs/" + PurePosixPath(relative).with_suffix(".bqrs").as_posix()
                require(record["path"] == expected_bqrs, "fresh result path differs")
                fresh_bqrs = archive.read(expected_bqrs)
                old_bqrs = archive.read("retained-bqrs/" + PurePosixPath(relative).with_suffix(".bqrs").as_posix())
                fresh_decoded = archive.read("partial-fresh-" + stem + "-decoded.stdout")
                old_decoded = archive.read("retained-" + stem + "-decoded.stdout")
                fresh_semantic = control.result_semantic_sha(fresh_decoded)
                old_semantic = control.result_semantic_sha(old_decoded)
                for prefix in ("partial-fresh-", "retained-"):
                    require(strict(archive.read(prefix + stem + "-decoded.json"))["returncode"] == 0, "original decoder failed")
                require(sha(fresh_bqrs) == record["bqrs_sha256"] and len(fresh_bqrs) == record["bytes"], "fresh BQRS bytes differ")
                require(sha(old_bqrs) == report["retained_results"][relative]["bqrs_sha256"], "retained BQRS bytes differ")
                require(fresh_semantic == old_semantic == record["semantic_sha256"] == report["retained_results"][relative]["semantic_sha256"], "decoded semantics differ")
                require(fresh_semantic == baseline["partial_results"]["results"][relative]["semantic_sha256"], "historical fresh semantics differ")
                rechecked[relative] = {
                    "fresh_bqrs_sha256": sha(fresh_bqrs),
                    "retained_bqrs_sha256": sha(old_bqrs),
                    "fresh_decoded_sha256": sha(fresh_decoded),
                    "retained_decoded_sha256": sha(old_decoded),
                    "semantic_sha256": fresh_semantic,
                }
            expected_queries = set(report["query_hashes"]) - {control.FULL_SUMMARY}
            require(set(rechecked) == expected_queries and len(rechecked) == 38, "partial result census differs")
            observed_fresh_bqrs = {name for name in names if name.startswith("partial-fresh-bqrs/") and name.endswith(".bqrs")}
            expected_fresh_bqrs = {"partial-fresh-bqrs/" + PurePosixPath(relative).with_suffix(".bqrs").as_posix() for relative in expected_queries}
            require(observed_fresh_bqrs == expected_fresh_bqrs, "archived fresh BQRS census differs")
            require(partial["missing_queries"] == [control.FULL_SUMMARY] and partial["uncaptured_queries"] == [control.FULL_SUMMARY], "missing result differs")

            verified_logs = []
            for record in observations["logs"]:
                digest, size = hashlib.sha256(), 0
                with archive.open(record["path"]) as source:
                    while block := source.read(1024 * 1024):
                        digest.update(block)
                        size += len(block)
                require(digest.hexdigest() == record["sha256"] and size == record["bytes"], "evaluator log identity differs")
                verified_logs.append(record)
            output["arms"][arm] = {
                "artifact": identity,
                "result_receipt_sha256": sha(archive.read("RESULT.json")),
                "baseline_result_receipt_sha256": sha(baseline_data),
                "completed": report["completed"],
                "failure": report["failure"],
                "evaluation": {key: query.get(key) for key in ("returncode", "stopped", "cleanup_ambiguous", "seconds")},
                "partial": {key: value for key, value in partial.items() if key != "results"},
                "plan_identity_verified_before_and_after": True,
                "plan_capsule_sha256": expected_plan["capsule_sha256"],
                "actual_precompiled_loads": len(observations["precompiled_query_loads"]),
                "actual_implicit_compilations": observations["query_compilations"],
                "historical_equal_fields": same_keys,
                "historical_changed_compiled_queries": changed_plans,
                "verified_evaluator_logs": verified_logs,
                "recomputed_results": rechecked,
            }

    first, second = reports["heap-2048"], reports["heap-1536"]
    paired_keys = retained_keys + ("compiled_query_hashes", "experiment_commit", "summary_plan", "summary_plan_after")
    output["paired_identity_equal_fields"] = {key: first[key] == second[key] for key in paired_keys}
    require(all(output["paired_identity_equal_fields"].values()), "paired identity differs")
    semantic_sets = [{query: record["semantic_sha256"] for query, record in output["arms"][arm]["recomputed_results"].items()} for arm in ("heap-2048", "heap-1536")]
    output["all_38_recomputed_fresh_semantics_equal_across_arms"] = semantic_sets[0] == semantic_sets[1]
    require(output["all_38_recomputed_fresh_semantics_equal_across_arms"], "cross-arm semantics differ")
    output["full_39_query_completion"] = False
    output["status"] = "verified_two_supervised_timeouts_with_38_equivalent_fresh_results"
    (root / "SEMANTICS_RECHECK.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": output["status"], "arms": {arm: {"evaluation": value["evaluation"], "verified_fresh_results": len(value["recomputed_results"]), "precompiled_loads": value["actual_precompiled_loads"], "implicit_compilations": value["actual_implicit_compilations"]} for arm, value in output["arms"].items()}}, indent=2))


if __name__ == "__main__":
    main()
