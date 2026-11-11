"""Verify retained artifact bytes and decoded semantics without running CodeQL."""

import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import zipfile


SOURCE = "4fb3b2db1d6647ec4fa85fb8bd744b1d97ef1215"
ARTIFACTS = {
    "heap-2048": (13872915159, 31837325, "e5ea00d64244f9083f3f1665ac847cd7bf24513849b7a4fa757fdbbbbb3cbfa5"),
    "heap-1536": (13872940192, 32645123, "586844529bcbd623c3bdfb84a69992f5e30d157e88616107ee209b620642feba"),
}
FULL_SUMMARY = "queries/summary/SummaryStats.ql"
COMPLETION = re.compile(
    r"^\[(\d+)/39 eval [^\]]+\] Evaluation done; writing results to "
    r"codeql/rust-queries/(queries/[^\r\n]+)\.bqrs\.$"
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def functions(source, names):
    tree = ast.parse(source)
    selected = {
        node.name: ast.dump(node, include_attributes=False)
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    }
    assert set(selected) == set(names)
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    # Reuse the existing pure semantic normalizer. Its relevant functions and
    # strict JSON parser must match the actual experiment revision's source.
    verified_functions = {}
    for relative, names in (
        ("artifact/codeql_summary_control.py", ["require", "canonical_sha", "result_semantic_sha"]),
        ("artifact/evidence_io.py", ["parse_strict_json_bytes"]),
    ):
        pinned = subprocess.check_output(
            ["git", "show", SOURCE + ":" + relative], cwd=args.source_root, timeout=30
        )
        current = (args.source_root / relative).read_bytes()
        before, after = functions(pinned, names), functions(current, names)
        assert before == after, relative
        verified_functions[relative] = {
            "pinned_source_sha256": digest(pinned),
            "function_ast_sha256": {name: digest(value.encode()) for name, value in before.items()},
        }
    sys.path.insert(0, str(args.source_root / "artifact"))
    import codeql_summary_control as control

    outcomes = []
    semantic_maps = {}
    for profile, (artifact_id, expected_bytes, expected_digest) in ARTIFACTS.items():
        archive_path = args.artifact_root / profile / "evidence.zip"
        with archive_path.open("rb") as stream:
            archive_digest = hashlib.file_digest(stream, "sha256").hexdigest()
        assert archive_path.stat().st_size == expected_bytes
        assert archive_digest == expected_digest
        with zipfile.ZipFile(archive_path) as archive:
            result = json.loads(archive.read("RESULT.json"))
            partial = json.loads(archive.read("PARTIAL_RESULTS.json"))
            resources = json.loads(archive.read("PROCESS_RESOURCES.json"))
            assert result["experiment_commit"] == SOURCE
            expected = set(result["query_hashes"]) - {FULL_SUMMARY}
            assert len(result["query_hashes"]) == 39 and len(expected) == 38
            assert set(partial["results"]) == expected == set(result["retained_results"])

            fresh_paths = {
                "partial-fresh-bqrs/" + query[:-3] + ".bqrs" for query in expected
            }
            retained_paths = {
                "retained-bqrs/" + query[:-3] + ".bqrs" for query in expected
            }
            actual_bqrs = {name for name in archive.namelist() if name.endswith(".bqrs")}
            assert actual_bqrs == fresh_paths | retained_paths

            query_records = []
            semantic_maps[profile] = {}
            for query in sorted(expected):
                declared = partial["results"][query]
                retained = result["retained_results"][query]
                fresh_path = "partial-fresh-bqrs/" + query[:-3] + ".bqrs"
                retained_path = "retained-bqrs/" + query[:-3] + ".bqrs"
                assert declared["path"] == fresh_path
                fresh_bytes, retained_bytes = archive.read(fresh_path), archive.read(retained_path)
                assert len(fresh_bytes) == declared["bytes"]
                fresh_hash, retained_hash = digest(fresh_bytes), digest(retained_bytes)
                assert fresh_hash == declared["bqrs_sha256"]
                assert retained_hash == retained["bqrs_sha256"]

                stem = PurePosixPath(query).stem
                fresh_decoded_path = "partial-fresh-" + stem + "-decoded.stdout"
                retained_decoded_path = "retained-" + stem + "-decoded.stdout"
                fresh_decoded = archive.read(fresh_decoded_path)
                retained_decoded = archive.read(retained_decoded_path)
                fresh_semantic = control.result_semantic_sha(fresh_decoded)
                retained_semantic = control.result_semantic_sha(retained_decoded)
                assert fresh_semantic == declared["semantic_sha256"]
                assert retained_semantic == retained["semantic_sha256"] == fresh_semantic
                assert declared["decode_status"] == "decoded"
                assert declared["retained_semantics_equal"] is True
                semantic_maps[profile][query] = fresh_semantic
                query_records.append({
                    "query": query,
                    "fresh_bqrs": {"path": fresh_path, "bytes": len(fresh_bytes), "sha256": fresh_hash},
                    "retained_bqrs": {"path": retained_path, "bytes": len(retained_bytes), "sha256": retained_hash},
                    "fresh_decoded": {"path": fresh_decoded_path, "bytes": len(fresh_decoded), "sha256": digest(fresh_decoded)},
                    "retained_decoded": {"path": retained_decoded_path, "bytes": len(retained_decoded), "sha256": digest(retained_decoded)},
                    "semantic_sha256": fresh_semantic,
                    "semantics_equal": True,
                    "fresh_table_rows": {k: len(v["tuples"]) for k, v in json.loads(fresh_decoded).items()},
                })

            stderr = archive.read("query.stderr")
            completions = []
            for line in stderr.decode().splitlines():
                match = COMPLETION.fullmatch(line)
                if match:
                    completions.append((int(match[1]), match[2] + ".ql"))
            assert len(completions) == 38
            assert {query for _, query in completions} == expected
            assert {number for number, _ in completions} == set(range(1, 39))

            sample_hash = hashlib.sha256()
            sample_bytes = sample_count = samples_with_processes = peak_tree = peak_roots = 0
            peak_line = first_line = last_line = b""
            with archive.open("PROCESS_RESOURCES.jsonl") as stream:
                for line in stream:
                    sample_hash.update(line)
                    sample_bytes += len(line)
                    sample_count += 1
                    item = json.loads(line)
                    if sample_count == 1:
                        first_line = line
                    last_line = line
                    samples_with_processes += bool(item["processes"])
                    if item["tree_rss_bytes"] > peak_tree:
                        peak_tree, peak_line = item["tree_rss_bytes"], line
                    peak_roots = max(peak_roots, item["roots_rss_bytes"])
            assert sample_bytes == resources["output_bytes"]
            assert sample_count == resources["samples"]
            assert samples_with_processes == resources["samples_with_processes"]
            assert peak_tree == resources["peak_sampled_tree_rss_bytes"]
            assert peak_roots == resources["peak_sampled_roots_rss_bytes"]
            sample_out = args.output / profile
            sample_out.mkdir(exist_ok=True)
            sample_out.joinpath("RESOURCE_SELECTED_SAMPLES.jsonl").write_bytes(first_line + peak_line + last_line)

            outcomes.append({
                "profile": profile,
                "artifact_id": artifact_id,
                "archive_bytes": expected_bytes,
                "archive_sha256": archive_digest,
                "archive_member_count": len(archive.infolist()),
                "fresh_bqrs_count": len(fresh_paths),
                "retained_bqrs_count": len(retained_paths),
                "all_bqrs_hashes_and_sizes_match_receipts": True,
                "semantic_equal_count": len(query_records),
                "binary_equal_count": sum(q["fresh_bqrs"]["sha256"] == q["retained_bqrs"]["sha256"] for q in query_records),
                "missing_query": FULL_SUMMARY,
                "completion_stderr": {"bytes": len(stderr), "sha256": digest(stderr), "distinct_queries": len(completions), "queries": sorted(expected)},
                "resource_samples": {"member": "PROCESS_RESOURCES.jsonl", "bytes": sample_bytes, "sha256": sample_hash.hexdigest(), "count": sample_count, "samples_with_processes": samples_with_processes, "peak_tree_rss_bytes": peak_tree, "peak_roots_rss_bytes": peak_roots, "selected_rows": ["first", "first maximum tree RSS", "last"]},
                "queries": query_records,
            })

    assert semantic_maps["heap-2048"] == semantic_maps["heap-1536"]
    report = {
        "schema": 1,
        "experiment_commit": SOURCE,
        "verification_scope": "Existing BQRS bytes and retained CodeQL-decoded JSON were read from the verified archives. No CodeQL, JVM, database extraction, query execution, or new BQRS decoding was run.",
        "normalizer_source_verification": verified_functions,
        "both_profiles_fresh_38_semantics_equal": True,
        "profiles": outcomes,
    }
    args.output.joinpath("READBACK_VERIFICATION.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"profiles": [{k: v for k, v in row.items() if k not in {"queries", "completion_stderr"}} for row in outcomes], "paired_fresh_38_semantics_equal": True}))


if __name__ == "__main__":
    main()
