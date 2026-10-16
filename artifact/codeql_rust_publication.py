"""Accept every target profile and its complete suite before SARIF publication."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re

import codeql_rust_quality as quality
from codeql_rust_profile import COMPILER, QUERY_VERSION, ROOT, TARGETS, VERSION, profile_host, validate_sarif
from codeql_target_coverage import MacroProfile, parse_macro_calls, validate_active_macro_coverage, validate_macro_profiles
from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk


def read_json(path: Path, *, maximum=16 * 1024**2):
    return parse_strict_json_bytes(sdk.snapshot(path, maximum=maximum).data, label=path.name)


def read_rows(path: Path):
    rows = read_json(path)
    sdk.require(isinstance(rows, list) and all(isinstance(row, list) for row in rows), "invalid quality result rows")
    return rows


def latest_profile_directories(parent: Path, attempt: int) -> dict[str, Path]:
    selected = {}
    entries = list(parent.iterdir())
    sdk.require(len(entries) <= 100, "too many profile artifacts")
    for path in entries:
        match = re.fullmatch(r"codeql-rust-profile-(native|wasm|macos)-([1-9][0-9]*)", path.name)
        sdk.require(match is not None and path.is_dir() and not path.is_symlink(), "unexpected profile artifact")
        name, generation = match[1], int(match[2])
        sdk.require(generation <= attempt, "profile artifact is from a future run attempt")
        if name not in selected or generation > selected[name][0]:
            selected[name] = (generation, path)
    sdk.require(set(selected) == set(TARGETS), "Linux, WASM and macOS artifacts are all required")
    # A failed newer artifact is never replaced by an older successful result.
    return {name: item[1] for name, item in selected.items()}


def validate_profile_artifact(directory: Path, name: str, root: Path,
                              expected_commit: str, run_id: str, attempt: int) -> MacroProfile:
    profile = read_json(directory / "PROFILE.json")
    analysis = read_json(directory / "ANALYSIS.json")
    sdk.require(isinstance(profile, dict) and isinstance(analysis, dict), "invalid profile result")
    sdk.require(profile.get("schema") == 1 and profile.get("profile") == name
                and profile.get("target") == TARGETS[name]
                and profile.get("source_commit") == expected_commit
                and profile.get("run_id") == run_id, "profile source or workflow identity differs")
    generation = profile.get("run_attempt")
    sdk.require(isinstance(generation, str) and re.fullmatch(r"[1-9][0-9]*", generation) is not None
                and int(generation) <= attempt and directory.name == f"codeql-rust-profile-{name}-{generation}",
                "profile attempt identity differs")
    sdk.require(profile.get("codeql_version") == analysis.get("codeql_version") == VERSION
                and profile.get("compiler") == COMPILER and analysis.get("query_pack") == QUERY_VERSION,
                "analysis toolchain identity differs")
    configuration = quality.hosted_configuration(profile_host(name))
    sdk.require(profile.get("compiler_host") == configuration.compiler_host
                and type(profile.get("query_threads")) is int and profile["query_threads"] == configuration.threads
                and type(profile.get("query_ram_mb")) is int and profile["query_ram_mb"] == configuration.ram_mb,
                "analysis host or resource budget differs")
    sdk.require(profile.get("active_target_quality_passed") is True
                and profile.get("paired_target_quality_passed") is False
                and analysis.get("completed") is True and analysis.get("upload_performed") is False,
                "analysis did not complete before publication")
    sdk.require(analysis.get("profile_sha256") == sdk.snapshot(directory / "PROFILE.json").sha256,
                "analysis is not bound to this profile")
    source = {path: sdk.snapshot(root / path, maximum=5 * 1024**2).sha256
              for path in sorted(quality.tracked_rust_paths(root))}
    sdk.require(profile.get("source_sha256") == source, "profile Rust source bytes differ")
    compiled = profile.get("compiled_sources")
    sdk.require(isinstance(compiled, dict) and compiled and set(compiled) <= source.keys()
                and all(source[path] == digest for path, digest in compiled.items()),
                "compiler source identity differs")
    expected_queries = {path.name: sdk.snapshot(path).sha256
                        for path in sorted((root / "artifact/codeql-rust-quality").glob("*.ql"))}
    sdk.require(profile.get("quality_queries_sha256") == expected_queries
                and profile.get("quality_pack_sha256") == sdk.snapshot(root / "artifact/codeql-rust-quality/qlpack.yml").sha256
                and profile.get("quality_lock_sha256") == sdk.snapshot(root / "artifact/codeql-rust-quality/codeql-pack.lock.yml").sha256,
                "profile quality query bytes differ")
    for name_key, filename in (("macro_census_sha256", "MacroCalls.json"),
                               ("extracted_paths_sha256", "ExtractedPaths.json")):
        sdk.require(profile.get(name_key) == sdk.snapshot(directory / filename).sha256, "quality result bytes differ")
    metric_rows = read_rows(directory / "Metrics.json")
    metrics = quality._parse_metrics(metric_rows)
    sdk.require(profile.get("metrics") == metrics, "profile metrics differ")
    paths = quality._parse_extracted_paths(read_rows(directory / "ExtractedPaths.json"))
    quality.validate_extraction_quality(frozenset(source), paths, metrics)
    inventory = read_json(directory / "QUERY_INVENTORY.json")
    pinned = read_json(root / "artifact/codeql_rust_queries.json")
    sdk.require(pinned == {"codeql_version": VERSION, "query_pack": QUERY_VERSION, "queries": inventory}
                and analysis.get("query_inventory_sha256") == sdk.snapshot(directory / "QUERY_INVENTORY.json").sha256,
                "full security query inventory differs")
    results = analysis.get("query_result_sha256")
    sdk.require(isinstance(results, dict) and set(results) == set(inventory)
                and all(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                        for digest in results.values()), "full query result census is incomplete")
    sdk.require(analysis.get("sarif_sha256") == sdk.snapshot(directory / "results.sarif", maximum=64 * 1024**2).sha256,
                "SARIF differs from the completed analysis")
    validate_sarif(read_json(directory / "results.sarif", maximum=64 * 1024**2), name)
    result = MacroProfile(TARGETS[name], source, frozenset(compiled),
                          parse_macro_calls(read_rows(directory / "MacroCalls.json")),
                          metrics["source_macro_calls"], metrics["unresolved_source_macro_calls"])
    validate_active_macro_coverage(result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    expected = os.environ.get("CODEQL_EXPECTED_COMMIT", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    sdk.require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None
                and re.fullmatch(r"[1-9][0-9]*", attempt) is not None, "missing workflow identity")
    quality.require_clean_checkout(expected)
    quality.require_repository_target_absent()
    directories = latest_profile_directories(args.inputs.resolve(strict=True), int(attempt))
    profiles = [validate_profile_artifact(directories[name], name, ROOT, expected, run_id, int(attempt))
                for name in TARGETS]
    result = validate_macro_profiles(profiles)
    args.output.mkdir()
    for name, directory in directories.items():
        with (args.output / (name + ".sarif")).open("xb") as output:
            output.write(sdk.snapshot(directory / "results.sarif", maximum=64 * 1024**2).data)
    sdk.write_json(args.output / "PAIRED_QUALITY.json", {
        "completed": True, "source_commit": expected, "run_id": run_id,
        "profile_inputs": {name: {"directory": directory.name,
                                  "profile_sha256": sdk.snapshot(directory / "PROFILE.json").sha256,
                                  "analysis_sha256": sdk.snapshot(directory / "ANALYSIS.json").sha256}
                           for name, directory in directories.items()}, "macro_coverage": result,
    })
    quality.require_clean_checkout(expected)
    print("CODEQL_RUST_PAIRED_QUALITY_PASS", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        raise SystemExit("error: Rust analysis publication: " + str(exc)) from exc
