"""Compile, extract and analyze one Rust target; upload requires paired validation."""
from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import time

from bounded_process import BoundedProcessError, TimeoutPolicy, capture_output
import codeql_consumer_context as consumers
from codeql_compiler_sources import collect_compiled_sources
import codeql_rust_quality as quality
from codeql_target_coverage import MacroProfile, parse_macro_calls, validate_active_macro_coverage
from evidence_io import parse_strict_json_bytes
from git_provenance import run_git_bytes
import rust_sdk_profile as sdk

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {"native": "x86_64-unknown-linux-gnu", "wasm": "wasm32-unknown-unknown",
           "macos": "aarch64-apple-darwin"}
VERSION = "2.27.2"
QUERY_VERSION = "0.1.44"
COMPILER = "1.98.1"
WORKSPACE_LOCKFILES = (
    "Cargo.lock",
    "fuzz/Cargo.lock",
    "research/continuity-identity-candidate/Cargo.lock",
    "research/continuity-openssl-peer/native/Cargo.lock",
    "research/continuity-reference-app/Cargo.lock",
    "research/continuity-spqr-reference/Cargo.lock",
    "research/continuity-whole-kem-reference/Cargo.lock",
    "research/hqc-fips207-candidate/Cargo.lock",
)


def profile_host(profile: str) -> str:
    sdk.require(profile in TARGETS, "unknown Rust analysis profile")
    return "darwin" if profile == "macos" else "linux"


class ProfileRun:
    def __init__(self, root: Path, output: Path, codeql: Path, environment: dict[str, str], *, resume=False, host="linux"):
        self.root, self.output, self.codeql, self.environment = root, output, codeql, environment
        self.configuration = quality.hosted_configuration(host)
        self.evidence = output / "evidence"
        if resume:
            sdk.require(self.evidence.is_dir(), "analysis evidence directory is missing")
        else:
            self.evidence.mkdir(parents=True)

    def command(self, label: str, argv: list[str], *, cwd: Path | None = None, seconds=900,
                timeout_policy: TimeoutPolicy = TimeoutPolicy.STANDARD):
        started = time.monotonic()
        record = {"argv": argv, "cwd": str(cwd or self.root), "maximum_seconds": seconds}
        try:
            with contextlib.chdir(cwd or self.root):
                result = capture_output(argv, timeout_seconds=seconds, maximum_stdout_bytes=32 * 1024**2,
                                        maximum_stderr_bytes=16 * 1024**2, environment=self.environment,
                                        timeout_policy=timeout_policy)
        except BoundedProcessError as exc:
            sdk.write_json(self.evidence / (label + ".json"), {
                **record, "completed": False, "boundary": exc.kind, "reason": str(exc),
                "cleanup_ambiguous": exc.cleanup_ambiguous, "elapsed_seconds": time.monotonic() - started,
            })
            raise
        for stream in ("stdout", "stderr"):
            with (self.evidence / (label + "." + stream)).open("xb") as destination:
                destination.write(getattr(result, stream))
        sdk.write_json(self.evidence / (label + ".json"), {
            **record, "returncode": result.returncode, "elapsed_seconds": time.monotonic() - started,
        })
        sdk.require(result.returncode == 0, "command failed: " + label)
        sdk.require(re.search(rb"(?im)^\s*(?:warning|error|fatal)\b", result.stderr) is None,
                    "command emitted diagnostics: " + label)
        sdk.require(re.search(rb"(?m)^.*\[build-(?:stdout|stderr)\]\s+(?:WARN|ERROR)\b",
                              result.stdout + result.stderr) is None, "extractor diagnostics: " + label)
        print(label + " complete", flush=True)
        return result.stdout


def compiler_commands(root: Path, profile: str):
    sdk.require(profile in TARGETS, "unknown Rust analysis profile")
    if profile == "wasm":
        return [
            ("browser", root, ["-p", "q-periapt-sdk-wasm", "--features", "browser-continuity"]),
            ("wasm-tests", root, ["-p", "q-periapt-wasm", "--tests", "--all-features"]),
        ]
    return [
        ("workspace", root, ["--workspace", "--all-targets", "--features",
                              "q-periapt-sdk/sealed-operations,q-periapt-cli/policy-store-migration"]),
        ("engine", root / consumers.CANDIDATE, ["--all-targets", "--all-features"]),
        ("independent-peer", root / "research/continuity-openssl-peer/native", ["--all-targets", "--all-features"]),
        ("reference-account", root / "research/continuity-reference-app", ["--all-targets", "--all-features"]),
        ("spqr", root / "research/continuity-spqr-reference", ["--all-targets"]),
        ("whole-kem", root / "research/continuity-whole-kem-reference", ["--all-targets"]),
        *[(label, root / path, ["--all-targets", "--all-features"])
          for label, path in consumers.CONSUMERS.items()],
    ]


def tracked_lockfiles(root: Path) -> tuple[str, ...]:
    locks = tuple(run_git_bytes(root, ["ls-files", "--", "*Cargo.lock"]).decode().splitlines())
    sdk.require(locks == WORKSPACE_LOCKFILES, "tracked workspace lock inventory differs")
    return locks


def validate_sarif(data: object, profile: str) -> None:
    sdk.require(isinstance(data, dict) and data.get("version") == "2.1.0", "invalid Rust SARIF version")
    runs = data.get("runs")
    sdk.require(isinstance(runs, list) and len(runs) == 1 and isinstance(runs[0], dict), "unexpected Rust SARIF run set")
    run = runs[0]
    sdk.require(run.get("automationDetails") == {"id": "/language:rust/target:" + profile + "/"},
                "SARIF belongs to a different target")
    tool = run.get("tool")
    sdk.require(isinstance(tool, dict) and isinstance(tool.get("driver"), dict), "missing SARIF tool")
    driver = tool["driver"]
    sdk.require(driver.get("name") == "CodeQL" and driver.get("semanticVersion") == VERSION,
                "SARIF tool identity differs")
    invocations = run.get("invocations")
    sdk.require(isinstance(invocations, list) and invocations
                and all(isinstance(item, dict) and item.get("executionSuccessful") is True for item in invocations),
                "SARIF reports an unsuccessful or missing invocation")
    for invocation in invocations:
        notifications = invocation.get("toolExecutionNotifications", [])
        sdk.require(isinstance(notifications, list) and all(isinstance(item, dict)
                    and item.get("level") in ("none", "note") for item in notifications),
                    "SARIF reports a tool warning or error")


def install_metadata_adapter(run: ProfileRun, sysroot: Path, host: str) -> None:
    cargo_home = Path(run.environment["CARGO_HOME"])
    binary_directory = cargo_home / "bin"
    binary_directory.mkdir(parents=True)
    settings = run.output / "cargo-settings.json"
    sdk.write_json(settings, {"cargo": str(sysroot / "bin/cargo"), "host": host,
                             "roots": [str(run.root), str(sysroot)],
                             "audit": str(run.evidence / "cargo-metadata.jsonl")})
    command = [sys.executable, "-I", "-S", "-B", str(run.root / "artifact/python_bootstrap.py"),
               str(run.root / "artifact/codeql_cargo_metadata.py"), str(settings)]
    launcher = binary_directory / "cargo"
    with launcher.open("x") as output:
        output.write("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
    launcher.chmod(0o700)


@contextlib.contextmanager
def prepared_consumers(run: ProfileRun):
    """Keep temporary inputs through extraction and remove them even on failure."""
    context = run.output / "consumers"
    consumers.prepare(run.root, context, [COMPILER], environment=run.environment)
    try:
        yield
    finally:
        run.command("remove-consumers", [sys.executable, "-I", "-S", "-B", str(run.root / "artifact/python_bootstrap.py"),
                                        str(run.root / "artifact/codeql_consumer_context.py"), "remove", "--output", str(context)])


def collect_quality(run: ProfileRun, compiled: dict[str, str], source: dict[str, str], profile: str):
    bindings = quality._open_fixed_codeql_bindings(host=run.configuration.platform)
    rows = {}
    try:
        for name in ("ExtractedPaths", "Metrics", "MacroCalls"):
            query = run.root / "artifact/codeql-rust-quality" / (name + ".ql")
            bqrs = run.output / (name + ".bqrs")
            quality._run_query(bindings, query, bqrs)
            rows[name] = quality._decode_query(bindings, bqrs)
            sdk.write_json(run.evidence / (name + ".json"), rows[name])
    finally:
        quality._close_fixed_codeql_bindings(bindings)
    paths = quality._parse_extracted_paths(rows["ExtractedPaths"])
    metrics = quality._parse_metrics(rows["Metrics"])
    quality.validate_extraction_quality(frozenset(source), paths, metrics)
    macro_profile = MacroProfile(TARGETS[profile], source, frozenset(compiled),
                                 parse_macro_calls(rows["MacroCalls"]), metrics["source_macro_calls"],
                                 metrics["unresolved_source_macro_calls"])
    validate_active_macro_coverage(macro_profile)
    return metrics


def extract_database(run: ProfileRun, database: Path) -> None:
    # setup-codeql installs the CLI but does not create init's database parent.
    # Require a fresh owned parent; existing analysis state must not be reused.
    database.parent.mkdir(mode=0o700)
    run.command("extract", [str(run.codeql), "database", "create", str(database),
                            "--language=rust", "--build-mode=none", "--source-root=" + str(run.root),
                            f"--threads={run.configuration.threads}", f"--ram={run.configuration.ram_mb}",
                            "--common-caches=" + str(run.output / "cache")])


def prepare(run: ProfileRun, profile: str, expected_commit: str) -> None:
    quality.require_repository_target_absent()
    quality.require_clean_checkout(expected_commit)
    source = {path: sdk.snapshot(run.root / path, maximum=5 * 1024**2).sha256
              for path in sorted(quality.tracked_rust_paths())}
    version = run.command("codeql-version", [str(run.codeql), "version", "--format=terse"]).decode().strip()
    sdk.require(version == VERSION, "unexpected CodeQL version")
    compiler = run.command("rust-version", ["rustc", "+" + COMPILER, "-vV"]).decode()
    sdk.require(compiler.startswith("rustc 1.98.1 (48a229cea 2026-09-01)\n")
                and f"host: {run.configuration.compiler_host}\n" in compiler, "unexpected analysis compiler or host")
    sysroot = Path(run.command("rust-sysroot", ["rustc", "+" + COMPILER, "--print", "sysroot"]).decode().strip()).resolve(strict=True)
    library = sysroot / "lib/rustlib/src/rust/library"
    sdk.require(library.is_dir(), "analysis compiler source is missing")
    run.environment.update(CODEQL_EXTRACTOR_RUST_OPTION_SYSROOT=str(sysroot),
                           CODEQL_EXTRACTOR_RUST_OPTION_SYSROOT_SRC=str(library),
                           CODEQL_EXTRACTOR_RUST_OPTION_CARGO_TARGET=TARGETS[profile])
    if profile == "wasm":
        clang = shutil.which("clang")
        sdk.require(clang is not None, "WASM analysis requires clang")
        targets = run.command("clang-targets", [clang, "--print-targets"])
        sdk.require(b"wasm32" in targets, "clang does not support the WASM target")
        run.environment["CC_wasm32_unknown_unknown"] = clang
    install_metadata_adapter(run, sysroot, run.configuration.compiler_host)
    locks = tracked_lockfiles(run.root)
    lock_hashes = {path: sdk.snapshot(run.root / path).sha256 for path in locks}
    for index, lock in enumerate(locks):
        manifest = (run.root / lock).with_name("Cargo.toml")
        run.command("fetch-" + str(index), ["cargo", "+" + COMPILER, "fetch", "--manifest-path", str(manifest), "--locked"])
    run.environment["CARGO_NET_OFFLINE"] = "true"
    compiled = {}
    with prepared_consumers(run):
        for label, cwd, options in compiler_commands(run.root, profile):
            argv = ["cargo", "+" + COMPILER, "check", *options, "--target", TARGETS[profile],
                    "--locked", "--offline", "--message-format=json-render-diagnostics"]
            stdout = run.command("compile-" + label, argv, cwd=cwd)
            compiled.update(collect_compiled_sources(run.root, cwd, stdout, source))
        extract_database(run, run.configuration.database)
    sdk.require(all(sdk.snapshot(run.root / path).sha256 == digest for path, digest in lock_hashes.items()), "workspace lock changed")
    sdk.require(all(sdk.snapshot(run.root / path, maximum=5 * 1024**2).sha256 == digest for path, digest in source.items()), "analyzed Rust source changed")
    quality.require_clean_checkout(expected_commit)
    quality.require_repository_target_absent()
    inputs = {
        "schema": 1, "profile": profile, "target": TARGETS[profile], "source_commit": expected_commit,
        "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "codeql_version": VERSION, "compiler": COMPILER, "source_sha256": source, "compiled_sources": compiled,
        "compiler_host": run.configuration.compiler_host,
        "query_threads": run.configuration.threads, "query_ram_mb": run.configuration.ram_mb,
        "quality_queries_sha256": {path.name: sdk.snapshot(path).sha256 for path in sorted((run.root / "artifact/codeql-rust-quality").glob("*.ql"))},
        "quality_pack_sha256": sdk.snapshot(run.root / "artifact/codeql-rust-quality/qlpack.yml").sha256,
        "quality_lock_sha256": sdk.snapshot(run.root / "artifact/codeql-rust-quality/codeql-pack.lock.yml").sha256,
        "active_target_quality_passed": False, "paired_target_quality_passed": False,
    }
    # Compiler depfiles may not survive a failed quality query. Retain their
    # validated inventory now; only PROFILE.json can admit later analysis.
    sdk.write_json(run.evidence / "EXTRACTION_INPUTS.json", inputs)
    metrics = collect_quality(run, compiled, source, profile)
    quality.require_clean_checkout(expected_commit)
    sdk.write_json(run.evidence / "PROFILE.json", {
        **inputs,
        "metrics": metrics, "macro_census_sha256": sdk.snapshot(run.evidence / "MacroCalls.json").sha256,
        "extracted_paths_sha256": sdk.snapshot(run.evidence / "ExtractedPaths.json").sha256,
        "active_target_quality_passed": True, "paired_target_quality_passed": False,
    })


def validate_query_inventory(inventory: dict[str, str], expected: object) -> None:
    # Upstream includes both summary queries. Require the full one and every
    # pinned query, rather than mistaking Reduced's presence for substitution.
    sdk.require("queries/summary/SummaryStats.ql" in inventory, "full summary query is missing")
    sdk.require(expected == {"codeql_version": VERSION, "query_pack": QUERY_VERSION, "queries": inventory},
                "resolved query bytes differ from the pinned full suite")


def analyze(run: ProfileRun, query_pack: Path) -> None:
    profile_path = run.evidence / "PROFILE.json"
    profile = parse_strict_json_bytes(sdk.snapshot(profile_path).data, label="Rust analysis profile")
    sdk.require(profile.get("target") == TARGETS.get(profile.get("profile"))
                and profile_host(profile["profile"]) == run.configuration.platform,
                "analysis profile belongs to a different host or target")
    sdk.require(profile["active_target_quality_passed"] is True, "active target quality has not passed")
    quality.require_clean_checkout(profile["source_commit"])
    suite = query_pack / "codeql-suites/rust-security-extended.qls"
    resolved = parse_strict_json_bytes(run.command("resolve-suite", [str(run.codeql), "resolve", "queries", str(suite), "--format=json"]), label="CodeQL query inventory")
    sdk.require(isinstance(resolved, list) and len(resolved) == len(set(resolved)) == 39, "full query suite inventory differs")
    inventory = {}
    for value in resolved:
        path = Path(value).resolve(strict=True)
        sdk.require(path.is_relative_to(query_pack) and path.suffix == ".ql", "query outside pinned Rust pack")
        inventory[path.relative_to(query_pack).as_posix()] = sdk.snapshot(path).sha256
    expected = parse_strict_json_bytes(sdk.snapshot(run.root / "artifact/codeql_rust_queries.json").data,
                                      label="pinned Rust query inventory")
    validate_query_inventory(inventory, expected)
    sdk.write_json(run.evidence / "QUERY_INVENTORY.json", inventory)
    sarif = run.evidence / "results.sarif"
    run.command("analyze", [str(run.codeql), "database", "analyze", str(run.configuration.database), str(suite),
                            "--format=sarif-latest", "--output=" + str(sarif),
                            f"--threads={run.configuration.threads}", f"--ram={run.configuration.ram_mb}",
                            "--threat-model=local", "--no-download", "--common-caches=" + str(run.output / "cache"),
                            "--sarif-category=/language:rust/target:" + profile["profile"]], seconds=18000,
                timeout_policy=TimeoutPolicy.LONG_ANALYSIS)
    results = {}
    for relative in inventory:
        path = run.configuration.database / "results/codeql/rust-queries" / Path(relative).with_suffix(".bqrs")
        results[relative] = sdk.snapshot(path, maximum=64 * 1024**2).sha256
    data = parse_strict_json_bytes(sdk.snapshot(sarif, maximum=64 * 1024**2).data, label="Rust SARIF")
    validate_sarif(data, profile["profile"])
    quality.require_clean_checkout(profile["source_commit"])
    sdk.write_json(run.evidence / "ANALYSIS.json", {
        "completed": True, "profile_sha256": sdk.snapshot(profile_path).sha256,
        "query_inventory_sha256": sdk.snapshot(run.evidence / "QUERY_INVENTORY.json").sha256,
        "query_result_sha256": results, "sarif_sha256": sdk.snapshot(sarif, maximum=64 * 1024**2).sha256,
        "codeql_version": VERSION, "query_pack": QUERY_VERSION, "upload_performed": False,
    })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "analyze"))
    parser.add_argument("--profile", choices=tuple(TARGETS), required=True)
    args = parser.parse_args()
    host = profile_host(args.profile)
    configuration = quality.hosted_configuration(host)
    sdk.require(sys.platform == host, "Rust hosted profile requires its selected platform")
    sdk.require(os.environ.get("CODEQL_BINARY") == str(configuration.codeql), "unexpected CodeQL binary path")
    sdk.require(os.environ.get("RUNNER_TEMP") == str(configuration.runner_temp), "unexpected runner temporary path")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        sdk.require(re.fullmatch(r"[1-9][0-9]*", os.environ.get(name, "")) is not None, "missing workflow identity")
    output = configuration.runner_temp / ("qperiapt-codeql-" + args.profile)
    environment = dict(os.environ, RUSTUP_TOOLCHAIN=COMPILER, RUSTUP_AUTO_INSTALL="0", RUSTFLAGS="-D warnings",
                       CARGO_HOME=str(output / "cargo-home"), CARGO_TARGET_DIR=str(output / "compile"), CARGO_NET_OFFLINE="false")
    sdk.require("CARGO_BUILD_TARGET" not in environment, "unexpected implicit Cargo build target")
    if args.action == "prepare":
        run = ProfileRun(ROOT, output, configuration.codeql, environment, host=host)
        prepare(run, args.profile, os.environ.get("CODEQL_EXPECTED_COMMIT", ""))
    else:
        run = ProfileRun(ROOT, output, configuration.codeql, environment, resume=True, host=host)
        pack = run.codeql.parent / "qlpacks/codeql/rust-queries" / QUERY_VERSION
        analyze(run, pack.resolve(strict=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        sys.exit("error: Rust analysis profile: " + str(exc))
