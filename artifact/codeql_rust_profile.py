"""Compile, extract and analyze one Rust target; upload requires paired validation."""
from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
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
import codeql_rust_plan as analysis_plan
import codeql_evaluator_logs as evaluator_logs
from codeql_target_coverage import MacroProfile, parse_macro_calls, validate_active_macro_coverage
from evidence_io import parse_strict_json_bytes
from git_provenance import run_git_bytes
import rust_sdk_profile as sdk

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {"native": "x86_64-unknown-linux-gnu", "wasm": "wasm32-unknown-unknown",
           "macos": "aarch64-apple-darwin"}
VERSION = "2.27.4"
QUERY_VERSION = "0.1.46"
# The extractor overrides RUSTUP_TOOLCHAIN with 1.99.0. Match it for both
# compilation and the explicit sysroot so its procedural-macro ABI agrees.
COMPILER = "1.99.0"
# The official 2.27.4 pack completed all 39 queries on the retained large
# database with this 14,000-MB split, matching the decoded 56,000-MB results.
# CodeQL resolves the remaining heap against each current database. macOS
# compilation/extraction keeps its native hosted policy; its sealed database
# uses the same Linux query budget.
LINUX_OFF_HEAP_RAM_MB = 9329
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
# Exact retained source/evidence snapshots are not Cargo fetch roots. Git's
# *Cargo.lock pathspec also matches prefixed archive names, so bind those
# explicitly instead of weakening the live workspace inventory.
ARCHIVE_LOCKFILES = {
    # Paper snapshots at f26e30a57cd6f22370ac2f1b3ba1962c1997b25d.
    "paper/continuity/artifacts/signature-bridge/sources/q-periapt-native/Cargo.lock":
        "b3f7403faca9c95c0f77d5abb6ce732bb9b89c1a4c72ad6ba6e58f533e0af3d9",
    "paper/continuity/artifacts/signature-bridge/sources/q-periapt-native/research/continuity-identity-candidate/Cargo.lock":
        "fda2e0592f7e013816b343d461da1e32346b4256603eda317d12b4ebd200c26b",
    # Installed native-consumer evidence; its prefixed manifest is archival.
    "research/sdk-alpha1/evidence/20261110-native-distribution/consumer-Cargo.lock":
        "9a10dfaca8599e74ca4a4783639c1bc9d34752cd73be3176e3d3499a28d0209e",
}


def profile_host(profile: str) -> str:
    sdk.require(profile in TARGETS, "unknown Rust analysis profile")
    return "darwin" if profile == "macos" else "linux"


def analysis_host(profile: str) -> str:
    sdk.require(profile in TARGETS, "unknown Rust analysis profile")
    return "linux"


def sarif_category(profile: str) -> str:
    sdk.require(profile in TARGETS, "unknown Rust analysis profile")
    # Keep the established Linux analysis identity on main. Target identity is
    # also bound by PROFILE.json and its source, compiler and coverage checks.
    return "/language:rust" if profile == "native" else "/language:rust/target:" + profile


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
                timeout_policy: TimeoutPolicy = TimeoutPolicy.STANDARD, stdin_fd: int | None = None,
                progress_queries: dict | None = None):
        started = time.monotonic()
        record = {"argv": argv, "cwd": str(cwd or self.root), "maximum_seconds": seconds,
                  "invoked_at_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                  "source_commit": self.environment.get("CODEQL_EXPECTED_COMMIT"),
                  "run_id": self.environment.get("GITHUB_RUN_ID"),
                  "run_attempt": self.environment.get("GITHUB_RUN_ATTEMPT")}
        try:
            # Stream bounded diagnostics into fresh evidence files while the
            # child runs. A timeout still fails, with the emitted query progress
            # retained alongside the failure receipt. Unbuffered files make
            # even small progress writes readable before command completion.
            with (self.evidence / (label + ".stdout")).open("xb", buffering=0) as stdout, \
                    (self.evidence / (label + ".stderr")).open("xb", buffering=0) as stderr, \
                    contextlib.chdir(cwd or self.root):
                # This receipt precedes the supervisor call, so a killed worker
                # still records which command was invoked and when. It is not
                # a completion receipt or the subprocess's exact deadline.
                sdk.write_json(self.evidence / (label + ".started.json"), record)
                print(f"{label} invoked at {record['invoked_at_utc']} (bound {seconds}s)", flush=True)
                result = capture_output(argv, timeout_seconds=seconds, maximum_stdout_bytes=32 * 1024**2,
                                        maximum_stderr_bytes=16 * 1024**2, environment=self.environment,
                                        stdout_sink=stdout.write,
                                        stderr_sink=(evaluator_logs.QueryCompletionSink(stderr.write, progress_queries)
                                                     if progress_queries is not None else stderr.write),
                                        timeout_policy=timeout_policy,
                                        **({"stdin_fd": stdin_fd} if stdin_fd is not None else {}))
        except BoundedProcessError as exc:
            sdk.write_json(self.evidence / (label + ".json"), {
                **record, "completed": False, "boundary": exc.kind, "reason": str(exc),
                "cleanup_ambiguous": exc.cleanup_ambiguous, "elapsed_seconds": time.monotonic() - started,
                "finished_at_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            })
            raise
        sdk.write_json(self.evidence / (label + ".json"), {
            **record, "returncode": result.returncode, "elapsed_seconds": time.monotonic() - started,
            "finished_at_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
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
    tracked = tuple(run_git_bytes(root, ["ls-files", "--", "*Cargo.lock"]).decode().splitlines())
    locks = tuple(path for path in tracked if path not in ARCHIVE_LOCKFILES)
    sdk.require(locks == WORKSPACE_LOCKFILES, "tracked workspace lock inventory differs")
    for relative in tracked:
        if relative in ARCHIVE_LOCKFILES:
            archive = root / relative
            manifest = archive.with_name("Cargo.toml")
            sdk.require(not manifest.exists() and not manifest.is_symlink(),
                        "archived lock has an adjacent Cargo.toml")
            sdk.require(sdk.snapshot(archive, maximum=1024 * 1024).sha256 == ARCHIVE_LOCKFILES[relative],
                        "archived lock snapshot differs")
    return locks


def validate_sarif(data: object, profile: str) -> None:
    sdk.require(isinstance(data, dict) and data.get("version") == "2.1.0", "invalid Rust SARIF version")
    runs = data.get("runs")
    sdk.require(isinstance(runs, list) and len(runs) == 1 and isinstance(runs[0], dict), "unexpected Rust SARIF run set")
    run = runs[0]
    sdk.require(run.get("automationDetails") == {"id": sarif_category(profile) + "/"},
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
    # The pinned partial source packets have no Cargo manifests. Load their
    # bytes into rust-analyzer's file view while retaining their non-module
    # status; the complete source census and diagnostic gates still apply.
    run.environment["CODEQL_EXTRACTOR_RUST_OPTION_EXTRA_INCLUDES"] = json.dumps(
        [str(run.root / quality.ARCHIVE_ROOT)])
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
    sdk.require(compiler.startswith("rustc 1.99.0 (b940084d7 2026-09-28)\n")
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
        # Keep the selected launcher identity across repository and Cargo cwd
        # changes without dereferencing a multicall/compiler symlink.
        clang = str(Path(clang).absolute())
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
    if profile == "macos":
        # The native compiler and extractor finish here. The authenticated
        # database is qualified on Linux before security analysis is admitted.
        return
    metrics = collect_quality(run, compiled, source, profile)
    quality.require_clean_checkout(expected_commit)
    sdk.write_json(run.evidence / "PROFILE.json", {
        **inputs,
        "metrics": metrics, "macro_census_sha256": sdk.snapshot(run.evidence / "MacroCalls.json").sha256,
        "extracted_paths_sha256": sdk.snapshot(run.evidence / "ExtractedPaths.json").sha256,
        "active_target_quality_passed": True, "paired_target_quality_passed": False,
    })


def qualify_macos(run: ProfileRun, expected_commit: str) -> None:
    """Qualify the authenticated native extraction using the Linux query budget."""
    from codeql_rust_transfer import validate_transfer_anchor, validate_qualified_profile
    sdk.require(run.configuration.platform == "linux", "macOS quality requires the Linux query worker")
    sdk.require(not (run.evidence / "PROFILE.json").exists()
                and not (run.evidence / "PROFILE.json").is_symlink(), "quality profile must be fresh")
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    transfer = validate_transfer_anchor(run.evidence, expected_commit=expected_commit,
                                        run_id=os.environ["GITHUB_RUN_ID"], analysis_attempt=attempt)
    snapshot = sdk.snapshot(run.evidence / "EXTRACTION_INPUTS.json")
    sdk.require(snapshot.sha256 == transfer["extraction_inputs_sha256"],
                "extraction inputs changed after transfer admission")
    inputs = parse_strict_json_bytes(snapshot.data, label="macOS extraction inputs")
    quality.require_clean_checkout(expected_commit)
    source = {path: sdk.snapshot(run.root / path, maximum=5 * 1024**2).sha256
              for path in sorted(quality.tracked_rust_paths(run.root))}
    compiled = inputs.get("compiled_sources")
    sdk.require(inputs.get("source_sha256") == source
                and isinstance(compiled, dict) and compiled and set(compiled) <= source.keys()
                and all(source[path] == digest for path, digest in compiled.items()),
                "transferred compiler source identity differs")
    queries = run.root / "artifact/codeql-rust-quality"
    sdk.require(inputs.get("quality_queries_sha256") == {
                    path.name: sdk.snapshot(path).sha256 for path in sorted(queries.glob("*.ql"))}
                and inputs.get("quality_pack_sha256") == sdk.snapshot(queries / "qlpack.yml").sha256
                and inputs.get("quality_lock_sha256") == sdk.snapshot(queries / "codeql-pack.lock.yml").sha256,
                "transferred quality query bytes differ")
    version = run.command("quality-codeql-version", [str(run.codeql), "version", "--format=terse"])
    sdk.require(version.decode().strip() == VERSION, "unexpected quality CodeQL version")
    metrics = collect_quality(run, compiled, source, "macos")
    quality.require_clean_checkout(expected_commit)
    sdk.require(sdk.snapshot(run.evidence / "EXTRACTION_INPUTS.json").sha256 == snapshot.sha256,
                "extraction inputs changed during qualification")
    profile = {
        **inputs, "extraction_inputs_sha256": snapshot.sha256,
        "quality_host": run.configuration.platform, "quality_threads": run.configuration.threads,
        "quality_ram_mb": run.configuration.ram_mb, "quality_run_attempt": str(attempt),
        "metrics": metrics, "macro_census_sha256": sdk.snapshot(run.evidence / "MacroCalls.json").sha256,
        "extracted_paths_sha256": sdk.snapshot(run.evidence / "ExtractedPaths.json").sha256,
        "active_target_quality_passed": True,
    }
    validate_qualified_profile(run.evidence, profile, analysis_attempt=attempt)
    sdk.write_json(run.evidence / "PROFILE.json", profile)


def validate_query_inventory(inventory: dict[str, str], expected: object) -> None:
    # Upstream includes both summary queries. Require the full one and every
    # pinned query, rather than mistaking Reduced's presence for substitution.
    sdk.require("queries/summary/SummaryStats.ql" in inventory, "full summary query is missing")
    sdk.require(expected == {"codeql_version": VERSION, "query_pack": QUERY_VERSION, "queries": inventory},
                "resolved query bytes differ from the pinned full suite")


def linux_query_memory(resolved: object, profile: str) -> dict:
    sdk.require(profile in TARGETS, "memory policy requires a reviewed Linux analysis profile")
    sdk.require(isinstance(resolved, list) and len(resolved) == 2
                and all(isinstance(argument, str) for argument in resolved),
                "Linux evaluator memory resolution is malformed")
    heap = re.fullmatch(r"-J-Xmx([1-9][0-9]*)M", resolved[0])
    sdk.require(heap is not None and resolved[1] == f"--off-heap-ram={LINUX_OFF_HEAP_RAM_MB}",
                "Linux evaluator allocation differs from the selected policy")
    heap_mb = int(heap[1])
    sdk.require(heap_mb + LINUX_OFF_HEAP_RAM_MB <= 14000,
                "Linux evaluator allocation exceeds its total budget")
    return {"schema": 1, "profile": profile, "codeql_version": VERSION,
            "requested_ram_mb": 14000, "off_heap_ram_mb": LINUX_OFF_HEAP_RAM_MB,
            "heap_mb": heap_mb, "remaining_budget_mb": 14000 - heap_mb - LINUX_OFF_HEAP_RAM_MB,
            "resolved_arguments": resolved}


def validate_linux_query_memory(record: object, profile: str) -> None:
    sdk.require(isinstance(record, dict) and all(type(record.get(key)) is int for key in
                ("schema", "requested_ram_mb", "off_heap_ram_mb", "heap_mb", "remaining_budget_mb")),
                "Linux evaluator memory record is malformed")
    sdk.require(record == linux_query_memory(record.get("resolved_arguments"), profile),
                "Linux evaluator memory record differs from its resolved allocation")


def analysis_memory_arguments(run: ProfileRun, profile: str) -> list[str]:
    sdk.require(analysis_host(profile) == run.configuration.platform,
                "analysis memory profile belongs to a different host")
    arguments = [f"--ram={run.configuration.ram_mb}"]
    if profile in TARGETS:
        sdk.require(run.configuration.ram_mb == 14000 and run.configuration.threads == 4,
                    "Linux allocation requires its reviewed hosted budget")
        arguments.append(f"--off-heap-ram={LINUX_OFF_HEAP_RAM_MB}")
        resolved = parse_strict_json_bytes(run.command("resolve-analysis-ram", [
            str(run.codeql), "resolve", "ram", "--dataset=" + str(run.configuration.database / "db-rust"),
            *arguments, "--format=json"]),
            label="Linux evaluator memory resolution")
        sdk.write_json(run.evidence / "QUERY_MEMORY.json", linux_query_memory(resolved, profile))
    return arguments


def analyze(run: ProfileRun, query_pack: Path, *, summary_plan_mode: str = "none",
            tool_archive: Path | None = None) -> None:
    sdk.require(summary_plan_mode in analysis_plan.MODES and
                (tool_archive is not None) == (summary_plan_mode == "official"),
                "official analysis requires its explicit fixed tool archive")
    profile_path = run.evidence / "PROFILE.json"
    # Bind the receipt to the same snapshots whose contents are validated.
    profile_snapshot = sdk.snapshot(profile_path)
    profile = parse_strict_json_bytes(profile_snapshot.data, label="Rust analysis profile")
    sdk.require(profile.get("target") == TARGETS.get(profile.get("profile"))
                and analysis_host(profile["profile"]) == run.configuration.platform,
                "analysis profile belongs to a different host or target")
    sdk.require(profile["active_target_quality_passed"] is True, "active target quality has not passed")
    run_id, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    expected_commit = os.environ.get("CODEQL_EXPECTED_COMMIT", "")
    sdk.require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None
                and re.fullmatch(r"[1-9][0-9]*", attempt) is not None
                and re.fullmatch(r"[0-9a-f]{40}", expected_commit) is not None
                and profile.get("source_commit") == expected_commit
                and profile.get("run_id") == run_id
                and isinstance(profile.get("run_attempt"), str)
                and re.fullmatch(r"[1-9][0-9]*", profile["run_attempt"]) is not None
                and int(profile["run_attempt"]) <= int(attempt), "analysis workflow identity differs")
    if profile["profile"] == "macos":
        from codeql_rust_transfer import validate_transfer_anchor, validate_qualified_profile
        validate_transfer_anchor(run.evidence, expected_commit=expected_commit,
                                 run_id=run_id, analysis_attempt=int(attempt))
        validate_qualified_profile(run.evidence, profile, analysis_attempt=int(attempt))
    else:
        sdk.require(not (run.evidence / "TRANSFER.json").exists()
                    and not (run.evidence / "TRANSFER.json").is_symlink(),
                    "native Linux extraction cannot use a macOS database transfer")
    quality.require_clean_checkout(profile["source_commit"])
    context = analysis_plan.prepare(run, tool_archive) if summary_plan_mode == "official" else None
    if context is not None:
        query_pack = context.pack
    suite = query_pack / "codeql-suites/rust-security-extended.qls"
    resolved = parse_strict_json_bytes(run.command("resolve-suite", [str(run.codeql), "resolve", "queries", str(suite), "--format=json",
        *(["--qlconfig-file=" + str(context.root / "qlconfig.yml")] if context is not None else [])]), label="CodeQL query inventory")
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
    memory_arguments = analysis_memory_arguments(run, profile["profile"])
    command = ([str(run.codeql), "database", "analyze", str(run.configuration.database), str(suite),
                             "--format=sarif-latest", "--output=" + str(sarif),
                             f"--threads={run.configuration.threads}", *memory_arguments,
                             "--threat-model=local", "--no-download", "--common-caches=" + str(run.output / "cache"),
                             "--sarif-category=" + sarif_category(profile["profile"])])
    if context is not None:
        command = analysis_plan.analysis_command(context, run.configuration.database, run.evidence,
                                                  profile["profile"], memory_arguments)
    with analysis_plan.guard(run, context) if context is not None else contextlib.nullcontext():
        run.command("analyze", command, seconds=18000, timeout_policy=TimeoutPolicy.LONG_ANALYSIS,
                    progress_queries=inventory)
    results = {}
    for relative in inventory:
        path = run.configuration.database / "results/codeql/rust-queries" / Path(relative).with_suffix(".bqrs")
        results[relative] = sdk.snapshot(path, maximum=64 * 1024**2).sha256
    sarif_snapshot = sdk.snapshot(sarif, maximum=64 * 1024**2)
    data = parse_strict_json_bytes(sarif_snapshot.data, label="Rust SARIF")
    validate_sarif(data, profile["profile"])
    quality.require_clean_checkout(profile["source_commit"])
    analysis = {
        "schema": 3 if context is not None else 2, "profile": profile["profile"], "target": profile["target"],
        "source_commit": profile["source_commit"], "run_id": run_id, "run_attempt": attempt,
        "analysis_host": run.configuration.platform,
        "query_threads": run.configuration.threads, "query_ram_mb": run.configuration.ram_mb,
        "completed": True, "profile_sha256": profile_snapshot.sha256,
        "query_inventory_sha256": sdk.snapshot(run.evidence / "QUERY_INVENTORY.json").sha256,
        "query_result_sha256": results, "sarif_sha256": sarif_snapshot.sha256,
        "codeql_version": VERSION, "query_pack": QUERY_VERSION, "upload_performed": False,
        "query_memory_sha256": sdk.snapshot(run.evidence / "QUERY_MEMORY.json").sha256,
        **({"transfer_sha256": sdk.snapshot(run.evidence / "TRANSFER.json").sha256}
           if profile["profile"] == "macos" else {}),
    }
    if context is not None:
        analysis.update(summary_plan_mode="official", analysis_plan_sha256=analysis_plan.complete(
            run, context, analysis, command, inventory))
    sdk.write_json(run.evidence / "ANALYSIS.json", analysis)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "export", "import", "qualify", "analyze"))
    parser.add_argument("--profile", choices=tuple(TARGETS), required=True)
    parser.add_argument("--summary-plan-mode", choices=analysis_plan.MODES, default="none")
    parser.add_argument("--tool-archive", type=Path,
                        help="Exact fixed official Rust archive required for opt-in official analysis")
    args = parser.parse_args()
    sdk.require((args.summary_plan_mode == "none" and args.tool_archive is None)
                or (args.action == "analyze" and args.summary_plan_mode == "official" and args.tool_archive is not None),
                "the explicit official archive is only accepted for analysis")
    sdk.require(args.action not in ("export", "import", "qualify") or args.profile == "macos",
                "only the macOS extraction uses a database transfer")
    host = profile_host(args.profile) if args.action in ("prepare", "export") else analysis_host(args.profile)
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
    elif args.action in ("export", "import"):
        from codeql_rust_transfer import export_database, import_database
        run = ProfileRun(ROOT, output, configuration.codeql, environment, resume=args.action == "export", host=host)
        (export_database if args.action == "export" else import_database)(run)
    elif args.action == "qualify":
        run = ProfileRun(ROOT, output, configuration.codeql, environment, resume=True, host=host)
        qualify_macos(run, os.environ.get("CODEQL_EXPECTED_COMMIT", ""))
    else:
        run = ProfileRun(ROOT, output, configuration.codeql, environment, resume=True, host=host)
        pack = run.codeql.parent / "qlpacks/codeql/rust-queries" / QUERY_VERSION
        analyze(run, pack.resolve(strict=True), summary_plan_mode=args.summary_plan_mode, tool_archive=args.tool_archive)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        sys.exit("error: Rust analysis profile: " + str(exc))
