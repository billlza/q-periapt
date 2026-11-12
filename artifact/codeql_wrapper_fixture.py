#!/usr/bin/env python3
"""Qualify the inline-read candidate through the complete CodeQL analysis path."""
from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import zipfile

sys.dont_write_bytecode = True

CANDIDATE_COMMIT = "0ab06568c956d2cece0a0f7562dd228a5bd14fad"
EVIDENCE_COMMIT = "99340939848d290191651ab306d1b5edc0f59df2"
EVIDENCE = "research/sdk-alpha1/evidence/"
FIXTURE_PACKET = EVIDENCE + "20261111-summary-projection-fixture/"
BASELINE_PATH = EVIDENCE + "20261111-summary-stage34-projection/results/retained-all/decoded.json"
FIXTURE_ZIP_SHA256 = "dc13ea1f6e1d7ea7ea1ef766dbb4599cf481dbbea2a990beb22daa87515d5ece"
FIXTURE_MEMBERS_SHA256 = "ee2de48ff6042bed38a007f85e1c50eca416dc25a7f8899fcbf84d74e6cf31ef"
BASELINE_SHA256 = "f05f212ce3a9847d01191fb595c9a154aac94a83e33faf6fdc7f85dbb19b259e"
BASELINE_SEMANTIC = "e2582f4726e1866ef348bf49f05d8c70c62afc6ce8a913eb883bf88684101725"
PACK_INVENTORY_SHA256 = "febd97c6ca5375ba9b263ca8e29c56d538f41b7aedafa8296547a99a662f68ae"
PLAN_MANIFEST_SHA256 = "aff9e8e5138909da53acc5f75c774e7bb31e1f0d4281546015f6ffb3ae4f9a6d"
PLAN_KEY = "fcbc88b667fe0122ca51593e2594a017"
SUMMARY = "queries/summary/SummaryStats.ql"
DOWNLOADS = {
    "codeql": (
        "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.2/codeql-bundle-rust-linux64.tar.zst",
        "acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea"),
    "cargo": (
        "https://static.rust-lang.org/dist/2026-09-03/cargo-1.98.1-x86_64-unknown-linux-gnu.tar.xz",
        "ea1de9f9e23107d97ee2b41a72c552f34064a593da503789218387aee59f3ba4"),
    "rustc": (
        "https://static.rust-lang.org/dist/2026-09-03/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz",
        "e974f036b28565f37c0f3bd92ddefa809bee16c04f9dcf07b9ed96e05aaaf7c4"),
    "rust-std": (
        "https://static.rust-lang.org/dist/2026-09-03/rust-std-1.98.1-x86_64-unknown-linux-gnu.tar.xz",
        "fa3ff450172a16c026944030230c5069947af93c728d9179971d44e5e0cfb561"),
    "rust-src": (
        "https://static.rust-lang.org/dist/2026-09-03/rust-src-1.98.1.tar.xz",
        "5c846ebcebcc7e2e0777a4cdaa12051691593f16a7e94edbae5e6241cc62d98c"),
}
SOURCE_CONTRACT = (
    "codeql_rust_plan.py", "codeql_rust_profile.py", "codeql_evaluator_logs.py",
    "codeql_summary_projection.py", "codeql_summary_projection.json",
    "codeql_summary_plan.py", "bounded_process.py", "evidence_io.py",
    "codeql_process_resources.py", "codeql_rust_queries.json",
    "codeql_rust_quality.py", "rust_sdk_profile.py",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    require(path.is_file() and not path.is_symlink(), "expected regular file: " + str(path))
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return {"bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "redirected input: " + str(path))
        if not path.is_dir():
            result[path.relative_to(root).as_posix()] = identity(path)
    return result


def canonical(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def read_json(data):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate JSON key: " + key)
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=unique)


def print_failure_stderr(evidence, last_command):
    names = list(dict.fromkeys([last_command + ".stderr" if last_command else "extract.stderr",
                               "extract.stderr"]))
    limit = 8192 // len(names)
    # Keep diagnostic bytes literal while preventing Actions command parsing.
    token = sha(os.urandom(32))
    print("::stop-commands::" + token, file=sys.stderr, flush=True)
    try:
        for name in names:
            path = evidence / name
            if not path.is_file() or path.is_symlink():
                continue
            try:
                with path.open("rb") as stream:
                    size = os.fstat(stream.fileno()).st_size
                    stream.seek(max(0, size - limit))
                    data = stream.read(limit)
            except OSError:
                continue
            print(f"{name}: last {len(data)} of {size} bytes (full file retained in artifact)",
                  file=sys.stderr, flush=True)
            print(data.decode("utf-8", errors="replace"), file=sys.stderr, flush=True)
    finally:
        print("::" + token + "::", file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(output.is_relative_to(runner_temp) and output != runner_temp,
            "fixture output must be a new directory beneath RUNNER_TEMP")
    require(not output.exists() and not output.is_symlink(), "fixture output already exists")
    require(sys.platform == "linux", "fixture requires the Linux runner")
    output.mkdir(mode=0o700)
    evidence = output / "evidence"
    evidence.mkdir()
    for name in ("tmp", "downloads", "components", "rust-source", "extract-cache", "extract-logs"):
        (output / name).mkdir()
    source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    require(source_commit == os.environ["GITHUB_SHA"], "workflow source identity differs")

    if str(repo / "artifact") not in sys.path:
        sys.path.append(str(repo / "artifact"))
    import codeql_rust_plan as plan
    import codeql_rust_profile as profile
    import codeql_summary_projection as projection
    import codeql_evaluator_logs as evaluator_logs
    from codeql_process_resources import ProcessResourceSampler
    from bounded_process import BoundedProcessError, capture_output, TimeoutPolicy

    class FixtureRun:
        def command(self, label, argv, **kwargs):
            self.last_command_label = label
            kwargs.setdefault("seconds", 180)
            return profile.ProfileRun.command(self, label, argv, **kwargs)

    run = FixtureRun()
    run.root, run.output, run.evidence = repo, output, evidence
    environment = dict(os.environ)
    environment["CODEQL_EXPECTED_COMMIT"] = source_commit
    run.environment = plan.controlled_environment(environment, output / "tmp")
    run.configuration = SimpleNamespace(platform="linux", database=output / "database",
                                         ram_mb=14000, threads=4)
    save(evidence / "METHOD.json", {
        "schema": 1, "kind": "qperiapt.hosted_nonempty_wrapper_fixture",
        "state": "started", "workflow_source_commit": source_commit,
        "candidate_source_commit": CANDIDATE_COMMIT, "evidence_commit": EVIDENCE_COMMIT,
        "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "runner_os": os.environ.get("RUNNER_OS"), "runner_arch": os.environ.get("RUNNER_ARCH"),
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "analysis_seconds": 600, "query_threads": 4, "requested_ram_mb": 14000,
        "off_heap_ram_mb": 9329, "heap_policy": "production resolver and actual evaluator invocation",
        "extraction_seconds": 300, "retained_baselines_rerun": False,
        "input_path_changes": {
            "fixture": {
                "original": "/workspace/scratch/4b61438fb07b/summary-env-validation-20261111/fixture-pack/env",
                "current": str(output / "reproduction/fixture/env")},
            "sysroot": {
                "original": "/workspace/scratch/4b61438fb07b/rustix-toolchain/install",
                "current": str(output / "rust")},
            "sysroot_source": {
                "original": "/workspace/scratch/4b61438fb07b/summary-env-validation-20261111/toolchain-source/unpack/rust-src-1.98.1/rust-src/lib/rustlib/src/rust/library",
                "current": str(output / "rust-source/rust-src/lib/rustlib/src/rust/library")}},
        "extraction_configuration": "Authenticated extractor runtime and controlled environment; test extract has no pack-manager configuration option",
        "database_scope": "New extraction on Ubuntu 24.04; source bytes fixed, new database byte identity recorded",
        "local_1024_4096_allocation_used": False,
        "hosted_profile_receipt_created": False, "sarif_upload_requested": False,
        "method_source": identity(Path(__file__))})

    try:
        run.command("fetch-frozen-inputs", [
            "/usr/bin/git", "-C", str(repo), "fetch", "--no-tags", "--depth=1", "origin",
            CANDIDATE_COMMIT, EVIDENCE_COMMIT], seconds=180)
        source_contract = {}
        for name in SOURCE_CONTRACT:
            original = run.command("source-" + name.replace(".", "-"), [
                "/usr/bin/git", "-C", str(repo), "show", CANDIDATE_COMMIT + ":artifact/" + name])
            actual = (repo / "artifact" / name).read_bytes()
            require(actual == original, "candidate method source differs: " + name)
            source_contract[name] = {"bytes": len(actual), "sha256": sha(actual)}
        save(evidence / "SOURCE_CONTRACT.json", source_contract)
        require(projection.MANIFEST_SHA256 == PLAN_MANIFEST_SHA256
                and projection.COMPILER_INPUTS_DIGEST == PLAN_KEY, "Inline-read candidate identity differs")

        inputs = {}
        for label, relative, expected in (
            ("fixture-archive", FIXTURE_PACKET + "reproduction-inputs.zip", FIXTURE_ZIP_SHA256),
            ("fixture-members", FIXTURE_PACKET + "REPRODUCTION_INPUTS.json", FIXTURE_MEMBERS_SHA256),
            ("retained-summary", BASELINE_PATH, BASELINE_SHA256),
        ):
            data = run.command(label, ["/usr/bin/git", "-C", str(repo), "show",
                                       EVIDENCE_COMMIT + ":" + relative])
            require(sha(data) == expected, "retained evidence bytes differ: " + label)
            inputs[label] = data
        require(len(inputs["fixture-archive"]) == 20895 and len(inputs["retained-summary"]) == 1185,
                "retained input lengths differ")
        baseline = read_json(inputs["retained-summary"])
        require(canonical(baseline) == BASELINE_SEMANTIC, "retained summary semantics differ")
        member_manifest = read_json(inputs["fixture-members"])
        require(member_manifest["archive_sha256"] == FIXTURE_ZIP_SHA256
                and member_manifest["member_count"] == 13 and member_manifest["expanded_bytes"] == 77260,
                "fixture member declaration differs")
        archive_path = evidence / "reproduction-inputs.zip"
        archive_path.write_bytes(inputs["fixture-archive"])
        reproduction = output / "reproduction"
        reproduction.mkdir()
        fixture_members = {}
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            require(len(members) == 13 and len({item.filename for item in members}) == 13
                    and {item.filename for item in members} == set(member_manifest["members"]),
                    "fixture ZIP member census differs")
            for item in members:
                path = PurePosixPath(item.filename)
                require(not item.is_dir() and not path.is_absolute() and ".." not in path.parts
                        and str(path) == item.filename and "\\" not in item.filename
                        and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG),
                        "fixture ZIP contains an unadmitted member")
                data = archive.read(item)
                require({"bytes": len(data), "sha256": sha(data)} == member_manifest["members"][item.filename],
                        "fixture member bytes differ")
                if item.filename.startswith("fixture/"):
                    destination = reproduction / item.filename
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                    fixture_members[item.filename] = member_manifest["members"][item.filename]
        require(len(fixture_members) == 8, "fixture source/license/support census differs")
        save(evidence / "FIXTURE_INPUTS.json", fixture_members)

        downloads = {}
        for name, (url, digest) in DOWNLOADS.items():
            destination = output / "downloads" / url.rsplit("/", 1)[1]
            run.command("download-" + name, ["/usr/bin/curl", "--fail", "--location",
                "--proto", "=https", "--proto-redir", "=https",
                "--retry", "2", "--connect-timeout", "30", "--max-time", "180",
                "--output", str(destination), url], seconds=300)
            record = identity(destination)
            require(record["sha256"] == digest, "official archive digest differs: " + name)
            downloads[name] = {"path": str(destination), "url": url, **record}
        require(downloads["codeql"]["bytes"] == 98247028
                and downloads["rust-src"]["bytes"] == 5741168, "official archive size differs")
        save(evidence / "OFFICIAL_DOWNLOADS.json", downloads)
        prefix = output / "rust"
        for name in ("cargo", "rustc", "rust-std"):
            component = output / "components" / name
            component.mkdir()
            run.command("unpack-" + name, ["/usr/bin/tar", "--extract", "--xz",
                "--file=" + downloads[name]["path"], "--strip-components=1",
                "--directory=" + str(component)], seconds=180)
            run.command("install-" + name, ["/bin/sh", str(component / "install.sh"),
                "--prefix=" + str(prefix), "--disable-ldconfig"], seconds=180)
        run.command("unpack-rust-src", ["/usr/bin/tar", "--extract", "--xz",
            "--file=" + downloads["rust-src"]["path"], "--strip-components=1",
            "--directory=" + str(output / "rust-source")], seconds=180)
        rust_source = output / "rust-source/rust-src/lib/rustlib/src/rust/library"
        require(rust_source.is_dir(), "official Rust standard-library source is missing")
        compiler_identity = {
            "rustc": identity(prefix / "bin/rustc"), "cargo": identity(prefix / "bin/cargo")}
        require(compiler_identity["rustc"] == {"bytes": 645952,
                "sha256": "859254978c0a0402c32f949f6de0d99aee73be8d15f45aac00ae1448aac51e74"},
                "installed official rustc bytes differ")
        require(compiler_identity["cargo"] == {"bytes": 40680304,
                "sha256": "da77c8b33849312255ccde3179198ada4c8deb370488d050286146b1d1b27e14"},
                "installed official cargo bytes differ")
        rustc_version = run.command("rustc-version", [str(prefix / "bin/rustc"), "--version", "--verbose"]).decode()
        cargo_version = run.command("cargo-version", [str(prefix / "bin/cargo"), "--version", "--verbose"]).decode()
        require("release: 1.98.1\n" in rustc_version
                and "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985\n" in rustc_version
                and "host: x86_64-unknown-linux-gnu\n" in rustc_version, "rustc toolchain identity differs")
        require("release: 1.98.1\n" in cargo_version
                and "commit-hash: 797e8a9bca276c1c9f9f738d2a20f484fa4eea9d\n" in cargo_version,
                "cargo toolchain identity differs")
        save(evidence / "COMPILER_IDENTITY.json", compiler_identity)

        official_archive = Path(downloads["codeql"]["path"])
        extraction_tool = plan.extract_runtime(official_archive, output / "extraction-tool", run.command)
        extraction_runtime = plan.runtime_inventory(extraction_tool)
        extracted = output / "database-extracted"
        fixture_root = reproduction / "fixture/env"
        extraction_environment = {**run.environment,
            "PATH": str(prefix / "bin") + os.pathsep + run.environment["PATH"],
            "CARGO_NET_OFFLINE": "true",
            "CODEQL_EXTRACTOR_RUST_SYSROOT": str(prefix),
            "CODEQL_EXTRACTOR_RUST_SYSROOT_SRC": str(rust_source)}
        command = [str(extraction_tool / "codeql"), "test", "extract", "-J-Xmx1536M",
            "--database=" + str(extracted), "--common-caches=" + str(output / "extract-cache"),
            "--logdir=" + str(output / "extract-logs"), "--show-extractor-output", "--format=json",
            "--", str(fixture_root)]
        extraction_record = {"command": command, "cwd": str(output), "maximum_seconds": 300,
            "environment_inputs": {key: extraction_environment[key] for key in
                ("PATH", "CARGO_NET_OFFLINE", "CODEQL_EXTRACTOR_RUST_SYSROOT",
                 "CODEQL_EXTRACTOR_RUST_SYSROOT_SRC")},
            "started_utc": datetime.now(timezone.utc).isoformat()}
        save(evidence / "extract.started.json", extraction_record)
        started = time.monotonic()
        run.last_command_label = "extract"
        try:
            with (evidence / "extract.stdout").open("xb", buffering=0) as stdout, \
                    (evidence / "extract.stderr").open("xb", buffering=0) as stderr, contextlib.chdir(output):
                result = capture_output(command, timeout_seconds=300,
                    maximum_stdout_bytes=64 * 1024**2, maximum_stderr_bytes=64 * 1024**2,
                    stdout_sink=stdout.write, stderr_sink=stderr.write, environment=extraction_environment)
            extraction_record["returncode"] = result.returncode
        except BoundedProcessError as error:
            extraction_record.update(boundary=error.kind, reason=str(error),
                                     cleanup_ambiguous=error.cleanup_ambiguous)
            raise
        finally:
            extraction_record.update(seconds=time.monotonic() - started,
                                     finished_utc=datetime.now(timezone.utc).isoformat())
            save(evidence / "extract.json", extraction_record)
        require(extraction_record.get("returncode") == 0, "fixture extraction failed")
        require(plan.runtime_inventory(extraction_tool) == extraction_runtime,
                "original extraction runtime changed")
        for name, expected in fixture_members.items():
            require(identity(reproduction / name) == expected, "fixture source changed: " + name)
        initial = inventory(extracted)
        require(not any(name.endswith(".bqrs") for name in initial), "extraction produced preexisting query results")
        shutil.copytree(extracted, run.configuration.database)
        require(inventory(run.configuration.database) == initial, "new database analysis copy differs")
        (evidence / "INITIAL_DATABASE_FILES.json.gz").write_bytes(gzip.compress(
            (json.dumps(initial, indent=2, sort_keys=True) + "\n").encode(), mtime=0))
        save(evidence / "DATABASE_INPUTS.json", {"files": len(initial), "inventory_sha256": canonical(initial),
            "source_root": str(fixture_root), "relation_to_retained_database": "same frozen fixture and official tools; newly extracted path-specific database"})
        plan.admit_database(run.configuration.database)

        # Use the production preparer, command assembler, memory policy and guard.
        # The command label is separate because the extraction helper also keeps
        # its authenticated tar command receipt.
        original_command = run.command
        def analysis_setup_command(label, argv, **kwargs):
            return original_command("analysis-" + label, argv, **kwargs)
        run.command = analysis_setup_command
        try:
            context = plan.prepare(run, official_archive)
        finally:
            run.command = original_command
        before = inventory(context.pack)
        require(len(before) == 1357 and canonical(before) == PACK_INVENTORY_SHA256,
                "candidate pack differs from the frozen inline-read pack")
        queries = read_json((repo / "artifact/codeql_rust_queries.json").read_bytes())["queries"]
        require(len(queries) == 39, "query manifest census differs")
        save(evidence / "PACK_BEFORE.json", before)
        sampler = ProcessResourceSampler(evidence)
        with plan.guard(run, context):
            memory_arguments = profile.analysis_memory_arguments(run, "native")
            memory = read_json((evidence / "QUERY_MEMORY.json").read_bytes())
            profile.validate_linux_query_memory(memory, "native")
            analysis_command = plan.analysis_command(context, run.configuration.database, evidence,
                                                     "native", memory_arguments)
            sampler.start()
            try:
                run.command("analyze", analysis_command, seconds=600,
                            timeout_policy=TimeoutPolicy.STANDARD, progress_queries=queries)
            finally:
                save(evidence / "RESOURCE_OBSERVATION_STATUS.json", sampler.stop())
            observations = evaluator_logs.observe(context.root, pattern="execute-queries-*.log",
                                                  stdio_prefix=None, capture_invocation=True)
            observed = {name: observations[name] for name in plan.OBSERVATION_FIELDS}
            save(evidence / "EVALUATOR_OBSERVATIONS.json", observed)
            completion = evaluator_logs.read_completion_receipt(evidence / "analyze.stderr", queries)
            save(evidence / "QUERY_COMPLETIONS.json", completion)
            plan.validate_observations(observed, context.pack, queries, memory["heap_mb"],
                                       completion=completion)
            results_root = run.configuration.database / "results/codeql/rust-queries"
            expected_results = {str(Path(name).with_suffix(".bqrs")) for name in queries}
            found = {path.relative_to(results_root).as_posix() for path in results_root.rglob("*.bqrs")}
            require(found == expected_results and len(list(run.configuration.database.rglob("*.bqrs"))) == 39,
                    "fresh 39-query BQRS census differs")
            results = {}
            for name in sorted(found):
                source = results_root / name
                results[name] = identity(source)
                destination = evidence / "results" / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            save(evidence / "FRESH_RESULTS.json", results)
            sarif_path = evidence / "results.sarif"
            profile.validate_sarif(read_json(sarif_path.read_bytes()), "native")
            decoded = run.command("decode-summary", [str(context.codeql), "bqrs", "decode",
                "--format=json", "-J-Xmx512M",
                str(results_root / Path(SUMMARY).with_suffix(".bqrs"))],
                seconds=120)
            summary = read_json(decoded)
            require(summary == baseline and canonical(summary) == BASELINE_SEMANTIC,
                    "complete 29-row SummaryStats result differs from the retained baseline")
            rows = summary["#select"]["tuples"]
            require(len(rows) == 29 and len(dict(rows)) == 29, "summary row census differs")
            values = dict(rows)
            require(values["Taint sources - active"] == 15 and values["Taint reach - nodes tainted"] == 106,
                    "fixture no longer has its retained nonempty source/reach counts")
            require(inventory(context.pack) == before, "candidate pack changed during analysis or decode")
            require(inventory(extracted) == initial, "original new extraction changed")
            for name, expected in fixture_members.items():
                require(identity(reproduction / name) == expected, "fixture source changed after analysis")
        require(context.after == context.before == plan.expected_identity(), "production postcheck incomplete")
        require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip() == source_commit,
                "workflow source HEAD changed")
        save(evidence / "FIXTURE_WRAPPER_RESULT.json", {
            "schema": 1, "kind": "qperiapt.hosted_nonempty_wrapper_fixture",
            "status": "complete_equal_summary_valid_sarif",
            "workflow_source_commit": source_commit, "candidate_source_commit": CANDIDATE_COMMIT,
            "evidence_commit": EVIDENCE_COMMIT, "finished_utc": datetime.now(timezone.utc).isoformat(),
            "summary_plan": context.before, "query_memory": memory, "query_threads": 4,
            "analysis_supervisor_seconds": 600, "precompiled_query_loads": 39,
            "implicit_compilations": 0, "fresh_bqrs_count": 39,
            "query_completion_evidence": completion,
            "sarif": identity(sarif_path), "summary_decoded": identity(evidence / "decode-summary.stdout"),
            "summary_semantic_sha256": canonical(summary), "summary_values": values,
            "retained_all_baseline_equal": True, "retained_baselines_rerun": False,
            "extracted_database_inventory_sha256": canonical(initial),
            "all_fixture_source_members_unchanged": True, "pack_and_runtime_postchecks_passed": True,
            "hosted_profile_receipt_created": False, "three_target_publication_claimed": False,
            "sarif_uploaded": False})
        return 0
    except BaseException as error:
        save(evidence / "FIXTURE_FAILURE.json", {"type": type(error).__name__, "message": str(error),
            "notes": getattr(error, "__notes__", []), "recorded_utc": datetime.now(timezone.utc).isoformat()})
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        with contextlib.suppress(OSError):
            print_failure_stderr(evidence, getattr(run, "last_command_label", None))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
