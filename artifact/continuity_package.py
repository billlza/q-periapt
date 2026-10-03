#!/usr/bin/env python3
"""Qualify the unpublished Continuity crate through exact installed Cargo archives.

This is a candidate Rust package boundary, not SDK publication or a frozen protocol.
All endpoint code is compiled outside the checkout from the produced archives.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import tomllib

import rust_sdk_profile as sdk
from evidence_io import fresh_output_directory, parse_strict_json_bytes
from rust_sdk_msrv import tool_identity, validate_report

ROOT = Path(__file__).resolve().parent.parent
CANDIDATE = ROOT / "research/continuity-identity-candidate"
NAME = "q-periapt-continuity-identity-candidate"
VERSION = "0.0.0"
CONSUMER = "q-periapt-continuity-package-consumer"
FIXTURE = "bindings/rust/ContinuityPackageConsumer/Cargo.toml"
TESTS = {"service_peer_process", "owned_services_connect_restart_rekey_and_reconcile_unknown_delivery",
         "reopen::public_session_reopen_after_expiry_reconciles_unknown_commit_over_real_tls"}


def source_inputs() -> dict:
    identity = sdk.source_identity()
    files = [*CANDIDATE.rglob("*"), *(ROOT / n for n in (
        FIXTURE, ".github/workflows/ci.yml", "artifact/continuity_package.py", "artifact/continuity_c_consumer.py", "artifact/continuity_c_recovery.py", "artifact/continuity_c_opening.py", "artifact/continuity_c_device.py", "artifact/continuity_c_account.py", "artifact/continuity_c_account_cleanup.py", "artifact/continuity_c_account_witness.py", "artifact/continuity_c_faults.py", "artifact/continuity_c_witness.py", "artifact/rust_sdk_msrv.py",
        "artifact/continuity_c_account_tls.py", "artifact/continuity_c_account_tls_loss.py",
        "artifact/continuity_c_witness_tls.py", "artifact/continuity_c_witness_openssl.py", "artifact/continuity_swift_consumer.py", "artifact/continuity_kotlin_consumer.py", "artifact/continuity_package_archive.py", "artifact/jvm_sdk_package.py", "artifact/third_party_licenses.py", "LICENSES/Rust-1.98.1-library.html", "artifact/python-run.sh", "artifact/python-env.sh", "artifact/python_bootstrap.py"))]
    files.extend((ROOT / "bindings/c/ContinuityPackageConsumer").rglob("*"))
    files.extend((ROOT / "bindings/swift/ContinuityPackageConsumer").rglob("*"))
    from continuity_kotlin_consumer import source_files
    files.extend(ROOT / "bindings/kotlin/ContinuityPackageConsumer" / name for name in source_files())
    files.extend(ROOT / "LICENSES" / name for name in ("Apache-2.0.txt", "MIT.txt"))
    for path in files:
        sdk.require(not path.is_symlink(), "candidate source contains a symlink")
        if path.is_file():
            identity["files"][path.relative_to(ROOT).as_posix()] = sdk.snapshot(path).sha256
    return identity


def validate_candidate(data: bytes, expected_files: set[str]) -> dict[str, bytes]:
    files = sdk.archive_files(data, NAME, version=VERSION)
    sdk.require(set(files) == expected_files, "candidate differs from Cargo package inventory")
    manifest = tomllib.loads(files["Cargo.toml"].decode())
    package = manifest["package"]
    sdk.require(package["name"] == NAME and package["version"] == VERSION and package["publish"] is False,
                "candidate package identity or publication boundary changed")
    for section in ("dependencies", "dev-dependencies"):
        for name, dep in manifest.get(section, {}).items():
            if name.startswith("q-periapt"):
                sdk.require(name in sdk.CONSUMER_CRATES and dep["version"] == "=" + sdk.VERSION
                            and "path" not in dep, "candidate normalized SDK dependency differs")
    sdk.require({"LICENSE", "LICENSE-APACHE", "LICENSE-MIT", "tests/owned_connection.rs"} <= files.keys(),
                "candidate archive is missing license or public consumer inputs")
    sdk.require(files["Cargo.toml.orig"] == sdk.snapshot(CANDIDATE / "Cargo.toml").data,
                "candidate original manifest differs")
    for relative, content in files.items():
        if relative not in {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}:
            sdk.require(content == sdk.snapshot(CANDIDATE / relative).data,
                        f"candidate archive source differs: {relative}")
    return files


def verify_resolution(metadata: dict, consumer: Path, lock: bytes, original: bytes,
                      *, consumer_name: str = CONSUMER,
                      required_features=frozenset({"connection-tls", "control-tls"})) -> dict:
    candidate = [row for row in metadata["packages"] if row["name"] == NAME]
    sdk.require(len(candidate) == 1, "consumer must resolve one candidate engine")
    row = candidate[0]
    expected = consumer / "packages" / f"{NAME}-{VERSION}" / "Cargo.toml"
    sdk.require(Path(row["manifest_path"]).resolve() == expected and row["source"] is None
                and row["version"] == VERSION and row["publish"] == [],
                "candidate consumer resolved checkout, registry or a different version")
    for package in metadata["packages"]:
        if not package["name"].startswith("q-periapt"):
            sdk.require(package["source"] == "registry+https://github.com/rust-lang/crates.io-index",
                        "consumer resolved a non-registry external dependency")
    filtered = dict(metadata, packages=[p for p in metadata["packages"] if p["name"] != NAME])
    result = sdk.verify_consumer_resolution(filtered, consumer, lock, original, consumer_name=consumer_name)
    nodes = metadata["resolve"]["nodes"]
    selected = [n for n in nodes if n["id"] == row["id"]]
    sdk.require(len(selected) == 1 and required_features <= set(selected[0]["features"]),
                "installed candidate omitted a transport feature")
    return dict(result, candidate_crates=1)


def verify_execution(stdout: bytes, directory: Path, reopen_directory: Path) -> dict:
    text = stdout.decode()
    passed = re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE)
    sdk.require(len(passed) == 3 and set(passed) == TESTS and re.search(
        r"^test result: ok\. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", text, re.MULTILINE),
        "installed candidate did not execute all three complete public API tests")
    report = parse_strict_json_bytes(sdk.snapshot(directory / "public-result.json").data,
                                    label="installed Continuity execution")
    for field in ("session", "forward_message", "reverse_message"):
        sdk.require(isinstance(report.get(field), str) and re.fullmatch(r"[0-9a-f]{64}", report[field]),
                    "installed connection identity is invalid")
    for field in ("unknown_delivery_reconciled", "durable_sdk_revocation", "cleanup_after_revocation"):
        sdk.require(report.get(field) is True, f"installed connection did not qualify {field}")
    for field, expected in (("network_rekeys", 1), ("independent_readbacks", 3),
                            ("exclusive_leases_checked", 8), ("cleanup_exclusive_leases_checked", 3)):
        sdk.require(type(report.get(field)) is int and report[field] == expected,
                    f"installed connection count differs: {field}")
    readbacks = {}
    for role, field, payload in (
        ("responder", "forward_message", b"persisted before process exit"),
        ("initiator", "reverse_message", b"reverse after original installation restart"),
    ):
        leaf = f"{role}/application-{report[field]}"
        received = sdk.snapshot(directory / leaf)
        sdk.require(received.data == bytes.fromhex(report["session"] + report[field]) + payload,
                    "installed connection application readback differs")
        sdk.require(len(list((directory / role).glob("application-*"))) == 1,
                    "installed connection produced unexpected application effects")
        readbacks[leaf] = received.sha256
    cleanup = [sdk.snapshot(directory / "responder" / leaf).data
               for leaf in ("closure-id", "cleanup-complete", "cleanup-verified")]
    sdk.require(len(cleanup[0]) == 32 and cleanup[0] == cleanup[1] == cleanup[2],
                "installed cleanup did not retain its original report identity")
    return dict(report, application_readbacks=readbacks, cleanup_id=cleanup[0].hex(),
                session_reopen=verify_reopen_execution(reopen_directory))



def verify_reopen_execution(directory: Path) -> dict:
    report = parse_strict_json_bytes(sdk.snapshot(directory / "public-reopen-result.json").data,
                                    label="installed session restoration")
    for field in ("session", "message", "context"):
        sdk.require(isinstance(report.get(field), str) and re.fullmatch(r"[0-9a-f]{64}", report[field]),
                    "installed session restoration identity is invalid")
    for field in ("original_context", "exact_outbox", "unknown_commit_reconciled", "fresh_bootstrap_refused",
                  "independent_processes", "injected_protocol_clock"):
        sdk.require(report.get(field) is True, f"installed session restoration did not qualify {field}")
    sdk.require(type(report.get("application_readbacks")) is int and report["application_readbacks"] == 2,
                "installed session restoration readback count differs")
    sdk.require(type(report.get("test_protocol_time")) is int and 0 < report["test_protocol_time"] < 2**64,
                "installed session restoration protocol clock differs")
    for role in ("initiator", "responder"):
        sdk.require(sdk.snapshot(directory / role / "reopen-test-time").data == report["test_protocol_time"].to_bytes(8, "big"),
                    "installed session restoration peers did not use the same protocol clock")
    original = sdk.snapshot(directory / "original-outbox")
    restored = sdk.snapshot(directory / "restored-outbox")
    sdk.require(original.size > 0 and original.data == restored.data,
                "installed session restoration changed the retained ciphertext")
    leaf = "responder/application-" + report["message"]
    received = sdk.snapshot(directory / leaf)
    sdk.require(received.data == bytes.fromhex(report["session"] + report["message"])
                + b"original application commit before advertisement expiry",
                "installed session restoration application readback differs")
    sdk.require(len(list((directory / "responder").glob("application-*"))) == 1,
                "installed session restoration duplicated application effects")
    return dict(report, original_outbox_sha256=original.sha256,
                restored_outbox_sha256=restored.sha256, application_file={leaf: received.sha256})


def verify_candidate_files(directory: Path, files: dict[str, bytes]) -> None:
    actual = set()
    for path in directory.rglob("*"):
        sdk.require(not path.is_symlink(), "installed candidate contains a symlink")
        if path.is_dir():
            continue
        relative = path.relative_to(directory).as_posix()
        actual.add(relative)
        sdk.require(relative in files and sdk.snapshot(path).data == files[relative],
                    "installed candidate source changed")
    sdk.require(actual == files.keys(), "installed candidate source inventory changed")


def built_test_binary(stdout: bytes, consumer: Path, build: Path) -> Path:
    messages = [parse_strict_json_bytes(line, label="Cargo build message") for line in stdout.splitlines()]
    artifacts = [m for m in messages if m.get("reason") == "compiler-artifact" and m.get("executable")]
    sdk.require(len(artifacts) == 1, "installed consumer must build one test executable")
    artifact = artifacts[0]
    expected = consumer / "packages" / f"{NAME}-{VERSION}" / "tests/owned_connection.rs"
    sdk.require(artifact["target"]["name"] == "owned_connection" and artifact["target"]["kind"] == ["test"]
                and Path(artifact["target"]["src_path"]).resolve() == expected,
                "test executable does not originate in the candidate archive")
    binary = Path(artifact["executable"]).resolve(strict=True)
    sdk.require(binary.is_relative_to(build) and binary.parent == build / "deps",
                "test executable lies outside the selected installed build")
    return binary


def compiler_identity(toolchain: Path) -> dict:
    tools = tool_identity(toolchain)
    for name in ("cargo-clippy", "clippy-driver"):
        path = toolchain / "bin" / name
        tools[name] = {"path": str(path), "sha256": sdk.snapshot(path, maximum=256 * 1024**2).sha256}
    return tools


def qualify(args: argparse.Namespace) -> dict:
    sdk.require(not args.with_swift_consumer or (args.with_c_consumer and os.uname().sysname == "Darwin"),
                "Swift qualification requires the installed C consumer on macOS")
    sdk.require(not args.with_kotlin_consumer or
                (args.with_c_consumer and args.kotlin_java_home is not None and args.kotlin_gradle_home is not None),
                "Kotlin qualification requires installed C packages and explicit JDK/Gradle installations")
    sdk.require(args.with_kotlin_consumer or (args.kotlin_java_home is None and args.kotlin_gradle_home is None),
                "Kotlin tool options require --with-kotlin-consumer")
    sdk.require(args.witness_openssl_prefix is None or args.with_c_consumer,
                "OpenSSL witness qualification requires the installed C consumer")
    sdk.validate_no_registry_credentials(os.environ)
    sdk.require(os.uname().sysname in {"Darwin", "Linux"}, "candidate host store requires Unix")
    commit, dirty = sdk.inspect_package_source(ROOT, allow_dirty=False)
    sdk.require(not dirty, "candidate package qualification requires clean source")
    before = source_inputs()
    pinned = sdk.snapshot(args.report)
    cohort = validate_report(pinned.data, args.report_sha256, pinned.sha256, before["rust_workspace_sha256"])
    output = fresh_output_directory(args.output, within=ROOT / "target", label="Continuity package evidence")
    sdk.require(shutil.disk_usage(ROOT).free >= 4 * 1024**3, "package qualification needs 4 GiB free")
    toolchain = args.toolchain_root.resolve(strict=True)
    tools = compiler_identity(toolchain)
    output.mkdir(parents=True, mode=0o700)
    outside = Path(tempfile.mkdtemp(prefix="qperiapt-continuity-package-")).resolve()
    sdk.require(not outside.is_relative_to(ROOT), "installed consumer must be outside checkout")
    sdk.write_json(output / "location.json", {"path": str(outside)})
    sdk.write_json(output / "sources-before.json", before)
    result = {"schema_version": 1, "kind": "qperiapt.continuity_candidate_package", "completed": False,
              "candidate_version": VERSION, "source_commit": commit, "source_inputs": before,
              "rust_report_sha256": pinned.sha256, "host_os": os.uname().sysname,
              "host_arch": os.uname().machine, "tool_binaries": tools,
              "requested_consumers": (["Rust", "C"] if args.with_c_consumer else ["Rust"])
                                     + (["Swift"] if args.with_swift_consumer else [])
                                     + (["Kotlin"] if args.with_kotlin_consumer else []),
              "release_claim_eligible": False, "publication_performed": False,
              "scope": "unpublished candidate and nine installed SDK archives; same-host Rust processes; no foreign bindings or cross-host qualification"}
    try:
        consumer = outside / "consumer"
        sdk.copy(ROOT / FIXTURE, consumer / "Cargo.toml")
        sdk.extract_recorded_crates(consumer, args.report.parent, cohort["crates"])
        home = outside / "cargo-home"
        home.mkdir(mode=0o700)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("CARGO_", "RUST", "DYLD_", "LD_", "QPERIAPT_"))}
        environment.update(CARGO_HOME=str(home), CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never",
                           # Reapply CI's fixed transfer policy after rejecting inherited Cargo overrides.
                           CARGO_HTTP_MULTIPLEXING="false",
                           CARGO_TARGET_DIR=str(outside / "build"), CARGO_INCREMENTAL="0",
                           RUSTC=str(toolchain / "bin/rustc"), RUSTDOC=str(toolchain / "bin/rustdoc"),
                           RUSTFLAGS="-D warnings", RUSTDOCFLAGS="-D warnings",
                           PATH=str(toolchain / "bin") + os.pathsep + environment.get("PATH", os.defpath))
        # Direct toolchain invocation needs the same compiler-private library
        # lookup that rustup supplies (not inherited user loader overrides).
        library_key = "DYLD_FALLBACK_LIBRARY_PATH" if os.uname().sysname == "Darwin" else "LD_LIBRARY_PATH"
        environment[library_key] = str(toolchain / "lib")
        result["compiler_library_path"] = {library_key: str(toolchain / "lib")}
        cargo = [str(toolchain / "bin/cargo")]

        def run(argv: list[str], label: str, cwd: Path = ROOT, *, env=None) -> bytes:
            return sdk.command(argv, output / label, cwd, environment=environment if env is None else env)

        compiler = run([str(toolchain / "bin/rustc"), "--version", "--verbose"], "rustc").decode()
        sdk.require(compiler.splitlines()[0] == "rustc 1.98.1 (48a229cea 2026-09-01)",
                    "candidate package compiler differs")
        result["rustc"] = compiler
        metadata = parse_strict_json_bytes(run([*cargo, "metadata", "--locked", "--offline", "--no-deps",
                                                "--format-version", "1"], "workspace-metadata"), label="SDK metadata")
        packages = sdk.classify(metadata)
        producer = outside / "source"
        for name in sdk.CONSUMER_CRATES:
            record = cohort["crates"][name]
            members = sdk.validate_archive(sdk.snapshot(args.report.parent / "crates" / record["file"]).data,
                                           name, packages[name], set(record["files"]))
            for relative, content in members.items():
                path = producer / "crates" / name / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as stream:
                    stream.write(content)
        candidate_source = producer / CANDIDATE.relative_to(ROOT)
        for path in CANDIDATE.rglob("*"):
            if path.is_file():
                sdk.copy(path, candidate_source / path.relative_to(CANDIDATE))
        manifest = ["--manifest-path", str(candidate_source / "Cargo.toml")]
        patches = []
        for name in sdk.CONSUMER_CRATES:
            path = producer / "crates" / name
            patches.extend(["--config", f"patch.crates-io.{name}.path=" + json.dumps(str(path))])
        run([*cargo, "fetch", "--locked", *manifest, *patches], "fetch",
            env=dict(environment, CARGO_NET_OFFLINE="false"))
        package_args = [*cargo, "package", *manifest, "--locked", "--offline", "--all-features", *patches]
        listed = run([*package_args, "--list"], "package-list").decode().splitlines()
        sdk.require(len(listed) == len(set(listed)), "duplicate candidate package members")
        run([*package_args, "-j", "2"], "package")
        streams = [(output / f"package.{suffix}").read_text() for suffix in ("stdout", "stderr")]
        sdk.validate_cargo_package_completion(NAME, streams)
        filename = f"{NAME}-{VERSION}.crate"
        archive = sdk.snapshot(outside / "build/package" / filename)
        files = validate_candidate(archive.data, set(listed))
        sdk.copy(archive.path, output / filename)
        result["archive"] = {"file": filename, "sha256": archive.sha256, "bytes": archive.size,
                             "files": sorted(files)}
        destination = consumer / "packages" / f"{NAME}-{VERSION}"
        for relative, content in files.items():
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(content)
        with (consumer / "Cargo.toml").open("a") as stream:
            stream.write(f'{NAME} = {{ path = "packages/{NAME}-{VERSION}" }}\n')
        sdk.copy(CANDIDATE / "Cargo.lock", consumer / "Cargo.lock")
        original = sdk.snapshot(CANDIDATE / "Cargo.lock").data
        resolved = parse_strict_json_bytes(run([*cargo, "metadata", "--offline", "--format-version", "1"],
                                               "consumer-metadata", consumer), label="installed candidate metadata")
        lock = sdk.snapshot(consumer / "Cargo.lock")
        result["resolution"] = verify_resolution(resolved, consumer, lock.data, original)
        result["execution"] = {}
        for profile in ("debug", "release"):
            evidence = outside / (profile + "-runtime")
            built = run([*cargo, "test", "--locked", "--offline", "-j", "2", "--no-run",
                         "--message-format=json", "--test", "owned_connection",
                         *(["--release"] if profile == "release" else [])], "build-" + profile, consumer)
            executable = built_test_binary(built, consumer, outside / "build" / profile)
            binary = sdk.snapshot(executable, maximum=256 * 1024**2)
            runtime_environment = {k: v for k, v in environment.items() if not k.startswith(("DYLD_", "LD_"))}
            tested = run([str(executable), "--nocapture"], "consumer-" + profile, consumer,
                         env=dict(runtime_environment, QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence)))
            result["execution"][profile] = verify_execution(tested, evidence, evidence.with_name(evidence.name + "-session-reopen"))
            sdk.require(sdk.snapshot(executable, maximum=256 * 1024**2).sha256 == binary.sha256,
                        "installed test executable changed during execution")
            result["execution"][profile]["binary"] = {"path": str(executable), "sha256": binary.sha256,
                                                       "bytes": binary.size}
        run([*cargo, "clippy", "--locked", "--offline", "--all-targets", "-j", "2", "--", "-D", "warnings"],
            "consumer-clippy", consumer)
        if args.with_c_consumer:
            from continuity_c_consumer import qualify_c
            result["c_consumer"] = qualify_c(outside, output, cargo, environment, files,
                                              original, args.report.parent, cohort["crates"],
                                              openssl_prefix=args.witness_openssl_prefix)
            result["scope"] = ("unpublished candidate and installed SDK archives; same-host Rust trace "
                               "and C client/server/recovery with local, signed-TCP and mutual-TLS witness profiles; "
                               "no independent witness engine, other foreign bindings or cross-host qualification")
        if args.with_swift_consumer:
            from continuity_swift_consumer import qualify_swift
            result["swift_consumer"] = qualify_swift(outside, output, result["c_consumer"], environment)
            result["scope"] = ("unpublished installed Rust/C connections and recovery, native and OpenSSL witness profiles, "
                               "and bidirectional Swift/Rust endpoints with local and explicit witness profiles; same host; no independent witness engine or cross-host qualification")
        if args.with_kotlin_consumer:
            from continuity_kotlin_consumer import qualify_kotlin
            result["kotlin_consumer"] = qualify_kotlin(outside, output, result["c_consumer"], environment,
                                                      args.kotlin_java_home, args.kotlin_gradle_home)
            result["scope"] = ("unpublished installed Rust/C connections, recovery and explicit witness profiles; "
                               + ("Swift local and witnessed profiles; " if args.with_swift_consumer else "")
                               + "Kotlin/JVM local and explicit witness client/server/recovery, constructor lifecycle and Java module admission; "
                               "same host and shared native engine; no independent engine or cross-host qualification; "
                               "Kotlin controller interruption uses explicit native cancel/join; "
                               "calibrated journal sync process interruptions and bounded prepared/in-flight owner GC under selected C2 frames; "
                               "other JVM implementations and automatic JVM cancellation qualification remain separate")
        sdk.require(sdk.snapshot(consumer / "Cargo.lock").sha256 == lock.sha256, "consumer lock changed")
        sdk.copy(consumer / "Cargo.lock", output / "consumer-Cargo.lock")
        sdk.verify_consumed_sources(consumer, args.report.parent, cohort["crates"])
        verify_candidate_files(destination, files)
        sdk.require(sdk.snapshot(output / filename).sha256 == archive.sha256, "candidate archive changed")
        sdk.require(sdk.snapshot(args.report).sha256 == pinned.sha256, "SDK report changed")
        sdk.require(before == source_inputs() and tools == compiler_identity(toolchain)
                    and sdk.inspect_package_source(ROOT, allow_dirty=False) == (commit, dirty),
                    "source or compiler identity changed")
        sdk.write_json(output / "sources-after.json", source_inputs())
        result.update(completed=True, sources_unchanged=True)
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "CONTINUITY_PACKAGE.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "report", "toolchain-root"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--report-sha256", required=True)
    parser.add_argument("--with-c-consumer", action="store_true",
                        help="also execute unpublished C client/server/cleanup, sync-interruption and signed TCP/mutual TLS witness profiles")
    parser.add_argument("--with-swift-consumer", action="store_true",
                        help="also package and execute the Swift owner with the installed C engine on macOS")
    parser.add_argument("--with-kotlin-consumer", action="store_true",
                        help="also package and execute Kotlin/JVM local/witnessed owners and constructor lifecycle with both installed C profiles")
    parser.add_argument("--kotlin-java-home", type=Path, help="explicit JDK 25 installation for the Kotlin consumer")
    parser.add_argument("--kotlin-gradle-home", type=Path, help="explicit Gradle 9.8.0 installation for the Kotlin consumer")
    parser.add_argument("--witness-openssl-prefix", type=Path,
                        help="also require bidirectional witness TLS interoperability with this OpenSSL installation (bin/include/lib)")
    result = qualify(parser.parse_args())
    print(json.dumps({key: result[key] for key in ("completed", "archive", "resolution", "execution",
                                                  "c_consumer", "swift_consumer", "kotlin_consumer", "release_claim_eligible") if key in result}, indent=2))


if __name__ == "__main__":
    main()
