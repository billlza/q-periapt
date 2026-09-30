"""C consumer extension of the same installed Continuity archive qualification."""
from __future__ import annotations

import os
from pathlib import Path
import re

import continuity_package as package
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

NAME = "q-periapt-continuity-c-consumer"
LIBRARY = "q_periapt_continuity_c_consumer"
FIXTURE = package.ROOT / "bindings/c/ContinuityPackageConsumer"
TEST = "c_client_owns_installed_connection_rekeys_and_reconciles_exact_delivery"
SCOPE = "unpublished C client to installed Rust peer; same host; local journal profile"
EXPORTS = {"qpc_owner_v1_" + name for name in
           ("open", "cancel", "close", "establish", "next_message", "send", "message_status", "rekey")}


def built_artifact(stdout: bytes, consumer: Path, build: Path, *, library: bool, unit: bool = False) -> Path:
    messages = [parse_strict_json_bytes(line, label="C consumer Cargo message") for line in stdout.splitlines()]
    target = LIBRARY if library or unit else "c_owner"
    items = [m for m in messages if m.get("reason") == "compiler-artifact" and m["target"]["name"] == target
             and (not unit or m.get("executable"))]
    sdk.require(len(items) == 1, "C consumer must build one exact target")
    item = items[0]
    expected = consumer / ("src/lib.rs" if library or unit else "tests/c_owner.rs")
    sdk.require(Path(item["target"]["src_path"]).resolve() == expected,
                "C consumer target came from another source")
    if library:
        suffix = ".dylib" if os.uname().sysname == "Darwin" else ".so"
        candidates = [Path(path) for path in item["filenames"] if path.endswith(suffix)]
        sdk.require(item["target"]["kind"] == ["cdylib", "rlib"] and len(candidates) == 1,
                    "C consumer shared-library output differs")
        binary = candidates[0].resolve(strict=True)
        sdk.require(binary.parent == build, "C shared library lies outside the selected profile")
    else:
        sdk.require(item["target"]["kind"] == (["cdylib", "rlib"] if unit else ["test"]) and item.get("executable"),
                    "C trace is not an executed test target")
        binary = Path(item["executable"]).resolve(strict=True)
        sdk.require(binary.parent == build / "deps", "C trace executable lies outside the selected profile")
    return binary


def verify_execution(stdout: bytes, directory: Path) -> dict:
    text = stdout.decode()
    passed = re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE)
    sdk.require(passed == [TEST] and re.search(
        r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;", text, re.MULTILINE),
        "installed C trace was not executed completely")
    report = parse_strict_json_bytes(sdk.snapshot(directory / "c-public-result.json").data,
                                    label="C connection execution")
    flags = {"completed", "unknown_delivery_reconciled", "pre_cancel_absent", "concurrent_close_busy",
             "cancelled_commit_reopened", "durable_sdk_revocation"}
    ids = {"session", "first_message", "post_rekey_message"}
    sdk.require(set(report) == flags | ids | {"schema_version", "scope", "network_rekeys",
                                           "independent_readbacks", "release_claim_eligible"},
                "C execution fields differ")
    sdk.require(all(report[field] is True for field in flags) and report["release_claim_eligible"] is False
                and report["scope"] == SCOPE, "C execution omitted a required outcome or changed its scope")
    for field, value in (("schema_version", 1), ("network_rekeys", 1), ("independent_readbacks", 3)):
        sdk.require(type(report[field]) is int and report[field] == value, f"C execution count differs: {field}")
    sdk.require(all(type(report[field]) is str and re.fullmatch(r"[0-9a-f]{64}", report[field])
                    and report[field] != "0" * 64 for field in ids)
                and report["first_message"] != report["post_rekey_message"], "C execution identities differ")
    sdk.require(bytes.fromhex(report["first_message"])[:8] == bytes(8)
                and bytes.fromhex(report["post_rekey_message"])[:8] == (1).to_bytes(8, "big"),
                "C application messages do not straddle the actual rekey epoch")
    readbacks = {}
    for field in ("first_message", "post_rekey_message"):
        leaf = "responder/application-" + report[field]
        received = sdk.snapshot(directory / leaf)
        sdk.require(received.data == bytes.fromhex(report["session"] + report[field])
                    + b"persisted before process exit", "C independent application readback differs")
        readbacks[leaf] = received.sha256
    sdk.require(len(list((directory / "responder").glob("application-*"))) == 2
                and not list((directory / "initiator").glob("application-*")),
                "C execution produced unexpected application effects")
    expected = {"self-check": "self-check-passed\n", "wrong-role": "rejected:211\n",
                "uncertain-send": "delivery-unknown-committed\n", "committed-status": "2\n",
                "exact-resend": "consumed\n", "rekey": "rekey-1-confirmed\n",
                "pre-cancel": "cancelled-absent\n", "concurrent-cancel": "cancelled-committed-reopened\n",
                "resume-cancelled": "consumed\n", "final-status": "3\n", "revoked-open": "rejected:603\n",
                "connect": report["session"] + "\n", "next": report["first_message"] + "\n",
                "next-after-rekey": report["post_rekey_message"] + "\n"}
    logs = {}
    for label, output in expected.items():
        for suffix, wanted in (("stdout", output.encode()), ("stderr", b"")):
            leaf = f"initiator/c-{label}.{suffix}"
            record = sdk.snapshot(directory / leaf, maximum=65536)
            sdk.require(record.data == wanted, "C command output or diagnostic differs")
            logs[leaf] = record.sha256
    return dict(report, application_readbacks=readbacks, command_logs=logs)


def verify_linkage(dependencies: str, loader: str, filename: str, *, darwin: bool) -> None:
    if darwin:
        names = [line.strip().split(" (", 1)[0] for line in dependencies.splitlines()[1:] if line.strip()]
        sdk.require("@rpath/" + filename in names and all(
            name == "@rpath/" + filename or name.startswith(("/usr/lib/", "/System/Library/Frameworks/"))
            for name in names), "C executable depends on an unqualified library path")
        paths = re.findall(r"cmd LC_RPATH\s+cmdsize \d+\s+path (.+?) \(offset", loader)
        sdk.require(paths == ["@loader_path"], "C executable does not use its installed sibling library")
    else:
        needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", dependencies)
        sdk.require(filename in needed and all("/" not in name for name in needed),
                    "C executable depends on an unqualified library path")
        paths = re.findall(r"\((?:RUNPATH|RPATH)\).*?\[(.*?)\]", loader)
        sdk.require(paths == ["$ORIGIN"], "C executable does not use its installed sibling library")


def qualify_c(outside: Path, output: Path, cargo: list[str], environment: dict,
              candidate_files: dict[str, bytes], original_lock: bytes,
              sdk_output: Path, records: dict) -> dict:
    result = {"completed": False, "scope": SCOPE, "release_claim_eligible": False, "execution": {}}
    try:
        return _qualify_c(outside, output, cargo, environment, candidate_files,
                          original_lock, sdk_output, records, result)
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "C_CONSUMER.json", result)


def _qualify_c(outside: Path, output: Path, cargo: list[str], environment: dict,
               candidate_files: dict[str, bytes], original_lock: bytes,
               sdk_output: Path, records: dict, result: dict) -> dict:
    consumer = outside / "c-consumer"
    for path in FIXTURE.rglob("*"):
        sdk.require(not path.is_symlink(), "C consumer fixture contains a symlink")
        if path.is_file():
            sdk.copy(path, consumer / path.relative_to(FIXTURE))
    template_hashes = {p.relative_to(consumer).as_posix(): sdk.snapshot(p).sha256
                       for p in consumer.rglob("*") if p.is_file()}
    sdk.extract_recorded_crates(consumer, sdk_output, records)
    destination = consumer / "packages" / f"{package.NAME}-{package.VERSION}"
    for relative, data in candidate_files.items():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    with (consumer / "Cargo.toml").open("a") as stream:
        stream.write(f'{package.NAME} = {{ path = "packages/{package.NAME}-{package.VERSION}" }}\n')
    manifest_hash = sdk.snapshot(consumer / "Cargo.toml").sha256
    (consumer / "Cargo.lock").write_bytes(original_lock)
    env = dict(environment)
    for key in ("CC", "CXX", "AR", "LD", "CPP", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
                "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "LIBRARY_PATH",
                "SDKROOT", "MACOSX_DEPLOYMENT_TARGET"):
        env.pop(key, None)
    def run(argv, label, cwd=consumer, *, runtime=None):
        return sdk.command(argv, output / ("c-" + label), cwd, environment=env if runtime is None else runtime)
    metadata = parse_strict_json_bytes(run([*cargo, "metadata", "--offline", "--format-version", "1"],
                                         "metadata"), label="C installed dependency resolution")
    lock = sdk.snapshot(consumer / "Cargo.lock")
    result["resolution"] = package.verify_resolution(metadata, consumer, lock.data, original_lock, consumer_name=NAME)
    darwin = os.uname().sysname == "Darwin"
    cc = Path(run(["/usr/bin/xcrun", "--sdk", "macosx", "--find", "clang"], "cc-path").decode().strip()) if darwin else Path("/usr/bin/cc")
    cc = cc.resolve(strict=True)
    compiler = sdk.snapshot(cc, maximum=256 * 1024**2)
    result["compiler"] = {"path": str(cc), "sha256": compiler.sha256,
                          "version": run([str(cc), "--version"], "cc-version").decode()}
    platform_flags = []
    if darwin:
        # A resolved toolchain clang does not supply xcrun's implicit SDKROOT.
        # Select the host SDK explicitly after discarding inherited build flags.
        platform_sdk = Path(run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
                                "sdk-path").decode().strip()).resolve(strict=True)
        sdk_settings = sdk.snapshot(platform_sdk / "SDKSettings.json")
        result["compiler"]["platform_sdk"] = {"path": str(platform_sdk),
                                               "settings_sha256": sdk_settings.sha256}
        platform_flags = ["-isysroot", str(platform_sdk)]
    filename = "lib" + LIBRARY + (".dylib" if darwin else ".so")
    linker_name = ("-Wl,-install_name,@rpath/" if darwin else "-Wl,-soname,") + filename
    for profile in ("debug", "release"):
        extra = ["--release"] if profile == "release" else []
        build = outside / "build" / profile
        built = run([*cargo, "rustc", "--locked", "--offline", "--lib", "--message-format=json", "-j", "2",
                     *extra, "--", "-C", "link-arg=" + linker_name], "library-" + profile)
        library = built_artifact(built, consumer, build, library=True)
        installed = outside / ("c-installed-" + profile)
        installed.mkdir(mode=0o700)
        sdk.copy(library, installed / filename)
        executable = installed / "qpc-c-client"
        run([str(cc), *platform_flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-pthread",
             *( ["-O2"] if profile == "release" else ["-O0", "-g"] ),
             str(consumer / "client.c"), "-I", str(consumer), "-L", str(installed), "-l" + LIBRARY,
             "-Wl,-rpath," + ("@loader_path" if darwin else "$ORIGIN"), "-o", str(executable)], "compile-" + profile)
        symbols = run(["/usr/bin/nm", *( ["-gU"] if darwin else ["-D", "--defined-only"] ),
                       str(installed / filename)], "exports-" + profile).decode()
        names = {line.split()[-1].removeprefix("_") if darwin else line.split()[-1]
                 for line in symbols.splitlines() if line.strip()}
        sdk.require(names == EXPORTS, "C consumer exported symbol set differs")
        if darwin:
            dependencies = run(["/usr/bin/otool", "-L", str(executable)], "dependencies-" + profile).decode()
            loader = run(["/usr/bin/otool", "-l", str(executable)], "loader-" + profile).decode()
        else:
            dependencies = run(["/usr/bin/readelf", "-d", str(executable)], "dependencies-" + profile).decode()
            loader = dependencies
        verify_linkage(dependencies, loader, filename, darwin=darwin)
        client_identity = sdk.snapshot(executable, maximum=256 * 1024**2)
        library_identity = sdk.snapshot(installed / filename, maximum=256 * 1024**2)
        built = run([*cargo, "test", "--locked", "--offline", "--test", "c_owner", "--no-run",
                     "--message-format=json", "-j", "2", *extra], "trace-build-" + profile)
        runtime = {k: v for k, v in env.items() if not k.startswith(("DYLD_", "LD_"))}
        unit_build = run([*cargo, "test", "--locked", "--offline", "--lib", "--no-run", "--message-format=json",
                          "-j", "2", *extra], "admission-build-" + profile)
        unit_test = built_artifact(unit_build, consumer, build, library=False, unit=True)
        unit_identity = sdk.snapshot(unit_test, maximum=256 * 1024**2)
        checked = run([str(unit_test)], "admission-" + profile, runtime=runtime)
        sdk.require(re.search(rb"test tests::full_call_budget_preserves_drain_and_returns_capacity_after_failure \.\.\. ok",
                              checked) and re.search(rb"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", checked),
                    "C admission budget and drain contract did not execute")
        trace = built_artifact(built, consumer, build, library=False)
        trace_identity = sdk.snapshot(trace, maximum=256 * 1024**2)
        evidence = outside / ("c-" + profile + "-runtime")
        runtime.update(QPERIAPT_C_OWNER_CLIENT=str(executable), QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
        tested = run([str(trace), "--exact", TEST, "--nocapture"], "trace-" + profile, runtime=runtime)
        result["execution"][profile] = verify_execution(tested, evidence)
        binaries = {}
        for name, path, identity in (("C_client", executable, client_identity),
                                     ("C_library", installed / filename, library_identity),
                                     ("Rust_admission", unit_test, unit_identity),
                                     ("Rust_trace", trace, trace_identity)):
            sdk.require(sdk.snapshot(path, maximum=256 * 1024**2).sha256 == identity.sha256,
                        "C qualification executable or library changed during execution")
            binaries[name] = {"path": str(path), "sha256": identity.sha256, "bytes": identity.size}
        result["execution"][profile]["binaries"] = binaries
    run([*cargo, "clippy", "--locked", "--offline", "--all-targets", "-j", "2", "--", "-D", "warnings"], "clippy")
    sdk.require(sdk.snapshot(cc, maximum=256 * 1024**2).sha256 == compiler.sha256
                and sdk.snapshot(consumer / "Cargo.lock").sha256 == lock.sha256
                and sdk.snapshot(consumer / "Cargo.toml").sha256 == manifest_hash,
                "C compiler or consumer resolution changed")
    if darwin:
        sdk.require(sdk.snapshot(platform_sdk / "SDKSettings.json").sha256 == sdk_settings.sha256,
                    "C platform SDK settings changed")
    for relative, digest in template_hashes.items():
        if relative != "Cargo.toml":
            sdk.require(sdk.snapshot(consumer / relative).sha256 == digest, "C consumer input changed")
    actual = set()
    for path in consumer.rglob("*"):
        relative = path.relative_to(consumer)
        sdk.require(not path.is_symlink(), "C consumer contains a symlink")
        if path.is_file() and relative.parts[0] != "packages":
            actual.add(relative.as_posix())
    sdk.require(actual == template_hashes.keys() | {"Cargo.lock"}, "C consumer file inventory changed")
    package.verify_candidate_files(destination, candidate_files)
    sdk.verify_consumed_sources(consumer, sdk_output, records)
    sdk.copy(consumer / "Cargo.lock", output / "c-consumer-Cargo.lock")
    result["completed"] = True
    return result
