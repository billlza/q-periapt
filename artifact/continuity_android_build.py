#!/usr/bin/env python3
"""Compile the selected Continuity sources into the formal arm64 Android capsule.

The native commands are the retained successful native02 recipe, with explicit
current-source/package/tool inputs. Build receipts describe this execution;
the separate distribution reader reopens its AAR and Maven outputs.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import shlex
import tempfile
import time

import continuity_android_distribution as distribution
import continuity_package as package
import rust_sdk_profile as sdk
import third_party_licenses
from bounded_process import capture_output, TimeoutPolicy
from evidence_io import fresh_output_directory, parse_strict_json_bytes

ROOT = Path(__file__).resolve().parent.parent
ENGINE = "research/continuity-identity-candidate"
CONSUMER_NAME = "q-periapt-continuity-c-consumer"
REQUIRED_FEATURES = frozenset({"connection-tls", "control-tls", "anchor-tls"})
RUSTC = "rustc 1.98.1 (48a229cea 2026-09-01)"
CLIPPY = "clippy 0.1.98 (48a229ceae 2026-09-01)"
HARDENING = ("--no-undefined", "--fatal-warnings", "-z,relro", "-z,now",
             "-z,max-page-size=16384", "-z,common-page-size=16384")
MAX_TOOL = 512 * 1024**2
BUILD_SOURCE_PREFIXES = (ENGINE + "/", distribution.CONSUMER + "/", distribution.ADAPTER + "/jni/")
SOURCE_LIMIT = 32 * 1024**2
COMMAND_TIMEOUTS = {"package": 1800, "native-build": 1800, "clippy": 1800, "fetch": 900,
                    "workspace-metadata": 300, "consumer-metadata": 300, "package-list": 300,
                    "jni-build": 300, "javac": 300}


def run_command(argv: list[str], prefix: Path, cwd: Path, *, environment: dict) -> bytes:
    """Retain bounded streams and a typed receipt even when a child times out."""
    timeout = COMMAND_TIMEOUTS.get(prefix.name, 60)
    record = {"argv": argv, "cwd": str(cwd), "timeout_seconds": timeout,
              "returncode": None, "completed": False}
    failure = None
    started = time.monotonic()
    try:
        with prefix.with_suffix(".stdout").open("xb") as stdout, prefix.with_suffix(".stderr").open("xb") as stderr:
            with contextlib.chdir(cwd):
                result = capture_output(argv, timeout_seconds=timeout, maximum_stdout_bytes=16 * 1024**2,
                    maximum_stderr_bytes=16 * 1024**2, environment=environment,
                    stdout_sink=stdout.write, stderr_sink=stderr.write,
                    timeout_policy=TimeoutPolicy.LONG_ANALYSIS if timeout > 900 else TimeoutPolicy.STANDARD)
        record["returncode"] = result.returncode
        sdk.require(result.returncode == 0, f"command failed ({result.returncode}): {prefix}.stderr")
        sdk.validate_cargo_output(prefix.name, [result.stdout.decode(), result.stderr.decode()])
        record["completed"] = True
        return result.stdout
    except BaseException as error:
        failure = error
        record.update(failure=str(error)[:4096], error_type=type(error).__name__,
                      failure_kind=getattr(error, "kind", "command_failure"),
                      cleanup_ambiguous=getattr(error, "cleanup_ambiguous", False))
        raise
    finally:
        record["elapsed_seconds"] = round(time.monotonic() - started, 6)
        try:
            sdk.write_json(prefix.with_suffix(".json"), record)
        except BaseException as evidence_error:
            if failure is None:
                raise
            failure.add_note("could not retain Android command receipt: " + str(evidence_error))


def capture_sources(paths: list[str], contract: dict) -> dict[str, bytes]:
    """Bind every copied input to one tracked inventory and exact consumed bytes."""
    selected = dict(contract["pinned"])
    for relative in paths:
        if relative.startswith(BUILD_SOURCE_PREFIXES) and relative not in selected:
            selected[relative] = sdk.snapshot(ROOT / relative, maximum=16 * 1024**2).data
    sdk.require(sum(map(len, selected.values())) <= SOURCE_LIMIT, "Android build sources exceed bounds")
    sdk.require({ENGINE + "/Cargo.toml", ENGINE + "/Cargo.lock", ENGINE + "/src/lib.rs",
                 distribution.CONSUMER + "/Cargo.toml", distribution.CONSUMER + "/src/lib.rs",
                 distribution.ADAPTER + "/jni/continuity_jni.c"} <= selected.keys(),
                "Android build source inventory is incomplete")
    return selected


def write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o644)


def copy_sources(sources: dict[str, bytes], prefix: str, destination: Path) -> dict[str, bytes]:
    members = {name.removeprefix(prefix + "/"): data for name, data in sources.items()
               if name.startswith(prefix + "/")}
    sdk.require(members, "selected source directory is empty")
    for relative, data in members.items():
        write_file(destination / relative, data)
    return members


def directory_files(directory: Path, *, maximum: int = SOURCE_LIMIT) -> dict[str, bytes]:
    files, total = {}, 0
    for path in sorted(directory.rglob("*")):
        sdk.require(not path.is_symlink(), "build directory contains a symlink")
        if path.is_dir():
            continue
        data = sdk.snapshot(path, maximum=maximum).data
        total += len(data)
        sdk.require(total <= maximum, "build directory exceeds bounds")
        files[path.relative_to(directory).as_posix()] = data
    return files


def verify_candidate_snapshot(files: dict[str, bytes], sources: dict[str, bytes]) -> None:
    sdk.require(files["Cargo.toml.orig"] == sources[ENGINE + "/Cargo.toml"],
                "packaged engine manifest differs from consumed source snapshot")
    for name, data in files.items():
        if name not in {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}:
            sdk.require(sources.get(ENGINE + "/" + name) == data,
                        "packaged engine differs from consumed source snapshot: " + name)


def build_environment(inherited: dict, *, outside: Path, toolchain: Path,
                      ndk_tools: Path, account_root: Path) -> tuple[dict, list[str]]:
    """Discard inherited compiler options and select the corrected native02 recipe."""
    sdk.require(account_root.is_absolute() and account_root != Path("/"), "account remap root is invalid")
    environment = {key: value for key, value in inherited.items() if not key.startswith(
        ("CARGO_", "RUST", "GIT_", "DYLD_", "LD_", "JAVA_", "JDK_", "GRADLE_", "KOTLIN_",
         "ANDROID_", "QPC_", "QPERIAPT_", "CC_", "CXX_", "AR_", "CFLAGS_", "CXXFLAGS_"))}
    for key in ("CC", "CXX", "AR", "LD", "CPP", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
                "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "LIBRARY_PATH",
                "SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "OPENSSL_CONF", "OPENSSL_CONF_INCLUDE",
                "OPENSSL_MODULES", "OPENSSL_ENGINES", "SSL_CERT_FILE", "SSL_CERT_DIR",
                "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH", "RUSTUP_TOOLCHAIN",
                "HOST_CC", "HOST_CXX", "HOST_AR", "HOST_CFLAGS", "HOST_CXXFLAGS",
                "TARGET_CC", "TARGET_CXX", "TARGET_AR", "TARGET_CFLAGS", "TARGET_CXXFLAGS",
                "CRATE_CC_NO_DEFAULTS", "CROSS_COMPILE", "CXXSTDLIB", "RANLIB", "ARFLAGS"):
        environment.pop(key, None)
    # The account-root map closes the rustls panic-location leak observed in the
    # first historical build. Both maps apply to Rust and dependency C sources.
    remaps = ((outside, "/qperiapt/installed"), (account_root, "/qperiapt-build/user"))
    remap_c = [flag + "=" + str(path) + "=" + replacement for path, replacement in remaps
               for flag in ("-ffile-prefix-map", "-fdebug-prefix-map", "-fmacro-prefix-map")]
    rust_flags = ["-Dwarnings", *("--remap-path-prefix=" + str(path) + "=" + replacement
                                  for path, replacement in remaps)]
    clang = ndk_tools / "bin/aarch64-linux-android23-clang"
    environment.update(CARGO_HOME=str(outside / "cargo-home"), CARGO_NET_OFFLINE="true",
        CARGO_HTTP_MULTIPLEXING="false", CARGO_NET_RETRY="10", CARGO_TERM_COLOR="never",
        CARGO_INCREMENTAL="0", CARGO_TARGET_DIR=str(outside / "build"),
        CARGO=str(toolchain / "bin/cargo"), RUSTC=str(toolchain / "bin/rustc"),
        RUSTDOC=str(toolchain / "bin/rustdoc"), CARGO_ENCODED_RUSTFLAGS="\x1f".join(rust_flags),
        RUSTDOCFLAGS="-D warnings", DYLD_FALLBACK_LIBRARY_PATH=str(toolchain / "lib"),
        CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=str(clang), CC_aarch64_linux_android=str(clang),
        AR_aarch64_linux_android=str(ndk_tools / "bin/llvm-ar"),
        CC_SHELL_ESCAPED_FLAGS="1", CFLAGS=shlex.join(remap_c),
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null",
        GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0",
        PATH=str(toolchain / "bin") + os.pathsep + environment.get("PATH", os.defpath),
        LC_ALL="C", LANG="C")
    return environment, remap_c


def tool_identity(toolchain: Path, ndk: Path, java_home: Path) -> tuple[dict, Path]:
    sdk.require(distribution.elf.verify_ndk_r29(ndk) == distribution.NDK, "Android NDK revision differs")
    ndk_tools = distribution.elf.find_ndk_toolchain(ndk)
    files = {"rust/" + name: toolchain / "bin" / name
             for name in ("cargo", "rustc", "rustdoc", "cargo-clippy", "clippy-driver")}
    files.update({"ndk/" + name: ndk_tools / "bin" / name for name in (
        "aarch64-linux-android23-clang", "clang", "ld.lld", "llvm-ar", "llvm-nm", "llvm-readelf", "llvm-strip")})
    files.update({"java/" + name: java_home / "bin" / name for name in ("java", "javac")})
    for path in files.values():
        sdk.require(os.access(path, os.X_OK), "required build tool is not executable: " + str(path))
    files.update({"ndk/source.properties": ndk / "source.properties",
                  "ndk/jni.h": ndk_tools / "sysroot/usr/include/jni.h",
                  "java/release": java_home / "release", "java/modules": java_home / "lib/modules"})
    standard = toolchain / "lib/rustlib" / distribution.TARGET / "lib"
    sdk.require(standard.is_dir() and not standard.is_symlink(), "selected Rust Android standard library is missing")
    std_paths = sorted(standard.rglob("*"))
    sdk.require(all(not path.is_symlink() for path in std_paths), "Rust Android standard library contains a symlink")
    std_files = [path for path in std_paths if not path.is_dir()]
    sdk.require(std_files and any(p.name.startswith("libstd-") and p.suffix == ".rlib" for p in std_files),
                "selected Rust toolchain lacks the Android standard library")
    files.update({"rust-android-std/" + p.relative_to(standard).as_posix(): p for p in std_files})
    return {name: {"path": str(path.resolve(strict=True)),
                   "sha256": sdk.snapshot(path.resolve(strict=True), maximum=MAX_TOOL).sha256}
            for name, path in sorted(files.items())}, ndk_tools


def native_commands(toolchain: Path, ndk_tools: Path, consumer: Path, adapter: Path,
                    native: Path, remap_c: list[str]) -> dict[str, list[str]]:
    jni_sources = sorted((adapter / "jni").glob("*.c"))
    sdk.require(jni_sources and adapter / "jni/continuity_jni.c" in jni_sources, "JNI source list is incomplete")
    hardening = ["-Wl," + flag for flag in HARDENING]
    cargo = [str(toolchain / "bin/cargo"), "rustc", "--lib", "--release", "--locked", "--offline",
             "--target", distribution.TARGET, "--message-format=json", "-j", "2", "--"]
    for flag in [*hardening, "-Wl,-soname," + distribution.C_LIBRARY]:
        cargo += ["-C", "link-arg=" + flag]
    return {
        "native-build": cargo,
        "native-strip": [str(ndk_tools / "bin/llvm-strip"), "--strip-unneeded", str(native / distribution.C_LIBRARY)],
        "jni-build": [str(ndk_tools / "bin/aarch64-linux-android23-clang"), "-std=c11", "-Wall", "-Wextra",
            "-Werror", "-Wpedantic", "-shared", "-fPIC", "-fvisibility=hidden", *remap_c,
            "-I" + str(consumer), "-I" + str(ndk_tools / "sysroot/usr/include"), *map(str, jni_sources),
            "-L" + str(native), "-lq_periapt_continuity_c_consumer", *hardening,
            "-Wl,-soname," + distribution.JNI_LIBRARY, "-o", str(native / distribution.JNI_LIBRARY)],
        "jni-strip": [str(ndk_tools / "bin/llvm-strip"), "--strip-unneeded", str(native / distribution.JNI_LIBRARY)],
        "clippy": [str(toolchain / "bin/cargo-clippy"), "clippy", "--lib", "--release", "--locked", "--offline",
            "--target", distribution.TARGET, "-j", "2", "--", "-D", "warnings"],
    }


def verify_tool_versions(run, toolchain: Path, ndk_tools: Path, java_home: Path) -> dict:
    rustc = run([str(toolchain / "bin/rustc"), "-vV"], "rustc").decode()
    sdk.require(rustc.splitlines()[0] == RUSTC and "host: aarch64-apple-darwin" in rustc.splitlines(),
                "Android producer requires the selected Apple Silicon Rust compiler")
    clippy = {name: run([str(toolchain / "bin" / name), *(["clippy"] if name == "cargo-clippy" else []),
                        "--version"], name + "-version").decode().strip()
              for name in ("cargo-clippy", "clippy-driver")}
    sdk.require(all(value == CLIPPY for value in clippy.values()), "Android Clippy compiler differs")
    java = {name: run([str(java_home / "bin" / name), "--version"], name + "-version").decode().strip()
            for name in ("java", "javac")}
    sdk.require(re.match(r"(?:openjdk|java) 25(?:[.\s]|$)", java["java"]) is not None
                and re.match(r"javac 25(?:[.\s]|$)", java["javac"]) is not None,
                "Android classes require Java 25")
    return {"rustc": rustc, "clippy": clippy, "java": java,
            "clang": run([str(ndk_tools / "bin/aarch64-linux-android23-clang"), "--version"], "clang").decode()}


def compile_classes(run, java_home: Path, outside: Path, contract: dict) -> tuple[bytes, dict]:
    java_source, classes = outside / "java-source", outside / "classes"
    classes.mkdir(mode=0o700)
    for name, data in contract["java"].items():
        write_file(java_source / name, data)
    run([str(java_home / "bin/javac"), "--release", "11", "-Xlint:all", "-Werror", "-d", str(classes),
         *(str(java_source / name) for name in sorted(contract["java"]))], "javac")
    members = directory_files(classes, maximum=distribution.MAX_ENTRY)
    verified = distribution.verify_classes(members, contract["java"], contract["bridge"])
    sdk.require(directory_files(java_source) == contract["java"], "Java compiler changed copied source bytes")
    return distribution.zip_bytes(members), verified


def selection_and_receipts(output: Path, source: dict, native_package_id: str, *,
                           native_details: dict, classes_details: dict) -> tuple[dict, bytes]:
    refs = {}
    for role, name in (("c", "native/" + distribution.C_LIBRARY), ("jni", "native/" + distribution.JNI_LIBRARY),
                       ("classes", "classes.jar"), ("licenses", "licenses.zip")):
        refs[role] = distribution.reference(name, sdk.snapshot(output / name, maximum=distribution.MAX_ENTRY).data)
    receipts = {}
    for role, name, artifacts, tools, details in (
        ("native", package.NAME, {key: refs[key] for key in ("c", "jni", "licenses")},
         {"rust": "1.98.1", "ndk": distribution.NDK, "target": distribution.TARGET}, native_details),
        ("classes", distribution.NAME, {"classes": refs["classes"]}, {"java_major": 25, "release": 11}, classes_details),
    ):
        receipt = {"schema_version": 1, "kind": "qperiapt.continuity_android_" + role + "_build",
            "completed": True, "source": source, "package": {"name": name, "version": distribution.VERSION},
            "artifacts": artifacts, "toolchain": tools, "details": details,
            "art_executed": False, "physical_device_executed": False, "publication_performed": False}
        data = distribution.canonical(receipt)
        filename = role + "-build.json"
        write_file(output / filename, data)
        receipts[role + "_receipt"] = distribution.reference(filename, data)
    selection = {"schema_version": 1, "kind": distribution.INPUT_KIND, "name": distribution.NAME,
        "version": distribution.VERSION, "abi": distribution.ABI, "target": distribution.TARGET,
        "source": source, "native_package_id": native_package_id, "native": {key: refs[key] for key in ("c", "jni")},
        "classes": refs["classes"], "licenses": refs["licenses"], **receipts}
    data = distribution.canonical(selection)
    distribution.validate_selection(data, output, expected_sha256=distribution.sha(data), source=source)
    write_file(output / "INPUT_SELECTION.json", data)
    return selection, data


def build(args: argparse.Namespace) -> dict:
    sdk.validate_no_registry_credentials(os.environ)
    sdk.require((os.uname().sysname, os.uname().machine) == ("Darwin", "arm64"),
                "selected Android build host is macOS arm64")
    sdk.require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", args.native_package_id) is not None,
                "native dependency row ID is invalid")
    sdk.require(re.fullmatch(r"[1-9][0-9]{0,19}", args.sdk_run_id) is not None,
                "selected SDK workflow run ID is invalid")
    paths = distribution.repository_paths(ROOT)
    source = distribution.source_identity(paths=paths)
    sdk.require(source == {"commit": args.source_commit, "tree": args.source_tree,
                          "tree_sha256": args.source_tree_sha256}, "independently selected build source differs")
    contract = distribution.source_contract(paths)
    sources = capture_sources(paths, contract)
    sdk.require(distribution.source_identity(paths=paths, pinned_files=sources) == source,
                "captured build source differs from selected checkout")
    output = fresh_output_directory(args.output, within=ROOT / "target", label="Continuity Android build")
    output.mkdir(parents=True, mode=0o700)
    report = {"schema_version": 1, "kind": "qperiapt.continuity_android_build", "completed": False,
        "source": source, "native_compilation_executed": False, "java_compilation_executed": False,
        "art_executed": False, "physical_device_executed": False, "publication_performed": False,
        "release_claim_eligible": False}
    try:
        toolchain, ndk, java_home = (p.resolve(strict=True) for p in (args.toolchain_root, args.ndk, args.java_home))
        tools, ndk_tools = tool_identity(toolchain, ndk, java_home)
        pinned, cohort = package.admit_sdk_report(args.report, args.report_sha256,
            sdk.source_identity()["rust_workspace_sha256"], source["commit"], output, sdk_run_id=args.sdk_run_id)
        report.update(sdk_report_sha256=pinned.sha256, tools=tools)
        outside = Path(tempfile.mkdtemp(prefix="qperiapt-android-build-")).resolve()
        sdk.require(not outside.is_relative_to(ROOT), "Android build must run outside checkout")
        (outside / "cargo-home").mkdir(mode=0o700)
        logs = output / "commands"; logs.mkdir(mode=0o700)
        sdk.write_json(output / "LOCATION.json", {"path": str(outside)})
        environment, remap_c = build_environment(os.environ, outside=outside, toolchain=toolchain,
                                               ndk_tools=ndk_tools, account_root=Path.home().resolve())
        command_refs = {}

        def run(argv, label, cwd=ROOT, *, env=None):
            sdk.require(label not in command_refs, "build command label was reused")
            if argv[0] == "git":
                argv = ["/usr/bin/git", "--git-dir=" + str(ROOT / ".git"), "--work-tree=" + str(ROOT),
                        "-c", "safe.directory=" + str(ROOT), "-c", "core.fsmonitor=false",
                        "-c", "core.hooksPath=/dev/null", *argv[1:]]
            stdout = run_command(argv, logs / label, cwd, environment=environment if env is None else env)
            if label == "candidate-sources":
                sdk.require(stdout.decode().splitlines() == [name for name in paths if name.startswith(ENGINE + "/")],
                            "candidate package source inventory differs from captured checkout")
            command_refs[label] = {suffix: distribution.reference("commands/" + label + "." + suffix,
                sdk.snapshot(logs / (label + "." + suffix)).data) for suffix in ("json", "stdout", "stderr")}
            return stdout

        report["versions"] = verify_tool_versions(run, toolchain, ndk_tools, java_home)
        cargo = [str(toolchain / "bin/cargo")]
        metadata = parse_strict_json_bytes(run([*cargo, "metadata", "--locked", "--offline", "--no-deps",
                                               "--format-version", "1"], "workspace-metadata"), label="SDK metadata")
        packages = sdk.classify(metadata)
        record, candidate = package.package_candidate(cargo, outside / "producer", outside / "producer-build",
            args.report.parent, cohort, packages, logs, run, environment)
        verify_candidate_snapshot(candidate, sources)
        report["candidate_archive"] = record
        consumer, adapter = outside / "c-consumer", outside / "android-source"
        fixture = copy_sources(sources, distribution.CONSUMER, consumer)
        adapter_files = copy_sources(sources, distribution.ADAPTER, adapter)
        sdk.extract_recorded_crates(consumer, args.report.parent, cohort["crates"])
        destination = consumer / "packages" / (package.NAME + "-" + package.VERSION)
        for relative, data in candidate.items():
            write_file(destination / relative, data)
        with (consumer / "Cargo.toml").open("a", encoding="utf-8") as stream:
            stream.write(f'{package.NAME} = {{ path = "packages/{package.NAME}-{package.VERSION}" }}\n')
        manifest = sdk.snapshot(consumer / "Cargo.toml").data
        original_lock = sources[ENGINE + "/Cargo.lock"]
        write_file(consumer / "Cargo.lock", original_lock)
        metadata = parse_strict_json_bytes(run([*cargo, "metadata", "--offline", "--format-version", "1",
            "--filter-platform", distribution.TARGET], "consumer-metadata", consumer), label="Android installed graph")
        lock = sdk.snapshot(consumer / "Cargo.lock").data
        report["resolution"] = package.verify_resolution(metadata, consumer, lock, original_lock,
            consumer_name=CONSUMER_NAME, required_features=REQUIRED_FEATURES)
        native = output / "native"; native.mkdir(mode=0o700)
        commands = native_commands(toolchain, ndk_tools, consumer, adapter, native, remap_c)
        report["native_compilation_executed"] = True
        run(commands["native-build"], "native-build", consumer)
        sdk.copy(outside / "build" / distribution.TARGET / "release" / distribution.C_LIBRARY,
                 native / distribution.C_LIBRARY, maximum=distribution.MAX_ENTRY)
        for label in ("native-strip", "jni-build", "jni-strip", "clippy"):
            run(commands[label], label, consumer)
        native_verified = {role: distribution.verify_native(native / name, role=role,
            tools=distribution.native_tools(ndk), exports=contract["exports"])
            for role, name in (("c", distribution.C_LIBRARY), ("jni", distribution.JNI_LIBRARY))}
        for name in (distribution.C_LIBRARY, distribution.JNI_LIBRARY):
            distribution.scan_release_file(native / name, forbidden_text=(str(ROOT), str(outside), str(Path.home().resolve())))
        report["java_compilation_executed"] = True
        jar, classes_verified = compile_classes(run, java_home, outside, contract)
        sdk.require((logs / "javac.stderr").read_bytes() == b"", "Java compiler emitted diagnostics")
        write_file(output / "classes.jar", jar)
        notices = outside / "notices"; notices.mkdir(mode=0o700)
        licenses = third_party_licenses.collect(consumer, notices, distribution.TARGET,
            root_package=CONSUMER_NAME, resolved_metadata=metadata)
        third_party_licenses.verify(notices, expected_target=distribution.TARGET, root_package=CONSUMER_NAME)
        write_file(output / "licenses.zip", distribution.zip_bytes(directory_files(notices)))
        # All installed Rust/C/JNI/Java inputs and exact tools are reread before
        # any successful compilation receipt can be issued.
        sdk.verify_consumed_sources(consumer, args.report.parent, cohort["crates"])
        package.verify_candidate_files(destination, candidate)
        package.verify_candidate_archive(logs, record)
        for name, data in fixture.items():
            sdk.require(sdk.snapshot(consumer / name).data == (manifest if name == "Cargo.toml" else data),
                        "C compiler changed installed source: " + name)
        sdk.require(sdk.snapshot(consumer / "Cargo.lock").data == lock, "Android build changed resolved lockfile")
        sdk.require(directory_files(adapter) == adapter_files, "JNI compiler changed copied source bytes")
        sdk.require(sdk.snapshot(args.report).data == pinned.data, "selected SDK report changed during build")
        sdk.require(tool_identity(toolchain, ndk, java_home)[0] == tools, "selected build tools changed")
        sdk.require(distribution.source_identity(paths=paths, pinned_files=sources) == source,
                    "consumed build sources differ from selected checkout")
        sdk.copy(consumer / "Cargo.lock", output / "consumer-Cargo.lock")
        native_details = {"compile_api": 23, "verification": native_verified, "resolution": report["resolution"],
            "sdk_report_sha256": pinned.sha256, "candidate_archive": record, "tools": tools,
            "licenses": {"packages": len(licenses["packages"])}, "clippy_completed": True,
            "commands": command_refs, "sources": {name: distribution.sha(data) for name, data in sorted(sources.items())}}
        classes_details = {"verification": classes_verified, "java": report["versions"]["java"],
            "source_files": {name: distribution.sha(data) for name, data in sorted(contract["java"].items())},
            "javac": command_refs["javac"], "tools": {name: row for name, row in tools.items() if name.startswith("java/")}}
        _, selection_data = selection_and_receipts(output, source, args.native_package_id,
            native_details=native_details, classes_details=classes_details)
        shared = dict(inputs=output, selection="INPUT_SELECTION.json", selection_sha256=distribution.sha(selection_data),
            source_commit=source["commit"], source_tree=source["tree"], source_tree_sha256=source["tree_sha256"], ndk=ndk)
        capsule = output / "capsule"
        produced = distribution.execute(argparse.Namespace(command="produce", output=capsule, capsule=None,
            distribution_sha256=None, **shared))
        receipt = sdk.snapshot(capsule / "DISTRIBUTION.json")
        reopened = distribution.execute(argparse.Namespace(command="verify", output=None, capsule=capsule,
            distribution_sha256=receipt.sha256, **shared))
        sdk.require(produced["aar"] == reopened["aar"], "independently reopened Android AAR differs")
        sdk.require(distribution.source_identity(paths=paths, pinned_files=sources) == source,
                    "source changed during Android distribution verification")
        report.update(completed=True, sources_unchanged=True, input_selection_sha256=distribution.sha(selection_data),
            distribution_receipt_sha256=receipt.sha256, aar=produced["aar"], distribution_reopened=True,
            native_verification=native_verified, classes_verification=classes_verified)
        return report
    except BaseException as error:
        report.update(failure=str(error)[:4096], error_type=type(error).__name__)
        raise
    finally:
        sdk.write_json(output / "BUILD.json", report)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("report", "toolchain-root", "ndk", "java-home", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("report-sha256", "sdk-run-id", "source-commit", "source-tree", "source-tree-sha256", "native-package-id"):
        parser.add_argument("--" + name, required=True)
    print(json.dumps(build(parser.parse_args()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
