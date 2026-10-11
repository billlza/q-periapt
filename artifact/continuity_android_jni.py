"""Host JNI qualification of the Android adapter against installed C archives.

This lane runs packaged Java classes and the real JNI bridge. Physical ART/AAR
acceptance is recorded separately; it does not require additional hardware.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import sys
import tempfile
import zipfile

import continuity_c_consumer as c
from continuity_kotlin_consumer import tool_identity
import rust_sdk_profile as sdk

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "bindings/android/ContinuityPackageConsumer"
SCOPE = "Android adapter host JNI, packaged Java classes, installed C engine; same-host endpoints; physical ART/AAR acceptance is separate; no independent protocol implementation"
CASES = (
    ("original.request", "enrollment-create"), ("resumed.request", "enrollment-resume"),
    ("rejected", "enrollment-reject"), ("after-rejection.request", "enrollment-resume"),
    ("activated.request", "enrollment-activate"), ("active-reopened", "enrollment-active-reopen"),
    ("connected.session", "peer-connect"), ("uncertain.message", "peer-uncertain"),
    ("acknowledged.message", "peer-retry"), ("rekeyed", "peer-rekey"),
    ("reverse", "peer-serve"), ("cancelled", "peer-cancel"),
)


def source_files() -> dict[str, bytes]:
    files = {}
    for path in sorted(SOURCE.rglob("*")):
        sdk.require(not path.is_symlink(), "Android adapter source contains a symlink")
        if path.is_file():
            files[path.relative_to(SOURCE).as_posix()] = sdk.snapshot(path).data
    sdk.require(files and "jni/continuity_jni.c" in files and "src/test/java/CancellationProbe.java" in files,
                "Android adapter source is incomplete")
    return files


def verify_execution(stdout: bytes, cases: Path) -> dict:
    text = stdout.decode()
    sdk.require(re.findall(r"^test (\S+) \.\.\. ok$", text, re.MULTILINE) == ["android_lifecycle"]
                and len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;", text, re.MULTILINE)) == 1,
                "Android JNI lifecycle was not executed completely")
    records = {}
    for profile in ("fixed", "recoverable"):
        marker = f"qualified {profile}: 12 foreign processes; registration, original retry, rekey, reverse callback retry, cancellation and concurrent close"
        sdk.require(text.splitlines().count(marker) == 1, "Android JNI profile outcome missing or duplicated")
        base = cases / profile
        for label, operation in CASES:
            sdk.require(sdk.snapshot(base / (label + ".stderr")).data == b""
                        and sdk.snapshot(base / (label + ".stdout")).data == f"{profile}:{operation}:passed\n".encode(),
                        "Android foreign process omitted an outcome or reported diagnostics")
        original = sdk.snapshot(base / "original.request").data
        sdk.require(len(original) == 5506 and all(sdk.snapshot(base / n).data == original
                    for n in ("resumed.request", "after-rejection.request", "activated.request")),
                    "Android original enrollment request changed")
        for name in ("rejected", "active-reopened", "rekeyed", "cancelled"):
            sdk.require(sdk.snapshot(base / name).data == b"\x01", "Android lifecycle outcome missing")
        session = sdk.snapshot(base / "connected.session").data
        uncertain = sdk.snapshot(base / "uncertain.message").data
        reverse = sdk.snapshot(base / "reverse.result").data
        sdk.require(len(session) == 32 and any(session) and len(uncertain) == 64
                    and uncertain[:32] == session and any(uncertain[32:])
                    and sdk.snapshot(base / "acknowledged.message").data == uncertain,
                    "Android original send identity changed")
        sdk.require(len(reverse) == 64 + len(b"reverse delivery after rekey") and reverse[:32] == session
                    and any(reverse[32:64]) and reverse[64:] == b"reverse delivery after rekey",
                    "Android reverse delivery missing or substituted")
        records[profile] = {"foreign_processes": len(CASES), "session": session.hex(),
                            "original_message": uncertain[32:].hex(), "reverse_message": reverse[32:64].hex()}
    return records


def _driver(directory: Path, java: Path, jar: Path, classes: Path, library: Path) -> Path:
    program = directory / "driver.py"
    program.write_text("import os, sys\n"
        "mode, profile, inputs, target, output = sys.argv[1:]\n"
        "probe = 'CredentialProbe' if mode.startswith('credential-') else ('AuthorityProbe' if mode.startswith('authority-') else ('WitnessProbe' if mode.startswith(('witness-', 'managed-')) else ('PeerProbe' if mode.startswith('peer-') else 'EnrollmentProbe')))\n"
        + "command = " + repr([str(java), "--enable-native-access=ALL-UNNAMED", "-Xcheck:jni",
            "-Djava.library.path=" + str(library), "-cp", str(jar) + os.pathsep + str(classes)]) + "\n"
        "command += ['dev.qperiapt.continuity.android.tests.' + probe, inputs, target, profile, mode, output]\n"
        "os.execv(command[0], command)\n")
    launcher = directory / "driver"
    launcher.write_text("#!/bin/sh\nexec " + shlex.join([sys.executable, str(program)]) + ' "$@"\n')
    launcher.chmod(0o700)
    return launcher


def qualify_android_jni(outside: Path, output: Path, native: dict, environment: dict, java_home: Path) -> dict:
    sdk.require(native["completed"] and (os.uname().sysname, os.uname().machine) == ("Darwin", "arm64"),
                "Android JNI host qualification requires completed C archives on macOS arm64")
    result = {"completed": False, "scope": SCOPE, "release_claim_eligible": False, "profiles": {}}
    try:
        tools = tool_identity(java_home)
        java_home = Path(tools["root"])
        java, javac = (java_home / "bin" / name for name in ("java", "javac"))
        sdk.require(all(p.is_file() and os.access(p, os.X_OK) for p in (java, javac)), "selected Java tools are not executable")
        env = {k: v for k, v in environment.items() if k not in {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"}
               and not k.startswith(("JAVA_", "GRADLE_", "KOTLIN_", "QPERIAPT_", "QPC_", "LD_"))}
        work = Path(tempfile.mkdtemp(prefix="android-jni-", dir=outside)).resolve()
        def run(argv, label, cwd=work, runtime=None):
            return sdk.command(argv, output / ("android-jni-" + label), cwd, environment=env if runtime is None else runtime)
        versions = {"java": run([str(java), "--version"], "java-version").decode(),
                    "javac": run([str(javac), "--version"], "javac-version").decode()}
        sdk.require(re.match(r"(?:openjdk|java) 25(?:[ .])", versions["java"])
                    and versions["javac"].startswith("javac 25"), "Android JNI qualification requires JDK 25")
        source = source_files(); builder = work / "source"
        for name, data in source.items():
            path = builder / name; path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream: stream.write(data)
        result.update(tools=tools, versions=versions, source_hashes={name: sdk.snapshot(builder / name).sha256 for name in source})
        classes = work / "classes"; classes.mkdir()
        run([str(javac), "--release", "11", "-Xlint:all", "-Werror", "-d", str(classes),
             *map(str, sorted((builder / "src/main/java").rglob("*.java")))], "main-compile")
        jar = output / "continuity-android-classes.jar"
        with zipfile.ZipFile(jar, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(classes.rglob("*.class")):
                info = zipfile.ZipInfo(path.relative_to(classes).as_posix()); info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16; archive.writestr(info, sdk.snapshot(path).data)
        jar_hash = sdk.snapshot(jar).sha256
        tests = work / "tests"; tests.mkdir()
        run([str(javac), "--release", "17", "-Xlint:all", "-Werror", "-cp", str(jar), "-d", str(tests),
             *map(str, sorted((builder / "src/test/java").glob("*.java")))], "test-compile")
        clang = Path(run(["xcrun", "--sdk", "macosx", "--find", "clang"], "clang-path").decode().strip()).resolve(strict=True)
        platform = Path(run(["xcrun", "--sdk", "macosx", "--show-sdk-path"], "sdk-path").decode().strip()).resolve(strict=True)
        result["compiler"] = {"path": str(clang), "sha256": sdk.snapshot(clang, maximum=c.MAX_BINARY).sha256,
                              "sdk_settings_sha256": sdk.snapshot(platform / "SDKSettings.json").sha256}
        consumer = outside / "c-consumer"; cargo = str(Path(environment["RUSTC"]).parent / "cargo")
        target = Path(environment["CARGO_TARGET_DIR"])
        for profile in ("debug", "release"):
            installed = work / profile; installed.mkdir(mode=0o700)
            record = native["execution"][profile]["binaries"]["C_library"]
            library = Path(record["path"])
            sdk.require(sdk.snapshot(library, maximum=c.MAX_BINARY).sha256 == record["sha256"], "native C library changed")
            sdk.copy(library, installed / library.name, maximum=c.MAX_BINARY)
            bridge = installed / "libqperiapt_continuity_jni.dylib"
            run([str(clang), "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-fvisibility=hidden",
                 "-isysroot", str(platform), "-I" + str(consumer), "-I" + str(java_home / "include"),
                 "-I" + str(java_home / "include/darwin"), "-dynamiclib",
                 *map(str, sorted((builder / "jni").glob("*.c"))), "-L" + str(installed),
                 "-lq_periapt_continuity_c_consumer", "-Wl,-rpath,@loader_path", "-o", str(bridge)], profile + "-bridge")
            boundary = run([str(java), "--enable-native-access=ALL-UNNAMED", "-Xcheck:jni",
                            "-Djava.library.path=" + str(installed), "-cp", str(jar) + os.pathsep + str(tests),
                            "dev.qperiapt.continuity.android.BridgeProbe"], profile + "-boundary")
            sdk.require(boundary == b"configuration:bridge:passed\n" and
                        sdk.snapshot(output / ("android-jni-" + profile + "-boundary.stderr")).data == b"",
                        "JNI boundary checks omitted an outcome or reported diagnostics")
            extra = ["--release"] if profile == "release" else []
            built = run([cargo, "test", "--locked", "--offline", "--test", "android", "--no-run", "--message-format=json", "-j", "2", *extra],
                        profile + "-build", consumer)
            binary = c.built_artifact(built, consumer, target / profile, library=False, test_name="android")
            driver = _driver(installed, java, jar, tests, installed)
            cases = installed / "cases"
            runtime = dict(env, QPC_ANDROID_CASES=str(cases), QPC_ANDROID_DRIVER=str(driver))
            checked = run([str(binary), "--exact", "android_lifecycle", "--nocapture"], profile + "-execution", consumer, runtime)
            outcomes = verify_execution(checked, cases)
            for trust in outcomes:
                for label, _ in CASES:
                    for suffix in ("stdout", "stderr"):
                        sdk.copy(cases / trust / f"{label}.{suffix}", output / f"android-jni-{profile}-{trust}-{label}.{suffix}")
            import continuity_android_witness as witnessed
            import continuity_android_credential as credential
            witness_results = {}
            for lane, managed, test in (("witness", False, witnessed.TEST), ("authority", True, "android_witness::managed_first_registration"),
                                        ("credential", True, credential.TEST)):
                witness_cases = installed / (lane + "-cases")
                witness_runtime = dict(env, QPC_ANDROID_CASES=str(witness_cases), QPC_ANDROID_DRIVER=str(driver))
                witnessed_stdout = run([str(binary), "--exact", test, "--nocapture"],
                                       profile + "-" + lane, consumer, witness_runtime)
                witness_outcomes = (credential.verify_execution(witnessed_stdout, witness_cases) if lane == "credential"
                                    else witnessed.verify_execution(witnessed_stdout, witness_cases, managed=managed))
                witness_results[lane] = witness_outcomes
                for label in witness_outcomes:
                    carrier = label.split("-", 1)[0]
                    public = ["genesis", "signed-witness-transcript"]
                    if managed: public += ["authority-created", "authority-reopened"]
                    if lane == "credential": public += list(credential.PUBLIC)
                    public += [name + "." + suffix for name, _ in witnessed.cases(carrier, managed=managed) for suffix in ("stdout", "stderr")]
                    for name in public:
                        sdk.copy(witness_cases / label / name, output / f"android-jni-{profile}-{lane}-{label}-{name}.public")
            result["profiles"][profile] = {"credential_outcomes": witness_results["credential"], "witness_outcomes": witness_results["witness"], "authority_outcomes": witness_results["authority"], "outcomes": outcomes, "boundary_checks": True, "native_sha256": record["sha256"],
                "bridge_sha256": sdk.snapshot(bridge, maximum=c.MAX_BINARY).sha256,
                "test_sha256": sdk.snapshot(binary, maximum=c.MAX_BINARY).sha256}
        sdk.require(source_files() == source and tool_identity(java_home) == tools and sdk.snapshot(jar).sha256 == jar_hash,
                    "Android JNI source, JDK or packaged classes changed during qualification")
        result.update(completed=True, jar_sha256=jar_hash)
        return result
    finally:
        sdk.write_json(output / "ANDROID_JNI_CONSUMER.json", result)
