"""Host JNI qualification of the Android adapter against installed C archives.

This lane runs packaged Java classes and the real JNI bridge. Physical ART/AAR
acceptance is recorded separately; it does not require additional hardware.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import tempfile
import zipfile

import continuity_c_consumer as c
from continuity_kotlin_consumer import tool_identity
import continuity_android_contract as contract
import rust_sdk_profile as sdk
import continuity_profiles as profiles_contract

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
PUBLIC = (
    "original.request", "resumed.request", "after-rejection.request", "activated.request",
    "rejected", "active-reopened", "rekeyed", "cancelled", "connected.session",
    "uncertain.message", "acknowledged.message", "reverse.result",
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
    contract.verify_single(stdout, "android_lifecycle")
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
    probes = (("pending-", "PendingWriteProbe"), ("recovery-", "FirstUseRecoveryProbe"), ("account-", "AccountProbe"), ("root-", "RootOwnedProbe"), ("retired-owned-", "RetiredOwnedProbe"), ("roster-witness-", "RosterWitnessProbe"),
              ("roster-", "RosterProbe"), ("policy-", "PolicyProbe"), ("credential-", "CredentialProbe"),
              ("authority-", "AuthorityProbe"), (("witness-", "managed-"), "WitnessProbe"), ("peer-", "PeerProbe"))
    cases = []
    for prefixes, probe in probes:
        prefixes = (prefixes,) if isinstance(prefixes, str) else prefixes
        cases.append("  " + "|".join(prefix + "*" for prefix in prefixes) + ") probe=" + probe + " ;;\n")
    command = [str(java), "--enable-native-access=ALL-UNNAMED", "-Xcheck:jni",
        "-Djava.library.path=" + str(library), "-cp", str(jar) + os.pathsep + str(classes)]
    launcher = directory / "driver"
    launcher.write_text("#!/bin/sh\nset -eu\n[ \"$#\" -eq 5 ] || exit 64\ncase \"$1\" in\n"
        + "".join(cases) + "  *) probe=EnrollmentProbe ;;\nesac\nexec " + shlex.join(command)
        + ' "dev.qperiapt.continuity.android.tests.$probe" "$3" "$4" "$2" "$1" "$5"\n')
    launcher.chmod(0o700)
    return launcher


def qualify_android_jni(outside: Path, output: Path, native: dict, environment: dict, java_home: Path,
                        *, profiles: tuple[str, ...] = profiles_contract.PROFILES) -> dict:
    profiles_contract.require_native(native, profiles)
    sdk.require((os.uname().sysname, os.uname().machine) == ("Darwin", "arm64"),
                "Android JNI host qualification requires completed C archives on macOS arm64")
    result = {"completed": False, "scope": SCOPE, "release_claim_eligible": False,
              "partition_completed": False, "build_profiles": list(profiles), "profiles": {}}
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
        for profile in profiles:
            installed = work / profile; installed.mkdir(mode=0o700)
            record = native["execution"][profile]["binaries"]["C_library"]
            library = Path(record["path"])
            sdk.require(sdk.snapshot(library, maximum=c.MAX_BINARY).sha256 == record["sha256"], "native C library changed")
            sdk.copy(library, installed / library.name, maximum=c.MAX_BINARY)
            receiver_record = native["execution"][profile]["binaries"]["C_client"]
            receiver = installed / "qpc-c-client"
            sdk.require(sdk.snapshot(Path(receiver_record["path"]), maximum=c.MAX_BINARY).sha256 == receiver_record["sha256"],
                        "installed C receiver changed")
            sdk.copy(Path(receiver_record["path"]), receiver, maximum=c.MAX_BINARY); receiver.chmod(0o700)
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
            catalog = run([str(binary), "--list"], profile + "-test-catalog", consumer)
            contract.verify_catalog(catalog)
            driver = _driver(installed, java, jar, tests, installed)
            import continuity_android_account as account
            account_cases = installed / "account-cases"
            account_runtime = dict(env, QPC_ANDROID_CASES=str(account_cases), QPC_ANDROID_DRIVER=str(driver))
            account_stdout = run([str(binary), "--exact", account.TEST, "--nocapture"], profile + "-account", consumer, account_runtime)
            account_results = account.verify_execution(account_stdout, account_cases)
            for trust in account_results:
                for name in account.PUBLIC:
                    sdk.copy(account_cases / trust / name, output / f"android-jni-{profile}-account-{trust}-{name}.public")
            import continuity_android_recovery as recovery
            recovery_results = recovery.qualify(consumer, installed, output, profile, environment, run,
                java=java, jar=jar, tests=tests, android=binary, android_driver=driver, client=receiver)
            cases = installed / "cases"
            runtime = dict(env, QPC_ANDROID_CASES=str(cases), QPC_ANDROID_DRIVER=str(driver))
            checked = run([str(binary), "--exact", "android_lifecycle", "--nocapture"], profile + "-execution", consumer, runtime)
            import continuity_android_local_credential as local_credential
            outcomes = local_credential.verify_execution(checked, cases)
            for trust in outcomes:
                for name in local_credential.PUBLIC:
                    sdk.copy(cases / trust / name, output / f"android-jni-{profile}-{trust}-{name}.public")
            for trust in outcomes:
                for label, _ in CASES:
                    for suffix in ("stdout", "stderr"):
                        sdk.copy(cases / trust / f"{label}.{suffix}", output / f"android-jni-{profile}-{trust}-{label}.{suffix}")
            import continuity_android_retirement as retirement
            retirement_results = retirement.qualify(binary, consumer, installed, output, profile,
                dict(env, QPC_ANDROID_DRIVER=str(driver), QPC_CONFIGURATION_RECEIVER=str(receiver)), run)
            import continuity_android_root as root_qualification
            root_results = root_qualification.qualify(binary, consumer, installed, output, profile,
                dict(env, QPC_ANDROID_DRIVER=str(driver), QPC_CONFIGURATION_RECEIVER=str(receiver)), run)
            import continuity_android_witness as witnessed
            import continuity_android_credential as credential
            import continuity_android_remote_credential as remote_credential
            import continuity_android_credential_terminal as terminal
            witness_results = {}
            for lane, managed, test in (("witness", False, witnessed.TEST), ("authority", True, "android_witness::managed_first_registration"),
                                        ("credential", True, credential.TEST)):
                witness_cases = installed / (lane + "-cases")
                witness_runtime = dict(env, QPC_ANDROID_CASES=str(witness_cases), QPC_ANDROID_DRIVER=str(driver), QPC_CONFIGURATION_RECEIVER=str(receiver))
                witnessed_stdout = run([str(binary), "--exact", test, "--nocapture"],
                                       profile + "-" + lane, consumer, witness_runtime)
                verify_witness = (terminal.verify_execution if lane == "credential" else
                                  lambda data, path: witnessed.verify_execution(data, path, managed=managed))
                witness_outcomes = verify_witness(witnessed_stdout, witness_cases)
                witness_results[lane] = witness_outcomes
                extra_public = credential.PUBLIC + remote_credential.PUBLIC + terminal.PUBLIC if lane == "credential" else ()
                witnessed.export_public(witnessed_stdout, witness_cases, output,
                    f"android-jni-{profile}-{lane}-", witness_outcomes, managed=managed,
                    extra_public=extra_public, verifier=verify_witness)
            import continuity_android_policy_expiry as expiry
            expiry_results = {}
            for trust, test in expiry.TESTS.items():
                expiry_cases = installed / ("policy-expiry-" + trust + "-cases")
                expiry_runtime = dict(env, QPC_ANDROID_CASES=str(expiry_cases), QPC_ANDROID_DRIVER=str(driver))
                expiry_stdout = run([str(binary), "--exact", test, "--nocapture"], profile + "-policy-expiry-" + trust, consumer, expiry_runtime)
                records = expiry.verify_execution(expiry_stdout, expiry_cases, trust)
                expiry_results.update(records)
                for label in records:
                    for name in expiry.public(label.endswith("-applied")):
                        sdk.copy(expiry_cases / label / name, output / f"android-jni-{profile}-policy-expiry-{label}-{name}.public")
            import continuity_android_policy_renewal as policy_renewal
            import continuity_android_pending as pending_write
            pending_cases = installed / "pending-write-cases"
            import continuity_c_witness_openssl as pending_openssl
            peer_record = native["execution"][profile].get("witness_openssl")
            sdk.require(peer_record is not None and peer_record["completed"], "Android pending matrix requires the qualified OpenSSL witness peer")
            peer = peer_record["peer"]
            pending_openssl.verify_dependencies(peer["dependency_files"])
            pending_runtime = dict(env, QPC_ANDROID_CASES=str(pending_cases), QPC_ANDROID_DRIVER=str(driver),
                                   QPC_CONFIGURATION_RECEIVER=str(receiver), QPERIAPT_WITNESS_OPENSSL_PEER=peer["path"])
            process_cases = installed / "pending-process-cases"
            process_runtime = dict(pending_runtime, QPC_ANDROID_CASES=str(process_cases))
            process_stdout = run([str(binary), "android_pending_process::", "--test-threads=2", "--nocapture"],
                                 profile + "-pending-process", consumer, process_runtime)
            process_results = {}
            for label in pending_write.PROCESS_TESTS:
                process_results.update(pending_write.verify_execution(process_stdout, process_cases, label, batch=True, process_loss=True))
                for name in pending_write.public(label.endswith("-applied"), process_loss=True):
                    sdk.copy(process_cases / (label + "-process-loss") / name,
                             output / f"android-jni-{profile}-pending-process-{label}-{name}.public")
            query_cases = installed / "pending-query-cases"
            query_runtime = dict(pending_runtime, QPC_ANDROID_CASES=str(query_cases))
            query_stdout = run([str(binary), "android_pending_query::", "--test-threads=2", "--nocapture"],
                               profile + "-pending-query", consumer, query_runtime)
            query_results = {}
            for label in pending_write.QUERY_TESTS:
                query_results.update(pending_write.verify_execution(query_stdout, query_cases, label, batch=True, query_cancel=True))
                for name in pending_write.public(label.endswith("-applied"), query_cancel=True):
                    sdk.copy(query_cases / (label + "-query-cancel") / name,
                             output / f"android-jni-{profile}-pending-query-{label}-{name}.public")
            pending_stdout = run([str(binary), "android_pending_write::", "--test-threads=2", "--nocapture"],
                                  profile + "-pending-write", consumer, pending_runtime)
            pending_results = {}
            for label in pending_write.TESTS:
                pending_results.update(pending_write.verify_execution(pending_stdout, pending_cases, label, batch=True))
                for name in pending_write.public(label.endswith("-applied")):
                    sdk.copy(pending_cases / label / name, output / f"android-jni-{profile}-pending-write-{label}-{name}.public")
            pending_openssl.verify_dependencies(peer["dependency_files"])
            target_client = installed / "qpc-configuration-client"
            run([str(clang), "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-isysroot", str(platform),
                 str(consumer / "first_configuration_client.c"), "-I" + str(consumer), "-L" + str(installed),
                 "-lq_periapt_continuity_c_consumer", "-Wl,-rpath,@loader_path", "-o", str(target_client)], profile + "-policy-target-client")
            import continuity_android_continuation as continuation
            continued_cases = installed / "pending-continuation-cases"
            continued_stdout = run([str(binary), "android_pending_continuation::", "--test-threads=2", "--nocapture"],
                profile + "-pending-continuation", consumer, dict(pending_runtime,
                    QPC_ANDROID_CASES=str(continued_cases), QPC_CONFIGURATION_TARGET_CLIENT=str(target_client)))
            continued_results = {}
            for label in continuation.TESTS:
                continued_results.update(continuation.verify_execution(continued_stdout, continued_cases, label, batch=True))
                for name in continuation.public(label):
                    sdk.copy(continued_cases / (label + "-continuation") / name,
                        output / f"android-jni-{profile}-pending-continuation-{label}-{name}.public")
            policy_results = {}
            for trust, test in policy_renewal.TESTS.items():
                policy_cases = installed / ("policy-renewal-" + trust + "-cases")
                policy_runtime = dict(env, QPC_ANDROID_CASES=str(policy_cases), QPC_ANDROID_DRIVER=str(driver),
                                      QPC_CONFIGURATION_TARGET_CLIENT=str(target_client), QPC_CONFIGURATION_RECEIVER=str(receiver))
                policy_stdout = run([str(binary), "--exact", test, "--nocapture"], profile + "-policy-renewal-" + trust, consumer, policy_runtime)
                records = policy_renewal.verify_execution(policy_stdout, policy_cases, trust)
                policy_results.update(records)
                for label in records:
                    for name in policy_renewal.public(label.split("-", 1)[0]):
                        sdk.copy(policy_cases / label / name, output / f"android-jni-{profile}-policy-renewal-{label}-{name}.public")
            import continuity_android_roster_qualification as roster_qualification
            roster_results = roster_qualification.qualify(binary, consumer, installed, output, profile,
                dict(env, QPC_ANDROID_DRIVER=str(driver), QPC_CONFIGURATION_RECEIVER=str(receiver),
                     QPC_CONFIGURATION_TARGET_CLIENT=str(target_client)), run)
            import continuity_android_policy_credential as policy_credential
            credential_policy_results = policy_credential.qualify(binary, consumer, installed, output, profile,
                dict(env, QPC_ANDROID_DRIVER=str(driver), QPC_CONFIGURATION_RECEIVER=str(receiver),
                     QPC_CONFIGURATION_TARGET_CLIENT=str(target_client)), run)
            import continuity_android_joint_policy as joint_policy
            joint_policy_results = joint_policy.qualify(binary, consumer, installed, output, profile,
                dict(env, QPC_ANDROID_DRIVER=str(driver), QPC_CONFIGURATION_RECEIVER=str(receiver),
                     QPC_CONFIGURATION_TARGET_CLIENT=str(target_client)), run)
            import continuity_android_witness_joint as witness_joint
            witness_joint_results = witness_joint.qualify(binary, consumer, installed, output, profile,
                dict(env, QPC_ANDROID_DRIVER=str(driver), QPC_CONFIGURATION_RECEIVER=str(receiver),
                     QPC_CONFIGURATION_TARGET_CLIENT=str(target_client)), run)
            import continuity_android_joint_cycle as joint_cycle
            joint_cycle_results = joint_cycle.qualify(binary, consumer, installed, output, profile,
                dict(env, QPC_ANDROID_DRIVER=str(driver), QPC_CONFIGURATION_RECEIVER=str(receiver),
                     QPC_CONFIGURATION_TARGET_CLIENT=str(target_client)), run)
            result["profiles"][profile] = {"root_outcomes": root_results, "retirement_outcomes": retirement_results, "roster_outcomes": roster_results, "policy_renewal_outcomes": policy_results,
                "policy_target_client_sha256": sdk.snapshot(target_client, maximum=c.MAX_BINARY).sha256,
                "pending_write_outcomes": pending_results, "policy_expiry_outcomes": expiry_results, "credential_outcomes": witness_results["credential"], "witness_outcomes": witness_results["witness"], "authority_outcomes": witness_results["authority"], "outcomes": outcomes, "boundary_checks": True, "native_sha256": record["sha256"],
                "bridge_sha256": sdk.snapshot(bridge, maximum=c.MAX_BINARY).sha256,
                "receiver_sha256": sdk.snapshot(receiver, maximum=c.MAX_BINARY).sha256,
                "test_sha256": sdk.snapshot(binary, maximum=c.MAX_BINARY).sha256}
            result["profiles"][profile]["account_outcomes"] = account_results
            result["profiles"][profile]["pending_query_cancellation_outcomes"] = query_results
            result["profiles"][profile]["pending_process_loss_outcomes"] = process_results
            result["profiles"][profile]["pending_continuation_outcomes"] = continued_results
            result["profiles"][profile]["recovery_outcomes"] = recovery_results
            result["profiles"][profile]["policy_credential_outcomes"] = credential_policy_results
            result["profiles"][profile]["joint_policy_outcomes"] = joint_policy_results
            result["profiles"][profile]["witness_joint_outcomes"] = witness_joint_results
            result["profiles"][profile]["joint_policy_cycles"] = joint_cycle_results
        sdk.require(source_files() == source and tool_identity(java_home) == tools and sdk.snapshot(jar).sha256 == jar_hash,
                    "Android JNI source, JDK or packaged classes changed during qualification")
        profiles_contract.require_execution(result, profiles, "profiles")
        result.update(completed=profiles == profiles_contract.PROFILES, partition_completed=True,
                      jar_sha256=jar_hash)
        return result
    finally:
        sdk.write_json(output / "ANDROID_JNI_CONSUMER.json", result)
