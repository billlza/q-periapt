"""C consumer extension of the same installed Continuity archive qualification."""
from __future__ import annotations

import os
from pathlib import Path
import re

import continuity_package as package
import continuity_c_recovery as recovery
import continuity_c_opening as opening
import continuity_c_device as device
import continuity_c_account as account
import continuity_c_witness as witness
import continuity_c_witness_tls as witness_tls
import continuity_c_witness_openssl as witness_openssl
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

NAME = "q-periapt-continuity-c-consumer"
LIBRARY = "q_periapt_continuity_c_consumer"
FEATURES = frozenset({"connection-tls", "control-tls", "anchor-tls"})
MAX_BINARY = 256 * 1024**2
FIXTURE = package.ROOT / "bindings/c/ContinuityPackageConsumer"
TEST = "c_client_owns_installed_connection_rekeys_and_reconciles_exact_delivery"
RESTORE_TEST = "installed_owner_restores_expired_advertisement_and_reconciles_original_message"
SERVER_TEST = "c_server_preserves_callback_failures_unknown_commits_replay_and_rekey"
SERVER_SCOPE = "installed native Rust client to unpublished C server; same host; local journal profile"
SCOPE = "unpublished C client to installed Rust peer; same host; local journal profile"
QUALIFICATION_SCOPE = "unpublished C client/server/recovery using installed shared Rust engine; same host; local and required-witness profiles with explicit signed TCP or mutual TLS witness carrier"
EXPORTS = {"qpc_owner_v1_" + name for name in
           ("open", "prepare_open", "prepare_reopen", "finish_open", "cancel", "close", "establish", "next_message", "send", "message_status", "rekey",
            "listen", "serve", "serve_rekey")}
EXPORTS |= {"qpc_recovery_v1_" + name for name in ("open", "session_count", "session_at", "select", "select_archive",
            "archive", "begin", "status", "reserved", "epoch", "unconfirmed", "delivery", "skipped",
            "acknowledge", "retire", "restore_index")}
EXPORTS |= {"qpc_owner_v1_open_witness", "qpc_recovery_v1_open_witness"}
EXPORTS |= {"qpc_owner_v1_open_witness_tls", "qpc_recovery_v1_open_witness_tls"}
EXPORTS |= {"qpc_peer_v1_prepare", "qpc_peer_v1_prepare_reopen"}
EXPORTS |= {"qpc_device_v1_next_account", "qpc_device_v1_account_status",
            "qpc_device_v1_send_account_member"}
EXPORTS |= {"qpc_recovery_v1_" + name for name in ("select_account", "account_begin", "account_status",
    "account_member", "account_reserved", "account_epoch", "account_unconfirmed", "account_delivery",
    "account_skipped", "account_acknowledge", "account_retire")}


def built_artifact(stdout: bytes, consumer: Path, build: Path, *, library: bool, unit: bool = False,
                   test_name: str = "c_owner") -> Path:
    sdk.require(test_name in ("c_owner", "sync_fault", "witness", "account_cleanup", "account_witness"), "unknown installed C test target")
    messages = [parse_strict_json_bytes(line, label="C consumer Cargo message") for line in stdout.splitlines()]
    target = LIBRARY if library or unit else test_name
    items = [m for m in messages if m.get("reason") == "compiler-artifact" and m["target"]["name"] == target
             and (not unit or m.get("executable"))]
    sdk.require(len(items) == 1, "C consumer must build one exact target")
    item = items[0]
    expected = consumer / ("src/lib.rs" if library or unit else "tests/" + test_name + ".rs")
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


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unknown installed client language")
    expected_scope = SCOPE.replace("C client", language + " client")
    text = stdout.decode()
    passed = re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE)
    sdk.require(passed == [TEST] and re.search(
        r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;", text, re.MULTILINE),
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
                and report["scope"] == expected_scope, "C execution omitted a required outcome or changed its scope")
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



def verify_restore_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unknown restoration language")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [RESTORE_TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;",
                              text, re.MULTILINE), "installed restoration trace did not execute completely")
    report_file = sdk.snapshot(directory / "c-restore-public-result.json")
    report = parse_strict_json_bytes(report_file.data, label="foreign session restoration")
    flags = {"fresh_refused", "wrong_session_refused", "pre_cancel_absent", "unknown_commit_reconciled", "actual_foreign_clock"}
    sdk.require(set(report) == flags | {"language", "session", "message", "advertisement_until", "current_time", "independent_readbacks"},
                "foreign restoration fields differ")
    sdk.require(report["language"] == language and all(report[name] is True for name in flags),
                "foreign restoration outcome or language differs")
    sdk.require(type(report["independent_readbacks"]) is int and report["independent_readbacks"] == 2,
                "foreign restoration readback count differs")
    sdk.require(all(type(report[name]) is int and 0 < report[name] < 2**64 for name in ("advertisement_until", "current_time"))
                and report["advertisement_until"] < report["current_time"], "foreign owner did not run after advertisement expiry")
    for name in ("session", "message"):
        sdk.require(type(report[name]) is str and re.fullmatch(r"[0-9a-f]{64}", report[name]) and report[name] != "0" * 64,
                    "foreign restoration identity differs")
    readbacks = {"c-restore-public-result.json": report_file.sha256}
    for role in ("initiator", "responder"):
        leaf = role + "/reopen-test-time"
        value = sdk.snapshot(directory / leaf)
        sdk.require(value.data == report["advertisement_until"].to_bytes(8, "big"), "foreign restoration advertisement boundary differs")
        readbacks[leaf] = value.sha256
        leaf = role + "/session"
        value = sdk.snapshot(directory / leaf)
        sdk.require(value.data == bytes.fromhex(report["session"]), "foreign restoration selected a different session")
        readbacks[leaf] = value.sha256
    leaf = "responder/application-" + report["message"]
    value = sdk.snapshot(directory / leaf)
    sdk.require(value.data == bytes.fromhex(report["session"] + report["message"]) + b"persisted before process exit",
                "foreign restoration application readback differs")
    sdk.require(len(list((directory / "responder").glob("application-*"))) == 1
                and not list((directory / "initiator").glob("application-*")), "foreign restoration duplicated application effects")
    readbacks[leaf] = value.sha256
    expected = {"restore-fresh-refused": "rejected:104\n", "restore-wrong-session": "rejected:201\n",
                "restore-next": report["message"] + "\n", "restore-cancelled": "cancelled-absent\n",
                "restore-same-slot": report["message"] + "\n", "restore-unknown": "delivery-unknown-committed\n",
                "restore-committed": "2\n", "restore-exact-resend": "consumed\n", "restore-acknowledged": "3\n"}
    logs = {}
    for name, expected_stdout in expected.items():
        for suffix, content in (("stdout", expected_stdout.encode()), ("stderr", b"")):
            leaf = f"initiator/c-{name}.{suffix}"
            value = sdk.snapshot(directory / leaf, maximum=65536)
            sdk.require(value.data == content, "foreign restoration command output or diagnostic differs")
            logs[leaf] = value.sha256
    return dict(report, public_readbacks=readbacks, command_logs=logs,
                release_claim_eligible=False, scope=f"installed {language} explicit existing-session restoration; same-host shared native engine; local profile; historical bootstrap fixture and actual current foreign clock")


def verify_server_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unknown installed server language")
    expected_scope = SERVER_SCOPE.replace("C server", language + " server")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [SERVER_TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;",
                              text, re.MULTILINE), "installed C server trace did not execute completely")
    report = parse_strict_json_bytes(sdk.snapshot(directory / "c-server-public-result.json").data,
                                    label="C server execution")
    flags = {"completed", "callback_failure_preserved", "unknown_commit_reconciled",
             "crash_after_application_reconciled", "duplicate_skips_callback",
             "reentrant_close_busy", "cancelled_listener_released",
             "acknowledged_send_refused", "native_recovery_consumption"}
    sdk.require(set(report) == flags | {"schema_version", "scope", "session", "messages", "network_rekeys",
                                       "application_records", "listener_tls_deadline_ms", "release_claim_eligible"},
                "C server execution fields differ")
    sdk.require(type(report["listener_tls_deadline_ms"]) is int
                and 18_000 <= report["listener_tls_deadline_ms"] < 23_000,
                "C listener and TLS did not share the invocation deadline")
    sdk.require(all(report[name] is True for name in flags) and report["release_claim_eligible"] is False
                and report["scope"] == expected_scope, "C server required outcome or scope differs")
    for name, value in (("schema_version", 1), ("network_rekeys", 1), ("application_records", 5)):
        sdk.require(type(report[name]) is int and report[name] == value, "C server execution count differs")
    messages = report["messages"]
    sdk.require(type(messages) is list and len(messages) == 5
                and all(type(x) is str and re.fullmatch(r"[0-9a-f]{64}", x) and x != "0" * 64
                        for x in [report["session"], *messages]) and len(set(messages)) == 5,
                "C server message identities differ")
    for index, message in enumerate(messages):
        epoch, sequence = (0, index) if index < 4 else (1, 0)
        sdk.require(bytes.fromhex(message)[:16] == epoch.to_bytes(8, "big") + sequence.to_bytes(8, "big"),
                    "C server message epoch/sequence differs")
    readbacks = {}
    for message in messages:
        leaf = "responder/application-" + message
        record = sdk.snapshot(directory / leaf)
        sdk.require(record.data == bytes.fromhex(report["session"] + message) + b"persisted before process exit",
                    "C server independent application readback differs")
        readbacks[leaf] = record.sha256
    sdk.require(len(list((directory / "responder").glob("application-*"))) == 5
                and not list((directory / "initiator").glob("application-*")), "C server application effects differ")
    def event(message: str, duplicate: int, calls: int, created: int) -> str:
        return f"served:{1 if message == '0' * 64 else 2}:{duplicate}:{calls}:{created}\n{report['session']}\n{message}\n"
    expected = {"server-deadline": "server-deadline\n", "server-bootstrap": event("0" * 64, 0, 0, 0), "server-cancel": "server-cancelled\n",
                "server-fail-before": "application-failed:1:0\n", "server-retry-0": event(messages[0], 0, 1, 1),
                "server-duplicate-prepare": "application-failed:1:1\n",
                "server-duplicate": event(messages[3], 1, 0, 0), "server-uncertain": "application-failed:1:1\n",
                "server-retry-1": event(messages[1], 0, 1, 0), "server-crash-after": "",
                "server-retry-2": event(messages[2], 0, 1, 0), "server-rekey": "server-rekey-1\n",
                "server-after-rekey": event(messages[4], 0, 1, 1)}
    logs = {}
    for name, wanted in expected.items():
        leaf = f"responder/c-{name}.stdout"
        record = sdk.snapshot(directory / leaf, maximum=65536)
        ready, separator, output = record.data.decode().partition("\n")
        sdk.require(separator and re.fullmatch(r"listening:[1-9][0-9]{0,4}", ready)
                    and int(ready.split(":")[1]) <= 65535 and output == wanted,
                    "C server command outcome differs")
        logs[leaf] = record.sha256
        leaf = f"responder/c-{name}.stderr"
        record = sdk.snapshot(directory / leaf, maximum=65536)
        sdk.require(record.data == b"", "C server diagnostic differs")
        logs[leaf] = record.sha256
    return dict(report, application_readbacks=readbacks, command_logs=logs)


def export_sync_faults(report: dict, output: Path, profile: str) -> dict[str, str]:
    """Retain only independently checked public matrix records, never private stores."""
    from continuity_c_faults import verify_public
    sdk.require(profile in {"debug", "release"}, "unknown C sync-fault profile")
    evidence = Path(report["outside"])
    checked = verify_public(report, evidence, language="C")
    return witness.export_selected(checked, evidence, output / "c-sync-fault-public" / profile, report["scope"],
                                   replay=lambda path: verify_public(report, path, language="C"))


def verify_admission(stdout: bytes) -> None:
    tests = {
        "tests::full_call_budget_preserves_drain_and_returns_capacity_after_failure",
        "opening::tests::prepared_open_is_cancelable_single_use_and_capacity_bounded",
        "invocation::tests::enclosing_deadline_is_shared_without_refresh_and_cannot_be_reentered",
        "invocation::tests::expired_admission_and_independent_owners_do_not_change_active_scope",
        "invocation::tests::sequential_calls_keep_their_own_cancellation_without_retaining_idle_authority",
        "recovery::invocation_tests::expired_constructor_publication_returns_its_slot_without_a_handle",
        "recovery::invocation_tests::late_native_errors_survive_and_success_requires_original_state_reconciliation",
        "witness::tests::retained_tcp_endpoint_observes_each_invocations_cancellation",
        "witness::tests::retained_tls_endpoint_observes_each_invocations_cancellation",
    }
    text = stdout.decode()
    passed = re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE)
    sdk.require(len(passed) == len(tests) and set(passed) == tests and re.search(
        r"^test result: ok\. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", text, re.MULTILINE),
        "C admission, deadline and drain contract did not execute completely")


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
              sdk_output: Path, records: dict, *, openssl_prefix: Path | None = None) -> dict:
    result = {"completed": False, "scope": QUALIFICATION_SCOPE, "release_claim_eligible": False, "execution": {}}
    try:
        return _qualify_c(outside, output, cargo, environment, candidate_files,
                          original_lock, sdk_output, records, result, openssl_prefix=openssl_prefix)
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "C_CONSUMER.json", result)


def _qualify_c(outside: Path, output: Path, cargo: list[str], environment: dict,
               candidate_files: dict[str, bytes], original_lock: bytes,
               sdk_output: Path, records: dict, result: dict, *, openssl_prefix: Path | None = None) -> dict:
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
                "SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "OPENSSL_CONF", "OPENSSL_CONF_INCLUDE", "OPENSSL_MODULES",
                "OPENSSL_ENGINES", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        env.pop(key, None)
    def run(argv, label, cwd=consumer, *, runtime=None):
        return sdk.command(argv, output / ("c-" + label), cwd, environment=env if runtime is None else runtime)
    metadata = parse_strict_json_bytes(run([*cargo, "metadata", "--offline", "--format-version", "1"],
                                         "metadata"), label="C installed dependency resolution")
    lock = sdk.snapshot(consumer / "Cargo.lock")
    result["resolution"] = package.verify_resolution(metadata, consumer, lock.data, original_lock,
                                                     consumer_name=NAME, required_features=FEATURES)
    darwin = os.uname().sysname == "Darwin"
    cc = Path(run(["/usr/bin/xcrun", "--sdk", "macosx", "--find", "clang"], "cc-path").decode().strip()) if darwin else Path("/usr/bin/cc")
    cc = cc.resolve(strict=True)
    compiler = sdk.snapshot(cc, maximum=MAX_BINARY)
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
        library_identity = sdk.snapshot(library, maximum=MAX_BINARY)
        installed = outside / ("c-installed-" + profile)
        installed.mkdir(mode=0o700)
        sdk.copy(library, installed / filename, maximum=MAX_BINARY)
        sdk.require(sdk.snapshot(installed / filename, maximum=MAX_BINARY).sha256 == library_identity.sha256,
                    "installed C library differs from the selected build output")
        executable = installed / "qpc-c-client"
        run([str(cc), *platform_flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-pthread",
             *( ["-O2"] if profile == "release" else ["-O0", "-g"] ),
             str(consumer / "client.c"), str(consumer / "recovery_client.c"), str(consumer / "opening_client.c"), "-I", str(consumer), "-L", str(installed), "-l" + LIBRARY,
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
        client_identity = sdk.snapshot(executable, maximum=MAX_BINARY)
        built = run([*cargo, "test", "--locked", "--offline", "--test", "c_owner", "--no-run",
                     "--message-format=json", "-j", "2", *extra], "trace-build-" + profile)
        runtime = {k: v for k, v in env.items() if not k.startswith(("DYLD_", "LD_"))}
        unit_build = run([*cargo, "test", "--locked", "--offline", "--lib", "--no-run", "--message-format=json",
                          "-j", "2", *extra], "admission-build-" + profile)
        unit_test = built_artifact(unit_build, consumer, build, library=False, unit=True)
        unit_identity = sdk.snapshot(unit_test, maximum=MAX_BINARY)
        checked = run([str(unit_test)], "admission-" + profile, runtime=runtime)
        verify_admission(checked)
        trace = built_artifact(built, consumer, build, library=False)
        trace_identity = sdk.snapshot(trace, maximum=MAX_BINARY)
        evidence = outside / ("c-" + profile + "-runtime")
        runtime.update(QPERIAPT_C_OWNER_CLIENT=str(executable), QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
        tested = run([str(trace), "--exact", TEST, "--nocapture"], "trace-" + profile, runtime=runtime)
        result["execution"][profile] = verify_execution(tested, evidence)
        device_evidence = outside / ("c-" + profile + "-device-runtime")
        runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(device_evidence)
        tested = run([str(trace), "--exact", device.TEST, "--nocapture"], "device-trace-" + profile, runtime=runtime)
        checked = device.verify_execution(tested, device_evidence)
        checked["exported_public_files"] = witness.export_selected(checked, device_evidence,
            output / "c-device-public" / profile, device.SCOPE,
            replay=lambda path: device.verify_execution(tested, path))
        result["execution"][profile]["device_parent"] = checked
        account_evidence = outside / ("c-" + profile + "-account-runtime")
        runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(account_evidence)
        tested = run([str(trace), "--exact", account.TEST, "--nocapture"], "account-trace-" + profile, runtime=runtime)
        account_evidence = account_evidence.with_name(account_evidence.name + "-account")
        checked = account.verify_execution(tested, account_evidence)
        checked["exported_public_files"] = witness.export_selected(checked, account_evidence,
            output / "c-account-public" / profile, account.SCOPE,
            replay=lambda path: account.verify_execution(tested, path))
        result["execution"][profile]["account_owner"] = checked
        server_evidence = outside / ("c-" + profile + "-server-runtime")
        runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(server_evidence)
        tested = run([str(trace), "--exact", SERVER_TEST, "--nocapture"], "server-trace-" + profile, runtime=runtime)
        result["execution"][profile]["server"] = verify_server_execution(tested, server_evidence)
        recovery_evidence = outside / ("c-" + profile + "-recovery-runtime")
        runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(recovery_evidence)
        tested = run([str(trace), "--exact", recovery.TEST, "--nocapture"], "recovery-trace-" + profile, runtime=runtime)
        result["execution"][profile]["recovery"] = recovery.verify_execution(tested, recovery_evidence)
        restore_evidence = outside / ("c-" + profile + "-restore-runtime")
        runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(restore_evidence)
        restored_stdout = run([str(trace), "--exact", RESTORE_TEST, "--nocapture"], "restore-trace-" + profile, runtime=runtime)
        restore_evidence = restore_evidence.with_name(restore_evidence.name + "-session-reopen")
        restored = verify_restore_execution(restored_stdout, restore_evidence)
        restored_files = witness.export_selected(restored, restore_evidence, output / "c-restore-public" / profile, restored["scope"],
            replay=lambda path: verify_restore_execution(restored_stdout, path))
        result["execution"][profile]["restoration"] = {"execution": restored, "public_files": restored_files}
        from continuity_c_faults import Matrix
        fault_build = run([*cargo, "test", "--locked", "--offline", "--test", "sync_fault", "--no-run",
                           "--message-format=json", "-j", "2", *extra], "fault-build-" + profile)
        fault_helper = built_artifact(fault_build, consumer, build, library=False, test_name="sync_fault")
        probe = installed / ("sync-probe.dylib" if darwin else "sync-probe.so")
        smoke = installed / "sync-probe-smoke"
        c_flags = [str(cc), *platform_flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                   *(["-O2"] if profile == "release" else ["-O0", "-g"])]
        run([*c_flags, *( ["-dynamiclib"] if darwin else ["-fPIC", "-shared"] ),
             str(consumer / "sync_probe.c"), *( [] if darwin else ["-ldl"] ), "-o", str(probe)],
            "fault-probe-" + profile)
        run([*c_flags, str(consumer / "sync_probe_smoke.c"), "-o", str(smoke)], "fault-smoke-" + profile)
        result["execution"][profile]["sync_faults"] = Matrix(
            outside, output, profile, runtime, executable, fault_helper, probe, smoke).execute()
        result["execution"][profile]["sync_fault_public_files"] = export_sync_faults(
            result["execution"][profile]["sync_faults"], output, profile)
        from continuity_c_account_cleanup import qualify as qualify_account_cleanup
        account_cleanup_build = run([*cargo, "test", "--locked", "--offline", "--test", "account_cleanup",
                                     "--no-run", "--message-format=json", "-j", "2", *extra],
                                    "account-cleanup-build-" + profile)
        account_cleanup_helper = built_artifact(account_cleanup_build, consumer, build,
                                               library=False, test_name="account_cleanup")
        result["execution"][profile]["account_cleanup"] = qualify_account_cleanup(
            outside, output, profile, runtime, executable, account_cleanup_helper,
            probe, smoke, installed / filename)
        from continuity_c_account_witness import qualify as qualify_account_witness
        account_witness_build = run([*cargo, "test", "--locked", "--offline", "--test", "account_witness",
                                     "--no-run", "--message-format=json", "-j", "2", *extra],
                                    "account-witness-build-" + profile)
        account_witness_helper = built_artifact(account_witness_build, consumer, build,
                                               library=False, test_name="account_witness")
        result["execution"][profile]["account_witness"] = qualify_account_witness(
            outside, output, profile, runtime, executable, account_witness_helper, installed / filename)
        result["execution"][profile]["account_tls"] = qualify_account_witness(
            outside, output, profile, runtime, executable, account_witness_helper, installed / filename, scenario="mutual-tls")
        result["execution"][profile]["account_tls_loss"] = qualify_account_witness(
            outside, output, profile, runtime, executable, account_witness_helper, installed / filename, scenario="mutual-tls-loss")
        result["execution"][profile]["account_delivery"] = qualify_account_witness(
            outside, output, profile, runtime, executable, account_witness_helper, installed / filename, scenario="mutual-tls-delivery")
        result["execution"][profile]["own_account_delivery"] = qualify_account_witness(
            outside, output, profile, runtime, executable, account_witness_helper, installed / filename, scenario="own-tls-delivery")
        result["execution"][profile]["own_account_tls_loss"] = qualify_account_witness(
            outside, output, profile, runtime, executable, account_witness_helper, installed / filename, scenario="own-tls-loss")
        witness_build = run([*cargo, "test", "--locked", "--offline", "--test", "witness", "--no-run",
                             "--message-format=json", "-j", "2", *extra], "witness-build-" + profile)
        witness_helper = built_artifact(witness_build, consumer, build, library=False, test_name="witness")
        witness_identity = sdk.snapshot(witness_helper, maximum=MAX_BINARY)
        opening_evidence = outside / ("c-" + profile + "-opening-runtime")
        device_witness_evidence = outside / ("c-" + profile + "-device-witness-runtime")
        runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(device_witness_evidence)
        tested = run([str(witness_helper), "--exact", device.WITNESS_TEST, "--nocapture"],
                     "device-witness-trace-" + profile, runtime=runtime)
        checked = device.verify_witness_execution(tested, device_witness_evidence)
        checked["exported_public_files"] = witness.export_selected(checked, device_witness_evidence,
            output / "c-device-witness-public" / profile, device.WITNESS_SCOPE,
            replay=lambda path: device.verify_witness_execution(tested, path))
        result["execution"][profile]["device_parent_witness"] = checked
        runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(opening_evidence)
        tested = run([str(witness_helper), "--exact", opening.TEST, "--nocapture"],
                     "opening-trace-" + profile, runtime=runtime)
        result["execution"][profile]["opening"] = opening.verify_execution(tested, opening_evidence)
        result["execution"][profile]["opening"]["exported_public_files"] = opening.export_public(
            tested, opening_evidence, output / "c-opening-public" / profile)
        restore_opening_evidence = outside / ("c-" + profile + "-restore-opening-runtime")
        runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(restore_opening_evidence)
        restored_opening_stdout = run([str(witness_helper), "--exact", opening.RESTORE_TEST, "--nocapture"],
                                     "restore-opening-trace-" + profile, runtime=runtime)
        restored_opening = opening.verify_restore_execution(restored_opening_stdout, restore_opening_evidence)
        restored_opening_files = witness.export_selected(restored_opening, restore_opening_evidence,
            output / "c-restore-opening-public" / profile, restored_opening["scope"],
            replay=lambda path: opening.verify_restore_execution(restored_opening_stdout, path))
        result["execution"][profile]["restoration_opening"] = {"execution": restored_opening, "public_files": restored_opening_files}
        witness_evidence = outside / ("c-" + profile + "-witness-runtime")
        runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(witness_evidence)
        tested = run([str(witness_helper), "--exact", witness.TEST, "--nocapture"], "witness-trace-" + profile, runtime=runtime)
        result["execution"][profile]["witness"] = witness.verify_execution(tested, witness_evidence)
        result["execution"][profile]["witness"]["exported_public_files"] = witness.export_public(
            tested, witness_evidence, output / "c-witness-public" / profile)
        tls_evidence = outside / ("c-" + profile + "-witness-tls-runtime")
        runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(tls_evidence)
        tested = run([str(witness_helper), "--exact", witness_tls.TEST, "--nocapture"],
                     "witness-tls-trace-" + profile, runtime=runtime)
        result["execution"][profile]["witness_tls"] = witness_tls.verify_execution(tested, tls_evidence)
        result["execution"][profile]["witness_tls"]["exported_public_files"] = witness_tls.export_public(
            tested, tls_evidence, output / "c-witness-tls-public" / profile)
        if openssl_prefix is not None:
            peer, peer_identity = witness_openssl.build_peer(
                openssl_prefix, cc, platform_flags, consumer, installed, run, darwin=darwin, profile=profile)
            runtime["QPERIAPT_WITNESS_OPENSSL_PEER"] = str(peer)
            qualification = {"completed": False, "peer": peer_identity, "execution": {}}
            result["execution"][profile]["witness_openssl"] = qualification
            for kind, test in witness_openssl.TESTS.items():
                interop_evidence = outside / f"c-{profile}-witness-openssl-{kind}-runtime"
                runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(interop_evidence)
                tested = run([str(witness_helper), "--exact", test, "--nocapture"],
                             f"witness-openssl-{kind}-{profile}", runtime=runtime)
                checked = witness_openssl.verify_execution(kind, tested, interop_evidence)
                checked["exported_public_files"] = witness_openssl.export_public(
                    kind, tested, interop_evidence, output / "c-witness-openssl-public" / profile / kind)
                qualification["execution"][kind] = checked
            witness_openssl.verify_dependencies(peer_identity["dependency_files"])
            qualification["completed"] = True
            runtime.pop("QPERIAPT_WITNESS_OPENSSL_PEER")
        sdk.require(sdk.snapshot(witness_helper, maximum=MAX_BINARY).sha256 == witness_identity.sha256,
                    "installed witness helper changed during execution")
        result["execution"][profile]["witness"]["binary"] = {
            "path": str(witness_helper), "sha256": witness_identity.sha256, "bytes": witness_identity.size}
        binaries = {}
        for name, path, identity in (("C_client", executable, client_identity),
                                     ("C_library", installed / filename, library_identity),
                                     ("Rust_admission", unit_test, unit_identity),
                                     ("Rust_trace", trace, trace_identity)):
            sdk.require(sdk.snapshot(path, maximum=MAX_BINARY).sha256 == identity.sha256,
                        "C qualification executable or library changed during execution")
            binaries[name] = {"path": str(path), "sha256": identity.sha256, "bytes": identity.size}
        result["execution"][profile]["binaries"] = binaries
    run([*cargo, "clippy", "--locked", "--offline", "--all-targets", "-j", "2", "--", "-D", "warnings"], "clippy")
    sdk.require(sdk.snapshot(cc, maximum=MAX_BINARY).sha256 == compiler.sha256
                and sdk.snapshot(consumer / "Cargo.lock").sha256 == lock.sha256
                and sdk.snapshot(consumer / "Cargo.toml").sha256 == manifest_hash,
                "C compiler or consumer resolution changed")
    if darwin:
        sdk.require(sdk.snapshot(platform_sdk / "SDKSettings.json").sha256 == sdk_settings.sha256,
                    "C platform SDK settings changed")
    for relative, digest in template_hashes.items():
        if relative != "Cargo.toml":
            sdk.require(sdk.snapshot(consumer / relative).sha256 == digest, "C consumer input changed")
    for profile in result["execution"].values():
        if "witness_openssl" in profile:
            witness_openssl.verify_dependencies(profile["witness_openssl"]["peer"]["dependency_files"])
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
