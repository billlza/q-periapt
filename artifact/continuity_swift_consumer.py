"""Package and execute the Swift owner against the already qualified C engine."""
from pathlib import Path
import hashlib
import os
import re

import continuity_c_consumer as c
import continuity_c_recovery as recovery
import continuity_c_opening as opening
import continuity_c_witness as witness
import continuity_c_witness_tls as witness_tls
import continuity_c_faults as faults
import continuity_c_account_cleanup as account_cleanup
import continuity_c_account_witness as account_witness
import continuity_c_setup as setup
import continuity_setup_faults as setup_faults
import continuity_setup_io as setup_io
import continuity_setup_witness_faults as setup_witness_faults
import continuity_package as package
from continuity_package_archive import MAX_PACKAGE, archive, unpack
import rust_sdk_profile as sdk
from evidence_io import consume_regular_snapshot, parse_strict_json_bytes
import third_party_licenses as licenses

FIXTURE = package.ROOT / "bindings/swift/ContinuityPackageConsumer"
LIBRARY = "libq_periapt_continuity_c_consumer.dylib"
# Hosted Xcode 16.4's compiler exceeds the native consumer's 256-MiB budget.
# Tool identity has its own cap; streaming preserves bounded memory and the
# same complete-file hash and mutation-sensitive descriptor checks.
MAX_COMPILER_BYTES = 1024**3
SCOPE = "unpublished installed Swift client/server/recovery and shared C/Rust engine; same-host macOS; local and explicitly witnessed original-installation profiles"


def compiler_command(value: str) -> tuple[Path, dict]:
    command = Path(value.strip())
    sdk.require(command.is_absolute() and command.name == "swift" and os.access(command, os.X_OK),
                "Swift package-manager command differs")
    resolved = command.resolve(strict=True)
    binary = consume_regular_snapshot(resolved, maximum=MAX_COMPILER_BYTES, label="Swift compiler identity")
    # Xcode's swift is a link to swift-frontend. Its invoked name selects driver
    # and package-manager dispatch; hashing the target must not change argv[0].
    return command, {"command_path": str(command), "path": str(resolved),
                     "sha256": binary.sha256, "bytes": binary.size}


def verify_tests(stdout: bytes, stderr: bytes) -> None:
    text = (stdout + stderr).decode()
    tests = {"OwnerTests.testARCRetiresPendingSlotsAndClosedAliases", "OwnerTests.testDiagnosticRejectsInconsistentAndInvalidUTF8",
             "OwnerTests.testIDsAndTextsRejectAmbiguousInput", "ServerTests.testCallbackCopiesBorrowedRegions",
             "ServerTests.testCallbackFailureAndForeignBoundsCannotBecomeConsumption",
             "ServerTests.testServedRecordRejectsUnknownKindsAndInconsistentBootstrap",
             "RecoveryTests.testRecoverySharesRegistryAndRetainsCancelledClosedAuthority",
             "RecoveryTests.testClosureDecodingPreservesCountersAndRejectsUnknownStates",
             "RecoveryTests.testClosureStatusKeepsReportIdentityAndRejectsMalformedOpen",
             "AccountRecoveryTests.testCompleteAccountMetadataPreservesFullWidthAndRejectsMalformedPresence",
             "AccountRecoveryTests.testAccountCleanupStatusRejectsNarrowingAndKeepsExactReport",
             "AccountRecoveryTests.testAccountCleanupCannotAcquireAuthorityFromPendingOrClosedOwner",
             "AccountRecoveryTests.testReconciliationKeepsEveryOutcomeAndRejectsPartialOrNoncanonicalFrames",
             "DeviceTests.testPreparedDeviceCapacityCancellationAndNoPrematurePeerAuthority",
             "DeviceTests.testAggregateStatusRequiresTheExactReportShapeAndPreservesUnknownStates",
             "DeviceTests.testAccountDeliveryRejectsMisboundOutputAndDistinguishesRetainedOutcomes",
             "SetupTests.testPendingSetupSharesCapacityAndCannotActivateAfterCancellation",
             "SetupTests.testInstallationStatusRejectsUnknownPhaseAndZeroJournal",
             "SetupTests.testOriginalGenesisRejectsMisbindingAndUnexpectedWitnessMetadata",
             "EnrollmentTests.testNativeEnrollmentLayoutsMatchHeader",
             "EnrollmentTests.testSixPhasesRejectImpossibleIdentityAndCheckpointCombinations",
             "EnrollmentTests.testRequestRejectsTruncationAndUnexpectedTail",
             "EnrollmentTests.testApprovedValuesOwnBytesAndPreserveUnsignedCounters",
             "EnrollmentTests.testPreparationCopiesIntentAndNativeRequestSurvivesFailedActivation",
             "EnrollmentTests.testPendingRegistrationSharesQuotaAndPreservesCloseAfterRefusal",
             "CredentialRenewalTests.testRenewalStatusPreservesHistoricalBindingAndRejectsMalformedCombinations",
             "CredentialRenewalTests.testWitnessProposalOwnsCanonicalBytesAndRejectsOverflowOrContradictoryHeads",
             "CredentialRenewalTests.testCancellationOwnsTargetFreeBytesAndRejectsProposalOrInvalidHead",
             "CredentialRenewalTests.testOriginalRenewalIdentitiesOwnBytesAndRejectZeroOrWrongWidths",
             "PolicyContinuationTests.testIndependentPolicyDocumentOwnsInputAndMatchesNativeLayout",
             "PolicyContinuationTests.testExtendedProposalAndCancellationPreserveGAndTWithExplicitTransactionMode",
             "PolicyContinuationTests.testExtendedMetadataRejectsInvalidModeTVersionAndWidth",
             "PolicyContinuationTests.testVariableNativeRecordsCheckPayloadTailAndExcludeABIPadding"}
    passed = [owner + "." + name for owner, name in re.findall(
        r"Test Case '-\[QPeriaptContinuityTests\.(\w+) (\w+)\]' passed", text)]
    sdk.require(len(passed) == len(tests) and set(passed) == tests
                and f"Executed {len(tests)} tests, with 0 failures" in text,
                "Swift owner tests did not all execute")


def verify_execution(stdout: bytes, directory: Path) -> dict:
    checked = c.verify_execution(stdout, directory, language="Swift")
    checked["public_readbacks"] = checked.pop("application_readbacks") | {
        "c-public-result.json": sdk.snapshot(directory / "c-public-result.json").sha256}
    return checked


def verify_server_execution(stdout: bytes, directory: Path) -> dict:
    checked = c.verify_server_execution(stdout, directory, language="Swift")
    checked["public_readbacks"] = checked.pop("application_readbacks") | {
        "c-server-public-result.json": sdk.snapshot(directory / "c-server-public-result.json").sha256}
    return checked


def verify_recovery_execution(stdout: bytes, directory: Path) -> dict:
    checked = recovery.verify_execution(stdout, directory, language="Swift")
    checked["public_readbacks"]["c-recovery-public-result.json"] = sdk.snapshot(directory / "c-recovery-public-result.json").sha256
    return checked


def verify_linkage(dependencies: str, loader: str, native_dir: Path) -> list[str]:
    names = [line.strip().split(" (", 1)[0] for line in dependencies.splitlines()[1:] if line.strip()]
    sdk.require(names.count("@rpath/" + LIBRARY) == 1 and all(
        name == "@rpath/" + LIBRARY or name.startswith(("/usr/lib/", "/System/Library/Frameworks/"))
        for name in names), "Swift executable depends on an unqualified library")
    paths = re.findall(r"cmd LC_RPATH\s+cmdsize \d+\s+path (.+?) \(offset", loader)
    sdk.require(paths.count(str(native_dir)) == 1, "Swift installed library search path differs")
    # SwiftBuild contributes toolchain/framework rpaths. Each actual client
    # process additionally checks dyld's loaded native image against native_dir.
    return paths


def qualify_swift(outside: Path, output: Path, native: dict, environment: dict) -> dict:
    sdk.require(os.uname().sysname == "Darwin" and native["completed"], "Swift qualification requires a completed native macOS C package")
    result = {"completed": False, "scope": SCOPE, "release_claim_eligible": False, "profiles": {}}
    env = {key: value for key, value in environment.items()
           if not key.startswith(("DYLD_", "LD_", "QPERIAPT_", "QPC_TEST_", "SWIFT_"))}
    try:
        def run(argv, label, cwd=outside, *, runtime=None):
            return sdk.command(argv, output / ("swift-" + label), cwd, environment=env if runtime is None else runtime)
        swift, identity = compiler_command(run(["/usr/bin/xcrun", "--find", "swift"], "tool-path").decode())
        result["compiler"] = dict(identity, version=run([str(swift), "--version"], "tool-version").decode())
        source = {}
        for path in FIXTURE.rglob("*"):
            sdk.require(not path.is_symlink(), "Swift source contains a symlink")
            if path.is_file():
                source[path.relative_to(FIXTURE).as_posix()] = sdk.snapshot(path).data
        for name in ("LICENSE", "LICENSE-APACHE", "LICENSE-MIT"):
            source[name] = sdk.snapshot(package.CANDIDATE / name).data
        source["native/include/qpc_owner.h"] = sdk.snapshot(c.FIXTURE / "qpc_owner.h").data
        source["LICENSES/Rust-1.98.1-library.html"] = sdk.snapshot(package.ROOT / "LICENSES/Rust-1.98.1-library.html").data
        for name in ("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md"):
            source["LICENSES/mlkem-native/" + name] = sdk.snapshot(
                package.ROOT / "crates/q-periapt-mlkem-native-sys/vendor" / name).data
        sdk.require(os.uname().machine == "arm64", "SDK 0.2.0 macOS support requires Apple Silicon")
        target = "aarch64-apple-darwin"
        cargo = str(Path(environment["RUSTC"]).parent / "cargo")
        metadata = parse_strict_json_bytes(run([cargo, "metadata", "--locked", "--offline", "--format-version", "1",
            "--filter-platform", target], "license-metadata", outside / "c-consumer", runtime=environment), label="Swift native license graph")
        notices = outside / "swift-native-notices"
        notices.mkdir(mode=0o700)
        licenses.collect(outside / "c-consumer", notices, target, root_package=c.NAME, resolved_metadata=metadata)
        for path in notices.rglob("*"):
            if path.is_file():
                source[path.relative_to(notices).as_posix()] = sdk.snapshot(path).data
        for profile in ("debug", "release"):
            row = native["execution"][profile]
            library = sdk.snapshot(Path(row["binaries"]["C_library"]["path"]), maximum=c.MAX_BINARY)
            sdk.require(library.sha256 == row["binaries"]["C_library"]["sha256"], "native library changed before Swift installation")
            files = dict(source, **{"native/lib/" + LIBRARY: library.data})
            hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
            data = archive(files)
            filename = f"q-periapt-continuity-swift-0.0.0-{profile}.zip"
            with (output / filename).open("xb") as stream:
                stream.write(data)
            consumer = outside / ("swift-installed-" + profile)
            unpack(sdk.snapshot(output / filename, maximum=MAX_PACKAGE).data, hashes, consumer)
            licenses.verify(consumer, expected_target=target, root_package=c.NAME)
            native_dir = consumer / "native/lib"
            arguments = [str(swift), "test", "--package-path", str(consumer), "--configuration", profile,
                         "-j", "2", "-Xswiftc", "-warnings-as-errors", "-Xcc", "-I" + str(consumer / "native/include"),
                         "-Xlinker", "-L" + str(native_dir), "-Xlinker", "-rpath", "-Xlinker", str(native_dir)]
            tested = run(arguments, "tests-" + profile)
            verify_tests(tested, sdk.snapshot(output / f"swift-tests-{profile}.stderr").data)
            path = run([str(swift), "build", "--package-path", str(consumer), "--configuration", profile,
                        "--show-bin-path"], "binary-path-" + profile).decode().strip()
            binary = Path(path).resolve(strict=True) / "ContinuityClient"
            sdk.require(binary.is_relative_to(consumer / ".build"), "Swift executable escaped the installed package")
            executable = sdk.snapshot(binary, maximum=c.MAX_BINARY)
            dependencies = run(["/usr/bin/otool", "-L", str(binary)], "dependencies-" + profile).decode()
            loader = run(["/usr/bin/otool", "-l", str(binary)], "loader-" + profile).decode()
            loader_paths = verify_linkage(dependencies, loader, native_dir)
            trace = Path(row["binaries"]["Rust_trace"]["path"])
            sdk.require(sdk.snapshot(trace, maximum=c.MAX_BINARY).sha256 == row["binaries"]["Rust_trace"]["sha256"],
                        "native protocol harness changed")
            evidence = outside / ("swift-" + profile + "-runtime")
            runtime = dict(env, QPERIAPT_C_OWNER_CLIENT=str(binary), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="Swift",
                           QPERIAPT_EXPECTED_CONTINUITY_LIBRARY=str(native_dir / LIBRARY),
                           QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
            stdout = run([str(trace), "--exact", c.TEST, "--nocapture"], "trace-" + profile, runtime=runtime)
            checked = verify_execution(stdout, evidence)
            exported = output / "swift-public" / profile
            from continuity_c_witness import export_selected
            public_files = export_selected(checked, evidence, exported, SCOPE,
                                           replay=lambda path: verify_execution(stdout, path))
            from continuity_c_enrollment import qualify_foreign as qualify_enrollment
            enrollment = qualify_enrollment(outside, output, profile, runtime, row, run, language="Swift")
            from continuity_c_account import TEST as ACCOUNT_TEST, SCOPE as ACCOUNT_SCOPE, verify_execution as verify_account
            account_evidence = outside / ("swift-" + profile + "-account-runtime")
            runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(account_evidence)
            account_stdout = run([str(trace), "--exact", ACCOUNT_TEST, "--nocapture"], "account-trace-" + profile, runtime=runtime)
            account_evidence = account_evidence.with_name(account_evidence.name + "-account")
            account_checked = verify_account(account_stdout, account_evidence, language="Swift")
            account_files = export_selected(account_checked, account_evidence, output / "swift-public/account" / profile,
                ACCOUNT_SCOPE.replace("C complete-account", "Swift complete-account"),
                replay=lambda path: verify_account(account_stdout, path, language="Swift"))
            server_evidence = outside / ("swift-" + profile + "-server-runtime")
            runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(server_evidence)
            server_stdout = run([str(trace), "--exact", c.SERVER_TEST, "--nocapture"], "server-trace-" + profile, runtime=runtime)
            server_checked = verify_server_execution(server_stdout, server_evidence)
            server_files = export_selected(server_checked, server_evidence, output / "swift-public/server" / profile, SCOPE,
                                            replay=lambda path: verify_server_execution(server_stdout, path))
            recovery_evidence = outside / ("swift-" + profile + "-recovery-runtime")
            runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(recovery_evidence)
            recovery_stdout = run([str(trace), "--exact", recovery.TEST, "--nocapture"], "recovery-trace-" + profile, runtime=runtime)
            recovery_checked = verify_recovery_execution(recovery_stdout, recovery_evidence)
            recovery_files = export_selected(recovery_checked, recovery_evidence, output / "swift-public/recovery" / profile, SCOPE,
                                              replay=lambda path: verify_recovery_execution(recovery_stdout, path))
            restore_evidence = outside / ("swift-" + profile + "-restore-runtime")
            runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(restore_evidence)
            restored_stdout = run([str(trace), "--exact", c.RESTORE_TEST, "--nocapture"], "restore-trace-" + profile, runtime=runtime)
            restore_evidence = restore_evidence.with_name(restore_evidence.name + "-session-reopen")
            restored = c.verify_restore_execution(restored_stdout, restore_evidence, language="Swift")
            restored_files = export_selected(restored, restore_evidence, output / "swift-public/restore" / profile, restored["scope"],
                replay=lambda path: c.verify_restore_execution(restored_stdout, path, language="Swift"))
            witness_binary = Path(row["witness"]["binary"]["path"])
            sdk.require(sdk.snapshot(witness_binary, maximum=c.MAX_BINARY).sha256 == row["witness"]["binary"]["sha256"],
                        "native witness harness changed before Swift execution")
            witnessed = {}
            for label, module in (("opening", opening), ("signed-tcp", witness), ("mutual-tls", witness_tls)):
                witness_evidence = outside / ("swift-" + profile + "-witness-" + label)
                runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(witness_evidence)
                witness_stdout = run([str(witness_binary), "--exact", module.TEST, "--nocapture"],
                                     "witness-" + label + "-" + profile, runtime=runtime)
                witness_checked = module.verify_execution(witness_stdout, witness_evidence, language="Swift")
                witness_files = export_selected(witness_checked, witness_evidence,
                    output / "swift-public" / ("witness-" + label) / profile, SCOPE,
                    replay=lambda path: module.verify_execution(witness_stdout, path, language="Swift"))
                witnessed[label] = {"execution": witness_checked, "public_files": witness_files}
            restore_opening_evidence = outside / f"swift-{profile}-restore-opening-runtime"
            runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(restore_opening_evidence)
            restore_opening_stdout = run([str(witness_binary), "--exact", opening.RESTORE_TEST, "--nocapture"],
                                        "restore-opening-trace-" + profile, runtime=runtime)
            restore_opening = opening.verify_restore_execution(restore_opening_stdout, restore_opening_evidence, language="Swift")
            restore_opening_files = export_selected(restore_opening, restore_opening_evidence,
                output / "swift-public/restore-opening" / profile, restore_opening["scope"],
                replay=lambda path: opening.verify_restore_execution(restore_opening_stdout, path, language="Swift"))
            sdk.require(sdk.snapshot(witness_binary, maximum=c.MAX_BINARY).sha256 == row["witness"]["binary"]["sha256"],
                        "native witness harness changed during Swift execution")
            fault_tools = faults.verified_tools(row["sync_faults"], language="C")
            sync_faults = faults.Matrix(outside, output, profile, runtime, binary,
                fault_tools["native_helper"], fault_tools["sync_probe"], fault_tools["probe_smoke"],
                language="Swift", expected_library=native_dir / LIBRARY).execute()
            fault_evidence = Path(sync_faults["outside"])
            fault_checked = faults.verify_public(sync_faults, fault_evidence, language="Swift")
            fault_files = export_selected(fault_checked, fault_evidence,
                output / "swift-public/sync-faults" / profile, sync_faults["scope"],
                replay=lambda path: faults.verify_public(sync_faults, path, language="Swift"))
            cleanup_helper = row["account_cleanup"]["binaries"]["native_helper"]
            sdk.require(sdk.snapshot(Path(cleanup_helper["path"]), maximum=c.MAX_BINARY).sha256 == cleanup_helper["sha256"],
                        "native account cleanup helper changed before Swift execution")
            cleaned = account_cleanup.qualify(outside, output, profile, runtime, binary,
                Path(cleanup_helper["path"]), fault_tools["sync_probe"], fault_tools["probe_smoke"],
                native_dir / LIBRARY, language="Swift")
            witness_helper = row["account_witness"]["binaries"]["native_helper"]
            sdk.require(sdk.snapshot(Path(witness_helper["path"]), maximum=c.MAX_BINARY).sha256 == witness_helper["sha256"],
                        "native account witness helper changed before Swift execution")
            witnessed_account = account_witness.qualify(outside, output, profile, runtime, binary,
                Path(witness_helper["path"]), native_dir / LIBRARY, language="Swift")
            tls_account = account_witness.qualify(outside, output, profile, runtime, binary,
                Path(witness_helper["path"]), native_dir / LIBRARY, scenario="mutual-tls", language="Swift")
            tls_loss_account = account_witness.qualify(outside, output, profile, runtime, binary,
                Path(witness_helper["path"]), native_dir / LIBRARY, scenario="mutual-tls-loss", language="Swift")
            delivered_account = account_witness.qualify(outside, output, profile, runtime, binary,
                Path(witness_helper["path"]), native_dir / LIBRARY, scenario="mutual-tls-delivery", language="Swift")
            own_delivery = account_witness.qualify(outside, output, profile, runtime, binary,
                Path(witness_helper["path"]), native_dir / LIBRARY, scenario="own-tls-delivery", language="Swift")
            own_cleanup = account_witness.qualify(outside, output, profile, runtime, binary,
                Path(witness_helper["path"]), native_dir / LIBRARY, scenario="own-tls-loss", language="Swift")
            setup_helper = row["setup"]["local"]["binaries"]["native_helper"]
            sdk.require(setup_helper == row["setup"]["witness"]["binaries"]["native_helper"]
                        and sdk.snapshot(Path(setup_helper["path"]), maximum=c.MAX_BINARY).sha256 == setup_helper["sha256"],
                        "native setup helper changed before Swift execution")
            configured = {scenario: setup.qualify(outside, output, profile, runtime, binary,
                Path(setup_helper["path"]), native_dir / LIBRARY, scenario=scenario, language="Swift")
                for scenario in ("local", "witness")}
            setup_fault_helper = row["setup_faults"]["binaries"]["native_helper"]
            sdk.require(sdk.snapshot(Path(setup_fault_helper["path"]), maximum=c.MAX_BINARY).sha256 == setup_fault_helper["sha256"],
                        "native setup fault helper changed before Swift execution")
            interrupted_setup = setup_faults.qualify(outside, output, profile, runtime, binary,
                Path(setup_fault_helper["path"]), fault_tools["sync_probe"], fault_tools["probe_smoke"],
                language="Swift", expected_library=native_dir / LIBRARY)
            io_setup = setup_io.qualify(outside, output, profile, runtime, binary,
                Path(setup_fault_helper["path"]), fault_tools["sync_probe"], fault_tools["probe_smoke"],
                language="Swift", expected_library=native_dir / LIBRARY)
            witnessed_setup = setup_witness_faults.qualify_all(outside, output, profile, runtime, binary,
                setup_witness_faults.installed_helper(row["setup_witness_faults"]), fault_tools["sync_probe"], fault_tools["probe_smoke"],
                language="Swift", expected_library=native_dir / LIBRARY)
            for name, expected in hashes.items():
                sdk.require(sdk.snapshot(consumer / name, maximum=MAX_PACKAGE).sha256 == expected,
                            "installed Swift package changed")
            sdk.require(sdk.snapshot(binary, maximum=c.MAX_BINARY).sha256 == executable.sha256,
                        "Swift executable changed during execution")
            result["profiles"][profile] = {"archive": filename, "archive_sha256": hashlib.sha256(data).hexdigest(),
                "files": hashes, "binary": {"path": str(binary), "sha256": executable.sha256, "bytes": executable.size},
                "native_library_sha256": library.sha256, "loader_paths": loader_paths,
                "execution": checked, "public_files": public_files, "enrollment": enrollment,
                "account_owner": {"execution": account_checked, "public_files": account_files},
                "account_cleanup": cleaned, "setup": configured, "setup_faults": interrupted_setup, "setup_io": io_setup,
                "setup_witness_faults": witnessed_setup,
                "account_witness": witnessed_account, "account_tls": tls_account, "account_tls_loss": tls_loss_account, "account_delivery": delivered_account,
                "own_account_delivery": own_delivery, "own_account_tls_loss": own_cleanup,
                "server_execution": server_checked, "server_public_files": server_files,
                "recovery_execution": recovery_checked, "recovery_public_files": recovery_files,
                "witnessed": witnessed, "restoration": {"execution": restored, "public_files": restored_files},
                "restoration_opening": {"execution": restore_opening, "public_files": restore_opening_files}, "sync_faults": sync_faults, "sync_fault_public_files": fault_files}
        sdk.require(compiler_command(str(swift))[1] == identity, "Swift compiler or command resolution changed")
        result["completed"] = True
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "SWIFT_CONSUMER.json", result)
    return result
