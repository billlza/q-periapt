"""Package and execute the Kotlin/JVM owner against qualified native C packages."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shlex
import xml.etree.ElementTree as ET

import continuity_c_consumer as c
import continuity_c_recovery as recovery
import continuity_c_faults as faults
import continuity_c_opening as opening
import continuity_c_witness as witness
import continuity_c_witness_tls as witness_tls
import continuity_c_account as account
import continuity_c_account_cleanup as account_cleanup
import continuity_c_account_witness as account_witness
import continuity_c_setup as setup
import continuity_setup_faults as setup_faults
import continuity_setup_io as setup_io
import continuity_setup_witness_faults as setup_witness_faults
from continuity_c_witness import export_selected
import continuity_package as package
from continuity_package_archive import MAX_PACKAGE, archive, unpack
from evidence_io import consume_regular_snapshot, parse_strict_json_bytes
import jvm_sdk_package as jvm
import rust_sdk_profile as sdk
import third_party_licenses as licenses

FIXTURE = package.ROOT / "bindings/kotlin/ContinuityPackageConsumer"
SCOPE = ("unpublished installed Kotlin/JVM client/server/recovery and shared C/Rust engine; "
         "same-host macOS or GNU/Linux; local and explicitly witnessed original-installation profiles; "
         "test-host controller interruption uses explicit native cancel/join; "
         "calibrated journal sync process interruption and bounded prepared/in-flight owner GC under selected C2 frames; "
         "other JVM implementations and automatic JVM cancellation qualification remain separate")
TEST_NAMES = frozenset({
    "identifiersAreTypedImmutablePublicValues", "unsignedCountersRetainTheirWholeRange",
    "structuresMatchThe64BitNativeContract", "pendingOwnersRejectWorkAndCancellationNeverActivates",
    "failedOpenReleasesTheOriginalOwnerSlot", "bothKindsShareCapacityAndDrainRemainsAvailable",
    "recoveryCancellationAndClosedStateKeepTheirNativeKinds",
    "textAndApplicationRefusalsCannotSilentlyCoerceInvalidInput",
    "devicePreparationCannotGrantPeerAuthorityAndSharesCapacity",
    "aggregateStatusPreservesReportsAndRejectsMalformedOutput",
    "accountDeliveryRequiresSelectedSessionAndTypedRetainedOutcomes",
    "accountCleanupCannotAcquireAuthorityFromPendingCancelledOrClosedOwner",
    "reconciliationPreservesEveryOutcomeAndRejectsPartialOrNoncanonicalFrames",
    "pendingSetupSharesCapacityAndCannotActivateAfterCancellation",
    "installationStatusRejectsUnknownPhaseAndZeroJournal",
    "originalGenesisRejectsMisbindingAndUnexpectedWitnessMetadata",
    "enrollmentCopiesApprovedInputsAndRejectsInvalidScope",
    "enrollmentPhaseAndRequestDecodingRefuseContradictoryNativeOutput",
    "pendingEnrollmentSharesCapacityAndCancellationConsumesOnlyAdmission",
    "originalEnrollmentRequestPersistsWithoutPolicyOrTlsConfiguration",
})
RENEWAL_TEST_NAMES = frozenset({
    "cancellationOwnsTargetFreeBytesAndRejectsProposalOrInvalidHead",
    "witnessProposalOwnsCanonicalBytesAndRejectsOverflowOrContradictoryHeads",
    "renewalIdentitiesAreDistinctImmutableAndNonzero",
    "historicalRenewalStatesRetainExactFieldsAndUnsignedTime",
    "contradictoryRenewalFieldsNeverBecomeAnAbsentOrSuccessfulResult",
    "grantLengthChecksPreserveOwnersAndInclusiveLimitReachesNativeAdmission",
})
POLICY_TEST_NAMES = frozenset({
    "policyLayoutsAndRecordPaddingMatchInstalledHeader",
    "policyFfmInputsReachRealNativeBoundaryWithoutReplacingPreparedOwner",
    "extendedGrammarRejectsWrongLengthsTagsModesZeroBindingsAndNonzeroUnusedTail",
    "independentPolicyDocumentOwnsInputsAndPreservesUnsignedCheckpoint",
    "adoptCarryAndLegacyKeepDifferentTransactionStatements",
})

INDEPENDENT_TEST_SUITES = {
    "RosterRefreshTests": frozenset({
        "retainedRosterProposalOwnsExactScopeAndRejectsOtherDomains",
        "rosterPreparationChecksCanonicalAbsenceAndABI",
        "rosterProgressPreservesAllSixStatesAndChecksProposalScope",
        "rosterCallsRespectPreparedCancelledAndClosedOwners",
        "peerRosterAdmissionRespectsBoundsAndOwnerLifetime",
    }),
    "PolicyRenewalTests": frozenset({
        "nativeLayoutsAndOffsetsMatchTheCanonicalCRecord",
        "retainedRequestOwnsEveryByteAndRoundTripsUnsignedFields",
        "scopesRejectContradictoryPredecessorsAndNoncanonicalOptions",
        "requestRejectsDirtyTailEmptyFieldsAndImpossibleOriginalHead",
        "allProgressStatesRemainDistinctIncludingBothAbandonmentReasons",
        "malformedStatusesCannotBecomeCommittedOrNoCommit",
    }),
    "RosterResolutionTests": frozenset({
        "layoutHasExactSizeAndAlignment",
        "allFourOutcomesPreserveUnknownAndUnsignedOrdering",
        "malformedAndContradictoryResultsAreRejected",
        "resolvedPhaseKeepsOriginalPairAndStillRejectsUnknownPhases",
    }),
    "IndependentPolicyTests": frozenset({
        "independentDescriptorOwnsAllBytesAndRejectsOtherDomains",
        "preparationDistinguishesCanonicalAbsenceAndRejectsDirtyFlags",
        "progressKeepsEveryTerminalAndRetirementStateDistinct",
        "witnessCallsRespectPreparedCancelledAndClosedOwnerBoundaries",
    }),
}


def verify_opening_interruption(stdout: bytes, directory: Path) -> dict:
    checked = opening.verify_execution(stdout, directory, language="Kotlin")
    for carrier in ("tcp", "tls"):
        leaf = "initiator/kotlin-opening-controller-interrupted-" + carrier
        receipt = sdk.snapshot(directory / leaf, maximum=128)
        sdk.require(receipt.data == b"QPC-JVM-INTERRUPT/1\n"
                    b"control-interrupted native-218 joined flag-retained owner-closed\n",
                    "Kotlin controller interruption receipt differs")
        checked["public_readbacks"][leaf] = receipt.sha256
    checked["scope"] += "; controlling JVM thread interrupted; explicit native cancel/join and retained interrupt flag"
    checked["controller_interruption"] = True
    return checked


def verify_gc_execution(stdout: bytes) -> dict:
    match = re.fullmatch(rb"QPC-JVM-GC/1 rounds=16 forgotten=1024 queued=1024 live=1024 stale=1024 collections=([1-9][0-9]{0,4})\n", stdout)
    sdk.require(match is not None and 32 <= int(match[1]) <= 16384,
                "Kotlin prepared-owner GC workload did not execute completely")
    return {"rounds": 16, "forgotten_owner_graphs": 1024, "queued_weak_references": 1024, "strongly_live_owners": 1024,
            "stale_owners_checked_after_slot_reuse": 1024, "observed_collections": int(match[1]),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "release_claim_eligible": False,
            "scope": "bounded prepared-owner Cleaner/capacity and stale-slot checks; no in-flight call or all-JVM GC qualification"}


def maven_contract() -> jvm.MavenContract:
    return jvm.MavenContract("dev.qperiapt", "q-periapt-continuity-kotlin", "0.0.0",
        "dev.qperiapt.continuity", "Q-Periapt Continuity JVM candidate",
        (("QPeriapt-Continuity-ABI", "qpc-owner/1"),), "dev/qperiapt/continuity/",
        ("ContinuityOwner", "ContinuityRecoveryOwner", "ContinuityDevice", "ContinuitySetup", "JournalID",
         "InstallationStatus", "InstallationPhase", "InstallationPreparation", "WitnessGenesis", "AccountTarget", "AccountOperationID",
         "AccountMemberState", "AccountReconciledMember", "AccountReconciliation",
         "ContinuityEnrollment", "PolicyRenewalID", "PolicyRenewalStatementID", "PolicyAuthorizationID",
         "PolicyRenewalScope", "PolicyRenewalRequest", "PolicyRenewalStatus", "PolicyRenewalAbandonment",
         "IndependentPolicyProposal", "IndependentPolicyState", "IndependentPolicyProgress",
         "RosterRefreshOutcome", "RosterRefreshResolution", "RosterRefreshID", "RosterPolicySource",
         "RosterRefreshScope", "RosterRefreshProposal", "RosterRefreshProgress", "RosterRefreshState",
         "SessionID", "MessageID", "Counter64"), FIXTURE)


def source_files() -> dict[str, bytes]:
    selected = [FIXTURE / name for name in ("build.gradle.kts", "settings.gradle.kts", "README.md",
                "gradle/verification-metadata.xml", "consumer/build.gradle.kts", "consumer/settings.gradle.kts")]
    for directory in ("src", "consumer/src", "consumer/negative"):
        for path in (FIXTURE / directory).rglob("*"):
            sdk.require(not path.is_symlink(), "Kotlin package source contains a symlink")
            if not path.is_dir(): selected.append(path)
    result = {}
    for path in selected:
        sdk.require(not path.is_symlink(), "Kotlin package source contains a symlink")
        result[path.relative_to(FIXTURE).as_posix()] = sdk.snapshot(path).data
    sdk.require(result and all(result.values()), "Kotlin package source is missing or empty")
    return result


def tool_identity(root: Path) -> dict:
    """Hash the tool distribution, including JVM modules and Gradle implementation JARs."""
    sdk.require(root.is_absolute(), "select an absolute JVM tool installation")
    root = root.resolve(strict=True)
    paths = sorted(root.rglob("*"))
    sdk.require(len(paths) <= 8192, "JVM tool distribution exceeds its file bound")
    result = {}
    total = 0
    for path in paths:
        if path.is_dir():
            sdk.require(not path.is_symlink(), "JVM tool contains a symlinked directory")
            continue
        target = path.resolve(strict=True)
        sdk.require(target.is_relative_to(root), "JVM tool link escapes its selected installation")
        value = consume_regular_snapshot(target, maximum=512 * 1024**2, label="JVM tool input")
        total += value.size
        sdk.require(total <= 2 * 1024**3, "JVM tool distribution exceeds its byte bound")
        result[path.relative_to(root).as_posix()] = {
            "sha256": value.sha256, "bytes": value.size,
            "target": target.relative_to(root).as_posix(),
            "link": os.readlink(path) if path.is_symlink() else None,
        }
    sdk.require(result, "JVM tool distribution is empty")
    return {"root": str(root), "files": result}


def verify_tests(data: bytes) -> dict:
    return _verify_test_suite(data, "OwnerTests", TEST_NAMES)


def _verify_test_suite(data: bytes, name: str, names: frozenset[str]) -> dict:
    sdk.require(len(data) <= 1024**2 and b"<!DOCTYPE" not in data and b"<!ENTITY" not in data,
                "JVM test report is oversized or contains external declarations")
    suite = ET.fromstring(data)
    cases = suite.findall("testcase")
    expected = {name + "()" for name in names}
    sdk.require(suite.tag == "testsuite" and suite.get("name") == "dev.qperiapt.continuity." + name
                and suite.get("tests") == str(len(expected))
                and all(suite.get(key) == "0" for key in ("failures", "errors", "skipped"))
                and len(cases) == len(expected) and {case.get("name") for case in cases} == expected
                and all(case.get("classname") == suite.get("name") and len(case) == 0 for case in cases),
                "JVM owner tests did not all execute successfully")
    sdk.require(all((suite.findtext(tag) or "").strip() == "" for tag in ("system-out", "system-err")),
                "JVM owner tests emitted unexpected diagnostics")
    return {"tests": len(expected), "report_sha256": hashlib.sha256(data).hexdigest()}


def verify_test_reports(directory: Path) -> dict:
    expected = {"OwnerTests": TEST_NAMES, "CredentialRenewalTests": RENEWAL_TEST_NAMES,
                "PolicyContinuationTests": POLICY_TEST_NAMES, **INDEPENDENT_TEST_SUITES}
    sdk.require({p.name for p in directory.glob("TEST-*.xml")} == {
        "TEST-dev.qperiapt.continuity." + name + ".xml" for name in expected},
        "JVM owner and lifecycle test report set differs")
    suites = {name: _verify_test_suite(sdk.snapshot(directory / (
        "TEST-dev.qperiapt.continuity." + name + ".xml")).data, name, names)
        for name, names in expected.items()}
    return {"tests": sum(row["tests"] for row in suites.values()), "suites": suites}


def retain_test_reports(directory: Path, output: Path, *, profile: str = "") -> dict:
    sdk.require(profile in {"", "debug", "release"}, "unqualified JVM test report profile")
    checked = verify_test_reports(directory)
    suffix = "-" + profile if profile else ""
    for name, record in checked["suites"].items():
        data = sdk.snapshot(directory / ("TEST-dev.qperiapt.continuity." + name + ".xml")).data
        sdk.require(hashlib.sha256(data).hexdigest() == record["report_sha256"],
                    "JVM test report changed before retention")
        label = re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()
        filename = "kotlin-" + label + suffix + ".xml"
        with (output / filename).open("xb") as stream:
            stream.write(data)
        record["report_file"] = filename
    return checked


def verify_execution(stdout: bytes, directory: Path) -> dict:
    checked = c.verify_execution(stdout, directory, language="Kotlin")
    checked["public_readbacks"] = checked.pop("application_readbacks") | {
        "c-public-result.json": sdk.snapshot(directory / "c-public-result.json").sha256}
    return checked


def verify_server_execution(stdout: bytes, directory: Path) -> dict:
    checked = c.verify_server_execution(stdout, directory, language="Kotlin")
    checked["public_readbacks"] = checked.pop("application_readbacks") | {
        "c-server-public-result.json": sdk.snapshot(directory / "c-server-public-result.json").sha256}
    return checked


def account_parent_lifetime(data: bytes) -> dict:
    match = re.fullmatch(rb"QPC-JVM-ACCOUNT/1 collections=([1-9][0-9]{0,3})\n"
        rb"public-parent-queued peers-activated close-winner=1 closed-aliases-held slots=64 store-reopened\n", data)
    sdk.require(match is not None and 2 <= int(match[1]) <= 1024,
                "Kotlin account parent collection and close workload did not complete")
    return {"observed_collections": int(match[1]), "concurrent_close_winners": 1,
        "native_slots_reclaimed_while_closed_aliases_live": 64, "public_parent_collected_before_activation": True}


def verify_account_execution(stdout: bytes, directory: Path) -> dict:
    checked = account.verify_execution(stdout, directory, language="Kotlin")
    leaf = "initiator/kotlin-account-parent-lifetime"
    receipt = sdk.snapshot(directory / leaf, maximum=256)
    checked["public_readbacks"][leaf] = receipt.sha256
    checked["parent_lifetime"] = account_parent_lifetime(receipt.data)
    return checked


def verify_inflight_execution(stdout: bytes, directory: Path) -> dict:
    checked = verify_server_execution(stdout, directory)
    messages = checked["messages"]
    expected = [("fail-before", messages[0]), ("uncertain", messages[1]),
                ("crash-after", messages[2]), ("uncertain", messages[3]),
                *(("message", messages[index]) for index in (0, 1, 2, 4))]
    leaves = set()
    collections = []
    for mode, message in expected:
        original = bytes.fromhex(checked["session"] + message) + b"persisted before process exit"
        leaf = f"responder/kotlin-gc-callback-{mode}-{message}"
        receipt = sdk.snapshot(directory / leaf, maximum=256)
        header, separator, payload = receipt.data.partition(b"\n")
        match = re.fullmatch(rb"QPC-JVM-INFLIGHT/1 callback collections=([1-9][0-9]{0,3})", header)
        sdk.require(separator and match is not None and 5 <= int(match[1]) <= 1024 and payload == original,
                    "Kotlin in-flight GC callback receipt differs")
        collections.append(int(match[1])); leaves.add(leaf)
        checked["public_readbacks"][leaf] = receipt.sha256
        if mode != "crash-after":
            leaf = f"responder/kotlin-gc-return-{mode}-{message}"
            receipt = sdk.snapshot(directory / leaf, maximum=256)
            sdk.require(receipt.data == b"QPC-JVM-INFLIGHT/1 returned slots=64 copied-delivery-valid\n" + original,
                        "Kotlin in-flight GC returned-owner receipt differs")
            leaves.add(leaf); checked["public_readbacks"][leaf] = receipt.sha256
    sdk.require({"responder/" + p.name for p in (directory / "responder").glob("kotlin-gc-*")} == leaves,
                "Kotlin in-flight GC receipt set differs")
    checked["inflight_gc"] = {"callbacks": 8, "returned_native_slot_checks": 7,
                              "callback_collections": collections, "crash_after_has_return_receipt": False}
    return checked


INFLIGHT_METHODS = frozenset({"consumer.UnrootedInvocation serve", "dev.qperiapt.continuity.ContinuityOwner serve",
                              "dev.qperiapt.continuity.NativeOwner call"})


def inflight_vm_flags(collector: str, logs: Path) -> list[str]:
    sdk.require(collector in {"Serial", "G1"}, "unknown Kotlin in-flight collector")
    methods = sorted(name.replace(" ", "::") for name in INFLIGHT_METHODS)
    return ["-Xms32m", "-Xmx128m", "-XX:+Use" + collector + "GC", "-Xcomp", "-Xbatch", "-XX:-TieredCompilation",
            "-XX:CompileCommand=quiet", *("-XX:CompileCommand=compileonly," + name for name in methods),
            *("-XX:CompileCommand=dontinline," + name for name in methods),
            "-XX:+UnlockDiagnosticVMOptions", "-XX:+LogCompilation", "-XX:LogFile=" + str(logs / "jit-%p.xml")]


def verify_inflight_compilation(logs: Path, evidence: Path, *, collector: str) -> dict:
    required_flags = set(inflight_vm_flags(collector, logs)[:-1])
    expected = {"message": 5, "uncertain": 2, "fail-before": 1, "crash-after": 1,
                "bootstrap": 1, "pre-cancel": 1, "deadline": 1, "rekey": 1}
    observed = dict.fromkeys(expected, 0)
    files = sorted(logs.glob("jit-*.xml"))
    sdk.require(len(files) == 13, "Kotlin in-flight compilation log count differs")
    checked = {}
    for path in files:
        data = sdk.snapshot(path, maximum=16 * 1024**2)
        sdk.require(b"<!DOCTYPE" not in data.data and b"<!ENTITY" not in data.data, "JVM compilation log declares entities")
        root = ET.fromstring(data.data)
        flags = set(shlex.split(root.findtext("vm_arguments/args") or ""))
        sdk.require(required_flags <= flags and {flag for flag in flags if re.fullmatch(r"-XX:\+Use.*GC", flag)}
                    == {"-XX:+Use" + collector + "GC"}, "Kotlin in-flight JVM stress configuration differs")
        command = shlex.split(root.findtext("vm_arguments/command") or "")
        sdk.require(root.tag == "hotspot_log" and len(command) in {5, 6}
                    and command[:4] == ["consumer.ContinuityClientKt", "--gc-in-flight", "serve", str(evidence / "responder")]
                    and command[4] in expected and (len(command) == 6) == (command[4] == "rekey"),
                    "Kotlin in-flight JVM invocation differs")
        mode = command[4]; observed[mode] += 1
        compiled = {" ".join(node.get("method", "").split()[:2]) for node in root.iter("nmethod")
                    if node.get("compiler") == "c2"}
        required = INFLIGHT_METHODS - ({"consumer.UnrootedInvocation serve"} if mode == "rekey" else set())
        sdk.require(required <= compiled, "Kotlin in-flight frames were not compiled by C2")
        checked[path.name] = {"sha256": data.sha256, "mode": mode, "compiled_frames": sorted(required)}
    sdk.require(observed == expected, "Kotlin in-flight compilation workload differs")
    return checked


def verify_recovery_execution(stdout: bytes, directory: Path) -> dict:
    checked = recovery.verify_execution(stdout, directory, language="Kotlin")
    checked["public_readbacks"]["c-recovery-public-result.json"] = sdk.snapshot(directory / "c-recovery-public-result.json").sha256
    return checked


def runtime_closure(data: bytes, distribution: Path, jar_sha256: str, outside: Path) -> dict:
    sdk.require(len(data) <= 65536 and data.endswith(b"\n"), "JVM runtime closure exceeds its bound or is truncated")
    expected = {maven_contract().coordinate, "org.jetbrains.kotlin:kotlin-stdlib:2.4.20", "org.jetbrains:annotations:13.0"}
    result = {}
    for line in data.decode("utf-8").splitlines():
        fields = line.split("\t")
        sdk.require(len(fields) == 3, "JVM runtime resolution record differs")
        coordinate, name, digest = fields
        path = Path(name)
        sdk.require(coordinate in expected and coordinate not in result and path.is_absolute()
                    and path.resolve(strict=True) == path
                    and not path.is_relative_to(package.ROOT) and path.is_relative_to(outside)
                    and re.fullmatch(r"[0-9a-f]{64}", digest), "JVM runtime coordinate or location differs")
        sdk.require(sdk.snapshot(path).sha256 == digest, "resolved JVM dependency bytes changed")
        installed = distribution / "lib" / path.name
        sdk.require(sdk.snapshot(installed).sha256 == digest, "installed JVM dependency differs from resolution")
        result[coordinate] = {"resolved": str(path), "installed": str(installed), "sha256": digest}
    sdk.require(set(result) == expected and result[maven_contract().coordinate]["sha256"] == jar_sha256,
                "JVM runtime dependency closure or SDK JAR differs")
    names = {Path(value["installed"]).name for value in result.values()} | {"continuity-installed-consumer.jar"}
    sdk.require({p.name for p in (distribution / "lib").iterdir()} == names,
                "installed JVM distribution contains an unqualified dependency")
    return result


def qualify_kotlin(outside: Path, output: Path, native: dict, environment: dict,
                   java_home: Path, gradle_home: Path) -> dict:
    sdk.require(native["completed"] and (os.uname().sysname == "Linux" or
                (os.uname().sysname == "Darwin" and os.uname().machine == "arm64")),
                "Kotlin qualification requires completed native C packages on a supported host")
    result = {"completed": False, "scope": SCOPE, "release_claim_eligible": False, "profiles": {}}
    try:
        tools = {"java": tool_identity(java_home), "gradle": tool_identity(gradle_home)}
        java_home = Path(tools["java"]["root"]); gradle_home = Path(tools["gradle"]["root"])
        java = java_home / "bin/java"; javac = java_home / "bin/javac"; gradle = gradle_home / "bin/gradle"
        sdk.require(all(p.is_file() and os.access(p, os.X_OK) for p in (java, javac, gradle)),
                    "selected Java/Gradle commands are not executable")
        result["tools"] = tools
        env = {k: v for k, v in environment.items()
               if k not in {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"}
               and not k.startswith(("JAVA_", "GRADLE_", "KOTLIN_", "DYLD_", "LD_", "QPERIAPT_", "QPC_"))}
        gradle_cache = outside / "kotlin-gradle-home"; gradle_cache.mkdir(mode=0o700)
        env.update(JAVA_HOME=str(java_home), GRADLE_USER_HOME=str(gradle_cache),
                   PATH=str(java_home / "bin") + os.pathsep + env.get("PATH", os.defpath))
        def run(argv, label, cwd=outside, *, runtime=None, rejection=None):
            return jvm.run(argv, output / ("kotlin-" + label), cwd, env if runtime is None else runtime, rejection=rejection)
        versions = {"java": run([str(java), "--version"], "java-version").decode(),
                    "javac": run([str(javac), "--version"], "javac-version").decode(),
                    "gradle": run([str(gradle), "--version"], "gradle-version").decode()}
        sdk.require(re.match(r"(?:openjdk|java) 25(?:[ .])", versions["java"])
                    and versions["javac"].startswith("javac 25") and "\nGradle 9.8.0\n" in versions["gradle"],
                    "Kotlin candidate requires JDK 25 and Gradle 9.8.0")
        result["versions"] = versions
        source = source_files(); contract = maven_contract()
        builder_root = outside / "kotlin-source"
        builder = builder_root / "bindings/kotlin/ContinuityPackageConsumer"
        for name, data in source.items():
            path = builder / name; path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream: stream.write(data)
        for name, path in jvm.NOTICE_PATHS.items():
            sdk.copy(path, builder_root / "LICENSES" / Path(name).name)
        flags = [str(gradle), "--no-daemon", "--warning-mode", "fail", "--dependency-verification", "strict",
                 "--max-workers", "2", "-Dorg.gradle.java.installations.auto-download=false",
                 "-Pkotlin.compiler.execution.strategy=in-process",
                 "-Dorg.gradle.java.home=" + str(java_home)]
        library_name = "libq_periapt_continuity_c_consumer." + ("dylib" if os.uname().sysname == "Darwin" else "so")
        debug_lib = Path(native["execution"]["debug"]["binaries"]["C_library"]["path"])
        sdk.require(sdk.snapshot(debug_lib, maximum=c.MAX_BINARY).sha256 == native["execution"]["debug"]["binaries"]["C_library"]["sha256"],
                    "native library changed before JVM owner tests")
        run([*flags, "--project-dir", str(builder), "test", "publishContinuityPublicationToCandidateRepository",
             "-Pqperiapt.continuity.lib=" + str(debug_lib)], "build-sdk")
        tests = builder / "build/test-results/test"
        result["owner_tests"] = retain_test_reports(tests, output)
        staged = builder / "build/candidate-maven"
        maven = outside / "kotlin-maven"
        for path in (staged / contract.path).iterdir(): sdk.copy(path, maven / contract.path / path.name)
        result["maven"] = jvm.verify_maven(maven, contract=contract)
        target = {("Darwin", "arm64"): "aarch64-apple-darwin",
                  ("Linux", "aarch64"): "aarch64-unknown-linux-gnu", ("Linux", "x86_64"): "x86_64-unknown-linux-gnu"}.get((os.uname().sysname, os.uname().machine))
        sdk.require(target is not None, "unsupported native Kotlin host")
        metadata = parse_strict_json_bytes(run([str(Path(environment["RUSTC"]).parent / "cargo"), "metadata", "--locked", "--offline",
            "--format-version", "1", "--filter-platform", target], "native-license-metadata", outside / "c-consumer", runtime=environment),
            label="Kotlin native license graph")
        notices = outside / "kotlin-native-notices"; notices.mkdir(mode=0o700)
        licenses.collect(outside / "c-consumer", notices, target, root_package=c.NAME, resolved_metadata=metadata)
        files = {"maven/" + p.relative_to(maven).as_posix(): sdk.snapshot(p).data for p in maven.rglob("*") if p.is_file()}
        files.update({p.relative_to(notices).as_posix(): sdk.snapshot(p).data for p in notices.rglob("*") if p.is_file()})
        files["README.md"] = source["README.md"]
        files["native/include/qpc_owner.h"] = sdk.snapshot(c.FIXTURE / "qpc_owner.h").data
        files["LICENSES/Rust-1.98.1-library.html"] = sdk.snapshot(package.ROOT / "LICENSES/Rust-1.98.1-library.html").data
        for name in ("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md"):
            files["LICENSES/mlkem-native/" + name] = sdk.snapshot(package.ROOT / "crates/q-periapt-mlkem-native-sys/vendor" / name).data
        files.update({name: data for name, data in source.items() if name.startswith("consumer/")})
        for profile in ("debug", "release"):
            row = native["execution"][profile]
            library = sdk.snapshot(Path(row["binaries"]["C_library"]["path"]), maximum=c.MAX_BINARY)
            sdk.require(library.sha256 == row["binaries"]["C_library"]["sha256"], "native library changed before Kotlin installation")
            payload = files | {"native/lib/" + library_name: library.data}
            hashes = {name: hashlib.sha256(data).hexdigest() for name, data in payload.items()}
            data = archive(payload); filename = f"q-periapt-continuity-kotlin-0.0.0-{target}-{profile}.zip"
            with (output / filename).open("xb") as stream: stream.write(data)
            installed = outside / ("kotlin-installed-" + profile)
            unpack(sdk.snapshot(output / filename, maximum=MAX_PACKAGE).data, hashes, installed)
            licenses.verify(installed, expected_target=target, root_package=c.NAME)
            sdk.require(jvm.verify_maven(installed / "maven", contract=contract) == result["maven"], "installed Maven identity differs")
            consumer = installed / "consumer"
            jvm.pin_consumer_dependencies(consumer, installed / "maven", contract=contract)
            run([*flags, "--project-dir", str(consumer), "installDist", "recordRuntime",
                 "-Pqperiapt.repository=" + str(installed / "maven")], "install-" + profile)
            distribution = consumer / "build/install/continuity-installed-consumer"
            resolved = runtime_closure(sdk.snapshot(consumer / "build/runtime.tsv").data, distribution,
                                       result["maven"]["jar_sha256"], outside)
            jar_files = {p.name: sdk.snapshot(p).sha256 for p in (distribution / "lib").iterdir()}
            library_path = installed / "native/lib" / library_name
            run([*flags, "--project-dir", str(builder), "--rerun-tasks", "test",
                 "-Pqperiapt.continuity.lib=" + str(library_path)], "owner-tests-" + profile)
            owner_tests = retain_test_reports(tests, output, profile=profile)
            classpath = os.pathsep.join(str(distribution / "lib" / name) for name in sorted(jar_files))
            argv = [str(java), "--enable-native-access=ALL-UNNAMED", "--illegal-native-access=deny",
                    "-Dqperiapt.continuity.lib=" + str(library_path), "-cp", classpath, "consumer.ContinuityClientKt"]
            launcher = installed / "client"
            with launcher.open("x") as stream: stream.write("#!/bin/sh\nexec " + shlex.join(argv) + ' "$@"\n')
            launcher.chmod(0o700); launcher_sha = sdk.snapshot(launcher).sha256
            gc_execution = {}
            for collector in ("Serial", "G1"):
                label = f"gc-{collector.lower()}-{profile}"
                stdout = run([str(java), "-Xms32m", "-Xmx128m", "-XX:+Use" + collector + "GC",
                              *argv[1:], "gc-owner-capacity"], label)
                sdk.require(sdk.snapshot(output / ("kotlin-" + label + ".stderr")).data == b"",
                            "Kotlin GC workload emitted unexpected diagnostics")
                gc_execution[collector] = verify_gc_execution(stdout)
            interrupt_launcher = installed / "client-opening-interrupt"
            with interrupt_launcher.open("x") as stream:
                stream.write("#!/bin/sh\nexec " + shlex.join([*argv, "--interrupt-opening-controller"]) + ' "$@"\n')
            interrupt_launcher.chmod(0o700); interrupt_launcher_sha = sdk.snapshot(interrupt_launcher).sha256
            trace = Path(row["binaries"]["Rust_trace"]["path"])
            sdk.require(sdk.snapshot(trace, maximum=c.MAX_BINARY).sha256 == row["binaries"]["Rust_trace"]["sha256"], "native Kotlin harness changed")
            traces = {}
            for label, test, verify in (("client", c.TEST, verify_execution), ("server", c.SERVER_TEST, verify_server_execution),
                                        ("recovery", recovery.TEST, verify_recovery_execution)):
                evidence = outside / f"kotlin-{profile}-{label}-runtime"
                runtime = dict(env, QPERIAPT_C_OWNER_CLIENT=str(launcher), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="Kotlin",
                               QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
                stdout = run([str(trace), "--exact", test, "--nocapture"], f"{label}-trace-{profile}", runtime=runtime)
                checked = verify(stdout, evidence)
                exported = export_selected(checked, evidence, output / "kotlin-public" / label / profile, SCOPE,
                                            replay=lambda path: verify(stdout, path))
                traces[label] = {"execution": checked, "public_files": exported}
            from continuity_c_enrollment import qualify_foreign as qualify_enrollment
            enrollment = {}
            for collector in ("Serial", "G1"):
                enrollment_launcher = installed / ("client-enrollment-" + collector.lower())
                command = [str(java), "-Xms32m", "-Xmx128m", "-XX:+Use" + collector + "GC", *argv[1:]]
                with enrollment_launcher.open("x") as stream:
                    stream.write("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
                enrollment_launcher.chmod(0o700)
                enrollment_digest = sdk.snapshot(enrollment_launcher).sha256
                enrollment_runtime = dict(env, QPERIAPT_C_OWNER_CLIENT=str(enrollment_launcher),
                                          QPERIAPT_INSTALLED_CLIENT_LANGUAGE="Kotlin")
                enrollment[collector] = qualify_enrollment(outside, output, profile, enrollment_runtime, row, run,
                                                           language="Kotlin", collector=collector)
                sdk.require(sdk.snapshot(enrollment_launcher).sha256 == enrollment_digest,
                            "Kotlin enrollment launcher changed during execution")
            accounts = {}
            for collector in ("Serial", "G1"):
                account_launcher = installed / ("client-account-" + collector.lower())
                command = [str(java), "-Xms32m", "-Xmx96m", "-XX:+Use" + collector + "GC", *argv[1:]]
                with account_launcher.open("x") as stream:
                    stream.write("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
                account_launcher.chmod(0o700); account_digest = sdk.snapshot(account_launcher).sha256
                evidence = outside / f"kotlin-{profile}-account-{collector.lower()}-runtime"
                runtime = dict(env, QPERIAPT_C_OWNER_CLIENT=str(account_launcher), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="Kotlin",
                               QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
                stdout = run([str(trace), "--exact", account.TEST, "--nocapture"], f"account-{collector.lower()}-trace-{profile}", runtime=runtime)
                evidence = evidence.with_name(evidence.name + "-account")
                checked = verify_account_execution(stdout, evidence)
                exported = export_selected(checked, evidence, output / "kotlin-public/account" / profile / collector, checked["scope"],
                                           replay=lambda path: verify_account_execution(stdout, path))
                sdk.require(sdk.snapshot(account_launcher).sha256 == account_digest, "Kotlin account launcher changed")
                accounts[collector] = {"execution": checked, "public_files": exported, "command": command,
                    "launcher": {"path": str(account_launcher), "sha256": account_digest}}
            restore_evidence = outside / f"kotlin-{profile}-restore-runtime"
            runtime = dict(env, QPERIAPT_C_OWNER_CLIENT=str(launcher), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="Kotlin",
                           QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(restore_evidence))
            restored_stdout = run([str(trace), "--exact", c.RESTORE_TEST, "--nocapture"], f"restore-trace-{profile}", runtime=runtime)
            restore_evidence = restore_evidence.with_name(restore_evidence.name + "-session-reopen")
            restored = c.verify_restore_execution(restored_stdout, restore_evidence, language="Kotlin")
            restored_files = export_selected(restored, restore_evidence, output / "kotlin-public/restore" / profile, restored["scope"],
                replay=lambda path: c.verify_restore_execution(restored_stdout, path, language="Kotlin"))
            inflight = {}
            for collector in ("Serial", "G1"):
                label = "inflight-" + collector.lower()
                logs = output / "kotlin-inflight-compilation" / profile / collector
                logs.mkdir(parents=True, mode=0o700)
                gc_launcher = installed / ("client-" + label)
                command = [str(java), *inflight_vm_flags(collector, logs), *argv[1:], "--gc-in-flight"]
                with gc_launcher.open("x") as stream:
                    stream.write("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
                gc_launcher.chmod(0o700); digest = sdk.snapshot(gc_launcher).sha256
                evidence = outside / f"kotlin-{profile}-{label}-runtime"
                runtime = dict(env, QPERIAPT_C_OWNER_CLIENT=str(gc_launcher), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="Kotlin",
                               QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
                stdout = run([str(trace), "--exact", c.SERVER_TEST, "--nocapture"], f"{label}-trace-{profile}", runtime=runtime)
                checked = verify_inflight_execution(stdout, evidence)
                exported = export_selected(checked, evidence, output / "kotlin-public" / label / profile, SCOPE,
                                            replay=lambda path: verify_inflight_execution(stdout, path))
                compilation = verify_inflight_compilation(logs, evidence, collector=collector)
                sdk.require(sdk.snapshot(gc_launcher).sha256 == digest, "Kotlin in-flight launcher changed")
                inflight[collector] = {"execution": checked, "public_files": exported, "compilation": compilation,
                                      "launcher": {"path": str(gc_launcher), "sha256": digest}, "command": command}
            witness_binary = Path(row["witness"]["binary"]["path"])
            sdk.require(sdk.snapshot(witness_binary, maximum=c.MAX_BINARY).sha256 == row["witness"]["binary"]["sha256"],
                        "native witness harness changed before Kotlin execution")
            witnessed = {}
            for label, module in (("opening", opening), ("opening-interrupt", opening),
                                  ("signed-tcp", witness), ("mutual-tls", witness_tls)):
                evidence = outside / f"kotlin-{profile}-witness-{label}"
                selected_launcher = interrupt_launcher if label == "opening-interrupt" else launcher
                verify_witness = (verify_opening_interruption if label == "opening-interrupt" else
                                  lambda data, path: module.verify_execution(data, path, language="Kotlin"))
                runtime = dict(env, QPERIAPT_C_OWNER_CLIENT=str(selected_launcher), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="Kotlin",
                               QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
                stdout = run([str(witness_binary), "--exact", module.TEST, "--nocapture"],
                             f"witness-{label}-{profile}", runtime=runtime)
                checked = verify_witness(stdout, evidence)
                exported = export_selected(checked, evidence, output / "kotlin-public" / ("witness-" + label) / profile, checked["scope"],
                    replay=lambda path: verify_witness(stdout, path))
                witnessed[label] = {"execution": checked, "public_files": exported}
            restore_opening_evidence = outside / f"kotlin-{profile}-restore-opening-runtime"
            runtime = dict(env, QPERIAPT_C_OWNER_CLIENT=str(launcher), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="Kotlin",
                           QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(restore_opening_evidence))
            restore_opening_stdout = run([str(witness_binary), "--exact", opening.RESTORE_TEST, "--nocapture"],
                                        f"restore-opening-trace-{profile}", runtime=runtime)
            restore_opening = opening.verify_restore_execution(restore_opening_stdout, restore_opening_evidence, language="Kotlin")
            restore_opening_files = export_selected(restore_opening, restore_opening_evidence,
                output / "kotlin-public/restore-opening" / profile, restore_opening["scope"],
                replay=lambda path: opening.verify_restore_execution(restore_opening_stdout, path, language="Kotlin"))
            sdk.require(sdk.snapshot(witness_binary, maximum=c.MAX_BINARY).sha256 == row["witness"]["binary"]["sha256"],
                        "native witness harness changed during Kotlin execution")
            fault_tools = faults.verified_tools(row["sync_faults"], language="C")
            jvm_runtime = {"jvm_executable": java,
                "jvm_consumer": distribution / "lib/continuity-installed-consumer.jar",
                "jvm_sdk": distribution / "lib" / (contract.prefix + ".jar"),
                "jvm_stdlib": distribution / "lib" / ("kotlin-stdlib-" + jvm.KOTLIN + ".jar"),
                "jvm_annotations": distribution / "lib/annotations-13.0.jar"}
            sync_faults = faults.Matrix(outside, output, profile, env, launcher,
                fault_tools["native_helper"], fault_tools["sync_probe"], fault_tools["probe_smoke"],
                language="Kotlin", expected_library=library_path, jvm_runtime=jvm_runtime).execute()
            fault_evidence = Path(sync_faults["outside"])
            fault_checked = faults.verify_public(sync_faults, fault_evidence, language="Kotlin")
            fault_files = export_selected(fault_checked, fault_evidence,
                output / "kotlin-public/sync-faults" / profile, sync_faults["scope"],
                replay=lambda path: faults.verify_public(sync_faults, path, language="Kotlin"))
            cleanup_helper = row["account_cleanup"]["binaries"]["native_helper"]
            sdk.require(sdk.snapshot(Path(cleanup_helper["path"]), maximum=c.MAX_BINARY).sha256 == cleanup_helper["sha256"],
                        "native account cleanup helper changed before Kotlin execution")
            cleaned = account_cleanup.qualify(outside, output, profile, runtime, launcher,
                Path(cleanup_helper["path"]), fault_tools["sync_probe"], fault_tools["probe_smoke"],
                library_path, language="Kotlin", jvm_runtime=jvm_runtime)
            witness_helper = row["account_witness"]["binaries"]["native_helper"]
            sdk.require(sdk.snapshot(Path(witness_helper["path"]), maximum=c.MAX_BINARY).sha256 == witness_helper["sha256"],
                        "native account witness helper changed before Kotlin execution")
            witnessed_account = account_witness.qualify(outside, output, profile, runtime, launcher,
                Path(witness_helper["path"]), library_path, language="Kotlin", jvm_runtime=jvm_runtime)
            tls_account = account_witness.qualify(outside, output, profile, runtime, launcher,
                Path(witness_helper["path"]), library_path, scenario="mutual-tls", language="Kotlin", jvm_runtime=jvm_runtime)
            tls_loss_account = account_witness.qualify(outside, output, profile, runtime, launcher,
                Path(witness_helper["path"]), library_path, scenario="mutual-tls-loss", language="Kotlin", jvm_runtime=jvm_runtime)
            delivered_account = account_witness.qualify(outside, output, profile, runtime, launcher,
                Path(witness_helper["path"]), library_path, scenario="mutual-tls-delivery", language="Kotlin", jvm_runtime=jvm_runtime)
            own_delivery = account_witness.qualify(outside, output, profile, runtime, launcher,
                Path(witness_helper["path"]), library_path, scenario="own-tls-delivery", language="Kotlin", jvm_runtime=jvm_runtime)
            own_cleanup = account_witness.qualify(outside, output, profile, runtime, launcher,
                Path(witness_helper["path"]), library_path, scenario="own-tls-loss", language="Kotlin", jvm_runtime=jvm_runtime)
            setup_helper = row["setup"]["local"]["binaries"]["native_helper"]
            sdk.require(setup_helper == row["setup"]["witness"]["binaries"]["native_helper"]
                        and sdk.snapshot(Path(setup_helper["path"]), maximum=c.MAX_BINARY).sha256 == setup_helper["sha256"],
                        "native setup helper changed before Kotlin execution")
            configured = {scenario: setup.qualify(outside, output, profile, runtime, launcher,
                Path(setup_helper["path"]), library_path, scenario=scenario, language="Kotlin", jvm_runtime=jvm_runtime)
                for scenario in ("local", "witness")}
            setup_fault_helper = row["setup_faults"]["binaries"]["native_helper"]
            sdk.require(sdk.snapshot(Path(setup_fault_helper["path"]), maximum=c.MAX_BINARY).sha256 == setup_fault_helper["sha256"],
                        "native setup fault helper changed before Kotlin execution")
            interrupted_setup = setup_faults.qualify(outside, output, profile, runtime, launcher,
                Path(setup_fault_helper["path"]), fault_tools["sync_probe"], fault_tools["probe_smoke"],
                language="Kotlin", expected_library=library_path, jvm_runtime=jvm_runtime)
            io_setup = setup_io.qualify(outside, output, profile, runtime, launcher,
                Path(setup_fault_helper["path"]), fault_tools["sync_probe"], fault_tools["probe_smoke"],
                language="Kotlin", expected_library=library_path, jvm_runtime=jvm_runtime)
            witnessed_setup = setup_witness_faults.qualify_all(outside, output, profile, runtime, launcher,
                setup_witness_faults.installed_helper(row["setup_witness_faults"]), fault_tools["sync_probe"], fault_tools["probe_smoke"],
                language="Kotlin", expected_library=library_path, jvm_runtime=jvm_runtime)
            sdk_jar = installed / "maven" / contract.path / (contract.prefix + ".jar")
            module_path = os.pathsep.join([str(sdk_jar), *(value["installed"] for name, value in sorted(resolved.items()) if name != contract.coordinate)])
            java_args = [str(java), "--illegal-native-access=deny", "--module-path", module_path,
                         "--add-modules", "dev.qperiapt.continuity,kotlin.stdlib", "-cp", str(consumer / "build/classes/java/main"),
                         "-Dqperiapt.expectedJar=" + str(sdk_jar)]
            granted = java_args + ["--enable-native-access=dev.qperiapt.continuity"]
            stdout = run([*granted, "-Dqperiapt.continuity.lib=" + str(library_path), "consumer.LoaderProbe"], "java-module-" + profile)
            sdk.require(stdout == b"INSTALLED_CONTINUITY_JAVA_MODULE_PASS\n", "installed Java module did not execute its native owner")
            negatives = {"missing-property": (granted, "qperiapt.continuity.lib must select"),
                         "relative-path": ([*granted, "-Dqperiapt.continuity.lib=relative"], "absolute regular file"),
                         "missing-library": ([*granted, "-Dqperiapt.continuity.lib=" + str(installed / "missing")], "absolute regular file"),
                         "directory-library": ([*granted, "-Dqperiapt.continuity.lib=" + str(installed)], "absolute regular file"),
                         "denied-native-access": ([*java_args, "-Dqperiapt.continuity.lib=" + str(library_path)], "IllegalCallerException")}
            incompatible = installed / "incompatible.c"
            with incompatible.open("x") as stream:
                stream.write("int deliberately_incompatible(void);\nint deliberately_incompatible(void) { return 0; }\n")
            bad_library = installed / library_name
            run(["cc", "-Wall", "-Wextra", "-Werror", "-pedantic", "-dynamiclib" if os.uname().sysname == "Darwin" else "-shared",
                 "-fPIC", str(incompatible), "-o", str(bad_library)], "incompatible-library-" + profile)
            negatives["missing-symbol"] = ([*granted, "-Dqperiapt.continuity.lib=" + str(bad_library)], "NoSuchElementException")
            for label, (arguments, rejection) in negatives.items():
                rejected = run([*arguments, "consumer.LoaderProbe"], f"negative-{label}-{profile}", rejection=rejection)
                sdk.require(b"INSTALLED_CONTINUITY_JAVA_MODULE_PASS" not in rejected, "refused module reported success")
            raw = installed / "RawOwnerProbe.java"
            sdk.copy(consumer / "negative/RawOwnerProbe.java.txt", raw)
            run([str(javac), "-XDrawDiagnostics", "--release", "25", "-cp", classpath,
                 "-d", str(installed / "negative-classes"), str(raw)], "negative-raw-owner-" + profile,
                rejection="compiler.err.report.access: dev.qperiapt.continuity.ContinuityOwner(dev.qperiapt.continuity.NativeOwner), private, dev.qperiapt.continuity.ContinuityOwner")
            sdk.require(not (installed / "negative-classes/RawOwnerProbe.class").exists(),
                        "raw-owner negative control produced an executable class")
            raw_device = installed / "RawDeviceProbe.java"
            sdk.copy(consumer / "negative/RawDeviceProbe.java.txt", raw_device)
            run([str(javac), "-XDrawDiagnostics", "--release", "25", "-cp", classpath,
                 "-d", str(installed / "negative-device-classes"), str(raw_device)], "negative-raw-device-" + profile,
                rejection="compiler.err.report.access: dev.qperiapt.continuity.ContinuityDevice(dev.qperiapt.continuity.NativeOwner), private, dev.qperiapt.continuity.ContinuityDevice")
            sdk.require(not (installed / "negative-device-classes/RawDeviceProbe.class").exists(),
                        "raw-device negative control produced an executable class")
            raw_setup = installed / "RawSetupProbe.java"
            sdk.copy(consumer / "negative/RawSetupProbe.java.txt", raw_setup)
            run([str(javac), "-XDrawDiagnostics", "--release", "25", "-cp", classpath,
                 "-d", str(installed / "negative-setup-classes"), str(raw_setup)], "negative-raw-setup-" + profile,
                rejection="compiler.err.report.access: dev.qperiapt.continuity.ContinuitySetup(dev.qperiapt.continuity.NativeOwner), private, dev.qperiapt.continuity.ContinuitySetup")
            sdk.require(not (installed / "negative-setup-classes/RawSetupProbe.class").exists(),
                        "raw-setup negative control produced an executable class")
            raw_enrollment = installed / "RawEnrollmentProbe.java"
            sdk.copy(consumer / "negative/RawEnrollmentProbe.java.txt", raw_enrollment)
            run([str(javac), "-XDrawDiagnostics", "--release", "25", "-cp", classpath,
                 "-d", str(installed / "negative-enrollment-classes"), str(raw_enrollment)], "negative-raw-enrollment-" + profile,
                rejection="compiler.err.report.access: dev.qperiapt.continuity.ContinuityEnrollment(dev.qperiapt.continuity.NativeOwner), private, dev.qperiapt.continuity.ContinuityEnrollment")
            sdk.require(not list((installed / "negative-enrollment-classes").glob("**/*.class")),
                        "raw-enrollment negative control produced an executable class")
            raw_native = installed / "RawNativeOwnerProbe.java"
            sdk.copy(consumer / "negative/RawNativeOwnerProbe.java.txt", raw_native)
            run([str(javac), "-XDrawDiagnostics", "--release", "25", "-cp", classpath,
                 "-d", str(installed / "negative-native-classes"), str(raw_native)], "negative-raw-native-owner-" + profile,
                rejection="compiler.err.report.access: dev.qperiapt.continuity.NativeOwner(long,dev.qperiapt.continuity.NativeOwner), private, dev.qperiapt.continuity.NativeOwner")
            sdk.require(not (installed / "negative-native-classes/RawNativeOwnerProbe.class").exists(),
                        "raw-native-owner negative control produced an executable class")
            for name, expected in hashes.items():
                sdk.require(sdk.snapshot(installed / name, maximum=MAX_PACKAGE).sha256 == expected, "installed Kotlin package changed")
            sdk.require({p.name: sdk.snapshot(p).sha256 for p in (distribution / "lib").iterdir()} == jar_files
                        and sdk.snapshot(launcher).sha256 == launcher_sha
                        and sdk.snapshot(interrupt_launcher).sha256 == interrupt_launcher_sha,
                        "executed Kotlin JAR or launcher changed")
            sdk.require(sdk.snapshot(trace, maximum=c.MAX_BINARY).sha256 == row["binaries"]["Rust_trace"]["sha256"], "native Kotlin harness changed during execution")
            sdk.require(sdk.snapshot(output / filename, maximum=MAX_PACKAGE).sha256 == hashlib.sha256(data).hexdigest(),
                        "Kotlin candidate archive changed during execution")
            result["profiles"][profile] = {"account_owner": accounts, "account_cleanup": cleaned, "setup": configured,
                "setup_faults": interrupted_setup, "setup_io": io_setup,
                "setup_witness_faults": witnessed_setup,
                "account_witness": witnessed_account, "account_tls": tls_account, "account_tls_loss": tls_loss_account, "account_delivery": delivered_account,
                "own_account_delivery": own_delivery, "own_account_tls_loss": own_cleanup,
                "archive": filename, "archive_sha256": hashlib.sha256(data).hexdigest(),
                "files": hashes, "native_library_sha256": library.sha256, "runtime_closure": resolved,
                "jars": jar_files, "launcher": {"path": str(launcher), "sha256": launcher_sha}, "traces": traces,
                "owner_tests": owner_tests, "witnessed": witnessed, "enrollment": enrollment,
                "restoration": {"execution": restored, "public_files": restored_files},
                "restoration_opening": {"execution": restore_opening, "public_files": restore_opening_files},
                "prepared_owner_gc": gc_execution,
                "inflight_owner_gc": inflight,
                "sync_faults": sync_faults, "sync_fault_public_files": fault_files,
                "opening_interrupt_launcher": {"path": str(interrupt_launcher), "sha256": interrupt_launcher_sha},
                "java_module_executed": True,
                "negative_controls": sorted(negatives) + ["raw-owner-construction", "raw-device-construction", "raw-setup-construction", "raw-enrollment-construction", "raw-native-owner-construction"]}
        sdk.require(source_files() == source and tools == {"java": tool_identity(java_home), "gradle": tool_identity(gradle_home)},
                    "Kotlin sources or tool installation changed during qualification")
        result["completed"] = True
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "KOTLIN_CONSUMER.json", result)
    return result
