"""Installed public independent-policy operations through the shared native engine."""
from pathlib import Path
from collections import Counter
import re

import rust_sdk_profile as sdk
from continuity_c_enrollment import _require_execution
from continuity_c_independent_policy import MARKERS

PREFIX = "credential_renewal::independent_policy::"
TESTS = frozenset(PREFIX + name for name in (
    "c_independent_policy_request_restarts_exact_stage_and_adopts_original_journal",
    "c_independent_policy_restores_original_tls_session_after_lost_application_receipt",
    "public_bindings::public_wrapper_rejects_request_substitution_and_pre_cancelled_stage",
    "witnessed::c_original_independent_policy_coordinates_applied_and_closed_over_tcp_and_mutual_tls",
    "witnessed::c_original_policy_lost_commit_or_ack_recovers_without_current_runtime_or_application_tls",
))
CASES = ("local-lifecycle", "local-refusals", "local-tls-session-recovery",
         "tcp-applied", "tcp-closed", "tls-applied", "tls-closed",
         "tcp-lost-commit", "tcp-lost-applied-ack", "tcp-lost-closed-ack")
CALL_COUNTS = {"request": 3, "request-refused": 1, "status": 1, "pending": 2, "stage": 12,
    "stage-corrupt-scope": 1, "stage-corrupt-certificate": 1, "stage-cancelled": 1,
    "reconcile": 2, "resolve-pending": 1, "resolve": 1, "activate": 3,
    "witness-request": 7, "witness-prepare": 7, "witness-recover-absent": 7,
    "witness-progress": 24, "witness-recover": 7, "witness-reconcile": 14,
    "witness-cancelled": 4, "witness-substitute": 11, "witness-commit": 2,
    "witness-close": 2, "witness-commit-lost": 2, "witness-close-lost": 1}
TRANSPORT_LABELS = frozenset("independent-traffic-" + label for label in
    ("connect", "next", "unknown", "pending-reopen", "retry", "ack", "original-identity"))
NATIVE_PREFIXES = frozenset(("C_INDEPENDENT_POLICY", "C_INDEPENDENT_POLICY_TRAFFIC",
    "C_INDEPENDENT_WITNESS", "C_INDEPENDENT_WITNESS_REPLY_LOSS", "PUBLIC_POLICY_REFUSALS"))


def markers(language: str) -> list[str]:
    sdk.require(language in {"Swift", "Kotlin"}, "unqualified policy lifecycle language")
    return [f"FOREIGN_POLICY_LIFECYCLE language={language} case={case} original_request=true "
            "exact_proposal=true native_outcomes=true C_registration_and_raw_controls=true shared_native_engine=true"
            for case in CASES]


def verify_execution(stdout: bytes, stderr: bytes, *, language: str) -> dict:
    _require_execution(stdout.decode(), TESTS, 22, "foreign independent policy workloads did not all execute")
    scope = stderr.decode()
    observed = re.findall(r"^FOREIGN_POLICY_LIFECYCLE .*?$", scope, re.MULTILINE)
    expected = markers(language)
    sdk.require(len(observed) == len(expected) and set(observed) == set(expected),
                "foreign policy lifecycle scope differs")
    calls = re.findall(r"^FOREIGN_POLICY_CALL language=(\S+) mode=(\S+) label=(\S+)$", scope, re.MULTILINE)
    sdk.require(calls and all(row[0] == language for row in calls)
                and Counter(row[1] for row in calls) == CALL_COUNTS,
                "foreign policy operation dispatch differs")
    transport = re.findall(r"^FOREIGN_POLICY_TRANSPORT language=(\S+) label=(\S+)$", scope, re.MULTILINE)
    sdk.require(len(transport) == 7 and all(row[0] == language for row in transport)
                and {row[1] for row in transport} == TRANSPORT_LABELS,
                "foreign original-session transport dispatch differs")
    for marker in MARKERS:
        prefix = marker.split(" ", 1)[0]
        if prefix in NATIVE_PREFIXES:
            sdk.require(re.findall(r"^" + prefix + r" .*?$", scope, re.MULTILINE) == [marker],
                        "foreign policy underlying scenario differs: " + prefix)
    return dict(completed=True, language=language, tests=sorted(TESTS), cases=len(CASES),
                foreign_policy_calls=len(calls), foreign_transport_calls=len(transport),
                scope="foreign local and required-witness independent policy request, stage, exact proposal, "
                      "commit/close, original history, owner activation and original TLS session recovery; "
                      "C registration and invalid raw-buffer controls; shared native protocol engine",
                TLS_commit_reply_loss_qualified=False, post_dispatch_cancellation_qualified=False,
                physical_process_cut_qualified=False, independent_protocol_implementation=False,
                physical_platform_qualified=False, release_claim_eligible=False)


def qualify(output: Path, profile: str, runtime: dict, native: dict, binary: Path,
            run, *, language: str, variant: str = "") -> dict:
    import continuity_c_consumer as c
    sdk.require(profile in {"debug", "release"} and
                ((language == "Swift" and variant == "") or
                 (language == "Kotlin" and variant in {"-serial", "-g1"})),
                "unqualified foreign policy profile")
    sdk.require(runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") == language,
                "foreign policy selected another language")
    identity = sdk.snapshot(binary, maximum=c.MAX_BINARY)
    expected = native["independent_policy_roster"]["binary"]
    sdk.require(expected == native["enrollment"]["binary"] and identity.sha256 == expected["sha256"]
                and identity.size == expected["bytes"], "foreign policy harness differs from C qualification")
    primary = native["binaries"]["C_client"]
    c_client = Path(primary["path"])
    c_identity = sdk.snapshot(c_client, maximum=c.MAX_BINARY)
    sdk.require(c_identity.sha256 == primary["sha256"] and c_identity.size == primary["bytes"],
                "foreign policy C registration client differs")
    foreign = Path(runtime["QPERIAPT_C_OWNER_CLIENT"])
    foreign_identity = sdk.snapshot(foreign, maximum=c.MAX_BINARY)
    selected = dict(runtime, QPERIAPT_C_OWNER_CLIENT=str(c_client), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="C",
                    QPERIAPT_POLICY_LIFECYCLE_CLIENT=str(foreign), QPERIAPT_POLICY_LIFECYCLE_LANGUAGE=language)
    selected.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
    label = "independent-policy-" + profile + variant
    stdout = run([str(binary), "--exact", *sorted(TESTS), "--test-threads=2", "--nocapture"], label, runtime=selected)
    stderr = sdk.snapshot(output / (language.lower() + "-" + label + ".stderr"))
    checked = verify_execution(stdout, stderr.data, language=language)
    for path, recorded in ((binary, identity), (c_client, c_identity), (foreign, foreign_identity)):
        sdk.require(sdk.snapshot(path, maximum=c.MAX_BINARY).sha256 == recorded.sha256,
                    "policy executable changed during execution")
    result = dict(execution=checked, native_harness_sha256=identity.sha256,
                  C_registration_client_sha256=c_identity.sha256, foreign_client_sha256=foreign_identity.sha256,
                  stderr_sha256=stderr.sha256)
    sdk.write_json(output / (language.upper() + "_INDEPENDENT_POLICY_" +
                            (profile + variant).replace("-", "_").upper() + ".json"), result)
    return result
