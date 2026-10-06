"""Installed public witnessed roster coordination through the shared native engine."""
from pathlib import Path
from collections import Counter
import re
import rust_sdk_profile as sdk
from continuity_c_enrollment import _require_execution
from continuity_c_independent_policy import MARKERS

PREFIX = "credential_renewal::independent_policy::witnessed::roster::"
TESTS = frozenset(PREFIX + name for name in (
    "c_roster_retains_exact_terminal_and_original_owner_under_p0_and_independent_p_tcp_tls",
    "c_roster_processed_commit_and_ack_losses_recover_original_target_without_current_runtime",
    "c_roster_failed_initial_head_query_retains_unprepared_intent_and_can_abandon_without_witness_terminal",
))
CALL_COUNTS = {"prepare": 13, "recover": 13, "progress": 37, "prepare-wrong-policy": 4,
    "reconcile": 22, "abandon-refused": 8, "substitute": 19, "cancelled": 8,
    "commit": 6, "close": 4, "commit-lost": 2, "close-lost": 1,
    "prepare-lost": 1, "recover-absent": 1, "abandon": 2}
NATIVE_PREFIXES = frozenset(("C_ROSTER_LIFECYCLE", "C_ROSTER_REPLY_LOSS", "C_ROSTER_UNPREPARED"))


def verify_execution(stdout: bytes, stderr: bytes, *, language: str) -> dict:
    sdk.require(language in {"Swift", "Kotlin"}, "unqualified roster lifecycle language")
    _require_execution(stdout.decode(), TESTS, 25, "foreign roster workloads did not all execute")
    scope = stderr.decode()
    calls = re.findall(r"^FOREIGN_ROSTER_CALL language=(\S+) mode=(\S+) label=(\S+)$", scope, re.MULTILINE)
    sdk.require(calls and all(row[0] == language for row in calls) and
                Counter(row[1] for row in calls) == CALL_COUNTS, "foreign roster operation dispatch differs")
    for marker in MARKERS:
        prefix = marker.split(" ", 1)[0]
        if prefix in NATIVE_PREFIXES:
            sdk.require(re.findall(r"^" + prefix + r" .*?$", scope, re.MULTILINE) == [marker],
                        "foreign roster underlying scenario differs: " + prefix)
    return dict(completed=True, language=language, tests=sorted(TESTS), cases=12,
                foreign_roster_calls=len(calls),
                scope="foreign required-witness R preparation, exact original proposal, current P0/selected P, "
                      "Applied/Closed over signed TCP and mTLS, processed TCP commit/ACK reply loss, "
                      "historical recovery and local abandonment before preparation; "
                      "C registration, P adoption, native invalid grammar, activation and successor P request; shared native engine",
                TLS_R_commit_reply_loss_qualified=False, post_dispatch_cancellation_qualified=False,
                physical_process_cut_qualified=False, peer_roster_public_API_qualified=False,
                independent_protocol_implementation=False, physical_platform_qualified=False,
                release_claim_eligible=False)


def qualify(output: Path, profile: str, runtime: dict, native: dict, binary: Path,
            run, *, language: str, variant: str = "") -> dict:
    import continuity_c_consumer as c
    sdk.require(profile in {"debug", "release"} and
                ((language == "Swift" and variant == "") or
                 (language == "Kotlin" and variant in {"-serial", "-g1"})),
                "unqualified foreign roster profile")
    sdk.require(runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") == language,
                "foreign roster selected another language")
    identity = sdk.snapshot(binary, maximum=c.MAX_BINARY)
    expected = native["independent_policy_roster"]["binary"]
    sdk.require(expected == native["enrollment"]["binary"] and identity.sha256 == expected["sha256"]
                and identity.size == expected["bytes"], "foreign roster harness differs from C qualification")
    primary = native["binaries"]["C_client"]
    c_client = Path(primary["path"])
    c_identity = sdk.snapshot(c_client, maximum=c.MAX_BINARY)
    sdk.require(c_identity.sha256 == primary["sha256"] and c_identity.size == primary["bytes"],
                "foreign roster C registration client differs")
    foreign = Path(runtime["QPERIAPT_C_OWNER_CLIENT"])
    foreign_identity = sdk.snapshot(foreign, maximum=c.MAX_BINARY)
    selected = dict(runtime, QPERIAPT_C_OWNER_CLIENT=str(c_client), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="C",
                    QPERIAPT_ROSTER_LIFECYCLE_CLIENT=str(foreign), QPERIAPT_ROSTER_LIFECYCLE_LANGUAGE=language)
    selected.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
    label = "witnessed-roster-" + profile + variant
    stdout = run([str(binary), "--exact", *sorted(TESTS), "--test-threads=2", "--nocapture"], label, runtime=selected)
    stderr = sdk.snapshot(output / (language.lower() + "-" + label + ".stderr"))
    checked = verify_execution(stdout, stderr.data, language=language)
    for path, recorded in ((binary, identity), (c_client, c_identity), (foreign, foreign_identity)):
        sdk.require(sdk.snapshot(path, maximum=c.MAX_BINARY).sha256 == recorded.sha256,
                    "roster executable changed during execution")
    result = dict(execution=checked, native_harness_sha256=identity.sha256,
                  C_registration_client_sha256=c_identity.sha256, foreign_client_sha256=foreign_identity.sha256,
                  stderr_sha256=stderr.sha256)
    sdk.write_json(output / (language.upper() + "_WITNESSED_ROSTER_" +
                            (profile + variant).replace("-", "_").upper() + ".json"), result)
    return result
