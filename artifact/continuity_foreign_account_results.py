"""Foreign complete-account result and retirement paths through the shared engine.

C performs enrollment and local P/R. The selected foreign client performs peer
roster admission, actual interruption, each durable member-loss report and ACK,
every complete result read and final metadata retirement; C retains raw controls.
"""
from pathlib import Path
from collections import Counter
import re

import rust_sdk_profile as sdk
from continuity_c_enrollment import _require_execution
from continuity_c_independent_policy import MARKERS

PREFIX = "credential_renewal::independent_policy::witnessed::roster::traffic::fanout::"
TESTS = frozenset(PREFIX + name for name in (
    "c_required_peer_revocation_reconciles_every_original_account_member_before_retirement",
    "c_peer_roster_unknown_commit_cancel_and_kill_recover_original_target_without_current_sdk",
    "c_peer_roster_tls_committed_reply_loss_cancel_and_kill_recover_original_target",
))
CASES = (("signed-TCP", "None"), ("mutual-TLS", "None"),
         *(("signed-TCP", "Some(" + cut + ")") for cut in
           ("Unprocessed", "LostReply", "CancelInFlight", "KillProcess")),
         *(("mutual-TLS", "Some(" + cut + ")") for cut in
           ("LostReply", "CancelInFlight", "KillProcess")))

CALL_LABEL_COUNTS = {"peer-roster-pre-cancel": 9, "peer-roster-revoke": 2,
    "peer-roster-exact-retry": 2, "peer-roster-interrupted": 5, "peer-roster-exact-retry-after-cut": 7}
RAW_LABEL_COUNTS = dict(CALL_LABEL_COUNTS, **{"peer-roster-killed": 2})


def peer_markers(language: str) -> list[str]:
    sdk.require(language in {"Swift", "Kotlin"}, "unqualified peer roster language")
    return [f"FOREIGN_PEER_ROSTER language={language} carrier={carrier} cut={cut} "
            "exact_target=true original_parent=true complete_foreign_results=true "
            "C_registration_P_R_and_raw_controls=true" for carrier, cut in CASES]


def peer_native_marker(marker: str) -> str:
    # Typed callers cannot inspect raw success-output memory after a native error.
    # The C-only run separately preserves that original sentinel assertion.
    return marker.replace("unchanged_error_output=true", "typed_error_results=true")


def markers(language: str) -> list[str]:
    sdk.require(language in {"Swift", "Kotlin"}, "unqualified account reconciliation language")
    return [f"FOREIGN_ACCOUNT_RECONCILIATION language={language} carrier={carrier} cut={cut} "
            "members=2 original_ids=true complete_results=true consumed_vs_unknown=true "
            "durable_host_report=true retired=true foreign_member_closure=true C_setup=true"
            for carrier, cut in CASES]


def connection_markers(language: str) -> list[str]:
    sdk.require(language in {"Swift", "Kotlin"}, "unqualified account connection language")
    return ([f"FOREIGN_ACCOUNT_CONNECT language={language} label=group-connect-{index} original_parent=true"
             for index in range(2)] +
            [f"FOREIGN_ACCOUNT_RECEIVER language={language} label={label} exit={code}"
             for label, code in (("group-bootstrap-0", 0), ("group-bootstrap-1", 0),
                                 ("group-first-delivery", 0), ("group-second-exit", 77))])


def verify_connection_calls(text: str, *, language: str, cases: int) -> None:
    observed = re.findall(r"^FOREIGN_ACCOUNT_(?:CONNECT|RECEIVER) .*?$", text, re.MULTILINE)
    sdk.require(Counter(observed) == Counter({row: cases for row in connection_markers(language)}),
                "foreign original connection/receiver execution differs")


def traffic_markers(language: str) -> list[str]:
    sdk.require(language in {"Swift", "Kotlin"}, "unqualified account traffic language")
    original = ("group-next", "group-first-send", "group-second-unknown", "group-partial-before-updates")
    continued = ("group-partial-after-updates", "group-first-retained", "group-reverse-order-retained",
                 "group-refuse-unary", "group-refuse-changed-input", "group-refuse-omit-retained", "group-refuse-cancel-peer")
    return [f"FOREIGN_ACCOUNT_TRAFFIC language={language} label={label} parent={parent}"
            for parent, labels in (("original", original), ("independent-policy", continued)) for label in labels]


def verify_traffic_calls(text: str, *, language: str, cases: int) -> None:
    observed = re.findall(r"^FOREIGN_ACCOUNT_TRAFFIC .*?$", text, re.MULTILINE)
    sdk.require(Counter(observed) == Counter({row: cases for row in traffic_markers(language)}),
                "foreign original account traffic dispatch differs")


def member_markers(language: str) -> list[str]:
    sdk.require(language in {"Swift", "Kotlin"}, "unqualified member closure language")
    return [f"FOREIGN_MEMBER_CLOSURE language={language} mode={mode} label={label}-{index}"
            for mode, label in (("recover-member-freeze", "peer-roster-freeze"),
                                ("recover-member-ack", "peer-roster-accounted")) for index in range(2)]


def verify_member_calls(text: str, *, language: str, cases: int) -> None:
    observed = re.findall(r"^FOREIGN_MEMBER_CLOSURE .*?$", text, re.MULTILINE)
    sdk.require(Counter(observed) == Counter({row: cases for row in member_markers(language)}),
                "foreign durable member closure dispatch differs")


def verify_execution(stdout: bytes, stderr: bytes, *, language: str) -> dict:
    _require_execution(stdout.decode(), TESTS, 25,
                       "foreign complete-account result workloads were not executed completely")
    text = stderr.decode()
    observed = re.findall(r"^FOREIGN_ACCOUNT_RECONCILIATION .*?$", text, re.MULTILINE)
    expected = markers(language)
    verify_member_calls(text, language=language, cases=len(CASES))
    verify_traffic_calls(text, language=language, cases=len(CASES))
    verify_connection_calls(text, language=language, cases=len(CASES))
    sdk.require(len(observed) == len(expected) and set(observed) == set(expected),
                "foreign account reconciliation scope differs")
    peer = re.findall(r"^FOREIGN_PEER_ROSTER .*?$", text, re.MULTILINE)
    sdk.require(len(peer) == len(CASES) and set(peer) == set(peer_markers(language)),
                "foreign peer roster scenario scope differs")
    for prefix, expected_counts in (("FOREIGN_PEER_ROSTER_CALL", CALL_LABEL_COUNTS),
                                   ("FOREIGN_PEER_ROSTER_RAW_CONTROL", RAW_LABEL_COUNTS)):
        observed_calls = re.findall(r"^" + prefix + r" language=(\S+) label=(\S+)$", text, re.MULTILINE)
        sdk.require(observed_calls and all(row[0] == language for row in observed_calls) and
                    Counter(row[1] for row in observed_calls) == expected_counts,
                    "foreign peer roster dispatch differs: " + prefix)
    killed = re.findall(r"^FOREIGN_PEER_ROSTER_KILLED .*?$", text, re.MULTILINE)
    sdk.require(killed == [f"FOREIGN_PEER_ROSTER_KILLED language={language} signal=9 actual_processed_barrier=true"] * 2,
                "foreign peer roster process cuts were not observed")
    for marker in MARKERS:
        if marker.split(" ", 1)[0] in {
            "C_REQUIRED_PEER_REVOCATION", "C_PEER_ROSTER_INTERRUPTION", "C_PEER_ROSTER_TLS_INTERRUPTION"
        }:
            prefix = marker.split(" ", 1)[0]
            sdk.require(re.findall(r"^" + prefix + r" .*?$", text, re.MULTILINE) == [peer_native_marker(marker)],
                        "foreign reconciliation underlying scenario differs: " + prefix)
    return dict(completed=True, language=language, tests=sorted(TESTS), cases=len(CASES),
                scope="foreign original-parent session establishment, receiver application commit and actual post-commit exit, "
                      "account traffic before/after local P/R, durable consumption vs unknown receipt, "
                      "retained exact retries and refused membership/input changes, current peer-roster admission, pre-cancel and in-flight cancellation, "
                      "actual process cuts after observed witness processing, unknown-commit exact-target recovery, "
                      "durable individual-member loss reports and ACKs, complete original account result observation and metadata retirement; "
                      "C registration, local P/R updates and raw input controls; shared native engine",
                foreign_peer_roster_calls=25, foreign_peer_roster_kills=2, C_raw_input_control_invocations=27,
                foreign_member_closure_calls=36, foreign_account_traffic_calls=99,
                foreign_connections=18, foreign_receivers=36, foreign_crashed_receivers=9,
                peer_roster_admission_qualified=True, local_P_R_updates_qualified=False,
                TLS_preprocessing_loss_qualified=False, independent_protocol_implementation=False,
                physical_platform_qualified=False, release_claim_eligible=False)


def qualify(output: Path, profile: str, runtime: dict, native: dict, binary: Path,
            run, *, language: str, variant: str = "") -> dict:
    import continuity_c_consumer as c
    sdk.require(profile in {"debug", "release"} and
                ((language == "Swift" and variant == "") or
                 (language == "Kotlin" and variant in {"-serial", "-g1"})),
                "unqualified foreign account reconciliation profile")
    sdk.require(runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") == language,
                "foreign account reconciliation selected another language")
    identity = sdk.snapshot(binary, maximum=c.MAX_BINARY)
    expected = native["independent_policy_roster"]["binary"]
    sdk.require(expected == native["enrollment"]["binary"] and
                identity.sha256 == expected["sha256"] and identity.size == expected["bytes"],
                "foreign account reconciliation harness differs from C qualification")
    primary = native["binaries"]["C_client"]
    c_client = Path(primary["path"])
    c_identity = sdk.snapshot(c_client, maximum=c.MAX_BINARY)
    sdk.require(c_identity.sha256 == primary["sha256"] and c_identity.size == primary["bytes"],
                "foreign account reconciliation C setup client differs")
    foreign = Path(runtime["QPERIAPT_C_OWNER_CLIENT"])
    foreign_identity = sdk.snapshot(foreign, maximum=c.MAX_BINARY)
    selected = dict(runtime, QPERIAPT_C_OWNER_CLIENT=str(c_client),
                    QPERIAPT_INSTALLED_CLIENT_LANGUAGE="C", QPERIAPT_ACCOUNT_RESULT_CLIENT=str(foreign),
                    QPERIAPT_ACCOUNT_RESULT_LANGUAGE=language,
                    QPERIAPT_PEER_ROSTER_LIFECYCLE_CLIENT=str(foreign),
                    QPERIAPT_PEER_ROSTER_LIFECYCLE_LANGUAGE=language)
    selected.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
    label = "account-reconciliation-" + profile + variant
    stdout = run([str(binary), "--exact", *sorted(TESTS), "--nocapture"], label, runtime=selected)
    stderr = sdk.snapshot(output / (language.lower() + "-" + label + ".stderr"))
    checked = verify_execution(stdout, stderr.data, language=language)
    for path, recorded in ((binary, identity), (c_client, c_identity), (foreign, foreign_identity)):
        sdk.require(sdk.snapshot(path, maximum=c.MAX_BINARY).sha256 == recorded.sha256,
                    "account reconciliation executable changed during execution")
    result = dict(execution=checked, native_harness_sha256=identity.sha256,
                  C_setup_client_sha256=c_identity.sha256, foreign_client_sha256=foreign_identity.sha256,
                  stderr_sha256=stderr.sha256)
    sdk.write_json(output / (language.upper() + "_ACCOUNT_RECONCILIATION_" +
                            (profile + variant).replace("-", "_").upper() + ".json"), result)
    return result
