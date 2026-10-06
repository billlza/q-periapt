"""Foreign complete-account result and retirement paths through the shared engine.

C performs enrollment, updates and individual-member closure. The selected
foreign client performs every complete result read and final metadata retirement.
"""
from pathlib import Path
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


def markers(language: str) -> list[str]:
    sdk.require(language in {"Swift", "Kotlin"}, "unqualified account reconciliation language")
    return [f"FOREIGN_ACCOUNT_RECONCILIATION language={language} carrier={carrier} cut={cut} "
            "members=2 original_ids=true complete_results=true consumed_vs_unknown=true "
            "durable_host_report=true retired=true C_setup_and_member_closure=true"
            for carrier, cut in CASES]


def verify_execution(stdout: bytes, stderr: bytes, *, language: str) -> dict:
    _require_execution(stdout.decode(), TESTS, 24,
                       "foreign complete-account result workloads were not executed completely")
    text = stderr.decode()
    observed = re.findall(r"^FOREIGN_ACCOUNT_RECONCILIATION .*?$", text, re.MULTILINE)
    expected = markers(language)
    sdk.require(len(observed) == len(expected) and set(observed) == set(expected),
                "foreign account reconciliation scope differs")
    for marker in MARKERS:
        if marker.split(" ", 1)[0] in {
            "C_REQUIRED_PEER_REVOCATION", "C_PEER_ROSTER_INTERRUPTION", "C_PEER_ROSTER_TLS_INTERRUPTION"
        }:
            prefix = marker.split(" ", 1)[0]
            sdk.require(re.findall(r"^" + prefix + r" .*?$", text, re.MULTILINE) == [marker],
                        "foreign reconciliation underlying scenario differs: " + prefix)
    return dict(completed=True, language=language, tests=sorted(TESTS), cases=len(CASES),
                scope="foreign complete-account result observation and metadata retirement; "
                      "C enrollment, policy/roster updates and individual-member closure; shared native protocol engine",
                Swift_Kotlin_policy_roster_updates_qualified=False,
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
                    QPERIAPT_ACCOUNT_RESULT_LANGUAGE=language)
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
