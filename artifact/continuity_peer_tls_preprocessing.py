"""Exact pre-processing loss through an independently pinned OpenSSL TLS peer."""
from pathlib import Path
from collections import Counter
import re
import rust_sdk_profile as sdk
from continuity_c_enrollment import _require_execution
from continuity_foreign_account_results import verify_member_calls, verify_traffic_calls

TEST = ("credential_renewal::independent_policy::witnessed::roster::traffic::fanout::"
        "c_peer_roster_tls_unprocessed_openssl_request_recovers_exact_target")
MARKERS = (
    "C_PEER_ROSTER_TLS_UNPROCESSED cases=1 endpoint=OpenSSL mutual_TLS=true complete_authorized_frame=true no_store_handle=true unchanged_witness_image=true original_target=true fresh_recovery_challenge=true complete_account_results=true no_plaintext_fallback=true",
    "PEER_ROSTER_OPENSSL_CARRIER subsequent_plain_records=0 TLS13=true X25519MLKEM768=true alpn=q-periapt-anchor/1",
    "PEER_ROSTER_COMMAND kind=Unprocessed processed_outcomes=[2] unchanged_command_and_target=true fresh_challenge=true",
    "PEER_ROSTER_CUT kind=Unprocessed original_target=true no_current_sdk_during_recovery=true",
)
LABELS = frozenset(("peer-roster-pre-cancel", "peer-roster-interrupted", "peer-roster-exact-retry-after-cut"))


def foreign_markers(language: str) -> list[str]:
    return [
        f"FOREIGN_PEER_ROSTER language={language} carrier=mutual-TLS cut=Some(Unprocessed) exact_target=true original_parent=true complete_foreign_results=true C_registration_P_R_and_raw_controls=true",
        f"FOREIGN_ACCOUNT_RECONCILIATION language={language} carrier=mutual-TLS cut=Some(Unprocessed) members=2 original_ids=true complete_results=true consumed_vs_unknown=true durable_host_report=true retired=true foreign_member_closure=true C_setup=true",
    ]


def verify(stdout: bytes, stderr: bytes, *, language: str) -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unqualified TLS pre-processing language")
    _require_execution(stdout.decode(), {TEST}, 27, "TLS pre-processing workload did not execute")
    text = stderr.decode()
    expected = list(MARKERS)
    if language != "C":
        expected += foreign_markers(language)
        verify_member_calls(text, language=language, cases=1)
        verify_traffic_calls(text, language=language, cases=1)
        for prefix in ("FOREIGN_PEER_ROSTER_CALL", "FOREIGN_PEER_ROSTER_RAW_CONTROL"):
            calls = re.findall(r"^" + prefix + r" language=(\S+) label=(\S+)$", text, re.MULTILINE)
            sdk.require(calls and all(row[0] == language for row in calls) and
                        Counter(row[1] for row in calls) == Counter(LABELS), "TLS pre-processing caller or controls differ")
        sdk.require(not re.search(r"^FOREIGN_PEER_ROSTER_KILLED ", text, re.MULTILINE), "unexpected process-cut evidence")
    else:
        sdk.require(not re.search(r"^FOREIGN_", text, re.MULTILINE), "C TLS pre-processing selected a foreign caller")
    for marker in expected:
        prefix = marker.split(" ", 1)[0]
        sdk.require(re.findall(r"^" + prefix + r" .*?$", text, re.MULTILINE) == [marker],
                    "TLS pre-processing scope differs: " + prefix)
    return dict(completed=True, language=language, cases=1, test=TEST, TLS_endpoint="OpenSSL",
                scope="actual TLS 1.3 X25519MLKEM768 client; complete certificate/subject-authorized frame "
                      "dropped before native witness handle, unchanged witness image, original pending target "
                      "recovered with a fresh signed challenge before full original account result accounting; "
                      "selected caller durably accounts for each member, C enrollment/local P/R and raw controls, shared native protocol engine",
                foreign_peer_calls=0 if language == "C" else 3,
                foreign_member_closure_calls=0 if language == "C" else 4,
                foreign_account_traffic_calls=0 if language == "C" else 11,
                independent_TLS_endpoint=True, independent_protocol_implementation=False,
                native_TLS_server_preprocessing_qualified=False, physical_platform_qualified=False,
                release_claim_eligible=False)


def qualify(output: Path, profile: str, runtime: dict, binary: Path, source: dict, run,
            *, language: str, variant: str = "") -> dict:
    import continuity_c_consumer as c
    import continuity_c_witness_openssl as openssl
    sdk.require(profile in {"debug", "release"} and
                ((language in {"C", "Swift"} and variant == "") or
                 (language == "Kotlin" and variant in {"-serial", "-g1"})), "unqualified TLS pre-processing profile")
    sdk.require(runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE", "C") == language,
                "TLS pre-processing selected another language")
    primary = Path(source["C_client"]["path"]); peer = source["openssl"]
    selected = dict(runtime, QPERIAPT_C_OWNER_CLIENT=str(primary), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="C",
                    QPERIAPT_WITNESS_OPENSSL_PEER=peer["path"])
    selected.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
    identities = {}
    for path, recorded in ((binary, source["enrollment"]), (primary, source["C_client"]), (Path(peer["path"]), peer)):
        identity = sdk.snapshot(path, maximum=c.MAX_BINARY)
        sdk.require(identity.sha256 == recorded["sha256"] and identity.size == recorded["bytes"],
                    "TLS pre-processing executable identity differs")
        identities[str(path)] = identity.sha256
    if language != "C":
        foreign = Path(runtime["QPERIAPT_C_OWNER_CLIENT"])
        identities[str(foreign)] = sdk.snapshot(foreign, maximum=c.MAX_BINARY).sha256
        selected.update(QPERIAPT_PEER_ROSTER_LIFECYCLE_CLIENT=str(foreign), QPERIAPT_PEER_ROSTER_LIFECYCLE_LANGUAGE=language,
                        QPERIAPT_ACCOUNT_RESULT_CLIENT=str(foreign), QPERIAPT_ACCOUNT_RESULT_LANGUAGE=language)
    openssl.verify_dependencies(peer["dependency_files"])
    label = "peer-tls-preprocessing-" + profile + variant
    stdout = run([str(binary), "--exact", TEST, "--nocapture"], label, runtime=selected)
    stderr = sdk.snapshot(output / (language.lower() + "-" + label + ".stderr"))
    checked = verify(stdout, stderr.data, language=language)
    for path, identity in identities.items():
        sdk.require(sdk.snapshot(Path(path), maximum=c.MAX_BINARY).sha256 == identity,
                    "TLS pre-processing executable changed during execution")
    openssl.verify_dependencies(peer["dependency_files"])
    result = dict(execution=checked, executable_sha256=identities, openssl_version=peer["version"], stderr_sha256=stderr.sha256)
    sdk.write_json(output / (language.upper() + "_PEER_TLS_PREPROCESSING_" +
                            (profile + variant).replace("-", "_").upper() + ".json"), result)
    return result
