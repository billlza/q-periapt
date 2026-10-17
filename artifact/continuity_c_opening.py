"""Public readback of real installed-C two-stage constructor execution."""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import commit, export_selected, RECORD_BYTES, transcript
from evidence_io import parse_strict_json_bytes

TEST = "opening::c_prepared_constructors_cancel_network_admission_and_release_original_owners"
RESTORE_TEST = "opening::restored_session_constructors_keep_required_witness_and_cancel_partial_admission"
SCOPE = "same-host installed C constructor lifecycle; signed TCP partial reply and stalled TLS handshake; no OS-preemption or performance claim"


def query_transcript(data: bytes, authority: bytes, prefix: bytes) -> int:
    checked = transcript(data, authority, expected_lost_advances=0, expected_lost_queries=1)
    lost = [data[offset + 3675:offset + RECORD_BYTES] for offset in range(0, len(data), RECORD_BYTES)
            if data[offset] == 0]
    sdk.require(len(lost) == 1 and prefix == (3659).to_bytes(4, "big") + lost[0][:1800],
                "constructor cancellation prefix differs from its original query reply")
    return checked["exchanges"]


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unsupported constructor language")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out;",
                              text, re.MULTILINE), "C constructor workload did not execute completely")
    public = {}
    def read(leaf, maximum=1024**2):
        record = sdk.snapshot(directory / leaf, maximum=maximum)
        public[leaf] = record.sha256
        return record.data
    report = parse_strict_json_bytes(read("c-opening-public-result.json"), label="C constructor result")
    flags = {"completed", "failed_handles_closed", "same_installation_reopened", "tcp_socket_closed", "tls_socket_closed"}
    numbers = {"tcp_cancel_ms", "tls_cancel_ms", "tcp_exchanges", "pre_cancel_cases", "snapshot_open_cases"}
    sdk.require(isinstance(report, dict) and set(report) == flags | numbers | {"release_claim_eligible", "schema_version", "language"}
                and type(report["schema_version"]) is int and report["schema_version"] == 2
                and report["language"] == language
                and all(report[name] is True for name in flags) and report["release_claim_eligible"] is False,
                "C constructor outcome or scope differs")
    sdk.require(all(type(report[name]) is int for name in numbers)
                and report["pre_cancel_cases"] == report["snapshot_open_cases"] == 6
                and all(0 <= report[name] < 1000 for name in ("tcp_cancel_ms", "tls_cancel_ms")),
                "C constructor case or cancellation bound differs")
    commands = {}
    for carrier in ("local", "tcp", "tls"):
        for kind, number in (("operational", 1), ("recovery", 2)):
            commands[f"opening-{carrier}-pre-{kind}"] = f"prepared-pre-cancel:{number}\n"
            if carrier != "local":
                commands[f"opening-{carrier}-ready-{kind}"] = f"prepared-open:{number}\n"
    for carrier in ("tcp", "tls"):
        commands[f"opening-{carrier}-reopen"] = "prepared-open:1\n"
        commands[f"opening-{carrier}-cancel"] = f"prepared-cancelled:218:{report[carrier + '_cancel_ms']}\n"
    logs = {}
    for label, wanted in commands.items():
        for suffix, expected in (("stdout", wanted.encode()), ("stderr", b"")):
            leaf = f"initiator/witness-{label}.{suffix}"
            sdk.require(read(leaf, 65536) == expected, "C constructor command result differs")
            logs[leaf] = public.pop(leaf)
    identity, key = read("initiator/witness-id", 32), read("initiator/witness-public", 1985)
    sdk.require(len(identity) == 32 and len(key) == 1985, "original witness pin shape differs")
    authority = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", identity + key)
    count = query_transcript(read("opening-witness-transcript"), authority,
                             read("initiator/witness-cancelled-prefix", 4096))
    sdk.require(count == report["tcp_exchanges"], "C constructor exchange count differs")
    for leaf in ("opening-tcp-held", "opening-tls-held", "opening-tls-closed"):
        sdk.require(read("initiator/" + leaf, 1) == b"1", "C constructor socket barrier absent")
    hello = read("initiator/opening-tls-client-hello", 16384)
    sdk.require(len(hello) >= 5 and hello[:2] == b"\x16\x03"
                and 0 < int.from_bytes(hello[3:5], "big") <= len(hello) - 5,
                "cancelled TLS constructor has no complete ClientHello record")
    return dict(report, scope=SCOPE.replace("installed C constructor", "installed " + language + " constructor"), public_readbacks=public, command_logs=logs)


def export_public(stdout: bytes, directory: Path, destination: Path) -> dict:
    return export_selected(verify_execution(stdout, directory), directory, destination, SCOPE,
                           replay=lambda path: verify_execution(stdout, path))


def verify_restore_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unsupported restoration constructor language")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [RESTORE_TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out;",
                              text, re.MULTILINE), "restoration constructor workload did not execute completely")
    public = {}
    def read(leaf, maximum=1024**2):
        value = sdk.snapshot(directory / leaf, maximum=maximum)
        public[leaf] = value.sha256
        return value.data
    report = parse_strict_json_bytes(read("c-restore-opening-public-result.json"), label="restoration constructor result")
    flags = {"missing_witness_refused", "wrong_pin_refused", "bad_signature_refused", "failed_handles_closed", "same_session_reopened"}
    numbers = {"schema_version", "local_role", "tcp_cancel_ms", "tls_cancel_ms", "tcp_exchanges", "pre_cancel_cases", "snapshot_open_cases"}
    sdk.require(type(report) is dict and set(report) == flags | numbers | {"language", "session", "release_claim_eligible"}
                and report["language"] == language and report["release_claim_eligible"] is False
                and all(report[name] is True for name in flags) and all(type(report[name]) is int for name in numbers),
                "restoration constructor result fields or authority differ")
    sdk.require(report["schema_version"] == 1 and report["local_role"] == 2
                and report["pre_cancel_cases"] == 3 and report["snapshot_open_cases"] == 4
                and all(0 <= report[name] < 1000 for name in ("tcp_cancel_ms", "tls_cancel_ms")),
                "restoration constructor role, case count or cancellation bound differs")
    sdk.require(type(report["session"]) is str and re.fullmatch(r"[0-9a-f]{64}", report["session"])
                and report["session"] != "0" * 64, "restoration constructor session is invalid")
    for role in ("initiator", "responder"):
        sdk.require(read(role + "/restore-selected-session", 32) == bytes.fromhex(report["session"]),
                    "restoration constructor changed its selected session")
    commands = {"restore-opening-missing": "rejected:216\n", "restore-opening-wrong-pin": "rejected:211\n",
                "restore-opening-bad-signature": "rejected:218\n"}
    for carrier in ("local", "tcp", "tls"):
        commands[f"restore-opening-{carrier}-pre"] = "prepared-pre-cancel:1\n"
    for carrier in ("tcp", "tls"):
        for stage in ("ready", "reopen"):
            commands[f"restore-opening-{carrier}-{stage}"] = "prepared-open:1\n"
        commands[f"restore-opening-{carrier}-cancel"] = f"prepared-cancelled:218:{report[carrier + '_cancel_ms']}\n"
    logs = {}
    for name, expected in commands.items():
        for suffix, content in (("stdout", expected.encode()), ("stderr", b"")):
            leaf = f"responder/witness-{name}.{suffix}"
            sdk.require(read(leaf, 65536) == content, "restoration constructor outcome or diagnostic differs")
            logs[leaf] = public.pop(leaf)
    leaf = "initiator/witness-restore-bootstrap-client.stdout"
    sdk.require(read(leaf, 65536) == (report["session"] + "\n").encode(), "restoration has no matching real bootstrap client")
    logs[leaf] = public.pop(leaf)
    leaf = "responder/witness-restore-bootstrap-server.stdout"
    server = read(leaf, 65536).decode()
    sdk.require(re.fullmatch(r"listening:[0-9]+\nserved:1:0:0:0\n" + report["session"] + r"\n0{64}\n", server),
                "restoration has no matching real bootstrap server")
    logs[leaf] = public.pop(leaf)
    for role, label in (("initiator", "client"), ("responder", "server")):
        leaf = f"{role}/witness-restore-bootstrap-{label}.stderr"
        sdk.require(read(leaf, 65536) == b"", "restoration bootstrap diagnostic is not empty")
        logs[leaf] = public.pop(leaf)
    identity, key = read("responder/witness-id", 32), read("responder/witness-public", 1985)
    sdk.require(len(identity) == 32 and len(key) == 1985, "restoration witness pin shape differs")
    authority = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", identity + key)
    count = query_transcript(read("restore-opening-witness-transcript"), authority,
        read("responder/witness-cancelled-prefix", 4096))
    sdk.require(count == report["tcp_exchanges"], "restoration witness exchange count differs")
    for name in ("restore-opening-tcp-held", "restore-opening-tls-held", "restore-opening-tls-closed"):
        sdk.require(read("responder/" + name, 1) == b"1", "restoration socket barrier missing")
    hello = read("responder/restore-opening-tls-client-hello", 16384)
    sdk.require(len(hello) >= 5 and hello[:2] == b"\x16\x03" and 0 < int.from_bytes(hello[3:5], "big") <= len(hello)-5,
                "restoration cancellation has no actual complete TLS ClientHello")
    return dict(report, public_readbacks=public, command_logs=logs,
        scope=f"same-host installed {language} explicit responder-session restoration; required signed TCP and mutual-TLS witness; partial reply and stalled handshake cancellation; advertisement expiry qualified separately")
