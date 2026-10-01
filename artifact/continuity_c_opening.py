"""Public readback of real installed-C two-stage constructor execution."""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import commit, export_selected, RECORD_BYTES, transcript
from evidence_io import parse_strict_json_bytes

TEST = "opening::c_prepared_constructors_cancel_network_admission_and_release_original_owners"
SCOPE = "same-host installed C constructor lifecycle; signed TCP partial reply and stalled TLS handshake; no OS-preemption or performance claim"


def query_transcript(data: bytes, authority: bytes, prefix: bytes) -> int:
    checked = transcript(data, authority, expected_lost_advances=0, expected_lost_queries=1)
    lost = [data[offset + 3675:offset + RECORD_BYTES] for offset in range(0, len(data), RECORD_BYTES)
            if data[offset] == 0]
    sdk.require(len(lost) == 1 and prefix == (3659).to_bytes(4, "big") + lost[0][:1800],
                "constructor cancellation prefix differs from its original query reply")
    return checked["exchanges"]


def verify_execution(stdout: bytes, directory: Path) -> dict:
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out;",
                              text, re.MULTILINE), "C constructor workload did not execute completely")
    public = {}
    def read(leaf, maximum=1024**2):
        record = sdk.snapshot(directory / leaf, maximum=maximum)
        public[leaf] = record.sha256
        return record.data
    report = parse_strict_json_bytes(read("c-opening-public-result.json"), label="C constructor result")
    flags = {"completed", "failed_handles_closed", "same_installation_reopened", "tcp_socket_closed", "tls_socket_closed"}
    numbers = {"tcp_cancel_ms", "tls_cancel_ms", "tcp_exchanges", "pre_cancel_cases", "snapshot_open_cases"}
    sdk.require(isinstance(report, dict) and set(report) == flags | numbers | {"release_claim_eligible"}
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
    return dict(report, scope=SCOPE, public_readbacks=public, command_logs=logs)


def export_public(stdout: bytes, directory: Path, destination: Path) -> dict:
    return export_selected(verify_execution(stdout, directory), directory, destination, SCOPE,
                           replay=lambda path: verify_execution(stdout, path))
