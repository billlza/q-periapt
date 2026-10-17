"""Independent accounting/readback checks for the installed C recovery trace."""
from __future__ import annotations
import hashlib
from pathlib import Path
import re
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

TEST = "c_recovery_preserves_complete_loss_accounting_after_revocation_and_process_exit"
SCOPE = "installed C recovery of original local-profile session after SDK revocation; same host"
DOMAIN = b"Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/resolution-ciphertext/v1"
PAYLOAD = b"persisted before process exit"


def ciphertext_digest(wire: bytes) -> str:
    return hashlib.sha3_256(len(DOMAIN).to_bytes(8, "big") + DOMAIN
                          + len(wire).to_bytes(8, "big") + wire).hexdigest()


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unsupported recovery language")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;",
                              text, re.MULTILINE), "installed C recovery trace did not execute completely")
    report = parse_strict_json_bytes(sdk.snapshot(directory / "c-recovery-public-result.json").data,
                                    label="C recovery execution")
    flags = {"completed", "revoked_operation_refused", "owner_kinds_separated", "report_exit_reconciled",
             "ack_exit_reconciled", "original_report_unchanged", "catalogue_retired", "archive_metadata_only",
             "cancelled_cleanup_unfrozen"}
    names = {"session", "context", "report", "peer_account", "peer_device", "old_incoming", "unconfirmed", "old_resolution"}
    sdk.require(set(report) == flags | names | {"schema_version", "scope", "incoming", "release_claim_eligible",
                                                "reserved_positive_case_executed"}, "C recovery fields differ")
    scope = SCOPE.replace("installed C recovery", "installed " + language + " recovery")
    sdk.require(all(report[name] is True for name in flags) and report["scope"] == scope
                and report["release_claim_eligible"] is False and report["reserved_positive_case_executed"] is False,
                "C recovery outcome, scope or unexecuted reservation claim differs")
    sdk.require(type(report["schema_version"]) is int and report["schema_version"] == 1, "C recovery schema differs")
    incoming = report["incoming"]
    sdk.require(type(incoming) is list and len(incoming) == 2, "C recovery incoming IDs differ")
    for name in names:
        length = 32 if name == "peer_device" else 64
        sdk.require(type(report[name]) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", report[name])
                    and report[name] != "0" * length, "C recovery identity shape differs")
    sdk.require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in incoming)
                and len(set([report["old_incoming"], report["unconfirmed"], *incoming])) == 4,
                "C recovery identities overlap")
    for message, epoch, sequence in ((report["old_incoming"], 0, 0), (incoming[0], 1, 0),
                                      (incoming[1], 1, 2), (report["unconfirmed"], 1, 0)):
        sdk.require(bytes.fromhex(message)[:16] == epoch.to_bytes(8, "big") + sequence.to_bytes(8, "big"),
                    "C recovery message epoch or sequence differs")
    wire = sdk.snapshot(directory / "responder/cleanup-unconfirmed-wire", maximum=32768)
    sdk.require(wire.data.startswith(b"QPCMSG03"), "C recovery ciphertext grammar differs")
    digest = ciphertext_digest(wire.data)
    header = (f"header {report['session']} {report['context']} {report['peer_account']} {report['peer_device']} "
              "2 1 1 1 1 1 2 0 2")
    wanted = ["QPC-C-LOSS/1", "report " + report["report"], header,
              f"epoch 0 0 0 0 0 1 1 1 1 {report['old_resolution']} 0 1 0",
              f"delivery 0 0 {report['old_incoming']} 0 {len(PAYLOAD)}",
              f"epoch 1 1 0 1 0 3 0 0 0 {'0' * 64} 1 2 1",
              f"unconfirmed 1 0 {report['unconfirmed']} {digest}",
              f"delivery 1 0 {incoming[0]} 0 {len(PAYLOAD)}",
              f"delivery 1 1 {incoming[1]} 2 {len(PAYLOAD)}", "skipped 1 0 1"]
    loss = sdk.snapshot(directory / "responder/c-loss-report", maximum=1048576)
    sdk.require(loss.data == ("\n".join(wanted) + "\n").encode(),
                "C complete loss accounting differs from the actual prepared history")
    original = sdk.snapshot(directory / "responder/native-closure-archive")
    saved = sdk.snapshot(directory / "responder/c-closure-archive")
    sdk.require(len(original.data) == 362 and original.data.startswith(b"QPCSCA01") and saved.data == original.data,
                "C retained archive differs from native original")
    expected = {"recovery-kind": "operational-owner-not-recovery\n", "recovery-denied": "rejected:603\n",
                "recovery-list-before": "catalogue:1\n", "recovery-missing": "missing-session-refused\n",
                "recovery-tamper": "tampered-archive-refused\n", "recovery-cancel": "cancelled-cleanup-not-frozen\n",
                "recovery-freeze": "", "recovery-ack-crash": "", "recovery-finish": "original-report-closed-retired\n",
                "recovery-list-after": "catalogue:0\n", "recovery-archive": "archive-closed-metadata-only\n",
                "recovery-list-final": "catalogue:0\n"}
    logs = {}
    for name, value in expected.items():
        for suffix, data in (("stdout", value.encode()), ("stderr", b"")):
            leaf = f"responder/c-{name}.{suffix}"
            record = sdk.snapshot(directory / leaf, maximum=65536)
            sdk.require(record.data == data, "C recovery command outcome differs")
            logs[leaf] = record.sha256
    for suffix, data in (("stdout", (report["session"] + "\n").encode()), ("stderr", b"")):
        leaf = "initiator/c-recovery-bootstrap." + suffix
        record = sdk.snapshot(directory / leaf, maximum=65536)
        sdk.require(record.data == data, "C recovery bootstrap outcome differs")
        logs[leaf] = record.sha256
    sdk.require(not list(directory.glob("*/application-*")), "cleanup trace unexpectedly consumed application data")
    return dict(report, command_logs=logs, public_readbacks={
        "responder/cleanup-unconfirmed-wire": wire.sha256, "responder/c-loss-report": loss.sha256,
        "responder/native-closure-archive": original.sha256, "responder/c-closure-archive": saved.sha256},
        ciphertext_digest=digest)
