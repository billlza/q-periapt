"""Validate installed C witness calls, full accounting and public transcript semantics.

The native endpoints verify signatures. This independent readback checks framing,
commitments, monotonic transitions and exact retry identity; it is not a second
signature implementation or a TLS/confidentiality qualification.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import re

import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes
from continuity_c_recovery import ciphertext_digest

TEST = "c_witness_owners_reconcile_actual_lost_advances_and_revoked_cleanup"
SCOPE = "installed C required-witness owners over native signed TCP; same host; metadata is not encrypted"
RECORD_BYTES = 1 + 3674 + 3659


def commit(domain: bytes, data: bytes) -> bytes:
    return hashlib.sha3_256(len(domain).to_bytes(8, "big") + domain + len(data).to_bytes(8, "big") + data).digest()


def head(data: bytes) -> tuple[int, int, bytes]:
    sdk.require(len(data) == 48, "witness head width differs")
    fence, revision = int.from_bytes(data[:8], "big"), int.from_bytes(data[8:16], "big")
    sdk.require(0 < fence < 2**64 - 1 and 0 < revision < 2**64 - 1 and any(data[16:]), "invalid witness head")
    return fence, revision, data[16:]


def transcript(data: bytes, authority: bytes, *, expected_lost_advances: int = 2, expected_lost_queries: int = 0) -> dict:
    sdk.require(all(type(value) is int and 0 <= value <= 4096
                    for value in (expected_lost_advances, expected_lost_queries)), "invalid expected witness loss census")
    sdk.require(len(authority) == 32 and data and len(data) % RECORD_BYTES == 0
                and len(data) <= RECORD_BYTES * 4096, "witness transcript framing differs")
    states, challenges, lost, recovered = {}, set(), {}, set()
    advanced, lost_queries = 0, 0
    for index in range(len(data) // RECORD_BYTES):
        row = data[index * RECORD_BYTES:(index + 1) * RECORD_BYTES]
        delivered, request, reply = row[0], row[1:3675], row[3675:]
        sdk.require(delivered in (0, 1) and request[:4] == (297).to_bytes(4, "big")
                    and reply[:4] == (282).to_bytes(4, "big"), "witness envelope size or disposition differs")
        rq, rs = request[4:301], reply[4:286]
        sdk.require(rq[:8] == b"QPANRQ01" and rs[:8] == b"QPANRS01"
                    and rq[8:40] == rs[8:40] == authority and rq[40:136] == rs[40:136],
                    "witness authority or subject differs")
        subject, command, challenge, operation = rq[40:136], rq[136:168], rq[168:200], rq[200:]
        sdk.require(all(any(subject[n:n + 32]) for n in (0, 32, 64)) and any(challenge)
                    and challenge not in challenges, "witness subject or fresh challenge differs")
        challenges.add(challenge)
        sdk.require(command == commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority + subject + operation)
                    and rs[136:168] == commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", rq)
                    and rs[168:200] == command, "witness command or attempt binding differs")
        outcome, observed = rs[200], head(rs[201:249])
        has_last, last = rs[249], rs[250:282]
        sdk.require((has_last == 0 and not any(last) and observed[:2] == (1, 1))
                    or (has_last == 1 and any(last) and observed[:2] != (1, 1)), "witness last-command state differs")
        last_id = last if has_last else None
        prior = states.get(subject)
        kind = operation[0]
        if kind == 1:
            sdk.require(operation[1:] == bytes(96) and outcome == 1, "witness query changed a transition")
            if prior is None:
                sdk.require(observed[:2] == (1, 1) and last_id is None, "witness initial query skipped genesis")
                states[subject] = (observed, last_id)
            else:
                sdk.require(prior == (observed, last_id), "witness query changed its current head")
        else:
            sdk.require(kind == 2 and prior is not None, "unexpected witness operation in installed trace")
            before, target = head(operation[1:49]), head(operation[49:97])
            sdk.require(target[0] == before[0] and target[1] == before[1] + 1 and target[2] != before[2],
                        "witness advance is not exact next revision")
            if prior == (target, command):
                sdk.require(outcome == 3, "witness exact retry advanced twice")
            else:
                sdk.require(prior[0] == before and outcome == 2, "witness accepted a conflicting advance")
                advanced += 1
                states[subject] = (target, command)
            sdk.require(observed == target and last_id == command, "witness acknowledged another target")
        if not delivered:
            if kind == 1:
                sdk.require(expected_lost_queries > 0, "unexpected lost witness query")
                lost_queries += 1
            else:
                sdk.require(outcome == 2 and command not in lost, "lost witness response was not one committed advance")
                lost[command] = (index, challenge)
        elif outcome == 3 and command in lost:
            original_index, original_challenge = lost[command]
            sdk.require(index > original_index and challenge != original_challenge, "witness retry did not use a fresh attempt")
            recovered.add(command)
    sdk.require(len(states) == 2 and len(lost) == expected_lost_advances
                and lost_queries == expected_lost_queries and recovered == lost.keys(), "witness original lost advances were not reconciled")
    return {"exchanges": len(data) // RECORD_BYTES, "subjects": len(states), "logical_advances": advanced,
            "lost_commands": sorted(value.hex() for value in lost), "fresh_challenges": len(challenges)}


def cancelled_reply_prefix(prefix: bytes, data: bytes) -> None:
    sdk.require(data and len(data) % RECORD_BYTES == 0, "partial witness transcript framing differs")
    lost = [data[n:n + RECORD_BYTES] for n in range(0, len(data), RECORD_BYTES) if data[n] == 0]
    sdk.require(len(lost) == 2 and prefix == (3659).to_bytes(4, "big") + lost[0][3675:3675 + 1800],
                "cancelled partial reply differs from original committed witness response")


def cancellation_latency(data: bytes) -> int:
    match = re.fullmatch(rb"witness-cancelled-outcome-unavailable:(0|[1-9][0-9]{0,2})\n", data)
    sdk.require(match is not None, "held witness cancellation exceeded its one-second qualification bound")
    return int(match[1])


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unsupported witness language")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;", text, re.MULTILINE),
                "installed C witness test did not execute completely")
    report_snapshot = sdk.snapshot(directory / "c-witness-public-result.json")
    report = parse_strict_json_bytes(report_snapshot.data, label="C witness result")
    names = {"session", "message", "unknown", "context", "peer_account", "peer_device", "report"}
    sdk.require(isinstance(report, dict) and set(report) == names | {"schema_version", "language", "completed", "witness_exchanges", "lost_advances", "release_claim_eligible"},
                "C witness report fields differ")
    sdk.require(type(report["schema_version"]) is int and report["schema_version"] == 2 and report["language"] == language
                and report["completed"] is True and report["release_claim_eligible"] is False
                and type(report["lost_advances"]) is int and report["lost_advances"] == 2,
                "C witness result or release claim differs")
    for name in names:
        length = 32 if name == "peer_device" else 64
        sdk.require(isinstance(report[name], str) and re.fullmatch(f"[0-9a-f]{{{length}}}", report[name])
                    and report[name] != "0" * length, "C witness public identity differs")
    sdk.require(report["message"][:32] == "0" * 32 and report["unknown"][:32] == "0000000000000001" + "0" * 16,
                "C witness message epoch/slot differs")
    public = {"c-witness-public-result.json": report_snapshot.sha256}
    def read(name, maximum=sdk.MAX_ARCHIVE):
        result = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = result.sha256
        return result.data
    identity, key = read("responder/witness-id"), read("responder/witness-public")
    sdk.require(len(identity) == 32 and len(key) == 1985, "witness original pin shape differs")
    trace_bytes = read("witness-transcript")
    trace = transcript(trace_bytes, commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", identity + key))
    cancelled_reply_prefix(read("responder/witness-cancelled-prefix", maximum=1804), trace_bytes)
    sdk.require(read("responder/witness-cancel-ready", maximum=1) == b"1", "witness cancellation barrier differs")
    cancelled = sdk.snapshot(directory / "responder/witness-lost-send.stdout", maximum=65536).data
    cancellation_ms = cancellation_latency(cancelled)
    sdk.require(type(report["witness_exchanges"]) is int and trace["exchanges"] == report["witness_exchanges"],
                "witness exchange census differs")
    wire = read("responder/witness-unknown-wire")
    sdk.require(wire.startswith(b"QPCMSG03"), "witness unknown ciphertext is missing")
    digest = ciphertext_digest(wire)
    rows = ["QPC-C-LOSS/1", "report " + report["report"],
            f"header {report['session']} {report['context']} {report['peer_account']} {report['peer_device']} 2 1 1 1 1 0 0 0 2",
            f"epoch 0 0 1 1 0 0 1 0 0 {'0' * 64} 0 0 0",
            f"epoch 1 1 0 1 0 0 0 0 0 {'0' * 64} 1 0 0",
            f"unconfirmed 1 0 {report['unknown']} {digest}"]
    sdk.require(read("responder/c-loss-report") == ("\n".join(rows) + "\n").encode(), "witness cleanup lost original accounting")
    original, saved = read("responder/native-closure-archive"), read("responder/c-closure-archive")
    sdk.require(len(original) == 362 and original.startswith(b"QPCSCA01") and original == saved, "witness cleanup archive changed")
    application = "initiator/application-" + report["message"]
    sdk.require(read(application) == bytes.fromhex(report["session"] + report["message"]) + b"persisted before process exit"
                and len(list(directory.glob("*/application-*"))) == 1, "witness sender duplicated or lost application effect")
    expected = {"initiator/missing": "rejected:216\n", "initiator/wrong-pin": "rejected:211\n",
                "initiator/bad-signature": "rejected:218\n", "initiator/bootstrap-client": report["session"] + "\n",
                "initiator/rekey-client": "rekey-1-confirmed\n", "responder/next": report["message"] + "\n",
                "responder/lost-send": cancelled.decode(), "responder/reserved": "1\n",
                "responder/exact-send": "consumed\n", "responder/next-after-rekey": report["unknown"] + "\n",
                "responder/unknown-send": "delivery-unknown-committed\n", "responder/revoked": "rejected:603\n",
                "responder/cleanup-missing": "selection-refused:216\n", "responder/cleanup-cancel": "cancelled-cleanup-not-frozen\n",
                "responder/lost-freeze": "witness-freeze-outcome-unavailable\n", "responder/freeze": "", "responder/ack": "",
                "responder/retire": "original-report-closed-retired\n", "responder/archive": "archive-closed-metadata-only\n",
                "responder/closed-missing": "archive-refused:216\n", "responder/closed-unavailable": "archive-refused:218\n"}
    server = {"responder/bootstrap-server": f"served:1:0:0:0\n{report['session']}\n{'0' * 64}\n",
              "initiator/application-server": f"served:2:0:1:1\n{report['session']}\n{report['message']}\n",
              "responder/rekey-server": "server-rekey-1\n"}
    logs = {}
    for label in expected.keys() | server.keys():
        role, name = label.split("/")
        for suffix in ("stdout", "stderr"):
            leaf = f"{role}/witness-{name}.{suffix}"
            data = sdk.snapshot(directory / leaf, maximum=65536)
            logs[leaf] = data.sha256
            if suffix == "stderr":
                sdk.require(data.data == b"", "C witness stderr is not empty")
            elif label in expected:
                sdk.require(data.data.decode() == expected[label], "C witness command outcome differs")
            else:
                marker, tail = data.data.decode().split("\n", 1)
                match = re.fullmatch(r"listening:([1-9][0-9]{0,4})", marker)
                sdk.require(match is not None and int(match[1]) <= 65535 and tail == server[label], "C witness server outcome differs")
    sdk.require({p.relative_to(directory).as_posix() for p in directory.glob("*/witness-*.std*")} == logs.keys(),
                "unexpected or missing C witness command logs")
    return dict(report, scope=SCOPE.replace("installed C required", "installed " + language + " required"), transcript=trace, public_readbacks=public, command_logs=logs,
                ciphertext_digest=digest, witness_tls_qualified=False, held_socket_cancellation_ms=cancellation_ms)


def export_public(stdout: bytes, directory: Path, destination: Path) -> dict:
    """Recheck the complete trace and retain only verifier-selected public files."""
    result = verify_execution(stdout, directory)
    return export_selected(result, directory, destination, SCOPE,
                           replay=lambda path: verify_execution(stdout, path))


def export_selected(result: dict, directory: Path, destination: Path, scope: str, *, replay) -> dict:
    """Copy selected public snapshots and replay them before publishing a manifest."""
    selected = result["public_readbacks"] | result["command_logs"]
    sources = {}
    for name, expected in selected.items():
        relative = Path(name)
        sdk.require(not relative.is_absolute() and relative.parts and all(part not in (".", "..") for part in relative.parts),
                    "witness public export escaped its original runtime")
        original = sdk.snapshot(directory / relative)
        sdk.require(original.sha256 == expected, "witness public input changed after verification")
        sources[relative] = original
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    exported = {}
    for relative, original in sources.items():
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(original.data)
        sdk.require(sdk.snapshot(target).sha256 == original.sha256, "witness public export readback differs")
        exported[relative.as_posix()] = original.sha256
    sdk.require(replay(destination) == result, "witness public export cannot replay its original execution")
    sdk.write_json(destination / "PUBLIC_FILES.json", {"schema_version": 1, "completed": True, "files": exported,
                                                       "scope": scope, "release_claim_eligible": False})
    return exported
