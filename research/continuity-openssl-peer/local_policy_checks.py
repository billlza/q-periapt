#!/usr/bin/env python3
"""Original registered policy-only continuation against an actual native peer."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import base64
import hashlib
import json
import os
from pathlib import Path
import sys


def policy_inputs(f, version):
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    head = (f.public / f"policy-head-{version}").read_bytes()
    pins = {"schema": "qperiapt-policy-pins/1", "sdk_root": b64(f.pins.sdk_root),
            "sdk_state": b64(f.pins.sdk_state), "policy_root": b64(f.pins.policy_root.raw),
            "policy_version": version, "policy_digest": list(head[8:]),
            "witness": None if f.pin is None else {"identity": list(f.pin.identity), "key": b64(f.pin.key.raw)}}
    materials = {"schema": "qperiapt-policy-materials/1", "sdk_document": b64(f.materials.sdk_document),
                 "sdk_signature": b64(f.materials.sdk_signature),
                 "policy": b64((f.public / f"policy-{version}").read_bytes())}
    return tuple(json.dumps(value, separators=(",", ":")).encode() for value in (pins, materials))


def scenario(args, count):
    from registration_fixture import Fixture
    from shared_account_checks import start
    from traffic_checks import application
    from qperiapt_continuity_reference.wire import require
    f = Fixture(args, f"local-{count}", account_members=count, enrolled_peer=True, policy_lifecycle=True)
    try:
        journal, session = start(f)
        identity = f.value("original-id", "next_id", now=170)
        wire = f.value("original-send", "send", (identity, b"same original policy session", b"policy"), now=170)
        reserved = f.value("reserved-id", "next_id", now=170)
        f.worker("original-reservation-cut", "send", (reserved, b"original reserved payload", b"policy"),
                 now=170, cut="protocol:send-reserved")
        f.worker("expired-p0-refused", "next_id", now=190, refusal="expired or premature authority")
        native_journal = None
        approvals = []
        for version, now in ((2, 190), (3, 270)):
            op = os.urandom(32)
            request = f.worker(f"policy-{version}-request", "policy_request", (op,), now=now)
            fields = {name: bytes.fromhex(value) for name, value in request.items()}
            require(len(fields["scope"]) == 313 and fields["scope"][32:64] == journal,
                    "request did not name original registered journal")
            payload = version.to_bytes(8, "big") + now.to_bytes(8, "big") + fields["scope"]
            for name in ("current_credential", "current_roster"):
                payload += len(fields[name]).to_bytes(2, "big") + fields[name]
            approval = f.call(f"native-approval-{version}", 41, payload)
            resigned = f.call(f"native-approval-{version}-retry", 41, payload)
            pins, materials = policy_inputs(f, version)
            arguments = (op, approval, pins, materials)
            head_before = (f.session_path / "head").read_bytes()
            wrong_journal = payload[:48] + bytes([90]) * 32 + payload[80:]
            other = f.call(f"native-other-journal-approval-{version}", 41, wrong_journal)
            f.worker(f"policy-{version}-other-journal-refused", "policy_stage", (op, other, pins, materials),
                     now=now, refusal="roots approved different original decisions")
            require((f.session_path / "head").read_bytes() == head_before, "wrong-journal approval changed state")
            f.worker(f"policy-{version}-stage-cut", "policy_stage", arguments, now=now,
                     cut="session-store:committed:intent")
            intent = (f.session_path / "intent").read_bytes()
            require(intent[:8] == b"QPREFI01", "local policy exact write intent")
            pending = f.worker(f"policy-{version}-stage-recovered", "policy_status", (op,), now=now)
            require(pending["status"] == "Pending" and (f.session_path / "head").read_bytes() == intent[52:-32]
                    and head_before != (f.session_path / "head").read_bytes(), "policy stage original recovery")
            retained = (f.session_path / "head").read_bytes()
            require(f.worker(f"policy-{version}-semantic-retry", "policy_stage", (op, resigned, pins, materials), now=now)
                    == pending and (f.session_path / "head").read_bytes() == retained, "retry replaced first policy approval")
            f.worker(f"policy-{version}-pending-blocks-session", "next_id", now=now, refusal="policy renewal remains pending")
            f.worker(f"policy-{version}-commit-cut", "policy_commit", (op,), now=now,
                     cut="session-store:committed:intent")
            commit_intent = (f.session_path / "intent").read_bytes()
            completed = f.worker(f"policy-{version}-commit-recovered", "policy_status", (op,), now=now)
            require(completed["status"] == "Committed" and completed["statement"] == pending["statement"]
                    and (f.session_path / "head").read_bytes() == commit_intent[52:-32], "policy commit original recovery")
            receipt = f.call(f"native-original-policy-{version}", 42, version.to_bytes(8, "big") + now.to_bytes(8, "big"))
            require(len(receipt) == 72 and receipt[32:64] == session and int.from_bytes(receipt[64:], "big") == now,
                    "native original policy continuation")
            if native_journal is None: native_journal = receipt[:32]
            require(receipt[:32] == native_journal, "native changed original journal")
            f.call(f"native-original-reopen-{version}", 12, expected=b"reopened")
            require(f.worker(f"policy-{version}-format", "storage_format", now=now) == 11, "explicit policy snapshot")
            if version == 2:
                f.worker("original-reservation-remains-exclusive", "resume", (identity,), now=now,
                         refusal="different reserved operation")
                pending_wire = f.value("original-reserved-completion", "resume", (reserved,), now=now)
            require(f.value(f"policy-{version}-original-wire", "resume", (identity,), now=now) == wire,
                    "policy adoption changed original ciphertext")
            f.call(f"native-old-message-{version}", 7, application(b"policy", wire), b"same original policy session")
            if version == 2:
                f.call("native-original-reserved-message", 7, application(b"policy", pending_wire), b"original reserved payload")
            next_id = f.value(f"fresh-id-{version}", "next_id", now=now)
            fresh = f.value(f"fresh-send-{version}", "send", (next_id, b"policy continued message", b"policy"), now=now)
            f.call(f"native-fresh-receive-{version}", 7, application(b"policy", fresh), b"policy continued message")
            native_id = f.call(f"native-fresh-id-{version}", 8)
            incoming = f.call(f"native-fresh-send-{version}", 9, native_id + application(b"policy", b"continued native reply"))
            result = f.worker(f"fresh-receive-{version}", "receive", (incoming, b"policy"), now=now)
            require(result == [native_id.hex(), b"continued native reply".hex()], "independent continued receive")
            approvals.append({"version": version, "operation": op.hex(), "statement": pending["statement"],
                              "now": now, "approval_sha256": hashlib.sha256(approval).hexdigest()})
        offer = f.value("continued-pq-offer", "prepare_rekey_offer", now=270)
        response = f.call("continued-native-pq-response", 14, offer)
        final = f.value("continued-pq-final", "accept_rekey_response", (response,), now=270)
        receipt = f.call("continued-native-pq-receipt", 15, final)
        require(f.worker("continued-pq-confirmation", "accept_rekey_receipt", (receipt,), now=270) == 1,
                "policy continuation lost rekey contract")
        after_id = f.value("new-epoch-id", "next_id", now=270)
        after = f.value("new-epoch-send", "send", (after_id, b"after policy continuation rekey", b"policy"), now=270)
        f.call("new-epoch-native-receive", 7, application(b"policy", after), b"after policy continuation rekey")
        f.worker("expired-adopted-policy-refused", "next_id", now=330, refusal="expired or premature authority")
        status = f.worker("historical-policy-completion", "policy_status", (op,), now=500)
        require(status["status"] == "Committed", "expiry rewrote historical completion")
        registration = f.worker("original-registration", "registration_status", now=500)
        require(registration["journal"] == journal.hex(), "policy adoption replaced registration journal")
        result = {"members": count, "journal": journal.hex(), "native_journal": native_journal.hex(),
                  "session": session.hex(), "original_wire_sha256": hashlib.sha256(wire).hexdigest(),
                  "approvals": approvals, "workers": len(f.driver.operations),
                  "process_kills": sum("signal" in row for row in f.driver.operations),
                  "denied_operations": [row["case"] for row in f.driver.operations if "refused" in row],
                  "scope": "Original registered local policy-only continuation, real native peer at explicit times190/270; exact original writes and process recovery. Required witness P and G/R after P remain separate work."}
        (f.out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        f.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args = arguments()
    args.output, args.native, args.provider_root = args.output.resolve(), args.native.resolve(), args.provider_root.resolve()
    crypto, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    root = Path(__file__).resolve().parent
    paths = [*sorted((root / "qperiapt_continuity_reference").glob("*.py")), *sorted(root.glob("*.py")),
             *sorted((root / "native/src").glob("*.rs")), root / "native/Cargo.toml", root / "native/Cargo.lock",
             root / "requirements.txt"]
    inventory = lambda: {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before, native = inventory(), hashlib.sha256(args.native.read_bytes()).hexdigest()
    args.output.mkdir()
    report = {"source_files": before, "native_sha256": native,
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (args.output / "INPUTS.json").write_text(json.dumps(report, indent=2) + "\n")
    report["profiles"] = [scenario(args, count) for count in (3, 32)]
    require(before == inventory() and native == hashlib.sha256(args.native.read_bytes()).hexdigest(), "policy inputs changed")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["profiles"]))


if __name__ == "__main__":
    main()
