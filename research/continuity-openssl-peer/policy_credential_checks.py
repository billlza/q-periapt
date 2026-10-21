#!/usr/bin/env python3
"""Actual original P/G/P/G composition after policy and credential expiry."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys


def scenario(args, count, witnessed, *, after_credentials=None):
    from registration_fixture import Fixture
    from shared_account_checks import start, request_arguments
    from witness_policy_checks import request_approval
    from local_policy_checks import policy_inputs
    from qperiapt_continuity_reference.local_renewal_protocol import Proposal
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    selected = argparse.Namespace(**vars(args))
    selected.output = args.output / str(count); selected.output.mkdir(exist_ok=True)
    f = Fixture(selected, "witness" if witnessed else "local", account_members=count,
                enrolled_peer=True, policy_lifecycle=True, policy_composition=True)
    try:
        journal, session = start(f)
        if witnessed: f.call("initial-clock", 33, (170).to_bytes(8, "big"), b"witness clock set")
        identity = f.value("original-id", "next_id", now=170)
        wire = f.value("original-send", "send", (identity, b"original P G session", b"compose"), now=170)
        reserved = f.value("reserved-id", "next_id", now=170)
        f.worker("original-send-reservation-cut", "send", (reserved, b"original reservation", b"compose"),
                 now=170, cut="protocol:send-reserved")
        native_journal = None
        policies, credentials = [], []
        for cycle, version, policy_time, credential_time in ((1, 2, 190, 210), (2, 3, 250, 310)):
            label = f"cycle-{cycle}"
            if witnessed: f.call(label + "-policy-clock", 33, policy_time.to_bytes(8, "big"), b"witness clock set")
            operation = os.urandom(32)
            request, approval = request_approval(f, label + "-policy", version, policy_time, operation)
            args_p = (operation, approval, *policy_inputs(f, version))
            g_args = request_arguments(f, count, label + "-credential", cycle)
            if witnessed:
                f.worker(label + "-policy-prepare-cut", "policy_prepare", args_p, now=policy_time, cut="policy:prepared")
                proposal = f.value(label + "-policy-prepared", "policy_prepare", args_p, now=policy_time)
                f.worker(label + "-P-blocks-G", "credential_account_prepare_files", g_args, now=policy_time,
                         refusal="local renewal intent authentication")
                f.call(label + "-policy-controller", 43, proposal + len(approval).to_bytes(2, "big") + approval + request, b"Prepared")
                f.worker(label + "-policy-head-cut", "policy_commit", (operation,), now=policy_time,
                         cut="session-store:committed:head")
                require(f.worker(label + "-policy-recovered", "policy_recover", (operation,), now=policy_time) == "Applied",
                        "original P recovery")
            else:
                f.worker(label + "-policy-stage-cut", "policy_stage", args_p, now=policy_time,
                         cut="session-store:committed:intent")
                require(f.worker(label + "-policy-pending", "policy_status", (operation,), now=policy_time)["status"] == "Pending",
                        "original local P stage")
                f.worker(label + "-P-blocks-G", "credential_account_stage_files", g_args, now=policy_time,
                         refusal="policy renewal remains pending")
                f.worker(label + "-policy-commit-cut", "policy_commit", (operation,), now=policy_time,
                         cut="session-store:committed:intent")
                require(f.worker(label + "-policy-recovered", "policy_status", (operation,), now=policy_time)["status"] == "Committed",
                        "original local P commit")
            native = f.call(label + "-native-policy", 42, version.to_bytes(8, "big") + policy_time.to_bytes(8, "big"))
            require(len(native) == 72 and native[32:64] == session, "native P replaced original session")
            if native_journal is None: native_journal = native[:32]
            require(native[:32] == native_journal, "native P replaced original journal")
            policies.append({"version": version, "at": policy_time, "operation": operation.hex()})

            if witnessed: f.call(label + "-credential-clock", 33, credential_time.to_bytes(8, "big"), b"witness clock set")
            f.worker(label + "-expired-C-still-denied", "next_id", now=credential_time,
                     refusal="witness current authority denied" if witnessed else "expired or premature authority")
            head = (f.session_path / "head").read_bytes()
            if witnessed:
                f.worker(label + "-credential-prepare-cut", "credential_account_prepare_files", g_args,
                         now=credential_time, cut="renewal:prepared")
                held = (f.session_path / "intent").read_bytes()
                require(held[:8] == b"QPRFLI02", "G after P lacks explicit intent schema")
                proposal = f.value(label + "-credential-prepared", "credential_account_prepare_files", g_args, now=credential_time)
                p = Proposal.decode(proposal)
                require(len(proposal) == 329 and p.policy is not None and p.subject[64:] == f.context.policy_digest,
                        "G changed P0 or omitted independent P")
                require((f.session_path / "intent").read_bytes() == held, "G retry resealed target")
                bad = replace(p, policy=b"x" * 32).wire() + version.to_bytes(8, "big")
                f.call(label + "-wrong-P-witness-refused", 34, bad, status=2)
                require(f.worker(label + "-unapproved-G", "credential_status", (g_args[0],), now=credential_time) == "Unavailable",
                        "wrong P approved G")
                f.worker(label + "-G-blocks-P", "policy_request", (os.urandom(32),), now=credential_time,
                         refusal="policy intent authentication")
                f.call(label + "-credential-controller", 34, proposal + version.to_bytes(8, "big"), b"Prepared")
                f.bridge.arm("after", 5)
                f.worker(label + "-lost-G-commit-reply", "credential_commit", (g_args[0],), now=credential_time,
                         refusal="truncated witness reply")
                f.worker(label + "-G-terminal-cut", "credential_recover", (g_args[0],), now=credential_time,
                         cut="renewal:terminal-durable")
                f.bridge.arm("after", 8)
                f.worker(label + "-lost-G-ACK-reply", "credential_recover", (g_args[0],), now=credential_time,
                         refusal="truncated witness reply")
                require(f.worker(label + "-G-recovered", "credential_recover", (g_args[0],), now=credential_time) == "Applied",
                        "G under P lost exact result")
            else:
                f.worker(label + "-G-stage-cut", "credential_account_stage_files", g_args, now=credential_time,
                         cut="session-store:committed:intent")
                require(f.worker(label + "-G-pending", "credential_status", (g_args[0],), now=credential_time)["status"] == "Pending",
                        "G original Pending")
                f.worker(label + "-G-blocks-P", "policy_request", (os.urandom(32),), now=credential_time,
                         refusal="account credential renewal remains pending")
                f.worker(label + "-G-commit-cut", "credential_commit", (g_args[0],), now=credential_time,
                         cut="session-store:committed:head")
                require(f.worker(label + "-G-recovered", "credential_status", (g_args[0],), now=credential_time)["status"] == "Committed",
                        "G original completion")
            require((f.session_path / "head").read_bytes() != head, "G did not advance original state")
            native = f.call(label + "-native-G", 40, cycle.to_bytes(8, "big") + credential_time.to_bytes(8, "big"))
            require(native[:32] == native_journal and native[32:64] == session
                    and native[64:] == credential_time.to_bytes(8, "big"), "native G/P original identity or time differs")
            f.call(label + "-native-original-reopen", 12, expected=b"reopened")
            if cycle == 1:
                f.worker("reservation-remains-exclusive", "resume", (identity,), now=credential_time,
                         refusal="different reserved operation")
                reserved_wire = f.value("original-reservation-completed", "resume", (reserved,), now=credential_time)
                f.call("native-original-reservation", 7, application(b"compose", reserved_wire), b"original reservation")
            require(f.value(label + "-same-old-ciphertext", "resume", (identity,), now=credential_time) == wire,
                    "G/P changed original ciphertext")
            f.call(label + "-native-old-decrypt", 7, application(b"compose", wire), b"original P G session")
            message_id = f.value(label + "-new-id", "next_id", now=credential_time)
            message = f.value(label + "-new-send", "send", (message_id, b"after P and G expiry recovery", b"compose"), now=credential_time)
            f.call(label + "-native-new-decrypt", 7, application(b"compose", message), b"after P and G expiry recovery")
            reply_id = f.call(label + "-native-reply-id", 8)
            reply = f.call(label + "-native-reply", 9, reply_id + application(b"compose", b"native continued G"))
            require(f.worker(label + "-continued-reply", "receive", (reply, b"compose"), now=credential_time)
                    == [reply_id.hex(), b"native continued G".hex()], "G/P native response differs")
            credentials.append({"cycle": cycle, "at": credential_time, "operation": g_args[0].hex()})
        offer = f.value("continued-rekey-offer", "prepare_rekey_offer", now=310)
        response = f.call("native-rekey-response", 14, offer)
        final = f.value("continued-rekey-final", "accept_rekey_response", (response,), now=310)
        receipt = f.call("native-rekey-receipt", 15, final)
        require(f.worker("continued-rekey-confirmation", "accept_rekey_receipt", (receipt,), now=310) == 1, "P/G PQ rekey")
        fresh_id = f.value("continued-new-epoch-id", "next_id", now=310)
        fresh_wire = f.value("continued-new-epoch-send", "send", (fresh_id, b"new epoch after P G", b"compose"), now=310)
        f.call("native-new-epoch-decrypt", 7, application(b"compose", fresh_wire), b"new epoch after P G")
        additional = None
        if after_credentials is None:
            if witnessed: f.call("expired-policy-clock", 33, (330).to_bytes(8, "big"), b"witness clock set")
            f.worker("expired-P-not-extended-by-G", "next_id", now=330,
                     refusal="witness current authority denied" if witnessed else "expired or premature authority")
        else:
            additional = after_credentials(f, count, journal, session, native_journal, identity, wire)
        result = {"members": count, "witnessed": witnessed, "journal": journal.hex(), "native_journal": native_journal.hex(),
                  "session": session.hex(), "original_wire_sha256": hashlib.sha256(wire).hexdigest(),
                  "policies": policies, "credentials": credentials, "confirmed_epoch": 1,
                  "workers": len(f.driver.operations), "process_kills": sum("signal" in r for r in f.driver.operations),
                  "denied_operations": [r["case"] for r in f.driver.operations if "refused" in r],
                  "after_credentials": additional,
                  "scope": "Actual original P/G/P/G after P0 and C0/C1 expiry using explicit fixture time, plus any explicitly reported follow-on composition. No device or PCS claim."}
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
             *sorted((root / "native/src").glob("*.rs")), root / "native/Cargo.toml", root / "native/Cargo.lock", root / "requirements.txt"]
    inventory = lambda: {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before, native = inventory(), hashlib.sha256(args.native.read_bytes()).hexdigest()
    args.output.mkdir()
    report = {"source_files": before, "native_sha256": native,
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (args.output / "INPUTS.json").write_text(json.dumps(report, indent=2) + "\n")
    report["profiles"] = [scenario(args, count, witnessed) for count in (3, 32) for witnessed in (False, True)]
    require(before == inventory() and native == hashlib.sha256(args.native.read_bytes()).hexdigest(), "P/G inputs changed")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["profiles"]))


if __name__ == "__main__":
    main()
