#!/usr/bin/env python3
"""Original required-witness P commits, unknown replies, closure and live traffic."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys


def request_approval(f, name, version, now, operation):
    result = f.worker(name + "-request", "policy_request", (operation,), now=now)
    fields = {k: bytes.fromhex(v) for k, v in result.items()}
    payload = version.to_bytes(8, "big") + now.to_bytes(8, "big") + fields["scope"]
    for field in ("current_credential", "current_roster"):
        payload += len(fields[field]).to_bytes(2, "big") + fields[field]
    return payload, f.call(name + "-approval", 41, payload)


def scenario(args, count):
    from registration_fixture import Fixture
    from shared_account_checks import start
    from local_policy_checks import policy_inputs
    from traffic_checks import application
    from qperiapt_continuity_reference.wire import require, ldh
    from qperiapt_continuity_reference.policy_witness_protocol import Proposal
    from qperiapt_continuity_reference.policy_renewal_proof import DOMAIN, BODY_BYTES
    from qperiapt_continuity_reference.witness import Head
    selected = argparse.Namespace(**vars(args))
    selected.output = args.output / str(count); selected.output.mkdir()
    f = Fixture(selected, "witness", account_members=count, enrolled_peer=True, policy_lifecycle=True)
    try:
        journal, session = start(f)
        f.call("initial-live-clock", 33, (170).to_bytes(8, "big"), b"witness clock set")
        identity = f.value("original-id", "next_id", now=170)
        wire = f.value("original-send", "send", (identity, b"original witnessed policy message", b"policy"), now=170)

        def approve(name, version, now, operation):
            return request_approval(f, name, version, now, operation)

        original_native = None
        adopted = []
        for version, now in ((2, 190), (3, 270), (4, 340)):
            label = f"p{version}"
            f.call(label + "-witness-clock", 33, now.to_bytes(8, "big"), b"witness clock set")
            operation = os.urandom(32)
            request, approval = approve(label, version, now, operation)
            arguments = (operation, approval, *policy_inputs(f, version))
            if version == 2:
                f.worker("old-policy-permission-denied", "next_id", now=now, refusal="witness current authority denied")
                f.worker(label + "-prepare-cut", "policy_prepare", arguments, now=now,
                         cut="session-store:committed:intent")
            else:
                f.worker(label + "-prepare-cut", "policy_prepare", arguments, now=now, cut="policy:prepared")
            intent = (f.session_path / "intent").read_bytes()
            require(intent[:8] == b"QPRFPI01", "original typed policy intent missing")
            proposal = f.value(label + "-prepare-recovered", "policy_prepare", arguments, now=now)
            require((f.session_path / "intent").read_bytes() == intent, "retry resealed original P target")
            p = Proposal.decode(proposal)
            exported = f.worker(label + "-original-preparation", "policy_preparation", (operation,), now=now)
            require(exported == {"schema": "qperiapt-policy-witness-preparation/1", "binding": list(p.binding),
                                 "proposal": proposal.hex(), "approval": approval.hex()},
                    "preparation did not recover the first sealed bytes")
            if version == 2:
                resigned = f.call(label + "-resigned-approval", 41, request)
                require(resigned != approval, "resigned control did not change signature bytes")
                require(f.value(label + "-resigned-retry", "policy_prepare",
                                (operation, resigned, *policy_inputs(f, version)), now=now) == proposal,
                        "semantic retry changed proposal")
                require(f.worker(label + "-resigned-export", "policy_preparation", (operation,), now=now) == exported
                        and (f.session_path / "intent").read_bytes() == intent,
                        "semantic retry replaced first sealed approval")
            require(p.subject[:32] == journal and p.subject[64:] == f.context.policy_digest,
                    "P changed original witness subject")
            f.worker(label + "-pending-blocks-session", "next_id", now=now, refusal="policy coordination remains pending")
            require(f.worker(label + "-unapproved-status", "policy_status", (operation,), now=now) == "Unavailable",
                    "missing witness history was treated as no-commit")
            f.worker(label + "-unapproved-commit-refused", "policy_commit", (operation,), now=now,
                     refusal="policy not independently prepared")
            controller = proposal + len(approval).to_bytes(2, "big") + approval + request
            if version == 2:
                bad = replace(p, statement=b"x" * 32).wire() + controller[296:]
                f.call("different-statement-witness-refused", 43, bad, b"policy witness: Protocol(Scope)", status=2)
            f.call(label + "-independent-witness-approval", 43, controller, b"Prepared")
            if version == 3:
                f.worker(label + "-closed-terminal-cut", "policy_close", (operation,), now=now,
                         cut="policy:terminal-durable")
                require(f.worker(label + "-closed-original-recovery", "policy_recover", (operation,), now=now) == "Closed",
                        "closed P was not retained")
                require(f.worker(label + "-closed-commit-stays-closed", "policy_commit", (operation,), now=now) == "Closed",
                        "closed policy revived")
                f.worker(label + "-closed-does-not-admit-expired-predecessor", "next_id", now=now,
                         refusal="witness current authority denied")
                retired = os.urandom(32)
                second_request, second = approve("retired-version", version, now, retired)
                f.worker("closed-version-floor-refused", "policy_prepare", (retired, second, *policy_inputs(f, version)),
                         now=now, refusal="policy target version retired")
                # This is a public test-controller proposal, not a local commit.
                # The native controller re-verifies both complete signatures.
                require(second[10:14] == BODY_BYTES.to_bytes(4, "big"), "policy approval body framing")
                retired_statement = ldh(DOMAIN, second[14:14 + BODY_BYTES])
                retired_proposal = replace(p, operation=retired, statement=retired_statement,
                    target=Head(p.expected.fence, p.expected.revision + 1, os.urandom(32)))
                request_wire = retired_proposal.wire() + len(second).to_bytes(2, "big") + second + second_request
                f.call("closed-version-witness-floor-refused", 43, request_wire,
                       b"policy witness: Protocol(Retired)", status=2)
                continue
            if version == 2:
                f.bridge.arm("after", 11)
                f.worker(label + "-lost-actual-commit-reply", "policy_commit", (operation,), now=now,
                         refusal="truncated witness reply")
                require((f.session_path / "intent").read_bytes() == intent, "unknown policy commit changed target")
                f.bridge.arm("after", 14)
                f.worker(label + "-lost-actual-ack-reply", "policy_recover", (operation,), now=now,
                         refusal="truncated witness reply")
            else:
                f.worker(label + "-applied-head-cut", "policy_commit", (operation,), now=now,
                         cut="session-store:committed:head")
            require(f.worker(label + "-original-recovery", "policy_recover", (operation,), now=now) == "Applied",
                    "original P result unavailable after recovery")
            require(not (f.session_path / "intent").exists(), "retired policy kept pending intent")
            f.worker(label + "-retired-export-refused", "policy_preparation", (operation,), now=now,
                     refusal="original policy preparation is no longer retained")
            native = f.call(label + "-native-original-adoption", 42, version.to_bytes(8, "big") + now.to_bytes(8, "big"))
            require(len(native) == 72 and native[32:64] == session and int.from_bytes(native[64:], "big") == now,
                    "native policy changed original session")
            if original_native is None: original_native = native[:32]
            require(native[:32] == original_native, "native policy changed original journal")
            f.call(label + "-native-reopen", 12, expected=b"reopened")
            f.bridge.arm("before", 15)
            f.worker(label + "-unavailable-admission-denies-output", "resume", (identity,), now=now,
                     refusal="truncated witness reply")
            delegate, admissions = f.transport(), [0]
            def fail_release(request_wire, deadline):
                if request_wire[204] == 15:
                    admissions[0] += 1
                    if admissions[0] == 2: raise TimeoutError("policy release admission unavailable")
                return delegate(request_wire, deadline)
            parent = f.owner()
            try:
                with parent.session(now, transport=fail_release) as owner:
                    f.refuses(label + "-release-withholds-output", lambda: owner.resume(identity, now=now),
                              "policy release admission unavailable")
                require(admissions[0] == 2, "fresh final policy admission not reached")
            finally:
                parent.close()
            before = len(f.bridge.records)
            require(f.value(label + "-original-ciphertext", "resume", (identity,), now=now) == wire,
                    "P changed original ciphertext")
            kinds = [r["kind"] for r in f.bridge.records[before:]]
            require(kinds.count(15) >= 2 and 4 not in kinds, "P output lacks fresh policy admission")
            f.call(label + "-native-original-receive", 7, application(b"policy", wire), b"original witnessed policy message")
            outgoing_id = f.value(label + "-new-id", "next_id", now=now)
            outgoing = f.value(label + "-new-message", "send", (outgoing_id, b"new witnessed policy message", b"policy"), now=now)
            f.call(label + "-native-new-receive", 7, application(b"policy", outgoing), b"new witnessed policy message")
            native_id = f.call(label + "-native-id", 8)
            incoming = f.call(label + "-native-send", 9, native_id + application(b"policy", b"native P reply"))
            require(f.worker(label + "-new-receive", "receive", (incoming, b"policy"), now=now)
                    == [native_id.hex(), b"native P reply".hex()], "independent P response differs")
            adopted.append({"version": version, "now": now, "operation": operation.hex(),
                            "proposal": p.binding.hex(), "statement": p.statement.hex(), "admission_kinds": kinds})
        offer = f.value("continued-pq-offer", "prepare_rekey_offer", now=340)
        response = f.call("continued-native-pq-response", 14, offer)
        final = f.value("continued-pq-final", "accept_rekey_response", (response,), now=340)
        receipt = f.call("continued-native-pq-receipt", 15, final)
        confirmed = f.worker("continued-pq-confirmation", "accept_rekey_receipt", (receipt,), now=340)
        require(confirmed == 1, "witness policy lost PQ rekey continuation")
        after_id = f.value("post-policy-rekey-id", "next_id", now=340)
        after = f.value("post-policy-rekey-send", "send", (after_id, b"fresh epoch after witnessed P", b"policy"), now=340)
        f.call("post-policy-rekey-native-decrypt", 7, application(b"policy", after), b"fresh epoch after witnessed P")
        f.call("expired-current-witness-clock", 33, (400).to_bytes(8, "big"), b"witness clock set")
        f.worker("expired-current-policy-denied", "next_id", now=400, refusal="witness current authority denied")
        require(f.worker("historical-applied-after-expiry", "policy_status", (operation,), now=400) == "Applied",
                "expiry rewrote historical P result")
        result = {"members": count, "journal": journal.hex(), "native_journal": original_native.hex(),
                  "session": session.hex(), "original_wire_sha256": hashlib.sha256(wire).hexdigest(),
                  "adopted": adopted, "workers": len(f.driver.operations),
                  "confirmed_epoch": confirmed,
                  "process_kills": sum("signal" in row for row in f.driver.operations),
                  "denied_operations": [r["case"] for r in f.driver.operations if "refused" in r],
                  "refusals": f.refusals,
                  "native_refusals": [{"case": r["case"], "error": r["error"]}
                                      for r in f.native.commands if r["status"] == 2],
                  "scope": "Actual original registered required-witness P at explicit clocks, same original native peer; no device or release claim."}
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
    report["profiles"] = [scenario(args, count) for count in (3, 32)]
    require(before == inventory() and native == hashlib.sha256(args.native.read_bytes()).hexdigest(), "witness policy inputs changed")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["profiles"]))


if __name__ == "__main__":
    main()
