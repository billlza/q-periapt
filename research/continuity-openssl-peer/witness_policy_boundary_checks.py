#!/usr/bin/env python3
"""Full original witnessed store through expired P, parent close and recovery."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys


def scenario(args):
    from registration_fixture import Fixture
    from shared_account_checks import start
    from account_capacity_fixture import fill
    from local_budget_controls import inventory
    from local_policy_checks import policy_inputs
    from witness_policy_checks import request_approval
    from qperiapt_continuity_reference.state_codec import encode, decode
    from qperiapt_continuity_reference.policy_control import admit
    from qperiapt_continuity_reference.storage_budget import MAX_POLICY_STATE
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    f = Fixture(args, "witness", account_members=32, enrolled_peer=True, policy_lifecycle=True)
    parent = None
    try:
        journal, session = start(f)
        f.call("live-fill-clock", 33, (170).to_bytes(8, "big"), b"witness clock set")
        full = fill(f)
        original_head = (f.session_path / "head").read_bytes()
        f.call("first-policy-clock", 33, (190).to_bytes(8, "big"), b"witness clock set")
        first = os.urandom(32)
        request, approval = request_approval(f, "expiring", 2, 190, first)
        arguments = (first, approval, *policy_inputs(f, 2))
        f.worker("full-original-prepare-cut", "policy_prepare", arguments, now=190,
                 cut="session-store:committed:intent")
        intent = (f.session_path / "intent").read_bytes()
        proposal = f.value("full-original-preparation-recovered", "policy_prepare", arguments, now=190)
        require((f.session_path / "intent").read_bytes() == intent, "full original target was regenerated")
        f.call("full-independent-approval", 43, proposal + len(approval).to_bytes(2, "big") + approval + request, b"Prepared")
        f.call("expire-prepared-target-clock", 33, (261).to_bytes(8, "big"), b"witness clock set")
        start_request = len(f.bridge.records)
        f.worker("expired-prepared-target-cannot-commit", "policy_commit", (first,), now=261,
                 refusal="expired or premature authority")
        expiry_kinds = [r["kind"] for r in f.bridge.records[start_request:]]
        require(11 not in expiry_kinds and (f.session_path / "head").read_bytes() == original_head,
                "expired P dispatched commit or changed original head")
        f.worker("expired-target-close-cut", "policy_close", (first,), now=261, cut="policy:terminal-durable")
        require(f.worker("expired-target-original-close-recovery", "policy_recover", (first,), now=261) == "Closed"
                and (f.session_path / "head").read_bytes() == original_head, "expired P replaced original state")
        f.worker("historical-closure-is-not-permission", "next_id", now=261, refusal="witness current authority denied")

        f.call("successor-live-clock", 33, (270).to_bytes(8, "big"), b"witness clock set")
        second = os.urandom(32)
        request, approval = request_approval(f, "successor", 3, 270, second)
        arguments = (second, approval, *policy_inputs(f, 3))
        armed = [True]
        def close_parent(stage):
            if armed[0] and stage == "session-store:committed:intent":
                armed[0] = False; parent.close()
        parent = f.owner(close_parent)
        child = parent.policy_renewal(second, 270, transport=f.transport())
        f.refuses("parent-close-withholds-policy-proposal", lambda: child.prepare(*arguments[1:], now=270), "closed")
        require(not armed[0], "parent close boundary not reached")
        parent.close(); parent = None
        retained = (f.session_path / "intent").read_bytes()
        proposal = f.value("original-parent-close-recovery", "policy_prepare", arguments, now=270)
        require((f.session_path / "intent").read_bytes() == retained, "parent-close recovery changed target")
        f.call("successor-independent-approval", 43, proposal + len(approval).to_bytes(2, "big") + approval + request, b"Prepared")
        f.worker("full-applied-head-cut", "policy_commit", (second,), now=270, cut="session-store:committed:head")
        require(f.worker("full-applied-original-recovery", "policy_recover", (second,), now=270) == "Applied",
                "full original P was not applied")
        native = f.call("full-native-original-adoption", 42, (3).to_bytes(8, "big") + (270).to_bytes(8, "big"))
        require(len(native) == 72 and native[32:64] == session, "full native original session changed")
        parent = f.owner()
        with parent.session(270, transport=f.transport()) as owner:
            with owner._owner._state(operational=False) as (snapshot, state):
                require(inventory(state) == full["inventory"], "full P changed business history")
                payload_bytes = len(snapshot.payload)
                f.refuses("witness-policy-control-cannot-be-removed", lambda: admit(None, state), "missing original policy completion")
                f.refuses("witness-policy-rejects-local-time-floor", lambda: encode(replace(state,
                    policy_renewal=replace(state.policy_renewal, floor=261))), "witness policy cannot use local-only disposition")
                f.refuses("witness-policy-overall-capacity", lambda: decode(snapshot.payload + bytes(
                    MAX_POLICY_STATE + 1 - len(snapshot.payload)), f.context), "policy snapshot capacity")
            require(owner.resume(full["first_id"], now=270) == full["first_wire"]
                    and owner.resume(full["last_id"], now=270) == full["last_wire"], "full P changed old ciphertext")
            next_id = owner.next_id(now=270)
            f.refuses("policy-metadata-cannot-fund-business", lambda: owner.send(next_id, b"x", b"", now=270),
                      "reserved final traffic capacity")
        parent.close(); parent = None
        f.call("native-first-epoch-decrypt", 7, application(b"", full["first_wire"]), full["plain"])
        f.call("native-last-epoch-decrypt", 7, application(b"", full["last_wire"]), full["last_plain"])
        f.call("current-expiry-clock", 33, (330).to_bytes(8, "big"), b"witness clock set")
        f.worker("current-policy-expiry-denies-full-output", "resume", (full["first_id"],), now=330,
                 refusal="witness current authority denied")
        require(f.worker("full-historical-policy-outcome", "policy_status", (second,), now=330) == "Applied",
                "expired current policy rewrote history")
        result = {"members": 32, "traffic_bytes": full["traffic_bytes"], "rows": full["rows"],
                  "original_inventory": full["inventory"], "journal": journal.hex(), "native_journal": native[:32].hex(),
                  "session": session.hex(), "payload_bytes": payload_bytes, "prepared_intent_bytes": len(retained),
                  "expiry_kinds": expiry_kinds, "workers": len(f.driver.operations),
                  "process_kills": sum("signal" in r for r in f.driver.operations), "refusals": f.refusals,
                  "denied_operations": [r["case"] for r in f.driver.operations if "refused" in r],
                  "scope": "Actual full original required-witness P with explicit expiry clocks and original native counterpart; not device, G/R-after-P or release evidence."}
        (f.out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        if parent is not None: parent.close()
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
    report["profile"] = scenario(args)
    require(before == inventory() and native == hashlib.sha256(args.native.read_bytes()).hexdigest(), "witness boundary inputs changed")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["profile"]))


if __name__ == "__main__":
    main()
