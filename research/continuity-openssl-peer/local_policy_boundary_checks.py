#!/usr/bin/env python3
"""Full original business store, expired P intent and parent-close recovery."""
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
    from qperiapt_continuity_reference.state_codec import encode, decode
    from qperiapt_continuity_reference.policy_snapshot import base_payload
    from qperiapt_continuity_reference.policy_record import Record
    from qperiapt_continuity_reference.storage_budget import MAX_STATE, MAX_SHARED_STATE, MAX_POLICY_STATE, MAX_POLICY_RECORD
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    f = Fixture(args, "local-32", account_members=32, enrolled_peer=True, policy_lifecycle=True)
    parent = None
    try:
        journal, session = start(f)
        full = fill(f)

        def approve(name, operation, version, now):
            value = f.worker(name + "-request", "policy_request", (operation,), now=now)
            request = {k: bytes.fromhex(v) for k, v in value.items()}
            wire = version.to_bytes(8, "big") + now.to_bytes(8, "big") + request["scope"]
            for field in ("current_credential", "current_roster"):
                wire += len(request[field]).to_bytes(2, "big") + request[field]
            return f.call(name + "-approval", 41, wire)

        first = os.urandom(32)
        a1 = approve("expire", first, 2, 190)
        first_inputs = (first, a1, *policy_inputs(f, 2))
        f.worker("full-policy-stage-cut", "policy_stage", first_inputs, now=190,
                 cut="session-store:committed:intent")
        pending_intent = (f.session_path / "intent").read_bytes()
        require(f.worker("expired-pending-recovery", "policy_status", (first,), now=261)["status"] == "Pending"
                and (f.session_path / "head").read_bytes() == pending_intent[52:-32],
                "expired stage recovery changed exact original target")
        f.worker("expired-target-cannot-commit", "policy_commit", (first,), now=261,
                 refusal="expired or premature authority")
        unknown = os.urandom(32)
        f.worker("unknown-is-not-no-commit", "policy_expire", (unknown,), now=261,
                 refusal="original policy outcome unavailable")
        f.worker("expiry-record-cut", "policy_expire", (first,), now=261,
                 cut="session-store:committed:head")
        expiry_intent = (f.session_path / "intent").read_bytes()
        expired = f.worker("expiry-record-recovered", "policy_status", (first,), now=261)
        require(expired["status"] == "ExpiredUncommitted" and expired["time_floor"] == 261
                and (f.session_path / "head").read_bytes() == expiry_intent[52:-32],
                "expiry observation lost original exact commit")
        f.worker("abandoned-operation-cannot-reissue", "policy_request", (first,), now=261,
                 refusal="already has a disposition")
        f.worker("historical-expiry-does-not-admit-old-policy", "next_id", now=261,
                 refusal="expired or premature authority")

        second = os.urandom(32)
        a2 = approve("replacement", second, 3, 270)
        second_inputs = (second, a2, *policy_inputs(f, 3))
        f.worker("time-floor-refuses-backdated-target", "policy_stage", second_inputs, now=250,
                 refusal="policy time precedes durable floor")
        armed = [True]
        def close_parent(stage):
            if stage == "session-store:committed:intent" and armed[0]:
                armed[0] = False
                parent.close()
        parent = f.owner(close_parent)
        child = parent.policy_renewal(second, 270)
        f.refuses("parent-close-withholds-pending-result", lambda: child.stage(*second_inputs[1:], now=270), "closed")
        require(not armed[0], "parent close cut not reached")
        parent.close(); parent = None
        staged = (f.session_path / "intent").read_bytes()
        pending = f.worker("closed-parent-original-recovery", "policy_status", (second,), now=270)
        require(pending["status"] == "Pending" and (f.session_path / "head").read_bytes() == staged[52:-32],
                "parent close regenerated policy target")
        f.worker("full-policy-commit-cut", "policy_commit", (second,), now=270,
                 cut="session-store:removed:intent")
        completed = f.worker("full-policy-commit-recovered", "policy_status", (second,), now=270)
        require(completed["status"] == "Committed" and completed["time_floor"] == 261, "policy floor lost")
        native = f.call("native-direct-policy-continuation", 42, (3).to_bytes(8, "big") + (270).to_bytes(8, "big"))
        require(len(native) == 72 and native[32:64] == session, "native changed original session")
        parent = f.owner()
        with parent.session(270) as owner:
            with owner._owner._state(operational=False) as (snapshot, state):
                payload = snapshot.payload
                require(inventory(state) == full["inventory"] and encode(state) == payload,
                        "policy adoption changed full original business state")
                require(len(payload) - len(base_payload(payload)) <= MAX_POLICY_RECORD + 48,
                        "policy metadata exceeded its independent allocation")
                f.refuses("policy-marker-cannot-be-removed", lambda: encode(replace(state, policy_renewal=None)),
                          "policy journal requires its record")
                f.refuses("empty-policy-wrapper", lambda: encode(replace(state, policy_renewal=Record())),
                          "empty policy wrapper")
                f.refuses("wrong-policy-journal", lambda: encode(replace(state, policy_journal=bytes([91]) * 32)),
                          "another journal")
                f.refuses("policy-base-capacity", lambda: decode(payload[:40] + (MAX_SHARED_STATE + 1).to_bytes(4, "big")
                          + payload[44:], f.context), "policy base capacity")
                f.refuses("policy-wrapper-cannot-expand-business", lambda: decode(payload[:52]
                          + (MAX_STATE + 1).to_bytes(4, "big") + payload[56:], f.context),
                          "shared-account snapshot field capacity")
                f.refuses("policy-aggregate-capacity", lambda: decode(payload + bytes(MAX_POLICY_STATE + 1 - len(payload)),
                          f.context), "policy snapshot capacity")
            require(owner.resume(full["first_id"], now=270) == full["first_wire"]
                    and owner.resume(full["last_id"], now=270) == full["last_wire"],
                    "full policy continuation replaced old ciphertext")
            f.refuses("policy-allocation-cannot-fund-business", lambda: owner.send(owner.next_id(now=270), b"x", b"", now=270),
                      "reserved final traffic capacity")
        parent.close(); parent = None
        f.call("native-first-original-decrypt", 7, application(b"", full["first_wire"]), full["plain"])
        f.call("native-last-original-decrypt", 7, application(b"", full["last_wire"]), full["last_plain"])
        f.worker("expired-adopted-policy-refuses-old-output", "resume", (full["last_id"],), now=330,
                 refusal="expired or premature authority")
        third = os.urandom(32)
        a3 = approve("next-full-policy", third, 4, 340)
        f.worker("full-active-plus-pending-stage", "policy_stage", (third, a3, *policy_inputs(f, 4)), now=340)
        parent = f.owner()
        with parent.policy_renewal(third, 340) as coordinator:
            with coordinator._owner._state() as (snapshot, state, record, _):
                large_pending = len(snapshot.payload)
                require(record.active is not None and record.pending is not None
                        and large_pending > MAX_STATE and inventory(state) == full["inventory"],
                        "full active and pending policy allocation not exercised")
        parent.close(); parent = None
        f.worker("full-next-policy-commit-cut", "policy_commit", (third,), now=340,
                 cut="session-store:committed:head")
        final_intent = (f.session_path / "intent").read_bytes()
        require(f.worker("full-next-policy-recovered", "policy_status", (third,), now=340)["status"] == "Committed"
                and (f.session_path / "head").read_bytes() == final_intent[52:-32], "full sequential original target")
        next_native = f.call("native-next-full-policy", 42, (4).to_bytes(8, "big") + (340).to_bytes(8, "big"))
        require(next_native[:64] == native[:64] and next_native[64:] == (340).to_bytes(8, "big"),
                "sequential policy changed native original installation")
        parent = f.owner()
        with parent.session(340) as owner:
            with owner._owner._state(operational=False) as (_, state):
                require(inventory(state) == full["inventory"], "sequential policy lost original business state")
            require(owner.resume(full["first_id"], now=340) == full["first_wire"]
                    and owner.resume(full["last_id"], now=340) == full["last_wire"], "sequential policy changed ciphertext")
        parent.close(); parent = None
        f.call("native-sequential-first-decrypt", 7, application(b"", full["first_wire"]), full["plain"])
        f.call("native-sequential-last-decrypt", 7, application(b"", full["last_wire"]), full["last_plain"])
        f.worker("expired-final-policy-refuses-output", "next_id", now=400, refusal="expired or premature authority")
        require(f.worker("historical-completion-after-expiry", "policy_status", (third,), now=500)["status"] == "Committed",
                "historical completion was lost")
        result = {"members": 32, "traffic_bytes": full["traffic_bytes"], "rows": full["rows"],
                  "original_inventory": full["inventory"], "journal": journal.hex(), "native_journal": native[:32].hex(),
                  "session": session.hex(), "policy_payload_bytes": len(payload), "time_floor": 261,
                  "active_pending_payload_bytes": large_pending,
                  "workers": len(f.driver.operations), "process_kills": sum("signal" in row for row in f.driver.operations),
                  "denied_operations": [row["case"] for row in f.driver.operations if "refused" in row],
                  "refusals": f.refusals,
                  "scope": "Full original local store through expired uncommitted P, parent-close and exact write recovery, then real native continuation. Explicit fixture times; no required-witness P claim."}
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
             *sorted((root / "native/src").glob("*.rs")), root / "native/Cargo.toml", root / "native/Cargo.lock",
             root / "requirements.txt"]
    inventory = lambda: {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before, native = inventory(), hashlib.sha256(args.native.read_bytes()).hexdigest()
    args.output.mkdir()
    report = {"source_files": before, "native_sha256": native,
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (args.output / "INPUTS.json").write_text(json.dumps(report, indent=2) + "\n")
    report["profile"] = scenario(args)
    require(before == inventory() and native == hashlib.sha256(args.native.read_bytes()).hexdigest(), "boundary inputs changed")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["profile"]))


if __name__ == "__main__":
    main()
