"""Policy composition hooks for the existing full-account storage workload."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import os
from local_policy_checks import policy_inputs
from witness_policy_checks import request_approval
from local_budget_controls import inventory
from qperiapt_continuity_reference.state_codec import encode, decode
from qperiapt_continuity_reference.policy_record import Record
from qperiapt_continuity_reference.policy_snapshot import original, current_device, base_payload
from qperiapt_continuity_reference.storage_budget import MAX_STATE, MAX_POLICY_STATE, MAX_POLICY_GRANT
from qperiapt_continuity_reference.wire import require


class PolicyCapacity:
    def __init__(self, fixture, session, filled):
        self.f, self.session, self.filled = fixture, session, filled
        self.version, self.native_journal, self.adoptions = 1, None, []

    def controller(self, proposal):
        return proposal + self.version.to_bytes(8, "big")

    def stage(self, version, now):
        f = self.f
        name = f"full-P{version}"
        if f.bridge:
            f.call(name + "-clock", 33, now.to_bytes(8, "big"), b"witness clock set")
        operation = os.urandom(32)
        request, approval = request_approval(f, name, version, now, operation)
        args = (operation, approval, *policy_inputs(f, version))
        if f.bridge:
            proposal = f.value(name + "-prepare", "policy_prepare", args, now=now)
            f.call(name + "-witness-approval", 43, proposal + len(approval).to_bytes(2, "big") + approval + request, b"Prepared")
        else:
            f.worker(name + "-stage", "policy_stage", args, now=now)
        return operation

    def commit(self, operation, version, now):
        f = self.f
        name = f"full-P{version}"
        f.worker(name + "-commit-cut", "policy_commit", (operation,), now=now, cut="session-store:committed:head")
        result = f.worker(name + "-original-recovery", "policy_recover" if f.bridge else "policy_status", (operation,), now=now)
        require(result == "Applied" if f.bridge else result["status"] == "Committed", "full original policy recovery")
        native = f.call(name + "-native", 42, version.to_bytes(8, "big") + now.to_bytes(8, "big"))
        require(len(native) == 72 and native[32:64] == self.session and native[64:] == now.to_bytes(8, "big"),
                "full P replaced original native session")
        if self.native_journal is None:
            self.native_journal = native[:32]
        require(native[:32] == self.native_journal, "full P replaced original native journal")
        self.version = version
        self.adoptions.append({"version": version, "at": now, "operation": operation.hex()})

    def advance(self, version, now):
        self.commit(self.stage(version, now), version, now)

    def check(self, state, payload):
        f = self.f
        require(encode(state) == payload and inventory(state) == self.filled["inventory"],
                "full P/R changed original business bytes")
        record = state.policy_renewal
        require(record.roster_history.target.version == 3, "full R lost original P3 proof")
        args = (original(f.context), f.context.devices[0], state.policy_journal, current_device(state, f.context))
        wire = record.encode()
        require(Record.read(wire, *args) == record, "full P/R record roundtrip")
        if record.active.target.version == 3:
            require(wire[:9] == b"QPIPRC02\x01", "current R proof was duplicated")
            base = replace(record, roster_history=None).encode()
            proof = record.active.encode()
            duplicate = b"QPIPRC02\x02" + len(proof).to_bytes(4, "big") + proof + base
            f.refuses("history-duplicate-active-proof", lambda: Record.read(duplicate, *args), "noncanonical")
            f.refuses("history-invalid-discriminator", lambda: Record.read(wire[:8] + b"\3" + wire[9:], *args),
                      "history discriminator")
            f.refuses("history-alias-without-active", lambda: Record.read(b"QPIPRC02\1" + Record().encode(), *args),
                      "alias requires active proof")
            f.refuses("history-cannot-expand-business", lambda: decode(payload[:52]
                + (MAX_STATE + 1).to_bytes(4, "big") + payload[56:], f.context), "shared-account snapshot field capacity")
        else:
            require(wire[:9] == b"QPIPRC02\x02", "older R proof not retained independently")
            f.refuses("history-full-field-capacity", lambda: Record.read(wire[:9]
                + (MAX_POLICY_GRANT + 1).to_bytes(4, "big") + wire[13:], *args), "history capacity")
            f.refuses("history-truncated-proof", lambda: Record.read(wire[:-1], *args), "truncated")
            f.refuses("history-wrong-journal", lambda: Record.read(wire, *args[:2], b"x" * 32, args[3]), "another journal")
        require(len(payload) > MAX_STATE and len(base_payload(payload)) < len(payload) <= MAX_POLICY_STATE,
                "full P/R allowance not exercised")

    def finish(self):
        f = self.f
        operation = self.stage(5, 355)
        parent = f.owner()
        try:
            with parent.policy_renewal(operation, 355, transport=f.transport()) as child:
                owner = child._owner
                if f.bridge:
                    snapshot, _, intent = owner._inspect()
                    target = owner._journal._decode(intent.target)
                    state = decode(target.payload, f.context)
                    try:
                        record = state.policy_renewal
                        require(record.active.target.version == 5 and record.pending is None
                                and record.roster_history.target.version == 3, "full witness target history differs")
                        require(inventory(state) == self.filled["inventory"], "full witnessed P target changed business")
                        pending_bytes = len(target.payload)
                    finally:
                        state.close()
                    prepared_proofs = 2
                else:
                    with owner._state() as (snapshot, state, record, _):
                        require(record.active.target.version == 4 and record.pending.target.version == 5
                                and record.roster_history.target.version == 3, "three full P proofs not retained")
                        require(inventory(state) == self.filled["inventory"], "full pending P changed business")
                        pending_bytes = len(snapshot.payload)
                    prepared_proofs = 3
        finally:
            parent.close()
        self.commit(operation, 5, 355)
        parent = f.owner()
        try:
            with parent.session(355, transport=f.transport()) as owner:
                with owner._owner._state(operational=False) as (snapshot, state):
                    require(inventory(state) == self.filled["inventory"]
                            and state.policy_renewal.active.target.version == 5
                            and state.policy_renewal.roster_history.target.version == 3,
                            "final full policy lost history or original business")
                    committed_bytes = len(snapshot.payload)
                require(owner.resume(self.filled["first_id"], now=355) == self.filled["first_wire"]
                        and owner.resume(self.filled["last_id"], now=355) == self.filled["last_wire"],
                        "final full policy changed original ciphertext")
                f.refuses("history-allocation-cannot-fund-send", lambda: owner.send(owner.next_id(now=355), b"x", b"", now=355),
                          "reserved final traffic capacity")
        finally:
            parent.close()
        return {"adoptions": self.adoptions, "history_policy": 3, "active_policy": 5,
                "prepared_proofs": prepared_proofs, "pending_bytes": pending_bytes,
                "committed_bytes": committed_bytes, "business_unchanged": True}
