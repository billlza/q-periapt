"""Original registered P transaction against an independently approving witness."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import threading
from .authority import authenticate_policy
from .durable import Session
from .enrollment_exchange import PolicyInputs
from .journal import locked
from .local_authority_control import (Control, admit_snapshot, admit_identity_control,
                                      read as read_control, write as write_control)
from .owner_guard import coordinated
from .policy_control import Control as PControl
from .policy_intent import Intent
from .policy_owner_inputs import certificate, check_original, public_request
from .policy_record import Grant, Record
from .policy_snapshot import original, current_device, validate
from .policy_witness_protocol import Proposal
from .state_codec import decode, encode
from .witness import Head, fixed
from .witness_journal import WitnessJournal
from .wire import require


class WitnessPolicyRenewal:
    def __init__(self, journal, context, operation, inputs):
        self._journal, self._context, self.operation, self._inputs = journal, context, operation, inputs
        self._lock, self._busy = threading.RLock(), False

    @classmethod
    def open(cls, path, scope, key, context, operation, inputs, *, client, observer=None):
        require(context.witness is not None, "policy witness profile missing")
        Session._scope(context, scope)
        fixed(operation, 32); check_original(context, inputs)
        require(client.signer is not None and client.signer.public() == context.initiator,
                "original policy signer differs")
        journal = WitnessJournal(path, scope, key, Session._validator(context), context.witness, client, observer)
        owner = cls(journal, context, operation, inputs)
        try:
            pending = journal._admit().read("intent")
            if pending is None or pending.startswith(b"QPREFI01"):
                journal._recover(False)
            owner._inspect()
            return owner
        except BaseException:
            owner.close(); raise

    def _inspect(self):
        journal = self._journal
        head = journal._admit().read("head")
        require(head is not None, "missing original policy head")
        snapshot, control = journal._decode(head), read_control(journal)
        intent = Intent.read(journal, self._context)
        p = None if control is None else control.policy
        require(control is not None or intent is None, "missing original policy control")
        if intent is not None:
            proposal = intent.proposal
            expected, target = proposal.expected, proposal.target
            actual = Head(1, snapshot.revision, snapshot.digest)
            require(actual in (expected, target), "policy current head conflicts")
            if p is not None and not p.ready():
                require(p.proposal == proposal and p.target == intent.checkpoint, "policy control/intent conflicts")
            else:
                require(control.ready() and actual == expected
                        and int.from_bytes(intent.checkpoint[:8], "big") > (0 if p is None else p.floor),
                        "policy target retired or installed without control")
        elif p is not None and not p.ready():
            require(p.phase in (2, 3), "missing original pending policy target")
            expected = p.proposal.target if p.phase == 2 else p.proposal.expected
            require(Head(1, snapshot.revision, snapshot.digest) == expected, "policy terminal lost original image")
        state = decode(snapshot.payload, self._context)
        try:
            require(state.traffic is not None, "policy renewal requires original established session")
            admit_identity_control(state, control)
            if state.policy_renewal is not None:
                validate(state, self._context, journal.scope.identity)
            if intent is None and (control is None or control.ready()):
                admit_snapshot(journal, state)
            else:
                active = None if state.policy_renewal is None else state.policy_renewal.active
                held = None if active is None else active.target.checkpoint() + active.approval.statement
                expected = None if p is None else p.active
                proposal = intent.proposal if intent is not None else p.proposal
                if snapshot.digest == proposal.target.digest:
                    expected = (intent.checkpoint if intent else p.target) + proposal.statement
                require(held == expected, "policy pending image/control differs")
        finally:
            state.close()
        return snapshot, control, intent

    def _current(self):
        snapshot, control, intent = self._inspect()
        p = None if control is None else control.policy
        proposal = intent.proposal if intent is not None else (p.proposal if p else None)
        require(proposal is not None and proposal.operation == self.operation, "original policy outcome unavailable")
        if intent is not None and control.ready():
            p = PControl(1, 0 if p is None else p.floor, proposal, intent.checkpoint, None if p is None else p.active)
            control = replace(control, policy=p); write_control(self._journal, control)
        return snapshot, control, intent

    @coordinated
    def request(self):
        try:
            snapshot, control, intent = self._inspect()
            require(intent is None and (control is None or control.ready()), "policy coordination remains pending")
            p = None if control is None else control.policy
            require(p is None or p.proposal.operation != self.operation, "policy request operation already retained")
            state = decode(snapshot.payload, self._context)
            try:
                self._journal._query(snapshot)
                return public_request(state, self._context, state.policy_renewal or Record(),
                                      current_device(state, self._context), self._inputs, self.operation,
                                      self._journal.scope.identity)
            finally:
                state.close()
        except BaseException:
            self.close(); raise

    @coordinated
    def prepare(self, approval, policy_pins, policy_materials, now):
        try:
            inputs = PolicyInputs.from_trusted(policy_pins, policy_materials)
            require(inputs.witness == self._context.witness.pin, "policy witness pin differs")
            target = authenticate_policy(inputs.pins, inputs.materials, now, witness_pin=inputs.witness)
            snapshot, control, intent = self._inspect()
            control = Control() if control is None else control
            p = control.policy
            state = decode(snapshot.payload, self._context)
            try:
                current = current_device(state, self._context)
                args = (original(self._context), self._context.devices[0], self._journal.scope.identity, current)
                record = state.policy_renewal or Record()
                known = intent.proposal if intent else (p.proposal if p else None)
                if known is not None and known.operation == self.operation:
                    require(intent is not None, "original policy terminal cannot be prepared again")
                    sealed = decode(self._journal._decode(intent.target).payload, self._context)
                    try:
                        held = sealed.policy_renewal.active
                        grant = Grant.current_inputs(approval, held.approval.scope, args[0], held.previous,
                            target, args[1], certificate(state, self._context, current, self._inputs), current.roster_wire, now)
                        require(grant.approval.statement == known.statement and grant.target == held.target,
                                "different original policy decision")
                    finally:
                        sealed.close()
                    self._current()
                    return known.wire()
                require(intent is None and control.ready(), "another policy coordination remains pending")
                require(target.history.version > (0 if p is None else p.floor), "policy target version retired")
                for pending in (state.account_renewal, state.local_renewal):
                    if pending is not None: pending.current_time(now)
                scope = record.request(self.operation, *args)
                previous = args[0] if record.active is None else record.active.target
                grant = Grant.current_inputs(approval, scope, args[0], previous, target, args[1],
                    certificate(state, self._context, current, self._inputs), current.roster_wire, now)
                committed = record.stage(grant, *args, now).commit(self.operation, *args, now)
                self._journal._query(snapshot)
                state.policy_renewal, state.policy_journal = committed, args[2]
                target_wire = self._journal._seal(snapshot.revision + 1, encode(state))
                sealed = self._journal._decode(target_wire)
                proposal = Proposal(self._context.witness.pin.binding, self._journal.subject, self.operation,
                    grant.approval.statement, Head(1, snapshot.revision, snapshot.digest), Head(1, sealed.revision, sealed.digest))
                intent = Intent(proposal, target_wire, grant.target.checkpoint())
                pending = replace(control, policy=PControl(1, 0 if p is None else p.floor, proposal,
                                  intent.checkpoint, None if p is None else p.active))
                wire = intent.wire(self._journal)
                self._journal._admit().quota(len(wire) + len(target_wire) + 2 * (len(pending.wire(self._journal.scope)) + 32), 4)
                if read_control(self._journal) is None: write_control(self._journal, control)
                self._journal._admit().publish("intent", wire)
                require(Intent.read(self._journal, self._context) == intent, "policy intent durable readback")
                write_control(self._journal, pending)
                self._journal._admit().observe("policy:prepared")
                return proposal.wire()
            finally:
                state.close()
        except BaseException:
            self.close(); raise

    @coordinated
    def preparation(self):
        """Recover the first sealed approval and proposal while intent is retained.

        No caller-supplied approval can replace the originally sealed bytes.
        Terminal history after intent retirement is queried through status/recover.
        """
        try:
            _, _, intent = self._current()
            require(intent is not None, "original policy preparation is no longer retained")
            state = decode(self._journal._decode(intent.target).payload, self._context)
            try:
                grant = state.policy_renewal.active
                require(grant.approval.scope.operation == self.operation
                        and grant.approval.statement == intent.proposal.statement,
                        "retained policy preparation differs")
                return {"schema": "qperiapt-policy-witness-preparation/1",
                        "binding": list(intent.proposal.binding), "proposal": intent.proposal.wire(),
                        "approval": grant.approval.wire}
            finally:
                state.close()
        except BaseException:
            self.close(); raise

    def _observed(self):
        snapshot, control, intent = self._current()
        p = control.policy
        if p.ready():
            return snapshot, control, intent, "Applied" if p.phase == 4 else "Closed"
        outcome = p.proposal.exchange(self._journal.client, 12)
        if p.phase in (2, 3):
            retained = "Applied" if p.phase == 2 else "Closed"
            require(outcome in (retained, "Unavailable"), "witness contradicts durable policy terminal")
            outcome = retained
        return snapshot, control, intent, outcome

    def _finish(self, snapshot, control, intent, outcome):
        p = control.policy
        if p.ready(): return outcome
        require(outcome in ("Applied", "Closed"), "policy has no exact terminal result")
        active = p.target + p.proposal.statement if outcome == "Applied" else p.active
        terminal = replace(p, phase=2 if outcome == "Applied" else 3,
                           floor=int.from_bytes(p.target[:8], "big"), active=active)
        from .maintenance_terminal import Transition, finish
        return finish(self._journal, snapshot, intent, outcome,
            Transition(p.proposal, replace(control, policy=terminal),
                       replace(control, policy=replace(terminal, phase=terminal.phase + 2)), 14,
                       lambda: Intent.read(self._journal, self._context), "policy"))

    @coordinated
    def status(self):
        try: return self._observed()[3]
        except BaseException:
            self.close(); raise

    @coordinated
    def recover(self):
        try:
            snapshot, control, intent, outcome = self._observed()
            return self._finish(snapshot, control, intent, outcome) if outcome in ("Applied", "Closed") else outcome
        except BaseException:
            self.close(); raise

    @coordinated
    def commit(self, now):
        try:
            snapshot, control, intent, outcome = self._observed()
            if outcome == "Prepared":
                require(intent is not None, "missing original policy commit target")
                state = decode(self._journal._decode(intent.target).payload, self._context)
                try:
                    validate(state, self._context, self._journal.scope.identity)
                    state.policy_renewal.active.check_current(now)
                    for record in (state.account_renewal, state.local_renewal):
                        if record is not None: record.current_time(now)
                finally:
                    state.close()
                outcome = control.policy.proposal.exchange(self._journal.client, 11)
            require(outcome in ("Applied", "Closed"), "policy not independently prepared")
            return self._finish(snapshot, control, intent, outcome)
        except BaseException:
            self.close(); raise

    @coordinated
    def close_proposal(self):
        try:
            snapshot, control, intent, outcome = self._observed()
            if outcome == "Prepared": outcome = control.policy.proposal.exchange(self._journal.client, 13)
            require(outcome in ("Applied", "Closed"), "policy exact close unavailable")
            return self._finish(snapshot, control, intent, outcome)
        except BaseException:
            self.close(); raise

    @locked
    def close(self):
        self._journal.close()
