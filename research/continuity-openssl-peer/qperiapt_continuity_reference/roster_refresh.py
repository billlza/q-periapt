"""Original common-account roster maintenance, preserving G and business state."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import threading
from .account_snapshot import shared
from .durable import Session
from .identity import roster as verify_roster
from .identity_state import local_view
from .journal import LocalSessionJournal, locked
from .local_authority_control import Control, admit_snapshot, read, write
from .maintenance_terminal import Transition, finish
from .owner_guard import root_coordinated as coordinated
from .roster_control import Control as RControl
from .roster_intent import Intent
from .roster_protocol import Scope, Proposal
from .state_codec import decode, encode
from .witness import Head, fixed
from .witness_journal import WitnessJournal
from .wire import require
from .policy_snapshot import admit as admit_policy, validate as validate_policy


class RosterRefresh:
    def __init__(self, journal, context, operation):
        self._journal, self._context, self.operation = journal, context, operation
        self._lock, self._busy = threading.RLock(), False

    @classmethod
    def open(cls, path, scope, key, context, operation, *, client=None, observer=None,root_lease=None):
        require(shared(context) and context.policy_version > 0, "roster maintenance requires original common-account policy")
        Session._scope(context, scope,root_lease)
        fixed(operation, 32)
        if context.witness is None:
            require(client is None, "local roster profile cannot use a witness carrier")
            journal = LocalSessionJournal.open(path, scope, key, Session._validator(context), observer=observer,root_lease=root_lease)
        else:
            require(client is not None and client.signer is not None
                    and client.signer.public() == context.initiator, "original roster signer")
            journal = WitnessJournal(path, scope, key, Session._validator(context), context.witness, client, observer,root_lease=root_lease)
        owner = cls(journal, context, operation)
        try:
            pending = journal._admit().read("intent")
            if context.witness is not None and (pending is None or pending.startswith(b"QPREFI01")):
                journal._recover(False)
            owner._inspect()
            return owner
        except BaseException:
            journal.close()
            raise

    def _inspect(self):
        journal = self._journal
        head = journal._admit().read("head")
        require(head is not None, "missing original roster head")
        snapshot = journal._decode(head)
        control = read(journal)
        intent = Intent.read(journal, self._context) if self._context.witness is not None else None
        state = decode(snapshot.payload, self._context)
        try:
            require(state.traffic is not None and state.account_authority is not None
                    and state.account_renewal is not None, "roster requires original established common account")
            if state.policy_renewal is not None:
                validate_policy(state, self._context, journal.scope.identity)
            if self._context.witness is None:
                require(control is None, "witness coordination in local roster store")
                return snapshot, None, None
            if control is not None:
                require(control.phase in (0, 4, 5), "credential coordination remains pending")
            r = None if control is None else control.roster
            if intent is not None:
                require(control is not None, "missing original roster control")
                p = intent.proposal
                require((snapshot.digest, snapshot.revision) in ((p.expected.digest, p.expected.revision),
                        (p.target.digest, p.target.revision)), "roster current head conflict")
                if r is not None and not r.ready():
                    require(r.proposal == p, "roster control/intent conflict")
                else:
                    require(control.ready() and int.from_bytes(p.scope.target[:8], "big")
                            > max(control.floor, r.floor if r else 0), "roster successor retired")
                # The independently retained G receipt still authenticates the
                # candidate target; R cannot create a new credential completion.
                target = decode(journal._decode(intent.target).payload, self._context)
                try:
                    admitted = replace(control, roster=RControl(4, int.from_bytes(p.scope.target[:8], "big"), p, p.scope.target))
                    self._check_control_image(admitted, target)
                finally:
                    target.close()
            elif r is not None and not r.ready():
                require(r.phase in (2, 3), "missing original pending roster target")
                expected = r.proposal.target if r.phase == 2 else r.proposal.expected
                require(snapshot.digest == expected.digest and snapshot.revision == expected.revision,
                        "terminal roster lost original image")
            else:
                admit_snapshot(journal, state)
        finally:
            state.close()
        return snapshot, control, intent

    @staticmethod
    def _check_control_image(control, state):
        from .policy_control import admit as check_policy_control
        check_policy_control(control, state)
        current = local_view(state, state.operation._context)
        if current.renewal is None:
            require(control.active == bytes(32) and control.active_account_binding is None,
                    "roster substituted original credential")
        else:
            receipt = state.account_renewal.completed
            require(control.active == current.renewal.statement and receipt is not None
                    and receipt.binding == control.active_account_binding,
                    "roster changed original credential completion")
        from .roster_control import admit
        admit(control, state, current)

    def _current(self, inspected=None):
        snapshot, control, intent = self._inspect() if inspected is None else inspected
        require(control is not None, "original roster control unavailable")
        r = control.roster
        p = intent.proposal if intent else (r.proposal if r else None)
        require(p is not None and p.scope.operation == self.operation, "original roster operation unavailable")
        if intent is not None and (r is None or r.ready()):
            r = RControl(1, max(control.floor, r.floor if r else 0), p, None if r is None else r.active)
            control = replace(control, roster=r)
            write(self._journal, control)
        return snapshot, control, intent

    def _advance_state(self, state, wire, target, now, floor):
        require(state.policy_renewal is None or state.policy_renewal.pending is None,
                "policy renewal remains pending")
        record, account = state.account_renewal, state.account_authority
        record.admit()
        record.current_time(now)
        admit_policy(state, self._context, now)
        current = account.view(self._context.devices[0], local=True)
        require(current.active(), "revoked original local device cannot refresh its roster")
        current.current.validity.check(now)
        next_account = account.advance(wire, target, now=now)
        next_account.view(self._context.devices[0], local=True).check(now)
        require(next_account.listing.version > floor, "roster successor retired")
        active = None if state.policy_renewal is None else state.policy_renewal.active
        policy = (self._context.policy_version.to_bytes(8, "big") + self._context.policy_digest
                  if active is None else active.target.checkpoint())
        scope = Scope(self.operation, account.listing.checkpoint(), target, policy,
                      None if active is None else active.approval.statement)
        scope.check_policy(self._context, state.policy_renewal, current=True)
        if active is not None:
            state.policy_renewal = replace(state.policy_renewal, roster_history=active)
        state.account_authority = next_account
        state.account_renewal = replace(record, roster=scope)
        state.format_version = 10
        return scope

    @coordinated
    def refresh(self, wire, target, now):
        try:
            require(self._context.witness is None, "required roster needs explicit prepare and commit")
            snapshot, _, _ = self._inspect()
            state = decode(snapshot.payload, self._context)
            try:
                listing = verify_roster(self._context.devices[0].pin, wire, expected=target)
                prior = state.account_renewal.roster
                if prior is not None and prior.operation == self.operation:
                    require(prior.target == listing.checkpoint(), "different original roster target")
                    return "Applied"
                self._advance_state(state, wire, target, now, 0)
                result = self._journal.update(snapshot.digest, encode(state))
                require(self._journal.read().digest == result.digest, "roster durable readback")
                self._journal._admit().observe("roster:completed")
                return "Applied"
            finally:
                state.close()
        except BaseException:
            self.close()
            raise

    @coordinated
    def prepare(self, wire, target, now):
        try:
            require(self._context.witness is not None, "local roster uses atomic refresh")
            snapshot, control, intent = self._inspect()
            listing = verify_roster(self._context.devices[0].pin, wire, expected=target)
            r = None if control is None else control.roster
            existing = intent.proposal if intent else (r.proposal if r else None)
            if existing is not None and existing.scope.operation == self.operation:
                require(existing.scope.target == listing.checkpoint(), "different original roster target")
                self._current()
                return existing.wire()
            require(intent is None and (control is None or control.ready()), "another roster or credential remains pending")
            state = decode(snapshot.payload, self._context)
            try:
                control = Control() if control is None else control
                scope = self._advance_state(state, wire, target, now, max(control.floor, r.floor if r else 0))
                self._journal._query(snapshot)
                sealed = self._journal._seal(snapshot.revision + 1, encode(state))
                next_snapshot = self._journal._decode(sealed)
                proposal = Proposal(self._context.witness.pin.binding, self._journal.subject, scope,
                                    Head(1, snapshot.revision, snapshot.digest),
                                    Head(1, next_snapshot.revision, next_snapshot.digest))
                retained = Intent(proposal, sealed)
                raw = retained.wire(self._journal)
                pending = replace(control, roster=RControl(1, max(control.floor, r.floor if r else 0),
                                                          proposal, None if r is None else r.active))
                self._journal._admit().quota(len(raw) + len(sealed) + 2 * (len(pending.wire(self._journal.scope)) + 32), 4)
                if read(self._journal) is None:
                    write(self._journal, control)
                self._journal._admit().publish("intent", raw)
                require(Intent.read(self._journal, self._context) == retained, "roster intent durable readback")
                write(self._journal, pending)
                self._journal._admit().observe("roster:prepared")
                return proposal.wire()
            finally:
                state.close()
        except BaseException:
            self.close()
            raise

    def _observed(self, inspected=None):
        snapshot, control, intent = self._current(inspected)
        r = control.roster
        if r.ready():
            return snapshot, control, intent, "Applied" if r.phase == 4 else "Closed"
        outcome = r.proposal.exchange(self._journal.client, 17)
        if r.phase in (2, 3):
            retained = "Applied" if r.phase == 2 else "Closed"
            require(outcome in (retained, "Unavailable"), "witness contradicts durable roster terminal")
            outcome = retained
        return snapshot, control, intent, outcome

    def _finish(self, snapshot, control, intent, outcome):
        r = control.roster
        if r.ready():
            return outcome
        require(outcome in ("Applied", "Closed"), "roster has no exact terminal")
        phase = 2 if outcome == "Applied" else 3
        terminal = RControl(phase, int.from_bytes(r.proposal.scope.target[:8], "big"), r.proposal,
                            r.proposal.scope.target if outcome == "Applied" else r.active)
        return finish(self._journal, snapshot, intent, outcome, Transition(r.proposal,
                      replace(control, roster=terminal), replace(control, roster=replace(terminal, phase=phase + 2)),
                      19, lambda: Intent.read(self._journal, self._context), "roster"))

    def _prior_applied(self, inspected):
        # A newer Pending/Closed coordinator does not erase the one active R
        # receipt. Observe it only; never run the newer transaction's terminal
        # sequence on behalf of this older operation.
        snapshot, control, _ = inspected
        r = None if control is None else control.roster
        if r is None or r.proposal.scope.operation == self.operation or r.active is None:
            return False
        state = decode(snapshot.payload, self._context)
        try:
            retained = state.account_renewal.roster
            return (retained is not None and retained.operation == self.operation
                    and retained.target == r.active)
        finally:
            state.close()

    @coordinated
    def status(self):
        try:
            if self._context.witness is not None:
                inspected = self._inspect()
                if self._prior_applied(inspected):
                    return "Applied"
                return self._observed(inspected)[3]
            snapshot, _, _ = self._inspect()
            state = decode(snapshot.payload, self._context)
            try:
                retained = state.account_renewal.roster
                require(retained is not None and retained.operation == self.operation, "original roster operation unavailable")
                return "Applied"
            finally:
                state.close()
        except BaseException:
            self.close()
            raise

    @coordinated
    def recover(self):
        try:
            inspected = self._inspect()
            if self._prior_applied(inspected):
                return "Applied"
            snapshot, control, intent, outcome = self._observed(inspected)
            return self._finish(snapshot, control, intent, outcome) if outcome in ("Applied", "Closed") else outcome
        except BaseException:
            self.close()
            raise

    @coordinated
    def commit(self, now):
        try:
            snapshot, control, intent, outcome = self._observed()
            if outcome == "Prepared":
                require(intent is not None, "missing original roster commit target")
                target = decode(self._journal._decode(intent.target).payload, self._context)
                try:
                    admit_policy(target, self._context, now)
                    local_view(target, self._context).check(now)
                finally:
                    target.close()
                outcome = control.roster.proposal.exchange(self._journal.client, 16)
            return self._finish(snapshot, control, intent, outcome)
        except BaseException:
            self.close()
            raise

    @coordinated
    def close_proposal(self):
        try:
            snapshot, control, intent, outcome = self._observed()
            if outcome == "Prepared":
                outcome = control.roster.proposal.exchange(self._journal.client, 18)
            return self._finish(snapshot, control, intent, outcome)
        except BaseException:
            self.close()
            raise

    @locked
    def close(self):
        self._journal.close()
