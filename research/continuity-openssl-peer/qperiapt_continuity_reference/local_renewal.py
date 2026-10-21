"""Original-owner joint head/credential coordination; never a runtime activation."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import threading

from .durable import Session
from .identity_state import IdentityState, local_view
from .account_snapshot import initialize, shared
from .account_record import AccountRecord, Receipt
from .account_request import AccountRequest
from .journal import locked
from .local_authority_control import Control, admit_snapshot, read as read_control, write as write_control
from .local_renewal_intent import Intent
from .local_renewal_protocol import Proposal
from .owner_guard import coordinated
from .renewal import verify
from .state_codec import decode, encode
from .witness import Head
from .witness_journal import WitnessJournal
from .wire import require
from .policy_snapshot import admit as admit_policy, authorization, validate as validate_policy


class LocalRenewal:
    def __init__(self, journal, context, operation, inputs=None):
        self._journal, self._context, self.operation = journal, context, operation
        self._inputs = inputs
        self._lock = threading.RLock()
        self._busy = False

    @classmethod
    def open(cls, path, scope, key, context, operation, *, client, observer=None, inputs=None):
        require(context.witness is not None, "joint local renewal requires original witness")
        Session._scope(context, scope)
        require(type(operation) is bytes and len(operation) == 32 and any(operation), "original local renewal operation")
        require(client.signer is not None and client.signer.public() == context.initiator,
                "original local renewal signer")
        journal = WitnessJournal(path, scope, key, Session._validator(context), context.witness, client, observer)
        try:
            pending = journal._admit().read("intent")
            if pending is None or pending.startswith(b"QPREFI01"):
                # Unrelated ordinary work must reconcile on its own original
                # terms; the root grant cannot overwrite or authorize that intent.
                journal._recover(False)
            owner = cls(journal, context, operation, inputs)
            owner._inspect()
            return owner
        except BaseException:
            journal.close()
            raise

    def _inspect(self):
        journal = self._journal; directory = journal._admit()
        head = directory.read("head"); require(head is not None, "missing original renewal head")
        snapshot = journal._decode(head); control = read_control(journal)
        intent = Intent.read(journal, self._context)
        require(control is not None or (intent is None and snapshot.payload[:8] != b"QPREFS06"),
                "missing original renewal control")
        if intent is not None:
            p = intent.proposal
            require(snapshot.digest in (p.expected.digest, p.target.digest)
                    and snapshot.revision in (p.expected.revision, p.target.revision), "local renewal current head conflict")
            require((snapshot.digest == p.expected.digest) == (snapshot.revision == p.expected.revision),
                    "local renewal predecessor revision conflict")
            if control.phase in (1, 2, 3):
                require(control.proposal == p and control.checkpoint == intent.checkpoint
                        and control.account_binding == intent.account_binding,
                        "local renewal control/intent conflict")
            else:
                require(control.ready() and int.from_bytes(intent.checkpoint[:8], "big")
                        > max(control.floor, control.roster.floor if control.roster else 0),
                        "local renewal target retired")
        elif control is not None and not control.ready():
            require(control.phase in (2, 3), "missing original pending renewal target")
            expected = control.proposal.target if control.phase == 2 else control.proposal.expected
            require(snapshot.digest == expected.digest and snapshot.revision == expected.revision,
                    "terminal renewal lost original image")
        state = decode(snapshot.payload, self._context)
        try:
            if state.policy_renewal is not None:
                validate_policy(state, self._context, journal.scope.identity)
            if control is not None and control.phase in (1, 2, 3):
                require(control.proposal.policy == authorization(state), "credential coordinator policy differs")
        finally:
            state.close()
        if intent is None and (control is None or control.ready()):
            state = decode(snapshot.payload, self._context)
            try:
                admit_snapshot(journal, state)
            finally:
                state.close()
        return snapshot, control, intent

    def _current(self):
        snapshot, control, intent = self._inspect()
        p = intent.proposal if intent is not None else (control.proposal if control else None)
        require(p is not None and p.operation == self.operation, "original renewal operation unavailable")
        if intent is not None and control.ready():
            control = Control(1, control.floor, control.active, p, intent.checkpoint,
                              intent.account_binding, control.active_account_binding, control.roster, control.policy)
            write_control(self._journal, control)
        return snapshot, control, intent

    @coordinated
    def request(self):
        """Historical original issuer request, never a reservation or live owner."""
        try:
            from .credential_request import retained
            snapshot, control, intent = self._inspect()
            require(intent is None and (control is None or control.ready()), 'credential coordination remains pending')
            require(control is None or control.proposal is None or control.proposal.operation != self.operation,
                    'credential request operation already retained')
            state = decode(snapshot.payload, self._context)
            try:
                result = retained(state, self._context, self._inputs, self.operation, self._journal.scope.identity)
                self._journal._query(snapshot)
                return result
            finally: state.close()
        except BaseException:
            self.close(); raise

    @coordinated
    def prepare(self, grant_wire, target_checkpoint, now, *, expected_statement=None):
        return self._prepare(grant_wire, target_checkpoint, now, None, expected_statement)

    @coordinated
    def prepare_account(self, grant_wire, companions, target_checkpoint, now):
        return self._prepare(grant_wire, target_checkpoint, now, companions)

    def _prepare(self, grant_wire, target_checkpoint, now, companions, expected_statement=None):
        try:
            snapshot, control, intent = self._inspect()
            state = decode(snapshot.payload, self._context)
            try:
                request = None
                if shared(self._context):
                    require(companions is not None, "shared account requires prepare_account")
                    if state.format_version == 5:
                        initialize(state)
                    require(state.account_authority is not None and state.account_renewal is not None,
                            "original common account state absent")
                    request = AccountRequest.parse(grant_wire, companions, self._context.devices[0],
                                                   self._context.family, self._context.policy_digest, target_checkpoint)
                    grant = request.local
                    current = local_view(state, self._context)
                else:
                    require(companions is None, "account renewal requires common account state")
                    current = state.local_authority or IdentityState.initial(self._context, role=0)
                    grant = verify(grant_wire, current.original, self._context.family, self._context.policy_digest,
                                   target_checkpoint)
                binding = None if request is None else request.binding()
                require(grant.operation == self.operation, "local renewal original operation differs")
                require(expected_statement is None or grant.statement == expected_statement,
                        'credential issuance statement differs from signed grant')
                existing = intent.proposal if intent else (control.proposal if control else None)
                if existing is not None and existing.operation == self.operation:
                    require(existing.statement == grant.statement and
                            (intent.checkpoint if intent else control.checkpoint) == target_checkpoint
                            and (intent.account_binding if intent else control.account_binding) == binding,
                            "conflicting original local renewal")
                    self._current()
                    return existing.wire()
                require(intent is None and (control is None or control.ready()), "another local renewal remains pending")
                require(state.traffic is not None, "local renewal requires original established session")
                admit_policy(state, self._context, now); grant.current(now)
                if request is None:
                    next_identity = current.renew(self._context, grant_wire, self.operation, target_checkpoint, now)
                    require(next_identity is not current, "local renewal target already installed without its receipt")
                    version = next_identity.listing.version
                else:
                    account = request.apply(state.account_authority, now)
                    version = account.listing.version
                if control is None:
                    control = Control(); write_control(self._journal, control)
                require(version > max(control.floor, control.roster.floor if control.roster else 0),
                        "local renewal successor retired")
                require(control.active == (current.renewal.statement if current.renewal else bytes(32)),
                        "local renewal predecessor control differs")
                active_binding = None if request is None or state.account_renewal.completed is None else state.account_renewal.completed.binding
                require(control.active_account_binding == active_binding, "local account predecessor control differs")
                self._journal._query(snapshot)
                if request is None:
                    state.local_authority = next_identity; state.format_version = 6
                else:
                    state.account_authority = account
                    state.account_renewal = AccountRecord(state.account_renewal.floor, completed=Receipt.for_request(request),
                                                         roster=state.account_renewal.roster)
                target = self._journal._seal(snapshot.revision + 1, encode(state))
                target_snapshot = self._journal._decode(target)
                p = Proposal(self._context.witness.pin.binding, self._journal.subject, self.operation, grant.statement,
                             Head(1, snapshot.revision, snapshot.digest), Head(1, target_snapshot.revision, target_snapshot.digest),
                             authorization(state))
                retained = Intent(p, target, target_checkpoint, binding)
                wire = retained.wire(self._journal)
                pending_control = Control(1, control.floor, control.active, p, target_checkpoint,
                                          binding, active_binding, control.roster, control.policy)
                self._journal._admit().quota(len(wire) + len(target)
                                            + 2 * (len(pending_control.wire(self._journal.scope)) + 32), 4)
                self._journal._admit().publish("intent", wire)
                require(Intent.read(self._journal, self._context) == retained, "local renewal intent durable readback")
                write_control(self._journal, pending_control)
                self._journal._admit().observe("renewal:prepared")
                return p.wire()
            finally:
                state.close()
        except BaseException:
            self.close(); raise

    def _observed(self):
        snapshot, control, intent = self._current()
        if control.phase in (4, 5):
            return snapshot, control, intent, "Applied" if control.phase == 4 else "Closed"
        outcome = control.proposal.exchange(self._journal.client, 6)
        if control.phase in (2, 3):
            retained = "Applied" if control.phase == 2 else "Closed"
            require(outcome in (retained, "Unavailable"), "witness contradicts durable renewal terminal")
            outcome = retained
        return snapshot, control, intent, outcome

    @coordinated
    def preparation(self):
        """Recover the exact retained proposal; no new approval is created."""
        try:
            _, _, intent = self._current()
            require(intent is not None, 'original credential preparation is no longer retained')
            return {'schema': 'qperiapt-credential-witness-proposal/1', 'operation': list(self.operation),
                    'journal': list(self._journal.scope.identity), 'proposal': intent.proposal.wire()}
        except BaseException:
            self.close(); raise

    @coordinated
    def status(self):
        try:
            return self._observed()[3]
        except BaseException:
            self.close(); raise

    def _finish(self, snapshot, control, intent, outcome):
        if control.ready():
            return outcome
        require(outcome in ("Applied", "Closed"), "local renewal has no terminal result")
        p = control.proposal
        phase, active = (2, p.statement) if outcome == "Applied" else (3, control.active)
        active_binding = control.account_binding if outcome == "Applied" else control.active_account_binding
        terminal = Control(phase, int.from_bytes(control.checkpoint[:8], "big"), active, p, control.checkpoint,
                           control.account_binding, active_binding, control.roster, control.policy)
        from .maintenance_terminal import Transition, finish
        return finish(self._journal, snapshot, intent, outcome,
                      Transition(p, terminal, replace(terminal, phase=phase + 2), 8,
                                 lambda: Intent.read(self._journal, self._context), "renewal"))

    @coordinated
    def recover(self):
        try:
            snapshot, control, intent, outcome = self._observed()
            if outcome in ("Applied", "Closed"):
                return self._finish(snapshot, control, intent, outcome)
            return outcome  # Prepared/Unavailable never authorizes installation.
        except BaseException:
            self.close(); raise

    @coordinated
    def commit(self, now):
        try:
            snapshot, control, intent, outcome = self._observed()
            if outcome == "Prepared":
                require(intent is not None, "missing original commit target")
                target = decode(self._journal._decode(intent.target).payload, self._context)
                try:
                    admit_policy(target, self._context, now)
                    local_view(target, self._context).check(now)
                    if target.account_authority is not None:
                        for grant in target.account_authority.renewals:
                            if grant.successor_roster.checkpoint() == intent.checkpoint:
                                grant.current(now)
                finally:
                    target.close()
                outcome = control.proposal.exchange(self._journal.client, 5)
            require(outcome in ("Applied", "Closed"), "renewal not independently prepared")
            return self._finish(snapshot, control, intent, outcome)
        except BaseException:
            self.close(); raise

    @coordinated
    def close_proposal(self):
        try:
            snapshot, control, intent, outcome = self._observed()
            if outcome == "Prepared":
                outcome = control.proposal.exchange(self._journal.client, 7)
            require(outcome in ("Applied", "Closed"), "renewal exact close unavailable")
            return self._finish(snapshot, control, intent, outcome)
        except BaseException:
            self.close(); raise

    @locked
    def close(self):
        self._journal.close()
