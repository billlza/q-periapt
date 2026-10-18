"""Original-owner joint head/credential coordination; never a runtime activation."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import functools
import threading

from .durable import Session
from .identity_state import IdentityState
from .journal import locked
from .local_authority_control import Control, admit_snapshot, read as read_control, write as write_control
from .local_renewal_intent import Intent
from .local_renewal_protocol import Proposal
from .renewal import verify
from .state_codec import decode, encode
from .witness import Head
from .witness_journal import WitnessJournal
from .wire import require


def coordinated(function):
    @functools.wraps(function)
    def call(self, *args, **kwargs):
        with self._lock:
            require(not self._busy, "local renewal operation already in progress")
            self._busy = True
            try:
                return function(self, *args, **kwargs)
            finally:
                self._busy = False
    return call


class LocalRenewal:
    def __init__(self, journal, context, operation):
        self._journal, self._context, self.operation = journal, context, operation
        self._lock = threading.RLock()
        self._busy = False

    @classmethod
    def open(cls, path, scope, key, context, operation, *, client, observer=None):
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
            owner = cls(journal, context, operation)
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
                require(control.proposal == p and control.checkpoint == intent.checkpoint,
                        "local renewal control/intent conflict")
            else:
                require(control.ready() and int.from_bytes(intent.checkpoint[:8], "big") > control.floor,
                        "local renewal target retired")
        elif control is not None and not control.ready():
            require(control.phase in (2, 3), "missing original pending renewal target")
            expected = control.proposal.target if control.phase == 2 else control.proposal.expected
            require(snapshot.digest == expected.digest and snapshot.revision == expected.revision,
                    "terminal renewal lost original image")
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
            control = Control(1, control.floor, control.active, p, intent.checkpoint)
            write_control(self._journal, control)
        return snapshot, control, intent

    @coordinated
    def prepare(self, grant_wire, target_checkpoint, now):
        try:
            snapshot, control, intent = self._inspect()
            state = decode(snapshot.payload, self._context)
            try:
                current = state.local_authority or IdentityState.initial(self._context, role=0)
                grant = verify(grant_wire, current.original, self._context.family, self._context.policy_digest,
                               target_checkpoint)
                require(grant.operation == self.operation, "local renewal original operation differs")
                existing = intent.proposal if intent else (control.proposal if control else None)
                if existing is not None and existing.operation == self.operation:
                    require(existing.statement == grant.statement and
                            (intent.checkpoint if intent else control.checkpoint) == target_checkpoint,
                            "conflicting original local renewal")
                    self._current()
                    return existing.wire()
                require(intent is None and (control is None or control.ready()), "another local renewal remains pending")
                require(state.traffic is not None, "local renewal requires original established session")
                self._context.intervals[0].check(now); grant.current(now)
                next_identity = current.renew(self._context, grant_wire, self.operation, target_checkpoint, now)
                require(next_identity is not current, "local renewal target already installed without its receipt")
                if control is None:
                    control = Control(); write_control(self._journal, control)
                require(next_identity.listing.version > control.floor, "local renewal successor retired")
                require(control.active == (current.renewal.statement if current.renewal else bytes(32)),
                        "local renewal predecessor control differs")
                self._journal._query(snapshot)
                state.local_authority = next_identity; state.format_version = 6
                target = self._journal._seal(snapshot.revision + 1, encode(state))
                target_snapshot = self._journal._decode(target)
                p = Proposal(self._context.witness.pin.binding, self._journal.subject, self.operation, grant.statement,
                             Head(1, snapshot.revision, snapshot.digest), Head(1, target_snapshot.revision, target_snapshot.digest))
                retained = Intent(p, target, target_checkpoint)
                wire = retained.wire(self._journal)
                self._journal._admit().quota(len(wire) + len(target) + 2 * 513, 4)
                self._journal._admit().publish("intent", wire)
                require(Intent.read(self._journal, self._context) == retained, "local renewal intent durable readback")
                write_control(self._journal, Control(1, control.floor, control.active, p, target_checkpoint))
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
        if outcome == "Applied":
            if snapshot.digest != p.target.digest:
                require(intent is not None and snapshot.digest == p.expected.digest, "missing original applied target")
                self._journal._admit().publish("head", intent.target)
                snapshot = self._journal._decode(intent.target)
            self._journal._query(snapshot)
            phase, active = 2, p.statement
        else:
            require(snapshot.digest == p.expected.digest, "closed target was installed")
            self._journal._query(snapshot)
            phase, active = 3, control.active
        terminal = Control(phase, int.from_bytes(control.checkpoint[:8], "big"), active, p, control.checkpoint)
        write_control(self._journal, terminal)
        self._journal._admit().observe("renewal:terminal-durable")
        require(p.exchange(self._journal.client, 8) in ("Acknowledged", "Unavailable"), "renewal terminal acknowledgement")
        self._journal._admit().observe("renewal:acknowledged")
        if self._journal._admit().read("intent") is not None:
            require(Intent.read(self._journal, self._context) == intent, "another intent replaced terminal renewal")
            self._journal._admit().remove_intent()
        write_control(self._journal, replace(terminal, phase=phase + 2))
        self._journal._admit().observe("renewal:completed")
        return outcome

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
                    self._context.intervals[0].check(now)
                    target.local_authority.check(now)
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
