"""Inspect an original ordinary intent and confirm its exact witnessed target."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import threading
from .durable import Session
from .identity_state import local_binding
from .journal import locked
from .local_authority_control import admit_snapshot
from .owner_guard import root_coordinated as coordinated
from .pending_recovery_protocol import Proposal, INTENT_DOMAIN
from .pending_recovery_views import encode as public_view
from .state_codec import decode
from .witness import Head, Operation
from .witness_journal import WitnessJournal
from .wire import ldh, require


@dataclass(frozen=True)
class Request:
    proposal: bytes
    metadata: bytes
    signed_request: bytes


class PendingWriteRecovery:
    def __init__(self, journal, context):
        self._journal, self._context = journal, context
        self._lock = threading.RLock(); self._busy = False

    @classmethod
    def open(cls, path, scope, key, context, *, client, observer=None,root_lease=None):
        require(context.witness is not None, "pending recovery requires original witness")
        Session._scope(context, scope,root_lease)
        require(client.signer is not None and client.signer.public() == context.initiator,
                "original pending recovery signer")
        # Ordinary open would replay Advance. This owner first inspects the
        # authenticated source/target without issuing any request or mutation.
        journal = WitnessJournal(path, scope, key, Session._validator(context), context.witness, client, observer,root_lease=root_lease)
        owner = cls(journal, context)
        try:
            owner._inspect()
            return owner
        except BaseException:
            owner.close(); raise

    def _view(self, snapshot):
        state = decode(snapshot.payload, self._context)
        try:
            admit_snapshot(self._journal, state)
            return (local_binding(state, self._context), public_view(state, self._journal.scope,
                    Head(1, snapshot.revision, snapshot.digest)))
        finally:
            state.close()

    def _inspect(self):
        directory = self._journal._admit(); wire = directory.read("head")
        require(wire is not None, "missing original pending recovery image")
        pending = directory.read("intent")
        snapshot = self._journal._opening_head(wire, pending)
        authority, view = self._view(snapshot)
        if pending is None:
            return snapshot, wire, authority, view, None
        require(pending.startswith(b"QPREFI01"), "pending recovery requires ordinary intent")
        revision, prior, target, result = self._journal._decode_intent(pending)
        require(revision > 0, "pending recovery cannot complete inactive creation")
        expected, next_head = Head(1, revision, prior), Head(1, result.revision, result.digest)
        require(Head(1, snapshot.revision, snapshot.digest) in (expected, next_head),
                "ordinary intent does not name the original image")
        target_authority, target_view = self._view(result)
        require(authority == target_authority, "ordinary recovery cannot change local authority")
        return snapshot, wire, authority, view, (pending, expected, next_head, target, target_view)

    def _expectation(self, inspected):
        snapshot, _wire, authority, source, retained = inspected
        require(retained is not None, "original ordinary intent is absent")
        pending, expected, target, _target_wire, target_view = retained
        require(Head(1, snapshot.revision, snapshot.digest) == expected,
                "original source image unavailable; retain the original recovery request")
        return Proposal.create(self._context.witness.pin.binding, self._journal.subject, expected, target,
                               authority, self._context.policy_digest, ldh(INTENT_DOMAIN, pending), (source, target_view))

    @coordinated
    def request(self):
        try:
            proposal, metadata = self._expectation(self._inspect())
            signed = self._journal.client.signer.sign(26, proposal.wire())
            self._journal._admit().observe("pending-recovery:prepared")
            return Request(proposal.wire(), metadata, signed)
        except BaseException:
            self.close(); raise

    @coordinated
    def confirm(self, proposal_wire, metadata):
        try:
            proposal = Proposal.decode(proposal_wire); views = proposal.check_metadata(metadata)
            snapshot, wire, authority, view, retained = inspected = self._inspect()
            require(proposal.witness == self._context.witness.pin.binding and proposal.subject == self._journal.subject
                    and proposal.authority == authority and proposal.policy == self._context.policy_digest
                    and proposal.authorization is None, "pending recovery original authority scope")
            if retained is not None:
                pending, expected, target, target_wire, target_view = retained
                require((expected, target, ldh(INTENT_DOMAIN, pending), target_view)
                        == (proposal.expected, proposal.target, proposal.intent, views[1]), "original pending recovery differs")
                if snapshot.digest == expected.digest:
                    actual, complete = self._expectation(inspected)
                    require(actual == proposal and complete == metadata, "original complete recovery metadata differs")
            else:
                require(Head(1, snapshot.revision, snapshot.digest) == proposal.target and view == views[1],
                        "missing intent is not an exact confirmed target")
                original = self._journal._intent(proposal.expected.revision, proposal.expected.digest, wire)
                require(ldh(INTENT_DOMAIN, original) == proposal.intent, "original intent commitment differs")
                target_wire = wire
            # A privileged completion reply is not trusted as witness evidence.
            # This always obtains a fresh challenge-bound, read-only Query.
            reply = self._journal.client.exchange(Operation.query())
            proposal.confirm(reply)
            self._journal._admit().observe("pending-recovery:queried")
            if retained is not None:
                if snapshot.digest != proposal.target.digest:
                    self._journal._admit().publish("head", target_wire)
                require(self._journal._admit().read("intent") == pending, "pending recovery intent changed")
                self._journal._admit().remove_intent()
            current, _wire, current_authority, current_view, remaining = self._inspect()
            require(remaining is None and Head(1, current.revision, current.digest) == proposal.target
                    and current_authority == proposal.authority and current_view == views[1], "pending recovery durable readback")
            self._journal._admit().observe("pending-recovery:confirmed")
            return proposal.target.wire()
        except BaseException:
            self.close(); raise

    @locked
    def close(self):
        self._journal.close()
