"""Owned independent bootstrap and multi-epoch session over the exact-target store."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

from contextlib import contextmanager
import threading

from .bootstrap import Initiator
from .journal import LocalSessionJournal, Scope, MAX_STATE, locked
from .storage_budget import MAX_LOCAL_STATE
from .state_codec import State, SendPlan, encode, decode
from .epoch_state import EpochState
from .rekey_owner import RekeyOwner
from .control import ControlOwner
from .resolution_owner import ResolutionOwner
from .peer_owner import PeerOwner
from .identity_state import admit_local, local_binding
from .local_authority_control import admit_snapshot
from .traffic import message_id
from .wire import ldh, require


def owner_binding(context) -> bytes:
    return ldh(b"Q-PERIAPT-INDEPENDENT-OWNER/v1", context.initiator.raw)


class Session(PeerOwner, ResolutionOwner, ControlOwner, RekeyOwner):
    def __init__(self, journal, context, observer, opening_snapshot):
        self._journal, self._context, self._observer = journal, context, observer
        self._lock = threading.RLock()
        self._authority_generation = 0
        try:
            # The owning factory already recovered/authenticated this image and,
            # for required stores, checked its exact live witness head. Transfer
            # that opening result directly; it is neither cached for later work
            # nor an output permit. Every operation still performs its own reads
            # and current-authority/release checks in _state.
            state = decode(opening_snapshot.payload, context)
            try:
                admit_snapshot(journal, state)
            finally:
                state.close()
        except BaseException:
            journal.close()
            raise

    @staticmethod
    def _scope(context, scope):
        require(context.current_peer is None and context.current_local is None, "derived session authority is not a creation/opening input")
        require(scope.owner == owner_binding(context) and scope.context == context.digest,
                "independent session scope")

    @staticmethod
    def _validator(context):
        def validate(payload):
            state = decode(payload, context)
            state.close()
        return validate

    @classmethod
    def create(cls, path, scope: Scope, key: bytes, context, signer, now: int, observer=None):
        require(context.witness is None, "required witness needs the witnessed session owner")
        cls._scope(context, scope)
        state = State(Initiator(context, signer, now))
        try:
            journal, snapshot = LocalSessionJournal._create(path, scope, key, encode(state), cls._validator(context), observer)
            return cls(journal, context, observer, snapshot)
        finally:
            state.close()

    @classmethod
    def open(cls, path, scope: Scope, key: bytes, context, *, creation=False, observer=None):
        require(context.witness is None, "required witness needs the witnessed session owner")
        cls._scope(context, scope)
        journal, snapshot = LocalSessionJournal._open(path, scope, key, cls._validator(context), creation=creation, observer=observer)
        return cls(journal, context, observer, snapshot)

    @contextmanager
    def _state(self, *, operational=True, now=None, peer_maintenance=False):
        snapshot = self._journal.read()
        state = decode(snapshot.payload, self._context)
        try:
            admit_snapshot(self._journal, state)
            authority = local_binding(state, self._context)
            if self._context.witness is not None:
                self._journal.admit(snapshot, operational, authority)
            if operational and now is not None:
                admit_local(state, self._context, now)
            if operational and now is not None and not peer_maintenance and state.peer_authority is not None:
                state.peer_authority.check(now)
            yield snapshot, state
            authority_generation = self._authority_generation
            if operational and now is not None and state.format_version in (5, 6, 7, 8):
                # A reentrant host observer may have committed revocation after
                # this call's own write. Recheck the durable current authority
                # before its result escapes; the earlier decoded view is stale.
                current = self._journal.read()
                fresh = decode(current.payload, self._context)
                try:
                    admit_snapshot(self._journal, fresh)
                    admit_local(fresh, self._context, now)
                    authority = local_binding(fresh, self._context)
                    if not peer_maintenance and fresh.peer_authority is not None:
                        fresh.peer_authority.check(now)
                finally:
                    fresh.close()
            if self._context.witness is not None:
                self._journal.release(operational, authority)
            if operational:
                require(self._authority_generation == authority_generation,
                        "peer authority changed during output admission")
        finally:
            state.close()

    def _admit_bootstrap(self, now):
        # Bootstrap outboxes retain the native contract's advertisement gate,
        # even after confirmation. Established traffic has its separate gate.
        self._context.check(now)

    def _observe(self, stage):
        if self._observer is not None:
            try:
                self._observer(stage)
            except BaseException:
                self._journal.close()
                raise
            # A diagnostic/cancellation observer may close this owner without
            # raising. A committed result still needs a live owner to release.
            self._journal._admit()

    @locked
    def initial(self, now: int) -> bytes:
        with self._state(now=now) as (_snapshot, state):
            self._admit_bootstrap(now)
            return state.operation._initial

    @locked
    def finish(self, reply: bytes, now: int) -> bytes:
        with self._state(now=now) as (snapshot, state):
            self._admit_bootstrap(now)
            if state.operation._reply is not None:
                require(reply == state.operation._reply, "conflicting successful reply")
                require(state.operation._final is not None, "missing final outbox")
                return state.operation._final
            final = state.operation.finish(reply, now)
            self._journal.update(snapshot.digest, encode(state))
            self._admit_bootstrap(now)
            self._observe("protocol:final-committed")
            return final

    @locked
    def activate(self, now: int) -> bytes:
        with self._state(now=now) as (snapshot, state):
            if state.traffic is None:
                self._context.check_established(now)
            else:
                state.traffic.admit(now)
            if state.traffic is None:
                state.traffic = EpochState.initial(state.operation.activate_volatile_traffic(now))
                self._journal.update(snapshot.digest, encode(state))
            return state.operation.session_id()

    @locked
    def connection_identity(self, now: int) -> bytes:
        """Current local traffic identity; this alone is not peer confirmation.

        Unlike activate(), it cannot create traffic from a pending handshake.
        The original registration separately retains authenticated READY evidence.
        """
        with self._state(now=now) as (_snapshot, state):
            require(state.traffic is not None, 'original traffic state is not active')
            state.traffic.admit(now)
            return state.operation.session_id()

    @locked
    def next_id(self, now: int) -> bytes:
        with self._state(now=now) as (_snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            return state.traffic.next_id(now)

    def _complete_send(self, snapshot, state, now):
        require(state.traffic is not None and state.pending is not None, "missing original send reservation")
        plan = state.pending
        wire = state.traffic.send(plan.identity, plan.plaintext, plan.ad, now)
        state.pending = None
        self._journal.update(snapshot.digest, encode(state))
        state.traffic.admit(now)
        self._observe("protocol:send-committed")
        return wire

    @locked
    def send(self, identity: bytes, plaintext: bytes, ad: bytes, now: int) -> bytes:
        with self._state(now=now) as (snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            plan = SendPlan(identity, plaintext, ad)
            if state.pending is None:
                wire = state.traffic.validate_send(identity, plaintext, ad, now)
                if wire is not None:
                    return wire
                # A committed outgoing row adds index+receipt+wire length+frame.
                # Reserve space for that final state before persisting plaintext.
                limit = MAX_LOCAL_STATE if state.format_version == 8 else MAX_STATE
                require(len(snapshot.payload) + 8 + 32 + 4 + 109 + len(plaintext) <= limit,
                        "final send image capacity")
                state.pending = plan
                snapshot = self._journal.update(snapshot.digest, encode(state))
                self._observe("protocol:send-reserved")
            else:
                require(state.pending == plan, "conflicting reserved send")
            return self._complete_send(snapshot, state, now)

    @locked
    def resume(self, identity: bytes, now: int) -> bytes:
        with self._state(now=now) as (snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            state.traffic.admit(now)
            if state.pending is not None:
                require(state.pending.identity == identity, "different reserved operation")
                return self._complete_send(snapshot, state, now)
            return state.traffic.resume(identity, now)

    @locked
    def receive(self, wire: bytes, ad: bytes, now: int) -> tuple[bytes, bytes]:
        with self._state(now=now) as (snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            # A reserved send remains pinned. Other mutations cannot use its
            # reserved final-image capacity before that operation completes.
            require(state.pending is None, "original send must finish before receive")
            result = state.traffic.receive(wire, ad, now)
            payload = encode(state)
            if payload != snapshot.payload:
                self._journal.update(snapshot.digest, payload)
            state.traffic.admit(now)
            self._observe("protocol:receive-committed")
            return result

    @locked
    def consume(self, identity: bytes, now: int) -> bytes:
        with self._state(now=now) as (snapshot, state):
            require(state.traffic is not None and state.pending is None, "traffic absent or send reserved")
            acknowledgement = state.traffic.consume(identity, now)
            payload = encode(state)
            if payload != snapshot.payload:
                self._journal.update(snapshot.digest, payload)
            state.traffic.admit(now)
            self._observe("protocol:consumption-committed")
            return acknowledgement

    @locked
    def acknowledgement(self, now: int) -> bytes:
        with self._state(now=now) as (_snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            return state.traffic.acknowledgement(now)

    @locked
    def acknowledgement_for_epoch(self, epoch: int, now: int) -> bytes:
        with self._state(now=now) as (_snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            return state.traffic.acknowledgement(now, epoch)

    @locked
    def storage_format(self) -> int:
        """Read-only upgrade disposition; it grants no protocol permission."""
        with self._state(operational=False) as (_snapshot, state):
            return state.format_version

    @locked
    def upgrade_format(self, now: int) -> int:
        """Explicit metadata-only migration; never releases retained peer traffic."""
        with self._state(now=now, peer_maintenance=True) as (snapshot, state):
            if state.traffic is None:
                self._admit_bootstrap(now)
            else:
                admit_local(state, self._context, now)
            if state.format_version < 5:
                state.format_version = 5
                self._journal.update(snapshot.digest, encode(state))
                self._observe("protocol:format-upgraded")
            return state.format_version

    @locked
    def accept_acknowledgement(self, wire: bytes, now: int) -> int:
        with self._state(now=now) as (snapshot, state):
            require(state.traffic is not None and state.pending is None, "traffic absent or send reserved")
            floor = state.traffic.accept_acknowledgement(wire, now)
            payload = encode(state)
            if payload != snapshot.payload:
                self._journal.update(snapshot.digest, payload)
            state.traffic.admit(now)
            return floor

    @locked
    def status(self, identity: bytes | None = None) -> str:
        """Read-only dispositions can survive expiry; no private/output bytes."""
        with self._state(operational=False) as (_snapshot, state):
            if identity is None:
                return "Traffic" if state.traffic is not None else ("Confirmed" if state.operation._reply is not None else "Waiting")
            require(state.traffic is not None, "traffic not activated")
            require(len(identity) == 32, "message ID length")
            epoch, index = int.from_bytes(identity[:8], "big"), int.from_bytes(identity[8:16], "big")
            require(identity == message_id(state.traffic.session, 1, index, epoch), "message ID scope")
            if epoch < min(state.traffic.epochs):
                return "Retired"
            traffic = state.traffic.for_id(identity, 1, metadata=True)
            if index < traffic._send_floor:
                return "Acknowledged"
            resolution = state.traffic.resolutions.get(epoch)
            if index < traffic._sent and resolution is not None:
                return "ResolutionPending" if resolution.phase == 1 else "DeliveryUnknown"
            if index in traffic._outbox:
                return "Committed"
            if state.pending is not None and identity == state.pending.identity:
                return "Reserved"
            return "Absent"

    @locked
    def close(self):
        self._journal.close()
