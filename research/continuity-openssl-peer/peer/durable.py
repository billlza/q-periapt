"""Owned independent bootstrap/epoch-zero session over the exact-target store."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

from contextlib import contextmanager
import threading

from .bootstrap import Initiator
from .journal import Journal, Scope, MAX_STATE, locked
from .state_codec import State, SendPlan, encode, decode
from .wire import ldh, require


def owner_binding(context) -> bytes:
    return ldh(b"Q-PERIAPT-INDEPENDENT-OWNER/v1", context.initiator.raw)


class Session:
    def __init__(self, journal, context, observer):
        self._journal, self._context, self._observer = journal, context, observer
        self._lock = threading.RLock()

    @staticmethod
    def _scope(context, scope):
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
        cls._scope(context, scope)
        state = State(Initiator(context, signer, now))
        try:
            journal = Journal.create(path, scope, key, encode(state), cls._validator(context), observer)
            return cls(journal, context, observer)
        finally:
            state.close()

    @classmethod
    def open(cls, path, scope: Scope, key: bytes, context, *, creation=False, observer=None):
        cls._scope(context, scope)
        journal = Journal.open(path, scope, key, cls._validator(context), creation=creation, observer=observer)
        return cls(journal, context, observer)

    @contextmanager
    def _state(self):
        snapshot = self._journal.read()
        state = decode(snapshot.payload, self._context)
        try:
            yield snapshot, state
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

    @locked
    def initial(self, now: int) -> bytes:
        with self._state() as (_snapshot, state):
            self._admit_bootstrap(now)
            return state.operation._initial

    @locked
    def finish(self, reply: bytes, now: int) -> bytes:
        with self._state() as (snapshot, state):
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
        with self._state() as (snapshot, state):
            self._context.check_established(now)
            if state.traffic is None:
                state.traffic = state.operation.activate_volatile_traffic(now)
                self._journal.update(snapshot.digest, encode(state))
            return state.operation.session_id()

    @locked
    def next_id(self, now: int) -> bytes:
        with self._state() as (_snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            return state.traffic.next_id(now)

    def _complete_send(self, snapshot, state, now):
        require(state.traffic is not None and state.pending is not None, "missing original send reservation")
        plan = state.pending
        wire = state.traffic.send(plan.identity, plan.plaintext, plan.ad, now)
        state.pending = None
        self._journal.update(snapshot.digest, encode(state))
        self._context.check_established(now)
        self._observe("protocol:send-committed")
        return wire

    @locked
    def send(self, identity: bytes, plaintext: bytes, ad: bytes, now: int) -> bytes:
        with self._state() as (snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            plan = SendPlan(identity, plaintext, ad)
            if state.pending is None:
                wire = state.traffic.validate_send(identity, plaintext, ad, now)
                if wire is not None:
                    return wire
                # A committed outgoing row adds index+receipt+wire length+frame.
                # Reserve space for that final state before persisting plaintext.
                require(len(snapshot.payload) + 8 + 32 + 4 + 109 + len(plaintext) <= MAX_STATE,
                        "final send image capacity")
                state.pending = plan
                snapshot = self._journal.update(snapshot.digest, encode(state))
                self._observe("protocol:send-reserved")
            else:
                require(state.pending == plan, "conflicting reserved send")
            return self._complete_send(snapshot, state, now)

    @locked
    def resume(self, identity: bytes, now: int) -> bytes:
        with self._state() as (snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            state.traffic._admit(now)
            if state.pending is not None:
                require(state.pending.identity == identity, "different reserved operation")
                return self._complete_send(snapshot, state, now)
            index = state.traffic._index(identity, 1)
            require(index >= state.traffic._send_floor, "retired send")
            require(index in state.traffic._outbox, "send operation absent")
            return state.traffic._outbox[index][1]

    @locked
    def receive(self, wire: bytes, ad: bytes, now: int) -> tuple[bytes, bytes]:
        with self._state() as (snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            # A reserved send remains pinned. Other mutations cannot use its
            # reserved final-image capacity before that operation completes.
            require(state.pending is None, "original send must finish before receive")
            result = state.traffic.receive(wire, ad, now)
            payload = encode(state)
            if payload != snapshot.payload:
                self._journal.update(snapshot.digest, payload)
            self._context.check_established(now)
            self._observe("protocol:receive-committed")
            return result

    @locked
    def consume(self, identity: bytes, now: int) -> bytes:
        with self._state() as (snapshot, state):
            require(state.traffic is not None and state.pending is None, "traffic absent or send reserved")
            acknowledgement = state.traffic.consume(identity, now)
            payload = encode(state)
            if payload != snapshot.payload:
                self._journal.update(snapshot.digest, payload)
            self._context.check_established(now)
            self._observe("protocol:consumption-committed")
            return acknowledgement

    @locked
    def acknowledgement(self, now: int) -> bytes:
        with self._state() as (_snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            return state.traffic.acknowledgement(now)

    @locked
    def accept_acknowledgement(self, wire: bytes, now: int) -> int:
        with self._state() as (snapshot, state):
            require(state.traffic is not None and state.pending is None, "traffic absent or send reserved")
            floor = state.traffic.accept_acknowledgement(wire, now)
            payload = encode(state)
            if payload != snapshot.payload:
                self._journal.update(snapshot.digest, payload)
            self._context.check_established(now)
            return floor

    @locked
    def status(self, identity: bytes | None = None) -> str:
        """Read-only dispositions can survive expiry; no private/output bytes."""
        with self._state() as (_snapshot, state):
            if identity is None:
                return "Traffic" if state.traffic is not None else ("Confirmed" if state.operation._reply is not None else "Waiting")
            require(state.traffic is not None, "traffic not activated")
            index = state.traffic._index(identity, 1)
            if index < state.traffic._send_floor:
                return "Acknowledged"
            if index in state.traffic._outbox:
                return "Committed"
            if state.pending is not None and identity == state.pending.identity:
                return "Reserved"
            return "Absent"

    @locked
    def close(self):
        self._journal.close()
