"""Canonical authenticated-local snapshots, never a network import capability."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

from dataclasses import dataclass
import hmac

from .authority import Context
from .bootstrap import Initiator, digest, mac
from .journal import MAX_STATE
from .kem import HybridPrivate
from .traffic import VolatileTraffic, message_id
from .wire import MAX_U64, Reader, require


@dataclass(frozen=True, repr=False)
class SendPlan:
    identity: bytes
    plaintext: bytes
    ad: bytes


@dataclass(repr=False)
class State:
    operation: Initiator
    traffic: VolatileTraffic | None = None
    pending: SendPlan | None = None

    def close(self):
        self.operation.close()
        if self.traffic is not None:
            self.traffic.close()
        self.pending = None


def blob(value: bytes, cap: int) -> bytes:
    require(type(value) is bytes and len(value) <= cap, "snapshot field capacity")
    return len(value).to_bytes(4, "big") + value


def read_blob(reader: Reader, cap: int) -> bytes:
    size = reader.integer(4)
    require(size <= cap, "snapshot field capacity")
    return reader.take(size)


def encode(state: State) -> bytes:
    op = state.operation
    require(not op._closed, "closed snapshot owner")
    phase = 3 if state.traffic is not None else (2 if op._reply is not None else 1)
    result = bytearray(b"QPREFS01" + op._context.digest + bytes([phase]))
    result.extend(op._initial)
    if phase == 1:
        require(op._reply_key is not None and op._first_secret is not None and state.pending is None,
                "waiting snapshot state")
        result.extend(op._reply_key._checkpoint() + op._first_secret)
    else:
        require(op._reply is not None and op._final is not None and op._session_id is not None,
                "completed snapshot state")
        result.extend(op._reply + op._final + op._session_id)
        if phase == 2:
            require(op._root is not None and state.pending is None, "pending confirmed root")
            result.extend(op._root)
        else:
            require(op._root is None and state.traffic is not None, "root transfer marker")
            traffic = state.traffic
            require(not traffic._closed, "closed traffic snapshot")
            require(traffic._epoch == 0, "snapshot does not yet support rekey epochs")
            for key in (traffic._rekey, traffic._send, traffic._receive, traffic._send_ack, traffic._receive_ack):
                require(len(key) == 32, "snapshot key length")
                result.extend(key)
            for counter in (traffic._sent, traffic._received, traffic._send_floor, traffic._receive_floor):
                result.extend(counter.to_bytes(8, "big"))
            result.extend(len(traffic._outbox).to_bytes(2, "big"))
            for index, (receipt, wire) in sorted(traffic._outbox.items()):
                result.extend(index.to_bytes(8, "big") + receipt + blob(wire, 16493))
            result.extend(len(traffic._inbox).to_bytes(2, "big"))
            for index, (receipt, plaintext) in sorted(traffic._inbox.items()):
                result.extend(index.to_bytes(8, "big") + receipt + bytes([plaintext is None]))
                if plaintext is not None:
                    result.extend(blob(plaintext, 16384))
            result.extend(len(traffic._skipped).to_bytes(2, "big"))
            for index, key in sorted(traffic._skipped.items()):
                result.extend(index.to_bytes(8, "big") + key)
            result.append(int(state.pending is not None))
            if state.pending is not None:
                plan = state.pending
                result.extend(plan.identity + blob(plan.plaintext, 16384) + blob(plan.ad, 1024))
    require(len(result) <= MAX_STATE, "snapshot aggregate capacity")
    return bytes(result)


def _indices(reader: Reader, cap: int):
    count = reader.integer(2)
    require(count <= cap, "snapshot record count")
    previous = -1
    for _ in range(count):
        index = reader.integer(8)
        require(previous < index < MAX_U64, "snapshot record order")
        previous = index
        yield index


def _traffic(reader: Reader, context: Context, session: bytes) -> tuple[VolatileTraffic, SendPlan | None]:
    value = VolatileTraffic.__new__(VolatileTraffic)
    value._context, value._session, value._closed = context, session, False
    value._epoch = 0
    value._rekey, value._send, value._receive, value._send_ack, value._receive_ack = (reader.take(32) for _ in range(5))
    value._sent, value._received, value._send_floor, value._receive_floor = (reader.integer(8) for _ in range(4))
    require(0 <= value._send_floor <= value._sent < MAX_U64
            and 0 <= value._receive_floor <= value._received < MAX_U64
            and value._sent <= context.send_budget, "snapshot counters/budget")
    value._outbox, value._inbox, value._skipped = {}, {}, {}
    for index in _indices(reader, 64):
        receipt, wire = reader.take(32), read_blob(reader, 16493)
        require(len(wire) >= 109 and wire[:41] == b"QPCMSG03" + session + b"\1"
                and wire[41:49] == bytes(8) and int.from_bytes(wire[49:57], "big") == index
                and wire[57:89] == message_id(session, 1, index)
                and int.from_bytes(wire[89:93], "big") == len(wire) - 109,
                "snapshot outgoing scope")
        value._outbox[index] = (receipt, wire)
    for index in _indices(reader, 64):
        receipt, consumed = reader.take(32), reader.integer(1)
        require(consumed in (0, 1), "snapshot consumption flag")
        value._inbox[index] = (receipt, None if consumed else read_blob(reader, 16384))
    for index in _indices(reader, 128):
        value._skipped[index] = reader.take(32)
    require(value._sent - value._send_floor == len(value._outbox)
            and list(value._outbox) == list(range(value._send_floor, value._sent)), "snapshot outgoing coverage")
    incoming = set(value._inbox) | set(value._skipped)
    require(not (set(value._inbox) & set(value._skipped))
            and value._received - value._receive_floor == len(incoming)
            and sorted(incoming) == list(range(value._receive_floor, value._received)),
            "snapshot incoming coverage")
    require(value._receive_floor not in value._inbox or value._inbox[value._receive_floor][1] is not None,
            "snapshot unadvanced consumption floor")
    present = reader.integer(1)
    require(present in (0, 1), "snapshot pending flag")
    pending = None
    if present:
        pending = SendPlan(reader.take(32), read_blob(reader, 16384), read_blob(reader, 1024))
        require(pending.identity == message_id(session, 1, value._sent)
                and value._sent < context.send_budget and len(value._outbox) < 64,
                "snapshot pending send slot")
    return value, pending


def decode(payload: bytes, context: Context) -> State:
    require(len(payload) <= MAX_STATE, "snapshot aggregate capacity")
    reader = Reader(payload)
    require(reader.take(8) == b"QPREFS01" and reader.take(32) == context.digest, "snapshot schema/context")
    phase = reader.integer(1)
    require(phase in (1, 2, 3), "snapshot phase")
    op = Initiator.__new__(Initiator)
    op._context, op._closed = context, False
    op._initial = reader.take(5817)
    body = context.initiator.open(op._initial, 5, 2440)
    require(body[:40] == b"QPBSI001" + context.digest, "snapshot initial scope")
    op._reply_key = op._first_secret = op._reply = op._final = op._session_id = op._root = None
    state = State(op)
    try:
        if phase == 1:
            op._reply_key = HybridPrivate._restore(reader.take(96))
            op._first_secret = reader.take(32)
            require(body[72:1288] == op._reply_key.public(), "snapshot reply-key binding")
            t0 = digest(b"initial-core", body[:-32])
            confirmation = context.sdk.initial_confirmation(op._first_secret, t0)
            require(hmac.compare_digest(mac(confirmation, t0), body[-32:]), "snapshot initial confirmation")
        else:
            op._reply, op._final, op._session_id = reader.take(4633), reader.take(136), reader.take(32)
            reply = context.responder.open(op._reply, 6, 1256)
            h0, h1 = digest(b"initial-wire", op._initial), digest(b"reply-wire", op._reply)
            require(reply[:72] == b"QPBSR001" + context.digest + h0
                    and op._final[:104] == b"QPBSF001" + context.digest + h0 + h1
                    and op._session_id == digest(b"session-id", op._final[:104]), "snapshot completed transcript")
            if phase == 2:
                op._root = reader.take(32)
            else:
                state.traffic, state.pending = _traffic(reader, context, op._session_id)
        reader.finish()
        require(encode(state) == payload, "noncanonical snapshot")
        return state
    except BaseException:
        state.close()
        raise
