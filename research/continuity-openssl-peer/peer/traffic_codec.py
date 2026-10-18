"""Private traffic records, with explicit old-format epoch-zero support."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .traffic import VolatileTraffic, message_id
from .snapshot_fields import blob, read_blob, indices
from .wire import MAX_U64, require


def encode_traffic(value, *, legacy_root=None):
    require(not value._closed, "closed traffic snapshot")
    result = bytearray()
    if legacy_root is not None:
        require(value._epoch == 0 and not value._send_closed and value._receive_limit is None,
                "legacy epoch format")
        result.extend(legacy_root)
    else:
        result.extend(value._epoch.to_bytes(8, "big"))
        result.extend(bytes([value._send_closed, value._receive_limit is not None]))
        if value._receive_limit is not None:
            result.extend(value._receive_limit.to_bytes(8, "big"))
    for key in (value._send, value._receive, value._send_ack, value._receive_ack):
        require(len(key) == 32, "snapshot key length")
        result.extend(key)
    for counter in (value._sent, value._received, value._send_floor, value._receive_floor):
        result.extend(counter.to_bytes(8, "big"))
    result.extend(len(value._outbox).to_bytes(2, "big"))
    for index, (receipt, wire) in sorted(value._outbox.items()):
        result.extend(index.to_bytes(8, "big") + receipt + blob(wire, 16493))
    result.extend(len(value._inbox).to_bytes(2, "big"))
    for index, (receipt, plaintext) in sorted(value._inbox.items()):
        result.extend(index.to_bytes(8, "big") + receipt + bytes([plaintext is None]))
        if plaintext is not None:
            result.extend(blob(plaintext, 16384))
    result.extend(len(value._skipped).to_bytes(2, "big"))
    for index, key in sorted(value._skipped.items()):
        result.extend(index.to_bytes(8, "big") + key)
    return bytes(result)


def decode_traffic(reader, context, session, *, legacy=False):
    value = VolatileTraffic.__new__(VolatileTraffic)
    value._context, value._session, value._closed = context, session, False
    value._epoch, value._send_closed, value._receive_limit = 0, False, None
    value._rekey = reader.take(32) if legacy else b""
    if not legacy:
        value._epoch = reader.integer(8)
        closed, limited = reader.integer(1), reader.integer(1)
        require(value._epoch < MAX_U64 and closed in (0, 1) and limited in (0, 1), "epoch flags")
        value._send_closed = bool(closed)
        value._receive_limit = reader.integer(8) if limited else None
    value._send, value._receive, value._send_ack, value._receive_ack = (reader.take(32) for _ in range(4))
    value._sent, value._received, value._send_floor, value._receive_floor = (reader.integer(8) for _ in range(4))
    require(0 <= value._send_floor <= value._sent <= context.send_budget
            and 0 <= value._receive_floor <= value._received <= context.send_budget,
            "snapshot counters/budget")
    require(not value._send_closed or value._send == bytes(32), "closed sending chain retained")
    if value._receive_limit is not None:
        require(value._receive_limit <= context.send_budget, "receive close budget")
        require(value._received < value._receive_limit or value._receive == bytes(32), "closed receiving chain retained")
    value._outbox, value._inbox, value._skipped = {}, {}, {}
    for index in indices(reader, 64):
        receipt, wire = reader.take(32), read_blob(reader, 16493)
        require(len(wire) >= 109 and wire[:41] == b"QPCMSG03" + session + b"\1"
                and int.from_bytes(wire[41:49], "big") == value._epoch
                and int.from_bytes(wire[49:57], "big") == index
                and wire[57:89] == message_id(session, 1, index, value._epoch)
                and int.from_bytes(wire[89:93], "big") == len(wire) - 109, "snapshot outgoing scope")
        value._outbox[index] = (receipt, wire)
    for index in indices(reader, 64):
        receipt, consumed = reader.take(32), reader.integer(1)
        require(consumed in (0, 1), "snapshot consumption flag")
        value._inbox[index] = (receipt, None if consumed else read_blob(reader, 16384))
    for index in indices(reader, 128):
        value._skipped[index] = reader.take(32)
    require(value._sent - value._send_floor == len(value._outbox)
            and list(value._outbox) == list(range(value._send_floor, value._sent)), "snapshot outgoing coverage")
    incoming = set(value._inbox) | set(value._skipped)
    require(not (set(value._inbox) & set(value._skipped))
            and value._received - value._receive_floor == len(incoming)
            and sorted(incoming) == list(range(value._receive_floor, value._received)), "snapshot incoming coverage")
    require(value._receive_floor not in value._inbox or value._inbox[value._receive_floor][1] is not None,
            "snapshot unadvanced consumption floor")
    return value
