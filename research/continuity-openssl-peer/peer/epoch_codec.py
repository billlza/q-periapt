"""Bounded version-two epoch inventory and exact control reservations."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .epoch_state import EpochState, RekeyPlan
from .epoch_validation import validate
from .journal import MAX_STATE
from .snapshot_fields import blob, read_blob, encode_pending, decode_pending
from .traffic_codec import encode_traffic, decode_traffic
from .wire import require

FIELDS = (("seed", 96), ("offer", 4746), ("response", 4714), ("final", 3634), ("body", 1337), ("root", 32))


def encode_epochs(owner, pending):
    validate(owner, pending)
    result = bytearray(owner.root)
    for value in (owner.confirmed, owner.sending, owner.receiving):
        result.extend(value.to_bytes(8, "big"))
    result.extend(owner.predecessor + bytes([owner.last is not None]))
    if owner.last is not None:
        for wire, size in zip(owner.last, (4746, 4714, 3634, 3666), strict=True):
            result.extend(blob(wire, size))
    result.append(owner.plan.phase if owner.plan else 0)
    if owner.plan is not None:
        for name, cap in FIELDS:
            result.extend(blob(getattr(owner.plan, name), cap))
    traffic = bytearray([len(owner.epochs)])
    for value in owner.epochs.values():
        traffic.extend(encode_traffic(value))
    if pending is not None:
        # The eventual outbox can exceed a short-AD reservation. Admission must
        # reserve that final row too, before committing an input that pins writes.
        final_size = len(traffic) + 1 + 8 + 32 + 4 + 109 + len(pending.plaintext)
        require(final_size <= MAX_STATE - 65536, "reserved final traffic capacity")
    traffic.extend(encode_pending(pending))
    # Bootstrap, public history, the largest control plan and a fresh empty epoch
    # fit in 64 KiB. Message growth cannot consume this cutover headroom.
    require(len(traffic) <= MAX_STATE - 65536, "traffic capacity reserves control completion")
    return bytes(result + traffic)


def decode_epochs(reader, context, session):
    owner = EpochState()
    owner.context, owner.session, owner.root = context, session, reader.take(32)
    owner.confirmed, owner.sending, owner.receiving = (reader.integer(8) for _ in range(3))
    owner.predecessor = reader.take(32)
    last = reader.integer(1)
    require(last in (0, 1), "completed history flag")
    owner.last = tuple(read_blob(reader, cap) for cap in (4746, 4714, 3634, 3666)) if last else None
    phase = reader.integer(1)
    require(0 <= phase <= 7, "unknown rekey phase")
    owner.plan = RekeyPlan(phase, **{name: read_blob(reader, cap) for name, cap in FIELDS}) if phase else None
    count = reader.integer(1)
    require(1 <= count <= 4, "retained epoch capacity")
    owner.epochs = {}
    previous = -1
    for _ in range(count):
        traffic = decode_traffic(reader, context, session)
        require(traffic._epoch > previous, "epoch order")
        previous = traffic._epoch
        owner.epochs[traffic._epoch] = traffic
    pending = decode_pending(reader)
    validate(owner, pending)
    return owner, pending
