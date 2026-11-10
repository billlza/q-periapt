"""Real Rust journal interoperability; Python traffic remains explicitly volatile."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from qperiapt_continuity_reference.bootstrap import Initiator
from qperiapt_continuity_reference.traffic import message_id
from qperiapt_continuity_reference.wire import require


def application(ad: bytes, payload: bytes) -> bytes:
    return len(ad).to_bytes(2, "big") + ad + payload


def exercise(context, signer, counterpart, output, refused):
    initiator = Initiator(context, signer, 150)
    initial = initiator.initial(150)
    reply = counterpart.command("durable-initial", 4, initial, 1)
    counterpart.command("durable-activation-before-final", 6, b"", 2, b"Suspended")
    counterpart.command("durable-reopen-reply", 12, b"", 1, b"reopened")
    require(counterpart.command("durable-initial-replay", 4, initial, 1) == reply,
            "durable reply changed after reopening")
    final = initiator.finish(reply, 150)
    session = counterpart.command("durable-final", 5, final, 1)
    require(session == initiator.session_id(), "durable session identity")
    counterpart.command("durable-reopen-complete", 12, b"", 1, b"reopened")
    require(counterpart.command("durable-activate", 6, b"", 1) == session,
            "durable root activation identity")
    refused("advertisement-expiry-blocks-bootstrap", lambda: context.check(170))
    traffic = initiator.activate_volatile_traffic(170)
    refused("root-transfer-only-once", lambda: initiator.activate_volatile_traffic(170))
    next_id = traffic.next_id(170)
    refused("plaintext-over-capacity", lambda: traffic.send(next_id, bytes(16385), b"", 170))
    refused("send-AD-over-capacity", lambda: traffic.send(next_id, b"", bytes(1025), 170))
    require(traffic.next_id(170) == next_id, "rejected oversized input consumed a send slot")
    plaintexts = [b"", b"independent application message", bytes(range(256)) * 64]
    ads = [b"empty", b"application context", bytes(range(256)) * 4]
    outgoing = []
    for index, (plaintext, ad) in enumerate(zip(plaintexts, ads)):
        identity = traffic.next_id(170)
        wire = traffic.send(identity, plaintext, ad, 170)
        require(traffic.send(identity, plaintext, ad, 170) == wire, "independent exact send replay")
        outgoing.append((identity, wire))
    refused("send-input-conflict", lambda: traffic.send(outgoing[1][0], b"changed", ads[1], 170))
    # Deliver the final slot first. Wrong AD must not consume Rust's skipped keys.
    counterpart.command("durable-wrong-AD", 7, application(b"wrong", outgoing[2][1]), 2,
                        b"Protocol(Authentication)")
    for label in ("last", "duplicate"):
        require(counterpart.command("durable-receive-" + label,
                7, application(ads[2], outgoing[2][1]), 1) == plaintexts[2], "Rust plaintext differs")
    zero_ack = counterpart.command("durable-consume-last", 10, outgoing[2][0], 1)
    require(traffic.accept_acknowledgement(zero_ack, 170) == 0, "out-of-order consumption skipped gap")
    counterpart.command("durable-reopen-skipped", 12, b"", 1, b"reopened")
    for index in (0, 1):
        require(counterpart.command("durable-receive-" + str(index), 7,
            application(ads[index], outgoing[index][1]), 1) == plaintexts[index], "reopened skipped key differs")
    first_ack = counterpart.command("durable-consume-first", 10, outgoing[0][0], 1)
    require(traffic.accept_acknowledgement(first_ack, 170) == 1, "first consumed prefix")
    full_ack = counterpart.command("durable-consume-middle", 10, outgoing[1][0], 1)
    refused("invalid-ACK-MAC", lambda: traffic.accept_acknowledgement(full_ack[:-1] + bytes([full_ack[-1] ^ 1]), 170))
    require(traffic.accept_acknowledgement(full_ack, 170) == 3, "full consumed prefix")
    require(traffic.accept_acknowledgement(first_ack, 170) == 3, "stale authenticated ACK regressed floor")
    refused("retired-send-ID", lambda: traffic.send(outgoing[0][0], plaintexts[0], ads[0], 170))
    counterpart.command("durable-retired-receive", 7, application(ads[2], outgoing[2][1]), 2,
                        b"Protocol(Retired)")
    incoming = []
    for index, (plaintext, ad) in enumerate(zip(plaintexts, ads)):
        identity = counterpart.command("durable-next-" + str(index), 8, b"", 1)
        wire = counterpart.command("durable-send-" + str(index), 9,
                                   identity + application(ad, plaintext), 1)
        incoming.append((identity, wire))
    counterpart.command("durable-reopen-outbox", 12, b"", 1, b"reopened")
    require(counterpart.command("durable-send-replay", 9,
            incoming[2][0] + application(ads[2], plaintexts[2]), 1) == incoming[2][1],
            "Rust reopened outbox differs")
    wire = incoming[2][1]
    excessive_gap = wire[:49] + (129).to_bytes(8, "big") + message_id(session, 2, 129) + wire[89:]
    refused("receive-skipped-key-capacity", lambda: traffic.receive(excessive_gap, ads[2], 170),
            "skipped-key capacity")
    refused("receive-AD-over-capacity", lambda: traffic.receive(wire, bytes(1025), 170))
    refused("receive-wrong-direction", lambda: traffic.receive(outgoing[2][1], ads[2], 170))
    refused("receive-wrong-AD", lambda: traffic.receive(wire, b"wrong", 170))
    refused("receive-invalid-tag", lambda: traffic.receive(wire[:-1] + bytes([wire[-1] ^ 1]), ads[2], 170))
    refused("receive-future-epoch", lambda: traffic.receive(wire[:41] + (1).to_bytes(8, "big") + wire[49:], ads[2], 170))
    for index in (2, 2, 0, 1):
        require(traffic.receive(incoming[index][1], ads[index], 170) == (incoming[index][0], plaintexts[index]),
                "independent plaintext or skipped key differs")
    zero = traffic.consume(incoming[2][0], 170)
    require(counterpart.command("durable-ACK-zero", 11, zero, 1) == bytes(8), "native zero ACK")
    first = traffic.consume(incoming[0][0], 170)
    complete = traffic.consume(incoming[1][0], 170)
    counterpart.command("durable-invalid-ACK", 11, complete[:-1] + bytes([complete[-1] ^ 1]), 2,
                        b"Protocol(Authentication)")
    require(counterpart.command("durable-ACK-complete", 11, complete, 1) == (3).to_bytes(8, "big"), "native full ACK")
    counterpart.command("durable-reopen-ACK", 12, b"", 1, b"reopened")
    require(counterpart.command("durable-ACK-stale", 11, first, 1) == (3).to_bytes(8, "big"), "native stale ACK")
    counterpart.command("durable-retired-send", 9, incoming[0][0] + application(ads[0], plaintexts[0]),
                        2, b"Protocol(Retired)")
    refused("retired-receive-ID", lambda: traffic.receive(incoming[2][1], ads[2], 170))
    refused("traffic-authority-expiry", lambda: traffic.next_id(200))
    for name, value in (("initial", initial), ("reply", reply), ("final", final), ("session", session)):
        (output / ("durable-bootstrap-" + name)).write_bytes(value)
    traffic.close()
    traffic.close()
    refused("closed-traffic", lambda: traffic.next_id(170))
    initiator.close()
    return {"scope": "Independent volatile epoch-zero traffic versus real Rust journal; independent persistence remains unimplemented",
            "directions": 2, "fresh_messages_per_direction": 3, "plaintext_sizes": [len(p) for p in plaintexts],
            "associated_data_sizes": [len(a) for a in ads], "native_journal_reopens": 5,
            "traffic_after_advertisement_expiry": True, "contiguous_consumption_prefix": 3,
            "actual_process_restart": False}
