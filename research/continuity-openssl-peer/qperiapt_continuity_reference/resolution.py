"""Private closed-epoch commitments and explicit application outcome reports."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hmac

from .traffic import DOMAIN, message_id
from .wire import ldh, require


@dataclass(repr=False)
class Resolution:
    phase: int
    identity: bytes
    key: bytes = b""


@dataclass(frozen=True, repr=False)
class ResolutionReport:
    identity: bytes
    epoch: int
    acknowledged_before: int
    sent: int
    consumed_before: int
    received: int
    peer_sent: int
    outgoing: tuple
    incoming: tuple
    skipped: tuple

    def public_record(self):
        """Authorized application output; plaintext is not restored authenticity."""
        return {"id": self.identity.hex(), "epoch": self.epoch,
                "acknowledged_before": self.acknowledged_before, "sent": self.sent,
                "consumed_before": self.consumed_before, "received": self.received, "peer_sent": self.peer_sent,
                "outgoing": [{"id": identity.hex(), "ciphertext_digest": digest.hex()} for identity, digest in self.outgoing],
                "incoming": [{"id": identity.hex(), "index": index, "plaintext": plain.hex()} for identity, index, plain in self.incoming],
                "skipped": list(self.skipped)}


def ciphertext_digest(wire):
    return ldh(DOMAIN + b"resolution-ciphertext/v1", wire)


def resolution_id(traffic, key):
    require(len(key) == 32 and traffic._send_closed and traffic._receive_limit is not None,
            "closed resolution key/scope")
    mac = hmac.new(key, digestmod="sha256")
    mac.update(DOMAIN + b"closed-epoch-resolution/v1")
    mac.update(traffic._session + b"\1")
    for counter in (traffic._epoch, traffic._send_floor, traffic._sent, traffic._receive_floor,
                    traffic._received, traffic._receive_limit):
        mac.update(counter.to_bytes(8, "big"))
    mac.update(len(traffic._outbox).to_bytes(2, "big"))
    for index, (intent, wire) in sorted(traffic._outbox.items()):
        mac.update(message_id(traffic._session, 1, index, traffic._epoch))
        mac.update(intent + ciphertext_digest(wire))
    mac.update(len(traffic._inbox).to_bytes(2, "big"))
    for index, (intent, plaintext) in sorted(traffic._inbox.items()):
        plain = b"" if plaintext is None else plaintext
        mac.update(message_id(traffic._session, 2, index, traffic._epoch))
        mac.update(index.to_bytes(8, "big") + intent + bytes([plaintext is None]))
        mac.update(len(plain).to_bytes(4, "big"))
        mac.update(ldh(DOMAIN + b"resolution-plaintext/v1", plain))
    mac.update(len(traffic._skipped).to_bytes(2, "big"))
    for index in sorted(traffic._skipped):
        mac.update(index.to_bytes(8, "big"))
    return mac.digest()


def validate(traffic, resolution):
    require(resolution.phase in (1, 2) and len(resolution.identity) == 32 and any(resolution.identity),
            "resolution phase/identity")
    require(traffic._send_closed and traffic._receive_limit is not None, "resolution epoch still open")
    if resolution.phase == 1:
        require(hmac.compare_digest(resolution.identity, resolution_id(traffic, resolution.key)),
                "frozen resolution commitment")
    else:
        require(not resolution.key and not traffic._outbox and not traffic._inbox and not traffic._skipped
                and all(key == bytes(32) for key in (traffic._send, traffic._receive, traffic._send_ack, traffic._receive_ack)),
                "acknowledged resolution retained secret/data owners")


def report(traffic, resolution):
    require(resolution.phase == 1, "resolution report retired")
    validate(traffic, resolution)
    return ResolutionReport(resolution.identity, traffic._epoch, traffic._send_floor, traffic._sent,
        traffic._receive_floor, traffic._received, traffic._receive_limit,
        tuple((message_id(traffic._session, 1, i, traffic._epoch), ciphertext_digest(w))
              for i, (_intent, w) in sorted(traffic._outbox.items())),
        tuple((message_id(traffic._session, 2, i, traffic._epoch), i, plain)
              for i, (_intent, plain) in sorted(traffic._inbox.items()) if plain is not None),
        tuple(sorted(traffic._skipped)))


def encode_resolutions(resolutions):
    require(len(resolutions) <= 4, "resolution metadata capacity")
    result = bytearray([len(resolutions)])
    for epoch, resolution in sorted(resolutions.items()):
        result.extend(epoch.to_bytes(8, "big") + bytes([resolution.phase]) + resolution.identity)
        if resolution.phase == 1:
            result.extend(resolution.key)
    return bytes(result)


def decode_resolutions(reader):
    count = reader.integer(1)
    require(count <= 4, "resolution metadata capacity")
    result, previous = {}, -1
    for _ in range(count):
        epoch, phase, identity = reader.integer(8), reader.integer(1), reader.take(32)
        require(epoch > previous and phase in (1, 2) and any(identity), "resolution metadata encoding")
        previous = epoch
        result[epoch] = Resolution(phase, identity, reader.take(32) if phase == 1 else b"")
    return result
