"""Independent per-epoch traffic computations for interoperability experiments.

State changes here are volatile. A durable wrapper must commit the reservation,
candidate state and release boundary before exposing frames or plaintext.
Nonzero epochs additionally require a separate control owner to enforce the
directional cutovers, aggregate unconfirmed send budget and retained history.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import hmac

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .authority import Context
from .kem import hkdf as expand
from .wire import MAX_U64, Reader, ldh, require

DOMAIN = b"Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/"


def commitment(label: bytes, value: bytes, ad: bytes) -> bytes:
    return ldh(DOMAIN + label, len(value).to_bytes(8, "big") + value + ad)


def message_id(session: bytes, direction: int, index: int, epoch: int = 0) -> bytes:
    require(len(session) == 32 and direction in (1, 2) and 0 <= index < MAX_U64 and 0 <= epoch < MAX_U64,
            "message identity scope")
    counters = epoch.to_bytes(8, "big") + index.to_bytes(8, "big")
    return counters + ldh(DOMAIN + b"epoch-message-id", session + bytes([direction]) + counters)[:16]


def step(chain: bytes, index: int) -> tuple[bytes, bytes]:
    result = expand(chain, None, DOMAIN + b"chain" + index.to_bytes(8, "big"), 64)
    return result[:32], result[32:]


class VolatileTraffic:
    """Explicitly non-durable initiator traffic; never a product storage owner."""
    def __init__(self, context: Context, session: bytes, root: bytes, now: int):
        context.check_established(now)
        require(len(session) == len(root) == 32, "session material size")
        material = expand(root, session, DOMAIN + b"initial/HKDF-SHA256/ChaCha20Poly1305" + context.digest, 160)
        self._initialize(context, session, 0, material)

    @classmethod
    def _from_epoch(cls, context, session, epoch, root, material, now):
        context.check_established(now)
        require(0 < epoch < MAX_U64 and len(session) == len(root) == 32
                and len(material) == 128, "epoch traffic material")
        owner = cls.__new__(cls)
        owner._initialize(context, session, epoch, root + material)
        return owner

    def _initialize(self, context, session, epoch, material):
        self._context, self._session = context, session
        self._epoch = epoch
        self._send_closed, self._receive_limit = False, None
        self._rekey, self._send, self._receive = material[:32], material[32:64], material[64:96]
        self._send_ack, self._receive_ack = material[96:128], material[128:160]
        self._sent = self._received = self._send_floor = self._receive_floor = 0
        self._outbox: dict[int, tuple[bytes, bytes]] = {}
        self._inbox: dict[int, tuple[bytes, bytes | None]] = {}
        self._skipped: dict[int, bytes] = {}
        self._closed = False

    def _admit(self, now: int) -> None:
        require(not self._closed, "closed traffic")
        self._context.check_established(now)

    def _index(self, identity: bytes, direction: int) -> int:
        require(len(identity) == 32, "message ID length")
        index = int.from_bytes(identity[8:16], "big")
        require(identity == message_id(self._session, direction, index, self._epoch), "message ID scope")
        return index

    def next_id(self, now: int) -> bytes:
        self._admit(now)
        return message_id(self._session, 1, self._sent, self._epoch)

    def send(self, identity: bytes, plaintext: bytes, ad: bytes, now: int) -> bytes:
        cached = self.validate_send(identity, plaintext, ad, now)
        if cached is not None:
            return cached
        index = self._index(identity, 1)
        receipt = commitment(b"send-intent", plaintext, ad)
        chain, key = step(self._send, index)
        header = (b"QPCMSG03" + self._session + b"\1" + self._epoch.to_bytes(8, "big") + index.to_bytes(8, "big")
                  + identity + len(plaintext).to_bytes(4, "big"))
        wire = header + ChaCha20Poly1305(key).encrypt(bytes(12), plaintext,
            DOMAIN + b"aead" + header + len(ad).to_bytes(2, "big") + ad)
        self._outbox[index] = (receipt, wire)
        self._send, self._sent = chain, index + 1
        return wire

    def validate_send(self, identity: bytes, plaintext: bytes, ad: bytes, now: int) -> bytes | None:
        """Validate or replay without advancing a chain or computing ciphertext."""
        self._admit(now)
        require(len(plaintext) <= 16384 and len(ad) <= 1024, "message capacity")
        index = self._index(identity, 1)
        require(index >= self._send_floor, "retired send")
        receipt = commitment(b"send-intent", plaintext, ad)
        if index in self._outbox:
            previous, wire = self._outbox[index]
            require(receipt == previous, "conflicting send input")
            return wire
        require(not self._send_closed, "closed sending epoch")
        require(index == self._sent and self._sent < MAX_U64 - 1, "send slot")
        require(len(self._outbox) < 64 and self._sent < self._context.send_budget,
                "send capacity or signed budget")
        return None

    def receive(self, wire: bytes, ad: bytes, now: int) -> tuple[bytes, bytes]:
        self._admit(now)
        require(109 <= len(wire) <= 16493 and len(ad) <= 1024, "received message capacity")
        reader = Reader(wire)
        require(reader.take(8) == b"QPCMSG03" and reader.take(32) == self._session
                and reader.integer(1) == 2, "received session/direction")
        require(reader.integer(8) == self._epoch, "unadmitted traffic epoch")
        index, identity, size = reader.integer(8), reader.take(32), reader.integer(4)
        require(identity == message_id(self._session, 2, index, self._epoch), "received message identity")
        require(size <= 16384, "received plaintext capacity")
        ciphertext = reader.take(size + 16)
        reader.finish()
        require(index >= self._receive_floor, "retired receive")
        require(self._receive_limit is None or index < self._receive_limit, "closed receiving epoch")
        receipt = commitment(b"receive-intent", wire, ad)
        if index in self._inbox:
            previous, plaintext = self._inbox[index]
            require(receipt == previous, "conflicting received input")
            require(plaintext is not None, "retired receive")
            return identity, plaintext
        require(len(self._inbox) < 64, "inbox capacity")
        chain, received = self._receive, self._received
        skipped = dict(self._skipped)
        if index < received:
            require(index in skipped, "missing skipped key")
            key = skipped.pop(index)
        else:
            require(index < MAX_U64 - 1 and len(skipped) + index - received <= 128, "skipped-key capacity")
            require(index < self._context.send_budget, "received signed budget")
            while received <= index:
                chain, key = step(chain, received)
                if received != index:
                    skipped[received] = key
                received += 1
        plaintext = ChaCha20Poly1305(key).decrypt(bytes(12), ciphertext,
            DOMAIN + b"aead" + wire[:93] + len(ad).to_bytes(2, "big") + ad)
        # Authentication errors do not consume persisted-equivalent candidate
        # keys or advance counters. Durable commit is not supplied by this class.
        self._receive, self._received, self._skipped = chain, received, skipped
        if self._receive_limit is not None and self._received >= self._receive_limit:
            self._receive = bytes(32)
        self._inbox[index] = (receipt, plaintext)
        return identity, plaintext

    def consume(self, identity: bytes, now: int) -> bytes:
        self._admit(now)
        index = self._index(identity, 2)
        if index >= self._receive_floor:
            require(index in self._inbox, "unreceived consumption")
            receipt, _plaintext = self._inbox[index]
            self._inbox[index] = (receipt, None)
            while self._receive_floor in self._inbox and self._inbox[self._receive_floor][1] is None:
                del self._inbox[self._receive_floor]
                self._receive_floor += 1
        return self.acknowledgement(now)

    def acknowledgement(self, now: int) -> bytes:
        self._admit(now)
        prefix = ((b"QPCMACK1" if self._epoch == 0 else b"QPCMACK2") + self._session + b"\2"
                  + (self._epoch.to_bytes(8, "big") if self._epoch else b"") + self._receive_floor.to_bytes(8, "big"))
        return prefix + hmac.digest(self._receive_ack, DOMAIN + b"acknowledgement" + prefix, "sha256")

    def accept_acknowledgement(self, wire: bytes, now: int) -> int:
        self._admit(now)
        prefix = ((b"QPCMACK1" if self._epoch == 0 else b"QPCMACK2") + self._session + b"\1"
                  + (self._epoch.to_bytes(8, "big") if self._epoch else b""))
        require(len(wire) == len(prefix) + 40 and wire.startswith(prefix), "ACK scope")
        expected = hmac.digest(self._send_ack, DOMAIN + b"acknowledgement" + wire[:-32], "sha256")
        require(hmac.compare_digest(expected, wire[-32:]), "ACK authentication")
        floor = int.from_bytes(wire[-40:-32], "big")
        require(floor <= self._sent, "ACK prefix")
        if floor <= self._send_floor:
            return self._send_floor
        self._outbox = {index: row for index, row in self._outbox.items() if index >= floor}
        self._send_floor = floor
        return floor

    def close(self) -> None:
        self._closed = True
        self._outbox.clear()
        self._inbox.clear()
        self._skipped.clear()
        self._rekey = self._send = self._receive = self._send_ack = self._receive_ack = b""
