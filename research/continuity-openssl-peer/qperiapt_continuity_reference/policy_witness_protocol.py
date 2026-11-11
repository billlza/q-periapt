"""Exact P witness proposal; parsing never grants policy or traffic authority."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .witness import Head, Operation, commitment, fixed
from .wire import Reader, ldh, require


@dataclass(frozen=True)
class Proposal:
    witness: bytes
    subject: bytes
    operation: bytes
    statement: bytes
    expected: Head
    target: Head

    def __post_init__(self):
        for value in (self.witness, self.operation, self.statement):
            fixed(value, 32)
        require(type(self.subject) is bytes and len(self.subject) == 96, "policy original subject size")
        for start in range(0, 96, 32):
            fixed(self.subject[start:start + 32], 32)
        require(Operation.advance(self.expected, self.target.digest).arguments[48:] == self.target.wire(),
                "policy exact next head")

    def wire(self):
        return (b"QPPWNP01" + self.witness + self.subject + self.operation + self.statement
                + self.expected.wire() + self.target.wire())

    @classmethod
    def decode(cls, wire):
        require(type(wire) is bytes and len(wire) == 296, "policy proposal size")
        r = Reader(wire)
        require(r.take(8) == b"QPPWNP01", "policy proposal schema")
        value = cls(r.take(32), r.take(96), r.take(32), r.take(32), Head.read(r), Head.read(r))
        r.finish()
        return value

    @property
    def binding(self):
        return ldh(b"Q-PERIAPT-ANCHOR-POLICY-RENEWAL/v1", self.wire())

    def command(self, kind):
        require(type(kind) is int and kind in (11, 12, 13, 14), "policy command kind")
        return Operation(kind, self.binding + bytes(64))

    def exchange(self, client, kind):
        require(client.pin.binding == self.witness and client.subject == self.subject, "policy original client scope")
        reply = client.exchange(self.command(kind))
        if reply.outcome == 12:
            require(reply.head == self.expected, "prepared policy changed head")
            return "Prepared"
        if reply.outcome == 13:
            command = commitment(b"COMMAND", self.witness + self.subject + self.command(11).wire())
            require(reply.head == self.target and reply.last == command, "policy applied another target")
            return "Applied"
        if reply.outcome == 14:
            require(reply.head == self.expected, "closed policy changed head")
            return "Closed"
        if reply.outcome == 15:
            return "Unavailable"
        require(reply.outcome == 16, "unexpected policy disposition")
        return "Acknowledged"
