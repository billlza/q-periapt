"""Exact witness/head credential proposals; public metadata grants no approval."""
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
    policy: bytes | None = None

    def __post_init__(self):
        for value in (self.witness, self.operation, self.statement):
            fixed(value, 32)
        require(type(self.subject) is bytes and len(self.subject) == 96, "renewal subject size")
        for start in range(0, 96, 32):
            fixed(self.subject[start:start + 32], 32)
        require(Operation.advance(self.expected, self.target.digest).arguments[48:] == self.target.wire(),
                "renewal exact next head")
        if self.policy is not None:
            fixed(self.policy, 32)

    def wire(self):
        return ((b"QPCRNP01" if self.policy is None else b"QPCRNP03")
                + self.witness + self.subject + self.operation + self.statement
                + self.expected.wire() + self.target.wire()
                + (b"" if self.policy is None else b"\0" + self.policy))

    @classmethod
    def decode(cls, wire):
        require(type(wire) is bytes and len(wire) in (296, 329), "renewal proposal size")
        reader = Reader(wire)
        tag = reader.take(8)
        require(tag in (b"QPCRNP01", b"QPCRNP03"), "unsupported renewal proposal")
        value = cls(reader.take(32), reader.take(96), reader.take(32), reader.take(32),
                    Head.read(reader), Head.read(reader))
        if tag == b"QPCRNP03":
            require(reader.integer(1) == 0, "credential renewal cannot adopt independent policy")
            value = cls(value.witness, value.subject, value.operation, value.statement,
                        value.expected, value.target, reader.take(32))
        reader.finish()
        return value

    @property
    def binding(self):
        return ldh(b"Q-PERIAPT-ANCHOR-CREDENTIAL-PROPOSAL/v1", self.wire())

    def command(self, kind):
        require(type(kind) is int and kind in (5, 6, 7, 8), "renewal command kind")
        return Operation(kind, self.binding + bytes(64))

    def observe(self, reply):
        if reply.outcome == 7:
            require(reply.head == self.expected, "prepared renewal changed head")
            return "Prepared"
        if reply.outcome == 8:
            commit_id = commitment(b"COMMAND", self.witness + self.subject + self.command(5).wire())
            require(reply.head == self.target and reply.last == commit_id, "renewal applied another target")
            return "Applied"
        if reply.outcome == 9:
            require(reply.head == self.expected, "closed renewal changed head")
            return "Closed"
        if reply.outcome == 10:
            return "Unavailable"
        require(reply.outcome == 11, "unexpected renewal disposition")
        return "Acknowledged"

    def exchange(self, client, kind):
        require(client.pin.binding == self.witness and client.subject == self.subject, "renewal client scope")
        return self.observe(client.exchange(self.command(kind)))
