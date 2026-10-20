"""Exact native-compatible R scope and witness descriptor, never approval."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .witness import Head, Operation, commitment, fixed
from .wire import Reader, MAX_U64, ldh, require


def checkpoint(value):
    require(type(value) is bytes and len(value) == 40
            and 0 < int.from_bytes(value[:8], "big") < MAX_U64 and any(value[8:]),
            "roster transaction checkpoint")


@dataclass(frozen=True)
class Scope:
    operation: bytes
    previous: bytes
    target: bytes
    policy: bytes
    authorization: bytes | None = None

    def __post_init__(self):
        fixed(self.operation, 32)
        for value in (self.previous, self.target, self.policy):
            checkpoint(value)
        require(int.from_bytes(self.target[:8], "big") > int.from_bytes(self.previous[:8], "big"),
                "roster target does not advance predecessor")
        if self.authorization is not None:
            fixed(self.authorization, 32)

    def wire(self):
        return (self.operation + self.previous + self.target + self.policy
                + bytes([self.authorization is not None]) + (self.authorization or bytes(32)))

    @classmethod
    def read(cls, reader):
        operation, previous, target, policy = reader.take(32), reader.take(40), reader.take(40), reader.take(40)
        flag, statement = reader.integer(1), reader.take(32)
        require((flag == 0 and statement == bytes(32)) or (flag == 1 and any(statement)),
                "roster policy authorization discriminator")
        return cls(operation, previous, target, policy, statement if flag else None)

    def check_policy(self, context):
        require(context.policy_version > 0 and self.policy == context.policy_version.to_bytes(8, "big")
                + context.policy_digest and self.authorization is None,
                "roster requires the original independently verified policy")


@dataclass(frozen=True)
class Proposal:
    witness: bytes
    subject: bytes
    scope: Scope
    expected: Head
    target: Head

    def __post_init__(self):
        fixed(self.witness, 32)
        require(type(self.subject) is bytes and len(self.subject) == 96, "roster original subject size")
        for start in range(0, 96, 32):
            fixed(self.subject[start:start + 32], 32)
        require(Operation.advance(self.expected, self.target.digest).arguments[48:] == self.target.wire(),
                "roster exact next head")
        require((self.scope.authorization is None) == (self.scope.policy[8:] == self.subject[64:]),
                "roster policy authorization differs from original subject")

    def wire(self):
        return (b"QPRWNP01" + self.witness + self.subject + self.scope.wire()
                + self.expected.wire() + self.target.wire())

    @classmethod
    def decode(cls, wire):
        require(type(wire) is bytes and len(wire) == 417, "roster proposal size")
        r = Reader(wire)
        require(r.take(8) == b"QPRWNP01", "roster proposal schema")
        value = cls(r.take(32), r.take(96), Scope.read(r), Head.read(r), Head.read(r))
        r.finish()
        return value

    @property
    def binding(self):
        return ldh(b"Q-PERIAPT-ANCHOR-ROSTER-REFRESH/v1", self.wire())

    def command(self, kind):
        require(type(kind) is int and kind in (16, 17, 18, 19), "roster command kind")
        return Operation(kind, self.binding + bytes(64))

    def exchange(self, client, kind):
        require(client.pin.binding == self.witness and client.subject == self.subject, "roster original client scope")
        reply = client.exchange(self.command(kind))
        if reply.outcome == 17:
            require(reply.head == self.expected, "prepared roster changed head")
            return "Prepared"
        if reply.outcome == 18:
            command = commitment(b"COMMAND", self.witness + self.subject + self.command(16).wire())
            require(reply.head == self.target and reply.last == command, "roster applied another target")
            return "Applied"
        if reply.outcome == 19:
            require(reply.head == self.expected, "closed roster changed head")
            return "Closed"
        if reply.outcome == 20:
            return "Unavailable"
        require(reply.outcome == 21, "unexpected roster disposition")
        return "Acknowledged"
