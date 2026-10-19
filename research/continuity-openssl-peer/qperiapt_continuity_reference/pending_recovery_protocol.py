"""Exact public expectations for privileged completion, never device approval."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .witness import Head, Operation, commitment, fixed
from .wire import MAX_U64, Reader, ldh, require

MAX_METADATA = 8 * 1024 * 1024
INTENT_DOMAIN = b"Q-PERIAPT-CONTINUITY-PENDING-WRITE-INTENT/v1"
METADATA_DOMAIN = b"Q-PERIAPT-CONTINUITY-PENDING-WRITE-METADATA/v1"


def scope_bytes(witness, subject, expected, target, authority, policy, authorization, intent):
    return (witness + subject + expected.wire() + target.wire() + authority + policy
            + bytes([authorization is not None]) + (authorization or bytes(32)) + intent)


@dataclass(frozen=True)
class Proposal:
    witness: bytes
    subject: bytes
    expected: Head
    target: Head
    authority: bytes
    policy: bytes
    authorization: bytes | None
    intent: bytes
    metadata: bytes

    def __post_init__(self):
        for value in (self.witness, self.authority, self.policy, self.intent, self.metadata): fixed(value, 32)
        require(type(self.subject) is bytes and len(self.subject) == 96, "pending recovery subject")
        for start in range(0, 96, 32): fixed(self.subject[start:start + 32], 32)
        if self.authorization is not None: fixed(self.authorization, 32)
        require(Operation.advance(self.expected, self.target.digest).arguments[48:] == self.target.wire(),
                "pending recovery exact next head")

    def scope(self):
        return scope_bytes(self.witness, self.subject, self.expected, self.target, self.authority,
                           self.policy, self.authorization, self.intent)

    def wire(self):
        return b"QPWRPL01" + self.scope() + self.metadata

    @classmethod
    def decode(cls, wire):
        require(type(wire) is bytes and len(wire) == 393, "pending recovery proposal size")
        r = Reader(wire); require(r.take(8) == b"QPWRPL01", "pending recovery proposal tag")
        witness, subject, expected, target = r.take(32), r.take(96), Head.read(r), Head.read(r)
        authority, policy, tag, authorization = r.take(32), r.take(32), r.integer(1), r.take(32)
        require(tag in (0, 1) and (tag == 1 or authorization == bytes(32)), "pending recovery policy authorization")
        value = cls(witness, subject, expected, target, authority, policy,
                    authorization if tag else None, r.take(32), r.take(32))
        r.finish(); return value

    @classmethod
    def create(cls, witness, subject, expected, target, authority, policy, intent, views):
        scope = scope_bytes(witness, subject, expected, target, authority, policy, None, intent)
        require(len(views) == 2 and all(type(v) is bytes for v in views), "two complete public views")
        metadata = b"QPWRMD01" + scope + b"".join(len(v).to_bytes(8, "big") + v for v in views)
        value = cls(witness, subject, expected, target, authority, policy, None, intent, ldh(METADATA_DOMAIN, metadata))
        value.check_metadata(metadata)
        return value, metadata

    def check_metadata(self, wire):
        require(type(wire) is bytes and len(wire) <= MAX_METADATA
                and ldh(METADATA_DOMAIN, wire) == self.metadata, "pending recovery metadata commitment")
        r = Reader(wire); prefix = b"QPWRMD01" + self.scope()
        require(r.take(len(prefix)) == prefix, "pending recovery metadata scope")
        views = []
        for head in (self.expected, self.target):
            size = r.integer(8); require(96 <= size <= MAX_METADATA, "pending recovery view size")
            view = r.take(size); require(view[:48] == head.wire(), "pending recovery view head")
            views.append(view)
        r.finish(); return tuple(views)

    def confirm(self, reply):
        operation = Operation.advance(self.expected, self.target.digest)
        command = commitment(b"COMMAND", self.witness + self.subject + operation.wire())
        require(reply.outcome == 1 and reply.head == self.target and reply.last == command,
                "pending recovery exact target and original command not confirmed")


def number(value):
    require(type(value) is int and 0 <= value < MAX_U64, "pending recovery metadata integer")
    return value.to_bytes(8, "big")
