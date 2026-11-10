"""Pinned dual-signature witness requests; byte carriers never grant permission."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import os
import ipaddress
import threading
import socket
import time

from .wire import Reader, VerificationKey, generation, ldh, require

DOMAIN = b"Q-PERIAPT-CONTINUITY-ANCHOR-"


def commitment(name, value):
    return ldh(DOMAIN + name + b"/v1", value)


def fixed(value, size):
    require(type(value) is bytes and len(value) == size and any(value), "witness field shape")
    return value


@dataclass(frozen=True)
class Pin:
    identity: bytes
    key: VerificationKey

    def __post_init__(self):
        fixed(self.identity, 32)
        fixed(self.key.raw, 1985)

    @property
    def binding(self):
        return commitment(b"AUTHORITY", self.identity + self.key.raw)


@dataclass(frozen=True)
class Profile:
    pin: Pin
    owner: bytes
    policy: bytes
    authority: bytes

    def __post_init__(self):
        for value in (self.owner, self.policy, self.authority):
            fixed(value, 32)

    def subject(self, journal):
        return fixed(journal, 32) + self.owner + self.policy


@dataclass(frozen=True)
class Head:
    fence: int
    revision: int
    digest: bytes

    def __post_init__(self):
        require(type(self.fence) is int and type(self.revision) is int, "witness counter type")
        generation(self.fence); generation(self.revision); fixed(self.digest, 32)

    def wire(self):
        return self.fence.to_bytes(8, "big") + self.revision.to_bytes(8, "big") + self.digest

    @classmethod
    def read(cls, reader):
        return cls(reader.integer(8), reader.integer(8), reader.take(32))


@dataclass(frozen=True)
class Operation:
    kind: int
    arguments: bytes

    def __post_init__(self):
        require(type(self.kind) is int, "witness operation kind type")
        require(type(self.arguments) is bytes and len(self.arguments) == 96, "witness operation size")
        if self.kind == 1:
            require(not any(self.arguments), "query padding")
        elif self.kind in (4, 5, 6, 7, 8, 11, 12, 13, 14, 16, 17, 18, 19):
            fixed(self.arguments[:32], 32)
            require(not any(self.arguments[32:]), "witness binding padding")
        elif self.kind == 15:
            fixed(self.arguments[:32], 32)
            fixed(self.arguments[32:64], 32)
            require(not any(self.arguments[64:]), "witness policy admission padding")
        else:
            require(self.kind in (2, 3), "unsupported witness operation")
            reader = Reader(self.arguments); old, new = Head.read(reader), Head.read(reader)
            require((new.fence == old.fence and new.revision == old.revision + 1 and new.digest != old.digest)
                    if self.kind == 2 else
                    (new.fence == old.fence + 1 and new.revision == old.revision and new.digest == old.digest),
                    "witness transition")

    def wire(self):
        return bytes([self.kind]) + self.arguments

    @classmethod
    def query(cls):
        return cls(1, bytes(96))

    @classmethod
    def advance(cls, old, digest):
        return cls(2, old.wire() + Head(old.fence, old.revision + 1, digest).wire())

    @classmethod
    def fence(cls, old):
        return cls(3, old.wire() + Head(old.fence + 1, old.revision, old.digest).wire())

    @classmethod
    def authority(cls, authority):
        return cls(4, fixed(authority, 32) + bytes(64))

    @classmethod
    def policy_authority(cls, authority, statement):
        return cls(15, fixed(authority, 32) + fixed(statement, 32) + bytes(32))


@dataclass(frozen=True)
class Reply:
    outcome: int
    head: Head
    last: bytes | None


def verify(pin, subject, operation, body, wire):
    command = commitment(b"COMMAND", pin.binding + subject + operation.wire())
    reader = Reader(pin.key.open(wire, 8, 282))
    require(reader.take(8) == b"QPANRS01" and reader.take(32) == pin.binding
            and reader.take(96) == subject and reader.take(32) == commitment(b"REQUEST", body)
            and reader.take(32) == command, "witness reply attempt/scope")
    outcome, head, present, last = reader.integer(1), Head.read(reader), reader.integer(1), reader.take(32)
    reader.finish()
    require((present == 0 and last == bytes(32) and head.fence == head.revision == 1)
            or (present == 1 and any(last) and (head.fence != 1 or head.revision != 1)), "witness last command")
    last = last if present else None
    if operation.kind == 1:
        require(outcome == 1, "witness query outcome")
    elif operation.kind in (4, 15):
        require(outcome in (5, 6), "witness authority outcome")
    elif operation.kind in (5, 6, 7, 8):
        allowed = {5: (8, 9, 10), 6: (7, 8, 9, 10), 7: (8, 9, 10), 8: (10, 11)}
        require(outcome in allowed[operation.kind], "witness renewal outcome")
        # The proposal owner additionally checks the exact expected/target head
        # and applied command. An authenticated disposition alone is not authority.
    elif operation.kind in (11, 12, 13, 14):
        allowed = {11: (13, 14, 15), 12: (12, 13, 14, 15), 13: (13, 14, 15), 14: (15, 16)}
        require(outcome in allowed[operation.kind], "witness policy outcome")
    elif operation.kind in (16, 17, 18, 19):
        allowed = {16: (18, 19, 20), 17: (17, 18, 19, 20), 18: (18, 19, 20), 19: (20, 21)}
        require(outcome in allowed[operation.kind], "witness roster outcome")
    else:
        r = Reader(operation.arguments); expected, target = Head.read(r), Head.read(r)
        exact = head == target and last == command
        require((outcome in (2, 3) and exact) or (outcome == 4 and head != expected and not exact),
                "inconsistent witness outcome")
    return Reply(outcome, head, last)


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("witness total deadline")
    return value


class TcpTransport:
    """One explicitly configured address, one bounded attempt, no implicit retry."""
    def __init__(self, address):
        require(type(address) is tuple and len(address) == 2 and type(address[1]) is int
                and 0 < address[1] <= 65535, "witness endpoint")
        # Explicit numeric addresses avoid an unbounded DNS lookup outside the
        # invocation's total transport deadline.
        ipaddress.ip_address(address[0])
        self.address = address

    def __call__(self, request, deadline):
        require(len(request) == 3674, "witness request frame")
        with socket.create_connection(self.address, timeout=min(5, remaining(deadline))) as stream:
            data = len(request).to_bytes(4, "big") + request
            while data:
                stream.settimeout(remaining(deadline))
                count = stream.send(data); require(count > 0, "closed witness request")
                data = data[count:]
            def read(size):
                result = bytearray()
                while len(result) < size:
                    stream.settimeout(remaining(deadline))
                    part = stream.recv(size - len(result)); require(bool(part), "truncated witness reply")
                    result.extend(part)
                return bytes(result)
            require(int.from_bytes(read(4), "big") == 3659, "witness reply frame")
            return read(3659)


class Client:
    def __init__(self, pin, subject, signer, transport, timeout=10):
        require(type(subject) is bytes and len(subject) == 96, "witness subject length")
        for i in range(0, 96, 32):
            fixed(subject[i:i + 32], 32)
        require(type(timeout) in (int, float) and 0 < timeout <= 60, "witness timeout")
        require(not signer.public().shares_component(pin.key), "witness/device key separation")
        self.pin, self.subject, self.signer, self.transport, self.timeout = pin, subject, signer, transport, timeout
        self._lock = threading.RLock()

    def exchange(self, operation):
        with self._lock:
            return self._exchange(operation)

    def _exchange(self, operation):
        require(self.signer is not None, "closed witness client")
        signer = self.signer
        deadline = time.monotonic() + self.timeout
        try:
            command = commitment(b"COMMAND", self.pin.binding + self.subject + operation.wire())
            body = b"QPANRQ01" + self.pin.binding + self.subject + command + fixed(os.urandom(32), 32) + operation.wire()
            wire = signer.sign(7, body); remaining(deadline)
            response = self.transport(wire, deadline); remaining(deadline)
            result = verify(self.pin, self.subject, operation, body, response); remaining(deadline)
            require(self.signer is signer, "closed witness client during exchange")
            return result
        except BaseException:
            self.close()
            raise

    def close(self):
        with self._lock:
            self.signer = None
