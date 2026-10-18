"""Atomic local-only renewal intent, abandonment and monotonic time floor."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .identity_state import IdentityState
from .renewal import Renewal, verify
from .wire import MAX_U64, require

MAX_RECORD = 8 + 1 + 40 + 4 + 65536 + 1 + 152
MAX_IDENTITY = 40 + 4 + 65536 + 2 + 8192


def time_value(value):
    require(type(value) is int and 0 <= value < MAX_U64, "local renewal time range")


def fixed(value, size):
    require(type(value) is bytes and len(value) == size and any(value), "local renewal terminal field")


@dataclass(frozen=True)
class Expired:
    operation: bytes
    statement: bytes
    target: bytes
    revision: int
    digest: bytes
    observed_at: int

    def __post_init__(self):
        for value in (self.operation, self.statement, self.digest):
            fixed(value, 32)
        fixed(self.target, 40)
        require(0 < int.from_bytes(self.target[:8], "big") < MAX_U64 and any(self.target[8:]),
                "expired original target checkpoint")
        require(type(self.revision) is int and 0 < self.revision < MAX_U64, "expired observation revision")
        time_value(self.observed_at)

    def encode(self):
        return (self.operation + self.statement + self.target + self.revision.to_bytes(8, "big")
                + self.digest + self.observed_at.to_bytes(8, "big"))

    @classmethod
    def read(cls, reader):
        return cls(reader.take(32), reader.take(32), reader.take(40), reader.integer(8),
                   reader.take(32), reader.integer(8))


@dataclass(frozen=True)
class Record:
    floor: int = 0
    pending: Renewal | None = None
    expired: Expired | None = None

    def __post_init__(self):
        time_value(self.floor)
        if self.expired is not None:
            require(self.expired.observed_at <= self.floor, "expired observation exceeds retained floor")
        if self.pending is not None and self.expired is not None:
            require(self.pending.operation != self.expired.operation, "abandoned operation cannot become pending")

    def encode(self):
        result = self.floor.to_bytes(8, "big") + bytes([self.pending is not None])
        if self.pending is not None:
            result += self.pending.successor_roster.checkpoint() + len(self.pending.wire).to_bytes(4, "big") + self.pending.wire
        result += bytes([self.expired is not None])
        if self.expired is not None:
            result += self.expired.encode()
        require(len(result) <= MAX_RECORD, "local renewal record capacity")
        return result

    @classmethod
    def read(cls, reader, context):
        floor = reader.integer(8); present = reader.integer(1)
        require(present in (0, 1), "local renewal pending discriminator")
        pending = None
        if present:
            target, size = reader.take(40), reader.integer(4)
            require(0 < size <= 65536, "local renewal grant capacity")
            original = IdentityState.initial(context, role=0).original
            pending = verify(reader.take(size), original, context.family, context.policy_digest, target)
        present = reader.integer(1); require(present in (0, 1), "local expiry discriminator")
        return cls(floor, pending, Expired.read(reader) if present else None)

    def validate(self, current):
        require(current.renewal is not None or self.pending is not None or self.expired is not None,
                "empty local renewal coordination")
        if self.pending is not None:
            require(current.active() and self.pending.previous.digest == current.current.digest
                    and self.pending.predecessor_roster.checkpoint() == current.listing.checkpoint(),
                    "pending renewal predecessor differs from retained state")
            require(current.renewal is None or current.renewal.operation != self.pending.operation,
                    "committed operation cannot remain pending")
        if self.expired is not None:
            require(current.renewal is None or current.renewal.operation != self.expired.operation,
                    "expired-uncommitted target is already current")

    def admit(self):
        require(self.pending is None, "local credential renewal remains pending")
        require(self.expired is None, "expired uncommitted renewal denies activation")

    def current_time(self, now):
        time_value(now)
        require(now >= self.floor, "local renewal time precedes durable floor")

    def status(self, current, operation):
        if self.pending is not None and self.pending.operation == operation:
            grant, status = self.pending, "Pending"
        elif current.renewal is not None and current.renewal.operation == operation:
            grant, status = current.renewal, "Committed"
        elif self.expired is not None and self.expired.operation == operation:
            value = self.expired
            return {"status": "ExpiredUncommitted", "operation": operation.hex(), "statement": value.statement.hex(),
                    "target": value.target.hex(), "time_floor": self.floor,
                    "expired_observation": {"revision": value.revision, "digest": value.digest.hex(), "at": value.observed_at}}
        else:
            raise ValueError("original local renewal outcome unavailable")
        return {"status": status, "operation": operation.hex(), "statement": grant.statement.hex(),
                "target": grant.successor_roster.checkpoint().hex(), "time_floor": self.floor, "expired_observation": None}
