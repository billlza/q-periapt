"""Account renewal facts stored atomically with the common account image.

The caller must hold the original journal lease and reconcile its exact write
intent first. These pure transitions do not write files or return a live owner.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass, replace

from .account_request import AccountRequest, MAX_REQUEST
from .local_renewal_record import fixed, time_value
from .storage_budget import MAX_ACCOUNT_COORDINATION as MAX_RECORD
from .wire import Reader, MAX_U64, require

def checkpoint(value):
    fixed(value, 40)
    require(0 < int.from_bytes(value[:8], "big") < MAX_U64 and any(value[8:]),
            "account outcome checkpoint")


@dataclass(frozen=True)
class Receipt:
    operation: bytes
    statement: bytes
    target: bytes
    binding: bytes

    def __post_init__(self):
        for value in (self.operation, self.statement, self.binding):
            fixed(value, 32)
        checkpoint(self.target)

    @classmethod
    def for_request(cls, request):
        return cls(request.local.operation, request.local.statement,
                   request.local.successor_roster.checkpoint(), request.binding())

    def encode(self):
        return self.operation + self.statement + self.target + self.binding

    @classmethod
    def read(cls, reader):
        return cls(reader.take(32), reader.take(32), reader.take(40), reader.take(32))


@dataclass(frozen=True)
class Expired:
    receipt: Receipt
    observed_head: bytes
    revision: int
    digest: bytes
    observed_at: int

    def __post_init__(self):
        checkpoint(self.observed_head)
        fixed(self.digest, 32)
        require(type(self.revision) is int and 0 < self.revision < MAX_U64,
                "account expiry observation revision")
        time_value(self.observed_at)

    def encode(self):
        return (self.receipt.encode() + self.observed_head + self.revision.to_bytes(8, "big")
                + self.digest + self.observed_at.to_bytes(8, "big"))

    @classmethod
    def read(cls, reader):
        return cls(Receipt.read(reader), reader.take(40), reader.integer(8),
                   reader.take(32), reader.integer(8))


@dataclass(frozen=True)
class AccountRecord:
    floor: int = 0
    pending: AccountRequest | None = None
    completed: Receipt | None = None
    expired: Expired | None = None

    def __post_init__(self):
        time_value(self.floor)
        operations = []
        if self.pending is not None:
            operations.append(self.pending.local.operation)
        if self.completed is not None:
            operations.append(self.completed.operation)
        if self.expired is not None:
            require(self.expired.observed_at <= self.floor, "account expiry exceeds time floor")
            operations.append(self.expired.receipt.operation)
        require(len(operations) == len(set(operations)), "account outcome operation collision")

    def current_time(self, now):
        time_value(now)
        require(now >= self.floor, "account renewal time precedes durable floor")

    def known(self, operation):
        if self.pending is not None and self.pending.local.operation == operation:
            return "Pending", Receipt.for_request(self.pending)
        if self.completed is not None and self.completed.operation == operation:
            return "Committed", self.completed
        if self.expired is not None and self.expired.receipt.operation == operation:
            return "ExpiredUncommitted", self.expired.receipt
        return None

    def status(self, operation):
        known = self.known(operation)
        require(known is not None, "original account renewal outcome unavailable")
        status, receipt = known
        observation = None
        if status == "ExpiredUncommitted":
            e = self.expired
            observation = {"head": e.observed_head.hex(), "revision": e.revision,
                           "digest": e.digest.hex(), "at": e.observed_at}
        return {"status": status, "operation": receipt.operation.hex(),
                "statement": receipt.statement.hex(), "target": receipt.target.hex(),
                "binding": receipt.binding.hex(), "time_floor": self.floor,
                "expired_observation": observation}

    def validate(self, account, original=None):
        if self.pending is not None:
            # Historical validation proves the full exact predecessor and grant
            # collection; it does not make an expired target current.
            self.pending.apply(account, None)
        if self.completed is not None:
            target = self.completed.target
            require(account.listing.version >= int.from_bytes(target[:8], "big")
                    and (account.listing.version != int.from_bytes(target[:8], "big")
                         or account.listing.checkpoint() == target),
                    "account completion precedes its committed target")
            if account.listing.checkpoint() == target:
                current = tuple(grant for grant in account.renewals
                                if grant.successor_roster.checkpoint() == target)
                local = next((grant for grant in current
                              if grant.operation == self.completed.operation
                              and grant.statement == self.completed.statement), None)
                require(local is not None, "account completion has no committed local grant")
                request = AccountRequest(local, tuple(grant for grant in current if grant is not local))
                require(Receipt.for_request(request) == self.completed,
                        "account completion differs from the committed collection")
        if original is not None:
            local = account.view(original, local=True)
            if local.renewal is not None:
                require(self.completed is not None
                        and self.completed.operation == local.renewal.operation
                        and self.completed.statement == local.renewal.statement
                        and self.completed.target == local.renewal.successor_roster.checkpoint(),
                        "account local grant lacks its original completion")

    def stage(self, account, request, now):
        receipt = Receipt.for_request(request)
        known = self.known(receipt.operation)
        if known is not None:
            require(known[1] == receipt, "different original account renewal collection")
            return self
        require(self.pending is None, "another account renewal remains pending")
        self.current_time(now)
        request.apply(account, now)
        result = replace(self, pending=request)
        result.encode()
        return result

    def commit(self, account, operation, now):
        known = self.known(operation)
        require(known is not None, "original account renewal outcome unavailable")
        if known[0] == "Committed":
            return account, self
        require(known[0] == "Pending", "expired account renewal cannot commit")
        self.current_time(now)
        target = self.pending.apply(account, now)
        return target, AccountRecord(self.floor, completed=known[1])

    def reconcile_expired(self, account, operation, now, revision, digest):
        known = self.known(operation)
        require(known is not None, "original account renewal outcome unavailable")
        if known[0] in ("Committed", "ExpiredUncommitted"):
            return self
        self.current_time(now)
        require(now >= self.pending.expires_at(), "account renewal target is not expired")
        self.validate(account)
        expiry = Expired(known[1], account.listing.checkpoint(), revision, digest, now)
        return AccountRecord(now, completed=self.completed, expired=expiry)

    def admit(self):
        require(self.pending is None, "account credential renewal remains pending")
        require(self.expired is None, "expired uncommitted account renewal denies activation")

    def encode(self):
        result = bytearray(b"QPRFAT01" + self.floor.to_bytes(8, "big")
                           + bytes([self.pending is not None]))
        if self.pending is not None:
            wire = self.pending.encode()
            result.extend(len(wire).to_bytes(4, "big") + wire)
        result.append(self.completed is not None)
        if self.completed is not None:
            result.extend(self.completed.encode())
        result.append(self.expired is not None)
        if self.expired is not None:
            result.extend(self.expired.encode())
        require(len(result) <= MAX_RECORD, "account coordination capacity")
        return bytes(result)

    @classmethod
    def read(cls, wire, original, family, policy, account):
        require(type(wire) is bytes and len(wire) <= MAX_RECORD, "account coordination capacity")
        reader = Reader(wire)
        require(reader.take(8) == b"QPRFAT01", "account coordination schema")
        floor = reader.integer(8)

        def present():
            value = reader.integer(1)
            require(value in (0, 1), "account coordination discriminator")
            return bool(value)

        pending = None
        if present():
            size = reader.integer(4)
            require(0 < size <= MAX_REQUEST, "account pending request capacity")
            pending = AccountRequest.read(reader.take(size), original, family, policy)
        completed = Receipt.read(reader) if present() else None
        expired = Expired.read(reader) if present() else None
        reader.finish()
        value = cls(floor, pending, completed, expired)
        value.validate(account, original)
        require(value.encode() == wire, "noncanonical account coordination")
        return value
