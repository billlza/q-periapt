"""Bounded policy coordination metadata for the original authenticated journal.

These pure transitions do not publish files, contact a witness or release traffic.
The journal owner must hold its original lease and compare the actual predecessor.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass, replace
from .authority import HistoricalPolicy, PolicySnapshot
from .identity import Device, credential, roster
from .local_renewal_record import Expired, time_value
from .policy_renewal_proof import (APPROVAL_BYTES, BODY_BYTES, MAX_APPROVAL,
                                 HistoricalApproval, Scope, storage_owner,
                                 verify_current, verify_historical)
from .wire import Reader, digest, require

POLICY_BYTES = 4 + 200 + 3373
CREDENTIAL_BYTES = 4 + 2097 + 3373
MAX_GRANT = 8 + 5 * 2 + 2 * POLICY_BYTES + CREDENTIAL_BYTES + 8192 + MAX_APPROVAL
MAX_RECORD = 8 + 8 + 2 * (4 + MAX_GRANT) + 1 + 152


def _stored_scope(wire):
    # Extract only enough to reconstruct a retained record. Both root signatures
    # and every remaining body field are checked by verify_historical below.
    require(type(wire) is bytes and len(wire) == MAX_APPROVAL, "retained policy approval size")
    r = Reader(wire)
    require(r.take(8) == b"QPPRNB01" and r.integer(2) == APPROVAL_BYTES
            and r.integer(4) == BODY_BYTES, "retained policy approval header")
    b = Reader(r.take(BODY_BYTES))
    require(b.take(8) == b"QPPRNW01", "retained policy statement tag")
    operation, journal, owner, first, current = (b.take(32) for _ in range(5))
    b.take(64)  # Exact current authority and family are checked by the verifier.
    listing, original, previous = (b.take(40) for _ in range(3))
    b.take(40)  # Target checkpoint must match the retained target policy.
    kind, authorization = b.integer(1), b.take(32)
    require(kind in (0, 1) and (kind != 0 or authorization == bytes(32)), "policy predecessor flag")
    require(b.integer(1) == 1, "policy permission is not original-established-only")
    b.finish()
    return Scope(operation, journal, owner, first, current, listing, original, previous,
                 authorization if kind else None)


def retained_device(original, certificate, listing_wire, expected, family):
    pin = replace(original.pin, roster_version=int.from_bytes(expected[:8], "big"), roster_digest=expected[8:])
    cert = credential(pin, certificate, family)
    listing = roster(pin, listing_wire, expected=expected)
    require(listing.contains(pin, cert.digest), "policy approval credential absent from its roster")
    # Require a real historical overlap; this is not a current admission call.
    start = max(cert.validity.start, listing.validity.start)
    cert.validity.check(start)
    listing.validity.check(start)
    return Device(cert.key, pin, cert.digest, cert.validity, listing.validity,
                  digest(b"AUTHORITY", pin.account + expected + family), listing_wire)


@dataclass(frozen=True)
class Grant:
    approval: HistoricalApproval
    previous: HistoricalPolicy
    target: HistoricalPolicy
    current: Device
    certificate: bytes

    @classmethod
    def current_inputs(cls, wire, scope, original_policy, previous_policy, target_policy,
                       original_device, current_certificate, current_roster, now):
        require(type(target_policy) is PolicySnapshot, "current target policy required")
        current = retained_device(original_device, current_certificate, current_roster,
                                  scope.current_roster, original_policy.family)
        approved = verify_current(wire, scope, original_policy, previous_policy, target_policy,
                                  original_device, current, now)
        return cls(approved, previous_policy, target_policy.history, current, current_certificate)

    def encode(self):
        fields = (self.previous.wire, self.target.wire, self.certificate,
                  self.current.roster_wire, self.approval.wire)
        require(all(type(field) is bytes and 0 < len(field) <= limit for field, limit in
                    zip(fields, (POLICY_BYTES, POLICY_BYTES, CREDENTIAL_BYTES, 8192, MAX_APPROVAL), strict=True)),
                "retained policy grant field bound")
        return b"QPIPGR01" + b"".join(len(field).to_bytes(2, "big") + field for field in fields)

    @classmethod
    def read(cls, wire, original_policy, original_device):
        require(type(wire) is bytes and len(wire) <= MAX_GRANT, "retained policy grant capacity")
        r = Reader(wire)
        require(r.take(8) == b"QPIPGR01", "retained policy grant tag")
        fields = []
        for limit in (POLICY_BYTES, POLICY_BYTES, CREDENTIAL_BYTES, 8192, MAX_APPROVAL):
            size = r.integer(2)
            require(0 < size <= limit, "retained policy grant field capacity")
            fields.append(r.take(size))
        r.finish()
        previous_wire, target_wire, certificate, listing, approval_wire = fields
        previous = original_policy.authenticate_retained(previous_wire)
        target = original_policy.authenticate_retained(target_wire)
        scope = _stored_scope(approval_wire)
        current = retained_device(original_device, certificate, listing, scope.current_roster, original_policy.family)
        approval = verify_historical(approval_wire, scope, original_policy, previous, target, original_device, current)
        value = cls(approval, previous, target, current, certificate)
        require(value.encode() == wire, "noncanonical retained policy grant")
        return value

    def check_current(self, now):
        self.target.validity.check(now)
        self.current.validity.check(now)
        self.current.roster_validity.check(now)


@dataclass(frozen=True)
class Record:
    floor: int = 0
    active: Grant | None = None
    pending: Grant | None = None
    expired: Expired | None = None

    def __post_init__(self):
        time_value(self.floor)
        if self.expired is not None:
            require(self.expired.observed_at <= self.floor, "policy expiry exceeds time floor")
        operations = [g.approval.scope.operation for g in (self.active, self.pending) if g is not None]
        if self.expired is not None:
            operations.append(self.expired.operation)
        require(len(operations) == len(set(operations)), "policy operation has multiple dispositions")

    def encode(self):
        wire = b"QPIPRC01" + self.floor.to_bytes(8, "big")
        for grant in (self.active, self.pending):
            field = b"" if grant is None else grant.encode()
            wire += len(field).to_bytes(4, "big") + field
        wire += bytes([self.expired is not None])
        if self.expired is not None:
            wire += self.expired.encode()
        require(len(wire) <= MAX_RECORD, "policy coordination capacity")
        return wire

    @classmethod
    def read(cls, wire, original_policy, original_device, journal, current):
        require(type(wire) is bytes and len(wire) <= MAX_RECORD, "policy coordination capacity")
        r = Reader(wire)
        require(r.take(8) == b"QPIPRC01", "policy coordination tag")
        floor, grants = r.integer(8), []
        for _ in range(2):
            size = r.integer(4)
            require(size <= MAX_GRANT, "policy coordination grant capacity")
            grants.append(Grant.read(r.take(size), original_policy, original_device) if size else None)
        present = r.integer(1)
        require(present in (0, 1), "policy expiry discriminator")
        value = cls(floor, *grants, Expired.read(r) if present else None)
        r.finish()
        value.validate(original_policy, original_device, journal, current)
        require(value.encode() == wire, "noncanonical policy coordination")
        return value

    def request(self, operation, original_policy, original_device, journal, current):
        require(self.pending is None, "policy renewal remains pending")
        require(self.known(operation) is None, "policy request operation already has a disposition")
        self.validate(original_policy, original_device, journal, current)
        previous = original_policy if self.active is None else self.active.target
        authorization = None if self.active is None else self.active.approval.statement
        return Scope(operation, journal, storage_owner(original_device), original_device.credential,
                     current.credential, current.pin.checkpoint(), original_policy.checkpoint(),
                     previous.checkpoint(), authorization)

    def validate(self, original_policy, original_device, journal, current):
        first = original_device
        require((first.key, first.pin.root, first.pin.account, first.pin.device, first.pin.generation)
                == (current.key, current.pin.root, current.pin.account, current.pin.device, current.pin.generation)
                and first.validity.start == current.validity.start and first.validity.end <= current.validity.end,
                "policy coordination changed the original device identity")
        require(current.authority == digest(b"AUTHORITY", current.pin.account + current.pin.checkpoint() + original_policy.family),
                "policy coordination current authority differs")
        for grant in (self.active, self.pending):
            if grant is not None:
                require(grant.approval.scope.journal == journal, "policy record belongs to another journal")
        if self.active is not None:
            prior = self.active.current
            # Later C/R can be admitted by the existing exact G/R coordinator.
            # Reading this record does not perform those transitions itself.
            require((prior.key, prior.pin.root, prior.pin.account, prior.pin.device, prior.pin.generation)
                    == (current.key, current.pin.root, current.pin.account, current.pin.device, current.pin.generation)
                    and prior.validity.start == current.validity.start and prior.validity.end <= current.validity.end,
                    "policy active credential lineage differs")
            require(current.pin.roster_version >= prior.pin.roster_version
                    and (current.pin.roster_version != prior.pin.roster_version or current.pin.checkpoint() == prior.pin.checkpoint()),
                    "policy active roster rolled back or forked")
            if current.credential != prior.credential:
                require(current.validity.end > prior.validity.end, "policy active credential changed without extension")
        if self.pending is not None:
            expected = replace(self, pending=None).request(self.pending.approval.scope.operation,
                original_policy, original_device, journal, current)
            require(self.pending.approval.scope == expected, "policy pending predecessor differs from actual state")

    def current_time(self, now):
        time_value(now)
        require(now >= self.floor, "policy time precedes durable floor")

    def known(self, operation):
        for grant, status in ((self.pending, "Pending"), (self.active, "Committed")):
            if grant is not None and grant.approval.scope.operation == operation:
                return {"status": status, "operation": operation.hex(), "statement": grant.approval.statement.hex(),
                        "target": grant.target.checkpoint().hex(), "time_floor": self.floor}
        if self.expired is not None and self.expired.operation == operation:
            e = self.expired
            return {"status": "ExpiredUncommitted", "operation": operation.hex(), "statement": e.statement.hex(),
                    "target": e.target.hex(), "time_floor": self.floor,
                    "observed": {"revision": e.revision, "digest": e.digest.hex(), "at": e.observed_at}}
        return None

    def status(self, operation):
        known = self.known(operation)
        require(known is not None, "original policy outcome unavailable")
        return known

    def stage(self, grant, original_policy, original_device, journal, current, now):
        require(Grant.read(grant.encode(), original_policy, original_device) == grant,
                "policy grant metadata differs from signed retained bytes")
        self.validate(original_policy, original_device, journal, current)
        self.current_time(now)
        known = self.known(grant.approval.scope.operation)
        if known is not None:
            require(known["status"] != "ExpiredUncommitted", "abandoned policy operation cannot be staged")
        grant.check_current(now)
        require(grant.approval.scope.journal == journal
                and grant.current.credential == current.credential
                and grant.current.pin.checkpoint() == current.pin.checkpoint(),
                "policy staging needs the actual current identity and journal")
        if known is not None:
            require(known["status"] != "Committed" or self.pending is None,
                    "later policy renewal remains pending")
            require(known["statement"] == grant.approval.statement.hex()
                    and known["target"] == grant.target.checkpoint().hex(), "different original policy decision")
            return self
        require(self.pending is None, "another policy renewal remains pending")
        value = replace(self, pending=grant)
        value.validate(original_policy, original_device, journal, current)
        return value

    def commit(self, operation, original_policy, original_device, journal, current, now):
        self.validate(original_policy, original_device, journal, current)
        known = self.status(operation)
        if known["status"] == "Committed":
            return self
        require(known["status"] == "Pending", "expired uncommitted policy cannot commit")
        self.current_time(now)
        self.pending.check_current(now)
        return replace(self, active=self.pending, pending=None)

    def reconcile_expired(self, operation, original_policy, original_device, journal, current,
                          now, revision, head):
        self.validate(original_policy, original_device, journal, current)
        known = self.status(operation)
        if known["status"] != "Pending":
            return self
        self.current_time(now)
        g = self.pending
        require(now >= min(g.target.validity.end, g.current.validity.end, g.current.roster_validity.end),
                "policy target is not expired")
        expired = Expired(operation, g.approval.statement, g.target.checkpoint(), revision, head, now)
        return replace(self, pending=None, expired=expired, floor=now)

    def admit(self, original_policy, now):
        require(self.pending is None, "policy renewal remains pending")
        self.current_time(now)
        (original_policy if self.active is None else self.active.target).validity.check(now)
