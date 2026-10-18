"""One retained identity; committed revocation cannot revive its generation."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass, replace
from .identity import Credential, Device, Roster, roster
from .renewal import Renewal, verify
from .wire import digest, require


@dataclass(frozen=True)
class IdentityState:
    original: Device
    current: Credential
    listing: Roster
    renewal: Renewal | None = None

    def active(self):
        return self.listing.contains(self.original.pin, self.current.digest)

    def check(self, now):
        self.current.validity.check(now); self.listing.validity.check(now)
        require(self.active(), "peer original identity revoked")

    @classmethod
    def initial(cls, context, role=1):
        require(context.devices is not None, "original identity metadata unavailable")
        require(type(role) is int and role in (0, 1), "retained identity role")
        original = context.devices[role]
        require(context.devices[1].pin.account != context.devices[0].pin.account,
                "same-account peer authority requires the local account coordinator")
        current = Credential(original.key, original.credential, original.validity)
        listing = roster(original.pin, original.roster_wire, expected=original.pin.checkpoint())
        return cls(original, current, listing)

    def encode(self):
        grant = self.renewal.wire if self.renewal is not None else b""
        target = self.renewal.successor_roster.checkpoint() if self.renewal is not None else bytes(40)
        return target + len(grant).to_bytes(4, "big") + grant + len(self.listing.wire).to_bytes(2, "big") + self.listing.wire

    @classmethod
    def read(cls, reader, context, role=1):
        value = cls.initial(context, role)
        target, size = reader.take(40), reader.integer(4)
        require(size <= 65536, "retained renewal capacity")
        grant_wire = reader.take(size)
        if size:
            grant = verify(grant_wire, value.original, context.family, context.policy_digest, target)
            current = grant.successor
        else:
            require(target == bytes(40), "absent renewal target padding")
            grant, current = None, value.current
        size = reader.integer(2); require(0 < size <= 8192, "retained roster capacity")
        listing = roster(value.original.pin, reader.take(size))
        floor = grant.successor_roster if grant is not None else value.listing
        require(listing.version >= floor.version and (listing.version != floor.version or listing.digest == floor.digest),
                "retained peer roster below credential grant")
        for identity, generation, digest in listing.members:
            if identity == value.original.pin.device and generation == value.original.pin.generation:
                require(digest == current.digest, "retained credential differs without grant")
        return cls(value.original, current, listing, grant)

    def renew(self, context, wire, operation, target, now):
        require(self.active(), "revoked original peer cannot be renewed")
        grant = verify(wire, self.original, context.family, context.policy_digest, target, now=now)
        require(type(operation) is bytes and operation == grant.operation, "original renewal operation differs")
        if self.listing.checkpoint() == grant.successor_roster.checkpoint():
            require(self.renewal is not None and self.renewal.statement == grant.statement
                    and self.renewal.operation == operation, "conflicting renewal at current head")
            self.check(now)
            return self
        require(self.listing.checkpoint() == grant.predecessor_roster.checkpoint()
                and self.current.digest == grant.previous.digest, "renewal predecessor differs from retained state")
        return IdentityState(self.original, grant.successor, grant.successor_roster, grant)

    def update_roster(self, wire, target, now):
        listing = roster(self.original.pin, wire, expected=target); listing.validity.check(now)
        if listing.checkpoint() == self.listing.checkpoint():
            return self
        require(self.active(), "revoked original peer cannot reappear")
        require(listing.version > self.listing.version, "peer roster rollback or fork")
        # A different credential for this same generation needs the separate
        # original-root renewal grant; plain roster admission cannot substitute.
        for identity, generation, digest in listing.members:
            if identity == self.original.pin.device:
                require(generation >= self.original.pin.generation, "peer generation rollback")
                if generation == self.original.pin.generation:
                    require(digest == self.current.digest, "credential replacement requires renewal grant")
        return replace(self, listing=listing)


def admit_local(state, context, now):
    context.intervals[0].check(now)
    if state.local_authority is None:
        for interval in context.intervals[1:3]:
            interval.check(now)
    else:
        state.local_authority.check(now)


def local_binding(state, context):
    if context.witness is None:
        return None
    if state.local_authority is None:
        return context.witness.authority
    return digest(b"AUTHORITY", state.local_authority.original.pin.account
                  + state.local_authority.listing.checkpoint() + context.family)


def bind(state, context):
    if state.peer_authority is not None or state.local_authority is not None:
        require(state.traffic is not None, "retained identity requires original established session")
        view = replace(context, current_peer=state.peer_authority, current_local=state.local_authority)
        state.traffic.context = view
        for traffic in state.traffic.epochs.values():
            traffic._context = view
