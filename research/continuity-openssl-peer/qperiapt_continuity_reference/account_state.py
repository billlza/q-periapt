"""One authenticated account roster and retained generation history.

This is a pure state transition, not an owner or permission to write a journal.
The owning coordinator must retain the whole grant collection, bind its exact
sealed target, and obtain any required witness approval before releasing work.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass

from .identity import DevicePin, Roster, roster
from .identity_state import IdentityState
from .renewal import Renewal, verify_account
from .storage_budget import MAX_ACCOUNT_RECORD as MAX_RECORD
from .wire import Reader, generation, nonzero, require

MAX_HISTORY = 256
MAX_GRANTS = 32


@dataclass(frozen=True)
class AccountState:
    authority: DevicePin
    family: bytes
    policy: bytes
    listing: Roster
    history: tuple[tuple[bytes, int, bytes], ...]
    renewals: tuple[Renewal, ...] = ()

    @classmethod
    def initial(cls, authority, family, policy, wire, checkpoint):
        listing = roster(authority, wire, expected=checkpoint)
        value = cls(authority, family, policy, listing, listing.members)
        value.validate()
        return value

    def validate(self):
        require(type(self.family) is bytes and len(self.family) == 32 and any(self.family)
                and type(self.policy) is bytes and len(self.policy) == 32 and any(self.policy),
                "account family and original policy")
        require(len(self.history) <= MAX_HISTORY and len(self.renewals) <= MAX_HISTORY,
                "account history capacity")
        require(self.listing.version >= self.authority.roster_version
                and (self.listing.version != self.authority.roster_version
                     or self.listing.digest == self.authority.roster_digest),
                "account original roster floor")
        history, previous = {}, b""
        for identity, revision, commitment in self.history:
            require(type(identity) is bytes and len(identity) == 16 and identity > previous,
                    "account history device order")
            nonzero(identity)
            generation(revision)
            require(type(commitment) is bytes and len(commitment) == 32 and any(commitment),
                    "account history credential")
            history[identity] = (revision, commitment)
            previous = identity
        for identity, revision, commitment in self.listing.members:
            require(history.get(identity) == (revision, commitment),
                    "account roster differs from retained history")
        previous = b""
        for grant in self.renewals:
            require(grant.pin.device > previous
                    and grant.pin.account == self.authority.account
                    and grant.pin.root == self.authority.root
                    and grant.family == self.family and grant.policy == self.policy,
                    "account retained grant order or scope")
            previous = grant.pin.device
            require(history.get(grant.pin.device) == (grant.pin.generation, grant.successor.digest),
                    "account retained grant differs from history")
            target = grant.successor_roster
            require(target.version < self.listing.version
                    or target.checkpoint() == self.listing.checkpoint(),
                    "account roster precedes retained grant")

    def view(self, original, *, local=False):
        """Project a role from the common record without a second mutable roster."""
        require(original.pin.account == self.authority.account
                and original.pin.root == self.authority.root,
                "account role uses different authority")
        require(self.listing.version >= original.pin.roster_version
                and (self.listing.version != original.pin.roster_version
                     or self.listing.digest == original.pin.roster_digest),
                "account role original roster floor")
        from .identity import Credential
        current = Credential(original.key, original.credential, original.validity)
        grant = next((g for g in self.renewals if g.pin.device == original.pin.device
                      and g.pin.generation == original.pin.generation), None)
        if grant is not None:
            require(grant.original.key == original.key
                    and (not local or grant.original.digest == original.credential),
                    "account role original key or local owner differs")
            current = grant.successor
        for identity, revision, commitment in self.listing.members:
            if identity == original.pin.device and revision == original.pin.generation:
                require(commitment == current.digest, "account role credential lacks retained grant")
        return IdentityState(original, current, self.listing, grant)

    def advance(self, wire, checkpoint, grant_wires=(), *, now=None):
        """Validate all same-generation changes against one exact predecessor."""
        require(len(grant_wires) <= MAX_GRANTS, "account grant collection capacity")
        listing = roster(self.authority, wire, expected=checkpoint)
        require(listing.version > self.listing.version, "account roster rollback or fork")
        if now is not None:
            listing.validity.check(now)
        history = {identity: (revision, commitment) for identity, revision, commitment in self.history}
        retained = {grant.pin.device: grant for grant in self.renewals}
        selected = {}
        for wire in grant_wires:
            grant = verify_account(wire, self.authority, self.family, self.policy, checkpoint, now=now)
            identity = grant.pin.device
            require(identity not in selected, "duplicate account renewal device")
            require(grant.predecessor_roster.checkpoint() == self.listing.checkpoint()
                    and self.listing.contains(grant.pin, grant.previous.digest)
                    and history.get(identity) == (grant.pin.generation, grant.previous.digest),
                    "account grant predecessor differs")
            prior = retained.get(identity)
            require(prior is None or prior.original.digest == grant.original.digest,
                    "account renewal original lineage differs")
            selected[identity] = grant
        for identity, revision, commitment in listing.members:
            previous = history.get(identity)
            if previous is not None:
                floor, original = previous
                granted = selected.get(identity)
                permitted = (granted is not None and revision == granted.pin.generation == floor
                             and commitment == granted.successor.digest
                             and original == granted.previous.digest
                             and (identity, floor, original) in self.listing.members)
                require(revision >= floor and (revision != floor
                        or (original == commitment and (identity, revision, commitment) in self.listing.members)
                        or permitted), "account generation, revocation or credential conflict")
            else:
                require(len(history) < MAX_HISTORY, "account history capacity")
            history[identity] = (revision, commitment)
        retained = {identity: grant for identity, grant in retained.items()
                    if history.get(identity) == (grant.pin.generation, grant.successor.digest)}
        retained.update(selected)
        value = AccountState(self.authority, self.family, self.policy, listing,
                             tuple((identity, *record) for identity, record in sorted(history.items())),
                             tuple(grant for _, grant in sorted(retained.items())))
        value.validate()
        value.encode()  # Reserve a valid, bounded result before the caller can stage it.
        return value

    def encode(self):
        self.validate()
        result = bytearray(b"QPRFAC01" + len(self.listing.wire).to_bytes(2, "big") + self.listing.wire)
        result.extend(len(self.history).to_bytes(2, "big"))
        for identity, revision, commitment in self.history:
            result.extend(identity + revision.to_bytes(8, "big") + commitment)
        result.extend(len(self.renewals).to_bytes(2, "big"))
        for grant in self.renewals:
            result.extend(grant.successor_roster.checkpoint()
                          + len(grant.wire).to_bytes(4, "big") + grant.wire)
        require(len(result) <= MAX_RECORD, "account record capacity")
        return bytes(result)

    @classmethod
    def read(cls, wire, authority, family, policy):
        require(type(wire) is bytes and len(wire) <= MAX_RECORD, "account record capacity")
        reader = Reader(wire)
        require(reader.take(8) == b"QPRFAC01", "account record schema")
        size = reader.integer(2)
        require(0 < size <= 8192, "account roster capacity")
        listing = roster(authority, reader.take(size))
        count = reader.integer(2)
        require(count <= MAX_HISTORY, "account history capacity")
        history = tuple((reader.take(16), reader.integer(8), reader.take(32)) for _ in range(count))
        count = reader.integer(2)
        require(count <= MAX_HISTORY, "account retained grant capacity")
        grants = []
        for _ in range(count):
            target, size = reader.take(40), reader.integer(4)
            require(0 < size <= 65536, "account retained grant bytes")
            grants.append(verify_account(reader.take(size), authority, family, policy, target))
        reader.finish()
        value = cls(authority, family, policy, listing, history, tuple(grants))
        require(value.encode() == wire, "noncanonical account record")
        return value
