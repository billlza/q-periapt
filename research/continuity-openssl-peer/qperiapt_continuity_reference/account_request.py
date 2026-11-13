"""Canonical complete-account input retained before sealing a journal target."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass

from .account_state import MAX_GRANTS
from .renewal import Renewal, verify, verify_account
from .storage_budget import MAX_ACCOUNT_REQUEST as MAX_REQUEST
from .wire import Reader, ldh, require


def fields(wire):
    """Decode bounded untrusted fields; this provides no verified authority."""
    require(type(wire) is bytes and len(wire) <= MAX_REQUEST, "account request capacity")
    reader = Reader(wire)
    require(reader.take(8) == b"QPRFAR01", "account request schema")
    target = reader.take(40)

    def grant():
        size = reader.integer(4)
        require(0 < size <= 65536, "account request grant capacity")
        return reader.take(size)

    local = grant()
    count = reader.integer(1)
    require(count < MAX_GRANTS, "account companion capacity")
    companions = tuple(grant() for _ in range(count))
    reader.finish()
    return local, companions, target

@dataclass(frozen=True)
class AccountRequest:
    local: Renewal
    companions: tuple[Renewal, ...]

    @classmethod
    def parse(cls, local_wire, companions, original, family, policy, target, *, expected_companions=None):
        require(len(companions) < MAX_GRANTS, "account companion capacity")
        local = verify(local_wire, original, family, policy, target)
        require(expected_companions is None or len(expected_companions) == len(companions),
                'companion issuance correlation count differs')
        selected = {}
        for index, wire in enumerate(companions):
            grant = verify_account(wire, original.pin, family, policy, target)
            require(expected_companions is None or (grant.operation, grant.statement) == expected_companions[index],
                    'companion issuance differs from signed grant')
            require(grant.pin.device != local.pin.device and grant.pin.device not in selected,
                    "duplicate account request device")
            require(grant.predecessor_roster.checkpoint() == local.predecessor_roster.checkpoint(),
                    "account request common predecessor")
            selected[grant.pin.device] = grant
        return cls(local, tuple(grant for _, grant in sorted(selected.items())))

    def binding(self):
        # This is authenticated-local request identity, not a root signature or
        # the witness transaction statement. The latter remains the local G
        # statement plus the exact predecessor and sealed target image.
        fields = self.local.operation + self.local.statement
        for grant in self.companions:
            fields += grant.pin.device + grant.operation + grant.statement
        return ldh(b"Q-PERIAPT-INDEPENDENT-ACCOUNT-REQUEST/v1", fields)

    def same_request(self, other):
        return self.binding() == other.binding()

    def apply(self, account, now):
        return account.advance(
            self.local.successor_roster.wire, self.local.successor_roster.checkpoint(),
            (self.local.wire, *(grant.wire for grant in self.companions)), now=now)

    def expires_at(self):
        return min(self.local.successor_roster.validity.end,
                   self.local.successor.validity.end,
                   *(grant.successor.validity.end for grant in self.companions))

    def encode(self):
        result = bytearray(b"QPRFAR01" + self.local.successor_roster.checkpoint()
                           + len(self.local.wire).to_bytes(4, "big") + self.local.wire
                           + bytes([len(self.companions)]))
        for grant in self.companions:
            result.extend(len(grant.wire).to_bytes(4, "big") + grant.wire)
        require(len(result) <= MAX_REQUEST, "account request capacity")
        return bytes(result)

    @classmethod
    def read(cls, wire, original, family, policy):
        local, companions, target = fields(wire)
        value = cls.parse(local, companions, original, family, policy, target)
        require(value.encode() == wire, "noncanonical account request")
        return value
