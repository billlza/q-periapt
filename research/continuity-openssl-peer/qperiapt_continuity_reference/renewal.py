"""Root-signed same-key peer renewal verification, separate from durable adoption."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass, replace
from .identity import Credential, DevicePin, Roster, credential, roster
from .wire import Reader, ldh, require


def field(reader):
    size = reader.integer(2)
    require(0 < size <= 8192, "renewal field capacity")
    return reader.take(size)


@dataclass(frozen=True)
class Renewal:
    wire: bytes
    operation: bytes
    statement: bytes
    original: Credential
    previous: Credential
    successor: Credential
    predecessor_roster: Roster
    successor_roster: Roster
    pin: DevicePin
    family: bytes
    policy: bytes

    def current(self, now):
        self.successor.validity.check(now)
        self.successor_roster.validity.check(now)
        require(max(self.previous.validity.start, self.predecessor_roster.validity.start) <= now,
                "future historical predecessor")


def verify(wire, original, family, policy, expected_target, *, now=None):
    """Local installation renewal must name its exact original credential."""
    value = verify_established_peer(wire, original, family, policy, expected_target, now=now)
    require(value.original.digest == original.credential, "renewal key/original credential differs")
    return value


def verify_established_peer(wire, original, family, policy, expected_target, *, now=None):
    """Verify retained-established permission for the full pinned peer identity.

    An established session may originate at an intermediate credential. The
    durable peer owner must still match its exact current predecessor or retained
    completion. This verifier neither admits a local owner nor creates a session.
    """
    value = verify_account(wire, original.pin, family, policy, expected_target, now=now)
    require(value.pin.device == original.pin.device and value.pin.generation == original.pin.generation,
            "renewal original identity")
    require(value.original.key == original.key, "renewal key/original credential differs")
    return value


def verify_account(wire, authority, family, policy, expected_target, *, now=None):
    """Authenticate a member grant under independently supplied account trust.

    The signed identity selects a member of this account, not a local owner.
    Original-owner and established-peer callers must additionally match their
    retained identity. Complete-account adoption must validate every changed
    member against one retained predecessor and its generation history.
    """
    require(type(wire) is bytes and len(wire) <= 65536, "renewal container capacity")
    require(type(expected_target) is bytes and len(expected_target) == 40, "independent target checkpoint")
    reader = Reader(wire); require(reader.take(8) == b"QPRNB001", "renewal container tag")
    signed, origin_wire, previous_wire, next_wire, old_roster_wire, next_roster_wire = (field(reader) for _ in range(6))
    reader.finish()
    body = authority.root.open(signed, 15, 369); r = Reader(body)
    require(r.take(8) == b"QPCRNW01", "renewal statement tag")
    operation = r.take(32); require(any(operation), "renewal operation")
    require(r.take(32) == authority.account, "renewal account authority")
    identity, revision = r.take(16), r.integer(8)
    pin = replace(authority, device=identity, generation=revision,
                  roster_version=int.from_bytes(expected_target[:8], "big"),
                  roster_digest=expected_target[8:])
    fam, key, od, pd, nd, pol = (r.take(32) for _ in range(6))
    predecessor, target = r.take(40), r.take(40)
    require(r.integer(1) == 1, "retained-established permission"); r.finish()
    require(fam == family and pol == policy and target == expected_target, "renewal policy/target scope")
    origin = credential(pin, origin_wire, family)
    previous = credential(pin, previous_wire, family)
    successor = credential(pin, next_wire, family)
    require(origin.key == previous.key == successor.key,
            "renewal key/original credential differs")
    require((od, pd, nd) == (origin.digest, previous.digest, successor.digest)
            and key == ldh(b"Q-PERIAPT-CREDENTIAL-RENEWAL-KEY/v1", origin.key.raw), "renewal credential commitments")
    require(origin.validity.start == previous.validity.start == successor.validity.start
            and origin.validity.end <= previous.validity.end < successor.validity.end, "renewal validity extension")
    old = roster(pin, old_roster_wire, expected=predecessor)
    new = roster(pin, next_roster_wire, expected=target)
    require(new.version > old.version and old.contains(pin, previous.digest) and new.contains(pin, successor.digest),
            "renewal exact roster memberships")
    historical = max(previous.validity.start, old.validity.start)
    previous.validity.check(historical); old.validity.check(historical)
    # Historical reconstruction authenticates a real common interval without
    # granting a current owner or backdating an operational call.
    common = max(historical, successor.validity.start, new.validity.start)
    successor.validity.check(common); new.validity.check(common)
    value = Renewal(wire, operation, ldh(b"Q-PERIAPT-CREDENTIAL-RENEWAL-STATEMENT/v1", body),
                    origin, previous, successor, old, new, pin, family, policy)
    if now is not None:
        value.current(now)
    return value
