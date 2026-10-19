"""Root-signed same-key peer renewal verification, separate from durable adoption."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .identity import Credential, Roster, credential, roster
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

    def current(self, now):
        self.successor.validity.check(now)
        self.successor_roster.validity.check(now)
        require(max(self.previous.validity.start, self.predecessor_roster.validity.start) <= now,
                "future historical predecessor")


def verify(wire, original, family, policy, expected_target, *, now=None):
    require(type(wire) is bytes and len(wire) <= 65536, "renewal container capacity")
    require(type(expected_target) is bytes and len(expected_target) == 40, "independent target checkpoint")
    reader = Reader(wire); require(reader.take(8) == b"QPRNB001", "renewal container tag")
    signed, origin_wire, previous_wire, next_wire, old_roster_wire, next_roster_wire = (field(reader) for _ in range(6))
    reader.finish()
    pin = original.pin
    body = pin.root.open(signed, 15, 369); r = Reader(body)
    require(r.take(8) == b"QPCRNW01", "renewal statement tag")
    operation = r.take(32); require(any(operation), "renewal operation")
    require(r.take(32) == pin.account and r.take(16) == pin.device and r.integer(8) == pin.generation,
            "renewal original identity")
    fam, key, od, pd, nd, pol = (r.take(32) for _ in range(6))
    predecessor, target = r.take(40), r.take(40)
    require(r.integer(1) == 1, "retained-established permission"); r.finish()
    require(fam == family and pol == policy and target == expected_target, "renewal policy/target scope")
    origin = credential(pin, origin_wire, family)
    previous = credential(pin, previous_wire, family)
    successor = credential(pin, next_wire, family)
    require(origin.key == previous.key == successor.key == original.key and origin.digest == original.credential,
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
                    origin, previous, successor, old, new)
    if now is not None:
        value.current(now)
    return value
