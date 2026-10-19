"""Canonical signed credentials/rosters; snapshots never imply current authority."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .wire import Interval, Reader, VerificationKey, digest, generation, nonzero, require


@dataclass(frozen=True)
class DevicePin:
    root: VerificationKey
    account: bytes
    roster_version: int
    roster_digest: bytes
    device: bytes
    generation: int

    def checkpoint(self):
        return self.roster_version.to_bytes(8, "big") + self.roster_digest


@dataclass(frozen=True)
class Credential:
    key: VerificationKey
    digest: bytes
    validity: Interval


@dataclass(frozen=True)
class Roster:
    version: int
    digest: bytes
    validity: Interval
    members: tuple[tuple[bytes, int, bytes], ...]
    wire: bytes

    def checkpoint(self):
        return self.version.to_bytes(8, "big") + self.digest

    def contains(self, pin, credential):
        return (pin.device, pin.generation, credential) in self.members


@dataclass(frozen=True)
class Device:
    key: VerificationKey
    pin: DevicePin
    credential: bytes
    validity: Interval
    roster_validity: Interval
    authority: bytes
    roster_wire: bytes

    def context(self) -> bytes:
        return (self.pin.account + self.pin.device + self.pin.generation.to_bytes(8, "big")
                + self.credential + self.authority)


def credential(pin, wire, family):
    require(len(pin.device) == 16 and any(pin.device), "expected device identity")
    generation(pin.generation)
    require(pin.account == digest(b"ACCOUNT", pin.root.raw), "account root pin")
    body = pin.root.open(wire, 1, 2097); reader = Reader(body)
    require(reader.take(8) == b"QPCERT01" and reader.take(32) == pin.account
            and reader.take(16) == pin.device and reader.integer(8) == pin.generation,
            "credential identity differs from intended device")
    validity = Interval.read(reader)
    require(reader.take(32) == family, "credential policy family")
    key = VerificationKey(reader.take(1985)); reader.finish()
    require(not key.shares_component(pin.root), "device/account signing key separation")
    return Credential(key, digest(b"CREDENTIAL", body), validity)


def roster(pin, wire, *, expected=None):
    require(type(wire) is bytes and 0 < len(wire) <= 8192, "roster envelope capacity")
    require(pin.account == digest(b"ACCOUNT", pin.root.raw), "account root pin")
    body = pin.root.open(wire, 2); commitment = digest(b"ROSTER", body); reader = Reader(body)
    require(reader.take(8) == b"QPROST01" and reader.take(32) == pin.account, "roster account")
    version = generation(reader.integer(8)); validity = Interval.read(reader)
    if expected is not None:
        require(type(expected) is bytes and expected == version.to_bytes(8, "big") + commitment,
                "roster checkpoint pin")
    count = reader.integer(2); require(count <= 32, "roster count")
    members, previous = [], b""
    for _ in range(count):
        identity, revision, value = nonzero(reader.take(16)), generation(reader.integer(8)), nonzero(reader.take(32))
        require(identity > previous, "roster device order or duplicate"); previous = identity
        members.append((identity, revision, value))
    reader.finish()
    return Roster(version, commitment, validity, tuple(members), wire)


def verify_device(pin, certificate, signed_roster, family, now):
    cert = credential(pin, certificate, family); cert.validity.check(now)
    listing = roster(pin, signed_roster, expected=pin.checkpoint()); listing.validity.check(now)
    require(listing.contains(pin, cert.digest), "device absent from current roster or exact credential")
    authority = digest(b"AUTHORITY", pin.account + listing.checkpoint() + family)
    return Device(cert.key, pin, cert.digest, cert.validity, listing.validity, authority, signed_roster)
