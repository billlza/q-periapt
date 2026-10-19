"""Bounded encrypted enrollment payload and exact original child installation."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from .identity import DevicePin, credential, roster
from .registration_inputs import Inputs
from .registration_protocol import authenticate_request
from .wire import Reader, SigningKey, digest, require

MAX_IMAGE = 128 * 1024
PHASES = ('Preparing', 'Requested', 'Accepted', 'Prepared', 'Active')


def signer(seed):
    require(type(seed) is bytes and len(seed) == 64, 'registration private seed shape')
    owner = SigningKey.__new__(SigningKey)
    owner._pq = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed[:32])
    owner._ec = ec.derive_private_key(int.from_bytes(seed[32:], 'big'), ec.SECP256R1())
    return owner


def seed_from(owner):
    return owner._pq.private_bytes_raw() + owner._ec.private_numbers().private_value.to_bytes(32, 'big')


def blob(value, maximum):
    require(type(value) is bytes and len(value) <= maximum, 'registration field capacity')
    return len(value).to_bytes(4, 'big') + value


def take_blob(reader, maximum):
    size = reader.integer(4); require(size <= maximum, 'registration field capacity'); return reader.take(size)


@dataclass(frozen=True)
class Admission:
    checkpoint: bytes
    policy: bytes
    journal: bytes
    certificate: bytes
    roster: bytes

    def pin(self, intent):
        require(len(self.checkpoint) == 40 and len(self.policy) == 40 and len(self.journal) == 32
                and any(self.journal), 'registration admission shape')
        return DevicePin(intent.root, digest(b'ACCOUNT', intent.root.raw), int.from_bytes(self.checkpoint[:8], 'big'),
                         self.checkpoint[8:], intent.device, intent.generation)

    def validate(self, intent, public):
        pin = self.pin(intent); cert = credential(pin, self.certificate, intent.family)
        listing = roster(pin, self.roster, expected=self.checkpoint)
        require(cert.validity == intent.validity and cert.key == public and listing.contains(pin, cert.digest),
                'registration original admission differs')
        return cert

    def wire(self):
        return self.checkpoint + self.policy + self.journal + blob(self.certificate, 8192) + blob(self.roster, 8192)

    @classmethod
    def read(cls, r):
        return cls(r.take(40), r.take(40), r.take(32), take_blob(r, 8192), take_blob(r, 8192))


@dataclass(frozen=True)
class Child:
    path: Path
    context: bytes
    inputs: Inputs

    def wire(self):
        require(self.path.is_absolute() and '..' not in self.path.parts and len(self.context) == 32 and any(self.context),
                'registration original installation scope')
        path = str(self.path).encode('utf-8')
        return blob(path, 4096) + self.context + blob(self.inputs.encode(), 112 * 1024)

    @classmethod
    def read(cls, r):
        return cls(Path(take_blob(r, 4096).decode('utf-8')), r.take(32), Inputs.decode(take_blob(r, 112 * 1024)))


@dataclass(repr=False)
class Image:
    identity: bytes
    seed: bytes
    request: bytes = b''
    admission: Admission | None = None
    child: Child | None = None
    active: bool = False

    def phase(self):
        return 4 if self.active else (3 if self.child is not None else (2 if self.admission is not None else (1 if self.request else 0)))

    def encode(self, intent):
        require(len(self.identity) == 32 and any(self.identity) and len(self.seed) == 64, 'registration original identity')
        public = signer(self.seed).public(); require(not public.shares_component(intent.root), 'registration account/device key separation')
        if self.request: require(authenticate_request(intent, self.request) == (self.identity, public), 'registration stored original request')
        if self.admission is not None:
            require(bool(self.request), 'admission without original request'); self.admission.validate(intent, public)
        if self.child is not None:
            require(self.admission is not None, 'installation without admission')
            p = self.child.inputs.pins
            require(p.initiator == self.admission.pin(intent) and p.policy_version.to_bytes(8, 'big') + p.policy_digest == self.admission.policy,
                    'installation original independent pins differ')
            require(self.child.inputs.materials.initiator_credential == self.admission.certificate
                    and self.child.inputs.materials.initiator_roster == self.admission.roster, 'installation original signed admission differs')
        require(not self.active or self.child is not None, 'active registration lacks original installation')
        wire = b'QPREGS01' + self.identity + self.seed + bytes([self.phase()]) + blob(self.request, 8192)
        if self.admission is not None: wire += self.admission.wire()
        if self.child is not None: wire += self.child.wire()
        require(len(wire) <= MAX_IMAGE, 'registration image capacity')
        return wire

    @classmethod
    def decode(cls, wire, intent):
        require(type(wire) is bytes and len(wire) <= MAX_IMAGE, 'registration image capacity')
        r = Reader(wire); require(r.take(8) == b'QPREGS01', 'registration state schema')
        identity, seed, phase, request = r.take(32), r.take(64), r.integer(1), take_blob(r, 8192)
        require(phase <= 4 and bool(request) == (phase >= 1), 'registration phase')
        value = cls(identity, seed, request, Admission.read(r) if phase >= 2 else None, Child.read(r) if phase >= 3 else None, phase == 4)
        r.finish(); require(value.encode(intent) == wire, 'registration state canonical encoding'); return value
