"""Exact independently approved qperiapt-enrollment/1 scope and possession proof."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .journal import Scope
from .wire import Interval, MAX_U64, Reader, VerificationKey, digest, ldh, require

DOMAIN = b'Q-PERIAPT-INDEPENDENT-REGISTRATION/v1/'
REQUEST_BODY = 2129


@dataclass(frozen=True)
class Intent:
    root: VerificationKey
    device: bytes
    generation: int
    validity: Interval
    family: bytes

    def __post_init__(self):
        require(isinstance(self.root, VerificationKey) and type(self.device) is bytes and len(self.device) == 16
                and any(self.device) and type(self.family) is bytes and len(self.family) == 32 and any(self.family),
                'registration intent identities')
        require(type(self.generation) is int and 0 < self.generation < MAX_U64, 'registration generation')
        require(type(self.validity.start) is int and type(self.validity.end) is int
                and 0 <= self.validity.start < self.validity.end < MAX_U64, 'registration validity')

    def description(self):
        return (self.device + self.generation.to_bytes(8, 'big') + self.validity.start.to_bytes(8, 'big')
                + self.validity.end.to_bytes(8, 'big') + self.family)

    def wire(self):
        return self.root.raw + self.description()

    def body(self):
        return digest(b'ACCOUNT', self.root.raw) + self.description()

    @classmethod
    def from_trusted(cls, wire):
        require(type(wire) is bytes and len(wire) == 2057, 'registration intent size')
        r = Reader(wire); value = cls(VerificationKey(r.take(1985)), r.take(16), r.integer(8), Interval.read(r), r.take(32))
        r.finish(); return value

    def scope(self, registration_id):
        return Scope(registration_id, ldh(DOMAIN + b'owner', self.body()), ldh(DOMAIN + b'intent', self.wire()))

    def verify_request(self, wire, now):
        self.validity.check(now)
        return authenticate_request(self, wire)

    def admit_device(self, device, public):
        require(device.pin.root == self.root and device.pin.device == self.device
                and device.pin.generation == self.generation and device.validity == self.validity
                and device.key == public, 'registration approved device differs')


def request_body(intent, identity, public):
    require(type(identity) is bytes and len(identity) == 32 and any(identity), 'original signing identity')
    require(not public.shares_component(intent.root), 'registration root/device key separation')
    return b'QPENRQ01' + identity + intent.body() + public.raw


def authenticate_request(intent, wire):
    """Historical signature/scope check only; returning it grants no permission."""
    require(type(wire) is bytes and len(wire) == 4 + REQUEST_BODY + 3373, 'registration request size')
    r = Reader(wire); require(r.integer(4) == REQUEST_BODY, 'registration request body size')
    body = r.take(REQUEST_BODY); r = Reader(body)
    require(r.take(8) == b'QPENRQ01', 'registration request tag')
    identity = r.take(32); require(r.take(104) == intent.body(), 'registration independently approved scope')
    public = VerificationKey(r.take(1985)); r.finish()
    require(request_body(intent, identity, public) == body, 'registration canonical request')
    require(public.open(wire, 14, REQUEST_BODY) == body, 'registration proof of possession')
    return identity, public
