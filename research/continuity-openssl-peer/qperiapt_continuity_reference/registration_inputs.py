"""Authenticated-local original bootstrap inputs; never received trust enrollment."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .authority import Pins, Materials
from .bootstrap_bundle import BootstrapBundle, decode as bundle_fields
from .identity import DevicePin
from .wire import Reader, VerificationKey, require
from .witness import Pin

MAX_INPUTS = 112 * 1024


def field(value):
    require(type(value) is bytes and len(value) <= 65536, 'registration input field bound')
    return len(value).to_bytes(4, 'big') + value


def device_head(pin):
    return pin.account + pin.checkpoint() + pin.device + pin.generation.to_bytes(8, 'big')


def read_device(root, head):
    require(len(head) == 96, 'registration original device expectation')
    r = Reader(head)
    value = DevicePin(VerificationKey(root), r.take(32), r.integer(8), r.take(32), r.take(16), r.integer(8))
    r.finish(); return value


@dataclass(frozen=True)
class Inputs:
    pins: Pins
    materials: Materials
    witness: Pin | None = None

    def encode(self):
        p, m = self.pins, self.materials
        bundle = BootstrapBundle.from_materials(m)
        values = (p.sdk_root, p.sdk_state, p.policy_root.raw, p.policy_version.to_bytes(8, 'big') + p.policy_digest,
                  p.initiator.root.raw, device_head(p.initiator), p.responder.root.raw, device_head(p.responder),
                  p.directory, b'' if self.witness is None else self.witness.identity + self.witness.key.raw,
                  m.sdk_document, m.sdk_signature, m.policy, bundle.wire)
        wire = b'QPREGIN1' + b''.join(field(v) for v in values)
        require(len(wire) <= MAX_INPUTS, 'registration retained inputs capacity')
        return wire

    @classmethod
    def decode(cls, wire):
        require(type(wire) is bytes and len(wire) <= MAX_INPUTS, 'registration retained inputs capacity')
        r = Reader(wire); require(r.take(8) == b'QPREGIN1', 'registration retained input schema')
        values = []
        for _ in range(14):
            size = r.integer(4); require(size <= 65536, 'registration input field bound'); values.append(r.take(size))
        r.finish()
        sdk, state, policy_root, head, i_root, i_head, r_root, r_head, directory, witness, document, signature, policy, bundle = values
        require(len(head) == 40 and len(sdk) == 1952 and len(state) == 36 and len(directory) == 32
                and len(witness) in (0, 2017), 'registration fixed trust fields')
        pins = Pins(sdk, state, VerificationKey(policy_root), int.from_bytes(head[:8], 'big'), head[8:],
                    read_device(i_root, i_head), read_device(r_root, r_head), directory)
        quality, fields = bundle_fields(bundle); require(quality == 2, 'registration supported prekey quality')
        value = cls(pins, Materials(document, signature, policy, *fields[:7]),
                    Pin(witness[:32], VerificationKey(witness[32:])) if witness else None)
        require(value.encode() == wire, 'registration input canonical encoding')
        return value

    def current(self, now):
        m = self.materials
        return BootstrapBundle.from_materials(m).verify(self.pins, m.sdk_document, m.sdk_signature, m.policy, now,
                                                        required_quality=2, witness_pin=self.witness)

    def original(self, digest, now):
        m = self.materials
        return BootstrapBundle.from_materials(m).verify_original(self.pins, m.sdk_document, m.sdk_signature, m.policy, now,
                    original_context=digest, required_quality=2, witness_pin=self.witness)
