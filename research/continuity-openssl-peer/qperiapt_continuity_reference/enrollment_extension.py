"""Independent approval and signed issuance for a reference-host extension."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass, replace
import json
from .enrollment_exchange import decode, shape, identifier, checkpoint, encoded, host_revision
from .identity import DevicePin, credential, roster
from .wire import Interval, MAX_U64, digest, require


def monotonic(target, previous, label):
    require(type(target) is bytes and type(previous) is bytes and len(target) == len(previous) == 40,
            label + ' checkpoint shape')
    current, old = int.from_bytes(target[:8], 'big'), int.from_bytes(previous[:8], 'big')
    require(0 < old <= current < MAX_U64 and (current > old or target == previous),
            label + ' rollback or same-version fork')


@dataclass(frozen=True)
class ExtensionApproval:
    identity: bytes
    enrollment: bytes
    previous: bytes | None
    predecessor: bytes
    until: int

    @classmethod
    def from_value(cls, value):
        shape(value, 'request_id enrollment previous_extension predecessor valid_until')
        identity, enrollment = identifier(value['request_id']), identifier(value['enrollment'])
        previous = None if value['previous_extension'] is None else identifier(value['previous_extension'])
        version, commitment = checkpoint(value['predecessor'])
        until = value['valid_until']
        require(previous != identity and type(until) is int and 0 < until < MAX_U64,
                'extension identity or finite validity')
        return cls(identity, enrollment, previous, version.to_bytes(8, 'big') + commitment, until)

    @classmethod
    def from_trusted(cls, raw):
        """The host must authenticate this exact approval independently of a reply."""
        return cls.from_value(decode(raw, 'request_id enrollment previous_extension predecessor valid_until', 2048))

    def wire(self):
        return json.dumps({'request_id':list(self.identity), 'enrollment':list(self.enrollment),
                           'previous_extension':None if self.previous is None else list(self.previous),
                           'predecessor':{'version':int.from_bytes(self.predecessor[:8], 'big'),
                                          'digest':list(self.predecessor[8:])},
                           'valid_until':self.until}, separators=(',', ':')).encode()


def verify_history(approval, certificate, signed_roster, head, intent):
    require(len(head) == 40 and int.from_bytes(head[:8], 'big') == int.from_bytes(approval.predecessor[:8], 'big') + 1,
            'extension issuance checkpoint must succeed its approved predecessor')
    granted = replace(intent, validity=Interval(intent.validity.start, approval.until))
    pin = DevicePin(intent.root, digest(b'ACCOUNT', intent.root.raw), int.from_bytes(head[:8], 'big'), head[8:],
                    intent.device, intent.generation)
    cert = credential(pin, certificate, intent.family)
    listing = roster(pin, signed_roster, expected=head)
    require(cert.validity == granted.validity and listing.contains(pin, cert.digest)
            and max(cert.validity.start, listing.validity.start) < min(cert.validity.end, listing.validity.end),
            'extension signed history differs from approved validity or membership')
    return granted, cert


@dataclass(frozen=True)
class IssuedExtension:
    approval: ExtensionApproval
    revision: int
    certificate: bytes
    roster: bytes
    checkpoint: bytes

    @classmethod
    def decode(cls, raw):
        value = decode(raw, 'request root_revision certificate roster checkpoint', 32768)
        version, commitment = checkpoint(value['checkpoint'])
        return cls(ExtensionApproval.from_value(value['request']), host_revision(value['root_revision']),
                   encoded(value['certificate'], 8192), encoded(value['roster'], 8192),
                   version.to_bytes(8, 'big') + commitment)

    def verify(self, approval, intent):
        require(self.approval == approval, 'extension response differs from independent approval')
        return verify_history(approval, self.certificate, self.roster, self.checkpoint, intent)
