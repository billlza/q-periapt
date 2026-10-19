"""Reference-host JSON adapters; trust inputs are supplied independently of replies.

These are application interchange files, not a new signed protocol. Constructors
named from_trusted require an authenticated host/operator provisioning channel.
No account login, cookie, private key or current-state default is inferred here.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import base64
import json
from .authority import PolicyPins, PolicyMaterials, authenticate_policy
from .identity import DevicePin, credential, roster
from .registration_protocol import Intent
from .wire import Interval, VerificationKey, digest, generation, require
from .witness import Pin


def decode(raw, fields, limit=128 * 1024):
    require(type(raw) is bytes and 0 < len(raw) <= limit, 'exchange JSON capacity')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate exchange field'); result[key] = value
        return result
    def invalid_number(_value): raise ValueError('exchange fields require exact integers')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                       parse_float=invalid_number, parse_constant=invalid_number)
    shape(value, fields)
    return value


def shape(value, fields):
    require(type(value) is dict and set(value) == set(fields.split()), 'exchange field set')


def encoded(value, maximum, exact=None):
    require(type(value) is str and 0 < len(value) <= ((maximum + 2) // 3) * 4,
            'exchange byte field capacity')
    require(all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in value),
            'exchange requires unpadded base64url')
    result = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    require(len(result) <= maximum and (exact is None or len(result) == exact)
            and base64.urlsafe_b64encode(result).rstrip(b'=').decode() == value, 'exchange canonical byte field')
    return result


def identifier(value, size=32):
    require(type(value) is list and len(value) == size
            and all(type(byte) is int and 0 <= byte <= 255 for byte in value) and any(value),
            'exchange identity shape')
    return bytes(value)


def checkpoint(value):
    shape(value, 'version digest')
    return counter(value['version']), identifier(value['digest'])


def counter(value):
    require(type(value) is int, 'exchange counter type')
    return generation(value)


def host_revision(value):
    require(type(value) is int and 0 < value <= (1 << 64) - 1, 'host revision type or range')
    return value


@dataclass(frozen=True)
class HostAuthority:
    application: bytes
    revision: int
    root: VerificationKey
    family: bytes

    @classmethod
    def from_trusted(cls, raw):
        value = decode(raw, 'schema application root_revision root family', 16384)
        require(value['schema'] == 'qperiapt-host-authority/1', 'host authority schema')
        return cls(identifier(value['application']), host_revision(value['root_revision']),
                   VerificationKey(encoded(value['root'], 1985, 1985)), identifier(value['family']))


@dataclass(frozen=True)
class HostInvitation:
    operation: bytes
    correlation: bytes
    application: bytes
    revision: int
    intent: Intent
    deadline: int
    predecessor: tuple[int, bytes] | None

    @classmethod
    def decode(cls, raw, authority):
        value = decode(raw, 'operation request_id application root_revision root family device generation valid_from valid_until deadline predecessor', 16384)
        root = VerificationKey(encoded(value['root'], 1985, 1985))
        application, family = identifier(value['application']), identifier(value['family'])
        revision = host_revision(value['root_revision'])
        require(application == authority.application and revision == authority.revision
                and root == authority.root and family == authority.family, 'invitation differs from independent host authority')
        intent = Intent(root, identifier(value['device'], 16), counter(value['generation']),
                        Interval(value['valid_from'], value['valid_until']), family)
        require(type(value['deadline']) is int and intent.validity.start < value['deadline'] <= intent.validity.end,
                'host approval interval')
        prior = None if value['predecessor'] is None else checkpoint(value['predecessor'])
        return cls(identifier(value['operation']), identifier(value['request_id']), application,
                   revision, intent, value['deadline'], prior)

    def same_device(self, other):
        require(self.application == other.application and self.revision == other.revision
                and self.intent == other.intent, 'approved successor changes original device intent')


@dataclass(frozen=True)
class PolicyInputs:
    pins: PolicyPins
    materials: PolicyMaterials
    witness: Pin | None

    @classmethod
    def from_trusted(cls, pins, materials):
        expected = decode(pins, 'schema sdk_root sdk_state policy_root policy_version policy_digest witness', 16384)
        received = decode(materials, 'schema sdk_document sdk_signature policy')
        require(expected['schema'] == 'qperiapt-policy-pins/1'
                and received['schema'] == 'qperiapt-policy-materials/1', 'policy exchange schema')
        witness = None
        if expected['witness'] is not None:
            shape(expected['witness'], 'identity key')
            witness = Pin(identifier(expected['witness']['identity']),
                          VerificationKey(encoded(expected['witness']['key'], 1985, 1985)))
        pins = PolicyPins(encoded(expected['sdk_root'], 1952, 1952), encoded(expected['sdk_state'], 36, 36),
                          VerificationKey(encoded(expected['policy_root'], 1985, 1985)),
                          counter(expected['policy_version']), identifier(expected['policy_digest']))
        materials = PolicyMaterials(encoded(received['sdk_document'], 65536),
                                    encoded(received['sdk_signature'], 3309, 3309), encoded(received['policy'], 8192))
        return cls(pins, materials, witness)

    def verify(self, authority, now):
        policy = authenticate_policy(self.pins, self.materials, now, witness_pin=self.witness)
        require(policy.family == authority.family, 'live policy belongs to another host family')
        return policy


@dataclass(frozen=True)
class CurrentMembership:
    authority: HostAuthority
    version: int
    digest: bytes
    wire: bytes
    issuance_suspended: bool

    @classmethod
    def from_trusted(cls, raw, authority):
        value = decode(raw, 'revision account public_key family suspended roster')
        require(host_revision(value['revision']) == authority.revision
                and encoded(value['public_key'], 1985, 1985) == authority.root.raw
                and identifier(value['family']) == authority.family
                and identifier(value['account']) == digest(b'ACCOUNT', authority.root.raw),
                'current membership differs from independent host authority')
        require(type(value['suspended']) is bool, 'issuance suspension flag')
        shape(value['roster'], 'checkpoint bytes')
        version, commitment = checkpoint(value['roster']['checkpoint'])
        return cls(authority, version, commitment, encoded(value['roster']['bytes'], 8192), value['suspended'])

    def pin(self, invitation):
        require(invitation.application == self.authority.application and invitation.revision == self.authority.revision
                and invitation.intent.root == self.authority.root and invitation.intent.family == self.authority.family,
                'membership and invitation differ')
        return DevicePin(self.authority.root, digest(b'ACCOUNT', self.authority.root.raw), self.version,
                         self.digest, invitation.intent.device, invitation.intent.generation)


@dataclass(frozen=True)
class IssuedEnrollment:
    operation: bytes
    revision: int
    certificate: bytes
    historical_roster: bytes
    version: int
    digest: bytes

    @classmethod
    def decode(cls, raw):
        value = decode(raw, 'operation root_revision certificate roster checkpoint', 32768)
        version, commitment = checkpoint(value['checkpoint'])
        return cls(identifier(value['operation']), host_revision(value['root_revision']),
                   encoded(value['certificate'], 8192), encoded(value['roster'], 8192), version, commitment)

    def verify_history(self, invitation):
        require(self.operation == invitation.operation and self.revision == invitation.revision,
                'issued response differs from independently approved operation')
        intent = invitation.intent
        pin = DevicePin(intent.root, digest(b'ACCOUNT', intent.root.raw), self.version, self.digest,
                        intent.device, intent.generation)
        cert = credential(pin, self.certificate, intent.family)
        listing = roster(pin, self.historical_roster, expected=pin.checkpoint())
        require(cert.validity == intent.validity and listing.contains(pin, cert.digest), 'historical issuance differs from original grant')


def accept_issued(owner, original, approved, issued, current, policy, now):
    """Admit with an independent current pin, never the reply's historical head.

    Host deadlines constrain host approval/issuance, not recovery of a committed
    grant. Credential, roster and signed-policy validity are checked at `now`.
    Issuer suspension is an issuance fence, not device revocation; live roster
    membership and policy determine acceptance of an already-issued credential.
    """
    original.same_device(approved)
    policy.verify(current.authority, now)
    issued.verify_history(approved)
    return owner.accept(issued.certificate, current.wire, current.pin(approved), policy.pins,
                        policy.materials, now, witness_pin=policy.witness)
