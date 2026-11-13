"""Independent historical directory receipts and attributable key-reuse evidence.

A service pin must be provisioned separately. These signatures assert an
allocation; historical verification does not grant current use, prove durable
occupancy, authenticate a requester, or establish receiver consumption.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .authority import SUITE
from .kem import SdkBinding
from .wire import Interval, Reader, VerificationKey, generation, ldh, nonzero, require

BODY_BYTES = 1796
LEASE_BYTES = 5173
CONFLICT_BYTES = 10354
PURPOSE = 39
AUTHORITY_DOMAIN = b'Q-PERIAPT-CONTINUITY-DIRECTORY-AUTHORITY/v1'
STATEMENT_DOMAIN = b'Q-PERIAPT-CONTINUITY-DIRECTORY-LEASE-STATEMENT/v1'
KEY_DOMAIN = b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLIC-CANDIDATE/v1'


def key_fingerprint(algorithm, public):
    require(type(algorithm) is int and algorithm in (1, 2), 'directory key algorithm')
    require(type(public) is bytes and len(public) == (32 if algorithm == 1 else 1184)
            and any(public), 'directory public key shape')
    return ldh(KEY_DOMAIN, bytes([algorithm]) + public)


@dataclass(frozen=True)
class LeaseStatement:
    service: bytes
    operation: bytes
    requester: bytes
    checkpoint: bytes
    account: bytes
    device: bytes
    generation: int
    credential: bytes
    authority: bytes
    manifest: bytes
    selection: bytes
    epoch: int
    family: bytes
    policy_version: int
    policy_digest: bytes
    sdk: SdkBinding
    validity: Interval
    classical: bytes
    pq: bytes
    classical_fingerprint: bytes
    pq_fingerprint: bytes

    @classmethod
    def decode(cls, body):
        require(type(body) is bytes and len(body) == BODY_BYTES, 'directory statement size')
        r = Reader(body)
        require(r.take(8) == b'QPDLSE01', 'directory statement tag')
        service, operation, requester, checkpoint, account = (nonzero(r.take(32)) for _ in range(5))
        device, revision = nonzero(r.take(16)), generation(r.integer(8))
        credential, authority, manifest, selection = (nonzero(r.take(32)) for _ in range(4))
        epoch, family, version = generation(r.integer(8)), nonzero(r.take(32)), generation(r.integer(8))
        policy_digest = nonzero(r.take(32))
        sdk_root, sdk_version, sdk_digest = nonzero(r.take(32)), r.integer(4), r.take(32)
        sdk = SdkBinding(sdk_version, sdk_digest, sdk_root)
        require(r.take(32) == SUITE, 'directory statement suite')
        validity = Interval.read(r)
        classical, pq = nonzero(r.take(32)), nonzero(r.take(1184))
        classical_fingerprint, pq_fingerprint = r.take(32), r.take(32)
        r.finish()
        require(classical_fingerprint == key_fingerprint(1, classical)
                and pq_fingerprint == key_fingerprint(2, pq), 'directory key fingerprint binding')
        return cls(service, operation, requester, checkpoint, account, device, revision,
                   credential, authority, manifest, selection, epoch, family, version,
                   policy_digest, sdk, validity, classical, pq, classical_fingerprint, pq_fingerprint)

    def encode(self):
        """Canonical public statement bytes; this does not add a signature."""
        u64 = lambda n: n.to_bytes(8, 'big')
        return (b'QPDLSE01' + self.service + self.operation + self.requester + self.checkpoint
                + self.account + self.device + u64(self.generation) + self.credential
                + self.authority + self.manifest + self.selection + u64(self.epoch)
                + self.family + u64(self.policy_version) + self.policy_digest + self.sdk.wire()
                + SUITE + u64(self.validity.start) + u64(self.validity.end) + self.classical + self.pq
                + self.classical_fingerprint + self.pq_fingerprint)


@dataclass(frozen=True)
class VerifiedDirectoryLease:
    """Authenticated historical assertion, not an opaque admission capability."""
    statement: LeaseStatement
    statement_digest: bytes
    wire: bytes


@dataclass(frozen=True)
class DirectoryPin:
    """Exact service identity/key from an independent provisioning channel."""
    identity: bytes
    key: VerificationKey

    def __post_init__(self):
        require(type(self.identity) is bytes and len(self.identity) == 32 and any(self.identity)
                and type(self.key) is VerificationKey, 'independent directory service pin')

    @property
    def binding(self):
        return ldh(AUTHORITY_DOMAIN, self.identity + self.key.raw)

    def verify_historical_lease(self, wire):
        """Verify historical signatures and shape; deliberately no current-time input."""
        require(type(wire) is bytes and len(wire) == LEASE_BYTES, 'directory receipt size')
        body = self.key.open(wire, PURPOSE, BODY_BYTES)
        statement = LeaseStatement.decode(body)
        require(statement.service == self.binding, 'directory receipt service differs')
        return VerifiedDirectoryLease(statement, ldh(STATEMENT_DOMAIN, body), wire)


@dataclass(frozen=True)
class DirectoryLeaseConflict:
    first: VerifiedDirectoryLease
    second: VerifiedDirectoryLease
    classical: bool
    pq: bool

    @classmethod
    def verify(cls, pin, first, second):
        a, b = pin.verify_historical_lease(first), pin.verify_historical_lease(second)
        # Compare immutable bodies, not signatures: randomized re-signing is not
        # another allocation and cannot create evidence against the service.
        require(a.statement != b.statement, 'identical directory allocation is not a conflict')
        classical = (a.statement.classical_fingerprint == b.statement.classical_fingerprint
                     and a.statement.classical == b.statement.classical)
        pq = (a.statement.pq_fingerprint == b.statement.pq_fingerprint
              and a.statement.pq == b.statement.pq)
        require(classical or pq, 'directory allocations do not share a one-time public key')
        a, b = sorted((a, b), key=lambda item: (item.statement_digest, item.wire))
        return cls(a, b, classical, pq)

    @classmethod
    def from_bytes(cls, pin, wire):
        require(type(wire) is bytes and len(wire) == CONFLICT_BYTES, 'directory conflict size')
        r = Reader(wire)
        require(r.take(8) == b'QPDLCF01', 'directory conflict tag')
        first, second = r.take(LEASE_BYTES), r.take(LEASE_BYTES)
        r.finish()
        proof = cls.verify(pin, first, second)
        require(proof.to_bytes() == wire, 'noncanonical directory conflict order')
        return proof

    def to_bytes(self):
        """Stable statement-digest/full-wire order; archival decoding requires it."""
        return b'QPDLCF01' + self.first.wire + self.second.wire
