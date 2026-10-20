"""Verify public bootstrap materials against separately supplied trust inputs.

This peer accepts explicitly selected local or witnessed two-leaf reusable profiles.
Unsupported profiles fail; parsing never supplies a durable admission decision.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .identity_state import IdentityState

from cryptography.hazmat.primitives.asymmetric import mldsa

from .kem import SdkBinding
from .identity import DevicePin, Device, verify_device
from .witness import Profile
from .wire import (Interval, Reader, VerificationKey, digest, generation, ldh,
                   lp, nonzero, require)

SUITE = digest(b"BOOTSTRAP-SUITE", b"ML-KEM-768+X25519/ContextBound;"
               b"ML-DSA-65+P-256/SHA-256;HKDF-SHA-256;HMAC-SHA-256")


@dataclass(frozen=True)
class PolicyPins:
    sdk_root: bytes
    sdk_state: bytes
    policy_root: VerificationKey
    policy_version: int
    policy_digest: bytes


@dataclass(frozen=True)
class Pins(PolicyPins):
    initiator: DevicePin
    responder: DevicePin
    directory: bytes


@dataclass(frozen=True)
class PolicyMaterials:
    sdk_document: bytes
    sdk_signature: bytes
    policy: bytes


@dataclass(frozen=True)
class Materials(PolicyMaterials):
    initiator_credential: bytes
    initiator_roster: bytes
    responder_credential: bytes
    responder_roster: bytes
    manifest: bytes
    classical_proof: bytes
    pq_proof: bytes


def verify_sdk(pins: PolicyPins, materials: PolicyMaterials) -> SdkBinding:
    document = materials.sdk_document
    require(len(document) <= 65536 and len(pins.sdk_root) == 1952, "SDK material bounds")
    message = b"Q-PERIAPT-SIGNED-POLICY/v1" + len(document).to_bytes(8, "big") + document
    mldsa.MLDSA65PublicKey.from_public_bytes(pins.sdk_root).verify(materials.sdk_signature, message)
    policy = tomllib.loads(document.decode("utf-8"))
    # Explicitly narrow supported algorithm policy. Future schemas cannot be
    # silently accepted through ignored fields or provider negotiation.
    require(set(policy) == {"schema_version", "policy_version", "min_nist_level",
                           "default_profile", "allowed_kems", "allowed_sigs", "deprecated"},
            "unsupported SDK policy fields")
    require(type(policy["schema_version"]) is int and policy["schema_version"] == 1
            and type(policy["policy_version"]) is int
            and type(policy["min_nist_level"]) is int and policy["min_nist_level"] == 3
            and policy["default_profile"] == "ContextBound"
            and policy["allowed_kems"] == ["ML-KEM-768", "X25519"]
            and policy["allowed_sigs"] == ["ML-DSA-65"] and policy["deprecated"] == [],
            "unsupported SDK policy profile")
    sdk = SdkBinding(policy["policy_version"], hashlib.sha3_256(document).digest(),
                     hashlib.sha256(pins.sdk_root).digest())
    require(sdk.state() == pins.sdk_state, "SDK state pin")
    return sdk


@dataclass(frozen=True)
class Context:
    sdk: SdkBinding
    digest: bytes
    initiator: VerificationKey
    responder: VerificationKey
    responder_prekey: bytes
    intervals: tuple[Interval, ...]
    selection: bytes
    send_budget: int
    witness: Profile | None = None
    devices: tuple[Device, Device] | None = None
    family: bytes = bytes(32)
    policy_digest: bytes = bytes(32)
    current_peer: IdentityState | None = None
    current_local: IdentityState | None = None
    # Zero denotes absent metadata in legacy synthetic contexts, never authority.
    policy_version: int = 0
    original_policy: HistoricalPolicy | None = None
    current_policy: HistoricalPolicy | None = None

    def check(self, now: int) -> None:
        for interval in self.intervals:
            interval.check(now)

    def check_established(self, now: int) -> None:
        # The first five windows are policy, two credentials and two rosters.
        # Advertisement/leaf expiry gates bootstrap, not established traffic.
        (self.intervals[0] if self.current_policy is None else self.current_policy.validity).check(now)
        if self.current_local is None:
            for interval in self.intervals[1:3]:
                interval.check(now)
        else:
            self.current_local.check(now)
        if self.current_peer is None:
            for interval in self.intervals[3:5]:
                interval.check(now)
        else:
            self.current_peer.check(now)


@dataclass(frozen=True)
class HistoricalPolicy:
    sdk: SdkBinding
    family: bytes
    version: int
    digest: bytes
    validity: Interval
    budget: int
    modes: int
    anchor: bytes | None
    root: VerificationKey
    wire: bytes

    def checkpoint(self):
        return self.version.to_bytes(8, "big") + self.digest

    def verify_metadata(self):
        # Python objects are not opaque native verifier handles. Recheck their
        # canonical signed body at the approval boundary as well as on parsing.
        body = self.root.open(self.wire, 4, 200)
        expected = (b"QPSESP03" + self.family + self.version.to_bytes(8, "big")
                    + self.validity.start.to_bytes(8, "big") + self.validity.end.to_bytes(8, "big")
                    + SUITE + self.sdk.wire() + bytes([self.modes, self.anchor is not None])
                    + (self.anchor or bytes(32)) + self.budget.to_bytes(2, "big"))
        require(body == expected and self.family == digest(b"POLICY-AUTHORITY", self.root.raw)
                and self.digest == digest(b"SESSION-POLICY", body), "policy signed metadata differs")

    def same_profile(self, other):
        require((self.sdk, self.family, self.root, self.modes, self.anchor, self.budget, self.validity.start)
                == (other.sdk, other.family, other.root, other.modes, other.anchor, other.budget, other.validity.start),
                "policy renewal changes the original profile")

    def check_external_signer(self, key):
        require(not key.shares_component(self.root)
                and hashlib.sha256(key.raw[:1952]).digest() != self.sdk.root_digest,
                "policy renewal signer separation")

    def authenticate_retained(self, wire):
        """Authenticate a stored same-profile policy, without selecting live trust.

        Incoming updates still need their independently pinned current snapshot.
        This method is for reconstructing an already authenticated journal record.
        """
        self.verify_metadata()
        body = self.root.open(wire, 4, 200)
        r = Reader(body)
        require(r.take(8) == b"QPSESP03" and r.take(32) == self.family, "retained policy family")
        version, validity = generation(r.integer(8)), Interval.read(r)
        require(r.take(32) == SUITE and r.take(68) == self.sdk.wire(), "retained policy SDK/suite")
        modes, anchored, binding, budget = r.integer(1), r.integer(1), r.take(32), r.integer(2)
        r.finish()
        require(anchored == (self.anchor is not None) and binding == (self.anchor or bytes(32)),
                "retained policy witness differs")
        value = HistoricalPolicy(self.sdk, self.family, version, digest(b"SESSION-POLICY", body),
                                 validity, budget, modes, self.anchor, self.root, wire)
        self.same_profile(value)
        return value


@dataclass(frozen=True)
class PolicySnapshot:
    sdk: SdkBinding
    family: bytes
    version: int
    digest: bytes
    validity: Interval
    budget: int
    history: HistoricalPolicy

    def __post_init__(self):
        require((self.sdk, self.family, self.version, self.digest, self.validity, self.budget)
                == (self.history.sdk, self.history.family, self.history.version,
                    self.history.digest, self.history.validity, self.history.budget),
                "current policy snapshot metadata differs")


def authenticate_historical_policy(pins: PolicyPins, wire: bytes, *, witness_pin=None) -> HistoricalPolicy:
    """Verify immutable signed metadata and retained pins, with no current grant."""
    require(len(pins.sdk_root) == 1952 and len(pins.sdk_state) == 36, "historical SDK binding pins")
    sdk = SdkBinding(int.from_bytes(pins.sdk_state[:4], "big"), pins.sdk_state[4:],
                     hashlib.sha256(pins.sdk_root).digest())
    family = digest(b"POLICY-AUTHORITY", pins.policy_root.raw)
    body = pins.policy_root.open(wire, 4, 200)
    require(digest(b"SESSION-POLICY", body) == pins.policy_digest, "protocol policy digest pin")
    reader = Reader(body)
    require(reader.take(8) == b"QPSESP03" and reader.take(32) == family, "policy family")
    version = generation(reader.integer(8))
    require(version == pins.policy_version, "protocol policy version pin")
    validity = Interval.read(reader)
    require(reader.take(32) == SUITE and reader.take(68) == sdk.wire(), "policy SDK/suite binding")
    modes = reader.integer(1)
    require(modes & ~15 == 0 and modes & 2 != 0, "reusable quality not permitted")
    anchor_mode, anchor_binding = reader.integer(1), reader.take(32)
    if witness_pin is None:
        require(anchor_mode == 0 and anchor_binding == bytes(32),
                "volatile peer cannot admit required-witness profile")
    else:
        require(anchor_mode == 1 and anchor_binding == witness_pin.binding, "required witness pin differs")
        require(not witness_pin.key.shares_component(pins.policy_root)
                and witness_pin.key.raw[:1952] != pins.sdk_root, "witness/policy key separation")
    budget = reader.integer(2)
    require(budget != 0, "zero send allowance")
    reader.finish()
    return HistoricalPolicy(sdk, family, version, pins.policy_digest, validity, budget,
                            modes, anchor_binding if anchor_mode else None, pins.policy_root, wire)


def authenticate_policy(pins: PolicyPins, materials: PolicyMaterials, now: int, *, witness_pin=None) -> PolicySnapshot:
    sdk = verify_sdk(pins, materials)
    history = authenticate_historical_policy(pins, materials.policy, witness_pin=witness_pin)
    require(history.sdk == sdk, "current policy SDK binding")
    history.validity.check(now)
    return PolicySnapshot(sdk, history.family, history.version, history.digest,
                          history.validity, history.budget, history)


def authenticate(pins: Pins, materials: Materials, now: int, *, witness_pin=None) -> Context:
    policy = authenticate_policy(pins, materials, now, witness_pin=witness_pin)
    sdk, family, version, validity, budget = policy.sdk, policy.family, policy.version, policy.validity, policy.budget
    initiator = verify_device(pins.initiator, materials.initiator_credential,
                              materials.initiator_roster, family, now)
    responder = verify_device(pins.responder, materials.responder_credential,
                              materials.responder_roster, family, now)
    require((pins.initiator.account, pins.initiator.device)
            != (pins.responder.account, pins.responder.device), "same device in both roles")
    require(not initiator.key.shares_component(responder.key), "peer signing key separation")
    for device in (initiator, responder):
        require(not device.key.shares_component(pins.policy_root)
                and device.key.raw[:1952] != pins.sdk_root, "device/policy key separation")
    witness = None
    if witness_pin is not None:
        for device in (initiator, responder):
            require(not witness_pin.key.shares_component(device.key)
                    and not witness_pin.key.shares_component(device.pin.root), "witness/device/account key separation")
        owner = ldh(b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/storage-owner",
                    pins.initiator.account + pins.initiator.device + pins.initiator.generation.to_bytes(8, "big")
                    + initiator.credential)
        witness = Profile(witness_pin, owner, pins.policy_digest, initiator.authority)
    manifest = responder.key.open(materials.manifest, 3, 290)
    r = Reader(manifest)
    require(r.take(8) == b"QPMANF01", "manifest tag")
    scope = r.take(248)
    count = r.integer(2)
    root = nonzero(r.take(32))
    r.finish()
    require(count == 2, "this peer requires the explicit two-leaf reusable profile")
    r = Reader(scope)
    require(r.take(32) == pins.responder.account and r.take(16) == pins.responder.device
            and r.integer(8) == pins.responder.generation and r.take(32) == responder.credential
            and r.integer(8) == pins.responder.roster_version
            and r.take(32) == pins.responder.roster_digest, "manifest credential/roster scope")
    epoch = generation(r.integer(8))
    require(r.take(32) == sdk.policy_digest and r.take(32) == SUITE
            and r.take(32) == pins.directory and len(pins.directory) == 32
            and any(pins.directory), "manifest policy/directory scope")
    manifest_time = Interval.read(r)
    manifest_time.check(now)
    require(responder.validity.contains(manifest_time)
            and responder.roster_validity.contains(manifest_time), "manifest authority interval")
    r.finish()
    leaves = []
    for proof, kind, size in ((materials.classical_proof, 1, 32), (materials.pq_proof, 3, 1184)):
        r = Reader(proof)
        index = r.integer(2)
        leaf = r.take(r.integer(2))
        require(index < 2 and r.integer(1) == 1, "two-leaf proof path")
        sibling = r.take(32)
        r.finish()
        r = Reader(leaf)
        require(r.take(8) == b"QPLEAF01" and r.integer(1) == kind, "prekey kind")
        leaf_time = Interval.read(r)
        leaf_time.check(now)
        require(manifest_time.contains(leaf_time), "leaf authority interval")
        public = nonzero(r.take(size))
        r.finish()
        leaf_id = digest(b"PREKEY-LEAF", scope + leaf)
        pair = leaf_id + sibling if index == 0 else sibling + leaf_id
        require(digest(b"PREKEY-NODE", pair) == root, "prekey membership proof")
        leaves.append((index, leaf_id, public, leaf_time, sibling))
    classical, pq = leaves
    ordered = sorted(leaves)
    require(ordered[0][0] == 0 and ordered[1][0] == 1 and ordered[0][1] < ordered[1][1]
            and classical[4] == pq[1] and pq[4] == classical[1], "manifest order or duplicate")
    selection = b"".join(lp(field) for field in (
        b"Q-PERIAPT-CONTINUITY-PREKEY-SELECTION/v1", b"\0\1", SUITE,
        pins.responder.account, pins.responder.device, pins.responder.generation.to_bytes(8, "big"),
        responder.credential, epoch.to_bytes(8, "big"), pins.directory, digest(b"MANIFEST", manifest),
        b"\2", classical[1], classical[1], b"\2", pq[1], pq[1]))
    require(len(selection) == 492, "selection canonical size")
    context = ldh(b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/context",
                  SUITE + family + version.to_bytes(8, "big") + pins.policy_digest + sdk.wire()
                  + initiator.context() + responder.context() + selection + pins.directory)
    return Context(sdk, context, initiator.key, responder.key, pq[2] + classical[2],
                   (validity, initiator.validity, initiator.roster_validity, responder.validity,
                    responder.roster_validity, manifest_time, classical[3], pq[3]), selection, budget, witness, (initiator, responder), family, pins.policy_digest,
                   policy_version=version, original_policy=policy.history)
