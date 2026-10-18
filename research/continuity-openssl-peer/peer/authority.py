"""Verify public bootstrap materials against separately supplied trust inputs.

This first peer accepts only the explicit local-only, two-leaf reusable profile.
Unsupported profiles fail; parsing never supplies a durable admission decision.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import mldsa

from .kem import SdkBinding
from .wire import (Interval, Reader, VerificationKey, digest, generation, ldh,
                   lp, nonzero, require)

SUITE = digest(b"BOOTSTRAP-SUITE", b"ML-KEM-768+X25519/ContextBound;"
               b"ML-DSA-65+P-256/SHA-256;HKDF-SHA-256;HMAC-SHA-256")


@dataclass(frozen=True)
class DevicePin:
    root: VerificationKey
    account: bytes
    roster_version: int
    roster_digest: bytes
    device: bytes
    generation: int


@dataclass(frozen=True)
class Pins:
    sdk_root: bytes
    sdk_state: bytes
    policy_root: VerificationKey
    policy_version: int
    policy_digest: bytes
    initiator: DevicePin
    responder: DevicePin
    directory: bytes


@dataclass(frozen=True)
class Materials:
    sdk_document: bytes
    sdk_signature: bytes
    policy: bytes
    initiator_credential: bytes
    initiator_roster: bytes
    responder_credential: bytes
    responder_roster: bytes
    manifest: bytes
    classical_proof: bytes
    pq_proof: bytes


@dataclass(frozen=True)
class Device:
    key: VerificationKey
    pin: DevicePin
    credential: bytes
    validity: Interval
    roster_validity: Interval
    authority: bytes

    def context(self) -> bytes:
        return (self.pin.account + self.pin.device + self.pin.generation.to_bytes(8, "big")
                + self.credential + self.authority)


def verify_device(pin: DevicePin, credential: bytes, roster: bytes,
                  family: bytes, now: int) -> Device:
    require(len(pin.device) == 16 and any(pin.device), "expected device identity")
    generation(pin.generation)
    require(pin.account == digest(b"ACCOUNT", pin.root.raw), "account root pin")
    cert = pin.root.open(credential, 1, 2097)
    reader = Reader(cert)
    require(reader.take(8) == b"QPCERT01" and reader.take(32) == pin.account
            and reader.take(16) == pin.device and reader.integer(8) == pin.generation,
            "credential identity differs from intended device")
    validity = Interval.read(reader)
    validity.check(now)
    require(reader.take(32) == family, "credential policy family")
    key = VerificationKey(reader.take(1985))
    reader.finish()
    require(not key.shares_component(pin.root), "device/account signing key separation")
    credential_digest = digest(b"CREDENTIAL", cert)
    body = pin.root.open(roster, 2)
    require(digest(b"ROSTER", body) == pin.roster_digest, "roster digest pin")
    reader = Reader(body)
    require(reader.take(8) == b"QPROST01" and reader.take(32) == pin.account,
            "roster account")
    version = generation(reader.integer(8))
    require(version == pin.roster_version, "roster version pin")
    roster_validity = Interval.read(reader)
    roster_validity.check(now)
    count = reader.integer(2)
    require(count <= 32, "roster count")
    previous, found = b"", False
    for _ in range(count):
        device = nonzero(reader.take(16))
        revision = generation(reader.integer(8))
        commitment = nonzero(reader.take(32))
        require(device > previous, "roster device order or duplicate")
        previous = device
        if device == pin.device:
            require(revision == pin.generation and commitment == credential_digest,
                    "roster does not authorize exact credential")
            found = True
    reader.finish()
    require(found, "device absent from current roster")
    authority = digest(b"AUTHORITY", pin.account + version.to_bytes(8, "big")
                       + pin.roster_digest + family)
    return Device(key, pin, credential_digest, validity, roster_validity, authority)


def verify_sdk(pins: Pins, materials: Materials) -> SdkBinding:
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

    def check(self, now: int) -> None:
        for interval in self.intervals:
            interval.check(now)


def authenticate(pins: Pins, materials: Materials, now: int) -> Context:
    sdk = verify_sdk(pins, materials)
    family = digest(b"POLICY-AUTHORITY", pins.policy_root.raw)
    body = pins.policy_root.open(materials.policy, 4, 200)
    require(digest(b"SESSION-POLICY", body) == pins.policy_digest, "protocol policy digest pin")
    reader = Reader(body)
    require(reader.take(8) == b"QPSESP03" and reader.take(32) == family, "policy family")
    version = generation(reader.integer(8))
    require(version == pins.policy_version, "protocol policy version pin")
    validity = Interval.read(reader)
    validity.check(now)
    require(reader.take(32) == SUITE and reader.take(68) == sdk.wire(), "policy SDK/suite binding")
    modes = reader.integer(1)
    require(modes & ~15 == 0 and modes & 2 != 0, "reusable quality not permitted")
    require(reader.integer(1) == 0 and reader.take(32) == bytes(32),
            "volatile peer cannot admit required-witness profile")
    require(reader.integer(2) != 0, "zero send allowance")
    reader.finish()
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
                    responder.roster_validity, manifest_time, classical[3], pq[3]), selection)
