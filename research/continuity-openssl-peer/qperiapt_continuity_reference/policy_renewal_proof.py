"""Independent two-root policy-only approval verification, never durable adoption.

The original journal owner must derive Scope from its protected state. Signature
verification cannot choose a predecessor, reserve a transition or release traffic.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .authority import HistoricalPolicy, PolicySnapshot
from .identity import Device
from .roster_protocol import checkpoint
from .wire import Reader, digest, ldh, require
from .witness import fixed

BODY_BYTES = 426
APPROVAL_BYTES = 4 + BODY_BYTES + 3373
MAX_APPROVAL = 8 + 2 * (2 + APPROVAL_BYTES)
DOMAIN = b"Q-PERIAPT-POLICY-RENEWAL-CANDIDATE/v1"


@dataclass(frozen=True)
class Scope:
    operation: bytes
    journal: bytes
    original_owner: bytes
    original_credential: bytes
    current_credential: bytes
    current_roster: bytes
    original_policy: bytes
    previous_policy: bytes
    previous_authorization: bytes | None = None

    def __post_init__(self):
        for field in (self.operation, self.journal, self.original_owner,
                      self.original_credential, self.current_credential):
            fixed(field, 32)
        for field in (self.current_roster, self.original_policy, self.previous_policy):
            checkpoint(field)
        if self.previous_authorization is None:
            require(self.previous_policy == self.original_policy, "policy renewal missing predecessor authorization")
        else:
            fixed(self.previous_authorization, 32)
            require(int.from_bytes(self.previous_policy[:8], "big") > int.from_bytes(self.original_policy[:8], "big"),
                    "policy renewal predecessor authorization scope")

    def wire(self):
        """Public request fields; an issuer must still check the original owner."""
        return (self.operation + self.journal + self.original_owner + self.original_credential
                + self.current_credential + self.current_roster + self.original_policy + self.previous_policy
                + bytes([self.previous_authorization is not None]) + (self.previous_authorization or bytes(32)))


def storage_owner(original: Device) -> bytes:
    pin = original.pin
    return ldh(b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/storage-owner",
               pin.account + pin.device + pin.generation.to_bytes(8, "big") + original.credential)


def statement_body(scope: Scope, original: HistoricalPolicy, previous: HistoricalPolicy,
                   target: HistoricalPolicy, original_device: Device, current_device: Device) -> bytes:
    """Canonical historical relation; no signing, current permission or adoption."""
    for policy in (original, previous, target):
        policy.verify_metadata()
    original.same_profile(previous)
    original.same_profile(target)
    first, current = original_device, current_device
    require((first.pin.root, first.pin.account, first.pin.device, first.pin.generation, first.key)
            == (current.pin.root, current.pin.account, current.pin.device, current.pin.generation, current.key),
            "policy renewal changes the original device identity")
    require(first.validity.start == current.validity.start and first.validity.end <= current.validity.end,
            "policy renewal credential lineage")
    require(scope.original_owner == storage_owner(first)
            and scope.original_credential == first.credential
            and scope.current_credential == current.credential
            and scope.current_roster == current.pin.checkpoint()
            and scope.original_policy == original.checkpoint()
            and scope.previous_policy == previous.checkpoint(), "policy renewal original or current scope differs")
    require(previous.validity.end >= original.validity.end
            and target.validity.end > previous.validity.end
            and target.version > previous.version, "policy renewal must extend the exact predecessor")
    target.check_external_signer(current.pin.root)
    target.check_external_signer(current.key)
    authority = digest(b"AUTHORITY", current.pin.account + current.pin.checkpoint() + original.family)
    require(current.authority == authority and first.authority == digest(
            b"AUTHORITY", first.pin.account + first.pin.checkpoint() + original.family),
            "policy renewal device family or authority differs")
    body = (b"QPPRNW01" + scope.operation + scope.journal + scope.original_owner
            + scope.original_credential + scope.current_credential + authority + original.family
            + scope.current_roster + scope.original_policy + scope.previous_policy + target.checkpoint()
            + bytes([scope.previous_authorization is not None]) + (scope.previous_authorization or bytes(32)) + b"\1")
    require(len(body) == BODY_BYTES, "policy renewal statement size")
    return body


@dataclass(frozen=True)
class HistoricalApproval:
    wire: bytes
    scope: Scope
    statement: bytes
    target: bytes


def verify_historical(wire: bytes, scope: Scope, original: HistoricalPolicy, previous: HistoricalPolicy,
                      target: HistoricalPolicy, original_device: Device, current_device: Device) -> HistoricalApproval:
    require(type(wire) is bytes and len(wire) == MAX_APPROVAL, "policy renewal container size")
    reader = Reader(wire)
    require(reader.take(8) == b"QPPRNB01", "policy renewal container tag")
    approvals = []
    for _ in range(2):
        require(reader.integer(2) == APPROVAL_BYTES, "policy renewal approval size")
        approvals.append(reader.take(APPROVAL_BYTES))
    reader.finish()
    expected = statement_body(scope, original, previous, target, original_device, current_device)
    account = current_device.pin.root.open(approvals[0], 17, BODY_BYTES)
    policy = original.root.open(approvals[1], 17, BODY_BYTES)
    require(account == policy == expected, "policy renewal roots approved different original decisions")
    return HistoricalApproval(wire, scope, ldh(DOMAIN, expected), target.checkpoint())


def verify_current(wire: bytes, scope: Scope, original: HistoricalPolicy, previous: HistoricalPolicy,
                   target: PolicySnapshot, original_device: Device, current_device: Device,
                   now: int) -> HistoricalApproval:
    """Check current target/C/R as well; result still grants no durable owner."""
    require(type(target) is PolicySnapshot, "policy renewal needs independently current target inputs")
    history = verify_historical(wire, scope, original, previous, target.history, original_device, current_device)
    target.history.validity.check(now)
    current_device.validity.check(now)
    current_device.roster_validity.check(now)
    return history
