"""Authenticated original renewal coordination; never a witness or output permit."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hmac
from .local_renewal_protocol import Proposal
from .wire import Reader, MAX_U64, require
from .roster_control import Control as RosterControl
from .policy_control import Control as PolicyControl

DOMAIN = b"Q-PERIAPT-INDEPENDENT-LOCAL-AUTHORITY/v1/"


@dataclass(frozen=True)
class Control:
    # 0 initial; 1 pending; 2/3 durable Applied/Closed before ACK cleanup;
    # 4/5 terminal Applied/Closed after cleanup. Terminal identity survives ACK.
    phase: int = 0
    floor: int = 0
    active: bytes = bytes(32)
    proposal: Proposal | None = None
    checkpoint: bytes = bytes(40)
    account_binding: bytes | None = None
    active_account_binding: bytes | None = None
    roster: RosterControl | None = None
    policy: PolicyControl | None = None

    def __post_init__(self):
        require(type(self.phase) is int and self.phase in range(6) and type(self.floor) is int
                and 0 <= self.floor < MAX_U64 and type(self.active) is bytes and len(self.active) == 32,
                "local authority control shape")
        if self.phase == 0:
            require(self.floor == 0 and self.active == bytes(32) and self.proposal is None
                    and self.checkpoint == bytes(40) and self.account_binding is None
                    and self.active_account_binding is None, "initial authority control")
        else:
            require(self.proposal is not None and type(self.checkpoint) is bytes and len(self.checkpoint) == 40
                    and any(self.checkpoint[8:]), "retained renewal metadata")
            version = int.from_bytes(self.checkpoint[:8], "big")
            require(0 < version < MAX_U64 and (version > self.floor if self.phase == 1 else version == self.floor),
                    "renewal permanent floor")
            if self.phase in (2, 4):
                require(self.active == self.proposal.statement, "applied authority statement")
            else:
                require(self.active != self.proposal.statement, "unapplied target cannot be current")
        if self.account_binding is not None:
            require(type(self.account_binding) is bytes and len(self.account_binding) == 32
                    and any(self.account_binding), "complete account control binding")
            require((self.active == bytes(32)) == (self.active_account_binding is None),
                    "active account control presence")
            if self.active_account_binding is not None:
                require(type(self.active_account_binding) is bytes
                        and len(self.active_account_binding) == 32 and any(self.active_account_binding),
                        "active account control binding")
            if self.phase in (2, 4):
                require(self.active_account_binding == self.account_binding,
                        "applied complete account control")
        else:
            require(self.active_account_binding is None, "active account requires complete account mode")
        require(self.roster is None or self.roster.ready() or self.phase in (0, 4, 5),
                "overlapping credential and roster coordination")
        require(self.policy is None or self.policy.ready()
                or (self.phase in (0, 4, 5) and (self.roster is None or self.roster.ready())),
                "overlapping policy and credential/roster coordination")

    def ready(self):
        return (self.phase in (0, 4, 5) and (self.roster is None or self.roster.ready())
                and (self.policy is None or self.policy.ready()))

    def wire(self, scope):
        tag = b"QPRFLC01" if self.account_binding is None else b"QPRFLC02"
        if self.proposal is not None and self.proposal.policy is not None:
            tag = b"QPRFLC05" if self.account_binding is None else b"QPRFLC06"
        value = tag + scope.wire() + bytes([self.phase]) + self.floor.to_bytes(8, "big") + self.active
        if self.proposal is not None:
            value += self.proposal.wire() + self.checkpoint
        if self.account_binding is not None:
            value += self.account_binding + (self.active_account_binding or bytes(32))
        if self.roster is not None:
            value = b"QPRFLC03" + self.roster.wire() + value
        if self.policy is not None:
            value = b"QPRFLC04" + self.policy.wire() + value
        return value


def read(journal):
    data = journal._admit().read("authority")
    if data is None:
        return None
    sizes = (177, 513, 577, 546, 610)
    sizes += tuple(size + 483 for size in sizes)
    require(len(data) in sizes + tuple(size + 434 for size in sizes), "authority control size")
    body = data[:-32]
    require(hmac.compare_digest(hmac.digest(journal._intent_key, DOMAIN + body, "sha256"), data[-32:]),
            "authority control authentication")
    r = Reader(body)
    tag = r.take(8)
    policy = PolicyControl.read(r.take(426)) if tag == b"QPRFLC04" else None
    if policy is not None:
        tag = r.take(8)
    roster = RosterControl.read(r.take(475)) if tag == b"QPRFLC03" else None
    if roster is not None:
        tag = r.take(8)
    require(tag in (b"QPRFLC01", b"QPRFLC02", b"QPRFLC05", b"QPRFLC06")
            and r.take(96) == journal.scope.wire(), "authority control scope")
    phase, floor, active = r.integer(1), r.integer(8), r.take(32)
    continued = tag in (b"QPRFLC05", b"QPRFLC06")
    require(not continued or phase != 0, "continued credential control requires proposal")
    proposal = Proposal.decode(r.take(329 if continued else 296)) if phase else None
    checkpoint = r.take(40) if phase else bytes(40)
    binding = r.take(32) if tag in (b"QPRFLC02", b"QPRFLC06") else None
    active_binding = r.take(32) if tag in (b"QPRFLC02", b"QPRFLC06") else bytes(32)
    r.finish()
    if proposal is not None:
        require(hasattr(journal, "profile") and proposal.witness == journal.profile.pin.binding
                and proposal.subject == journal.subject and proposal.expected.fence == proposal.target.fence == 1,
                "authority original witness/subject")
    if roster is not None:
        p = roster.proposal
        require(p.witness == journal.profile.pin.binding and p.subject == journal.subject
                and p.expected.fence == p.target.fence == 1, "roster control original witness/subject")
    if policy is not None:
        p = policy.proposal
        require(p.witness == journal.profile.pin.binding and p.subject == journal.subject
                and p.expected.fence == p.target.fence == 1, "policy control original witness/subject")
    value = Control(phase, floor, active, proposal, checkpoint, binding,
                    None if active_binding == bytes(32) else active_binding, roster, policy)
    require(value.wire(journal.scope) == body, "noncanonical authority control")
    return value


def write(journal, control):
    body = control.wire(journal.scope)
    data = body + hmac.digest(journal._intent_key, DOMAIN + body, "sha256")
    suffix = str(control.phase) if control.roster is None else "r-" + str(control.roster.phase)
    if control.policy is not None:
        suffix = "p-" + str(control.policy.phase)
    journal._admit().publish("authority", data, fixed_slot="authority-" + suffix)
    require(read(journal) == control, "authority control durable readback")


def admit_snapshot(journal, state):
    if state.policy_renewal is not None:
        from .policy_snapshot import validate
        validate(state, state.operation._context, journal.scope.identity)
        require(state.policy_renewal.pending is None, "policy renewal remains pending")
    if state.operation._context.witness is None:
        require(journal._admit().read("authority") is None, "witness coordination in local-only store")
        if state.format_version in (9, 10):
            require(state.account_renewal is not None, "common account coordination absent")
            state.account_renewal.admit()
        elif state.format_version in (7, 8):
            require(state.local_renewal is not None, "local coordination absent")
            state.local_renewal.admit()
        else:
            require(state.local_authority is None and state.local_renewal is None,
                    "local-only authority requires atomic coordination")
        return
    require(state.local_renewal is None, "local coordination cannot bypass required witness")
    control = read(journal)
    from .policy_control import admit as admit_policy
    admit_policy(control, state)
    require(control is None or control.ready(), "local renewal coordination remains pending")
    admit_identity_control(state, control)


def admit_identity_control(state, control):
    """Check original G/R dependencies without granting any policy permission."""
    from .identity_state import local_view
    current = local_view(state, state.operation._context)
    require(state.local_renewal is None, "local coordination cannot bypass required witness")
    if control is None:
        require(current is None or current.renewal is None, "missing original local authority control")
        require(state.account_renewal is None or state.account_renewal.roster is None,
                "missing original roster control")
        return
    require(control.phase in (0, 4, 5) and (control.roster is None or control.roster.ready()),
            "credential/roster coordination remains pending")
    if current is None or current.renewal is None:
        require(control.active == bytes(32), "local authority control/image mismatch")
    else:
        require(current.renewal is not None and control.active == current.renewal.statement
                and control.floor >= current.renewal.successor_roster.version,
                "retained local authority control/image mismatch")
        if state.account_renewal is not None:
            receipt = state.account_renewal.completed
            require(receipt is not None and receipt.binding == control.active_account_binding,
                    "complete account control/image mismatch")
        else:
            require(control.account_binding is None, "account control requires common account image")
    from .roster_control import admit
    admit(control, state, current)
