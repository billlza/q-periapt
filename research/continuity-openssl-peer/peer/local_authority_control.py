"""Authenticated original renewal coordination; never a witness or output permit."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hmac
from .local_renewal_protocol import Proposal
from .wire import Reader, MAX_U64, require

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

    def __post_init__(self):
        require(type(self.phase) is int and self.phase in range(6) and type(self.floor) is int
                and 0 <= self.floor < MAX_U64 and type(self.active) is bytes and len(self.active) == 32,
                "local authority control shape")
        if self.phase == 0:
            require(self.floor == 0 and self.active == bytes(32) and self.proposal is None
                    and self.checkpoint == bytes(40), "initial authority control")
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

    def ready(self):
        return self.phase in (0, 4, 5)

    def wire(self, scope):
        value = b"QPRFLC01" + scope.wire() + bytes([self.phase]) + self.floor.to_bytes(8, "big") + self.active
        if self.proposal is not None:
            value += self.proposal.wire() + self.checkpoint
        return value


def read(journal):
    data = journal._admit().read("authority")
    if data is None:
        return None
    require(len(data) in (177, 513), "authority control size")
    body = data[:-32]
    require(hmac.compare_digest(hmac.digest(journal._intent_key, DOMAIN + body, "sha256"), data[-32:]),
            "authority control authentication")
    r = Reader(body)
    require(r.take(8) == b"QPRFLC01" and r.take(96) == journal.scope.wire(), "authority control scope")
    phase, floor, active = r.integer(1), r.integer(8), r.take(32)
    proposal = Proposal.decode(r.take(296)) if phase else None
    checkpoint = r.take(40) if phase else bytes(40)
    r.finish()
    if proposal is not None:
        require(hasattr(journal, "profile") and proposal.witness == journal.profile.pin.binding
                and proposal.subject == journal.subject and proposal.expected.fence == proposal.target.fence == 1,
                "authority original witness/subject")
    return Control(phase, floor, active, proposal, checkpoint)


def write(journal, control):
    body = control.wire(journal.scope)
    data = body + hmac.digest(journal._intent_key, DOMAIN + body, "sha256")
    journal._admit().publish("authority", data, fixed_slot="authority-" + str(control.phase))
    require(read(journal) == control, "authority control durable readback")


def admit_snapshot(journal, state):
    if state.operation._context.witness is None:
        require(journal._admit().read("authority") is None, "witness coordination in local-only store")
        if state.format_version == 7:
            require(state.local_renewal is not None, "local coordination absent")
            state.local_renewal.admit()
        else:
            require(state.local_authority is None and state.local_renewal is None,
                    "local-only authority requires atomic coordination")
        return
    require(state.local_renewal is None, "local coordination cannot bypass required witness")
    control = read(journal)
    if control is None:
        require(state.local_authority is None, "missing original local authority control")
        return
    require(control.ready(), "local renewal coordination remains pending")
    current = state.local_authority
    if current is None:
        require(control.active == bytes(32), "local authority control/image mismatch")
    else:
        require(current.renewal is not None and control.active == current.renewal.statement
                and control.floor >= current.listing.version, "retained local authority control/image mismatch")
