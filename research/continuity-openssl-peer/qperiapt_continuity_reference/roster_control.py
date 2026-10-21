"""Historical R completion alongside, never replacing, the original G receipt."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .roster_protocol import Proposal, checkpoint
from .wire import Reader, MAX_U64, require


@dataclass(frozen=True)
class Control:
    # Same ordered boundary vocabulary as G; this separately names R.
    phase: int
    floor: int
    proposal: Proposal
    active: bytes | None = None

    def __post_init__(self):
        require(type(self.phase) is int and self.phase in (1, 2, 3, 4, 5)
                and type(self.floor) is int and 0 <= self.floor < MAX_U64, "roster control shape")
        target = int.from_bytes(self.proposal.scope.target[:8], "big")
        require(target > self.floor if self.phase == 1 else target == self.floor, "roster permanent floor")
        if self.active is not None:
            checkpoint(self.active)
        if self.phase in (2, 4):
            require(self.active == self.proposal.scope.target, "applied roster control")
        else:
            require(self.active is None or int.from_bytes(self.active[:8], "big") < target,
                    "unapplied roster control")

    def ready(self):
        return self.phase in (4, 5)

    def wire(self):
        return (b"QPRFRC01" + bytes([self.phase]) + self.floor.to_bytes(8, "big")
                + self.proposal.wire() + bytes([self.active is not None]) + (self.active or bytes(40)))

    @classmethod
    def read(cls, wire):
        r = Reader(wire)
        require(r.take(8) == b"QPRFRC01", "roster control schema")
        phase, floor, proposal = r.integer(1), r.integer(8), Proposal.decode(r.take(417))
        flag, active = r.integer(1), r.take(40)
        require(flag in (0, 1) and (flag == 1 or active == bytes(40)), "roster control presence")
        r.finish()
        return cls(phase, floor, proposal, active if flag else None)


def admit(control, state, current):
    record = state.account_renewal
    retained = None if record is None else record.roster
    r = control.roster
    require((retained is None) == (r is None or r.active is None), "missing original roster completion")
    if retained is not None:
        retained.check_policy(state.operation._context, state.policy_renewal)
        require(r.ready() and retained.target == r.active, "roster completion/control differs")
        if r.phase == 4:
            require(retained == r.proposal.scope, "applied roster exact scope differs")
    if current is None:
        require(r is None, "roster control without local identity")
        return
    # Current R may advance past G's historical receipt; neither a Closed
    # target nor an arbitrary newer local image is applied authority.
    base = current.original.pin.checkpoint() if current.renewal is None else current.renewal.successor_roster.checkpoint()
    latest = r.active if r is not None and r.active is not None else base
    if int.from_bytes(base[:8], "big") > int.from_bytes(latest[:8], "big"):
        latest = base
    elif base[:8] == latest[:8]:
        require(base == latest, "roster and credential same-version fork")
    require(current.listing.checkpoint() == latest, "current roster lacks exact G or R completion")
