"""Retained P terminal and version floor alongside the original G/R control."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .policy_witness_protocol import Proposal
from .roster_protocol import checkpoint
from .wire import Reader, MAX_U64, require
from .witness import fixed


@dataclass(frozen=True)
class Control:
    phase: int
    floor: int
    proposal: Proposal
    target: bytes
    active: bytes | None = None  # checkpoint40 + statement32

    def __post_init__(self):
        require(type(self.phase) is int and self.phase in (1, 2, 3, 4, 5)
                and type(self.floor) is int and 0 <= self.floor < MAX_U64, "policy control shape")
        checkpoint(self.target)
        version = int.from_bytes(self.target[:8], "big")
        require(version > self.floor if self.phase == 1 else version == self.floor, "policy permanent version floor")
        if self.active is not None:
            fixed(self.active, 72)
            checkpoint(self.active[:40])
            fixed(self.active[40:], 32)
        if self.phase in (2, 4):
            require(self.active == self.target + self.proposal.statement, "applied policy control")
        else:
            require(self.active is None or int.from_bytes(self.active[:8], "big") < version,
                    "unapplied policy control")

    def ready(self):
        return self.phase in (4, 5)

    def wire(self):
        return (b"QPRFPC01" + bytes([self.phase]) + self.floor.to_bytes(8, "big")
                + self.proposal.wire() + self.target + bytes([self.active is not None]) + (self.active or bytes(72)))

    @classmethod
    def read(cls, wire):
        r = Reader(wire)
        require(r.take(8) == b"QPRFPC01", "policy control schema")
        phase, floor, proposal, target = r.integer(1), r.integer(8), Proposal.decode(r.take(296)), r.take(40)
        flag, active = r.integer(1), r.take(72)
        require(flag in (0, 1) and (flag == 1 or active == bytes(72)), "policy active control presence")
        r.finish()
        return cls(phase, floor, proposal, target, active if flag else None)


def admit(control, state):
    p = None if control is None else control.policy
    record = state.policy_renewal
    active = None if record is None else record.active
    require((active is None) == (p is None or p.active is None), "missing original policy completion")
    if active is not None:
        require(p.ready() and p.active == active.target.checkpoint() + active.approval.statement,
                "policy completion/control differs")
        if p.phase == 4:
            require(active.approval.scope.operation == p.proposal.operation,
                    "applied policy operation differs")
