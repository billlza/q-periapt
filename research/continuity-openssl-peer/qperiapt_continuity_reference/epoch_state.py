"""Candidate multi-epoch state; the Session owns all durable release boundaries."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass

from .rekey import RekeyScope, genesis
from .traffic import VolatileTraffic
from .wire import require


@dataclass(repr=False)
class RekeyPlan:
    phase: int
    seed: bytes = b""
    offer: bytes = b""
    response: bytes = b""
    final: bytes = b""
    body: bytes = b""
    root: bytes = b""


@dataclass(repr=False)
class RequestPlan:
    body: bytes
    wire: bytes = b""


class EpochState:
    @classmethod
    def initial(cls, traffic):
        owner = cls()
        owner.context, owner.session = traffic._context, traffic._session
        owner.root, traffic._rekey = traffic._rekey, b""
        owner.epochs = {0: traffic}
        owner.confirmed = owner.sending = owner.receiving = 0
        owner.predecessor = genesis(owner.session, owner.context.digest)
        owner.last, owner.plan, owner.request = None, None, None
        owner.resolutions = {}
        return owner

    def scope(self):
        return RekeyScope(self.context, self.session, self.confirmed, self.predecessor)

    def admit(self, now):
        self.context.check_established(now)

    def traffic(self, epoch):
        require(epoch in self.epochs, "retired or unadmitted epoch")
        return self.epochs[epoch]

    def operational_traffic(self, epoch):
        traffic = self.traffic(epoch)
        require(epoch not in self.resolutions, "resolution freezes old epoch operations")
        return traffic

    def for_id(self, identity, direction, *, metadata=False):
        require(len(identity) == 32, "message ID length")
        traffic = self.traffic(int.from_bytes(identity[:8], "big"))
        traffic._index(identity, direction)
        if not metadata:
            self.operational_traffic(traffic._epoch)
        return traffic

    def fenced(self):
        return self.plan is not None and self.plan.phase in (5, 7)

    def spent(self):
        return sum(self.traffic(epoch)._sent for epoch in range(self.confirmed, self.sending + 1))

    def next_id(self, now):
        self.admit(now)
        return self.operational_traffic(self.sending).next_id(now)

    def validate_send(self, identity, plaintext, ad, now):
        self.admit(now)
        traffic = self.for_id(identity, 1)
        wire = traffic.validate_send(identity, plaintext, ad, now)
        if wire is None:
            require(traffic._epoch == self.sending and not self.fenced(), "rekey send fence")
            require(self.spent() < self.context.send_budget, "aggregate signed send budget")
        return wire

    def send(self, identity, plaintext, ad, now):
        cached = self.validate_send(identity, plaintext, ad, now)
        return cached if cached is not None else self.for_id(identity, 1).send(identity, plaintext, ad, now)

    def resume(self, identity, now):
        self.admit(now)
        traffic = self.for_id(identity, 1)
        index = traffic._index(identity, 1)
        require(index >= traffic._send_floor, "retired send")
        require(index in traffic._outbox, "send operation absent")
        return traffic._outbox[index][1]

    def receive(self, wire, ad, now):
        self.admit(now)
        require(109 <= len(wire) <= 16493, "received message capacity")
        epoch = int.from_bytes(wire[41:49], "big")
        require(epoch <= self.receiving, "unadmitted traffic epoch")
        return self.operational_traffic(epoch).receive(wire, ad, now)

    def consume(self, identity, now):
        self.admit(now)
        return self.for_id(identity, 2).consume(identity, now)

    def acknowledgement(self, now, epoch=None):
        self.admit(now)
        return self.operational_traffic(self.receiving if epoch is None else epoch).acknowledgement(now)

    def accept_acknowledgement(self, wire, now):
        self.admit(now)
        require((len(wire) == 81 and wire[:8] == b"QPCMACK1")
                or (len(wire) == 89 and wire[:8] == b"QPCMACK2"), "ACK encoding")
        epoch = 0 if wire[:8] == b"QPCMACK1" else int.from_bytes(wire[41:49], "big")
        require(epoch == 0 if len(wire) == 81 else epoch > 0, "ACK epoch encoding")
        return self.operational_traffic(epoch).accept_acknowledgement(wire, now)

    def can_retire(self, traffic):
        limit = traffic._receive_limit
        if traffic._epoch in self.resolutions:
            return (self.resolutions[traffic._epoch].phase == 2 and traffic._send_closed and limit is not None
                    and not traffic._outbox and not traffic._inbox and not traffic._skipped)
        return (traffic._send_closed and traffic._send_floor == traffic._sent and not traffic._outbox
                and limit is not None and traffic._receive_floor >= limit
                and all(index >= limit for index in traffic._skipped)
                and all(plain is None for _receipt, plain in traffic._inbox.values()))

    def admit_history(self):
        first = max(0, self.scope().target - 3)
        require(all(self.can_retire(traffic) for epoch, traffic in self.epochs.items() if epoch < first),
                "unsettled history capacity")

    def install(self, scope, root, offer, response, now):
        self.admit_history()
        require(scope.target not in self.epochs, "epoch already installed")
        fresh = VolatileTraffic._from_epoch(self.context, self.session, scope.target, root,
                                            scope.traffic_material(offer, response, root), now)
        fresh._rekey = b""
        first = max(0, scope.target - 3)
        for epoch in list(self.epochs):
            if epoch < first:
                self.epochs.pop(epoch).close()
                self.resolutions.pop(epoch, None)
        self.epochs[scope.target] = fresh
        self.root = root

    def close_send(self, closing):
        traffic = self.traffic(self.sending)
        require(not traffic._send_closed and traffic._sent == closing, "send cutover count")
        traffic._send_closed, traffic._send = True, bytes(32)
        self.sending = self.scope().target

    def close_receive(self, closing):
        traffic = self.traffic(self.receiving)
        require(traffic._receive_limit is None, "receive already closed")
        traffic._receive_limit = closing
        if traffic._received >= closing:
            traffic._receive = bytes(32)
        self.receiving = self.scope().target

    def complete(self, scope, wires, root):
        self.predecessor = scope.completed(*wires, root)
        self.confirmed, self.last, self.plan = scope.target, wires, None
        self.request = None

    def close(self):
        for traffic in self.epochs.values():
            traffic.close()
        self.epochs.clear()
        self.resolutions.clear()
        self.root, self.plan, self.request = b"", None, None
