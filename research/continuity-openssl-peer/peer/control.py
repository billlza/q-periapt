"""One explicit control target per call; transport retries remain host bounded."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .epoch_state import RequestPlan
from .journal import locked
from .rekey import RekeyScope, FLIGHTS
from .wire import MAX_U64, Reader, require


def inspect(wire):
    """Bounded routing only. Every handler must authenticate before mutation."""
    require(isinstance(wire, bytes) and 0 < len(wire) <= 8192, "control wire capacity")
    reader = Reader(wire)
    size = reader.integer(4)
    require(153 <= size <= 1369, "control body size")
    body = reader.take(size)
    reader.take(3373)
    reader.finish()
    sizes = {tag: length for tag, _purpose, length in FLIGHTS}
    sizes[b"QPRKRQ01"] = 153
    require(body[:8] in sizes and size == sizes[body[:8]], "control tag/body size")
    target = int.from_bytes(body[112:120], "big")
    require(0 < target < MAX_U64, "control target range")
    return body[:8], target


def output(wire):
    return inspect(wire)[1], wire


class ControlOwner:
    def _control_state(self, state, now):
        require(state.format_version in (3, 4, 5, 6, 7, 8), "control requires explicit snapshot upgrade")
        return self._rekey_state(state, now)

    @locked
    def prepare_rekey_request(self, signer, now):
        with self._state(now=now) as (snapshot, state):
            owner = self._control_state(state, now)
            scope = owner.scope()
            require(scope.role(1) == 1, "only the non-proposer requests progress")
            if owner.request is not None and owner.request.wire:
                return owner.request.wire
            self._signer(signer)
            if owner.request is None:
                require(owner.plan is None, "offer already admitted; resume its response")
                owner.request = RequestPlan(scope.request_body())
                snapshot = self._save_rekey(snapshot, state, "request-prepared")
            # Provider signatures cannot restore Rust's signature-randomness token.
            # An unsigned body may be signed anew; a committed wire is immutable.
            wire = self._signer(signer).sign(13, owner.request.body)
            scope.open_request(wire)
            owner.request.wire = wire
            self._save_rekey(snapshot, state, "request-committed")
            owner.admit(now)
            return wire

    @locked
    def respond_rekey_request(self, wire, signer, now):
        tag, target = inspect(wire)
        require(tag == b"QPRKRQ01", "not a control request")
        with self._state(now=now) as (_snapshot, state):
            owner = self._control_state(state, now)
            require(target % 2 == 1, "request addressed to another proposer")
            if target == owner.confirmed:
                require(owner.last is not None, "completed request history absent")
                scope = RekeyScope(owner.context, owner.session, target - 1, owner.last[0][125:157])
            else:
                require(target > owner.confirmed, "retired control request")
                scope = owner.scope()
                require(target == scope.target, "future control request")
            scope.open_request(wire)
            if target == owner.confirmed or (owner.plan is not None and owner.plan.phase in (5, 6)):
                return self.rekey_outbox(target, 0, now)
        return self.prepare_rekey_offer(signer, now)

    @locked
    def rekey_request_status(self):
        """BodyPrepared is not Rust's signature-randomness reservation."""
        with self._state(operational=False) as (_snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            request = state.traffic.request
            return "Absent" if request is None else ("Committed" if request.wire else "BodyPrepared")

    @locked
    def advance_rekey_control(self, target, signer, now):
        """Return (target, exact output), or (target, None) for local completion."""
        require(type(target) is int and 0 < target < MAX_U64, "control target range")
        with self._state(now=now) as (_snapshot, state):
            owner = self._control_state(state, now)
            if target == owner.confirmed:
                require(owner.last is not None, "completed control history absent")
                return target, None
            require(target > owner.confirmed, "retired control target")
            require(target == owner.scope().target, "future control target")
            plan = owner.plan
            if plan is not None and plan.phase in (3, 4):
                handler, arguments = self.respond_rekey_offer, (plan.offer,)
            elif plan is not None and plan.phase in (5, 6):
                handler, arguments = self.accept_rekey_response, (plan.response,)
            elif plan is not None and plan.phase == 7:
                handler, arguments = self.finish_rekey, (plan.final,)
            elif target % 2 == 1:
                handler, arguments = self.prepare_rekey_offer, ()
            else:
                handler, arguments = self.prepare_rekey_request, ()
        return output(handler(*arguments, signer=signer, now=now))

    @locked
    def receive_rekey_control(self, wire, signer, now):
        tag, target = inspect(wire)
        # Require the new format even when an old four-flight handler can resume
        # in format two. No control call silently upgrades the original image.
        with self._state(now=now) as (_snapshot, state):
            self._control_state(state, now)
        handlers = {b"QPRKRQ01": self.respond_rekey_request, b"QPRKOF01": self.respond_rekey_offer,
                    b"QPRKRP01": self.accept_rekey_response, b"QPRKFN01": self.finish_rekey}
        if tag == b"QPRKRC01":
            confirmed = self.accept_rekey_receipt(wire, now)
            require(confirmed == target, "receipt target differs")
            return confirmed, None
        return output(handlers[tag](wire, signer=signer, now=now))

    @locked
    def start_rekey_control(self, target, signer, now):
        """Explicit delivery also resends a possibly lost final receipt."""
        step = self.advance_rekey_control(target, signer, now)
        if step[1] is None:
            with self._state(now=now) as (_snapshot, state):
                owner = self._control_state(state, now)
                if owner.plan is None and owner.request is None and target % 2 == 0:
                    return output(self.rekey_outbox(target, 3, now))
        return step

    @locked
    def replay_rekey_control(self, wire, now):
        """Release only original committed output, never start replacement work."""
        tag, target = inspect(wire)
        require(wire[124] == 1, "control output belongs to the other signer")
        with self._state(now=now) as (_snapshot, state):
            owner = self._control_state(state, now)
            if tag == b"QPRKRQ01":
                require(owner.request is not None and owner.request.wire == wire, "control request outbox absent or changed")
                return output(owner.request.wire)
        flight = next(index for index, (kind, _purpose, _size) in enumerate(FLIGHTS) if kind == tag)
        saved = self.rekey_outbox(target, flight, now)
        require(saved == wire, "control output changed")
        return output(saved)
