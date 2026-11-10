"""Two committed application steps; neither step asserts successful delivery."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import os

from .journal import locked
from .resolution import Resolution, report, resolution_id, validate
from .state_codec import encode
from .wire import require


class ResolutionOwner:
    def _resolution_state(self, state, now):
        require(state.format_version in (4, 5, 6, 7, 8, 9, 10), "resolution requires explicit snapshot upgrade")
        require(state.traffic is not None, "traffic not activated")
        state.traffic.admit(now)
        return state.traffic

    @locked
    def begin_closed_epoch_resolution(self, epoch, now):
        require(type(epoch) is int and epoch >= 0, "resolution epoch")
        with self._state(now=now) as (snapshot, state):
            owner = self._resolution_state(state, now)
            require(epoch < owner.sending and epoch < owner.receiving, "resolution epoch still open")
            traffic = owner.traffic(epoch)
            if epoch not in owner.resolutions:
                require(owner.plan is None and owner.request is None, "pending control fences new resolution")
                key = os.urandom(32)
                owner.resolutions[epoch] = Resolution(1, resolution_id(traffic, key), key)
                self._journal.update(snapshot.digest, encode(state))
                self._observe("protocol:resolution-frozen")
            owner.admit(now)
            return report(traffic, owner.resolutions[epoch])

    @locked
    def acknowledge_closed_epoch_resolution(self, epoch, identity: bytes, now):
        """The host must have durably accounted for this exact report first."""
        require(type(epoch) is int and epoch >= 0 and type(identity) is bytes
                and len(identity) == 32 and any(identity), "resolution acknowledgement scope")
        with self._state(now=now) as (snapshot, state):
            owner = self._resolution_state(state, now)
            traffic = owner.traffic(epoch)
            require(epoch in owner.resolutions, "resolution not requested")
            resolution = owner.resolutions[epoch]
            require(resolution.identity == identity, "conflicting resolution identity")
            if resolution.phase == 1:
                validate(traffic, resolution)
                traffic._outbox.clear()
                traffic._inbox.clear()
                traffic._skipped.clear()
                traffic._send = traffic._receive = traffic._send_ack = traffic._receive_ack = bytes(32)
                owner.resolutions[epoch] = Resolution(2, identity)
                self._journal.update(snapshot.digest, encode(state))
                self._observe("protocol:resolution-acknowledged")
            owner.admit(now)
            return identity

    @locked
    def closed_epoch_resolution_status(self, epoch):
        """Read-only metadata survives expiry; it grants no report or traffic."""
        require(type(epoch) is int and epoch >= 0, "resolution epoch")
        with self._state(operational=False) as (_snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            state.traffic.traffic(epoch)
            resolution = state.traffic.resolutions.get(epoch)
            if resolution is None:
                return "Unrequested", None
            return ("Pending" if resolution.phase == 1 else "Acknowledged"), resolution.identity
