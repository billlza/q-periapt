"""Durable remote authority updates on the original established session owner."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .journal import locked
from .identity_state import IdentityState, admit_local
from .state_codec import encode
from .wire import require


class PeerOwner:
    def _peer_state(self, state, now):
        require(state.format_version in (5, 6, 7) and state.traffic is not None, "peer authority requires established format five")
        # Only local credential/roster and policy gate maintenance. An expired or
        # revoked remote peer does not prevent receiving a valid signed update.
        admit_local(state, self._context, now)
        return state.peer_authority or IdentityState.initial(self._context)

    @locked
    def admit_peer_credential_renewal(self, wire, operation, target, now):
        with self._state(now=now, peer_maintenance=True) as (snapshot, state):
            current = self._peer_state(state, now)
            next_state = current.renew(self._context, wire, operation, target, now)
            if next_state is not current:
                state.peer_authority = next_state
                self._journal.update(snapshot.digest, encode(state))
                self._authority_generation += 1
                self._observe("protocol:peer-renewal-committed")
            next_state.check(now)
            admit_local(state, self._context, now)
            return next_state.listing.checkpoint()

    @locked
    def admit_peer_roster(self, wire, target, now):
        with self._state(now=now, peer_maintenance=True) as (snapshot, state):
            current = self._peer_state(state, now)
            next_state = current.update_roster(wire, target, now)
            if next_state is not current:
                state.peer_authority = next_state
                self._journal.update(snapshot.digest, encode(state))
                self._authority_generation += 1
                self._observe("protocol:peer-roster-committed")
            admit_local(state, self._context, now)
            return next_state.listing.checkpoint()

    @locked
    def peer_authority_status(self):
        with self._state(operational=False) as (_snapshot, state):
            require(state.traffic is not None, "peer authority requires established session")
            current = state.peer_authority or IdentityState.initial(self._context)
            return [current.listing.checkpoint().hex(), current.current.digest.hex(),
                    current.renewal.operation.hex() if current.renewal else None, current.active()]
