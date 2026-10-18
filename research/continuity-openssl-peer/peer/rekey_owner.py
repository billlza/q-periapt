"""Journal-owned four-flight transitions mixed into the independent Session."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .epoch_state import RekeyPlan
from .journal import locked
from .kem import HybridPrivate
from .rekey import digest
from .state_codec import encode
from .wire import require


class RekeyOwner:
    def _rekey_state(self, state, now):
        require(state.format_version in (2, 3, 4, 5, 6), "explicit snapshot upgrade required")
        require(state.traffic is not None, "traffic not activated")
        state.traffic.admit(now)
        return state.traffic

    def _signer(self, signer):
        require(signer is not None and signer.public().raw == self._context.initiator.raw,
                "current local signing owner required")
        return signer

    def _save_rekey(self, snapshot, state, stage):
        result = self._journal.update(snapshot.digest, encode(state))
        self._observe("protocol:rekey-" + stage)
        return result

    @locked
    def prepare_rekey_offer(self, signer, now):
        with self._state(now=now) as (snapshot, state):
            owner = self._rekey_state(state, now)
            scope = owner.scope()
            require(scope.role(0) == 1, "not the designated proposer")
            owner.admit_history()
            if owner.plan is None:
                self._signer(signer)
                owner.plan = RekeyPlan(1, seed=HybridPrivate()._checkpoint())
                snapshot = self._save_rekey(snapshot, state, "key-reserved")
            require(owner.plan.phase in (1, 2), "offer is already completing")
            if owner.plan.phase == 1:
                key = HybridPrivate._restore(owner.plan.seed)
                wire = self._signer(signer).sign(9, scope.offer_body(key.public()))
                owner.plan = RekeyPlan(2, seed=owner.plan.seed, offer=wire)
                self._save_rekey(snapshot, state, "offer-committed")
            owner.admit(now)
            return owner.plan.offer

    @locked
    def respond_rekey_offer(self, offer, signer, now):
        with self._state(now=now) as (snapshot, state):
            owner = self._rekey_state(state, now)
            if owner.last is not None and owner.confirmed % 2 == 0 and owner.last[0] == offer:
                return owner.last[1]
            scope = owner.scope()
            require(scope.role(0) == 2, "not the designated responder")
            owner.admit_history()
            if owner.plan is None:
                public = scope.open(0, offer)[153:]
                self._signer(signer)
                ciphertext, shared = owner.context.sdk.encapsulate(public, digest(b"response-kem", offer))
                body, root = scope.response_body(offer, ciphertext, shared, owner.root)
                owner.plan = RekeyPlan(3, offer=offer, body=body, root=root)
                snapshot = self._save_rekey(snapshot, state, "response-prepared")
            plan = owner.plan
            require(plan.phase in (3, 4, 7) and plan.offer == offer, "conflicting rekey offer")
            if plan.phase == 3:
                wire = self._signer(signer).sign(10, plan.body)
                owner.plan = RekeyPlan(4, offer=offer, response=wire, root=plan.root)
                self._save_rekey(snapshot, state, "response-committed")
            owner.admit(now)
            return owner.plan.response

    @locked
    def accept_rekey_response(self, response, signer, now):
        with self._state(now=now) as (snapshot, state):
            owner = self._rekey_state(state, now)
            if owner.last is not None and owner.confirmed % 2 == 1 and owner.last[1] == response:
                return owner.last[2]
            scope, plan = owner.scope(), owner.plan
            require(scope.role(0) == 1 and plan is not None and plan.phase in (2, 5, 6), "no pending local offer")
            if plan.phase == 2:
                require(state.pending is None, "original send must finish before cutover")
                self._signer(signer)
                owner.admit_history()
                root = scope.verify_response(plan.offer, response, HybridPrivate._restore(plan.seed), owner.root)
                body = scope.final_body(plan.offer, response, root, owner.traffic(owner.sending)._sent)
                owner.plan = RekeyPlan(5, offer=plan.offer, response=response, body=body, root=root)
                snapshot = self._save_rekey(snapshot, state, "final-prepared")
            plan = owner.plan
            require(plan.response == response, "conflicting rekey response")
            if plan.phase == 5:
                require(state.pending is None, "original send must finish before cutover")
                wire = self._signer(signer).sign(11, plan.body)
                closing = int.from_bytes(plan.body[-40:-32], "big")
                owner.install(scope, plan.root, plan.offer, response, now)
                owner.close_send(closing)
                owner.plan = RekeyPlan(6, offer=plan.offer, response=response, final=wire)
                self._save_rekey(snapshot, state, "final-committed")
            owner.admit(now)
            return owner.plan.final

    @locked
    def finish_rekey(self, final, signer, now):
        with self._state(now=now) as (snapshot, state):
            owner = self._rekey_state(state, now)
            if owner.last is not None and owner.confirmed % 2 == 0 and owner.last[2] == final:
                return owner.last[3]
            scope, plan = owner.scope(), owner.plan
            require(scope.role(0) == 2 and plan is not None and plan.phase in (4, 7), "no pending rekey response")
            if plan.phase == 4:
                require(state.pending is None, "original send must finish before cutover")
                self._signer(signer)
                owner.admit_history()
                body = scope.receipt_body(plan.offer, plan.response, final, plan.root, owner.traffic(owner.sending)._sent)
                owner.plan = RekeyPlan(7, offer=plan.offer, response=plan.response, final=final, body=body, root=plan.root)
                snapshot = self._save_rekey(snapshot, state, "receipt-prepared")
            plan = owner.plan
            require(plan.final == final and state.pending is None, "conflicting final or pending send")
            receipt = self._signer(signer).sign(12, plan.body)
            peer_closing = scope.verify_final(plan.offer, plan.response, final, plan.root)
            closing = int.from_bytes(plan.body[-40:-32], "big")
            owner.install(scope, plan.root, plan.offer, plan.response, now)
            owner.close_send(closing)
            owner.close_receive(peer_closing)
            owner.complete(scope, (plan.offer, plan.response, final, receipt), plan.root)
            self._save_rekey(snapshot, state, "receipt-committed")
            owner.admit(now)
            return receipt

    @locked
    def accept_rekey_receipt(self, receipt, now):
        with self._state(now=now) as (snapshot, state):
            owner = self._rekey_state(state, now)
            if owner.last is not None and owner.confirmed % 2 == 1 and owner.last[3] == receipt:
                return owner.confirmed
            scope, plan = owner.scope(), owner.plan
            require(scope.role(0) == 1 and plan is not None and plan.phase == 6, "no committed final")
            closing = scope.verify_receipt(plan.offer, plan.response, plan.final, receipt, owner.root)
            owner.close_receive(closing)
            owner.complete(scope, (plan.offer, plan.response, plan.final, receipt), owner.root)
            self._save_rekey(snapshot, state, "receipt-accepted")
            owner.admit(now)
            return owner.confirmed

    @locked
    def rekey_outbox(self, target, flight, now):
        with self._state(now=now) as (_snapshot, state):
            owner = self._rekey_state(state, now)
            require(type(target) is int and target > 0 and type(flight) is int and 0 <= flight <= 3,
                    "rekey outbox selection")
            if target == owner.confirmed and owner.last is not None:
                return owner.last[flight]
            require(owner.plan is not None and target == owner.scope().target, "rekey outbox absent")
            wire = getattr(owner.plan, ("offer", "response", "final")[flight]) if flight < 3 else b""
            require(bool(wire), "unsigned rekey outbox")
            return wire

    @locked
    def rekey_progress(self):
        """Read-only counters; zero pending target means no pending exchange."""
        with self._state(operational=False) as (_snapshot, state):
            require(state.traffic is not None, "traffic not activated")
            owner = state.traffic
            return (owner.confirmed, owner.sending, owner.receiving,
                    owner.scope().target if owner.plan is not None or owner.request is not None else 0)
