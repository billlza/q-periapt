"""State invariants checked before sealing and after authenticated decoding."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hmac
from .kem import HybridPrivate
from .rekey import RekeyScope, genesis
from .traffic import message_id
from .wire import MAX_U64, require

PLAN_FIELDS = {
    1: ("seed",), 2: ("seed", "offer"), 3: ("offer", "body", "root"),
    4: ("offer", "response", "root"), 5: ("offer", "response", "body", "root"),
    6: ("offer", "response", "final"), 7: ("offer", "response", "final", "body", "root"),
}


def validate(owner, pending):
    c, s, r = owner.confirmed, owner.sending, owner.receiving
    phase = owner.plan.phase if owner.plan is not None else 0
    require(0 <= c < MAX_U64 and r == c and s == c + int(phase == 6) and s < MAX_U64,
            "directional epoch state")
    require(len(owner.root) == len(owner.predecessor) == 32, "epoch root/predecessor size")
    require(list(owner.epochs) == list(range(max(0, s - 3), s + 1)), "retained epoch inventory")
    for epoch, traffic in owner.epochs.items():
        require(traffic._epoch == epoch and traffic._rekey == b""
                and traffic._send_closed == (epoch < s)
                and (traffic._receive_limit is not None) == (epoch < r), "epoch cutover flags")
        require(traffic._sent <= owner.context.send_budget and traffic._received <= owner.context.send_budget,
                "epoch signed budget")
    require(owner.spent() + int(pending is not None) <= owner.context.send_budget, "aggregate reserved budget")
    if pending is not None:
        traffic = owner.traffic(s)
        require(not owner.fenced() and pending.identity == message_id(owner.session, 1, traffic._sent, s)
                and len(traffic._outbox) < 64, "reserved send slot")
    if c == 0:
        require(owner.last is None and owner.predecessor == genesis(owner.session, owner.context.digest), "epoch genesis")
    else:
        require(owner.last is not None and len(owner.last) == 4, "missing completed transcript")
        first = owner.last[0]
        require(len(first) == 4746, "completed offer size")
        scope = RekeyScope(owner.context, owner.session, c - 1, first[125:157])
        require(scope.public_completed(*owner.last) == owner.predecessor, "completed predecessor")
    if phase:
        validate_plan(owner)
    if owner.request is not None:
        scope = owner.scope()
        require(scope.role(1) == 1 and owner.request.body == scope.request_body(), "reserved request binding")
        if owner.request.wire:
            scope.open_request(owner.request.wire)


def validate_plan(owner):
    plan, scope = owner.plan, owner.scope()
    require(plan.phase in PLAN_FIELDS, "unknown rekey phase")
    for name in ("seed", "offer", "response", "final", "body", "root"):
        require(bool(getattr(plan, name)) == (name in PLAN_FIELDS[plan.phase]), "rekey phase field inventory")
    proposer = plan.phase in (1, 2, 5, 6)
    require((scope.role(0) == 1) == proposer, "local rekey role")
    if plan.seed:
        key = HybridPrivate._restore(plan.seed)
        if plan.offer:
            require(scope.open(0, plan.offer)[153:] == key.public(), "reserved offer key binding")
    if plan.offer:
        scope.open(0, plan.offer)
    if plan.phase == 3:
        from .rekey import digest, confirmation
        core = plan.body[:-32]
        require(len(plan.body) == 1337 and plan.body[:185] == scope.prefix(1) + digest(b"offer-wire", plan.offer)
                and hmac.compare_digest(plan.body[-32:], confirmation(plan.root, b"response", core)),
                "prepared response binding")
    if plan.phase in (4, 5, 6, 7):
        root = owner.root if plan.phase == 6 else plan.root
        scope._transcript(plan.offer, plan.response, root)
    if plan.phase == 5:
        require(plan.body == scope.final_body(plan.offer, plan.response, plan.root, owner.traffic(owner.sending)._sent),
                "prepared final count/body")
    if plan.phase == 6:
        require(scope.verify_final(plan.offer, plan.response, plan.final, owner.root)
                == owner.traffic(owner.confirmed)._sent, "committed final count")
    if plan.phase == 7:
        require(plan.body == scope.receipt_body(plan.offer, plan.response, plan.final, plan.root,
                                               owner.traffic(owner.sending)._sent), "prepared receipt count/body")
