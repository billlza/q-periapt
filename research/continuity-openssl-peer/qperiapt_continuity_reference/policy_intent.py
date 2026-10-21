"""One authenticated original P target, distinct from ordinary Advance and G/R."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hmac
from .policy_witness_protocol import Proposal
from .storage_budget import MAX_POLICY_STATE
from .state_codec import decode
from .wire import Reader, require
from .account_binding import SIZE as ROOT_BINDING_SIZE

DOMAIN = b"Q-PERIAPT-INDEPENDENT-POLICY-INTENT/v1/"


@dataclass(frozen=True, repr=False)
class Intent:
    proposal: Proposal
    target: bytes
    checkpoint: bytes

    def wire(self, journal):
        body = b"QPRFPI01" + self.proposal.wire() + len(self.target).to_bytes(4, "big") + self.target
        return body + hmac.digest(journal._intent_key, DOMAIN + journal.scope.wire() + body, "sha256")

    @classmethod
    def read(cls, journal, context):
        wire = journal._admit().read("intent")
        if wire is None:
            return None
        require(604 <= len(wire) <= MAX_POLICY_STATE + 604 + ROOT_BINDING_SIZE, "policy intent capacity")
        body = wire[:-32]
        require(hmac.compare_digest(wire[-32:], hmac.digest(journal._intent_key,
                DOMAIN + journal.scope.wire() + body, "sha256")), "policy intent authentication")
        r = Reader(body)
        require(r.take(8) == b"QPRFPI01", "not an original policy intent")
        p = Proposal.decode(r.take(296))
        size = r.integer(4)
        require(264 <= size <= MAX_POLICY_STATE + 264 + ROOT_BINDING_SIZE, "policy target capacity")
        target = r.take(size); r.finish()
        require(p.witness == journal.profile.pin.binding and p.subject == journal.subject
                and p.expected.fence == p.target.fence == 1, "policy original scope")
        snapshot = journal._decode(target)
        require(snapshot.digest == p.target.digest and snapshot.revision == p.target.revision,
                "policy exact sealed target differs")
        state = decode(snapshot.payload, context)
        try:
            from .policy_snapshot import validate
            validate(state, context, journal.scope.identity)
            record = state.policy_renewal
            require(record.active is not None and record.pending is None
                    and record.active.approval.scope.operation == p.operation
                    and record.active.approval.statement == p.statement,
                    "policy target lacks exact completion")
            checkpoint = record.active.target.checkpoint()
        finally:
            state.close()
        return cls(p, target, checkpoint)
