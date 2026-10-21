"""One original sealed head target for an independently approved local renewal."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hmac
from .storage_budget import MAX_SHARED_STATE, MAX_POLICY_STATE
from .local_renewal_protocol import Proposal
from .state_codec import decode
from .wire import Reader, require

DOMAIN = b"Q-PERIAPT-INDEPENDENT-LOCAL-RENEWAL-INTENT/v1/"


@dataclass(frozen=True, repr=False)
class Intent:
    proposal: Proposal
    target: bytes
    checkpoint: bytes
    account_binding: bytes | None = None

    def wire(self, journal):
        body = (b"QPRFLI01" if self.proposal.policy is None else b"QPRFLI02") + self.proposal.wire() + len(self.target).to_bytes(4, "big") + self.target
        return body + hmac.digest(journal._intent_key, DOMAIN + journal.scope.wire() + body, "sha256")

    @classmethod
    def read(cls, journal, context):
        wire = journal._admit().read("intent")
        if wire is None:
            return None
        require(604 <= len(wire) <= MAX_POLICY_STATE + 637, "local renewal intent capacity")
        body = wire[:-32]
        require(hmac.compare_digest(wire[-32:], hmac.digest(journal._intent_key,
                DOMAIN + journal.scope.wire() + body, "sha256")), "local renewal intent authentication")
        r = Reader(body); tag = r.take(8)
        require(tag in (b"QPRFLI01", b"QPRFLI02"), "not a local renewal intent")
        continued = tag == b"QPRFLI02"
        proposal = Proposal.decode(r.take(329 if continued else 296)); size = r.integer(4)
        require((proposal.policy is not None) == continued, "credential intent policy discriminator")
        require(264 <= size <= (MAX_POLICY_STATE if continued else MAX_SHARED_STATE) + 264, "local renewal target size")
        target = r.take(size); r.finish()
        require(proposal.witness == journal.profile.pin.binding and proposal.subject == journal.subject
                and proposal.expected.fence == proposal.target.fence == 1, "local renewal original scope")
        snapshot = journal._decode(target)
        require(snapshot.digest == proposal.target.digest and snapshot.revision == proposal.target.revision,
                "local renewal sealed target differs")
        state = decode(snapshot.payload, context)
        try:
            from .policy_snapshot import authorization, validate
            if state.policy_renewal is not None:
                validate(state, context, journal.scope.identity)
            require(proposal.policy == authorization(state), "credential target policy authorization differs")
            from .identity_state import local_view
            current = local_view(state, context)
            require(state.format_version in (6, 9, 10) and current is not None
                    and current.renewal is not None, "local renewal target authority absent")
            grant = current.renewal
            require(grant.operation == proposal.operation and grant.statement == proposal.statement,
                    "local renewal grant/proposal differs")
            binding = None if state.account_renewal is None else state.account_renewal.completed.binding
            return cls(proposal, target, grant.successor_roster.checkpoint(), binding)
        finally:
            state.close()
