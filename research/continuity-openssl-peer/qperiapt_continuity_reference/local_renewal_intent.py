"""One original sealed head target for an independently approved local renewal."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hmac
from .journal import MAX_STATE
from .local_renewal_protocol import Proposal
from .state_codec import decode
from .wire import Reader, require

DOMAIN = b"Q-PERIAPT-INDEPENDENT-LOCAL-RENEWAL-INTENT/v1/"


@dataclass(frozen=True, repr=False)
class Intent:
    proposal: Proposal
    target: bytes
    checkpoint: bytes

    def wire(self, journal):
        body = b"QPRFLI01" + self.proposal.wire() + len(self.target).to_bytes(4, "big") + self.target
        return body + hmac.digest(journal._intent_key, DOMAIN + journal.scope.wire() + body, "sha256")

    @classmethod
    def read(cls, journal, context):
        wire = journal._admit().read("intent")
        if wire is None:
            return None
        require(604 <= len(wire) <= MAX_STATE + 604, "local renewal intent capacity")
        body = wire[:-32]
        require(hmac.compare_digest(wire[-32:], hmac.digest(journal._intent_key,
                DOMAIN + journal.scope.wire() + body, "sha256")), "local renewal intent authentication")
        r = Reader(body); require(r.take(8) == b"QPRFLI01", "not a local renewal intent")
        proposal = Proposal.decode(r.take(296)); size = r.integer(4)
        require(264 <= size <= MAX_STATE + 264, "local renewal target size")
        target = r.take(size); r.finish()
        require(proposal.witness == journal.profile.pin.binding and proposal.subject == journal.subject
                and proposal.expected.fence == proposal.target.fence == 1, "local renewal original scope")
        snapshot = journal._decode(target)
        require(snapshot.digest == proposal.target.digest and snapshot.revision == proposal.target.revision,
                "local renewal sealed target differs")
        state = decode(snapshot.payload, context)
        try:
            require(state.format_version == 6 and state.local_authority is not None
                    and state.local_authority.renewal is not None, "local renewal target authority absent")
            grant = state.local_authority.renewal
            require(grant.operation == proposal.operation and grant.statement == proposal.statement,
                    "local renewal grant/proposal differs")
            return cls(proposal, target, grant.successor_roster.checkpoint())
        finally:
            state.close()
