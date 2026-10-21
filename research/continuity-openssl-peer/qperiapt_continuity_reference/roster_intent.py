"""One authenticated exact R target; it cannot be ordinary Advance or G evidence."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hmac
from .roster_protocol import Proposal
from .storage_budget import MAX_POLICY_STATE
from .state_codec import decode
from .wire import Reader, require

DOMAIN = b"Q-PERIAPT-INDEPENDENT-ROSTER-INTENT/v1/"


@dataclass(frozen=True, repr=False)
class Intent:
    proposal: Proposal
    target: bytes

    def wire(self, journal):
        body = b"QPRFRI01" + self.proposal.wire() + len(self.target).to_bytes(4, "big") + self.target
        return body + hmac.digest(journal._intent_key, DOMAIN + journal.scope.wire() + body, "sha256")

    @classmethod
    def read(cls, journal, context):
        wire = journal._admit().read("intent")
        if wire is None:
            return None
        require(725 <= len(wire) <= MAX_POLICY_STATE + 725, "roster intent capacity")
        body = wire[:-32]
        require(hmac.compare_digest(wire[-32:], hmac.digest(journal._intent_key,
                DOMAIN + journal.scope.wire() + body, "sha256")), "roster intent authentication")
        r = Reader(body)
        require(r.take(8) == b"QPRFRI01", "not an original roster intent")
        p = Proposal.decode(r.take(417))
        size = r.integer(4)
        require(264 <= size <= MAX_POLICY_STATE + 264, "roster target capacity")
        target = r.take(size)
        r.finish()
        require(p.witness == journal.profile.pin.binding and p.subject == journal.subject
                and p.expected.fence == p.target.fence == 1, "roster original scope")
        snapshot = journal._decode(target)
        require(snapshot.digest == p.target.digest and snapshot.revision == p.target.revision,
                "roster exact sealed target differs")
        state = decode(snapshot.payload, context)
        try:
            from .policy_snapshot import validate
            if state.policy_renewal is not None:
                validate(state, context, journal.scope.identity)
            p.scope.check_policy(context, state.policy_renewal, current=True)
            require(state.format_version == 10 and state.account_renewal.roster == p.scope
                    and state.account_authority.listing.checkpoint() == p.scope.target,
                    "roster target lacks exact completion")
        finally:
            state.close()
        return cls(p, target)
