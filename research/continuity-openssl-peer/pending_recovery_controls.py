"""Distinct parser, authority and fresh-query guards for exact recovery."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
from qperiapt_continuity_reference.pending_recovery_protocol import Proposal, INTENT_DOMAIN, METADATA_DOMAIN
from qperiapt_continuity_reference.witness import Head
from qperiapt_continuity_reference.wire import Reader, ldh, require


def malformed(f, request):
    p = Proposal.decode(request[0])
    for label, wire in [('truncated', request[0][:-1]), ('extended', request[0] + b'\0'),
                        ('unknown-authorization', request[0][:296] + b'\2' + request[0][297:]),
                        ('noncanonical-padding', request[0][:297] + b'\1' + request[0][298:])]:
        f.refuses('proposal-' + label, lambda wire=wire: Proposal.decode(wire), 'pending recovery')
    f.refuses('metadata-commitment', lambda: p.check_metadata(request[1][:-1] + bytes([request[1][-1] ^ 1])), 'metadata commitment')
    for label, data in [('short-view', request[1][:361] + (1).to_bytes(8, 'big') + request[1][369:]),
                        ('trailing-data', request[1] + b'\0')]:
        changed = replace(p, metadata=ldh(METADATA_DOMAIN, data))
        f.refuses('metadata-' + label, lambda changed=changed, data=data: changed.check_metadata(data),
                  'view size' if label == 'short-view' else 'trailing record')
    source, target = p.check_metadata(request[1])
    r = Reader(source); r.take(96 + 65)
    for _ in range(3): r.take(32 * r.integer(8))
    malformed_source = source[:r.offset] + b'\xff' + source[r.offset + 1:]
    changed, metadata = Proposal.create(p.witness, p.subject, p.expected, p.target, p.authority, p.policy,
                                        p.intent, (malformed_source, target))
    # The controller's genuine native inspector rejects unknown record kinds,
    # even when the outer framing/hash is internally consistent.
    f.call('native-inspector-refuses-unknown-record', 36, changed.wire() + metadata, status=2)
    owner = f.owner(); attempts = len(f.bridge.records)
    try:
        f.refuses('private-state-refuses-altered-complete-view', lambda: owner.confirm(changed.wire(), metadata),
                  'original complete recovery metadata differs')
    finally: owner.close()
    require(len(f.bridge.records) == attempts, 'malformed local metadata dispatched a query')


def cannot_relabel_renewal_head(f, original_request):
    previous = Proposal.decode(original_request[0]).target
    owner = f.owner()
    try:
        snapshot, wire, authority, target_view, pending = owner._inspect()
        require(pending is None and snapshot.revision == previous.revision + 1, 'actual renewed head immediately follows confirmed target')
        target = Head(1, snapshot.revision, snapshot.digest)
        # Model a caller with the wrapping key. Even a correctly reconstructed
        # intent MAC and exact current target cannot invent its witness history.
        ordinary = owner._journal._intent(previous.revision, previous.digest, wire)
        forged_source = previous.wire() + target_view[48:]
        proposal, metadata = Proposal.create(f.pin.binding, owner._journal.subject, previous, target, authority,
                                             f.context.policy_digest, ldh(INTENT_DOMAIN, ordinary),
                                             (forged_source, target_view))
        attempts = len(f.bridge.records); before = (f.path / 'head').read_bytes()
        f.refuses('joint-renewal-is-not-original-ordinary-write', lambda: owner.confirm(proposal.wire(), metadata),
                  'exact target and original command not confirmed')
        require(len(f.bridge.records) == attempts + 1 and f.bridge.records[-1]['kind'] == 1
                and (f.path / 'head').read_bytes() == before and not (f.path / 'intent').exists(),
                'failed relabel changed state or bypassed fresh Query')
        (f.out / 'forged-renewal-as-ordinary.proposal').write_bytes(proposal.wire())
        (f.out / 'forged-renewal-as-ordinary.metadata').write_bytes(metadata)
    finally: owner.close()
