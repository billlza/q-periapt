"""Actual host reapproval of one independent original device before P/G."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import os
from native_exchange_fixture import b64, save
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require


def approve(peer, probe):
    original = peer.invitation
    request = {'previous':original['operation'], 'request_id':list(os.urandom(32)),
               'predecessor':original['predecessor'], 'request':b64(peer.proof)}
    save(peer.root / 'peer-signing-public.bin', peer.public)
    save(peer.root / 'peer-reapproval-request.json', request)
    probe.request('bob', 'peer-reapproval-lost', '/api/enrollment/reapprove', request, lost=True)
    approved = probe.request('bob', 'peer-reapproval-retry', '/api/enrollment/reapprove', request)
    require(approved['operation'] != original['operation'] and approved['request_id'] == request['request_id']
            and all(approved[k] == original[k] for k in ('application','root_revision','root','family','device',
                'generation','valid_from','valid_until','predecessor')), 'host reapproval changed original intent')
    probe.request('bob', 'peer-original-issue-refused', '/api/enrollment/issue',
                  {'operation':original['operation']}, status=409)
    save(peer.root / 'peer-approved-invitation.json', approved)
    peer.invitation = approved
    return {'original_operation':original['operation'], 'issued_operation':approved['operation'],
            'request_sha256':hashlib.sha256(peer.proof).hexdigest(),
            'signing_key_sha256':hashlib.sha256(peer.public).hexdigest()}


def accepted(peer, result):
    owner = EnrollmentClient.open(peer.directory, peer.client_id, peer.key)
    try:
        status = owner.status()
        require(status['operation'] == bytes(result['original_operation'])
                and status['issued_operation'] == bytes(result['issued_operation'])
                and status['journal'] == peer.journal and status['public_key'] == peer.public,
                'reapproved original owner lost its issued operation or signing identity')
    finally:
        owner.close()
    result.update(journal=list(peer.journal), same_identity=True)
    save(peer.root / 'peer-reapproval.json', result)
    return result
