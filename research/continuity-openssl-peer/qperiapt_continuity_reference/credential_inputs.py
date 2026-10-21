"""Correlate host issuance with protected enrollment and separately selected trust.

This does not replace signature verification by the original journal owner.
The statement is compared to the authenticated grant before any preparation.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .enrollment_exchange import CurrentMembership, checkpoint, decode, encoded, host_revision, identifier, shape
from .identity import roster
from .wire import require


def selected(issued, current, authority, invitation, journal, now):
    value = decode(issued, 'enrollment operation journal root_revision statement checkpoint grant')
    require(identifier(value['enrollment']) == invitation.operation
            and host_revision(value['root_revision']) == invitation.revision
            and identifier(value['journal']) == journal, 'credential issuance differs from original installation')
    membership = CurrentMembership.from_trusted(current, authority)
    pin = membership.pin(invitation)
    target = checkpoint(value['checkpoint'])
    require(target == (membership.version, membership.digest), 'credential issuance differs from selected current roster')
    listing = roster(pin, membership.wire, expected=pin.checkpoint()); listing.validity.check(now)
    return identifier(value['operation']), encoded(value['grant'], 65536), pin.checkpoint(), identifier(value['statement'])


def companions(raw, authority, target):
    """Bound untrusted issuer envelopes; owner verifies each signed grant.

    Companion enrollment/journal IDs are public correlation, not local owners.
    The original account state supplies device history and complete-set checks.
    """
    from .account_state import MAX_GRANTS
    from .storage_budget import MAX_ACCOUNT_REQUEST
    value = decode(raw, 'schema grants', MAX_ACCOUNT_REQUEST * 2)
    require(value['schema'] == 'qperiapt-companion-credential-grants/1'
            and type(value['grants']) is list and len(value['grants']) < MAX_GRANTS,
            'companion credential schema or capacity')
    wires, expected = [], []
    for item in value['grants']:
        shape(item, 'enrollment operation journal root_revision statement checkpoint grant')
        identifier(item['enrollment']); identifier(item['journal'])
        require(host_revision(item['root_revision']) == authority.revision
                and checkpoint(item['checkpoint']) == (int.from_bytes(target[:8], 'big'), target[8:]),
                'companion differs from selected account revision or roster')
        wires.append(encoded(item['grant'], 65536))
        expected.append((identifier(item['operation']), identifier(item['statement'])))
    return tuple(wires), tuple(expected)
