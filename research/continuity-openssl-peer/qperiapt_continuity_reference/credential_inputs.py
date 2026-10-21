"""Correlate host issuance with protected enrollment and separately selected trust.

This does not replace signature verification by the original journal owner.
The statement is compared to the authenticated grant before any preparation.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .enrollment_exchange import CurrentMembership, checkpoint, decode, encoded, host_revision, identifier
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
