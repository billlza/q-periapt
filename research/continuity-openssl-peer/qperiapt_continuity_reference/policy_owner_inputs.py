"""Original protected inputs shared by the local and witnessed P coordinators."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .identity_state import local_view
from .policy_record import retained_device
from .policy_snapshot import original
from .renewal import field
from .wire import Reader, require


def check_original(context, inputs):
    original(context)
    first = retained_device(context.devices[0], inputs.materials.initiator_credential,
                            inputs.materials.initiator_roster, context.devices[0].pin.checkpoint(), context.family)
    require(first == context.devices[0], "policy original credential inputs differ")


def certificate(state, context, current, inputs):
    view = local_view(state, context)
    if view is None or view.renewal is None:
        wire = inputs.materials.initiator_credential
    else:
        reader = Reader(view.renewal.wire)
        require(reader.take(8) == b"QPRNB001", "retained credential grant tag")
        _, _, _, wire = (field(reader) for _ in range(4))
    checked = retained_device(context.devices[0], wire, current.roster_wire,
                              current.pin.checkpoint(), context.family)
    require(checked == current, "policy current credential differs from actual journal")
    return wire


def public_request(state, context, record, current, inputs, operation, journal):
    policy = original(context)
    scope = record.request(operation, policy, context.devices[0], journal, current)
    previous = policy if record.active is None else record.active.target
    return {"scope": scope.wire(), "original_policy": policy.wire, "previous_policy": previous.wire,
            "original_credential": inputs.materials.initiator_credential,
            "original_roster": inputs.materials.initiator_roster,
            "current_credential": certificate(state, context, current, inputs), "current_roster": current.roster_wire}
