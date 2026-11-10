"""Public credential issuer context from the original protected session."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .policy_owner_inputs import certificate, check_original
from .policy_snapshot import authorization, current_device, original
from .policy_renewal_proof import storage_owner
from .policy_request import public_checkpoint
from .cli_files import public
from .identity_state import local_view
from .wire import require


def retained(state, context, inputs, operation, journal):
    require(inputs is not None, 'credential request requires original protected inputs')
    check_original(context, inputs)
    require(state.traffic is not None, 'credential request requires original established session')
    for record in (state.local_renewal, state.account_renewal):
        if record is None: continue
        require(record.pending is None, 'credential renewal remains pending')
        if state.account_renewal is record:
            require(record.known(operation) is None, 'credential request operation already retained')
        else:
            require(record.expired is None or record.expired.operation != operation,
                    'credential request operation already retained')
    view = local_view(state, context)
    require(view is None or view.renewal is None or view.renewal.operation != operation,
            'credential request operation already retained')
    policy = original(context)
    record = state.policy_renewal
    require(record is None or record.pending is None, 'policy renewal remains pending')
    active = policy if record is None or record.active is None else record.active.target
    current = current_device(state, context)
    return {'operation': operation, 'journal': journal, 'original_owner': storage_owner(context.devices[0]),
            'original_policy': policy.checkpoint(), 'current_policy': active.checkpoint(),
            'current_policy_authorization': authorization(state), 'previous_checkpoint': current.pin.checkpoint(),
            'original_certificate': inputs.materials.initiator_credential,
            'previous_certificate': certificate(state, context, current, inputs),
            'original_roster': inputs.materials.initiator_roster, 'previous_roster': current.roster_wire}


def for_host(invitation, request):
    result = {'schema': 'qperiapt-retained-credential-request/1', 'application': list(invitation.application),
              'enrollment': list(invitation.operation), 'root_revision': invitation.revision}
    for name in ('operation', 'journal', 'original_owner'): result[name] = list(request[name])
    for name in ('original_policy', 'current_policy', 'previous_checkpoint'):
        result[name] = public_checkpoint(request[name])
    value = request['current_policy_authorization']
    result['current_policy_authorization'] = None if value is None else list(value)
    for name in ('original_certificate', 'previous_certificate', 'original_roster', 'previous_roster'):
        result[name] = public(request[name])
    return result
