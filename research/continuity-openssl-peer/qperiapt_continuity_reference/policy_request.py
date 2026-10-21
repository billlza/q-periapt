"""Public host policy request derived only from an owned protected snapshot."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import base64
from .policy_renewal_proof import Scope
from .roster_protocol import checkpoint
from .wire import Reader, require


def public_checkpoint(value):
    checkpoint(value)
    return {'version': int.from_bytes(value[:8], 'big'), 'digest': list(value[8:])}


def for_host(invitation, request):
    raw = request['scope']
    require(type(raw) is bytes and len(raw) == 313, 'owned policy request scope size')
    reader = Reader(raw)
    identities = [reader.take(32) for _ in range(5)]
    checkpoints = [reader.take(40) for _ in range(3)]
    present, authorization = reader.integer(1), reader.take(32)
    reader.finish()
    require(present in (0, 1) and (present == 1 or authorization == bytes(32)),
            'owned policy predecessor flag')
    scope = Scope(*identities, *checkpoints, authorization if present else None)
    require(scope.wire() == raw, 'owned policy request is not canonical')
    names = ('operation', 'journal', 'original_owner', 'original_credential', 'current_credential')
    exposed = {name: list(getattr(scope, name)) for name in names}
    for name in ('current_roster', 'original_policy', 'previous_policy'):
        exposed[name] = public_checkpoint(getattr(scope, name))
    exposed['previous_authorization'] = None if scope.previous_authorization is None else list(scope.previous_authorization)
    result = {'schema': 'qperiapt-retained-policy-request/1', 'application': list(invitation.application),
              'enrollment': list(invitation.operation), 'root_revision': invitation.revision, 'scope': exposed,
              'original_checkpoint': public_checkpoint(request['original_checkpoint'])}
    for target, source in (('original_certificate', 'original_credential'), ('original_roster', 'original_roster'),
                           ('current_certificate', 'current_credential'), ('current_roster', 'current_roster')):
        value = request[source]
        require(type(value) is bytes and 0 < len(value) <= 16384, 'owned policy public record bound')
        result[target] = base64.urlsafe_b64encode(value).rstrip(b'=').decode()
    return result
