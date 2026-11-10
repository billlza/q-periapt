"""Independently chosen test approvals and retained native issuance materials."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import base64
from dataclasses import dataclass
import json
import os


def encoded(value): return json.dumps(value, separators=(',', ':')).encode()
def b64(value): return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
def checkpoint(value):
    if len(value) != 40: raise ValueError('checkpoint width')
    return {'version':int.from_bytes(value[:8], 'big'), 'digest':list(value[8:])}


@dataclass(frozen=True)
class Grant:
    original: tuple[bytes, ...]
    refresh: tuple[bytes, ...]
    extension: tuple[bytes, ...]


def grant(public, authority, invitation, pins, materials, witness):
    from fixture_inputs import read_public
    head=checkpoint(read_public(public,'original-i-checkpoint'))
    issued={'operation':invitation['operation'],'root_revision':1,
            'certificate':b64(read_public(public,'original-i-credential')),
            'roster':b64(read_public(public,'original-i-roster')),'checkpoint':head}
    current={'revision':1,'account':list(pins.initiator.account),'public_key':authority['root'],
             'family':authority['family'],'suspended':False,
             'roster':{'checkpoint':head,'bytes':issued['roster']}}
    old_policy_head=checkpoint(read_public(public,'original-pin-policy-head'))
    policy_pins={'schema':'qperiapt-policy-pins/1','sdk_root':b64(pins.sdk_root),'sdk_state':b64(pins.sdk_state),
                 'policy_root':b64(pins.policy_root.raw),'policy_version':old_policy_head['version'],
                 'policy_digest':old_policy_head['digest'],
                 'witness':None if witness is None else {'identity':list(witness.identity),'key':b64(witness.key.raw)}}
    policy_materials={'schema':'qperiapt-policy-materials/1','sdk_document':b64(materials.sdk_document),
                      'sdk_signature':b64(materials.sdk_signature),'policy':b64(read_public(public,'original-policy'))}
    approval={'request_id':list(os.urandom(32)),'enrollment':invitation['operation'],
              'previous_extension':None,'predecessor':head,'valid_until':300}
    target_head={'version':pins.initiator.roster_version,'digest':list(pins.initiator.roster_digest)}
    extension={'request':approval,'root_revision':1,'certificate':b64(materials.initiator_credential),
               'roster':b64(materials.initiator_roster),'checkpoint':target_head}
    target_current=dict(current,roster={'checkpoint':target_head,'bytes':extension['roster']})
    target_pins=dict(policy_pins,policy_version=pins.policy_version,policy_digest=list(pins.policy_digest))
    target_materials=dict(policy_materials,policy=b64(materials.policy))
    return Grant(
        tuple(encoded(x) for x in (invitation,issued,current,policy_pins,policy_materials)),
        tuple(encoded(x) for x in (current,policy_pins,policy_materials)),
        tuple(encoded(x) for x in (invitation,approval,extension,target_current,target_pins,target_materials)),
    )
