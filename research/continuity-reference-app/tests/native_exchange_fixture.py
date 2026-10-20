"""Explicit test issuer; never imported by the application or installed package."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import base64
import hashlib
import json
import os
import time
from cryptography.hazmat.primitives.asymmetric import mldsa
from qperiapt_continuity_reference.authority import SUITE
from qperiapt_continuity_reference.enrollment_exchange import HostAuthority, HostInvitation, PolicyInputs
from qperiapt_continuity_reference.wire import SigningKey, digest


def b64(value): return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
def wire(value): return json.dumps(value, separators=(',', ':')).encode()
def save(path, value):
    data = value if isinstance(value, bytes) else wire(value)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as file:
        file.write(data); file.flush(); os.fsync(file.fileno())


class Issuer:
    def __init__(self, path, *, witness=None):
        self.path = path
        self.start = int(time.time()); self.end = self.start + 1800
        self.root, policy_root = SigningKey(), SigningKey()
        self.account = digest(b'ACCOUNT', self.root.public().raw)
        sdk_root = mldsa.MLDSA65PrivateKey.generate()
        sdk_public = sdk_root.public_key().public_bytes_raw()
        document = b'schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile="ContextBound"\nallowed_kems=["ML-KEM-768","X25519"]\nallowed_sigs=["ML-DSA-65"]\ndeprecated=[]\n'
        state = (1).to_bytes(4, 'big') + hashlib.sha3_256(document).digest()
        signature = sdk_root.sign(b'Q-PERIAPT-SIGNED-POLICY/v1' + len(document).to_bytes(8,'big') + document)
        self.family = digest(b'POLICY-AUTHORITY', policy_root.public().raw)
        policy = (b'QPSESP03' + self.family + (1).to_bytes(8,'big') + self.start.to_bytes(8,'big')
                  + self.end.to_bytes(8,'big') + SUITE + hashlib.sha256(sdk_public).digest() + state
                  + b'\2' + (b'\0'+bytes(32) if witness is None else b'\1'+witness.binding)
                  + (8).to_bytes(2,'big'))
        pins = {'schema':'qperiapt-policy-pins/1','sdk_root':b64(sdk_public),'sdk_state':b64(state),
                'policy_root':b64(policy_root.public().raw),'policy_version':1,
                'policy_digest':list(digest(b'SESSION-POLICY',policy)),
                'witness':None if witness is None else {'identity':list(witness.identity),'key':b64(witness.key.raw)}}
        materials = {'schema':'qperiapt-policy-materials/1','sdk_document':b64(document),
                     'sdk_signature':b64(signature),'policy':b64(policy_root.sign(4,policy))}
        save(path/'policy-pins.json',pins); save(path/'policy-materials.json',materials)
        self.policy = PolicyInputs.from_trusted(wire(pins),wire(materials))
        self.authority_json = {'schema':'qperiapt-host-authority/1','application':list(os.urandom(32)),
                               'root_revision':1,'root':b64(self.root.public().raw),'family':list(self.family)}
        self.authority = HostAuthority.from_trusted(wire(self.authority_json))
        self.members = []

    def invitation(self, name):
        value = {'operation':list(os.urandom(32)),'request_id':list(os.urandom(32)),
                 'application':self.authority_json['application'],'root_revision':1,
                 'root':self.authority_json['root'],'family':list(self.family),'device':list(os.urandom(16)),
                 'generation':1,'valid_from':self.start,'valid_until':self.end,
                 'deadline':self.start+600,'predecessor':None}
        save(self.path/(name+'-invitation.json'),value)
        return value, HostInvitation.decode(wire(value), self.authority)

    def certificate(self, invitation, request):
        _, public = invitation.intent.verify_request(request,int(time.time()))
        body = (b'QPCERT01'+self.account+invitation.intent.device+(1).to_bytes(8,'big')
                +self.start.to_bytes(8,'big')+self.end.to_bytes(8,'big')+self.family+public.raw)
        self.members.append((invitation.intent.device,digest(b'CREDENTIAL',body)))
        return self.root.sign(1,body)

    def current(self):
        body = (b'QPROST01'+self.account+(1).to_bytes(8,'big')+self.start.to_bytes(8,'big')
                +self.end.to_bytes(8,'big')+len(self.members).to_bytes(2,'big'))
        body += b''.join(device+(1).to_bytes(8,'big')+certificate for device,certificate in sorted(self.members))
        self.roster, self.checkpoint = self.root.sign(2,body), {'version':1,'digest':list(digest(b'ROSTER',body))}
        current = {'revision':1,'account':list(self.account),'public_key':self.authority_json['root'],
                   'family':list(self.family),'suspended':False,
                   'roster':{'checkpoint':self.checkpoint,'bytes':b64(self.roster)}}
        save(self.path/'current.json',current)
        return current

    def issued(self, invitation, certificate):
        return {'operation':invitation['operation'],'root_revision':1,'certificate':b64(certificate),
                'roster':b64(self.roster),'checkpoint':self.checkpoint}
