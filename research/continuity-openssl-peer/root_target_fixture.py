"""Explicit isolated test issuer and real inactive independent successor.

The selected native policy/responder materials are reused unchanged. The test
host independently approves a fresh root, issues this actual client's request,
and prepares its original journal. This is not a live user-account approval.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import base64
from dataclasses import replace
import json
import os
from qperiapt_continuity_reference.account_root_protocol import Plan
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.enrollment_exchange import HostAuthority, HostInvitation
from qperiapt_continuity_reference.identity import DevicePin
from qperiapt_continuity_reference.registration_inputs import Inputs
from qperiapt_continuity_reference.wire import Reader, SigningKey, digest, require
from signing_fixture import write


def prepare(private, application, pins, materials, context, now, fresh_peer, *, root_revision=2,credential_until=None):
    require(context.witness is not None, 'root target fixture requires original witness policy')
    require(type(root_revision) is int and 2 <= root_revision < 2**64, 'root target fixture revision')
    path = private / 'root-target'; path.mkdir(mode=0o700)
    client_path, session_path = path / 'client', path / 'session'
    client_path.mkdir(mode=0o700); session_path.mkdir(mode=0o700)
    root = SigningKey(); write(path / 'issuer', root)
    identity, key, device, operation = os.urandom(32), os.urandom(32), os.urandom(16), os.urandom(32)
    with os.fdopen(os.open(path / 'host-key-and-id', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
        out.write(key + identity); out.flush(); os.fsync(out.fileno())
    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
    wire = lambda value: json.dumps(value, separators=(',', ':')).encode()
    validity = context.original_policy.validity
    if credential_until is not None:
        require(type(credential_until) is int and now<credential_until<=validity.end,'target credential fixture validity')
        validity=type(validity)(validity.start,credential_until)
    authority = {'schema':'qperiapt-host-authority/1', 'application':list(application),
                 'root_revision':root_revision, 'root':b64(root.public().raw), 'family':list(context.family)}
    invitation = {'operation':list(operation), 'request_id':list(os.urandom(32)), 'application':list(application),
                  'root_revision':root_revision, 'root':authority['root'], 'family':authority['family'], 'device':list(device),
                  'generation':1, 'valid_from':validity.start, 'valid_until':validity.end,
                  'deadline':validity.end, 'predecessor':None}
    owner = EnrollmentClient.begin(client_path, identity, key, wire(authority), wire(invitation), now)
    try:
        selected = HostInvitation.decode(wire(invitation), HostAuthority.from_trusted(wire(authority)))
        request = owner.request(now); _, public = selected.intent.verify_request(request, now)
        account = digest(b'ACCOUNT', root.public().raw)
        interval = validity.start.to_bytes(8, 'big') + validity.end.to_bytes(8, 'big')
        body = b'QPCERT01' + account + device + (1).to_bytes(8, 'big') + interval + context.family + public.raw
        certificate = root.sign(1, body)
        roster_body = (b'QPROST01' + account + (1).to_bytes(8, 'big') + interval + (1).to_bytes(2, 'big')
                       + device + (1).to_bytes(8, 'big') + digest(b'CREDENTIAL', body))
        roster = root.sign(2, roster_body); checkpoint = digest(b'ROSTER', roster_body)
        device_pin = DevicePin(root.public(), account, 1, checkpoint, device, 1)
        target_pins = replace(pins, initiator=device_pin)
        reader = Reader(fresh_peer)
        fields = [reader.take(reader.integer(4)) for _ in range(3)]; reader.finish()
        target_materials = replace(materials, initiator_credential=certificate, initiator_roster=roster,
                                   manifest=fields[0], classical_proof=fields[1], pq_proof=fields[2])
        current = {'revision':root_revision, 'account':list(account), 'public_key':authority['root'], 'family':authority['family'],
                   'suspended':False, 'roster':{'checkpoint':{'version':1, 'digest':list(checkpoint)}, 'bytes':b64(roster)}}
        issued = {'operation':list(operation), 'root_revision':root_revision, 'certificate':b64(certificate), 'roster':b64(roster),
                  'checkpoint':{'version':1, 'digest':list(checkpoint)}}
        policy_pins = {'schema':'qperiapt-policy-pins/1', 'sdk_root':b64(pins.sdk_root), 'sdk_state':b64(pins.sdk_state),
                       'policy_root':b64(pins.policy_root.raw), 'policy_version':pins.policy_version,
                       'policy_digest':list(pins.policy_digest),
                       'witness':{'identity':list(context.witness.pin.identity), 'key':b64(context.witness.pin.key.raw)}}
        policy_materials = {'schema':'qperiapt-policy-materials/1', 'sdk_document':b64(materials.sdk_document),
                            'sdk_signature':b64(materials.sdk_signature), 'policy':b64(materials.policy)}
        journal = owner.accept(wire(invitation), wire(issued), wire(current), wire(policy_pins), wire(policy_materials), now)
        inputs = Inputs(target_pins, target_materials, context.witness.pin)
        genesis = owner.prepare(session_path, inputs, now)
        plan = Plan(context.witness.pin, os.urandom(32), os.urandom(32), pins.initiator.root, device_pin,
                    certificate, roster, context.original_policy, journal, genesis[-32:])
        require(plan._parts()[2] == genesis[:96], 'actual prepared successor subject differs')
        with (path / 'approved-public.json').open('x') as out:
            json.dump({'authority':authority, 'invitation':invitation, 'issued':issued, 'current':current,
                       'policy_pins':policy_pins, 'policy_materials':policy_materials, 'genesis':genesis.hex(),
                       'plan':plan.wire().hex()}, out, indent=2); out.write('\n')
        return plan
    finally:
        owner.close()
