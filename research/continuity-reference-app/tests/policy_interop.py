#!/usr/bin/env python3
"""Native publisher CLI to the selected independent OpenSSL verifier.

Both native tools create their own protected signers through their operator CLIs.
The witness pin is an explicit test fixture. No account/device authorization or
real witness service is inferred from these public policy checks.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--publisher', type=Path, required=True)
parser.add_argument('--sdk-authority', type=Path, required=True)
parser.add_argument('--implementation-root', type=Path, required=True)
parser.add_argument('--provider-root', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
implementation = args.implementation_root.resolve(strict=True)
sys.path.insert(0, str(implementation))
from qperiapt_continuity_reference.provider import load_provider
provider, backend = load_provider(args.provider_root)
from cryptography.hazmat.primitives.asymmetric import mldsa
from qperiapt_continuity_reference import enrollment_exchange
from qperiapt_continuity_reference.authority import authenticate_policy
from qperiapt_continuity_reference.wire import SigningKey
assert Path(enrollment_exchange.__file__).resolve().is_relative_to(implementation)
publisher = args.publisher.resolve(strict=True)
native_digest = hashlib.sha256(publisher.read_bytes()).hexdigest()
sdk_authority = args.sdk_authority.resolve(strict=True)
sdk_digest = hashlib.sha256(sdk_authority.read_bytes()).hexdigest()
root = args.output
assert root.is_absolute() and not root.exists()
root.mkdir(mode=0o700)
inputs = root / 'private-inputs'; inputs.mkdir(mode=0o700)
database = root / 'publisher.redb'
sdk_database = root / 'sdk-authority.redb'
b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b'=').decode()
encode = lambda value: json.dumps(value, separators=(',', ':')).encode()
commands = []

def save(name, data):
    path = inputs / name
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())
    return path

def directory(name):
    path = root / name; path.mkdir(mode=0o700); return path

identity = b64(os.urandom(32))
sdk_identity = b64(os.urandom(32))

def run(label, operation, *values, success=True, sdk=False):
    command = [str(sdk_authority if sdk else publisher), operation,
               str(sdk_database if sdk else database), sdk_identity if sdk else identity, *map(str, values)]
    result = subprocess.run(command, capture_output=True, timeout=60, check=False)
    assert len(result.stdout) <= 256 * 1024 and len(result.stderr) <= 256 * 1024
    (root / (label + '.stdout')).write_bytes(result.stdout)
    (root / (label + '.stderr')).write_bytes(result.stderr)
    commands.append({'label':label,'tool':'sdk' if sdk else 'protocol','argv':command,'exit':result.returncode})
    (root / 'COMMANDS.json').write_bytes(encode(commands))
    assert (result.returncode == 0) is success, (label, result.stderr.decode())
    if success:
        assert not result.stderr, (label, result.stderr.decode())
        return json.loads(result.stdout)
    assert result.stdout == b'', (label, 'failure emitted a success response')
    return result.stderr.decode()

def check(path):
    pins, materials = (path / 'policy-pins.json').read_bytes(), (path / 'policy-materials.json').read_bytes()
    policy = enrollment_exchange.PolicyInputs.from_trusted(pins, materials)
    verified = authenticate_policy(policy.pins, policy.materials, int(time.time()), witness_pin=policy.witness)
    assert verified.family == bytes(authority['family'])
    assert b64(policy.pins.policy_root.raw) == authority['policy_root']
    return pins, materials, verified

try:
    sdk_root_info = run('sdk-init', 'init', sdk=True)
    assert sdk_root_info['allocated_version'] == 0 and sdk_root_info['pending'] is None
    assert run('sdk-prepare', 'prepare', sdk=True) == sdk_root_info
    assert run('sdk-authority', 'authority', sdk=True) == sdk_root_info
    document = b'schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile="ContextBound"\nallowed_kems=["ML-KEM-768","X25519"]\nallowed_sigs=["ML-DSA-65"]\ndeprecated=[]\n'
    sdk_document = save('sdk-request-v1.toml', document)
    jump = save('sdk-request-max.toml', document.replace(b'policy_version=1', b'policy_version=4294967295'))
    sdk_refused = directory('sdk-export-refused-version')
    assert 'next allocated version' in run('sdk-refuse-version', 'issue', b64(os.urandom(32)), jump,
                                           sdk_refused, sdk=True, success=False)
    assert not list(sdk_refused.iterdir())
    sdk_operation = b64(os.urandom(32)); sdk_first = directory('sdk-export-first')
    sdk_issued = run('sdk-issue-first', 'issue', sdk_operation, sdk_document, sdk_first, sdk=True)

    def sdk_check(path, issued, expected_version):
        values = {name:(path/name).read_bytes() for name in ('sdk-root','sdk-state','sdk-document','sdk-signature')}
        assert issued['version'] == expected_version
        assert b64(values['sdk-root']) == sdk_root_info['root'] == issued['input']['root']
        assert values['sdk-state'] == expected_version.to_bytes(4,'big') + hashlib.sha3_256(values['sdk-document']).digest()
        assert issued['input'] == {name.removeprefix('sdk-'):b64(value) for name,value in values.items()}
        message = b'Q-PERIAPT-SIGNED-POLICY/v1' + len(values['sdk-document']).to_bytes(8,'big') + values['sdk-document']
        mldsa.MLDSA65PublicKey.from_public_bytes(values['sdk-root']).verify(values['sdk-signature'], message)
        return values

    original_sdk = sdk_check(sdk_first, sdk_issued, 1)
    sdk_root, state = original_sdk['sdk-root'], original_sdk['sdk-state']
    assert original_sdk['sdk-document'] == document
    for label, name, operation_name in [('sdk-retrieve-first','sdk-export-retrieved','result'),
                                         ('sdk-retry-first','sdk-export-retry','issue')]:
        destination = directory(name)
        parameters = [sdk_operation, sdk_document, destination] if operation_name == 'issue' else [sdk_operation,destination]
        assert run(label, operation_name, *parameters, sdk=True) == sdk_issued
        assert sdk_check(destination, sdk_issued, 1) == original_sdk
    sdk_second_document = save('sdk-request-v2.toml', document.replace(b'policy_version=1',b'policy_version=2'))
    sdk_retarget = directory('sdk-export-refused-retarget')
    assert 'Original SDK policy document differs' in run('sdk-refuse-retarget','issue',sdk_operation,
                sdk_second_document,sdk_retarget,sdk=True,success=False)
    assert not list(sdk_retarget.iterdir())
    authority = run('init', 'init', *[sdk_first/name for name in ('sdk-root','sdk-state','sdk-document','sdk-signature')])
    assert authority['sdk_root'] == b64(sdk_root) and authority['sdk_state'] == b64(state)
    assert run('prepare', 'prepare') == authority and run('authority', 'authority') == authority
    now = int(time.time())
    request = {'bootstrap_mode':'reusable_both', 'valid_from':now-5, 'valid_until':now+900,
               'send_budget':100, 'anchor':{'kind':'local_only'}}
    contradictory = dict(request, anchor={'kind':'local_only','identity':list(os.urandom(32)),'key':'AQ'})
    contradictory_path = save('request-contradictory.json', encode(contradictory))
    refused_fields = directory('export-refused-fields')
    assert 'unknown field' in run('refuse-anchor-fields', 'issue', b64(os.urandom(32)),
                                 contradictory_path, refused_fields, success=False)
    assert not list(refused_fields.iterdir())
    request_path = save('request-local.json', encode(request)); operation = b64(os.urandom(32))
    first_path = directory('export-first')
    issued = run('issue-first', 'issue', operation, request_path, first_path)
    pins1, materials1, verified1 = check(first_path)
    assert issued['version'] == verified1.version == 1 and verified1.budget == 100
    second_path = directory('export-retrieved')
    assert run('retrieve-first', 'result', operation, second_path) == issued
    retry_path = directory('export-retry')
    assert run('retry-first', 'issue', operation, request_path, retry_path) == issued
    for path in (second_path, retry_path):
        assert {p.name:p.read_bytes() for p in path.iterdir()} == {p.name:p.read_bytes() for p in first_path.iterdir()}
    before = {p.name:p.read_bytes() for p in first_path.iterdir()}
    assert 'Export directory must be empty' in run('refuse-overwrite', 'result', operation, first_path, success=False)
    assert {p.name:p.read_bytes() for p in first_path.iterdir()} == before
    changed = save('changed-request.json', encode(dict(request, send_budget=99)))
    refused = directory('export-refused')
    assert 'Original policy request differs' in run('refuse-retarget', 'issue', operation, changed, refused, success=False)
    assert not list(refused.iterdir())

    witness = SigningKey(); witness_id = os.urandom(32)
    required = dict(request, send_budget=99, anchor={'kind':'required','identity':list(witness_id),'key':b64(witness.public().raw)})
    witnessed_path = directory('export-witnessed')
    witnessed = run('issue-witnessed', 'issue', b64(os.urandom(32)), save('request-witnessed.json', encode(required)), witnessed_path)
    pins2, materials2, verified2 = check(witnessed_path)
    assert witnessed['version'] == verified2.version == 2 and verified2.budget == 99
    wrong = enrollment_exchange.PolicyInputs.from_trusted(pins1, materials2)
    try: authenticate_policy(wrong.pins, wrong.materials, int(time.time()), witness_pin=wrong.witness)
    except ValueError as error: assert 'digest pin' in str(error)
    else: raise AssertionError('new materials selected their own policy pin')

    disabled_path = directory('export-disabled')
    disabled = run('issue-disabled', 'issue', b64(os.urandom(32)),
                   save('request-disabled.json', encode(dict(request, bootstrap_mode='disabled'))), disabled_path)
    policy = enrollment_exchange.PolicyInputs.from_trusted((disabled_path/'policy-pins.json').read_bytes(),
                                                          (disabled_path/'policy-materials.json').read_bytes())
    assert disabled['version'] == 3
    policy.pins.policy_root.open(policy.materials.policy, 4, 200)
    try: authenticate_policy(policy.pins, policy.materials, int(time.time()))
    except ValueError as error: assert 'reusable quality not permitted' in str(error)
    else: raise AssertionError('disabled bootstrap policy granted reusable bootstrap')
    assert 'Issued policy cannot be cancelled' in run('refuse-issued-cancel', 'cancel', operation, success=False)
    historical = directory('export-original-after-updates')
    assert run('original-after-updates', 'result', operation, historical) == issued
    assert (historical/'policy-pins.json').read_bytes() == pins1
    assert (historical/'policy-materials.json').read_bytes() == materials1
    sdk_second_path = directory('sdk-export-second')
    sdk_second = run('sdk-issue-second','issue',b64(os.urandom(32)),sdk_second_document,sdk_second_path,sdk=True)
    sdk_check(sdk_second_path,sdk_second,2)
    sdk_historical = directory('sdk-export-original-after-updates')
    assert run('sdk-original-after-updates','result',sdk_operation,sdk_historical,sdk=True) == sdk_issued
    assert sdk_check(sdk_historical,sdk_issued,1) == original_sdk
    assert 'Issued SDK policy cannot be cancelled' in run('sdk-refuse-issued-cancel','cancel',sdk_operation,sdk=True,success=False)
    assert hashlib.sha256(publisher.read_bytes()).hexdigest() == native_digest
    assert hashlib.sha256(sdk_authority.read_bytes()).hexdigest() == sdk_digest
    result = {'completed':True, 'native_sha256':native_digest, 'commands':len(commands),
              'sdk_authority_sha256':sdk_digest, 'sdk_policy_versions':[1,2],
              'expected_refusals':sum(c['exit'] != 0 for c in commands), 'policy_versions':[1,2,3],
              'provider':provider.__version__, 'openssl':backend.openssl_version_text(),
              'independent_implementation':str(Path(enrollment_exchange.__file__).resolve()),
              'private_state_retained':str(root),
              'scope':'Native SDK authority and protocol publisher CLIs to independent OpenSSL verifier with an explicit witness test pin. No fixture SDK signing key. Local operator trust, no real user/device authorization, witness service, live consumer activation or authority replacement.'}
    (root/'RESULT.json').write_bytes(encode(result)); print(json.dumps(result))
except BaseException as error:
    (root/'FAILURE.json').write_bytes(encode({'completed':False,'error':type(error).__name__+': '+str(error),'private_state_retained':str(root)}))
    raise
