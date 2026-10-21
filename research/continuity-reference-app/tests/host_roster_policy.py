"""Real authenticated P between two original R transitions; no account signer."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import os
import time
from native_exchange_fixture import b64, save
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.wire import require


def activation(native):
    if native.original_policy is None:
        return [native.binary, 'activate', *native.active_args]
    return [native.binary, 'policy-witness-activate', *native.common, native.current_path,
            native.original_policy, native.policy_input, native.witness.endpoint()]


def adopt(root, native, probe, witness, paths, run, selected):
    history = root / 'p-original-policy.json'
    original = {'pins': json.loads((root/'policy-pins.json').read_bytes()),
                'materials': json.loads((root/'policy-materials.json').read_bytes())}
    save(history, original)
    operation = b64(os.urandom(32)); request_file = root/'p-retained-request.json'
    run([native.binary, 'policy-witness-request', *native.common, operation, history, witness.endpoint(), request_file], 'p-request')
    request = json.loads(request_file.read_bytes())
    require(request['scope']['current_roster'] == native.current['roster']['checkpoint'], 'P lost preceding R')
    publisher, db, owner = paths['publisher'], root/'publisher.redb', selected['publisher']
    target_id = b64(os.urandom(32)); old = selected['publication']
    publication = root/'p-target-publication.json'
    source = json.loads((root/'policy-request.json').read_bytes())
    save(publication, dict(source, valid_until=int(time.time())+3600))
    target_dir = root/'p-target'; target_dir.mkdir(mode=0o700)
    run([publisher,'issue',db,owner,target_id,publication,target_dir],'p-target-issue')
    run([publisher,'renewal-enable',db,owner],'p-publisher-enable')
    selection = root/'p-selected-policies.json'
    run([publisher,'renewal-policies',db,owner,old,old,target_id,selection],'p-policies')
    policies = json.loads(selection.read_bytes())
    body = {'retained':request,'original_extension':None,'current_extension':None,
            **{key:policies[key] for key in ('original','previous','target')}}
    preview = probe.request('alice','p-account-preview','/api/enrollment/policy-approval/preview',body)
    require(preview['state']=='Absent' and preview['review']['witness_required'] is True,'P account review differs')
    probe.request('alice','p-account-lost','/api/enrollment/policy-approval',body,lost=True)
    status = probe.request('alice','p-account-status','/api/enrollment/policy-approval/status',body)
    require(status['state']=='Issued','P account original result not retained')
    approved = probe.request('alice','p-account-retry','/api/enrollment/policy-approval',body,raw=True)
    require(encoded(status['response'],131072)==approved,'P account retry re-signed or changed result')
    issued = json.loads(approved); statement = b64(bytes(issued['statement']))
    account_file=root/'p-account-approval.bin'; save(account_file,encoded(issued['approval'],65536))
    policy_file=root/'p-policy-approval.bin'
    authority=run([publisher,'renewal-approve',db,owner,request_file,native.current_path,old,old,target_id,policy_file],'p-policy-approve')
    require(authority['state']=='Issued' and authority['result']['statement']==issued['statement'],'P roots approved different relations')
    staged=run([native.binary,'policy-witness-stage',*native.common,request_file,account_file,policy_file,native.current_path,
        root/'policy-pins.json',root/'policy-materials.json',root/'policy-pins.json',root/'policy-materials.json',
        target_dir/'policy-pins.json',target_dir/'policy-materials.json'],'p-stage')
    require(staged['state']=='Pending' and staged['statement']==issued['statement'],'P staging differs')
    occupied=root/'p-occupied.json';save(occupied,b'original policy export retained')
    run([native.binary,'policy-witness-prepare',*native.common,operation,statement,selection,witness.endpoint(),occupied],
        'p-lost-export',success=False)
    require(occupied.read_bytes()==b'original policy export retained','P replaced export')
    preparation_file=root/'p-preparation.json'
    preparation=run([native.binary,'policy-witness-recover-preparation',*native.common,operation,statement,history,preparation_file],'p-recover')
    require(preparation==json.loads(preparation_file.read_bytes()),'P preparation export differs')
    pending=run([native.binary,'policy-witness-commit',*native.common,preparation_file,selection,witness.endpoint()],'p-unapproved')
    require(pending=={'binding':preparation['binding'],'state':'Unavailable'},'P unapproved target changed authority')
    target_input=root/'p-target-policy.json';save(target_input,policies['target'])
    args=[native.binary,'policy-witness-activate',*native.common,native.current_path,history,target_input,witness.endpoint()]
    run(args,'p-pending-activation',success=False)
    trust=root/'p-witness-trust.json'
    save(trust,{'schema':'qperiapt-witness-policy-renewal-trust/1','account':native.current,
        'device':native.invitation['device'],'generation':native.invitation['generation'],
        'subject':b64(bytes(native.prepared['subject'])),'proposal_binding':preparation['binding'],'request':request,
        **{key:policies[key] for key in ('original','previous','target')}})
    run(witness.command('policy-prepare',trust,preparation_file),'p-witness-lost-output',success=False,lost_stdout=True)
    require(run(witness.command('policy-prepare',trust,preparation_file),'p-witness-retry')==
            {'binding':preparation['binding'],'state':'Prepared'},'P witness exact preparation absent')
    run([native.binary,'policy-witness-commit',*native.common,preparation_file,selection,witness.endpoint()],
        'p-commit-lost-output',success=False,lost_stdout=True)
    observed=run([native.binary,'policy-witness-observe',*native.common,preparation_file,history,witness.endpoint()],'p-observe')
    progress=run([native.binary,'policy-witness-status',*native.common],'p-status')
    require(observed=={'binding':preparation['binding'],'state':'Applied'} and progress['state']=='Applied'
            and progress['retired'] is True,'P did not recover exact retired result')
    run(activation(native),'p-old-activation',success=False)
    native.original_policy=history;native.policy_input=target_input
    native.local_inputs=[native.current_path,target_dir/'policy-pins.json',target_dir/'policy-materials.json']
    require(bytes(run(activation(native),'p-activate')['journal'])==native.journal,'P replaced original journal')
    return {'operation':operation,'statement':statement,'preparation':preparation,'observation':observed,'progress':progress,
            'request':request,'account_approval':issued,'policy_approval':authority['result']}
