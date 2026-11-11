"""Complete-account G through the independent CLI and native witness operator.

The existing explicit test issuer supplies public grants. The test operator
selects the original witness subject and exact proposal independently of network
input. No production account login, clock override or signer API is introduced.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
import sys
from account_credential_cli import grant_set
from host_replacement_process import Commands,fingerprints
from native_exchange_fixture import b64,save
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.local_renewal_protocol import Proposal
from qperiapt_continuity_reference.wire import require


def exercise(issuer,implementation,provider,root,client_dir,session_dir,client_id,
             local_journal,native_journal,sid,message,witness,genesis):
    run=Commands(root);grants,current=grant_set(issuer,root,local_journal,native_journal)
    local,companion=grants;operation=b64(bytes(local['operation']))
    save(root/'wg-issued.json',local);save(root/'wg-current.json',current)
    container={'schema':'qperiapt-companion-credential-grants/1','grants':[companion]}
    save(root/'wg-companions.json',container)
    command=[sys.executable,'-I','-S','-B','-c',
        f'import sys;sys.path.insert(0,{str(implementation)!r});from qperiapt_continuity_reference.credential_cli import main;raise SystemExit(main())',
        '--provider-root',provider,'--directory',client_dir,'--client-id',client_id.hex(),'--key-file',root/'client-wrap.key']
    def cli(label,action,*extra,witnessed=True,**kw):
        arguments=[*command,action,'--operation='+operation,*extra]
        if witnessed:arguments+=['--witness-address',*witness.address]
        return run(arguments,'wg-'+label,**kw)
    def state():return {'client':fingerprints(client_dir),'session':fingerprints(session_dir)}
    before=state();key_hash=hashlib.sha256((root/'client-wrap.key').read_bytes()).hexdigest()
    request=cli('request','request','--output',root/'wg-request.json')
    require(request['enrollment']==local['enrollment'] and request['journal']==local['journal']
            and request['operation']==local['operation'],'witness account original request')
    cli('missing-witness','request','--output',root/'wg-no-witness.json',witnessed=False,success=False)
    inputs=['--issued',root/'wg-issued.json','--current',root/'wg-current.json']
    cli('single-refused','prepare',*inputs,'--output',root/'wg-single.json',success=False)
    save(root/'wg-missing.json',dict(container,grants=[]))
    cli('missing-companion','prepare-account',*inputs,'--companions',root/'wg-missing.json',
        '--output',root/'wg-missing-output.json',success=False)
    altered=dict(companion,statement=list(os.urandom(32)))
    save(root/'wg-wrong-companion.json',dict(container,grants=[altered]))
    cli('wrong-companion','prepare-account',*inputs,'--companions',root/'wg-wrong-companion.json',
        '--output',root/'wg-wrong-output.json',success=False)
    require(state()==before and not (session_dir/'intent').exists(),'refused account input changed original state')
    save(root/'wg-occupied.json',b'original witnessed account export retained')
    inputs+=['--companions',root/'wg-companions.json']
    cli('lost-export','prepare-account',*inputs,'--output',root/'wg-occupied.json',success=False)
    require((root/'wg-occupied.json').read_bytes()==b'original witnessed account export retained','account export overwritten')
    intent_hash=hashlib.sha256((session_dir/'intent').read_bytes()).hexdigest()
    prep_file=root/'wg-preparation.json';prep=cli('recover-preparation','recover-preparation','--output',prep_file)
    require(cli('prepare-retry','prepare-account',*inputs,'--output',root/'wg-preparation-retry.json')==prep
            and hashlib.sha256((session_dir/'intent').read_bytes()).hexdigest()==intent_hash,
            'witness account retry resealed original target')
    require(cli('unapproved-status','status')=='Unavailable','unapproved account proposal appeared prepared')
    cli('unapproved-commit','commit',success=False)
    run([sys.executable,'-I','-S','-B','-c',
        f'import sys;sys.path.insert(0,{str(implementation)!r});from qperiapt_continuity_reference.session_cli import main;raise SystemExit(main())',
        '--provider-root',provider,'--directory',client_dir,'--client-id',client_id.hex(),'--key-file',root/'client-wrap.key',
        'next','--session='+sid,'--witness-address',*witness.address], 'wg-pending-blocks-session',success=False)
    proposal=Proposal.decode(encoded(prep['proposal'],329))
    require(proposal.subject==bytes(genesis['subject']) and proposal.operation==bytes(local['operation'])
            and proposal.statement==bytes(local['statement']),'witness account proposal changed original owner')
    policy={'pins':json.loads((root/'policy-pins.json').read_bytes()),
            'materials':json.loads((root/'policy-materials.json').read_bytes())}
    trust={'schema':'qperiapt-witness-credential-renewal-trust/1','account':current,
        'enrollment':local['enrollment'],'operation':local['operation'],'statement':local['statement'],
        'subject':b64(bytes(genesis['subject'])),'proposal_binding':list(proposal.binding),
        'lineage':{'kind':'original'},'original':policy,'policy':policy}
    trust_file=root/'wg-witness-trust.json';save(trust_file,trust)
    wrong=root/'wg-wrong-witness-trust.json';save(wrong,dict(trust,proposal_binding=list(os.urandom(32))))
    run(witness.command('credential-prepare',wrong,prep_file,root/'wg-issued.json'),
        'wg-witness-wrong-binding',success=False)
    require(cli('still-unapproved','status')=='Unavailable'
            and hashlib.sha256((session_dir/'intent').read_bytes()).hexdigest()==intent_hash,
            'wrong operator selection changed prepared account')
    operator=witness.command('credential-prepare',trust_file,prep_file,root/'wg-issued.json')
    run(operator,'wg-witness-lost-output',success=False,lost_stdout=True)
    approved=run(operator,'wg-witness-retry')
    require(approved=={'binding':list(proposal.binding),'state':'Prepared'},'witness account approval retry differs')
    cli('commit-lost-output','commit',success=False,lost_stdout=True)
    require(cli('recover','recover')=='Applied' and cli('status','status')=='Applied','witness account terminal differs')
    cli('retired-export','recover-preparation','--output',root/'wg-retired.json',success=False)
    cli('reused-request','request','--output',root/'wg-reused.json',success=False)
    require(not (root/'wg-retired.json').exists() and not (root/'wg-reused.json').exists()
            and not (session_dir/'intent').exists(),'witness account retired intent reused')
    require(hashlib.sha256((root/'client-wrap.key').read_bytes()).hexdigest()==key_hash,
            'witness account changed original wrapping key')
    return {'completed':True,'session':sid,'message':message,'journal':b64(local_journal),'operation':operation,
        'request':request,'issued':local,'companion':companion,'preparation':prep,'proposal_binding':list(proposal.binding),
        'state':'Applied','retired':True,'original_key_unchanged':True,'original_intent_sha256':intent_hash,
        'commands':run.rows,'scope':'Actual OS time, explicit two-device test issuer, independent required-witness CLI and separate native operator. No human/host account authorization or elapsed expiry claim.'}
