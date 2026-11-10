"""Actual-clock complete-account CLI on the original local session.

Only this test issuer holds fixture roots. Product clients receive public signed
inputs; no production issuer, clock override or account login is introduced.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
import sys
from native_exchange_fixture import b64,save,wire
from host_replacement_process import Commands,fingerprints
from qperiapt_continuity_reference.wire import digest,ldh,require


def grant_set(issuer, root, local_journal, native_journal):
    previous=issuer.roster;old=issuer.checkpoint;new_until=issuer.end+1800
    rows=[]
    for name,journal in [('client',local_journal),('native',native_journal)]:
        invitation=json.loads((root/(name+'-invitation.json')).read_bytes())
        issued=json.loads((root/(name+'-issued.json')).read_bytes())
        from qperiapt_continuity_reference.enrollment_exchange import encoded
        certificate=encoded(issued['certificate'],8192)
        body=issuer.root.public().open(certificate,1,2097)
        successor=body[:72]+new_until.to_bytes(8,'big')+body[80:]
        rows.append((name,journal,invitation,certificate,body,issuer.root.sign(1,successor),successor))
    roster=(b'QPROST01'+issuer.account+(2).to_bytes(8,'big')+issuer.start.to_bytes(8,'big')
            +new_until.to_bytes(8,'big')+len(rows).to_bytes(2,'big'))
    roster+=b''.join(bytes(r[2]['device'])+(1).to_bytes(8,'big')+digest(b'CREDENTIAL',r[6])
                     for r in sorted(rows,key=lambda r:bytes(r[2]['device'])))
    target={'version':2,'digest':list(digest(b'ROSTER',roster))};roster=issuer.root.sign(2,roster)
    current=dict(json.loads((root/'current.json').read_bytes()),roster={'checkpoint':target,'bytes':b64(roster)})
    results=[]
    for name,journal,invitation,certificate,body,next_certificate,next_body in rows:
        operation=os.urandom(32)
        decision=(b'QPCRNW01'+operation+issuer.account+bytes(invitation['device'])+(1).to_bytes(8,'big')
            +issuer.family+ldh(b'Q-PERIAPT-CREDENTIAL-RENEWAL-KEY/v1',body[112:])
            +digest(b'CREDENTIAL',body)*2+digest(b'CREDENTIAL',next_body)+issuer.policy.pins.policy_digest
            +old['version'].to_bytes(8,'big')+bytes(old['digest'])+target['version'].to_bytes(8,'big')+bytes(target['digest'])+b'\1')
        require(len(decision)==369,'fixture renewal decision width')
        fields=(issuer.root.sign(15,decision),certificate,certificate,next_certificate,previous,roster)
        grant=b'QPRNB001'+b''.join(len(f).to_bytes(2,'big')+f for f in fields)
        results.append({'enrollment':invitation['operation'],'operation':list(operation),'journal':list(journal),
            'root_revision':1,'statement':list(ldh(b'Q-PERIAPT-CREDENTIAL-RENEWAL-STATEMENT/v1',decision)),
            'checkpoint':target,'grant':b64(grant)})
    return results,current


def exercise(issuer,implementation,provider,root,client_dir,session_dir,client_id,local_journal,native_journal,sid,message):
    run=Commands(root);grants,current=grant_set(issuer,root,local_journal,native_journal)
    local,companion=grants;operation=b64(bytes(local['operation']))
    save(root/'ag-issued.json',local);save(root/'ag-current.json',current)
    container={'schema':'qperiapt-companion-credential-grants/1','grants':[companion]};save(root/'ag-companions.json',container)
    command=[sys.executable,'-I','-S','-B','-c',f'import sys;sys.path.insert(0,{str(implementation)!r});from qperiapt_continuity_reference.credential_cli import main;raise SystemExit(main())',
        '--provider-root',provider,'--directory',client_dir,'--client-id',client_id.hex(),'--key-file',root/'client-wrap.key']
    def call(label,action,*extra,**kw):return run([*command,action,'--operation='+operation,*extra],'ag-'+label,**kw)
    def state():return {'client':fingerprints(client_dir),'session':fingerprints(session_dir)}
    original=state();request=call('request','request','--output',root/'ag-request.json')
    require(request['enrollment']==local['enrollment'] and request['journal']==local['journal'],'account request lost original registration')
    require(state()==original,'account issuer observation mutated state')
    inputs=['--issued',root/'ag-issued.json','--current',root/'ag-current.json']
    call('single-refused','prepare',*inputs,'--output',root/'ag-single.json',success=False)
    require(state()==original and not (root/'ag-single.json').exists(),'single-device path changed shared account')
    save(root/'ag-missing.json',dict(container,grants=[]))
    call('missing-refused','prepare-account',*inputs,'--companions',root/'ag-missing.json','--output',root/'ag-missing-output.json',success=False)
    require(state()==original and not (root/'ag-missing-output.json').exists(),'incomplete account changed original state')
    bad=dict(companion,statement=list(os.urandom(32)));save(root/'ag-wrong.json',dict(container,grants=[bad]))
    call('statement-refused','prepare-account',*inputs,'--companions',root/'ag-wrong.json','--output',root/'ag-wrong-output.json',success=False)
    require(state()==original and not (root/'ag-wrong-output.json').exists(),'wrong companion metadata changed state')
    save(root/'ag-occupied.json',b'original export retained')
    call('lost-export','prepare-account',*inputs,'--companions',root/'ag-companions.json','--output',root/'ag-occupied.json',success=False)
    require((root/'ag-occupied.json').read_bytes()==b'original export retained','account export overwritten')
    pending=call('pending','status');require(pending['status']=='Pending','account lost export lost target')
    retained=state()
    require(call('prepare-retry','prepare-account',*inputs,'--companions',root/'ag-companions.json','--output',root/'ag-prepared.json')==pending
            and state()==retained,'account prepare retry rewrote target')
    call('commit-lost-output','commit',success=False,lost_stdout=True)
    committed=call('committed','status');require(committed['status']=='Committed','account commit output loss')
    stable=state();require(call('commit-retry','commit')==committed and state()==stable,'account committed retry rewrote state')
    require(committed['operation']==bytes(local['operation']).hex() and committed['statement']==bytes(local['statement']).hex(),
            'account committed wrong decision')
    return {'completed':True,'scope':'Actual OS time, explicit test issuer, complete2-device local account and original pending message. No real account authorization, expiry or positive required-witness CLI claim.',
        'session':sid,'message':message,'journal':b64(local_journal),'operation':operation,'request':request,'issued':local,'companion':companion,
        'pending':pending,'committed':committed,'commands':run.rows,'original_pending_message_retained':True}
