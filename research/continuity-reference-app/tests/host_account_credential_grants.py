"""HTTP-issued complete-account grants and original independent adoption.

No account signing key is available to this controller. Public responses come
from the authenticated reference service and are verified by the real owners.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from native_exchange_fixture import b64,save
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.local_renewal_protocol import Proposal
from qperiapt_continuity_reference.wire import require
from host_replacement_process import fingerprints


def renew(root,native,peer,probe,host,witness,run,sessions):
    peers=[native,peer]
    original=peers[0].current;requests={};extensions={};grants={};operations={}
    require(len(peers)==2 and all(p.current==original for p in peers),'common original account roster')
    def cli(peer,label,action,*extra,**kw):
        return run([*peer.credential_command,action,'--operation='+operations[peer.label],
            *extra,'--witness-address',*witness.address],peer.label+'-cg-'+label,**kw)
    for peer in peers:
        operations[peer.label]=b64(os.urandom(32));path=root/(peer.label+'-cg-request.json')
        if peer is native:
            run([native.binary,'renewal-request',*native.common,operations[peer.label],
                 root/'policy-pins.json',root/'policy-materials.json',witness.endpoint(),path],'native-cg-request')
            request=json.loads(path.read_bytes())
        else:
            request=cli(peer,'request','request','--output',path)
        require(request['journal']==list(peer.journal) and request['enrollment']==peer.invitation['operation']
                and request['previous_checkpoint']==original['roster']['checkpoint'],'common retained predecessor')
        requests[peer.label]=request
    target=original
    for peer in peers:
        body={'request_id':list(os.urandom(32)),'enrollment':peer.invitation['operation'],
              'previous_extension':None,'predecessor':target['roster']['checkpoint'],
              'valid_until':peer.invitation['valid_until']+3600}
        label=peer.label+'-cg-extension'
        probe.request('alice',label+'-lost','/api/enrollment/extend-credential',body,lost=True)
        extended=probe.request('alice',label+'-retry','/api/enrollment/extend-credential',body)
        target=probe.request('alice',label+'-current','/api/enrollment/root')
        require(extended['checkpoint']==target['roster']['checkpoint']
                and target['roster']['checkpoint']['version']==body['predecessor']['version']+1,
                'sequential account extension current roster')
        extensions[peer.label]=extended
    require(target['roster']['checkpoint']['version']==original['roster']['checkpoint']['version']+2,
            'complete account final roster did not include both extensions')
    save(root/'cohort-current.json',target)
    approvals={}
    for index,peer in enumerate(peers):
        label=peer.label+'-cg';request=requests[peer.label]
        body={'retained':request,'original_extension':None,'previous_extension':None,
              'successor_extension':extensions[peer.label]['request']['request_id'],
              'target_checkpoint':target['roster']['checkpoint']}
        approvals[peer.label]=body;save(root/(label+'-approval.json'),body)
        if index==0:
            stale=dict(body,target_checkpoint=extensions[peer.label]['checkpoint'])
            probe.request('alice',label+'-stale-target','/api/enrollment/credential-grant',stale,status=409)
        require(probe.request('alice',label+'-absent','/api/enrollment/credential-grant/status',body)=={'state':'Absent'},
                'common account grant appeared before approval')
        probe.request('alice',label+'-issue-lost','/api/enrollment/credential-grant',body,lost=True)
        if index==0:
            host.stop(kill=True);host.start('account-after-cohort-grant')
            probe.request('alice','cohort-old-login','/api/me',status=401);probe.login('alice','cohort-relogin')
            require(probe.request('alice','cohort-current-after-restart','/api/enrollment/root')==target,
                    'account restart changed the final cohort roster')
        observed=probe.request('alice',label+'-issued-status','/api/enrollment/credential-grant/status',body)
        issued=probe.request('alice',label+'-issue-retry','/api/enrollment/credential-grant',body,raw=True)
        require(observed['state']=='Issued' and encoded(observed['response'],131072)==issued,
                'HTTP cohort grant recovery replaced original bytes')
        grant=json.loads(issued);save(root/(label+'-issued.json'),issued)
        require(grant['checkpoint']==target['roster']['checkpoint'] and grant['operation']==request['operation']
                and grant['journal']==request['journal'],'cohort grant changed retained identity or final roster')
        grants[peer.label]=grant
    from host_account_native_credential import adopt
    transitions=[adopt(root,native,requests['native'],approvals['native'],grants['native'],grants['peer'],target,witness,run,sessions['peer'])]
    policy={'pins':json.loads((root/'policy-pins.json').read_bytes()),'materials':json.loads((root/'policy-materials.json').read_bytes())}
    for peer in peers[1:]:
        label=peer.label+'-cg';grant=grants[peer.label];before=fingerprints(peer.directory,peer.session_dir)
        key_hash=hashlib.sha256(peer.key_file.read_bytes()).hexdigest()
        inputs=['--issued',root/(label+'-issued.json'),'--current',root/'cohort-current.json']
        cli(peer,'single-refused','prepare',*inputs,'--output',root/(label+'-single.json'),success=False)
        companions={'schema':'qperiapt-companion-credential-grants/1','grants':[grants[p.label] for p in peers if p is not peer]}
        save(root/(label+'-companions.json'),companions);save(root/(label+'-missing.json'),dict(companions,grants=[]))
        cli(peer,'missing-refused','prepare-account',*inputs,'--companions',root/(label+'-missing.json'),
            '--output',root/(label+'-missing-output.json'),success=False)
        require(fingerprints(peer.directory,peer.session_dir)==before,'incomplete HTTP cohort changed original state')
        inputs+=['--companions',root/(label+'-companions.json')]
        occupied=root/(label+'-occupied.json');save(occupied,b'original cohort export retained')
        cli(peer,'lost-export','prepare-account',*inputs,'--output',occupied,success=False)
        require(occupied.read_bytes()==b'original cohort export retained','cohort preparation overwrote export')
        intent_hash=hashlib.sha256((peer.session_dir/'intent').read_bytes()).hexdigest()
        prep_file=root/(label+'-preparation.json');prep=cli(peer,'recover-preparation','recover-preparation','--output',prep_file)
        require(cli(peer,'prepare-retry','prepare-account',*inputs,'--output',root/(label+'-preparation-retry.json'))==prep
                and hashlib.sha256((peer.session_dir/'intent').read_bytes()).hexdigest()==intent_hash,'cohort retry resealed target')
        require(cli(peer,'unapproved-status','status')=='Unavailable','cohort unexpectedly authorized')
        cli(peer,'unapproved-commit','commit',success=False)
        peer.next(sessions[peer.label],'cg-pending-session',success=False)
        proposal=Proposal.decode(encoded(prep['proposal'],329))
        require(proposal.subject==bytes(peer.prepared['subject']) and proposal.operation==bytes(grant['operation'])
                and proposal.statement==bytes(grant['statement']) and proposal.policy is None,'original cohort proposal binding')
        trust_file=root/(label+'-witness-trust.json')
        save(trust_file,{'schema':'qperiapt-witness-credential-renewal-trust/1','account':target,
            'enrollment':grant['enrollment'],'operation':grant['operation'],'statement':grant['statement'],
            'subject':b64(bytes(peer.prepared['subject'])),'proposal_binding':list(proposal.binding),
            'lineage':{'kind':'original'},'original':policy,'policy':policy})
        command=witness.command('credential-prepare',trust_file,prep_file,root/(label+'-issued.json'))
        run(command,label+'-witness-lost-output',success=False,lost_stdout=True)
        require(run(command,label+'-witness-retry')=={'binding':list(proposal.binding),'state':'Prepared'},'cohort operator retry')
        cli(peer,'commit-lost-output','commit',success=False,lost_stdout=True)
        require(cli(peer,'recover','recover')=='Applied' and cli(peer,'status','status')=='Applied','cohort original terminal')
        cli(peer,'retired-export','recover-preparation','--output',root/(label+'-retired.json'),success=False)
        require(not (peer.session_dir/'intent').exists() and not (root/(label+'-retired.json')).exists()
                and hashlib.sha256(peer.key_file.read_bytes()).hexdigest()==key_hash,'cohort retirement or original key changed')
        peer.current=target
        transitions.append({'label':peer.label,'kind':'independent','request':requests[peer.label],'approval':approvals[peer.label],
            'extension':extensions[peer.label],'issued':grant,'companions':companions['grants'],'preparation':prep,
            'binding':list(proposal.binding),'original_intent_sha256':intent_hash,'original_key_unchanged':True,
            'state':'Applied','retired':True,'session':sessions[peer.label],'journal':b64(peer.journal)})
    return {'previous':original['roster']['checkpoint'],'target':target['roster']['checkpoint'],
            'current':target,'transitions':transitions,'account_restarted_after_lost_grant':True}
