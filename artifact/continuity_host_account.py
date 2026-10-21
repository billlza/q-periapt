"""Installed real HTTP common-account credential recovery qualification."""
import json
from pathlib import Path
import sys
from continuity_independent_python import PACKAGE,require
from continuity_host_network import count,stats
from continuity_host_replacement import identity
from continuity_host_roster_credential import raw
from evidence_io import parse_strict_json_bytes,read_regular_snapshot

LABELS=tuple(('witness-init sdk-init sdk-issue policy-init policy-issue account-init account-enable-enrollment '
 'account-enable-reapproval account-enable-credential-extension account-enable-credential-grants '
 'account-enable-policy-approvals account-enable-device-replacements native-key native-begin native-request native-accept '
 'native-refresh-before-session native-prepare native-witness-enroll native-publication-id native-before-invalid-publication '
 'native-refuse-precredential-publication native-after-invalid-publication native-publication-id-after-refusal '
 'native-publish native-inbox native-original-status cohort-native-before peer-prepare peer-witness-enroll peer-connect '
 'peer-lost-next peer-lost-send peer-lost-status peer-original-effect native-cg-request peer-cg-request '
 'native-cg-stage native-cg-single-refused native-cg-after-refusal native-cg-lost-export native-cg-prepare '
 'native-cg-prepare-retry native-cg-unapproved native-cg-witness-lost-output native-cg-witness-retry '
 'native-cg-commit-lost-output native-cg-status native-cg-activate-retry peer-cg-single-refused peer-cg-missing-refused '
 'peer-cg-lost-export peer-cg-recover-preparation peer-cg-prepare-retry peer-cg-unapproved-status peer-cg-unapproved-commit '
 'peer-cg-pending-session peer-cg-witness-lost-output peer-cg-witness-retry peer-cg-commit-lost-output peer-cg-recover '
 'peer-cg-status peer-cg-retired-export peer-resume peer-recovered-effect peer-rekey peer-fresh-next peer-fresh-send '
 'peer-fresh-effect peer-inbox peer-native-rekey peer-native-next peer-native-send peer-read-reverse cohort-native-after').split())
FAILED=tuple(('native-refuse-precredential-publication peer-lost-send native-cg-single-refused native-cg-lost-export '
 'native-cg-unapproved native-cg-witness-lost-output native-cg-commit-lost-output peer-cg-single-refused peer-cg-missing-refused '
 'peer-cg-lost-export peer-cg-unapproved-commit peer-cg-pending-session peer-cg-witness-lost-output '
 'peer-cg-commit-lost-output peer-cg-retired-export').split())
HTTP=tuple(('register-alice alice-prepare-root native-invitation native-approve native-issue native-authority-identity '
 'native-authority-root cohort-authority-identity cohort-authority-root peer-invitation peer-approve peer-issue peer-current '
 'native-cg-extension-lost native-cg-extension-retry native-cg-extension-current peer-cg-extension-lost '
 'peer-cg-extension-retry peer-cg-extension-current native-cg-stale-target native-cg-absent native-cg-issue-lost '
 'cohort-old-login cohort-relogin cohort-current-after-restart native-cg-issued-status native-cg-issue-retry '
 'peer-cg-absent peer-cg-issue-lost peer-cg-issued-status peer-cg-issue-retry probe-finish').split())
BINARIES=('account_host','account_client','sdk_authority','publisher','witness','native_device','native_session','native_outgoing')


def inventory(*,credential_expiry=False):
    if not credential_expiry:return LABELS,FAILED,HTTP
    split=LABELS.index('native-cg-request');http_split=HTTP.index('native-cg-extension-lost')
    expired=('peer-expiry-refused','native-expiry-refused')
    return (LABELS[:split]+expired+LABELS[split:],FAILED+expired,
            HTTP[:http_split]+('expiry-old-login','expiry-relogin')+HTTP[http_split:])


def verify(value,binaries,application,*,credential_expiry=False):
    labels,failed,http=inventory(credential_expiry=credential_expiry)
    require(value.get('kind')=='qperiapt.authenticated_account_credential' and value.get('completed') is True
            and value.get('release_claim_eligible') is False and value.get('cleanup_errors')==[],'HTTP cohort completion')
    for key,n in [('schema_version',2 if credential_expiry else 1),('effects',3),('confirmed_epoch',2)]:count(value.get(key),n,key)
    if credential_expiry:
        from continuity_host_account_expiry import verify as verify_expiry
        verify_expiry(value.get('expiry'))
    else:require('expiry' not in value,'immediate cohort cannot claim elapsed expiry')
    require(value.get('native_sha256')==binaries and value.get('provider')=='48.0.1' and value.get('clock')=='actual OS time'
            and value.get('implementation')==str(application/PACKAGE/'credential_cli.py'),'HTTP cohort implementation')
    for key in ('original_keys_unchanged','witness_keys_unchanged','original_wire_unchanged'):
        require(value.get(key) is True,'HTTP cohort '+key)
    require(type(value.get('sessions')) is dict and set(value['sessions'])=={'peer'}
            and type(value.get('original_pending_messages')) is dict and set(value['original_pending_messages'])=={'peer'},'HTTP cohort session inventory')
    identity(value['sessions']['peer']);identity(value['original_pending_messages']['peer'])
    rows=value.get('commands');require(type(rows) is list and len(rows)==len(labels),'HTTP cohort command count')
    for row,label in zip(rows,labels):
        require(set(row)=={'label','exit'} and row['label']==label and type(row['exit']) is int
                and (row['exit']!=0)==(label in failed),'HTTP cohort command disposition')
    rows=value.get('account_requests');require(type(rows) is list and len(rows)==len(http),'HTTP cohort request count')
    for index,(row,label) in enumerate(zip(rows,http),1):
        action={'register-alice':'register','cohort-relogin':'login','expiry-relogin':'login','probe-finish':'finish'}.get(label,'request')
        require(row=={'label':label,'id':index,'action':action} and type(row['id']) is int,'HTTP cohort request identity')
    renewal=value['renewal'];count(renewal['previous']['version'],2,'HTTP cohort predecessor');count(renewal['target']['version'],4,'HTTP cohort target')
    require(renewal['account_restarted_after_lost_grant'] is True
            and renewal['current']['roster']['checkpoint']==renewal['target'],'HTTP cohort current account')
    transitions=renewal['transitions'];require(type(transitions) is list and len(transitions)==2,'HTTP cohort owner count')
    for t,label,kind in zip(transitions,('native','peer'),('native','independent')):
        request,issued=t['request'],t['issued'];operation=raw(issued['operation']);statement=raw(issued['statement']);journal=identity(t['journal'])
        require(t['label']==label and t['kind']==kind and t['state']=='Applied' and t['original_key_unchanged'] is True
                and t['session']==value['sessions']['peer'],'HTTP cohort original owner outcome')
        require(request['previous_checkpoint']==renewal['previous'] and issued['checkpoint']==renewal['target']
                and request['operation']==list(operation) and request['journal']==issued['journal']==list(journal)
                and request['enrollment']==issued['enrollment'],'HTTP cohort original grant identity')
        count(request['root_revision'],1,'HTTP cohort request root');count(issued['root_revision'],1,'HTTP cohort issued root')
        require(request['current_policy']==request['original_policy'] and request['current_policy_authorization'] is None,
                'HTTP cohort policy lineage')
        require(t['approval']['retained']==request and t['approval']['target_checkpoint']==renewal['target'], 'HTTP cohort original approval')
        other=transitions[1] if label=='native' else transitions[0]
        require(t['companions']==[other['issued']] and raw(other['issued']['journal'])!=journal
                and raw(other['issued']['operation'])!=operation,'HTTP cohort complete companions')
        if label=='native':
            require(t['terminal']=={'state':'Committed','operation':list(operation),'statement':list(statement),'target':renewal['target']}
                    and t['activation']=={'state':'Active','operation':list(operation),'statement':list(statement),'journal':list(journal),'checkpoint':renewal['target']},
                    'HTTP cohort native committed activation')
        else:require(t['retired'] is True,'HTTP cohort independent retirement')
    groups=[('services',('peer-before-service','peer-after-service'),(0,0)),('receivers',('peer-receiver',),(0,)),
            ('witness_services',('witness-first','witness-reopened'),(-9,0)),('account_services',('account-first','account-after-cohort-grant'),(-9,0))]
    for key,labels,codes in groups:
        rows=value.get(key);require(type(rows) is list and len(rows)==len(labels),'HTTP cohort process inventory')
        for row,label,code in zip(rows,labels,codes):
            fields={'label','pid','exit'} | ({'stats'} if code==0 and key!='account_services' else set())
            require(set(row)==fields and row['label']==label and type(row['pid']) is int and row['pid']>0
                    and type(row['exit']) is int and row['exit']==code,'HTTP cohort process outcome')
            if 'stats' in row:
                n={'peer-before-service':3,'peer-after-service':4,'peer-receiver':3}.get(label,row['stats']['completed_responses'])
                require(type(n) is int and 1<=n<=1024,'HTTP cohort process work bound');stats(row['stats'],n,n)
    stats(value['recovery_relay'],1,1)
    rows=value['recovery_wire'];require(type(rows) is list and len(rows)==1 and rows[0]['label']=='replacement-wire-1'
            and rows[0]['kind']==3 and rows[0]['outcome']=='response','HTTP cohort original wire record')


def qualify(args,reference,application,provider,outside,output,snapshot,run):
    from continuity_host_account_evidence import retain,negative_controls
    paths={key:getattr(args,key).resolve(strict=True) for key in BINARIES}
    def hashes():return {str(p):read_regular_snapshot(p,maximum=128*1024**2,label='HTTP cohort native executable').sha256 for p in paths.values()}
    binaries=hashes();harness=outside/'http-account-harness';harness.mkdir();expected={}
    for p in (reference/'tests').glob('*.py'):
        item=snapshot(p);target=harness/p.name;target.write_bytes(item.data);expected[str(target)]=item.sha256
    for p in (application/PACKAGE).glob('*.py'):expected[str(p)]=snapshot(p).sha256
    private=outside/'private-http-account'
    command=[sys.executable,'-I','-S','-B',str(harness/'host_account_credential.py')]
    for key,path in paths.items():command+=['--'+key.replace('_','-'),str(path)]
    command+=['--implementation-root',str(application),'--provider-root',str(provider),'--output',str(private)]
    execution=run(command,'authenticated-account-credential');value=parse_strict_json_bytes(execution.stdout,label='installed HTTP cohort')
    verify(value,binaries,application)
    require(value['source_files']==expected and parse_strict_json_bytes(snapshot(private/'RESULT.json').data,label='retained HTTP cohort')==value,
            'HTTP cohort source or retained result differs')
    retain(value,private,output/'http-account-public',snapshot)
    controls=negative_controls(value,private,output/'http-account-negative',snapshot)
    require(len(controls)==5,'HTTP cohort negative control inventory')
    (output/'http-account-integrity.json').write_text(json.dumps(controls,indent=2)+'\n')
    require(hashes()==binaries and all(snapshot(Path(name)).sha256==digest for name,digest in expected.items()),
            'HTTP cohort executable or harness changed')
    return value
