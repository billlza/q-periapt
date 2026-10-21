"""Public execution readback for HTTP-issued native/independent account renewal.

Signatures are verified by executing owners. This reader checks correlation and
retained outputs; it neither needs nor exports account/device private keys.
"""
import dataclasses
import hashlib
import json
from continuity_independent_python import require
from continuity_host_account import inventory
from continuity_host_roster_credential import raw
from continuity_host_roster_policy import wire
from evidence_io import parse_strict_json_bytes


def retain(value,private,public,snapshot,*,credential_expiry=False):
    labels,failed,http=inventory(credential_expiry=credential_expiry)
    public.mkdir()
    def data(name):
        item=snapshot(private/name);(public/name).write_bytes(item.data);return item.data
    def doc(name):return parse_strict_json_bytes(data(name),label=name)
    def output(label):return doc(label+'.stdout')
    require(doc('RESULT.json')==value,'HTTP cohort retained result')
    for label in labels:
        stdout,stderr=data(label+'.stdout'),data(label+'.stderr')
        require(bool(stderr)==(label in failed),'HTTP cohort diagnostic disposition')
        if label in failed:require(not stdout,'failed HTTP cohort command emitted success')
        if label.endswith(('witness-lost-output','commit-lost-output')):
            require(b'broken pipe' in stderr.lower(),'HTTP cohort output loss was not a broken pipe')
    requests={};responses={}
    for index,label in enumerate(http,1):
        request=doc(label+'.http-request.json');response=doc(label+'.http-response.json')
        require(set(request)=={'id','command'} and set(response)=={'id','result'}
                and request['id']==response['id']==index,'HTTP cohort transport correlation')
        command=request['command'];result=response['result']
        require(command['action']==value['account_requests'][index-1]['action'],'HTTP cohort transport action')
        if command['action']!='finish':require(command['account']=='alice','HTTP cohort authenticated account')
        if command['action']=='request':
            status=401 if label in ('cohort-old-login','expiry-old-login') else 409 if label=='native-cg-stale-target' else 204 if label in ('native-approve','peer-approve') else 200
            require(set(result)=={'status','body','content_type'} and type(result['status']) is int
                    and result['status']==status and type(result['body']) is str,'HTTP cohort response status')
            if command['disconnect_before_body'] or status==204:require(result['body']=='','HTTP cohort lost/empty response')
        requests[label]=command;responses[label]=result
    require(responses['register-alice']=={'authenticated':'registered_software_test_passkey'}
            and responses['cohort-relogin']=={'authenticated':'original_software_test_passkey'}
            and responses['probe-finish']=={'finished':True},'HTTP cohort original account authentication')
    if credential_expiry:
        from continuity_host_account_expiry import retain as retain_expiry
        retain_expiry(value,doc,data,requests,responses)
    def body(label):return parse_strict_json_bytes(responses[label]['body'].encode(),label=label)
    renewal=value['renewal'];current=doc('cohort-current.json');previous=doc('cohort-original-current.json');trust=doc('peer-trust.json')
    require(current==renewal['current']==body('peer-cg-extension-current')==body('cohort-current-after-restart')
            and previous['roster']['checkpoint']==renewal['previous'] and current['roster']['checkpoint']==renewal['target'],
            'HTTP cohort selected current roster')
    require(trust['initiator']['current']==trust['responder']['current']==previous
            and current['account']==previous['account'],'HTTP cohort endpoints must share the original account')
    policy={'pins':doc('policy-pins.json'),'materials':doc('policy-materials.json')}
    for index,t in enumerate(renewal['transitions']):
        label=t['label']+'-cg';request=doc(label+'-request.json');issued=doc(label+'-issued.json');approval=doc(label+'-approval.json')
        require(request==t['request'] and issued==t['issued'] and approval==t['approval'],'HTTP cohort original issued inputs')
        initial=doc(t['label']+'-issued.json');invitation=doc(t['label']+'-invitation.json')
        require(request['original_certificate']==request['previous_certificate']==initial['certificate']
                and request['enrollment']==invitation['operation'] and wire(request['previous_roster'])==wire(previous['roster']['bytes']),
                'HTTP cohort original credential history')
        require(request['original_policy']=={'version':policy['pins']['policy_version'],'digest':policy['pins']['policy_digest']},
                'HTTP cohort retained policy')
        extension=body(label+'-extension-retry');extension_request=requests[label+'-extension-retry']['body']
        predecessor=previous['roster']['checkpoint'] if index==0 else body('native-cg-extension-current')['roster']['checkpoint']
        require(extension['request']==extension_request==requests[label+'-extension-lost']['body']
                and extension_request['enrollment']==request['enrollment'] and extension_request['predecessor']==predecessor
                and extension['checkpoint']==body(label+'-extension-current')['roster']['checkpoint']
                and extension['checkpoint']['version']==3+index
                and approval['successor_extension']==extension_request['request_id'],'HTTP cohort sequential extension history')
        for suffix in ('-extension-lost','-extension-retry'):
            require(requests[label+suffix]['route']=='/api/enrollment/extend-credential','HTTP cohort extension route')
        for suffix in ('-absent','-issue-lost','-issued-status','-issue-retry'):
            command=requests[label+suffix]
            route='/api/enrollment/credential-grant'+('/status' if suffix in ('-absent','-issued-status') else '')
            require(command['route']==route and command['body']==approval,'HTTP cohort exact retained grant request')
        status=body(label+'-issued-status')
        require(body(label+'-absent')=={'state':'Absent'} and status['state']=='Issued'
                and wire(status['response'])==responses[label+'-issue-retry']['body'].encode()
                and body(label+'-issue-retry')==issued,'HTTP cohort exact lost grant recovery')
        companions=doc(label+'-companions.json')
        schema='qperiapt-account-credential-grants/1' if index==0 else 'qperiapt-companion-credential-grants/1'
        require(companions=={'schema':schema,'grants':t['companions']},'HTTP cohort complete companion collection')
        prep=doc(label+'-preparation.json');require(prep==t['preparation']==doc(label+'-preparation-retry.json'),'HTTP cohort exact preparation recovery')
        proposal=wire(prep['proposal']);journal=raw(request['journal']);operation=raw(issued['operation']);statement=raw(issued['statement'])
        require(prep['schema']=='qperiapt-credential-witness-proposal/1' and prep['journal']==list(journal)
                and prep['operation']==list(operation) and len(proposal)==296 and proposal[:8]==b'QPCRNP01'
                and proposal[40:72]==journal and proposal[136:168]==operation and proposal[168:200]==statement,'HTTP cohort original proposal scope')
        domain=b'Q-PERIAPT-ANCHOR-CREDENTIAL-PROPOSAL/v1'
        binding=hashlib.sha3_256(len(domain).to_bytes(8,'big')+domain+len(proposal).to_bytes(8,'big')+proposal).digest()
        operator=doc(label+'-witness-trust.json')
        require(raw(t['binding'])==binding and operator['account']==current and operator['enrollment']==issued['enrollment']
                and operator['operation']==issued['operation'] and operator['statement']==issued['statement']
                and operator['proposal_binding']==t['binding'] and wire(operator['subject'])==proposal[40:136]
                and operator['lineage']=={'kind':'original'} and operator['original']==operator['policy']==policy,
                'HTTP cohort independent witness selection')
        require(output(label+'-witness-retry')=={'binding':t['binding'],'state':'Prepared'},'HTTP cohort exact witness recovery')
        expected=b'original native cohort export retained' if index==0 else b'original cohort export retained'
        require(data(label+'-occupied.json')==expected,'HTTP cohort exclusive export')
        if index==0:
            require(output(label+'-stage')==output(label+'-after-refusal')=={'state':'Pending','operation':issued['operation'],'statement':issued['statement']}
                    and output(label+'-status')==t['terminal'] and output(label+'-activate-retry')==t['activation'],'HTTP cohort native outcomes')
        else:
            require(output(label+'-request')==request and output(label+'-recover-preparation')==output(label+'-prepare-retry')==prep
                    and output(label+'-unapproved-status')=='Unavailable' and output(label+'-recover')==output(label+'-status')=='Applied',
                    'HTTP cohort independent outcomes')
            require(doc(label+'-missing.json')==dict(companions,grants=[]),'HTTP cohort missing-companion control')
    stale=requests['native-cg-stale-target']['body'];first=renewal['transitions'][0]['approval']
    require(stale==dict(first,target_checkpoint=body('native-cg-extension-current')['roster']['checkpoint']), 'HTTP cohort stale target control')
    sid=value['sessions']['peer'];message=value['original_pending_messages']['peer']
    require(output('peer-connect')=={'session':sid,'peer_confirmation':'Recorded'}
            and output('peer-lost-status')=={'session':sid,'message':message,'status':'Committed'}
            and output('peer-resume')=={'session':sid,'message':message,'consumption':'Confirmed'},'HTTP cohort recovered original message')
    for side,kind in [('request',3),('response',131)]:
        actual=data('replacement-wire-1.'+side)
        require(actual==data('peer-lost.'+side) and 10<=len(actual)<=32768 and actual[:9]==b'QPCXCH01'+bytes([kind])
                and hashlib.sha256(actual).hexdigest()==value['recovery_wire'][0][side+'_sha256'],'HTTP cohort exact original wire')
    for name,expected in [('peer-original-effect.bin',b'peer original lost ACK'),('peer-recovered-effect.bin',b'peer original lost ACK'),
                          ('peer-fresh-effect.bin',b'peer after cohort renewal'),('peer-reverse.bin',b'peer reverse cohort effect')]:
        require(data(name)==expected,'HTTP cohort durable effect')
    require(output('peer-rekey')=={'session':sid,'epoch':1,'exchanges':2} and output('peer-native-rekey')=={'epoch':2,'exchanges':2}
            and output('peer-native-send')=={'consumption':'Confirmed'},'HTTP cohort two-way rekey')
    for key in ('services','receivers','witness_services','account_services'):
        for row in value[key]:
            lines=data(row['label']+'.stdout').splitlines();require(not data(row['label']+'.stderr'),'HTTP cohort process diagnostics')
            if key!='account_services':
                require(len(lines)==(1 if row['exit']==-9 else 2)
                        and parse_strict_json_bytes(lines[0],label='readiness')['service']=='Listening','HTTP cohort readiness')
                if row['exit']==0:require(parse_strict_json_bytes(lines[1],label='shutdown')=={'service':'Stopped','stats':row['stats']},'HTTP cohort terminal process')
    return len(list(public.iterdir()))


def negative_controls(value,private,output,snapshot,*,credential_expiry=False):
    output.mkdir()
    cases=[('native-cg-issued.json',lambda b:json.dumps(dict(json.loads(b),operation=[99]*32)).encode()),
           ('peer-cg-companions.json',lambda b:json.dumps(dict(json.loads(b),grants=[])).encode()),
           ('native-cg-witness-trust.json',lambda b:json.dumps(dict(json.loads(b),proposal_binding=[99]*32)).encode()),
           ('native-cg-witness-lost-output.stderr',lambda b:b'generic failure'),
           ('replacement-wire-1.request',lambda b:b[:-1]+bytes([b[-1]^1]))]
    if credential_expiry:
        cases += [('EXPIRY_OBSERVATION.json',lambda b:json.dumps(dict(json.loads(b),elapsed_seconds=0)).encode()),
                  ('native-expiry-refused.stderr',lambda b:b'Error: Io(PermissionDenied)\n'),
                  ('peer-expiry-refused.stderr',lambda b:b'OSError: disk unavailable\n'),
                  ('native-invitation.json',lambda b:json.dumps(dict(json.loads(b),valid_until=1)).encode()),
                  ('expiry-relogin.http-response.json',lambda b:json.dumps(dict(json.loads(b),result={'authenticated':'registered_software_test_passkey'})).encode())]
    rows=[]
    for index,(name,change) in enumerate(cases):
        def altered(path):
            item=snapshot(path)
            if path==private/name:
                body=change(item.data);item=dataclasses.replace(item,data=body,size=len(body),sha256=hashlib.sha256(body).hexdigest())
            return item
        try:retain(value,private,output/str(index),altered,credential_expiry=credential_expiry)
        except ValueError as error:rows.append({'file':name,'rejected':str(error)})
        else:raise ValueError('Altered HTTP cohort evidence accepted: '+name)
    return rows
