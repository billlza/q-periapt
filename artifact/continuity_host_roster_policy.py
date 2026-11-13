"""Correlate the actual account/publisher/witness P between two original R steps.

Structural receipt checks; signatures are verified by the executing SDK, not by
this collector. Historical records cannot be promoted to runtime permission.
"""
import base64
from continuity_independent_python import require
from continuity_host_replacement import identity

LABELS = tuple(('p-request p-target-issue p-publisher-enable p-policies p-policy-approve p-stage '
    'p-lost-export p-recover p-unapproved p-pending-activation p-witness-lost-output p-witness-retry '
    'p-commit-lost-output p-observe p-status p-old-activation p-activate').split())
FAILED = ('p-lost-export','p-pending-activation','p-witness-lost-output','p-commit-lost-output','p-old-activation')
HTTP = ('p-account-preview','p-account-lost','p-account-status','p-account-retry')


def wire(value):
    require(type(value) is str and len(value)<=256*1024,'P public wire bound')
    data=base64.b64decode(value+'='*((-len(value))%4),altchars=b'-_',validate=True)
    require(base64.urlsafe_b64encode(data).rstrip(b'=').decode()==value,'P canonical wire')
    return data


def verify(value):
    p=value['policy_transition'];op=identity(p['operation']);statement=identity(p['statement'])
    preparation=p['preparation'];progress=p['progress'];request=p['request']
    for raw in (preparation['binding'],progress['target']['digest']):
        require(type(raw) is list and len(raw)==32 and any(raw)
                and all(type(n) is int and 0<=n<=255 for n in raw),'P public commitment bytes')
    require(preparation['schema']=='qperiapt-policy-witness-preparation/1'
            and progress['schema']=='qperiapt-policy-witness-progress/1'
            and progress['state']=='Applied' and progress['retired'] is True
            and progress['binding']==preparation['binding'] and progress['proposal']==preparation['proposal']
            and p['observation']=={'binding':preparation['binding'],'state':'Applied'},'exact P completion')
    proposal=wire(preparation['proposal'])
    require(len(proposal)==296 and proposal[:8]==b'QPPWNP01' and wire(preparation['approval']),'P proposal domain and approvals')
    scope=request['scope']
    require(request['schema']=='qperiapt-retained-policy-request/1' and scope['operation']==list(op)
            and scope['journal']==list(identity(value['journal']))
            and scope['current_roster']==value['transitions'][0]['progress']['scope']['target']
            and scope['original_policy']==scope['previous_policy']==value['transitions'][0]['progress']['scope']['policy']
            and scope['previous_authorization'] is None,'P original identity and R predecessor')
    require(p['account_approval']['statement']==p['policy_approval']['statement']==list(statement)
            and p['account_approval']['operation']==p['policy_approval']['operation']==list(op)
            and p['account_approval']['target']==progress['target']
            and value['transitions'][1]['progress']['scope']['policy']==progress['target']
            and value['transitions'][1]['progress']['scope']['policy_authorization']==list(statement),'R retained exact two-root P')
    require(type(progress['target']['version']) is int and progress['target']['version']==2,'actual P2 target')
    identity(value['policy_pending_message'])
    require(value['policy_pending_message']!=value['original_pending_message'],'distinct original pending operations')


def retain(value,copy,doc,output,commands,responses):
    from evidence_io import parse_strict_json_bytes
    p=value['policy_transition'];prep=doc('p-preparation.json');request=doc('p-retained-request.json')
    policies=doc('p-selected-policies.json');trust=doc('p-witness-trust.json')
    require(prep==p['preparation']==output('p-recover') and request==p['request']==trust['request'],'actual original P exports')
    require(output('p-unapproved')=={'binding':prep['binding'],'state':'Unavailable'}
            and output('p-witness-retry')=={'binding':prep['binding'],'state':'Prepared'}
            and output('p-observe')==p['observation'] and output('p-status')==p['progress'],'actual P coordination readbacks')
    require(output('p-stage')['state']=='Pending' and output('p-stage')['statement']==p['account_approval']['statement']
            and output('p-activate')=={'state':'Activated','journal':list(identity(value['journal']))},'actual original P staging/activation')
    require(trust['proposal_binding']==prep['binding'] and trust['account']==doc('addition-current.json')
            and all(trust[k]==policies[k] for k in ('original','previous','target'))
            and policies['original']==policies['previous']==doc('p-original-policy.json')
            and policies['target']==doc('p-target-policy.json'),'independent P operator selections')
    require(copy('p-occupied.json')==b'original policy export retained','P exclusive export')
    decoded={k:parse_strict_json_bytes(responses[k].encode(),label=k) for k in HTTP if k!='p-account-lost'}
    approval=decoded['p-account-retry'];status=decoded['p-account-status'];preview=decoded['p-account-preview']
    require(preview['state']=='Absent' and preview['review']['witness_required'] is True
            and preview['review']['statement']==approval['statement']
            and status['state']=='Issued' and wire(status['response'])==responses['p-account-retry'].encode()
            and approval==p['account_approval'],'real account P review and lost result recovery')
    require(all(commands[k]['account']=='alice' and commands[k]['body']==commands['p-account-preview']['body'] for k in HTTP)
            and commands['p-account-lost']['route']==commands['p-account-retry']['route']=='/api/enrollment/policy-approval'
            and commands['p-account-status']['route']=='/api/enrollment/policy-approval/status'
            and commands['p-account-preview']['route']=='/api/enrollment/policy-approval/preview','same authenticated P request')
    require(commands['p-account-preview']['body']['retained']==request,'account approves original P request')
    issued=output('p-policy-approve')
    require(issued['state']=='Issued' and issued['result']==p['policy_approval']
            and copy('p-account-approval.bin')==wire(approval['approval'])
            and copy('p-policy-approval.bin')==wire(issued['result']['approval']),'two original public signatures')
    require(output('peer-policy-pending-status')=={'session':value['session'],'message':value['policy_pending_message'],'status':'Committed'},'P original unknown ACK')
    for name in ('policy-pending-effect.bin','original-effect-after-policy.bin'):
        require(copy(name)==b'pending before policy update','same durable effect through R/P/R')
    for name in ('policy-lost.request','policy-lost.response'):copy(name)
