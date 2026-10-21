"""Read back independent P CLI outputs and their separately authorized inputs."""
from continuity_independent_python import require
from continuity_host_roster_policy import wire
from continuity_host_replacement import identity
from continuity_host_roster_credential import raw

LABELS = tuple(('ip-request ip-request-retry ip-missing-witness ip-target-issue ip-policies ip-policy-approve '
    'ip-wrong-root ip-lost-export ip-recover-preparation ip-prepare-retry ip-unapproved-status ip-unapproved-commit '
    'peer-ip-pending-blocks-session ip-witness-lost-output ip-witness-retry ip-commit-lost-output ip-recover '
    'ip-status ip-retired-export').split())
FAILED = ('ip-missing-witness','ip-wrong-root','ip-lost-export','ip-unapproved-commit','peer-ip-pending-blocks-session',
          'ip-witness-lost-output','ip-commit-lost-output','ip-retired-export')
HTTP = ('ip-relogin','ip-account-preview','ip-account-lost','ip-account-status','ip-account-retry')


def verify(value):
    p=value['independent_policy_transition'];op=identity(p['operation']);request=p['request'];scope=request['scope']
    prep=p['preparation'];account=p['account_approval'];policy=p['policy_approval']
    journal=raw(scope['journal']);raw(prep['binding']);statement=raw(account['statement']);raw(policy['statement'])
    require(p['state']=='Applied' and p['retired'] is True and p['original_key_unchanged'] is True,
            'independent P exact completion')
    require(request['schema']=='qperiapt-retained-policy-request/1' and scope['operation']==list(op)
            and journal!=identity(value['journal'])
            and scope['previous_authorization'] is None and scope['previous_policy']==scope['original_policy'],
            'independent P original lineage')
    require(prep['schema']=='qperiapt-policy-witness-preparation/1'
            and account['operation']==policy['operation']==list(op)
            and account['statement']==policy['statement'],
            'independent P two-root statement')
    proposal=wire(prep['proposal'])
    require(len(proposal)==296 and proposal[:8]==b'QPPWNP01' and proposal[136:168]==op
            and proposal[168:200]==statement and proposal[40:72]==journal,
            'independent P original proposal')
    approvals=[wire(a['approval']) for a in (account,policy)]
    require(all(len(a)==3803 for a in approvals)
            and wire(prep['approval'])==b'QPPRNB01'+b''.join(len(a).to_bytes(2,'big')+a for a in approvals),
            'independent P first exact approvals')
    h=p['original_intent_sha256']
    require(type(h) is str and len(h)==64 and all(c in '0123456789abcdef' for c in h),
            'independent P original intent hash')


def retain(value,copy,doc,output,commands,responses):
    from evidence_io import parse_strict_json_bytes
    p=value['independent_policy_transition'];request=doc('ip-request.json');prep=doc('ip-preparation.json')
    require(request==p['request']==output('ip-request')==output('ip-request-retry')==doc('ip-request-retry.json'),
            'independent P request export readback')
    require(prep==p['preparation']==output('ip-recover-preparation')==output('ip-prepare-retry')==doc('ip-preparation-retry.json'),
            'independent P preparation recovery readback')
    require(output('ip-unapproved-status')=='Unavailable' and output('ip-recover')==output('ip-status')=='Applied'
            and output('ip-witness-retry')=={'binding':prep['binding'],'state':'Prepared'},
            'independent P exact witness outcomes')
    require(copy('ip-occupied.json')==b'original policy export retained','independent P exclusive export')
    trust=doc('ip-witness-trust.json');policies=doc('ip-selected-policies.json');current=doc('peer-current.json')
    invitation=doc('peer-approved-invitation.json');subject=output('peer-prepare')['subject']
    require(trust['account']==current and trust['request']==request and trust['proposal_binding']==prep['binding']
            and trust['device']==invitation['device'] and trust['generation']==invitation['generation']
            and wire(trust['subject'])==bytes(subject) and request['scope']['journal']==subject[:32]
            and request['application']==invitation['application'] and request['enrollment']==invitation['operation']
            and request['root_revision']==invitation['root_revision']
            and request['scope']['current_roster']==current['roster']['checkpoint']
            and all(trust[k]==policies[k] for k in ('original','previous','target')),
            'independent P protected original identity and operator selection')
    labels=HTTP[1:]
    decoded={k:parse_strict_json_bytes(responses[k].encode(),label=k) for k in labels if k!='ip-account-lost'}
    approval=decoded['ip-account-retry'];status=decoded['ip-account-status'];preview=decoded['ip-account-preview']
    require(preview['state']=='Absent' and preview['review']['witness_required'] is True
            and preview['review']['statement']==approval['statement'] and status['state']=='Issued'
            and wire(status['response'])==responses['ip-account-retry'].encode() and approval==p['account_approval'],
            'independent P actual account result recovery')
    require(all(commands[k]['account']=='bob' and commands[k]['body']==commands['ip-account-preview']['body'] for k in labels)
            and commands['ip-account-preview']['body']['retained']==request
            and commands['ip-account-lost']['route']==commands['ip-account-retry']['route']=='/api/enrollment/policy-approval'
            and commands['ip-account-preview']['route']=='/api/enrollment/policy-approval/preview'
            and commands['ip-account-status']['route']=='/api/enrollment/policy-approval/status',
            'independent P authenticated request correlation')
    issued=output('ip-policy-approve')
    require(issued['state']=='Issued' and issued['result']==p['policy_approval']
            and copy('ip-account-approval.bin')==wire(approval['approval'])
            and copy('ip-policy-approval.bin')==wire(issued['result']['approval']),
            'independent P actual two-root signatures')
