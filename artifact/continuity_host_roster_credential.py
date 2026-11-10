"""Correlate installed G with the retained R/P/R account and original session.

These are structural execution-receipt checks. The running SDK and witness
verify signatures; this collector does not provide an independent crypto proof.
"""
from continuity_independent_python import require
from continuity_host_replacement import identity
from continuity_host_roster_policy import wire
from evidence_io import parse_strict_json_bytes

LABELS = tuple(('g-request g-stage g-prepare g-unapproved g-witness-lost-output '
    'g-witness-retry g-activation-lost-output g-terminal g-recovered-activation '
    'g-reopen g-returned-owner').split())
FAILED = ('g-unapproved', 'g-witness-lost-output', 'g-activation-lost-output')
HTTP = ('g-extension', 'g-current', 'g-absent', 'g-lost', 'g-status', 'g-retry')


def raw(value, size=32):
    require(type(value) is list and len(value)==size and any(value)
            and all(type(n) is int and 0<=n<=255 for n in value), 'G public identity bytes')
    return bytes(value)


def verify(value):
    g=value['credential_transition'];request=g['request'];issued=g['issued'];prep=g['preparation']
    operation=raw(request['operation']);statement=raw(issued['statement'])
    journal=identity(value['journal']);p=value['policy_transition'];previous=value['transitions'][1]['progress']['scope']['target']
    require(request['schema']=='qperiapt-retained-credential-request/1'
            and request['journal']==issued['journal']==prep['journal']==list(journal)
            and request['enrollment']==issued['enrollment']
            and request['operation']==issued['operation']==prep['operation']
            and request['original_policy']==p['request']['scope']['original_policy']
            and request['current_policy']==p['progress']['target']
            and request['current_policy_authorization']==list(identity(p['statement']))
            and request['previous_checkpoint']==previous, 'G original identity and R/P/R predecessor')
    raw(request['enrollment']);raw(request['original_owner']);raw(g['proposal_binding'])
    extension=g['extension'];target=issued['checkpoint']
    raw(target['digest'])
    require(type(target['version']) is int and target['version']==previous['version']+1
            and extension['checkpoint']==target and extension['request']['predecessor']==previous
            and extension['request']['enrollment']==request['enrollment']
            and type(issued['root_revision']) is int and issued['root_revision']>0
            and issued['root_revision']==request['root_revision']==extension['root_revision'], 'G exact next account roster')
    proposal=wire(prep['proposal'])
    require(prep['schema']=='qperiapt-credential-witness-proposal/1'
            and len(proposal)==329 and proposal[:8]==b'QPCRNP03'
            and proposal[136:168]==operation and proposal[168:200]==statement
            and proposal[296:]==b'\0'+identity(p['statement']), 'G proposal lost the selected operation or independent P')
    require(g['terminal']==dict(state='Committed',operation=list(operation),statement=list(statement),target=target)
            and g['activation']==dict(state='Active',operation=list(operation),statement=list(statement),
                                      journal=list(journal),checkpoint=target), 'G original committed outcome')
    returned=g['returned_owner']
    require(returned['same_returned_owner'] is True and returned['status']=='Absent'
            and returned['journal']==list(journal) and returned['session']==list(identity(value['session'])),
            'G returned owner did not reopen the original session')
    raw(returned['message'])


def retain(value,copy,doc,output,commands,responses,private):
    g=value['credential_transition'];request=doc('g-request.json');approval=doc('g-approval.json')
    issued=doc('g-issued.json');current=doc('g-current.json');prep=doc('g-preparation.json');trust=doc('g-witness-trust.json')
    decoded={key:parse_strict_json_bytes(responses[key].encode(),label=key) for key in HTTP if key!='g-lost'}
    require(request==g['request']==approval['retained'] and issued==g['issued']==decoded['g-retry']
            and prep==g['preparation'] and current==decoded['g-current']==trust['account']
            and decoded['g-extension']==g['extension'] and decoded['g-absent']=={'state':'Absent'}, 'actual G public exports')
    require(decoded['g-status']['state']=='Issued'
            and wire(decoded['g-status']['response'])==responses['g-retry'].encode(), 'G lost HTTP result was replaced')
    for label in ('g-absent','g-lost','g-status','g-retry'):
        require(commands[label]['account']=='alice' and commands[label]['body']==approval, 'same authenticated G request')
    require(commands['g-lost']['route']==commands['g-retry']['route']=='/api/enrollment/credential-grant'
            and commands['g-absent']['route']==commands['g-status']['route']=='/api/enrollment/credential-grant/status'
            and commands['g-extension']['route']=='/api/enrollment/extend-credential'
            and commands['g-current']['route']=='/api/enrollment/root'
            and all(commands[label]['account']=='alice' for label in HTTP), 'G authenticated account routes')
    extension=g['extension']['request']
    require(commands['g-extension']['body']==extension and approval['successor_extension']==extension['request_id']
            and approval['original_extension'] is None and approval['previous_extension'] is None
            and approval['target_checkpoint']==current['roster']['checkpoint']==issued['checkpoint'], 'G original selected extension')
    original=doc('native-issued.json');invitation=doc('native-invitation.json')
    # This is the first G. R has advanced the admission's signed roster while
    # preserving the original credential and immutable storage owner.
    require(request['original_certificate']==request['previous_certificate']==original['certificate']
            and request['original_roster']==request['previous_roster']==doc('replacement-current.json')['roster']['bytes']
            and request['enrollment']==invitation['operation'] and request['application']==invitation['application'],
            'G did not retain original enrollment and accepted current roster')
    proposal=wire(prep['proposal'])
    require(trust['schema']=='qperiapt-witness-credential-renewal-trust/1'
            and trust['enrollment']==issued['enrollment'] and trust['operation']==issued['operation']
            and trust['statement']==issued['statement'] and trust['proposal_binding']==g['proposal_binding']
            and wire(trust['subject'])==proposal[40:136]==raw(output('native-prepare')['subject'],96)
            and trust['lineage']=={'kind':'independent','statement':list(identity(value['policy_transition']['statement']))}
            and trust['original']==doc('p-original-policy.json') and trust['policy']==doc('p-target-policy.json'),
            'G independently selected original witness subject and acknowledged P')
    require(output('g-stage')=={'state':'Pending','operation':issued['operation'],'statement':issued['statement']}
            and output('g-prepare')=={'state':'RequiresWitnessApproval','operation':issued['operation'],'journal':issued['journal']}
            and output('g-witness-retry')=={'state':'Prepared','binding':g['proposal_binding']}
            and output('g-terminal')==g['terminal'] and output('g-recovered-activation')==g['activation']
            and output('g-reopen')=={'state':'Activated','journal':issued['journal']}
            and output('g-returned-owner')==g['returned_owner'], 'G actual operator, journal and returned-owner outcomes')
    selection=doc('g-returned-owner.json')
    paths={'device_directory':'native-device','wrapping_key':'native-wrap.key','invitation':'native-invitation.json',
           'approval':'g-approval.json','issued':'g-issued.json','current_root':'g-current.json',
           'original_policy':'p-original-policy.json','target_policy':'p-target-policy.json'}
    require(selection['schema']=='qperiapt-credential-recovery-probe/1'
            and selection['session']==list(identity(value['session']))
            and all(selection[key]==str(private/name) for key,name in paths.items()), 'G probe original installation inputs')
    for label in ('g-witness-lost-output','g-activation-lost-output'):
        require(b'broken pipe' in copy(label+'.stderr').lower(), 'G output loss was not observed')
