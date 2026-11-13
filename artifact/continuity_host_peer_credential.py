"""Read back independently implemented G after P on the original peer session."""
from continuity_independent_python import require
from continuity_host_roster_credential import raw
from continuity_host_roster_policy import wire
from continuity_host_replacement import identity

LABELS = tuple(('ig-request ig-request-retry ig-missing-witness ig-wrong-journal ig-wrong-statement '
    'ig-lost-export ig-recover-preparation ig-prepare-retry ig-unapproved-status ig-unapproved-commit '
    'peer-ig-pending-blocks-session ig-witness-lost-output ig-witness-retry ig-commit-lost-output '
    'ig-recover ig-status ig-retired-export ig-reused-request').split())
FAILED = ('ig-missing-witness','ig-wrong-journal','ig-wrong-statement','ig-lost-export','ig-unapproved-commit',
          'peer-ig-pending-blocks-session','ig-witness-lost-output','ig-commit-lost-output','ig-retired-export','ig-reused-request')
HTTP = ('ig-extension','ig-current','ig-absent','ig-lost','ig-issued-status','ig-retry')


def verify(value):
    g=value['independent_credential_transition'];p=value['independent_policy_transition'];request=g['request']
    issued=g['issued'];prep=g['preparation'];op=identity(g['operation']);journal=raw(request['journal'])
    statement=raw(issued['statement']);raw(request['original_owner']);raw(g['proposal_binding'])
    require(g['state']=='Applied' and g['retired'] is True and g['original_key_unchanged'] is True,
            'independent G original completion')
    require(request['schema']=='qperiapt-retained-credential-request/1'
            and request['operation']==issued['operation']==prep['operation']==list(op)
            and request['journal']==issued['journal']==prep['journal']==p['request']['scope']['journal']
            and request['enrollment']==issued['enrollment']==p['request']['enrollment']
            and request['application']==p['request']['application']
            and type(issued['root_revision']) is int and issued['root_revision']>0
            and request['root_revision']==issued['root_revision'], 'independent G original enrollment')
    require(request['original_policy']==p['request']['scope']['original_policy']
            and request['current_policy']==p['account_approval']['target']
            and request['current_policy_authorization']==p['account_approval']['statement']
            and request['previous_checkpoint']==p['request']['scope']['current_roster'],
            'independent G retained P and predecessor')
    extension=g['extension'];target=issued['checkpoint'];raw(target['digest'])
    require(type(target['version']) is int and target['version']==request['previous_checkpoint']['version']+1
            and extension['checkpoint']==target and extension['request']['predecessor']==request['previous_checkpoint']
            and extension['request']['enrollment']==request['enrollment'] and extension['root_revision']==issued['root_revision'],
            'independent G exact target extension')
    proposal=wire(prep['proposal'])
    require(prep['schema']=='qperiapt-credential-witness-proposal/1' and len(proposal)==329 and proposal[:8]==b'QPCRNP03'
            and proposal[40:72]==journal and proposal[136:168]==op and proposal[168:200]==statement
            and proposal[296:]==b'\0'+raw(request['current_policy_authorization']), 'independent G exact proposal')
    h=g['original_intent_sha256']
    require(type(h) is str and len(h)==64 and all(c in '0123456789abcdef' for c in h), 'independent G sealed intent hash')


def retain(value,copy,doc,output,commands,responses):
    from evidence_io import parse_strict_json_bytes
    g=value['independent_credential_transition'];request=doc('ig-request.json');prep=doc('ig-preparation.json')
    issued=doc('ig-issued.json');current=doc('ig-current.json');approval=doc('ig-approval.json');trust=doc('ig-witness-trust.json')
    require(request==g['request']==output('ig-request')==output('ig-request-retry')==doc('ig-request-retry.json')
            and prep==g['preparation']==output('ig-recover-preparation')==output('ig-prepare-retry')==doc('ig-preparation-retry.json'),
            'independent G original exports')
    require(output('ig-unapproved-status')=='Unavailable' and output('ig-recover')==output('ig-status')=='Applied'
            and output('ig-witness-retry')=={'binding':g['proposal_binding'],'state':'Prepared'},
            'independent G exact observations')
    require(copy('ig-occupied.json')==b'original credential export retained','independent G exclusive export')
    subject=output('peer-prepare')['subject'];policies=doc('ip-selected-policies.json')
    require(trust['account']==current and trust['enrollment']==request['enrollment']
            and trust['operation']==issued['operation'] and trust['statement']==issued['statement']
            and trust['proposal_binding']==g['proposal_binding'] and wire(trust['subject'])==bytes(subject)
            and trust['lineage']=={'kind':'independent','statement':request['current_policy_authorization']}
            and trust['original']==policies['original'] and trust['policy']==policies['target'],
            'independent G separately selected witness trust')
    decoded={k:parse_strict_json_bytes(responses[k].encode(),label=k) for k in HTTP if k!='ig-lost'}
    require(issued==g['issued']==decoded['ig-retry'] and current==decoded['ig-current']
            and g['extension']==decoded['ig-extension'] and decoded['ig-absent']=={'state':'Absent'}
            and decoded['ig-issued-status']['state']=='Issued'
            and wire(decoded['ig-issued-status']['response'])==responses['ig-retry'].encode(),
            'independent G real issuer recovery')
    for label in ('ig-absent','ig-lost','ig-issued-status','ig-retry'):
        require(commands[label]['account']=='bob' and commands[label]['body']==approval,'independent G original account request')
    require(approval['retained']==request and approval['target_checkpoint']==issued['checkpoint']
            and commands['ig-extension']['body']['request_id']==approval['successor_extension']
            and commands['ig-lost']['route']==commands['ig-retry']['route']=='/api/enrollment/credential-grant'
            and commands['ig-absent']['route']==commands['ig-issued-status']['route']=='/api/enrollment/credential-grant/status',
            'independent G original authorization chain')
    for field in ('journal','statement'):
        wrong=doc('ig-wrong-'+field+'.json')
        require(set(wrong)==set(issued) and wrong[field]!=issued[field]
                and all(wrong[k]==issued[k] for k in issued if k!=field), 'independent G actual envelope rejection control')
