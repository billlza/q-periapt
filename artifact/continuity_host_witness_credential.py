"""Correlate complete-account G with the original witness and session receipts.

Execution checks, not independent signature or account-authorization proofs.
"""
import hashlib
from continuity_independent_python import require
from continuity_host_network import count
from continuity_host_replacement import identity
from continuity_host_roster_credential import raw
from continuity_host_roster_policy import wire
from evidence_io import parse_strict_json_bytes

LABELS=tuple('wg-'+name for name in ('request','missing-witness','single-refused','missing-companion',
    'wrong-companion','lost-export','recover-preparation','prepare-retry','unapproved-status','unapproved-commit',
    'pending-blocks-session','witness-wrong-binding','still-unapproved','witness-lost-output','witness-retry',
    'commit-lost-output','recover','status','retired-export','reused-request'))
FAILED=tuple('wg-'+name for name in ('missing-witness','single-refused','missing-companion','wrong-companion',
    'lost-export','unapproved-commit','pending-blocks-session','witness-wrong-binding','witness-lost-output',
    'commit-lost-output','retired-export','reused-request'))


def verify(value):
    g=value.get('account_credential')
    require(type(g) is dict and all(g.get(k) is True for k in ('completed','retired','original_key_unchanged'))
            and g.get('state')=='Applied','witness account completion')
    op=identity(g['operation']);journal=identity(g['journal']);request=g['request'];issued=g['issued'];companion=g['companion']
    require(g['session']==value['session'] and g['message']==value['original_lost_message']
            and list(journal)==value['genesis']['subject'][:32],'witness account original session')
    require(request['schema']=='qperiapt-retained-credential-request/1'
            and request['operation']==issued['operation']==list(op)
            and request['journal']==issued['journal']==list(journal)
            and request['enrollment']==issued['enrollment'],'witness account original issuance')
    for item in (request,issued,companion):count(item['root_revision'],1,'witness account root revision')
    count(request['previous_checkpoint']['version'],1,'witness account predecessor')
    for item in (issued,companion):count(item['checkpoint']['version'],2,'witness account target')
    require(issued['checkpoint']==companion['checkpoint'] and request['current_policy']==request['original_policy']
            and request['current_policy_authorization'] is None,'witness account selected lineage')
    require(raw(companion['journal'])!=journal and raw(companion['operation'])!=op,'witness account distinct companion')
    for item in (issued,companion):
        raw(item['enrollment']);raw(item['statement']);raw(item['checkpoint']['digest'])
        grant=wire(item['grant']);require(8<len(grant)<=65536 and grant[:8]==b'QPRNB001','witness account grant wire')
    prep=g['preparation'];proposal=wire(prep['proposal'])
    require(prep['schema']=='qperiapt-credential-witness-proposal/1' and prep['journal']==list(journal)
            and prep['operation']==list(op) and len(proposal)==296 and proposal[:8]==b'QPCRNP01'
            and proposal[40:136]==bytes(value['genesis']['subject']) and proposal[136:168]==op
            and proposal[168:200]==raw(issued['statement']),'witness account exact original proposal')
    domain=b'Q-PERIAPT-ANCHOR-CREDENTIAL-PROPOSAL/v1'
    require(raw(g['proposal_binding'])==hashlib.sha3_256(len(domain).to_bytes(8,'big')+domain
            +len(proposal).to_bytes(8,'big')+proposal).digest(),'witness account proposal binding')
    h=g['original_intent_sha256'];require(type(h) is str and len(h)==64 and all(c in '0123456789abcdef' for c in h),'witness account retained intent')
    rows=g['commands'];require(type(rows) is list and len(rows)==len(LABELS),'witness account command count')
    for row,label in zip(rows,LABELS):
        require(set(row)=={'label','exit'} and row['label']==label and type(row['exit']) is int
                and (row['exit']!=0)==(label in FAILED),'witness account command disposition')


def retain(value,copy,output):
    g=value['account_credential']
    def data(name):return copy(name).data
    def doc(name):return parse_strict_json_bytes(data(name),label=name)
    for label in LABELS:
        stdout,stderr=data(label+'.stdout'),data(label+'.stderr')
        require(bool(stderr)==(label in FAILED),'witness account diagnostics')
        if label in FAILED:require(not stdout,'failed witness account command emitted success')
        if label in ('wg-witness-lost-output','wg-commit-lost-output'):
            require(b'broken pipe' in stderr.lower(),'witness account output was not lost')
    require(doc('wg-request.json')==output('wg-request')==g['request']
            and doc('wg-issued.json')==g['issued'],'witness account original exports')
    require(doc('wg-preparation.json')==doc('wg-preparation-retry.json')==g['preparation']
            ==output('wg-recover-preparation')==output('wg-prepare-retry'),'witness account exact proposal recovery')
    require(output('wg-unapproved-status')==output('wg-still-unapproved')=='Unavailable'
            and output('wg-witness-retry')=={'binding':g['proposal_binding'],'state':'Prepared'}
            and output('wg-recover')==output('wg-status')=='Applied','witness account original outcomes')
    require(data('wg-occupied.json')==b'original witnessed account export retained','witness account exclusive export')
    companions=doc('wg-companions.json');wrong=doc('wg-wrong-companion.json')
    require(companions=={'schema':'qperiapt-companion-credential-grants/1','grants':[g['companion']]}
            and doc('wg-missing.json')==dict(companions,grants=[]),'witness account complete-set controls')
    require(set(wrong)==set(companions) and wrong['schema']==companions['schema']
            and type(wrong['grants']) is list and len(wrong['grants'])==1,'witness account altered companion')
    changed=wrong['grants'][0];original=g['companion']
    require(set(changed)==set(original) and raw(changed['statement'])!=raw(original['statement'])
            and all(changed[k]==original[k] for k in original if k!='statement'),'witness account statement control')
    current=doc('wg-current.json');trust=doc('wg-witness-trust.json');wrong=doc('wg-wrong-witness-trust.json')
    policy={'pins':doc('policy-pins.json'),'materials':doc('policy-materials.json')}
    require(current['roster']['checkpoint']==g['issued']['checkpoint']
            and trust=={'schema':'qperiapt-witness-credential-renewal-trust/1','account':current,
                'enrollment':g['issued']['enrollment'],'operation':g['issued']['operation'],'statement':g['issued']['statement'],
                'subject':trust['subject'],'proposal_binding':g['proposal_binding'],'lineage':{'kind':'original'},
                'original':policy,'policy':policy}
            and wire(trust['subject'])==bytes(value['genesis']['subject']),'witness account independent operator selection')
    require(set(wrong)==set(trust) and raw(wrong['proposal_binding'])!=raw(trust['proposal_binding'])
            and all(wrong[k]==trust[k] for k in trust if k!='proposal_binding'),'witness account wrong-binding control')
