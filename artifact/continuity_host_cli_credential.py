"""Read back complete-account CLI adoption under the explicit test issuer.

These are execution-receipt correlations; running owners verify signatures.
They do not establish real account authorization or witness operator coverage.
"""
from continuity_independent_python import require
from continuity_host_replacement import identity
from continuity_host_network import count
from continuity_host_roster_credential import raw
from continuity_host_roster_policy import wire
from evidence_io import parse_strict_json_bytes

LABELS = tuple('ag-' + name for name in ('request', 'single-refused', 'missing-refused',
    'statement-refused', 'lost-export', 'pending', 'prepare-retry', 'commit-lost-output',
    'committed', 'commit-retry'))
FAILED = ('ag-single-refused', 'ag-missing-refused', 'ag-statement-refused',
          'ag-lost-export', 'ag-commit-lost-output')


def verify(value):
    g = value.get('account_credential')
    require(type(g) is dict and g.get('completed') is True
            and g.get('original_pending_message_retained') is True, 'account CLI completion')
    op = identity(g['operation']); journal = identity(g['journal'])
    identity(g['session']); identity(g['message'])
    request, issued, companion = g['request'], g['issued'], g['companion']
    for item in (request, issued, companion):count(item['root_revision'],1,'account CLI root revision')
    count(request['previous_checkpoint']['version'],1,'account CLI previous roster')
    for item in (issued,companion):count(item['checkpoint']['version'],2,'account CLI next roster')
    require(request['schema'] == 'qperiapt-retained-credential-request/1'
            and raw(request['journal']) == raw(issued['journal']) == journal
            and raw(request['operation']) == raw(issued['operation']) == op
            and request['enrollment'] == issued['enrollment']
            and request['root_revision'] == issued['root_revision'] == companion['root_revision'] == 1,
            'account CLI original installation')
    require(request['current_policy'] == request['original_policy']
            and request['current_policy_authorization'] is None
            and request['previous_checkpoint']['version'] == 1
            and issued['checkpoint'] == companion['checkpoint']
            and issued['checkpoint']['version'] == 2, 'account CLI original policy and next roster')
    raw(request['enrollment']); raw(companion['enrollment']); raw(companion['statement'])
    require(raw(companion['journal']) != journal and raw(companion['operation']) != op,
            'account CLI distinct companion')
    for grant in (issued, companion):
        encoded = wire(grant['grant'])
        require(8 < len(encoded) <= 65536 and encoded[:8] == b'QPRNB001', 'account CLI grant wire')
    pending = g['pending']; committed = g['committed']
    require(set(pending) == {'status','operation','statement','target','binding','time_floor','expired_observation'}
            and pending['status'] == 'Pending' and pending['operation'] == op.hex()
            and pending['statement'] == raw(issued['statement']).hex()
            and pending['target'] == ((2).to_bytes(8,'big') + raw(issued['checkpoint']['digest'])).hex()
            and type(pending['binding']) is str and len(pending['binding']) == 64
            and all(c in '0123456789abcdef' for c in pending['binding'])
            and type(pending['time_floor']) is int and pending['time_floor'] == 0
            and pending['expired_observation'] is None
            and committed == dict(pending, status='Committed'), 'account CLI retained target')
    rows = g['commands']
    require(type(rows) is list and len(rows) == len(LABELS), 'account CLI command count')
    for row, label in zip(rows, LABELS):
        require(set(row) == {'label','exit'} and row['label'] == label and type(row['exit']) is int
                and (row['exit'] != 0) == (label in FAILED), 'account CLI command outcome')


def retain(value, copy, output):
    g = value['account_credential']
    def data(name): return copy(name).data
    def doc(name): return parse_strict_json_bytes(data(name), label=name)
    for label in LABELS:
        stdout, stderr = data(label+'.stdout'), data(label+'.stderr')
        require(bool(stderr) == (label in FAILED), 'account CLI diagnostics')
        if label in FAILED: require(not stdout, 'failed account CLI emitted success')
        if label == 'ag-commit-lost-output':
            require(b'broken pipe' in stderr.lower(), 'account CLI commit output was not lost')
    require(doc('ag-request.json') == output('ag-request') == g['request']
            and doc('ag-issued.json') == g['issued'], 'account CLI original exports')
    require(output('ag-pending') == output('ag-prepare-retry') == doc('ag-prepared.json') == g['pending']
            and output('ag-committed') == output('ag-commit-retry') == g['committed'],
            'account CLI exact retry readback')
    require(data('ag-occupied.json') == b'original export retained', 'account CLI export overwritten')
    companions = doc('ag-companions.json')
    require(companions == {'schema':'qperiapt-companion-credential-grants/1','grants':[g['companion']]}
            and doc('ag-missing.json') == dict(companions, grants=[]), 'account CLI complete-set controls')
    wrong = doc('ag-wrong.json')
    require(set(wrong) == set(companions) and wrong['schema'] == companions['schema']
            and type(wrong['grants']) is list and len(wrong['grants']) == 1, 'account CLI altered envelope')
    changed, original = wrong['grants'][0], g['companion']
    require(set(changed) == set(original) and raw(changed['statement']) != raw(original['statement'])
            and all(changed[k] == original[k] for k in original if k != 'statement'),
            'account CLI statement rejection control')
    current = doc('ag-current.json')
    require(current['roster']['checkpoint'] == g['issued']['checkpoint'], 'account CLI selected current roster')
    require(output('cli-connect')['session'] == g['session']
            and output('cli-prepare')['journal'] == g['journal']
            and output('cli-lost-next')['message'] == g['message']
            and output('cli-resume') == {'session':g['session'],'message':g['message'],'consumption':'Confirmed'},
            'account CLI original session and pending message')
