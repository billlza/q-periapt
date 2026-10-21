"""Installed surviving-device R/P/R/G and read-back public receipts."""
import sys
from continuity_independent_python import PACKAGE, require
from continuity_host_cli import count
from continuity_host_replacement import BINARIES as REPLACEMENT_BINARIES, identity, stats
from evidence_io import parse_strict_json_bytes, read_regular_snapshot
import continuity_host_roster_policy as policy
import continuity_host_roster_credential as credential

BINARIES = REPLACEMENT_BINARIES + ('credential_recovery_probe',)

PREFIX = tuple(('witness-init sdk-init sdk-issue policy-init policy-issue account-init account-enable-enrollment '
    'account-enable-reapproval account-enable-credential-extension account-enable-credential-grants '
    'account-enable-policy-approvals account-enable-device-replacements native-key native-begin native-request '
    'native-accept native-prepare native-witness-enroll native-publication-id native-before-invalid-publication '
    'native-refuse-precredential-publication native-after-invalid-publication native-publication-id-after-refusal '
    'native-publish native-inbox native-original-status survivor-initial peer-prepare peer-witness-enroll peer-connect '
    'peer-lost-next peer-lost-send peer-pending-status pending-effect').split())
STEPS = ('lost-export','recover-original','unapproved','pending-activation','witness-lost-output',
         'witness-retry','commit-lost-output','observe','status','old-current','activate')
LABELS = PREFIX + tuple('addition-'+s for s in STEPS) + tuple(('peer-resume-original-after-add original-effect-after-add '
    'peer-original-bootstrap-retry peer-policy-lost-next peer-policy-lost-send peer-policy-pending-status policy-pending-effect').split()) + policy.LABELS + \
    tuple('replacement-'+s for s in STEPS) + credential.LABELS + tuple(('peer-resume-original-after-policy original-effect-after-policy peer-rekey peer-fresh-next '
        'peer-fresh-send fresh-effect peer-inbox reverse-next reverse-send peer-read-reverse survivor-final').split())
FAILED = ('native-refuse-precredential-publication','peer-lost-send','peer-policy-lost-send') + policy.FAILED + credential.FAILED + tuple(p+'-'+s for p in ('addition','replacement')
    for s in ('lost-export','pending-activation','witness-lost-output','commit-lost-output','old-current'))
HTTP = tuple(('register-alice alice-root register-bob bob-root native-invitation native-approve native-issue '
    'native-authority-identity native-authority-root peer-authority-identity peer-authority-root peer-invitation '
    'peer-approve peer-issue peer-current sibling-authority-identity sibling-authority-root sibling-invitation '
    'sibling-approve sibling-issue added-current p-account-preview p-account-lost p-account-status p-account-retry sibling-replace-lost expired-login alice-relogin '
    'sibling-replace-recovered successor-approve successor-issue replacement-current').split()) + credential.HTTP + ('sibling-history','probe-finish')


def verify(value, binaries, application):
    require(value.get('kind') == 'qperiapt.authenticated_surviving_device_roster' and value.get('completed') is True
            and value.get('release_claim_eligible') is False and value.get('cleanup_errors') == [], 'own roster completion')
    for key,n in [('schema_version',3),('effects',4),('confirmed_epoch',1),('sibling_generation',1),('successor_generation',2)]:
        count(value.get(key),n,key)
    require(value.get('native_sha256') == binaries and value.get('provider') == '48.0.1'
            and value.get('implementation') == str(application / PACKAGE / 'session_cli.py')
            and value.get('clock') == 'actual OS time', 'own roster implementation')
    for key in ('original_keys_unchanged','old_sibling_unchanged'): require(value.get(key) is True,key)
    for key in ('session','journal','original_pending_message'): identity(value.get(key))
    rows = value.get('commands')
    require(type(rows) is list and [r['label'] for r in rows] == list(LABELS), 'own roster command inventory')
    for row in rows:
        require(type(row['exit']) is int and (row['exit'] != 0) == (row['label'] in FAILED), 'own roster command outcome')
    rows = value.get('account_requests')
    require(type(rows) is list and [r['label'] for r in rows] == list(HTTP), 'own roster HTTP inventory')
    for i,row in enumerate(rows,1):
        count(row['id'],i,'HTTP id')
        expected = 'register' if row['label'].startswith('register-') else 'login' if row['label']=='alice-relogin' else 'finish' if row['label']=='probe-finish' else 'request'
        require(row['action'] == expected,'own roster HTTP action')
    transitions = value.get('transitions')
    require(type(transitions) is list and len(transitions)==2,'two own roster transitions')
    for i,t in enumerate(transitions):
        operation = identity(t['operation'])
        p = t['progress']; scope = p['scope']
        require(p['schema']=='qperiapt-roster-refresh-progress/1' and p['state']=='Applied' and p['retired'] is True
                and scope['operation']==list(operation) and p['binding']==t['binding']
                and t['observation']=={'binding':t['binding'],'state':'Applied'},'exact retired own roster result')
        count(scope['previous']['version'],i+1,'predecessor version'); count(scope['target']['version'],i+2,'target version')
    require(transitions[0]['binding'] != transitions[1]['binding'] and transitions[0]['operation'] != transitions[1]['operation']
            and transitions[0]['progress']['scope']['target'] == transitions[1]['progress']['scope']['previous'], 'original R chain')
    policy.verify(value)
    credential.verify(value)
    pids = set()
    for key,expected in [('services',[('survivor-first',0),('survivor-after-add',0),('survivor-after-replacement',0)]),
                         ('witness_services',[('witness-first',-9),('witness-reopened',0)]),
                         ('account_services',[('account-first',-9),('account-reopened',0)]),
                         ('independent_service',[('peer-receiver',0)])]:
        rows = [value[key]] if key=='independent_service' else value[key]
        require(len(rows)==len(expected),'own roster service inventory')
        for row,(label,code) in zip(rows,expected):
            require(row['label']==label and type(row['pid']) is int and row['pid']>0 and row['pid'] not in pids,'own roster process identity')
            count(row['exit'],code,'own roster process exit'); pids.add(row['pid'])
    for row,n in zip(value['services'],(3,2,4)): stats(row['stats'],n,n)
    stats(value['independent_service']['stats'],1,1)


def retain(value, private, public, snapshot):
    public.mkdir()
    def copy(name):
        item=snapshot(private/name); (public/name).write_bytes(item.data); return item.data
    def doc(name): return parse_strict_json_bytes(copy(name),label=name)
    def output(label): return doc(label+'.stdout')
    copy('RESULT.json')
    for label in LABELS:
        out,err=copy(label+'.stdout'),copy(label+'.stderr')
        require(bool(err)==(label in FAILED),'own roster diagnostics')
        if label in FAILED: require(not out,'own roster refusal output')
        if label.endswith(('witness-lost-output','commit-lost-output')):
            require(b'broken pipe' in err.lower(),'own roster actual lost output')
    responses,commands={},{}
    for row in value['account_requests']:
        label=row['label']; q,a=doc(label+'.http-request.json'),doc(label+'.http-response.json')
        require(type(q['id']) is int and type(a['id']) is int and q['id']==a['id']==row['id']
                and q['command']['action']==row['action'],'own roster HTTP correlation')
        c,r=q['command'],a['result']; commands[label]=c
        if row['action'] != 'request':
            expected={'authenticated':'registered_software_test_passkey'} if row['action']=='register' else {'authenticated':'original_software_test_passkey'} if row['action']=='login' else {'finished':True}
            require(r==expected,'own roster authentication outcome'); continue
        code=401 if label=='expired-login' else 204 if label.endswith('-approve') else 200
        count(r['status'],code,'HTTP status')
        require(c['disconnect_before_body'] is (label in ('sibling-replace-lost','p-account-lost','g-lost')),'own roster HTTP disconnect')
        if label in ('sibling-replace-lost','p-account-lost','g-lost') or code==204: require(r['body']=='','lost HTTP body')
        responses[label]=r['body']
    for key in ('account','route','body'):
        require(commands['sibling-replace-lost'][key]==commands['sibling-replace-recovered'][key],'original HTTP replacement retry')
    require(commands['sibling-replace-recovered']['route']=='/api/enrollment/replace-device'
            and responses['sibling-issue']==responses['sibling-history'],'original sibling history')
    for label,http,version in [('addition','added-current',2),('replacement','replacement-current',3)]:
        target=doc(label+'-current.json'); request=doc(label+'-request.json'); trust=doc(label+'-trust.json')
        require(target==parse_strict_json_bytes(responses[http].encode(),label='actual HTTP target')
                and doc(label+'-inputs.json')['target']==target and trust['account']==target,'actual independently selected roster')
        require(output(label+'-recover-original')==request and output(label+'-unapproved')=={'binding':request['binding'],'state':'Unavailable'}
                and output(label+'-witness-retry')=={'binding':request['binding'],'state':'Prepared'},'own roster original preparation')
        t=value['transitions'][version-2]
        require(output(label+'-observe')==t['observation'] and output(label+'-status')==t['progress']
                and t['binding']==request['binding']==trust['proposal_binding'],'own roster terminal readback')
        require(t['progress']['scope']['target']==target['roster']['checkpoint']
                and request['proposal']==t['progress']['proposal'],'own roster exact target and proposal')
        require(copy(label+'-occupied.json')==b'original export retained','original export preservation')
    require(output('survivor-initial')==output('survivor-final')==output('native-original-status'),'original survivor identity')
    protected=doc('protected-before.json')
    require(set(protected)=={'native-device/device.key','native-wrap.key'} and protected==doc('protected-after.json')
            and all(type(h) is str and len(h)==64 and all(c in '0123456789abcdef' for c in h) for h in protected.values()),'original protected key hashes')
    require(output('peer-connect')==output('peer-original-bootstrap-retry')=={'session':value['session'],'peer_confirmation':'Recorded'},'original session retry')
    require(output('peer-rekey')=={'session':value['session'],'epoch':1,'exchanges':2},'original session rekey')
    require(output('peer-pending-status')=={'session':value['session'],'message':value['original_pending_message'],'status':'Committed'},'original lost ACK status')
    for name,body in [('pending-effect.bin',b'pending before sibling addition'),('original-effect-after-add.bin',b'pending before sibling addition'),
                      ('fresh-effect.bin',b'after sibling replacement'),('reverse.bin',b'surviving original owner')]:
        require(copy(name)==body,'own roster durable effect')
    for name in ('lost.request','lost.response','account-probe.stderr'): copy(name)
    policy.retain(value,copy,doc,output,commands,responses)
    credential.retain(value,copy,doc,output,commands,responses,private)
    return len(list(public.iterdir()))


def qualify(args, reference, application, provider, outside, output, snapshot, run):
    paths=[getattr(args,key).resolve(strict=True) for key in BINARIES]
    def hashes(): return {str(p):read_regular_snapshot(p,maximum=128*1024**2,label='roster executable').sha256 for p in paths}
    binaries=hashes()
    for name in ('host_roster','host_roster_policy','host_roster_credential','host_replacement_device','host_replacement_process','native_exchange_fixture',
                 'native_network_driver','independent_inbound_cli','witness_cli_exchange'):
        (outside/(name+'.py')).write_bytes(snapshot(reference/'tests'/(name+'.py')).data)
    private=outside/'private-authenticated-roster'
    command=[sys.executable,'-I','-S','-B',str(outside/'host_roster.py')]
    for key,path in zip(BINARIES,paths): command += ['--'+key.replace('_','-'),str(path)]
    command += ['--implementation-root',str(application),'--provider-root',str(provider),'--output',str(private),'--credential-renewal']
    executed=run(command,'authenticated-roster')
    value=parse_strict_json_bytes(executed.stdout,label='installed authenticated roster')
    verify(value,binaries,application)
    require(parse_strict_json_bytes(snapshot(private/'RESULT.json').data,label='retained roster')==value,'roster retained result')
    retain(value,private,output/'authenticated-roster-public',snapshot)
    require(hashes()==binaries,'roster executable changed')
    return value
