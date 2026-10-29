"""Installed local TCP interoperability; no TLS or cross-host release claim."""
import sys
from continuity_independent_python import PACKAGE, require
from continuity_host_native_exchange import LABELS as FILE_LABELS, REFUSALS as FILE_REFUSALS
from evidence_io import parse_strict_json_bytes, read_regular_snapshot

LABELS = FILE_LABELS[:9] + ('network-native-next','network-native-first','network-native-lost-next',
    'network-native-lost','network-native-lost-status','network-native-resume','network-native-rekey',
    'network-native-epoch-next','network-native-epoch-two','network-read-delivery')
REFUSALS = FILE_REFUSALS[:8] + ('network-independent-lost','network-native-lost')
EXCHANGES = (('tcp-bootstrap-1',1),('tcp-bootstrap-2',2),('tcp-first-1',3),('tcp-idle-admission-1',3),
    ('tcp-resume-1',3),('tcp-control-1',4),('tcp-control-2',4),('tcp-return-1',3))
NATIVE_EXCHANGES = tuple(('tcp-native-'+str(i),kind) for i,kind in enumerate((3,3,3,4,4,3),1))
STATS = {'accepted','evicted_incomplete','rejected_busy','read_errors','completed_responses',
         'operation_errors','last_operation_error'}
NATIVE_STATS = STATS | {'queued_requests','expired_queued'}


def count(value,expected,label):
    require(type(value) is int and value==expected,label)


def stats_shape(value,*,native=False,queued=False):
    fields=NATIVE_STATS if native else STATS
    require(type(value) is dict and set(value)==fields,'network service stats schema')
    require(all(type(value[k]) is int and value[k]>=0 for k in fields-{'last_operation_error'}),
            'network service count type')
    if native:
        count(value['expired_queued'],0,'unexpected expired network request')
        if queued:
            require(value['queued_requests']<=value['accepted'],'network queued request count')
        else:count(value['queued_requests'],0,'unexpected queued network request')


def stats(value,accepted,completed,*,idle=False,native=False,queued=False):
    stats_shape(value,native=native,queued=queued)
    count(value['accepted'],accepted,'network accepted requests')
    count(value['completed_responses'],completed,'network completed responses')
    require(value['operation_errors']==0 and value['last_operation_error'] is None
            and value['rejected_busy']==0,'unexpected network owner error')
    if idle:
        require(value['evicted_incomplete']>=7 and value['evicted_incomplete']+value['read_errors']==8,
                'idle TCP admission did not evict incomplete reads')
    else:require(value['evicted_incomplete']==0 and value['read_errors']==0,'unexpected network read failure')


def exchanges(value,expected):
    require(type(value) is list and len(value)==len(expected),'network exchange inventory')
    for row,(label,kind) in zip(value,expected):
        require(type(row) is dict and set(row)=={'label','kind','request_sha256','response_sha256'}
                and row['label']==label,'network exchange record')
        count(row['kind'],kind,'network exchange kind')
        for name in ('request_sha256','response_sha256'):
            digest=row[name]
            require(type(digest) is str and len(digest)==64 and all(c in '0123456789abcdef' for c in digest),
                    'network frame digest')


def verify(observed,binaries,application):
    require(type(observed) is dict and observed.get('kind')=='qperiapt.native_reference_network'
            and observed.get('completed') is True,'network completion')
    count(observed.get('schema_version'),1,'network result schema')
    require(observed.get('native_sha256')==binaries and observed.get('provider')=='48.0.1'
            and observed.get('implementation')==str(application/PACKAGE/'network.py')
            and observed.get('clock')=='actual OS time','network implementation differs')
    for key,expected in (('effects',3),('effect_commit_calls',3),('confirmed_epoch',2)):
        count(observed.get(key),expected,'network '+key)
    commands=observed.get('commands')
    require(type(commands) is list and len(commands)==len(LABELS),'network command inventory')
    for row,label in zip(commands,LABELS):
        require(type(row) is dict and set(row)=={'label','exit'} and row['label']==label,'network command')
        count(row['exit'],1 if label in ('wrong-inbox-journal','network-native-lost') else 0,'network command result')
    require(observed.get('refusals')==list(REFUSALS),'network refusal inventory')
    services=observed.get('services');require(type(services) is list and len(services)==2,'service reopen inventory')
    pids=set()
    for index,label in enumerate(('network-service-first','network-service-reopened')):
        row=services[index]
        require(type(row) is dict and set(row)=={'label','pid','exit','stats'} and row['label']==label
                and type(row['pid']) is int and row['pid']>0 and row['pid'] not in pids,'service process identity')
        pids.add(row['pid']);count(row['exit'],0,'service exit')
        stats(row['stats'],14 if index else 3,6 if index else 3,idle=bool(index),native=True)
    stats(observed.get('independent_service'),6,6)
    exchanges(observed.get('independent_exchanges'),EXCHANGES)
    native=observed.get('native_exchanges');exchanges(native,NATIVE_EXCHANGES)
    require(all(native[1][key]==native[2][key] for key in ('request_sha256','response_sha256')),
            'native consumed retry changed original frames')


def retain(observed,private,public,snapshot):
    """Recompute frame hashes, reconcile lost replies, retain only public outputs."""
    public.mkdir()
    def copy(name):
        item=snapshot(private/name);(public/name).write_bytes(item.data);return item
    copy('RESULT.json')
    for label in LABELS:
        for suffix in ('.stdout','.stderr'):copy(label+suffix)
    for service in observed['services']:
        label=service['label'];out=copy(label+'.stdout');err=copy(label+'.stderr')
        lines=out.data.splitlines();require(len(lines)==2 and not err.data,'network service retained output')
        ready=parse_strict_json_bytes(lines[0],label='network listener receipt')
        require(set(ready)=={'service','carrier','address'} and ready['service']=='Listening'
                and ready['carrier']=='QPCXCH01/TCP' and type(ready['address']) is str
                and ready['address'].startswith('127.0.0.1:'),'network listening receipt')
        port=ready['address'].removeprefix('127.0.0.1:')
        require(port.isascii() and port.isdecimal() and 1<=int(port)<=65535,'network listening endpoint')
        require(parse_strict_json_bytes(lines[1],label='network service stop')==
                {'service':'Stopped','stats':service['stats']},'network retained stop differs')
    for row in observed['independent_exchanges']+observed['native_exchanges']:
        for side in ('request','response'):
            item=copy(row['label']+'.'+side)
            require(item.sha256==row[side+'_sha256'],'network retained frame hash differs')
            require(10<=len(item.data)<=32768 and item.data[:8]==b'QPCXCH01'
                    and item.data[8]==row['kind']+(128 if side=='response' else 0),'network retained frame kind')
    for label,retry in (('tcp-lost','tcp-resume-1'),('tcp-native-lost','tcp-native-3')):
        for suffix,side in (('.request','request'),('-upstream.response','response')):
            lost=copy(label+suffix);original=snapshot(private/(retry+'.'+side))
            require(lost.data==original.data,'network lost response original retry differs')


def qualify(args,reference,application,provider,outside,output,snapshot,run):
    paths=[getattr(args,key).resolve(strict=True) for key in ('native_device','native_session','crash_probe','native_outgoing')]
    def hashes():
        return {str(path):read_regular_snapshot(path,maximum=128*1024**2,label='network executable').sha256 for path in paths}
    binaries=hashes()
    # Other native_exchange helpers are retained by the preceding file workload.
    for name in ('native_network_flow.py','native_network_driver.py'):
        (outside/name).write_bytes(snapshot(reference/'tests'/name).data)
    private=outside/'private-native-network'
    command=[sys.executable,'-I','-S','-B',str(outside/'native_exchange.py'),'--network']
    for key,path in zip(('native-device','native-session','crash-probe','native-outgoing'),paths):command+=['--'+key,str(path)]
    command+=['--implementation-root',str(application),'--provider-root',str(provider),'--output',str(private)]
    execution=run(command,'native-network')
    observed=parse_strict_json_bytes(execution.stdout,label='installed native network result')
    verify(observed,binaries,application)
    require(parse_strict_json_bytes(snapshot(private/'RESULT.json').data,label='retained native network result')==observed,
            'network retained result differs')
    retain(observed,private,output/'native-network-public',snapshot)
    require(hashes()==binaries,'network executable changed')
    return observed
