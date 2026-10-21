"""Installed required-witness first use and original service recovery evidence."""
import sys
from continuity_independent_python import PACKAGE,require
from continuity_host_network import count,stats
from continuity_host_native_exchange import REFUSALS as ORIGINAL_REFUSALS
from evidence_io import parse_strict_json_bytes,read_regular_snapshot
import continuity_host_witness_credential as credential

LABELS=tuple('witness-init native-key native-begin native-request native-accept native-prepare native-witness-enroll '
    'native-publication-id native-publish native-inbox wrong-inbox-journal witness-cli-prepare witness-cli-prepare-retry '
    'witness-cli-unenrolled wrong-head-witness-enroll independent-witness-enroll witness-cli-missing-carrier '
    'witness-cli-connect witness-cli-connect-reopen witness-cli-next witness-cli-deliver witness-read-first '
    'witness-cli-lost-next witness-cli-lost witness-cli-lost-status witness-cli-offline witness-original-pin '
    'advanced-retry-witness-enroll witness-cli-resume witness-read-lost witness-cli-rekey witness-cli-provision-inbox '
    'witness-native-rekey witness-native-next witness-native-delivery witness-cli-read-inbox'.split())
FAILED=('wrong-inbox-journal','witness-cli-unenrolled','wrong-head-witness-enroll',
        'witness-cli-missing-carrier','witness-cli-lost','witness-cli-offline')
REFUSALS=ORIGINAL_REFUSALS[:8]+FAILED[1:]


def verify(value,binaries,application,*,account_credential=False):
    require(type(value) is dict and value.get('kind')=='qperiapt.required_witness_session_cli'
            and value.get('completed') is True,'required witness completion')
    count(value.get('schema_version'),2 if account_credential else 1,'witness receipt version')
    if account_credential:credential.verify(value)
    count(value.get('confirmed_epoch'),2,'witness epoch');count(value.get('effects'),3,'witness effects')
    require(value.get('native_sha256')==binaries and value.get('provider')=='48.0.1'
            and value.get('implementation')==str(application/PACKAGE/'session_cli.py')
            and value.get('clock')=='actual OS time','witness installed implementation')
    require(value.get('commands')==[{'label':label,'exit':1 if label in FAILED else 0} for label in LABELS]
            and all(type(row['exit']) is int for row in value['commands']),'witness command inventory')
    require(value.get('refusals')==list(REFUSALS),'witness refusal inventory')
    require(value.get('witness_keys_unchanged') is True,'witness key continuity')
    genesis=value.get('genesis')
    require(type(genesis) is dict and set(genesis)=={'preparation','subject','head'}
            and genesis['preparation']=='RequiresWitnessEnrollment','witness genesis export')
    for key,length in [('subject',96),('head',32)]:
        raw=genesis[key]
        require(type(raw) is list and len(raw)==length and all(type(v) is int and 0<=v<=255 for v in raw)
                and any(raw),'witness genesis bytes')
    services=[]
    for key,label,n in [('native_service','witness-native-service',7),('independent_service','witness-independent-service',3)]:
        row=value.get(key)
        require(type(row) is dict and set(row)=={'label','pid','exit','stats'} and row['label']==label,'witness session service')
        count(row['exit'],0,'witness session service exit');stats(row['stats'],n,n);services.append(row)
    witnesses=value.get('witness_services')
    require(type(witnesses) is list and len(witnesses)==2,'witness service lifecycle')
    for row,label,exit_code in zip(witnesses,('witness-first','witness-reopened'),(-9,0)):
        require(type(row) is dict and set(row)==({'label','pid','exit'} if exit_code==-9 else {'label','pid','exit','stats'})
                and row['label']==label and type(row['exit']) is int and row['exit']==exit_code,'witness original kill/reopen')
        if exit_code==0:
            n=row['stats'].get('completed_responses')
            require(type(n) is int and 1<=n<=1024,'witness bounded response workload')
            stats(row['stats'],n,n)
        services.append(row)
    require(all(type(s['pid']) is int and s['pid']>0 for s in services)
            and len({s['pid'] for s in services})==4,'separate original witness/session processes')


def retain(value,private,public,snapshot):
    public.mkdir()
    def copy(name):
        item=snapshot(private/name);(public/name).write_bytes(item.data);return item
    def result(name):return parse_strict_json_bytes(copy(name+'.stdout').data,label=name)
    copy('RESULT.json')
    if value.get('schema_version')==2:credential.retain(value,copy,result)
    for label in LABELS:
        out=copy(label+'.stdout');err=copy(label+'.stderr')
        require(bool(err.data)==(label in FAILED),'witness diagnostic disposition')
        if label in FAILED:require(not out.data,'failed witness command emitted result')
    sid=value['session'];lost=value['original_lost_message']
    require(result('witness-cli-connect')=={'session':sid,'peer_confirmation':'Recorded'}
            and result('witness-cli-connect-reopen')==result('witness-cli-connect'),'original required witness session')
    require(result('witness-cli-prepare')==value['genesis']
            and result('witness-cli-prepare-retry')==value['genesis'],'original witness genesis retry')
    require(result('witness-init')==result('witness-original-pin'),'original witness pin')
    require(result('witness-cli-lost-next')=={'session':sid,'message':lost}
            and result('witness-cli-lost-status')=={'session':sid,'message':lost,'status':'Committed'}
            and result('witness-cli-resume')=={'session':sid,'message':lost,'consumption':'Confirmed'},'original unknown-result recovery')
    require(result('witness-cli-rekey')=={'session':sid,'epoch':1,'exchanges':2}
            and result('witness-native-rekey')=={'epoch':2,'exchanges':2}
            and result('witness-native-delivery')=={'consumption':'Confirmed'},'witness two-way rekey and delivery')
    incoming=result('witness-native-next')['message']
    require(type(incoming) is list and len(incoming)==32 and all(type(x) is int and 0<=x<=255 for x in incoming)
            and bytes(incoming[:8])==(2).to_bytes(8,'big'),'new epoch real message')
    for name,body in [('witness-first.bin',b'required witness original delivery'),
        ('witness-lost.bin',b'required witness original delivery'),('witness-reverse.bin',b'native required witness epoch two')]:
        require(copy(name).data==body,'witness durable effect readback')
    for side,kind in [('request',3),('response',131)]:
        raw=copy('witness-lost.'+side).data
        require(10<=len(raw)<=32768 and raw[:9]==b'QPCXCH01'+bytes([kind]),'real lost witness application exchange')
    for row in [value['native_service'],value['independent_service'],*value['witness_services']]:
        lines=copy(row['label']+'.stdout').data.splitlines()
        require(not copy(row['label']+'.stderr').data and len(lines)==(1 if row['exit']==-9 else 2),'witness process output')
        require(parse_strict_json_bytes(lines[0],label='service readiness')['service']=='Listening','witness readiness')
        if row['exit']==0:
            require(parse_strict_json_bytes(lines[1],label='service stop')=={'service':'Stopped','stats':row['stats']},'witness process shutdown')
    before=parse_strict_json_bytes(copy('witness-key-hashes-before.json').data,label='original witness keys')
    after=parse_strict_json_bytes(copy('witness-key-hashes-after.json').data,label='reopened witness keys')
    require(type(before) is dict and before==after and len(before)==2,'witness retained protected key hashes')
    for name,digest in before.items():
        require(type(name) is str and '/' not in name and '\\' not in name and name.startswith('witness-')
                and name.endswith(('.wrap','.signer')),'witness protected key filename')
        require(snapshot(private/name).sha256==digest,'witness original key file differs')
    for label in ('native','wrong-head','independent','advanced-retry'):
        approval=parse_strict_json_bytes(copy(label+'-witness-trust.json').data,label='operator approval')
        genesis=parse_strict_json_bytes(copy(label+'-genesis.json').data,label='device genesis')
        require(approval['genesis_head']!=genesis['head'] if label=='wrong-head' else approval['genesis_head']==genesis['head'],'exact approved genesis')
        if label in ('independent','advanced-retry'):
            require(genesis==value['genesis'] and approval['journal']==genesis['subject'][:32],'original enrollment approval')
    require(snapshot(private/'independent-witness-trust.json').data==snapshot(private/'advanced-retry-witness-trust.json').data,
            'advanced enrollment retry changed approval')


def qualify(args,reference,application,provider,outside,output,snapshot,run):
    keys=('native_device','native_session','crash_probe','native_outgoing','witness')
    paths=[getattr(args,key).resolve(strict=True) for key in keys]
    def hashes():return {str(p):read_regular_snapshot(p,maximum=128*1024**2,label='witness native executable').sha256 for p in paths}
    binaries=hashes()
    for name in ('witness_cli_exchange.py','witness_account_credential_cli.py','account_credential_cli.py','host_replacement_process.py'):
        (outside/name).write_bytes(snapshot(reference/'tests'/name).data)
    private=outside/'private-witness-cli'
    command=[sys.executable,'-I','-S','-B',str(outside/'native_exchange.py'),'--client-cli','--account-credential-cli']
    for key,path in zip(('native-device','native-session','crash-probe','native-outgoing','required-witness'),paths):
        command+=['--'+key,str(path)]
    command+=['--implementation-root',str(application),'--provider-root',str(provider),'--output',str(private)]
    execution=run(command,'required-witness-cli')
    value=parse_strict_json_bytes(execution.stdout,label='installed required witness CLI')
    verify(value,binaries,application,account_credential=True)
    require(parse_strict_json_bytes(snapshot(private/'RESULT.json').data,label='retained witness result')==value,'witness retained result differs')
    retain(value,private,output/'witness-cli-public',snapshot)
    require(hashes()==binaries,'witness native executable changed')
    return value
