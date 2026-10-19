"""Installed independent command boundary and original TCP recovery evidence."""
import sys
from continuity_independent_python import PACKAGE,require
from continuity_host_native_exchange import LABELS as FILE_LABELS,REFUSALS as FILE_REFUSALS
from continuity_host_network import count,stats,exchanges
from evidence_io import parse_strict_json_bytes,read_regular_snapshot

CLI_LABELS=tuple('cli-'+name for name in ('wrong-directory','other-credential','prepare','prepare-retry',
    'connect','connect-reopen','wrong-session','noncanonical-session','local-profile-witness','next',
    'oversized','rekey-bound','deliver','status','read-first','lost-next','lost','lost-status','resume',
    'rekey','empty-next','empty','read-empty'))
LABELS=FILE_LABELS[:9]+CLI_LABELS
CLI_REFUSALS=tuple('cli-'+name for name in ('wrong-directory','other-credential','wrong-session',
    'noncanonical-session','local-profile-witness','oversized','rekey-bound','lost'))
REFUSALS=FILE_REFUSALS[:8]+CLI_REFUSALS
FRAMES=tuple(('cli-wire-'+str(i),kind) for i,kind in enumerate((1,2,3,3,4,4,3),1))


def verify(value,binaries,application):
    require(type(value) is dict and value.get('completed') is True
            and value.get('kind')=='qperiapt.independent_session_cli','CLI completion')
    count(value.get('schema_version'),1,'CLI receipt version')
    count(value.get('confirmed_epoch'),1,'CLI confirmed epoch')
    require(value.get('native_sha256')==binaries and value.get('provider')=='48.0.1'
            and value.get('implementation')==str(application/PACKAGE/'session_cli.py')
            and value.get('clock')=='actual OS time','CLI implementation differs')
    commands=value.get('commands');require(type(commands) is list and len(commands)==len(LABELS),'CLI command inventory')
    for row,label in zip(commands,LABELS):
        require(type(row) is dict and set(row)=={'label','exit'} and row['label']==label,'CLI command identity')
        count(row['exit'],1 if label in REFUSALS else 0,'CLI command result')
    require(value.get('refusals')==list(REFUSALS),'CLI refusal inventory')
    exchanges(value.get('frames'),FRAMES);stats(value.get('relay'),7,7)
    service=value.get('native_service')
    require(type(service) is dict and set(service)=={'label','pid','exit','stats'}
            and service['label']=='cli-native-service' and type(service['pid']) is int and service['pid']>0,
            'CLI native service identity')
    count(service['exit'],0,'CLI native exit');stats(service['stats'],8,8)


def retain(value,private,public,snapshot):
    public.mkdir()
    def copy(name):
        item=snapshot(private/name);(public/name).write_bytes(item.data);return item
    def result(label):return parse_strict_json_bytes(copy(label+'.stdout').data,label=label)
    copy('RESULT.json')
    for label in LABELS:
        out=copy(label+'.stdout');err=copy(label+'.stderr')
        require(bool(err.data)==(label in REFUSALS),'CLI stderr result differs')
        if label in CLI_REFUSALS:require(not out.data,'failed CLI emitted a success result')
    connection=result('cli-connect');sid=connection.get('session')
    require(type(sid) is str and connection=={'session':sid,'peer_confirmation':'Recorded'}
            and result('cli-connect-reopen')==connection,'CLI connection readback')
    prepared=result('cli-prepare')
    require(set(prepared)=={'prepared','journal'} and prepared['prepared'] is True
            and result('cli-prepare-retry')==prepared,'CLI prepare retry readback')
    for prefix in ('','lost-','empty-'):
        msg=result('cli-'+prefix+'next')['message'];require(type(msg) is str,'CLI message identity')
        action={'':'deliver','lost-':'resume','empty-':'empty'}[prefix]
        require(result('cli-'+action)=={'session':sid,'message':msg,'consumption':'Confirmed'},'CLI confirmed operation readback')
        if prefix!='empty-':
            require(result('cli-'+prefix+'status')=={'session':sid,'message':msg,
                'status':'Committed' if prefix else 'Acknowledged'},'CLI durable status readback')
    require(result('cli-rekey')=={'session':sid,'epoch':1,'exchanges':2},'CLI rekey readback')
    require(copy('cli-first-received.bin').data==b'original CLI delivery'
            and copy('cli-empty-received.bin').data==b'','CLI durable application effect')
    for row in value['frames']:
        for side in ('request','response'):
            frame=copy(row['label']+'.'+side)
            require(frame.sha256==row[side+'_sha256'] and 10<=len(frame.data)<=32768
                    and frame.data[:8]==b'QPCXCH01' and frame.data[8]==row['kind']+(128 if side=='response' else 0),
                    'CLI retained wire differs')
    for suffix,side in (('.request','request'),('-upstream.response','response')):
        require(copy('cli-lost'+suffix).data==snapshot(private/('cli-wire-4.'+side)).data,'CLI original lost reply retry differs')
    lines=copy('cli-native-service.stdout').data.splitlines()
    require(len(lines)==2 and not copy('cli-native-service.stderr').data,'CLI service output')
    ready=parse_strict_json_bytes(lines[0],label='CLI listener')
    require(ready.get('service')=='Listening' and ready.get('carrier')=='QPCXCH01/TCP'
            and ready.get('address','').startswith('127.0.0.1:'),'CLI listener receipt')
    require(parse_strict_json_bytes(lines[1],label='CLI stopped service')==
            {'service':'Stopped','stats':value['native_service']['stats']},'CLI service stopped receipt')


def qualify(args,reference,application,provider,outside,output,snapshot,run):
    paths=[getattr(args,key).resolve(strict=True) for key in ('native_device','native_session','crash_probe','native_outgoing')]
    def hashes():return {str(p):read_regular_snapshot(p,maximum=128*1024**2,label='CLI native executable').sha256 for p in paths}
    binaries=hashes()
    (outside/'independent_cli_flow.py').write_bytes(snapshot(reference/'tests/independent_cli_flow.py').data)
    private=outside/'private-independent-cli'
    command=[sys.executable,'-I','-S','-B',str(outside/'native_exchange.py'),'--client-cli']
    for key,path in zip(('native-device','native-session','crash-probe','native-outgoing'),paths):command+=['--'+key,str(path)]
    command+=['--implementation-root',str(application),'--provider-root',str(provider),'--output',str(private)]
    execution=run(command,'independent-session-cli')
    value=parse_strict_json_bytes(execution.stdout,label='installed session CLI')
    verify(value,binaries,application)
    require(parse_strict_json_bytes(snapshot(private/'RESULT.json').data,label='retained CLI result')==value,'CLI retained result differs')
    retain(value,private,output/'independent-cli-public',snapshot)
    require(hashes()==binaries,'CLI native executable changed')
    return value
