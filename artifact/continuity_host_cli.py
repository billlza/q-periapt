"""Installed independent command boundary and original TCP recovery evidence."""
import sys
import base64
from continuity_independent_python import PACKAGE,require
from continuity_host_native_exchange import LABELS as FILE_LABELS,REFUSALS as FILE_REFUSALS
from continuity_host_network import count,stats,exchanges
from evidence_io import parse_strict_json_bytes,read_regular_snapshot

CLI_LABELS=tuple('cli-'+name for name in ('wrong-directory','other-credential','prepare','prepare-retry',
    'connect','connect-reopen','wrong-session','noncanonical-session','local-profile-witness','next',
    'oversized','rekey-bound','deliver','status','read-first','lost-next','lost','lost-status','resume',
    'rekey','empty-next','empty','read-empty','inbox-missing','inbox-provision','inbox-duplicate',
    'inbox-recover','inbox-wrong-session','native-next','native-deliver','inbox-read',
    'native-lost-next','native-lost','native-lost-status','native-resume','native-rekey',
    'native-empty-next','native-empty','inbox-read-lost','inbox-read-empty','inbox-export-exists'))
LABELS=FILE_LABELS[:9]+CLI_LABELS
CLI_REFUSALS=tuple('cli-'+name for name in ('wrong-directory','other-credential','wrong-session',
    'noncanonical-session','local-profile-witness','oversized','rekey-bound','lost',
    'inbox-missing','inbox-duplicate','inbox-wrong-session','native-lost','inbox-export-exists'))
REFUSALS=FILE_REFUSALS[:8]+CLI_REFUSALS
FRAMES=tuple(('cli-wire-'+str(i),kind) for i,kind in enumerate((1,2,3,3,4,4,3),1))


def verify(value,binaries,application):
    require(type(value) is dict and value.get('completed') is True
            and value.get('kind')=='qperiapt.independent_session_cli','CLI completion')
    count(value.get('schema_version'),1,'CLI receipt version')
    count(value.get('confirmed_epoch'),2,'CLI confirmed epoch')
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
    inbound=value.get('inbound')
    require(type(inbound) is dict and set(inbound)=={'receivers','relay','frames','confirmed_epoch','effects','original_effect_unchanged_on_retry'},'inbound CLI receipt')
    count(inbound['confirmed_epoch'],2,'inbound CLI epoch');count(inbound['effects'],3,'inbound CLI effects')
    require(inbound['original_effect_unchanged_on_retry'] is True,'inbound CLI repeated host effect')
    stats(inbound['relay'],4,4)
    exchanges(inbound['frames'],tuple(('cli-inbound-wire-'+str(i),k) for i,k in enumerate((3,4,4,3),1)))
    receivers=inbound['receivers'];require(type(receivers) is list and len(receivers)==2,'inbound receiver inventory')
    for row,label,exit_code in zip(receivers,('cli-inbound-first','cli-inbound-reopened'),(-9,0)):
        require(type(row) is dict and set(row)==({'label','pid','exit'} if exit_code==-9 else {'label','pid','exit','stats'})
                and row['label']==label and type(row['pid']) is int and row['pid']>0
                and type(row['exit']) is int and row['exit']==exit_code,'inbound receiver lifecycle')
        if exit_code==0:stats(row['stats'],4,4)


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
    for name,body in [('first',b'original native inbound CLI'),('lost',b'original lost inbound CLI'),('empty',b'')]:
        require(copy('cli-inbound-'+name+'.bin').data==body,'inbound effect readback')
        next_label={'first':'cli-native-next','lost':'cli-native-lost-next','empty':'cli-native-empty-next'}[name]
        read_label={'first':'cli-inbox-read','lost':'cli-inbox-read-lost','empty':'cli-inbox-read-empty'}[name]
        native_id=result(next_label).get('message')
        require(type(native_id) is list and len(native_id)==32
                and all(type(b) is int and 0<=b<=255 for b in native_id),'inbound native message identity')
        encoded=base64.urlsafe_b64encode(bytes(native_id)).rstrip(b'=').decode()
        require(result(read_label)=={'session':sid,'message':encoded,'delivery':'Exported','bytes':len(body)},'inbound export correlation')
    for label in ('cli-native-deliver','cli-native-resume','cli-native-empty'):
        require(result(label)=={'consumption':'Confirmed'},'inbound native confirmation')
    require(result('cli-native-lost-status')=={'status':'Committed'}
            and result('cli-native-rekey')=={'epoch':2,'exchanges':2},'inbound unknown/rekey disposition')
    for label,state in [('cli-inbox-provision','Provisioned'),('cli-inbox-recover','Recovered')]:
        require(result(label)=={'session':sid,'journal':prepared['journal'],'inbox':state},'inbox original owner correlation')
    for row in value['inbound']['frames']:
        for side in ('request','response'):
            wire=copy(row['label']+'.'+side)
            require(wire.sha256==row[side+'_sha256'] and 10<=len(wire.data)<=32768
                    and wire.data[:8]==b'QPCXCH01' and wire.data[8]==row['kind']+(128 if side=='response' else 0),'inbound wire receipt')
    for side in ('request','response'):
        require(copy('cli-inbound-lost.'+side).data==snapshot(private/('cli-inbound-wire-1.'+side)).data,'original inbound retry differs')
    for row in value['inbound']['receivers']:
        lines=copy(row['label']+'.stdout').data.splitlines()
        require(not copy(row['label']+'.stderr').data and len(lines)==(1 if row['exit']==-9 else 2),'inbound receiver output')
        ready=parse_strict_json_bytes(lines[0],label='inbound readiness')
        require(ready.get('service')=='Listening' and ready.get('carrier')=='QPCXCH01/TCP'
                and ready.get('session')==sid and ready.get('journal')==prepared['journal'],'inbound original owner differs')
        address=ready.get('address')
        require(type(address) is list and len(address)==2 and address[0]=='127.0.0.1'
                and type(address[1]) is int and 1<=address[1]<=65535,'inbound listen endpoint')
        if row['exit']==0:
            require(parse_strict_json_bytes(lines[1],label='inbound shutdown')=={'service':'Stopped','stats':row['stats']},'inbound terminal receipt')


def qualify(args,reference,application,provider,outside,output,snapshot,run):
    paths=[getattr(args,key).resolve(strict=True) for key in ('native_device','native_session','crash_probe','native_outgoing')]
    def hashes():return {str(p):read_regular_snapshot(p,maximum=128*1024**2,label='CLI native executable').sha256 for p in paths}
    binaries=hashes()
    (outside/'independent_cli_flow.py').write_bytes(snapshot(reference/'tests/independent_cli_flow.py').data)
    (outside/'independent_inbound_cli.py').write_bytes(snapshot(reference/'tests/independent_inbound_cli.py').data)
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
