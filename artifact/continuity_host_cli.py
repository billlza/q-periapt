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
    'native-empty-next','native-empty','inbox-read-lost','inbox-read-empty','inbox-export-exists',
    'opposing-next','opposing-native-next','opposing-python','opposing-native','opposing-status',
    'opposing-native-status','opposing-read-independent','opposing-read-native')) + tuple(
        'cli-phase-'+case+'-'+action for case in ('wrong-journal','cancelled-reply','tampered-ack')
        for action in ('next','status','resume')) + tuple('cli-'+name for name in (
        'rekey-opposing-independent','rekey-opposing-native','rekey-repeat-independent','rekey-repeat-native',
        'rekey-data-independent-next','rekey-data-independent-send','rekey-data-native-read',
        'rekey-data-native-next','rekey-data-native-send','rekey-data-independent-read')) + tuple(
        'cli-control-phase-'+case+'-resume' for case in ('wrong-journal','cancelled-reply','tampered-flight','forged-empty'))
LABELS=FILE_LABELS[:9]+CLI_LABELS
CLI_REFUSALS=tuple('cli-'+name for name in ('wrong-directory','other-credential','wrong-session',
    'noncanonical-session','local-profile-witness','oversized','rekey-bound','lost',
    'inbox-missing','inbox-duplicate','inbox-wrong-session','native-lost','inbox-export-exists'))
REFUSALS=FILE_REFUSALS[:8]+CLI_REFUSALS
FRAMES=tuple(('cli-wire-'+str(i),kind) for i,kind in enumerate((1,2,3,3,4,4,3),1))
CONTROL_PHASES=tuple({'case':case,'target':target} for target,case in
    enumerate(('wrong-journal','cancelled-reply','tampered-flight','forged-empty'),4))
CONTROL_FRAMES=tuple(('cli-rekey-'+side+'-wire-'+str(i),4)
    for side,n in (('independent',2),('native',3)) for i in range(1,n+1))


def verify(value,binaries,application):
    require(type(value) is dict and value.get('completed') is True
            and value.get('kind')=='qperiapt.independent_session_cli','CLI completion')
    count(value.get('schema_version'),1,'CLI receipt version')
    count(value.get('confirmed_epoch'),7,'CLI confirmed epoch')
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
    opposing=value.get('opposing')
    require(type(opposing) is dict and set(opposing)=={'frames','relays','native_service','independent_service','phase_refusals','effects','simultaneous'},'opposing workload inventory')
    require(opposing['simultaneous'] is True and opposing['phase_refusals']==['wrong-journal','cancelled-reply','tampered-ack'],'opposing admission checks')
    count(opposing['effects'],2,'opposing effect count')
    exchanges(opposing['frames'],(('cli-opposing-native-wire',3),('cli-opposing-python-wire',3)))
    require(type(opposing['relays']) is list and len(opposing['relays'])==2,'opposing relay count')
    for row in opposing['relays']:stats(row,1,1)
    for key,label,n in [('native_service','cli-opposing-native-service',7),('independent_service','cli-opposing-independent-service',1)]:
        row=opposing[key]
        require(type(row) is dict and set(row)=={'label','pid','exit','stats'} and row['label']==label
                and type(row['pid']) is int and row['pid']>0,'opposing service identity')
        count(row['exit'],0,'opposing service exit');stats(row['stats'],n,n)
    control=value.get('opposing_rekey')
    require(type(control) is dict and set(control)=={'target','simultaneous','frames','relays','native_service','independent_service','phase_refusals','effects'},'opposing rekey inventory')
    require(control['simultaneous'] is True and control['phase_refusals']==list(CONTROL_PHASES),'opposing rekey boundaries')
    count(control['target'],3,'opposing rekey target');count(control['effects'],2,'opposing rekey effects')
    exchanges(control['frames'],CONTROL_FRAMES)
    require(type(control['relays']) is list and len(control['relays'])==2,'control relay count')
    require(sorted(row['completed_responses'] for row in control['relays'])==[2,3],'control relay flights')
    for row in control['relays']:stats(row,row['completed_responses'],row['completed_responses'])
    for key,label,n in [('native_service','cli-rekey-native-service',17),('independent_service','cli-rekey-independent-service',5)]:
        row=control[key]
        require(type(row) is dict and set(row)=={'label','pid','exit','stats'} and row['label']==label
                and type(row['pid']) is int and row['pid']>0,'control service identity')
        count(row['exit'],0,'control service exit');stats(row['stats'],n,n)


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
    for side,body in [('native',b'independent simultaneous delivery'),('independent',b'native simultaneous delivery')]:
        require(copy('cli-opposing-'+side+'.bin').data==body,'opposing durable effect')
    py=result('cli-opposing-next')['message']
    require(result('cli-opposing-python')=={'session':sid,'message':py,'consumption':'Confirmed'}
            and result('cli-opposing-native')=={'consumption':'Confirmed'}
            and result('cli-opposing-status')=={'session':sid,'message':py,'status':'Acknowledged'}
            and result('cli-opposing-native-status')=={'status':'Acknowledged'},'opposing confirmation/readback')
    for row in value['opposing']['frames']:
        for side in ('request','response'):
            data=copy(row['label']+'.'+side)
            require(data.sha256==row[side+'_sha256'] and 10<=len(data.data)<=32768
                    and data.data[:9]==b'QPCXCH01'+bytes([3 if side=='request' else 131]),'opposing real wire evidence')
    for key in ('native_service','independent_service'):
        row=value['opposing'][key];lines=copy(row['label']+'.stdout').data.splitlines()
        require(len(lines)==2 and not copy(row['label']+'.stderr').data,'opposing terminal service output')
        require(parse_strict_json_bytes(lines[0],label='opposing readiness').get('service')=='Listening'
                and parse_strict_json_bytes(lines[1],label='opposing shutdown')=={'service':'Stopped','stats':row['stats']},'opposing service lifecycle')
    for case in value['opposing']['phase_refusals']:
        label='cli-phase-'+case;message=result(label+'-next')['message']
        require(result(label+'-status')=={'session':sid,'message':message,'status':'Committed'}
                and result(label+'-resume')=={'session':sid,'message':message,'consumption':'Confirmed'},'original phase recovery')
        for side,kind in [('request',3),('response',131)]:
            data=copy(label+'.'+side).data
            require(10<=len(data)<=32768 and data[:9]==b'QPCXCH01'+bytes([kind]),'real phase frame')
    control=value['opposing_rekey']
    require(result('cli-rekey-opposing-independent')=={'session':sid,'epoch':3,'exchanges':2}
            and result('cli-rekey-opposing-native')=={'epoch':3,'exchanges':3}
            and result('cli-rekey-repeat-independent')=={'session':sid,'epoch':3,'exchanges':0}
            and result('cli-rekey-repeat-native')=={'epoch':3,'exchanges':1},'original concurrent control completion')
    message=result('cli-rekey-data-independent-next')['message']
    require(result('cli-rekey-data-independent-send')=={'session':sid,'message':message,'consumption':'Confirmed'}
            and result('cli-rekey-data-native-send')=={'consumption':'Confirmed'},'post-control consumption')
    raw=base64.urlsafe_b64decode(message+'='*(-len(message)%4))
    native_message=bytes(result('cli-rekey-data-native-next')['message'])
    require(len(raw)==len(native_message)==32 and raw[:8]==native_message[:8]==(3).to_bytes(8,'big'),'post-control real message epoch')
    for side in ('native','independent'):
        require(copy('cli-rekey-'+side+'.bin').data==b'after opposing rekey','post-control durable effect')
    for row in control['frames']:
        for side,kind in [('request',4),('response',132)]:
            data=copy(row['label']+'.'+side)
            require(data.sha256==row[side+'_sha256'] and 10<=len(data.data)<=32768
                    and data.data[:9]==b'QPCXCH01'+bytes([kind]),'actual concurrent control frame')
    for key in ('native_service','independent_service'):
        row=control[key];lines=copy(row['label']+'.stdout').data.splitlines()
        require(len(lines)==2 and not copy(row['label']+'.stderr').data,'control terminal service output')
        require(parse_strict_json_bytes(lines[0],label='control readiness').get('service')=='Listening'
                and parse_strict_json_bytes(lines[1],label='control shutdown')=={'service':'Stopped','stats':row['stats']},'control service lifecycle')
    for row in CONTROL_PHASES:
        case,target=row['case'],row['target'];label='cli-control-phase-'+case
        progress=parse_strict_json_bytes(copy(label+'.progress.json').data,label='control phase progress')
        refusal={'cancelled-reply':'Cancelled','tampered-flight':'InvalidSignature'}.get(case,'ValueError')
        require(progress=={'target':target,'before':[target-1]*3+[target],'after':[target-1]*3+[target],
                           'refused':refusal},'control refusal retained original progress')
        expected_exchanges=3 if target%2==0 else 2
        require(result(label+'-resume')=={'session':sid,'epoch':target,'exchanges':expected_exchanges},'original control phase recovery')
        for side,kind in [('request',4),('response',132)]:
            data=copy(label+'.'+side).data
            require(10<=len(data)<=32768 and data[:9]==b'QPCXCH01'+bytes([kind]),'actual control phase reply')


def qualify(args,reference,application,provider,outside,output,snapshot,run):
    paths=[getattr(args,key).resolve(strict=True) for key in ('native_device','native_session','crash_probe','native_outgoing')]
    def hashes():return {str(p):read_regular_snapshot(p,maximum=128*1024**2,label='CLI native executable').sha256 for p in paths}
    binaries=hashes()
    (outside/'independent_cli_flow.py').write_bytes(snapshot(reference/'tests/independent_cli_flow.py').data)
    (outside/'independent_inbound_cli.py').write_bytes(snapshot(reference/'tests/independent_inbound_cli.py').data)
    (outside/'opposing_cli_flow.py').write_bytes(snapshot(reference/'tests/opposing_cli_flow.py').data)
    (outside/'opposing_rekey_cli_flow.py').write_bytes(snapshot(reference/'tests/opposing_rekey_cli_flow.py').data)
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
