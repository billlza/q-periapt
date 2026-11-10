"""Original required-witness authority across installed setup process/EIO faults."""
from pathlib import Path
import math
import os
import re
import signal
import subprocess
import time

import continuity_c_faults as faults
import continuity_c_witness as witness
import continuity_setup_faults as setup
import continuity_setup_io as io
from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk

HELPERS={'hold_original_setup_witness_across_fault','publish_setup_witness_marker'}
SCENARIOS=tuple((carrier,action) for carrier in ('signed-tcp','mutual-tls') for action in ('exit','io'))
CONTROLLER_TIMEOUT=120
SCOPE='same-host installed {language} original required {carrier} witness across {action} installation sync faults; no replacement lineage or local-only fallback; not power loss or independent witness implementation'


def helper_inventory(data):
    names=re.findall(r'^([^\n]+): test$',data.decode(),re.MULTILINE)
    expected=HELPERS|{'setup::'+name for name in setup.setup.TESTS.values()}|{'setup::fixture::'+name for name in setup.NATIVE_TESTS}
    sdk.require(len(names)==len(expected) and set(names)==expected and re.search(r'^7 tests, 0 benchmarks$',data.decode(),re.MULTILINE),'setup witness helper inventory differs')


def helper_trace(data,name):
    sdk.require(name in HELPERS and re.findall(r'^test ([a-z_]+) \.\.\. ok$',data.decode(),re.MULTILINE)==[name]
                and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;',data.decode(),re.MULTILINE),
                'setup witness helper did not complete')


def controller_result(data,carrier):
    row=parse_strict_json_bytes(data,label='setup witness phase report')
    count_names={kind+'_'+stage for kind in ('plain','tls') for stage in ('before_activation','after_activation','before_reconciliation','after_reconciliation','total')}
    sdk.require(isinstance(row,dict) and set(row)==count_names|{'schema_version','completed','carrier'}
                and type(row['schema_version']) is int and row['schema_version']==1 and row['completed'] is True
                and row['carrier']==carrier and carrier in ('signed-tcp','mutual-tls'),'setup witness phase scope differs')
    for key in count_names:sdk.require(type(row[key]) is int and 0<=row[key]<=128,'setup witness admission count differs')
    for kind in ('plain','tls'):
        values=[row[kind+'_'+stage] for stage in ('before_activation','after_activation','before_reconciliation','after_reconciliation','total')]
        sdk.require(values==sorted(values),'setup witness phase order differs')
    sdk.require(row['plain_before_activation']>0 and row['plain_after_activation']<row['plain_before_reconciliation']
                and row['plain_after_reconciliation']<row['plain_total'],'native observation omitted original witness admission')
    if carrier=='signed-tcp':
        sdk.require(all(row[key]==0 for key in count_names if key.startswith('tls_'))
                    and row['plain_after_reconciliation']>row['plain_before_reconciliation'],'signed setup witness activity differs')
    else:
        sdk.require(row['plain_before_activation']==row['plain_after_activation']
                    and row['plain_before_reconciliation']==row['plain_after_reconciliation']
                    and row['tls_before_activation']==0 and row['tls_after_activation']==row['tls_before_reconciliation']
                    and row['tls_after_reconciliation']==row['tls_total']>row['tls_before_reconciliation'],
                    'setup TLS fell back to plaintext or omitted original admission')
    return row


def selected_files(root):
    leaves=['setup-fault-original-id','setup-fault-original-batch',*[f'setup-fault-{stage}.json' for stage in ('original','observed','reconciled')],
        'witness-controller-subject','witness-controller-image','witness-subject','witness-public','witness-id',
        'witness-controller-transcript','witness-controller-result.json','witness-controller-address','witness-controller-carrier']
    return {'responder/'+leaf:sdk.snapshot(root/'responder'/leaf,maximum=faults.MAX_LOG).sha256 for leaf in leaves}


def original_transcript(data,identity,key,subject,digest):
    sdk.require(len(identity)==32 and len(key)==1985 and len(subject)==96 and len(digest)==32
                and data and len(data)<=128*witness.RECORD_BYTES,'setup witness original pin or transcript bound differs')
    result=witness.transcript(data,witness.commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1',identity+key),
        expected_lost_advances=0,expected_lost_queries=0,expected_subjects=1)
    sdk.require(result['logical_advances']==0,'setup witness unexpectedly advanced')
    for offset in range(0,len(data),witness.RECORD_BYTES):
        row=data[offset:offset+witness.RECORD_BYTES]
        sdk.require(row[1+4+40:1+4+136]==subject and row[1+3674+4+201+16:1+3674+4+249]==digest,
                    'setup witness query changed original subject or genesis image')
    return result


class Matrix(setup.Matrix):
    def __init__(self,outside,output,profile,runtime,client,helper,probe,smoke,*,carrier,action,language='C',expected_library,jvm_runtime=None):
        sdk.require(carrier in ('signed-tcp','mutual-tls') and action in ('exit','io') and language in ('C','Swift','Kotlin')
                    and profile in ('debug','release'),'unsupported setup witness selection')
        owned=outside/(language.lower()+'-setup-witness-'+carrier+'-'+action+'-'+profile);owned.mkdir(mode=0o700)
        super().__init__(owned,output,profile,runtime,client,helper,probe,smoke,language=language,expected_library=expected_library,jvm_runtime=jvm_runtime)
        self.carrier,self.action=carrier,action
        self.prefix=language.lower()+'-setup-witness-'+carrier+'-'+action
        self.report_name=language.upper()+'_SETUP_WITNESS_FAULTS_'+carrier.upper().replace('-','_')+'_'+action.upper()+'_'+profile.upper()
        self.scope=SCOPE.format(language=language,carrier=carrier,action=action)

    def wait_marker(self,child,path,deadline):
        while time.monotonic()<deadline:
            sdk.require(child.poll() is None,'setup witness controller exited before '+path.name)
            try:path.lstat()
            except FileNotFoundError:pass
            else:
                sdk.require(sdk.snapshot(path,maximum=1).data==b'1','setup witness marker differs');return
            time.sleep(0.01)
        raise TimeoutError('setup witness phase deadline: '+path.name)

    def marker(self,root,label,stage):
        sdk.require(stage in ('storage','observe','reconciled'),'unknown setup witness phase')
        helper_trace(self.command([self.helper,'--exact','publish_setup_witness_marker','--nocapture'],label+'-signal-'+stage,
            extra=dict(QPC_TEST_PATH=str(root/'responder'),QPC_TEST_SETUP_MARKER=stage)),'publish_setup_witness_marker')

    def activation_case(self,cut,side):
        label=f'activate-{cut}-{side}';root=self.outside/label;path=root/'responder'
        prefix=self.output/(self.prefix+'-'+self.profile+'-'+label+'-controller')
        argv=[str(self.helper),'--exact','hold_original_setup_witness_across_fault','--nocapture']
        env=dict(self.runtime,QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(root),QPC_TEST_SETUP_CARRIER=self.carrier)
        controller=dict(argv=argv,expected_exit=0,completed=False);started=time.monotonic();completed=None
        with Path(str(prefix)+'.stdout').open('xb') as out,Path(str(prefix)+'.stderr').open('xb') as err:
            child=subprocess.Popen(argv,cwd=self.outside,env=env,stdout=out,stderr=err,start_new_session=True)
            try:
                deadline=time.monotonic()+CONTROLLER_TIMEOUT-10
                self.wait_marker(child,path/'witness-controller-ready',deadline)
                created=self.c('setup-create',label+'-create',root);prepared=self.c('setup-storage',label+'-storage',root)
                self.marker(root,label,'storage');self.wait_marker(child,path/'witness-controller-enrolled',deadline)
                original=setup.observation(sdk.snapshot(path/'setup-fault-original.json').data)
                subject=sdk.snapshot(path/'witness-controller-subject').data;digest=sdk.snapshot(path/'witness-controller-image').data
                sdk.require(len(subject)==96 and subject[:32]==bytes.fromhex(original['journal']) and len(digest)==32
                            and sdk.snapshot(path/'witness-subject').data==subject,'setup witness original genesis differs')
                sdk.require(created==b'setup-status:1\n'+original['journal'].encode()+b'\n'
                            and prepared==b'setup-prepared:2\n'+original['journal'].encode()+b'\n'+subject.hex().encode()+b'\n'+digest.hex().encode()+b'\n',
                            'foreign setup did not preserve required genesis')
                address=sdk.snapshot(path/'witness-controller-address').data.decode()
                sdk.require(re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{0,4}',address) and int(address.rsplit(':',1)[1])<=65535
                            and sdk.snapshot(path/'witness-controller-carrier').data==self.carrier.encode(),'setup witness endpoint differs')
                selector='--witness' if self.carrier=='signed-tcp' else '--witness-tls'
                def configured(mode,suffix,tail=(),*,expected=0,extra=None):
                    return self.command([*self.client_command,selector,address,mode,path,*tail],label+'-'+suffix,expected=expected,extra=extra)
                sdk.require(configured('setup-device','creating-denied',[211])==b'setup-refused:211\n','Creating released witnessed authority')
                receipt=self.receipt(label);injection=self.inject(path/'installation.redb',receipt,cut,side)
                if self.action=='io':injection['QPC_TEST_SYNC_ACTION']='io'
                output=configured('setup-io-activate' if self.action=='io' else 'setup-activate','activate',
                    expected=86 if cut and self.action=='exit' else 0,extra=injection)
                response=setup.activation(original,self.language)
                detail={}
                if self.action=='io':
                    detail.update(io.events(sdk.snapshot(receipt).data,cut,side,phased=True))
                    detail['response_code']=io.response(output,original);count=detail['syncs']
                    sdk.require(detail.pop('phases')==([1,3,4] if detail['response_code']==204 else [1,2,3,4]),'witnessed I/O response crossed its phase')
                else:
                    sdk.require(output in (b'',response) if cut else output==response,'witnessed interruption changed its response')
                    count=faults.events(sdk.snapshot(receipt).data,cut,side);detail.update(syncs=count,outcome_observed=output==response)
                self.marker(root,label,'observe');self.wait_marker(child,path/'witness-controller-observed',deadline)
                observed=setup.observation(sdk.snapshot(path/'setup-fault-observed.json').data)
                sdk.require(observed==dict(original,phase=observed['phase']),'setup witness fault changed original state')
                sdk.require(self.c('setup-status',label+'-status',root)==b'setup-status:'+str(observed['phase']).encode()+b'\n'+original['journal'].encode()+b'\n','setup witness phase differs')
                tail=[211] if observed['phase']==1 else []
                sdk.require(configured('setup-device','device',tail)==(b'setup-refused:211\n' if tail else b'setup-device\n'+original['next_account'].encode()+b'\n'),'witnessed device crossed persisted phase')
                sdk.require(self.c('setup-create',label+'-recreate-denied',root,[211])==b'setup-refused:211\n','witness fault authorized replacement')
                sdk.require(self.c('setup-activate',label+'-missing-witness',root,[216])==b'setup-refused:216\n','required witness disappeared during recovery')
                sdk.require(configured('setup-activate','reconcile')==response,'original witness reconciliation differs')
                sdk.require(self.c('setup-storage',label+'-storage-denied',root,[211])==b'setup-refused:211\n','Active recreated children')
                self.marker(root,label,'reconciled');controller['exit']=child.wait(timeout=max(1,deadline-time.monotonic()))
                stdout=sdk.snapshot(Path(str(prefix)+'.stdout'));stderr=sdk.snapshot(Path(str(prefix)+'.stderr'))
                sdk.require(controller['exit']==0 and stderr.data==b'','setup witness controller failed; inspect retained logs')
                helper_trace(stdout.data,'hold_original_setup_witness_across_fault')
                sdk.require(setup.observation(sdk.snapshot(path/'setup-fault-reconciled.json').data)==dict(original,phase=2),'witness recovery changed original identity')
                phases=controller_result(sdk.snapshot(path/'witness-controller-result.json').data,self.carrier)
                key=sdk.snapshot(path/'witness-public').data;identity=sdk.snapshot(path/'witness-id').data
                protocol=original_transcript(sdk.snapshot(path/'witness-controller-transcript').data,identity,key,subject,digest)
                sdk.require(protocol['exchanges']==phases['plain_total'],'setup witness public transcript differs')
                public=selected_files(root)
                if self.carrier=='mutual-tls':
                    public.update({'responder/'+name:sdk.snapshot(path/name).sha256 for name in ('witness-tls-cert','witness-tls-peer','witness-tls-name')})
                controller.update(completed=True,stdout_sha256=stdout.sha256,stderr_sha256=stderr.sha256)
                completed=dict(completed=True,cut=cut,side=side,root=str(root),journal=original['journal'],next_account=original['next_account'],
                    observed_phase=observed['phase'],controller=controller,witness_protocol=protocol,witness_phases=phases,public_readbacks=public,**detail)
            finally:
                if child.poll() is None:
                    try:os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:sdk.require(child.poll() is not None,'owned witness controller disappeared before exit')
                    child.wait();controller['terminated_for_failed_fixture']=True
                controller['elapsed_seconds']=round(time.monotonic()-started,3)
                sdk.write_json(Path(str(prefix)+'.json'),controller)
        sdk.require(completed is not None,'setup witness case produced no completed observation')
        self.results.append(completed);return count

    def execute(self):
        result=dict(schema_version=1,completed=False,language=self.language,scope=self.scope,profile=self.profile,carrier=self.carrier,action=self.action,
            outside=str(self.outside),binaries=self.binaries,release_claim_eligible=False);started=time.monotonic()
        try:
            helper_inventory(self.command([self.helper,'--list'],'helper-inventory'));self.probe_check()
            if self.action=='io':io.Matrix.io_probe_check(self)
            count=self.activation_case(0,'before')
            for cut in range(1,count+1):
                for side in ('before','after'):self.activation_case(cut,side)
            sdk.require(self.identities=={path:sdk.snapshot(Path(path),maximum=256*1024**2).sha256 for path in self.identities},'setup witness binaries changed')
            result.update(completed=True,coverage=(io.coverage if self.action=='io' else setup.coverage)(self.results))
        finally:
            result.update(cases=self.results,commands=self.command_records,elapsed_seconds=round(time.monotonic()-started,3));sdk.write_json(self.output/(self.report_name+'.json'),result)
        return result

    def inject_io(self,target,receipt,cut,side):
        return dict(self.inject(target,receipt,cut,side),QPC_TEST_SYNC_ACTION='io')


def verify_public(result,directory,*,language,carrier,action):
    fields={'schema_version','completed','language','scope','profile','carrier','action','outside','binaries','release_claim_eligible','cases','commands','elapsed_seconds','coverage'}
    sdk.require(language in ('C','Swift','Kotlin') and carrier in ('signed-tcp','mutual-tls') and action in ('exit','io')
                and isinstance(result,dict) and set(result) in (fields,fields|{'public_files'})
                and type(result['schema_version']) is int and result['schema_version']==1 and result['completed'] is True
                and result['language']==language and result['carrier']==carrier and result['action']==action
                and result['scope']==SCOPE.format(language=language,carrier=carrier,action=action)
                and result['release_claim_eligible'] is False and result['profile'] in ('debug','release'),'setup witness report scope differs')
    def elapsed(value):
        sdk.require(type(value) in (int,float) and math.isfinite(value) and value>=0,'setup witness elapsed time differs')
    elapsed(result['elapsed_seconds'])
    summary=(io.coverage if action=='io' else setup.coverage)(result['cases'])
    sdk.require(summary==result['coverage'],'setup witness coverage differs')
    roles={'client','native_helper','installed_library','sync_probe','probe_smoke'}|(set(faults.JVM_ROLES) if language=='Kotlin' else set())
    sdk.require(isinstance(result['binaries'],dict) and set(result['binaries'])==roles,'setup witness binary inventory differs')
    for info in result['binaries'].values():
        sdk.require(isinstance(info,dict) and set(info)=={'path','sha256','bytes'} and isinstance(info['path'],str) and Path(info['path']).is_absolute()
                    and type(info['bytes']) is int and 0<info['bytes']<=256*1024**2 and isinstance(info['sha256'],str)
                    and re.fullmatch('[0-9a-f]{64}',info['sha256']),'setup witness binary identity differs')
    sdk.require(isinstance(result['outside'],str) and Path(result['outside']).is_absolute(),'setup witness original root differs')
    outside=Path(result['outside']);helper=result['binaries']['native_helper']['path'];client=[result['binaries']['client']['path']]
    if language=='Kotlin':client=faults.jvm_command({role:Path(result['binaries'][role]['path']) for role in faults.JVM_ROLES},Path(result['binaries']['installed_library']['path']))
    sdk.require(isinstance(result['commands'],dict) and len(result['commands'])==(11 if action=='io' else 6)+13*len(result['cases']),
                'setup witness command count differs')
    public={};logs={};commands=set()
    def read(name,*,log=False):
        item=sdk.snapshot(directory/name,maximum=faults.MAX_LOG);(logs if log else public)[name]=item.sha256;return item.data
    def command(label,argv,expected=0,*,controller=None):
        sdk.require(label not in commands,'setup witness command repeated');commands.add(label)
        row=result['commands'].get(label) if controller is None else controller
        sdk.require(isinstance(row,dict) and set(row)=={'argv','expected_exit','completed','exit','stdout_sha256','stderr_sha256','elapsed_seconds'}
                    and row['argv']==[str(value) for value in argv] and type(row['expected_exit']) is int and row['expected_exit']==expected
                    and type(row['exit']) is int and row['exit']==expected and row['completed'] is True,'setup witness command selection or outcome differs')
        elapsed(row['elapsed_seconds'])
        if controller is not None:sdk.require(row['elapsed_seconds']<=CONTROLLER_TIMEOUT,'setup witness controller exceeded its deadline')
        sdk.require(parse_strict_json_bytes(read('commands/'+label+'.json',log=True),label='setup witness command')==row,'setup witness command record differs')
        stdout=read('commands/'+label+'.stdout',log=True)
        sdk.require(read('commands/'+label+'.stderr',log=True)==b'' and logs['commands/'+label+'.stdout']==row['stdout_sha256']
                    and logs['commands/'+label+'.stderr']==row['stderr_sha256'],'setup witness command bytes differ');return stdout
    helper_inventory(command('helper-inventory',[helper,'--list']))
    for probe_action in (('exit','io') if action=='io' else ('exit',)):
        for cut,side in ((0,'before'),(1,'before'),(1,'after'),(2,'before'),(2,'after')):
            label=('io-' if probe_action=='io' else '')+f'probe-{cut}-{side}';path=outside/label
            status=0 if not cut else (4+cut if probe_action=='io' else 86)
            sdk.require(command(label,[result['binaries']['probe_smoke']['path'],path/'target',path/'control'],status)==b'','setup witness probe output differs')
            data=read('commands/'+label+'.events',log=True)
            count=io.events(data,cut,side,phased=False)['syncs'] if probe_action=='io' else faults.events(data,cut,side)
            sdk.require(count==(cut or 2) and read(label+'/control')==b'control' and read(label+'/target')==(b'one' if cut==1 else b'onetwo'),
                        'setup witness probe calibration or unrelated inode differs')
    for row in result['cases']:
        extra={'sync_phases','injected_phase','response_code'} if action=='io' else {'outcome_observed'}
        sdk.require(set(row)=={'completed','cut','side','root','journal','next_account','observed_phase','controller','witness_protocol','witness_phases','public_readbacks','syncs'}|extra,
                    'setup witness case shape differs')
        cut,side=row['cut'],row['side'];label=f'activate-{cut}-{side}';path=outside/label/'responder'
        sdk.require(row['root']==str(outside/label),'setup witness original case root differs')
        helper_trace(command(label+'-controller',[helper,'--exact','hold_original_setup_witness_across_fault','--nocapture'],controller=row['controller']),
                     'hold_original_setup_witness_across_fault')
        observations={stage:setup.observation(read(label+'/responder/setup-fault-'+stage+'.json')) for stage in ('original','observed','reconciled')}
        original=observations['original'];sdk.require(original['phase']==1 and original['journal']==row['journal'] and original['next_account']==row['next_account']
            and observations['observed']==dict(original,phase=row['observed_phase']) and observations['reconciled']==dict(original,phase=2),'setup witness original state differs')
        sdk.require(read(label+'/responder/setup-fault-original-id')==bytes.fromhex(row['journal'])
                    and read(label+'/responder/setup-fault-original-batch')==bytes.fromhex(row['next_account']),'setup witness original raw identities differ')
        subject=read(label+'/responder/witness-controller-subject');digest=read(label+'/responder/witness-controller-image')
        sdk.require(len(subject)==96 and subject[:32]==bytes.fromhex(row['journal']) and read(label+'/responder/witness-subject')==subject,
                    'setup witness original subject differs')
        identity=read(label+'/responder/witness-id');key=read(label+'/responder/witness-public')
        protocol=original_transcript(read(label+'/responder/witness-controller-transcript'),identity,key,subject,digest)
        phases=controller_result(read(label+'/responder/witness-controller-result.json'),carrier)
        sdk.require(protocol==row['witness_protocol'] and phases==row['witness_phases'] and protocol['exchanges']==phases['plain_total'],
                    'setup witness original public transcript differs')
        address=read(label+'/responder/witness-controller-address').decode()
        sdk.require(re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{0,4}',address) and int(address.rsplit(':',1)[1])<=65535
                    and read(label+'/responder/witness-controller-carrier')==carrier.encode(),'setup witness carrier endpoint differs')
        if carrier=='mutual-tls':
            for leaf in ('witness-tls-cert','witness-tls-peer'):
                certificate=read(label+'/responder/'+leaf)
                sdk.require(256<=len(certificate)<=16384 and certificate[0]==0x30,'setup witness TLS certificate differs')
            sdk.require(read(label+'/responder/witness-tls-name')==b'localhost','setup witness TLS name differs')
        sdk.require({name.removeprefix(label+'/'):sha for name,sha in public.items() if name.startswith(label+'/')}==row['public_readbacks'],
                    'setup witness public inventory differs')
        journal,batch=row['journal'].encode(),row['next_account'].encode();selector='--witness' if carrier=='signed-tcp' else '--witness-tls'
        activation=(b'setup-io:'+str(row['response_code']).encode()+b'\n'+(batch+b'\n' if row['response_code']==0 else b'')) if action=='io' else (setup.activation(original,language) if row['outcome_observed'] else b'')
        outcomes={
            'create':(False,'setup-create',[],b'setup-status:1\n'+journal+b'\n'),
            'storage':(False,'setup-storage',[],b'setup-prepared:2\n'+journal+b'\n'+subject.hex().encode()+b'\n'+digest.hex().encode()+b'\n'),
            'creating-denied':(True,'setup-device',[211],b'setup-refused:211\n'),
            'activate':(True,'setup-io-activate' if action=='io' else 'setup-activate',[],activation),
            'status':(False,'setup-status',[],b'setup-status:'+str(row['observed_phase']).encode()+b'\n'+journal+b'\n'),
            'device':(True,'setup-device',[211] if row['observed_phase']==1 else [],b'setup-refused:211\n' if row['observed_phase']==1 else b'setup-device\n'+batch+b'\n'),
            'recreate-denied':(False,'setup-create',[211],b'setup-refused:211\n'),
            'missing-witness':(False,'setup-activate',[216],b'setup-refused:216\n'),
            'reconcile':(True,'setup-activate',[],setup.activation(original,language)),
            'storage-denied':(False,'setup-storage',[211],b'setup-refused:211\n')}
        for stage,(configured,mode,tail,expected) in outcomes.items():
            argv=[*client,*([selector,address] if configured else []),mode,path,*tail]
            sdk.require(command(label+'-'+stage,argv,86 if stage=='activate' and cut and action=='exit' else 0)==expected,
                        'setup witness response or authority differs')
        for stage in ('storage','observe','reconciled'):
            helper_trace(command(label+'-signal-'+stage,[helper,'--exact','publish_setup_witness_marker','--nocapture']),'publish_setup_witness_marker')
        events=read('commands/'+label+'.events',log=True)
        if action=='io':
            checked=io.events(events,cut,side,phased=True)
            sdk.require(all(checked[key]==row[key] for key in ('syncs','sync_phases','injected_phase'))
                        and checked['phases']==([1,3,4] if row['response_code']==204 else [1,2,3,4]),'setup witness I/O event/response differs')
        else:sdk.require(faults.events(events,cut,side)==row['syncs'],'setup witness interruption event differs')
    sdk.require(commands==set(result['commands'])|{f"activate-{row['cut']}-{row['side']}-controller" for row in result['cases']},'setup witness command inventory differs')
    if 'public_files' in result:sdk.require(result['public_files']==public|logs,'setup witness exported file map differs')
    return dict(language=language,coverage=summary,public_readbacks=public,command_logs=logs,release_claim_eligible=False)


def qualify(outside,output,profile,runtime,client,helper,probe,smoke,*,carrier,action,language='C',expected_library,jvm_runtime=None):
    matrix=Matrix(outside,output,profile,runtime,client,helper,probe,smoke,carrier=carrier,action=action,language=language,
                  expected_library=expected_library,jvm_runtime=jvm_runtime)
    result=matrix.execute();commands=matrix.outside/'commands';commands.mkdir(mode=0o700)
    labels=list(result['commands'])+[f"activate-{row['cut']}-{row['side']}-controller" for row in result['cases']]
    for label in labels:
        for suffix in ('.stdout','.stderr','.json'):sdk.copy(output/f'{matrix.prefix}-{profile}-{label}{suffix}',commands/(label+suffix))
    for path in output.glob(f'{matrix.prefix}-{profile}-*.events'):sdk.copy(path,commands/path.name.removeprefix(f'{matrix.prefix}-{profile}-'))
    checked=verify_public(result,matrix.outside,language=language,carrier=carrier,action=action)
    exported=output/(language.lower()+'-setup-witness-fault-public')/carrier/action/profile
    files=witness.export_selected(checked,matrix.outside,exported,result['scope'],
        replay=lambda path:verify_public(result,path,language=language,carrier=carrier,action=action))
    sdk.write_json(output/(matrix.report_name+'_PUBLIC.json'),dict(completed=True,public_files=files,coverage=checked['coverage'],release_claim_eligible=False))
    return dict(result,public_files=files)


def qualify_all(outside,output,profile,runtime,client,helper,probe,smoke,*,language='C',expected_library,jvm_runtime=None):
    return {carrier+'-'+action:qualify(outside,output,profile,runtime,client,helper,probe,smoke,
        language=language,expected_library=expected_library,jvm_runtime=jvm_runtime,carrier=carrier,action=action)
        for carrier,action in SCENARIOS}


def installed_helper(results):
    sdk.require(isinstance(results,dict) and set(results)=={carrier+'-'+action for carrier,action in SCENARIOS},
                'native setup witness scenario inventory differs')
    identity=results['signed-tcp-exit']['binaries']['native_helper']
    sdk.require(all(row['completed'] is True and row['binaries']['native_helper']==identity for row in results.values())
                and sdk.snapshot(Path(identity['path']),maximum=256*1024**2).sha256==identity['sha256'],
                'native setup witness helper changed before binding execution')
    return Path(identity['path'])
