"""Returned installation-sync errors at actual installed consumer phase boundaries."""
from pathlib import Path
import math
import re
import time

import continuity_c_faults as faults
import continuity_setup_faults as setup
from continuity_c_setup import identifier
from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk

SCOPE = ("same-host installed C local installation sync EIO returns; opening, activation commit and close phases; "
         "consumed error owners and original Creating/Active reconciliation; not physical power loss")


def events(data: bytes, cut: int, side: str, *, phased: bool) -> dict:
    sdk.require(type(cut) is int and 0 <= cut <= faults.MAX_SYNC and side in ('before','after'), 'invalid I/O selection')
    lines=data.decode().splitlines()
    sdk.require(lines and lines.pop(0)==f'armed-io {cut} {int(side=="after")}', 'I/O probe was not armed exactly')
    current=0;phases=[];sync_phases=[];pending=None;injected=0;injected_phase=0;done=False
    for line in lines:
        match=re.fullmatch(r'([a-z-]+) ([0-9]+) (-?[0-9]+)',line)
        sdk.require(match is not None and not done,'I/O event shape or terminal order differs')
        kind,number,value=match[1],int(match[2]),int(match[3])
        if kind=='phase':
            sdk.require(phased and pending is None and value==0 and number in (1,2,3,4)
                        and number>current and (current!=0 or number==1), 'I/O phase order differs')
            phases.append(number);current=number
        elif kind=='before':
            sdk.require(pending is None and number==len(sync_phases)+1 and number<=faults.MAX_SYNC and value==0
                        and (not phased or current in (1,2,3)), 'I/O before event differs')
            sync_phases.append(current);pending=number
        elif kind=='after':
            sdk.require(pending==number and value==0,'real sync failed or after event differs')
            pending=None
        elif kind in ('injected-before','injected-after'):
            sdk.require(number==cut and cut>0 and kind=='injected-'+side and value==5 and injected==0
                        and (pending==number if side=='before' else pending is None)
                        and number==len(sync_phases), 'I/O injection identity or order differs')
            sdk.require(lines[lines.index(line)-1]==f'{side} {number} 0', 'I/O injection is not adjacent to its selected side')
            pending=None;injected=1;injected_phase=current
        elif kind=='done':
            sdk.require(pending is None and number==len(sync_phases) and value==0
                        and (not phased or current==4),'I/O completion differs')
            done=True
        else:raise ValueError('unknown I/O probe event')
    sdk.require(done and sync_phases and injected==int(cut>0) and (not phased or phases in ([1,2,3,4],[1,3,4])),
                'I/O trace incomplete or selected error missing')
    return dict(syncs=len(sync_phases),sync_phases=sync_phases,injected_phase=injected_phase,phases=phases)


def response(data: bytes, original: dict) -> int:
    values={b'setup-io:0\n'+original['next_account'].encode()+b'\n':0,b'setup-io:204\n':204,b'setup-io:207\n':207}
    sdk.require(data in values,'I/O consumer response differs');return values[data]


def coverage(cases: list[dict]) -> dict:
    sdk.require(isinstance(cases,list) and 1<=len(cases)<=1+2*faults.MAX_SYNC and all(isinstance(row,dict) for row in cases),'I/O cases missing or oversized')
    baseline=[row for row in cases if type(row.get('cut')) is int and row['cut']==0]
    sdk.require(len(baseline)==1,'I/O calibration missing or repeated')
    plan=baseline[0].get('sync_phases')
    sdk.require(isinstance(plan,list) and 1<=len(plan)<=faults.MAX_SYNC
                and all(type(phase) is int and phase in (1,2,3) for phase in plan)
                and plan==sorted(plan) and set(plan)=={1,2,3},'I/O phase calibration differs')
    inventory=set()
    for row in cases:
        cut,side=row.get('cut'),row.get('side')
        sdk.require(type(cut) is int and 0<=cut<=len(plan) and side in ('before','after')
                    and (cut,side) not in inventory,'I/O cut selection differs');inventory.add((cut,side))
        phase=plan[cut-1] if cut else 0
        sdk.require(row['completed'] is True and type(row['injected_phase']) is int and row['injected_phase']==phase
                    and type(row['response_code']) is int and row['response_code']=={0:0,1:204,2:207,3:0}[phase]
                    and type(row['observed_phase']) is int and row['observed_phase'] in (1,2)
                    and (phase!=1 or row['observed_phase']==1)
                    and (phase not in (0,3) or row['observed_phase']==2), 'I/O error crossed its phase or authority boundary')
        seen=row['sync_phases']
        sdk.require(isinstance(seen,list) and all(type(value) is int and value in (1,2,3) for value in seen)
                    and type(row['syncs']) is int and row['syncs']==len(seen)
                    and (seen==plan if cut==0 else len(seen)>=cut and seen[:cut]==plan[:cut]),'I/O observed sync prefix differs')
        for key in ('journal','next_account'):identifier(row[key].encode())
    sdk.require(inventory=={(0,'before')}|{(n,side) for n in range(1,len(plan)+1) for side in ('before','after')},
                'I/O before/after inventory incomplete')
    sdk.require({row['observed_phase'] for row in cases if row['response_code']==207}=={1,2},
                'uncertain activation errors omitted a durable phase')
    return dict(syncs=len(plan),cases=len(cases),opening_errors=sum(row['response_code']==204 for row in cases),
                uncertain_creating=sum(row['response_code']==207 and row['observed_phase']==1 for row in cases),
                uncertain_active=sum(row['response_code']==207 and row['observed_phase']==2 for row in cases),
                close_errors_after_commit=sum(row['injected_phase']==3 for row in cases))


class Matrix(setup.Matrix):
    def __init__(self,outside,output,profile,runtime,client,helper,probe,smoke,*,language='C',expected_library,jvm_runtime=None):
        sdk.require(language in ('C','Swift','Kotlin') and profile in ('debug','release'),'unsupported I/O matrix profile')
        owned=outside/(language.lower()+'-setup-io-'+profile);owned.mkdir(mode=0o700)
        super().__init__(owned,output,profile,runtime,client,helper,probe,smoke,language=language,
                         expected_library=expected_library,jvm_runtime=jvm_runtime)
        self.prefix=language.lower()+'-setup-io';self.scope=SCOPE.replace('installed C','installed '+language)

    def inject_io(self,target,receipt,cut,side):
        return dict(self.inject(target,receipt,cut,side),QPC_TEST_SYNC_ACTION='io')

    def io_probe_check(self):
        for cut,side in ((0,'before'),(1,'before'),(1,'after'),(2,'before'),(2,'after')):
            label=f'io-probe-{cut}-{side}';root=self.outside/label;root.mkdir(mode=0o700)
            for leaf in ('target','control'):
                path=root/leaf
                with path.open('xb'):pass
                path.chmod(0o600)
            receipt=self.receipt(label)
            stdout=self.command([self.smoke,root/'target',root/'control'],label,expected=0 if not cut else 4+cut,
                extra=self.inject_io(root/'target',receipt,cut,side))
            checked=events(sdk.snapshot(receipt).data,cut,side,phased=False)
            sdk.require(stdout==b'' and checked['syncs']==(cut or 2) and sdk.snapshot(root/'control').data==b'control'
                        and sdk.snapshot(root/'target').data==(b'one' if cut==1 else b'onetwo'),'EIO smoke changed its operation or unrelated inode')

    def activation_case(self,cut,side):
        label=f'activate-{cut}-{side}';root,original=self.prepare(label);receipt=self.receipt(label)
        stdout=self.c('setup-io-activate',label+'-activate',root,
            extra=self.inject_io(root/'responder/installation.redb',receipt,cut,side))
        observed_events=events(sdk.snapshot(receipt).data,cut,side,phased=True)
        code=response(stdout,original);observed=self.observe(root,label,'observed')
        sdk.require(observed==dict(original,phase=observed['phase']),'returned I/O error replaced original state')
        expected_phases=[1,3,4] if code==204 else [1,2,3,4]
        sdk.require(observed_events['phases']==expected_phases,'I/O error returned from another phase')
        sdk.require(self.c('setup-status',label+'-status',root)==b'setup-status:'+str(observed['phase']).encode()+b'\n'+original['journal'].encode()+b'\n',
                    'foreign/native I/O recovery phase differs')
        tail=[211] if observed['phase']==1 else [];device=b'setup-device\n'+original['next_account'].encode()+b'\n'
        sdk.require(self.c('setup-device',label+'-device',root,tail)==(b'setup-refused:211\n' if tail else device),'I/O recovery crossed operational authority')
        sdk.require(self.c('setup-create',label+'-recreate-denied',root,[211])==b'setup-refused:211\n','I/O error authorized replacement provisioning')
        sdk.require(self.c('setup-activate',label+'-reconcile',root)==setup.activation(original,self.language),'I/O recovery did not reconcile original setup')
        sdk.require(self.c('setup-storage',label+'-active-storage-denied',root,[211])==b'setup-refused:211\n','I/O recovery recreated Active children')
        sdk.require(self.c('setup-device',label+'-active-device',root)==device,'I/O recovery advanced original account position')
        sdk.require(self.observe(root,label,'reconciled')==dict(original,phase=2),'I/O recovery changed original lineage or children')
        leaves=['setup-fault-original-id','setup-fault-original-batch',*[f'setup-fault-{stage}.json' for stage in ('original','observed','reconciled')]]
        public={'responder/'+leaf:sdk.snapshot(root/'responder'/leaf).sha256 for leaf in leaves}
        self.results.append(dict(completed=True,cut=cut,side=side,syncs=observed_events['syncs'],sync_phases=observed_events['sync_phases'],
            injected_phase=observed_events['injected_phase'],response_code=code,observed_phase=observed['phase'],journal=original['journal'],
            next_account=original['next_account'],root=str(root),public_readbacks=public))
        return observed_events['syncs']

    def execute(self):
        result=dict(schema_version=1,completed=False,language=self.language,scope=self.scope,profile=self.profile,
            outside=str(self.outside),binaries=self.binaries,release_claim_eligible=False);started=time.monotonic()
        try:
            setup.helper_inventory(self.command([self.helper,'--list'],'helper-inventory'))
            self.probe_check();self.io_probe_check();count=self.activation_case(0,'before')
            for cut in range(1,count+1):
                for side in ('before','after'):self.activation_case(cut,side)
            sdk.require(self.identities=={path:sdk.snapshot(Path(path),maximum=256*1024**2).sha256 for path in self.identities},'I/O binaries changed')
            result.update(completed=True,coverage=coverage(self.results))
        finally:
            result.update(cases=self.results,commands=self.command_records,elapsed_seconds=round(time.monotonic()-started,3))
            sdk.write_json(self.output/f'{self.language.upper()}_SETUP_IO_{self.profile.upper()}.json',result)
        return result


def verify_public(result:dict,directory:Path,*,language:str)->dict:
    fields={'schema_version','completed','language','scope','profile','outside','binaries','release_claim_eligible','cases','commands','elapsed_seconds','coverage'}
    sdk.require(language in ('C','Swift','Kotlin') and isinstance(result,dict) and set(result) in (fields,fields|{'public_files'})
                and type(result['schema_version']) is int and result['schema_version']==1 and result['completed'] is True
                and result['language']==language and result['scope']==SCOPE.replace('installed C','installed '+language)
                and result['release_claim_eligible'] is False and result['profile'] in ('debug','release'),'I/O report scope differs')
    elapsed=result['elapsed_seconds'];sdk.require(type(elapsed) in (int,float) and math.isfinite(elapsed) and elapsed>=0,'I/O elapsed time differs')
    summary=coverage(result['cases']);sdk.require(summary==result['coverage'],'I/O coverage differs')
    roles={'client','native_helper','installed_library','sync_probe','probe_smoke'}|(set(faults.JVM_ROLES) if language=='Kotlin' else set())
    sdk.require(isinstance(result['binaries'],dict) and set(result['binaries'])==roles,'I/O binary inventory differs')
    for info in result['binaries'].values():
        sdk.require(isinstance(info,dict) and set(info)=={'path','sha256','bytes'} and isinstance(info['path'],str) and Path(info['path']).is_absolute()
                    and type(info['bytes']) is int and 0<info['bytes']<=256*1024**2 and isinstance(info['sha256'],str)
                    and re.fullmatch('[0-9a-f]{64}',info['sha256']),'I/O binary identity differs')
    sdk.require(isinstance(result['outside'],str) and Path(result['outside']).is_absolute(),'I/O original root differs')
    outside=Path(result['outside']);helper=result['binaries']['native_helper']['path'];client=[result['binaries']['client']['path']]
    if language=='Kotlin':client=faults.jvm_command({role:Path(result['binaries'][role]['path']) for role in faults.JVM_ROLES},Path(result['binaries']['installed_library']['path']))
    sdk.require(isinstance(result['commands'],dict) and len(result['commands'])==11+14*len(result['cases']),'I/O command count differs')
    public={};logs={};commands=set()
    def read(name,*,log=False):
        item=sdk.snapshot(directory/name,maximum=faults.MAX_LOG);(logs if log else public)[name]=item.sha256;return item.data
    def command(label,argv,expected=0):
        sdk.require(label not in commands,'I/O command repeated');commands.add(label);row=result['commands'].get(label)
        sdk.require(isinstance(row,dict) and set(row)=={'argv','expected_exit','completed','exit','stdout_sha256','stderr_sha256','elapsed_seconds'}
                    and row['argv']==[str(value) for value in argv] and type(row['expected_exit']) is int and row['expected_exit']==expected
                    and type(row['exit']) is int and row['exit']==expected and row['completed'] is True,'I/O command selection or outcome differs')
        value=row['elapsed_seconds'];sdk.require(type(value) in (int,float) and math.isfinite(value) and value>=0,'I/O command elapsed time differs')
        sdk.require(parse_strict_json_bytes(read('commands/'+label+'.json',log=True),label='I/O command')==row,'I/O command record differs')
        stdout=read('commands/'+label+'.stdout',log=True)
        sdk.require(read('commands/'+label+'.stderr',log=True)==b'' and logs['commands/'+label+'.stdout']==row['stdout_sha256']
                    and logs['commands/'+label+'.stderr']==row['stderr_sha256'],'I/O command bytes differ');return stdout
    setup.helper_inventory(command('helper-inventory',[helper,'--list']))
    for action in ('exit','io'):
        for cut,side in ((0,'before'),(1,'before'),(1,'after'),(2,'before'),(2,'after')):
            label=('io-' if action=='io' else '')+f'probe-{cut}-{side}';path=outside/label
            status=0 if not cut else (4+cut if action=='io' else 86)
            sdk.require(command(label,[result['binaries']['probe_smoke']['path'],path/'target',path/'control'],status)==b'','I/O smoke response differs')
            raw=read('commands/'+label+'.events',log=True)
            count=events(raw,cut,side,phased=False)['syncs'] if action=='io' else faults.events(raw,cut,side)
            sdk.require(count==(cut or 2) and read(label+'/control')==b'control' and read(label+'/target')==(b'one' if cut==1 else b'onetwo'),
                        'I/O probe calibration or unrelated inode differs')
    for row in result['cases']:
        sdk.require(set(row)=={'completed','cut','side','syncs','sync_phases','injected_phase','response_code','observed_phase','journal','next_account','root','public_readbacks'},'I/O case shape differs')
        cut,side=row['cut'],row['side'];label=f'activate-{cut}-{side}';path=outside/label/'responder'
        sdk.require(row['root']==str(outside/label),'I/O original case root differs')
        setup.native_trace(command(label+'-prepare',[helper,'--exact','prepare_setup_fault_case','--nocapture']),'prepare_setup_fault_case')
        observations={stage:setup.observation(read(label+'/responder/setup-fault-'+stage+'.json')) for stage in ('original','observed','reconciled')}
        original=observations['original'];sdk.require(original['phase']==1 and original['journal']==row['journal'] and original['next_account']==row['next_account']
            and observations['observed']==dict(original,phase=row['observed_phase']) and observations['reconciled']==dict(original,phase=2),'I/O original observation differs')
        sdk.require(read(label+'/responder/setup-fault-original-id')==bytes.fromhex(row['journal'])
                    and read(label+'/responder/setup-fault-original-batch')==bytes.fromhex(row['next_account']),'I/O original raw identities differ')
        sdk.require({name.removeprefix(label+'/'):sha for name,sha in public.items() if name.startswith(label+'/')}==row['public_readbacks'],'I/O public inventory differs')
        journal,batch=row['journal'].encode(),row['next_account'].encode()
        outcomes={'create':('setup-create',[],b'setup-status:1\n'+journal+b'\n'),
            'storage':('setup-storage',[],b'setup-prepared:1\n'+journal+b'\n'+b'0'*192+b'\n'+b'0'*64+b'\n'),
            'creating-denied':('setup-device',[211],b'setup-refused:211\n'),
            'activate':('setup-io-activate',[],b'setup-io:'+str(row['response_code']).encode()+b'\n'+(batch+b'\n' if row['response_code']==0 else b'')),
            'status':('setup-status',[],b'setup-status:'+str(row['observed_phase']).encode()+b'\n'+journal+b'\n'),
            'device':('setup-device',[211] if row['observed_phase']==1 else [],b'setup-refused:211\n' if row['observed_phase']==1 else b'setup-device\n'+batch+b'\n'),
            'recreate-denied':('setup-create',[211],b'setup-refused:211\n'),
            'reconcile':('setup-activate',[],setup.activation(original,language)),
            'active-storage-denied':('setup-storage',[211],b'setup-refused:211\n'),
            'active-device':('setup-device',[],b'setup-device\n'+batch+b'\n')}
        for stage,(mode,tail,expected) in outcomes.items():sdk.require(command(label+'-'+stage,[*client,mode,path,*tail])==expected,'I/O response or authority differs')
        for stage in observations:setup.native_trace(command(label+'-'+stage,[helper,'--exact','inspect_setup_fault_case','--nocapture']),'inspect_setup_fault_case')
        checked=events(read('commands/'+label+'.events',log=True),cut,side,phased=True)
        sdk.require(all(checked[key]==row[key] for key in ('syncs','sync_phases','injected_phase'))
                    and checked['phases']==([1,3,4] if row['response_code']==204 else [1,2,3,4]),'I/O event/response phase binding differs')
    sdk.require(commands==set(result['commands']),'I/O command inventory differs')
    if 'public_files' in result:sdk.require(result['public_files']==public|logs,'I/O exported file map differs')
    return dict(language=language,coverage=summary,public_readbacks=public,command_logs=logs,release_claim_eligible=False)


def qualify(outside,output,profile,runtime,client,helper,probe,smoke,*,language='C',expected_library,jvm_runtime=None):
    matrix=Matrix(outside,output,profile,runtime,client,helper,probe,smoke,language=language,expected_library=expected_library,jvm_runtime=jvm_runtime)
    result=matrix.execute();commands=matrix.outside/'commands';commands.mkdir(mode=0o700)
    for label in result['commands']:
        for suffix in ('.stdout','.stderr','.json'):sdk.copy(output/f'{matrix.prefix}-{profile}-{label}{suffix}',commands/(label+suffix))
    for path in output.glob(f'{matrix.prefix}-{profile}-*.events'):sdk.copy(path,commands/path.name.removeprefix(f'{matrix.prefix}-{profile}-'))
    checked=verify_public(result,matrix.outside,language=language)
    from continuity_c_witness import export_selected
    exported=output/(language.lower()+'-setup-io-public')/profile
    files=export_selected(checked,matrix.outside,exported,result['scope'],replay=lambda path:verify_public(result,path,language=language))
    sdk.write_json(output/f'{language.upper()}_SETUP_IO_PUBLIC_{profile.upper()}.json',dict(completed=True,public_files=files,coverage=checked['coverage'],release_claim_eligible=False))
    return dict(result,public_files=files)
