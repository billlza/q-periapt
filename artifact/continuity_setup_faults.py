"""Observe original setup authority after actual installed-process sync interruption."""
from pathlib import Path
import math
import re
import time

import continuity_c_faults as faults
import continuity_c_setup as setup
from continuity_package import TESTS as NATIVE_TESTS
from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk

HELPERS = {"prepare_setup_fault_case", "inspect_setup_fault_case"}
SCOPE = ("same-host installed C local-profile activation/close sync process interruptions; "
         "observed versus unknown results, original Creating/Active reconciliation and no replacement lineage; "
         "not power-loss or complete setup-failure qualification")


def helper_inventory(data: bytes) -> None:
    text = data.decode()
    names = re.findall(r"^([^\n]+): test$", text, re.MULTILINE)
    expected = HELPERS | {"setup::" + name for name in setup.TESTS.values()} | {"setup::fixture::" + name for name in NATIVE_TESTS}
    sdk.require(len(names) == len(expected) and set(names) == expected
                and re.search(r"^7 tests, 0 benchmarks$", text, re.MULTILINE), "setup fault helper inventory differs")


def observation(data: bytes) -> dict:
    row = parse_strict_json_bytes(data, label="native original setup observation")
    sdk.require(isinstance(row, dict) and set(row) == {"schema_version", "phase", "journal", "next_account", "account_absent", "archives_empty"}
                and type(row["schema_version"]) is int and row["schema_version"] == 1
                and type(row["phase"]) is int and row["phase"] in (1, 2)
                and row["account_absent"] is True and row["archives_empty"] is True, "setup observation shape differs")
    for key in ("journal", "next_account"):
        sdk.require(isinstance(row[key], str), "setup observation identifier differs")
        setup.identifier(row[key].encode())
    sdk.require(row["next_account"][:16] == "0" * 16, "setup consumed its original account position")
    return row


def activation(original: dict, language: str) -> bytes:
    value = b"setup-activated\n" + original["next_account"].encode() + b"\n"
    return value + (b"setup-transfer:closed-alias-released-device-live\n" if language != "C" else b"")


def coverage(cases: list[dict]) -> dict:
    sdk.require(isinstance(cases, list) and 1 <= len(cases) <= 1+2*faults.MAX_SYNC
                and all(isinstance(row,dict) for row in cases), "setup fault cases missing or oversized")
    for row in cases:
        sdk.require(type(row.get('cut')) is int and 0 <= row['cut'] <= faults.MAX_SYNC
                    and isinstance(row.get('side'),str) and row['side'] in {'before','after'},
                    'setup fault cut selection differs')
    baselines = [row for row in cases if row.get("cut") == 0]
    sdk.require(len(baselines) == 1, "setup activation calibration missing or repeated")
    count = baselines[0].get("syncs")
    sdk.require(type(count) is int and 1 <= count <= faults.MAX_SYNC, "setup sync calibration bound differs")
    expected = {(0, "before")} | {(cut, side) for cut in range(1, count + 1) for side in ("before", "after")}
    sdk.require(len(cases) == len(expected) and {(row.get("cut"), row.get("side")) for row in cases} == expected,
                "setup sync cut inventory differs")
    for row in cases:
        sdk.require(type(row["cut"]) is int and row["completed"] is True
                    and type(row["observed_phase"]) is int and row["observed_phase"] in (1, 2)
                    and type(row["outcome_observed"]) is bool
                    and (not row["outcome_observed"] or row["observed_phase"] == 2)
                    and type(row['syncs']) is int
                    and row["syncs"] == (row["cut"] or count), "setup sync outcome differs")
        for key in ('journal','next_account'):
            sdk.require(isinstance(row.get(key),str),'setup fault identifier type differs')
            setup.identifier(row[key].encode())
    sdk.require(baselines[0]["observed_phase"] == 2 and baselines[0]["outcome_observed"] is True
                and {row["observed_phase"] for row in cases if row["cut"] and not row["outcome_observed"]} == {1, 2},
                "unknown-result setup interruption omitted a durable phase")
    return dict(syncs=count, cases=len(cases), creating=sum(row["observed_phase"] == 1 for row in cases),
                active=sum(row["observed_phase"] == 2 for row in cases),
                unknown_active=sum(row["observed_phase"] == 2 and not row["outcome_observed"] for row in cases),
                result_seen_before_interruption=sum(bool(row["cut"]) and row["outcome_observed"] for row in cases))


def native_trace(data: bytes, name: str) -> None:
    text=data.decode()
    sdk.require(name in HELPERS and re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [name]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;", text, re.MULTILINE),
                "setup observer did not execute")


def verify_public(result: dict, directory: Path, *, language: str) -> dict:
    fields={"schema_version","completed","language","scope","profile","outside","binaries","release_claim_eligible",
            "cases","commands","elapsed_seconds","coverage"}
    sdk.require(language in {"C","Swift","Kotlin"} and isinstance(result,dict) and set(result) in (fields,fields|{'public_files'})
                and type(result['schema_version']) is int and result['schema_version']==1
                and result['completed'] is True and result['language']==language and result['release_claim_eligible'] is False
                and result['scope']==SCOPE.replace('installed C','installed '+language)
                and result['profile'] in {'debug','release'},'setup fault report scope differs')
    elapsed=result['elapsed_seconds']
    sdk.require(type(elapsed) in (int,float) and math.isfinite(elapsed) and elapsed>=0,'setup fault elapsed time differs')
    summary=coverage(result['cases']);sdk.require(summary==result['coverage'],'setup fault coverage differs')
    sdk.require(isinstance(result['commands'],dict) and len(result['commands'])==6+14*len(result['cases']),
                'setup fault command count differs')
    sdk.require(isinstance(result['outside'],str),'setup fault original root type differs')
    outside=Path(result['outside']);sdk.require(outside.is_absolute(),'setup fault original root is not absolute')
    roles={'client','native_helper','installed_library','sync_probe','probe_smoke'} | (set(faults.JVM_ROLES) if language=='Kotlin' else set())
    sdk.require(isinstance(result['binaries'],dict) and set(result['binaries'])==roles,'setup fault binary inventory differs')
    for info in result['binaries'].values():
        sdk.require(set(info)=={'path','sha256','bytes'} and isinstance(info['path'],str) and Path(info['path']).is_absolute()
                    and type(info['bytes']) is int and 0<info['bytes']<=256*1024**2
                    and isinstance(info['sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',info['sha256']),
                    'setup fault binary identity differs')
    client=[result['binaries']['client']['path']]
    if language=='Kotlin':
        client=faults.jvm_command({role:Path(result['binaries'][role]['path']) for role in faults.JVM_ROLES},
                                 Path(result['binaries']['installed_library']['path']))
    helper=result['binaries']['native_helper']['path']
    public,logs,commands={}, {}, set()
    def read(name,*,log=False,maximum=faults.MAX_LOG):
        value=sdk.snapshot(directory/name,maximum=maximum)
        (logs if log else public)[name]=value.sha256
        return value.data
    def command(label,argv,expected=0):
        sdk.require(label not in commands,'setup command repeated');commands.add(label)
        record=result['commands'].get(label)
        sdk.require(isinstance(record,dict) and set(record)=={'argv','expected_exit','completed','exit','stdout_sha256','stderr_sha256','elapsed_seconds'}
                    and record['argv']==[str(value) for value in argv] and type(record['exit']) is int and record['exit']==expected
                    and type(record['expected_exit']) is int and record['expected_exit']==expected and record['completed'] is True,
                    'setup command selection or outcome differs')
        sdk.require(type(record['elapsed_seconds']) in (int,float) and math.isfinite(record['elapsed_seconds'])
                    and record['elapsed_seconds']>=0,'setup command elapsed time differs')
        encoded=parse_strict_json_bytes(read('commands/'+label+'.json',log=True),label='setup command record')
        sdk.require(encoded==record,'setup command record differs')
        stdout=read('commands/'+label+'.stdout',log=True)
        sdk.require(read('commands/'+label+'.stderr',log=True)==b'' and logs['commands/'+label+'.stdout']==record['stdout_sha256']
                    and logs['commands/'+label+'.stderr']==record['stderr_sha256'],'setup command output differs')
        return stdout
    helper_inventory(command('helper-inventory',[helper,'--list']))
    for cut,side in ((0,'before'),(1,'before'),(1,'after'),(2,'before'),(2,'after')):
        label=f'probe-{cut}-{side}';path=outside/label
        sdk.require(command(label,[result['binaries']['probe_smoke']['path'],path/'target',path/'control'],86 if cut else 0)==b'',
                    'setup probe output differs')
        sdk.require(faults.events(read('commands/'+label+'.events',log=True),cut,side)==(cut or 2)
                    and read(label+'/control')==b'control' and read(label+'/target')==(b'one' if cut==1 else b'onetwo'),
                    'setup probe calibration or unrelated inode differs')
    for row in result['cases']:
        sdk.require(set(row)=={'completed','cut','side','syncs','observed_phase','outcome_observed','journal','next_account','root','public_readbacks'},
                    'setup fault case shape differs')
        cut,side=row['cut'],row['side'];label=f'activate-{cut}-{side}';path=outside/label/'responder'
        sdk.require(row['root']==str(outside/label),'setup fault original case root differs')
        native_trace(command(label+'-prepare',[helper,'--exact','prepare_setup_fault_case','--nocapture']),'prepare_setup_fault_case')
        original=observation(read(label+'/responder/setup-fault-original.json'))
        observed=observation(read(label+'/responder/setup-fault-observed.json'))
        reconciled=observation(read(label+'/responder/setup-fault-reconciled.json'))
        sdk.require(original['phase']==1 and original['journal']==row['journal'] and original['next_account']==row['next_account']
                    and observed==dict(original,phase=row['observed_phase']) and reconciled==dict(original,phase=2),
                    'setup fault original state binding differs')
        journal=original['journal'].encode();batch=original['next_account'].encode()
        sdk.require(read(label+'/responder/setup-fault-original-id')==bytes.fromhex(original['journal'])
                    and read(label+'/responder/setup-fault-original-batch')==bytes.fromhex(original['next_account']),
                    'setup fault original binary identities differ')
        mapping={name.removeprefix(label+'/'):sha for name,sha in public.items() if name.startswith(label+'/')}
        sdk.require(mapping==row['public_readbacks'],'setup fault public inventory differs')
        outcomes={
            'create':('setup-create',[],b'setup-status:1\n'+journal+b'\n'),
            'storage':('setup-storage',[],b'setup-prepared:1\n'+journal+b'\n'+b'0'*192+b'\n'+b'0'*64+b'\n'),
            'creating-denied':('setup-device',[211],b'setup-refused:211\n'),
            'activate':('setup-activate',[],activation(original,language) if row['outcome_observed'] else b''),
            'status':('setup-status',[],b'setup-status:'+str(row['observed_phase']).encode()+b'\n'+journal+b'\n'),
            'device':('setup-device',[211] if row['observed_phase']==1 else [],
                      b'setup-refused:211\n' if row['observed_phase']==1 else b'setup-device\n'+batch+b'\n'),
            'recreate-denied':('setup-create',[211],b'setup-refused:211\n'),
            'reconcile':('setup-activate',[],activation(original,language)),
            'active-storage-denied':('setup-storage',[211],b'setup-refused:211\n'),
            'active-device':('setup-device',[],b'setup-device\n'+batch+b'\n')}
        for stage,(mode,tail,expected) in outcomes.items():
            sdk.require(command(label+'-'+stage,[*client,mode,path,*tail],86 if stage=='activate' and cut else 0)==expected,
                        'setup fault command changed its original authority or response')
        for stage in ('original','observed','reconciled'):
            native_trace(command(label+'-'+stage,[helper,'--exact','inspect_setup_fault_case','--nocapture']),'inspect_setup_fault_case')
        sdk.require(faults.events(read('commands/'+label+'.events',log=True),cut,side)==row['syncs'],'setup cut event differs')
    sdk.require(set(result['commands'])==commands,'setup command inventory differs')
    if 'public_files' in result:
        sdk.require(result['public_files']==public|logs,'setup exported file map differs')
    return dict(language=language,coverage=summary,public_readbacks=public,command_logs=logs,release_claim_eligible=False)


class Matrix(faults.Matrix):
    """Reuse the owned bounded runner and calibrated inode probe, not protocol state."""
    def __init__(self, outside, output, profile, runtime, client, helper, probe, smoke, *,
                 language="C", expected_library, jvm_runtime=None):
        sdk.require(language in ('C','Swift','Kotlin') and profile in ('debug','release'),
                    'unsupported setup fault language or profile')
        private = outside / (language.lower() + "-setup-faults-" + profile)
        private.mkdir(mode=0o700)
        super().__init__(private, output, profile, runtime, client, helper, probe, smoke,
                         language=language, expected_library=expected_library if language != "C" else None,
                         jvm_runtime=jvm_runtime)
        self.prefix = language.lower() + "-setup-fault"
        self.scope = SCOPE.replace("installed C", "installed " + language)
        sdk.require(expected_library.is_absolute(), "setup fault library path must be absolute")
        self.runtime["QPERIAPT_EXPECTED_CONTINUITY_LIBRARY"] = str(expected_library)
        library = sdk.snapshot(expected_library, maximum=256*1024**2)
        self.binaries["installed_library"] = dict(path=str(expected_library), sha256=library.sha256, bytes=library.size)
        self.identities[str(expected_library)] = library.sha256

    def native(self, name, label, root, *, observed=None):
        sdk.require(name in HELPERS and observed in (None, "original", "observed", "reconciled"), "unknown setup observation command")
        env = dict(QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(root), QPC_TEST_PATH=str(root/"responder"))
        if observed is not None: env["QPC_TEST_SETUP_OBSERVATION"] = observed
        native_trace(self.command([self.helper, "--exact", name, "--nocapture"], label, extra=env),name)

    def observe(self, root, label, stage):
        self.native("inspect_setup_fault_case", label+"-"+stage, root, observed=stage)
        return observation(sdk.snapshot(root/"responder"/("setup-fault-"+stage+".json")).data)

    def prepare(self, label):
        root = self.outside/label
        self.native("prepare_setup_fault_case", label+"-prepare", root)
        created = self.c("setup-create", label+"-create", root)
        prepared = self.c("setup-storage", label+"-storage", root)
        original = self.observe(root,label,"original")
        journal = original["journal"].encode()
        sdk.require(original["phase"] == 1 and created == b"setup-status:1\n"+journal+b"\n"
                    and prepared == b"setup-prepared:1\n"+journal+b"\n"+b"0"*192+b"\n"+b"0"*64+b"\n",
                    "foreign setup did not retain original preparation")
        sdk.require(self.c("setup-device", label+"-creating-denied", root, [211]) == b"setup-refused:211\n",
                    "Creating released operational authority")
        return root,original

    def activation_case(self, cut, side):
        label=f"activate-{cut}-{side}"
        root,original=self.prepare(label)
        receipt=self.receipt(label)
        stdout=self.c("setup-activate",label+"-activate",root,expected=86 if cut else 0,
            extra=self.inject(root/"responder/installation.redb",receipt,cut,side))
        response=activation(original,self.language)
        sdk.require(stdout in (b"",response) if cut else stdout == response,
                    "setup interruption produced a partial result or another identity")
        outcome_observed=stdout==response
        count=faults.events(sdk.snapshot(receipt).data,cut,side)
        observed=self.observe(root,label,"observed")
        sdk.require(not outcome_observed or observed['phase']==2,"observed activation was not durably Active")
        sdk.require({k:v for k,v in observed.items() if k!='phase'} == {k:v for k,v in original.items() if k!='phase'},
                    "setup interruption changed original lineage or children")
        status=b"setup-status:"+str(observed['phase']).encode()+b"\n"+original['journal'].encode()+b"\n"
        sdk.require(self.c("setup-status",label+"-status",root)==status,"foreign and native setup phase differ")
        expected=b"setup-device\n"+original['next_account'].encode()+b"\n"
        tail=[211] if observed['phase']==1 else []
        sdk.require(self.c("setup-device",label+"-device",root,tail)==(b"setup-refused:211\n" if tail else expected),
                    "ordinary device open crossed the persisted phase")
        sdk.require(self.c("setup-create",label+"-recreate-denied",root,[211])==b"setup-refused:211\n","unknown activation authorized a new lineage")
        sdk.require(self.c("setup-activate",label+"-reconcile",root)==activation(original,self.language),"setup did not reconcile original activation")
        sdk.require(self.c("setup-storage",label+"-active-storage-denied",root,[211])==b"setup-refused:211\n","Active recreated children")
        sdk.require(self.c("setup-device",label+"-active-device",root)==expected,"reconciled device changed its original account position")
        reconciled=self.observe(root,label,"reconciled")
        sdk.require(reconciled == dict(original,phase=2),"reconciled setup changed its original state")
        leaves=['setup-fault-original-id','setup-fault-original-batch',*[f'setup-fault-{stage}.json' for stage in ('original','observed','reconciled')]]
        public={'responder/'+leaf:sdk.snapshot(root/'responder'/leaf).sha256 for leaf in leaves}
        self.results.append(dict(completed=True,cut=cut,side=side,syncs=count,observed_phase=observed['phase'],outcome_observed=outcome_observed,journal=original['journal'],
            next_account=original['next_account'],root=str(root),public_readbacks=public))
        return count

    def execute(self):
        result=dict(schema_version=1,completed=False,language=self.language,scope=self.scope,profile=self.profile,outside=str(self.outside),
            binaries=self.binaries,release_claim_eligible=False)
        started=time.monotonic()
        try:
            helper_inventory(self.command([self.helper,'--list'],'helper-inventory'))
            self.probe_check()
            count=self.activation_case(0,'before')
            for cut in range(1,count+1):
                for side in ('before','after'):self.activation_case(cut,side)
            sdk.require(self.identities=={path:sdk.snapshot(Path(path),maximum=256*1024**2).sha256 for path in self.identities},
                        "setup fault binaries changed during execution")
            result.update(completed=True,coverage=coverage(self.results))
        finally:
            result.update(cases=self.results,commands=self.command_records,elapsed_seconds=round(time.monotonic()-started,3))
            sdk.write_json(self.output/f'{self.language.upper()}_SETUP_FAULTS_{self.profile.upper()}.json',result)
        return result


def qualify(outside,output,profile,runtime,client,helper,probe,smoke,*,language='C',expected_library,jvm_runtime=None):
    matrix=Matrix(outside,output,profile,runtime,client,helper,probe,smoke,language=language,
                  expected_library=expected_library,jvm_runtime=jvm_runtime)
    result=matrix.execute()
    commands=matrix.outside/'commands';commands.mkdir(mode=0o700)
    for label in result['commands']:
        for suffix in ('.stdout','.stderr','.json'):
            sdk.copy(output/f'{matrix.prefix}-{profile}-{label}{suffix}',commands/(label+suffix))
    for path in output.glob(f'{matrix.prefix}-{profile}-*.events'):
        sdk.copy(path,commands/path.name.removeprefix(f'{matrix.prefix}-{profile}-'))
    checked=verify_public(result,matrix.outside,language=language)
    from continuity_c_witness import export_selected
    exported=output/(language.lower()+'-setup-fault-public')/profile
    files=export_selected(checked,matrix.outside,exported,result['scope'],
                          replay=lambda path:verify_public(result,path,language=language))
    sdk.write_json(output/f'{language.upper()}_SETUP_FAULT_PUBLIC_{profile.upper()}.json',
                   dict(completed=True,public_files=files,coverage=checked['coverage'],release_claim_eligible=False))
    return dict(result,public_files=files)
