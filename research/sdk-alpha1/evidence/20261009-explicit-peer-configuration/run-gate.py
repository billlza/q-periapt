from pathlib import Path
import subprocess,json,hashlib,os,sys,time,tempfile
b=Path(__file__).resolve().parent.parent;root=b.parent.parent;label,profile=sys.argv[1:];out=b/'integration'/label;out.mkdir(mode=0o700);outside=Path(tempfile.mkdtemp(prefix='qperiapt-peer-gate-')).resolve();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sys.path.insert(0,str(root/'artifact'));import continuity_peer_configuration as gate
source_files=[p for p in (root/'artifact').glob('continuity*.py') if p.is_file()];source_files += [p for language in ['c','swift','kotlin'] for p in (root/'bindings'/language/'ContinuityPackageConsumer').rglob('*') if p.is_file() and '.gradle' not in p.parts and 'build' not in p.parts];inputs={str(p):sha(p) for p in source_files}
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO','RUST','QPERIAPT','QPC','DYLD','LD_','PYTHON','JAVA','JDK','GRADLE','KOTLIN','SWIFT')) and k not in ('_JAVA_OPTIONS','CLASSPATH')};runs=[];record=dict(profile=profile,outside=str(outside),scope='Integrated gate and exact copied binding implementations over qualified component binaries; complete freshly rebuilt distribution remains a CI gate',inputs=inputs,runs=runs,completed=False)
def save():
 record['sources_unchanged']=all(sha(Path(n))==h for n,h in inputs.items());(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');assert record['sources_unchanged']
def run(args,label,*,runtime=None):
 start=time.monotonic()
 with (out/(label+'.stdout')).open('wb') as so,(out/(label+'.stderr')).open('wb') as se:p=subprocess.run(args,cwd=outside,env=env if runtime is None else runtime,stdout=so,stderr=se,timeout=180)
 runs.append(dict(label=label,command=args,returncode=p.returncode,seconds=time.monotonic()-start));save();print(json.dumps(runs[-1]),flush=True)
 if p.returncode:print((out/(label+'.stderr')).read_text()[-4500:],flush=True)
 p.check_returncode();return (out/(label+'.stdout')).read_bytes()
native_label='external-debug-04' if profile=='debug' else 'external-release-01';native=b/native_label/'installed';identity=json.loads((b/native_label/'RESULT.json').read_text());assert all(sha(native/n)==h for n,h in identity['installed'].items())
record['native']=gate.qualify_native(outside,out,profile,env,native/'enrollment',native/'c_owner',native/'qpc-c-client',run);save()
swift_manifest=json.loads((b/'SWIFT_INSTALLED.json').read_text());swift_row=swift_manifest['profiles'][profile];swift_result=json.loads((b/f'swift-installed-peer-{profile}-01/RESULT.json').read_text());client=Path(swift_result['executable']['path']);assert sha(client)==swift_result['executable']['sha256'];swift_env=dict(env,QPERIAPT_EXPECTED_CONTINUITY_LIBRARY=str(Path(swift_row['path'])/'native/lib/libq_periapt_continuity_c_consumer.dylib'))
record['swift']=gate.qualify_foreign(outside,out,profile,swift_env,{'peer_configuration':record['native']},run,client,language='Swift');save();record['kotlin']={}
for collector in ['G1','Serial']:
 prior=json.loads((b/f'kotlin-installed-peer-flow-{profile}-{collector.lower()}-01/RESULT.json').read_text());assert prior['completed'] and all(sha(Path(n))==h for n,h in prior['binaries'].items());client=Path(prior['lifetime_command'][0]);record['kotlin'][collector]=gate.qualify_foreign(outside,out,profile,env,{'peer_configuration':record['native']},run,client,language='Kotlin',collector=collector);save()
record['completed']=True;save();print(json.dumps({'completed':True,'profile':profile,'runs':len(runs)}),flush=True)
