from pathlib import Path
import sys,json,os,subprocess,hashlib,tempfile,time
b=Path(__file__).resolve().parent;root=b.parent.parent;sys.path.insert(0,str(root/'artifact'))
import continuity_first_configuration as gate
import rust_sdk_profile as sdk
label,expected=sys.argv[1:];out=b/label;out.mkdir();outside=Path(tempfile.mkdtemp(prefix='qpc-configuration-env-')).resolve();old_evidence=outside/'previous-connection';old_evidence.mkdir(mode=0o700)
prior=json.loads((root/'target/configuration-integration-current/installed-gate-debug-01/RESULT.json').read_text());native=prior['native'];helper=Path(native['binaries']['helper']['path']);client=Path(native['binaries']['client']['path'])
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for name,path in [('helper',helper),('client',client)]:assert sha(path)==native['binaries'][name]['sha256']
env={k:v for k,v in os.environ.items() if not k.startswith(('QPC','QPERIAPT','DYLD','LD_','RUST','CARGO','PYTHON','JAVA','JDK','GRADLE'))};env.update(PATH='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(old_evidence))
record={'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'source_sha256':sha(Path(gate.__file__)),'helper_sha256':sha(helper),'client_sha256':sha(client),'inherited_private_fixture_directory':str(old_evidence),'expected':expected,'observed':'unstarted','completed':False};(out/'START.json').write_text(json.dumps(record,indent=2)+'\n')
def run(command,label,cwd=outside,*,runtime=None):
 (out/(label+'.environment.json')).write_text(json.dumps({k:v for k,v in (runtime or env).items() if k.startswith(('QPC','QPERIAPT'))},indent=2)+'\n')
 return sdk.command(command,out/label,cwd,environment=runtime or env)
start=time.monotonic()
try:
 try:
  checked=gate._qualify(outside,out,'debug',env,helper,client,run,language='C');record['observed']='passed';record['execution']=checked
 except ValueError as error:
  record['observed']='rejected';record['error']=str(error)
  if expected!='rejected':raise
  stderr=(out/'configuration-c-debug.stderr').read_text();assert 'AlreadyExists' in stderr and 'File exists' in stderr
 assert record['observed']==expected
 assert list(old_evidence.iterdir())==[] and sha(helper)==record['helper_sha256'] and sha(client)==record['client_sha256']
 record['completed']=True
finally:
 record['seconds']=time.monotonic()-start;(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k!='execution'}),flush=True)
