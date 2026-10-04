from pathlib import Path
import sys,os,subprocess,time,json,hashlib
r=Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite');i=r/'target/credential-lifecycle-integration';w=r/'target/credential-renewal-20261004'
label,language,client_path,library_path,trace_path,source_path=sys.argv[1:]
assert language in ('Swift','Kotlin')
client,library,trace,source=map(Path,(client_path,library_path,trace_path,source_path))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files={str(p):sha(p) for p in (client,library,trace)}
if language == 'Kotlin':
 package=json.loads((w/'KOTLIN_RENEWAL_PACKAGE.json').read_text());assert source==Path(package['installed'])
 assert str(client) in [v['path'] for v in package['launchers'].values()]
 assert all(sha(Path(p))==h for p,h in package['jars'].items())
 files.update(package['jars'])
sources={str(p.relative_to(source)):sha(p) for p in source.rglob('*') if p.is_file() and not set(p.relative_to(source).parts)&{'.build','build','.gradle'}}
env={k:v for k,v in os.environ.items() if not k.startswith(('QPERIAPT_','QPC_','DYLD_','LD_','JAVA_','JDK_','CARGO_','RUST')) and k not in ('CLASSPATH','_JAVA_OPTIONS')}
env.update(QPERIAPT_C_OWNER_CLIENT=str(client),QPERIAPT_INSTALLED_CLIENT_LANGUAGE=language,QPERIAPT_EXPECTED_CONTINUITY_LIBRARY=str(library))
command=[str(trace),'credential_renewal::','--nocapture'];start=time.monotonic()
with (w/(label+'.log')).open('xb') as log:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
assert all(sha(Path(p))==h for p,h in files.items());assert all(sha(source/p)==h for p,h in sources.items())
record={'command':command,'runtime_inputs':{k:v for k,v in env.items() if k.startswith('QPERIAPT_')},'exit':result.returncode,'seconds':time.monotonic()-start,'source':str(source),'source_hashes':sources,'binaries':files,'completed':False,'scope':language+' selected foreign-owner renewal execution; archive provenance requires separate package record','release_claim_eligible':False}
if result.returncode==0:
 sys.path.insert(0,str(i/'artifact'));from continuity_c_enrollment import verify_renewal_execution
 record['execution']=verify_renewal_execution((w/(label+'.log')).read_bytes(),language=language);record['completed']=True
(w/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k not in ('source_hashes','binaries')},indent=2));print((w/(label+'.log')).read_text()[-6000:]);raise SystemExit(result.returncode)
