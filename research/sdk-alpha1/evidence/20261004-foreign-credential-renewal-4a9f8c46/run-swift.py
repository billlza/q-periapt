from pathlib import Path
import os,subprocess,hashlib,json,sys,time
r=Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite');w=r/'target/credential-renewal-20261004';i=r/'target/credential-lifecycle-integration'
label,mode,*args=sys.argv[1:]
source=Path(args[0]) if args else i/'bindings/swift/ContinuityPackageConsumer'
include=source/'native/include' if args else w/'development-c-owner'
native=source/'native/lib' if args else w/'c-owner-installed'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sources={str(p.relative_to(source)):sha(p) for p in source.rglob('*') if p.is_file() and '.build' not in p.parts}
library=native/'libq_periapt_continuity_c_consumer.dylib';libhash=sha(library);headerhash=sha(include/'qpc_owner.h')
env={k:v for k,v in os.environ.items() if not k.startswith(('SWIFT_','QPERIAPT_','QPC_','DYLD_','LD_','RUST','CARGO_'))}
env['DEVELOPER_DIR']='/Applications/Xcode.app/Contents/Developer'
swift=subprocess.check_output(['/usr/bin/xcrun','--find','swift'],env=env,text=True).strip()
scratch=(source/'.build') if args else w/'swift-development-build'
command=[swift,'test' if mode=='tests' else 'build','--package-path',str(source),'--scratch-path',str(scratch),'--cache-path',str(w/'swift-cache'),'--configuration','debug','-j','2','-Xswiftc','-warnings-as-errors','-Xcc','-I'+str(include),'-Xlinker','-L'+str(native),'-Xlinker','-rpath','-Xlinker',str(native)]
if mode=='client':command += ['--product','ContinuityClient']
start=time.monotonic()
with (w/(label+'.log')).open('xb') as log:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
assert sha(library)==libhash and sha(include/'qpc_owner.h')==headerhash
assert all(sha(source/p)==h for p,h in sources.items())
record={'command':command,'exit':result.returncode,'seconds':time.monotonic()-start,'source':str(source),'source_hashes':sources,'library_sha256':libhash,'header_sha256':headerhash,'scope':'installed archive Swift package' if args else 'Swift source development preflight','completed':result.returncode==0,'release_claim_eligible':False}
if mode=='tests' and result.returncode==0:
 sys.path.insert(0,str(i/'artifact'));import continuity_swift_consumer as gate
 gate.verify_tests((w/(label+'.log')).read_bytes(),b'')
record['compiler_version']=subprocess.check_output([swift,'--version'],text=True,env=env).strip()
(w/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k not in ('source_hashes','command')},indent=2));print((w/(label+'.log')).read_text()[-8500:]);raise SystemExit(result.returncode)
