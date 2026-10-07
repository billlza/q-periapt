from pathlib import Path
import os,sys,json,subprocess,hashlib,shutil,time
r=Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite');i=r/'target/credential-lifecycle-integration';w=r/'target/credential-renewal-20261004';outside=Path('/Users/bill/Documents/Codex/credential-lifecycle-packages-20261004')
label=sys.argv[1];source=i/'bindings/kotlin/ContinuityPackageConsumer';builder=outside/'kotlin-source/bindings/kotlin/ContinuityPackageConsumer';builder.parent.mkdir(parents=True,exist_ok=True)
shutil.copytree(source,builder,dirs_exist_ok=True)
licenses=outside/'kotlin-source/LICENSES';licenses.mkdir(parents=True,exist_ok=True)
for name in ('Apache-2.0.txt','MIT.txt'):shutil.copy2(i/'LICENSES'/name,licenses/name)
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244/continuity-kotlin-development/toolchains/installed');java=base/'jdk-25.0.4.1+1/Contents/Home';gradle=base/'gradle-9.8.0/bin/gradle';lib=outside/'c-installed-debug/libq_periapt_continuity_c_consumer.dylib'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','JAVA_','JDK_','GRADLE_','KOTLIN_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')}
env.update(JAVA_HOME=str(java),GRADLE_USER_HOME=str(r/'target/enrollment-kotlin-20261004/gradle-home'),PATH=str(java/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sources={str(p.relative_to(source)):sha(p) for p in source.rglob('*') if p.is_file()};libhash=sha(lib)
cmd=[str(gradle),'--no-daemon','--offline','--warning-mode','fail','--dependency-verification','strict','--max-workers','2','-Dorg.gradle.java.installations.auto-download=false','-Pkotlin.compiler.execution.strategy=in-process','-Dorg.gradle.java.home='+str(java),'--project-dir',str(builder),'test','publishContinuityPublicationToCandidateRepository','-Pqperiapt.continuity.lib='+str(lib)]
start=time.monotonic()
with (w/(label+'.log')).open('xb') as log:result=subprocess.run(cmd,cwd=outside,env=env,stdout=log,stderr=subprocess.STDOUT)
assert sha(lib)==libhash and all(sha(source/p)==h for p,h in sources.items())
record={'command':cmd,'exit':result.returncode,'seconds':time.monotonic()-start,'source':str(source),'source_hashes':sources,'library_sha256':libhash,'gradle_cache':env['GRADLE_USER_HOME'],'completed':False,'release_claim_eligible':False}
if result.returncode==0:
 sys.path.insert(0,str(i/'artifact'));import continuity_kotlin_consumer as gate
 record['owner_tests']=gate.verify_test_reports(builder/'build/test-results/test');record['completed']=True
 for p in (builder/'build/test-results/test').glob('TEST-*.xml'):shutil.copy2(p,w/(label+'-'+p.name))
(w/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k not in ('source_hashes','command')},indent=2));print((w/(label+'.log')).read_text()[-6500:]);raise SystemExit(result.returncode)
