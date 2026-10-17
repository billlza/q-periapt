from pathlib import Path
import sys,hashlib,json,shutil,subprocess,os,time,shlex
r=Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite');i=r/'target/credential-lifecycle-integration';w=r/'target/credential-renewal-20261004';outside=Path('/Users/bill/Documents/Codex/credential-lifecycle-packages-20261004');builder=outside/'kotlin-source/bindings/kotlin/ContinuityPackageConsumer'
sys.path.insert(0,str(i/'artifact'));import continuity_kotlin_consumer as gate;import third_party_licenses as licenses
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();prior=json.loads((w/'kotlin-renewal-sdk-01.json').read_text());assert prior['completed'];record=json.loads((w/'ARCHIVE_C_QUALIFICATION.json').read_text());assert record['completed']
source=i/'bindings/kotlin/ContinuityPackageConsumer';assert all(sha(source/p)==h for p,h in prior['source_hashes'].items())
contract=gate.maven_contract();staged=builder/'build/candidate-maven';maven=outside/'kotlin-maven'
for p in (staged/contract.path).iterdir():
 dest=maven/contract.path/p.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
verified=gate.jvm.verify_maven(maven,contract=contract)
files={'maven/'+str(p.relative_to(maven)):p.read_bytes() for p in maven.rglob('*') if p.is_file()}
for p in (outside/'foreign-native-notices').rglob('*'):
 if p.is_file():files[str(p.relative_to(outside/'foreign-native-notices'))]=p.read_bytes()
files['README.md']=(source/'README.md').read_bytes();files['native/include/qpc_owner.h']=(i/'bindings/c/ContinuityPackageConsumer/qpc_owner.h').read_bytes()
files['LICENSES/Rust-1.98.1-library.html']=(i/'LICENSES/Rust-1.98.1-library.html').read_bytes()
for name in ('INVENTORY.sha256','LICENSE-INVENTORY.md','LICENSE.mlkem-native','PROVENANCE.md'):files['LICENSES/mlkem-native/'+name]=(i/'crates/q-periapt-mlkem-native-sys/vendor'/name).read_bytes()
for p in (source/'consumer').rglob('*'):
 if p.is_file():files[str(p.relative_to(source))]=p.read_bytes()
lib=outside/'c-installed-debug/libq_periapt_continuity_c_consumer.dylib';assert sha(lib)==record['binaries'][str(lib)];files['native/lib/'+lib.name]=lib.read_bytes()
hashes={p:hashlib.sha256(b).hexdigest() for p,b in files.items()};data=gate.archive(files);zipfile=outside/'q-periapt-continuity-kotlin-0.0.0-debug.zip'
with zipfile.open('xb') as f:f.write(data)
installed=outside/'kotlin-installed-debug';gate.unpack(data,hashes,installed);licenses.verify(installed,expected_target='aarch64-apple-darwin',root_package=gate.c.NAME);assert gate.jvm.verify_maven(installed/'maven',contract=contract)==verified
consumer=installed/'consumer';gate.jvm.pin_consumer_dependencies(consumer,installed/'maven',contract=contract)
cache=outside/'kotlin-gradle-home';cache.mkdir(mode=0o700);shutil.copytree(r/'target/enrollment-kotlin-20261004/gradle-home/caches/modules-2',cache/'caches/modules-2')
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244/continuity-kotlin-development/toolchains/installed');java=base/'jdk-25.0.4.1+1/Contents/Home';gradle=base/'gradle-9.8.0/bin/gradle'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','JAVA_','JDK_','GRADLE_','KOTLIN_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')};env.update(JAVA_HOME=str(java),GRADLE_USER_HOME=str(cache),PATH=str(java/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
cmd=[str(gradle),'--no-daemon','--offline','--warning-mode','fail','--dependency-verification','strict','--max-workers','2','-Dorg.gradle.java.installations.auto-download=false','-Pkotlin.compiler.execution.strategy=in-process','-Dorg.gradle.java.home='+str(java),'--project-dir',str(consumer),'installDist','recordRuntime','-Pqperiapt.repository='+str(installed/'maven')];start=time.monotonic()
with (w/'kotlin-renewal-consumer-01.log').open('xb') as log:result=subprocess.run(cmd,cwd=outside,env=env,stdout=log,stderr=subprocess.STDOUT)
record={'archive':str(zipfile),'sha256':sha(zipfile),'bytes':len(data),'installed':str(installed),'files':hashes,'maven':verified,'command':cmd,'exit':result.returncode,'seconds':time.monotonic()-start,'native_C_package_record':'ARCHIVE_C_QUALIFICATION.json','completed':False,'release_claim_eligible':False}
if result.returncode==0:
 distribution=consumer/'build/install/continuity-installed-consumer';record['runtime_closure']=gate.runtime_closure((consumer/'build/runtime.tsv').read_bytes(),distribution,verified['jar_sha256'],outside)
 jars={str(p):sha(p) for p in (distribution/'lib').iterdir()};classpath=os.pathsep.join(sorted(jars));library=installed/'native/lib'/lib.name;record['jars']=jars;record['launchers']={}
 for collector in ('Serial','G1'):
  launcher=installed/('client-'+collector.lower());argv=[str(java/'bin/java'),'-Xms32m','-Xmx128m','-XX:+Use'+collector+'GC','--enable-native-access=ALL-UNNAMED','--illegal-native-access=deny','-Dqperiapt.continuity.lib='+str(library),'-cp',classpath,'consumer.ContinuityClientKt'];launcher.write_text('#!/bin/sh\nexec '+shlex.join(argv)+' "$@"\n');launcher.chmod(0o700);record['launchers'][collector]={'path':str(launcher),'sha256':sha(launcher)}
 record['stage']='Maven/archive/runtime closure and installed compilation verified; actual renewal execution pending'
else:record['stage']='Installed consumer compilation failed; archive and diagnostics preserved'
(w/'KOTLIN_RENEWAL_PACKAGE.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k not in ('files','command','jars','runtime_closure','maven')},indent=2));print((w/'kotlin-renewal-consumer-01.log').read_text()[-7000:]);raise SystemExit(result.returncode)
