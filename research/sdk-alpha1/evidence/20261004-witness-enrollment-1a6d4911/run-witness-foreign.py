from pathlib import Path
import os, sys, json, hashlib, subprocess, shutil, time
w=Path(__file__).resolve().parent
i=w.parent/'credential-lifecycle-integration'
label,mode=sys.argv[1:]
assert mode in ('c','swift','kotlin')
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244')
tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
root=w/'witness-enrollment-foreign';root.mkdir(exist_ok=True)
native=root/'native';native.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON','JAVA_','JDK_','GRADLE_','KOTLIN_','SWIFT_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(w.parent/'continuity-c-enrollment'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
records=[];start=time.monotonic(); log=w/(label+'.log')
source=i/('bindings/'+('c' if mode=='c' else mode)+'/ContinuityPackageConsumer')
hashes={str(p.relative_to(i)):sha(p) for p in source.rglob('*') if p.is_file()}
if mode=='c': hashes.update({str(p.relative_to(i)):sha(p) for part in ('src','tests') for p in (i/'research/continuity-identity-candidate'/part).rglob('*.rs')})
def run(command,cwd):
 t=time.monotonic()
 result=subprocess.run(command,cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT)
 records.append(dict(command=command,cwd=str(cwd),exit=result.returncode,seconds=time.monotonic()-t))
 if result.returncode: raise RuntimeError('command failed: '+str(result.returncode))
lib=native/'libq_periapt_continuity_c_consumer.dylib'
error=None
with log.open('xb') as stream:
 try:
  if mode=='c':
   build=root/'c-consumer';shutil.copytree(source,build,dirs_exist_ok=True)
   shutil.copytree(i/'research/continuity-identity-candidate/tests',build/'packages/q-periapt-continuity-identity-candidate-0.0.0/tests',dirs_exist_ok=True)
   original=(w/'development-c-owner/Cargo.toml').read_text()
   with (build/'Cargo.toml').open('a') as f:f.write('\n[patch.crates-io]'+original.split('[patch.crates-io]',1)[1])
   shutil.copy2(w/'development-c-owner/Cargo.lock',build/'Cargo.lock')
   cargo=str(tc/'bin/cargo')
   run([cargo,'clean','--locked','--offline','-p','q-periapt-continuity-c-consumer','-p','q-periapt-continuity-identity-candidate'],build)
   run([cargo,'clippy','--locked','--offline','--all-targets','--all-features','--','-D','warnings'],build)
   run([cargo,'test','--locked','--offline','--lib','--','--test-threads=2'],build)
   run([cargo,'rustc','--locked','--offline','--lib','--','-Dwarnings','-C','link-arg=-Wl,-install_name,@rpath/libq_periapt_continuity_c_consumer.dylib'],build)
   shutil.copy2(Path(env['CARGO_TARGET_DIR'])/'debug'/lib.name,lib)
   shutil.copy2(source/'qpc_owner.h',native/'qpc_owner.h')
   clang=subprocess.check_output(['/usr/bin/xcrun','--find','clang'],text=True,env=env).strip()
   sdk=subprocess.check_output(['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path'],text=True,env=env).strip()
   run([clang,'-isysroot',sdk,'-std=c11','-Wall','-Wextra','-Werror','-Wpedantic','-pthread',str(build/'client.c'),str(build/'recovery_client.c'),str(build/'opening_client.c'),'-I',str(build),'-L',str(native),'-lq_periapt_continuity_c_consumer','-Wl,-rpath,@loader_path','-o',str(native/'qpc-c-client')],build)
  elif mode=='swift':
   assert lib.is_file()
   run(['/usr/bin/xcrun','swift','test','--package-path',str(source),'--scratch-path',str(root/'swift-build'),'--cache-path',str(w/'swift-cache'),'--configuration','debug','-j','2','-Xswiftc','-warnings-as-errors','-Xcc','-I'+str(native),'-Xlinker','-L'+str(native),'-Xlinker','-rpath','-Xlinker',str(native)],root)
  else:
   assert lib.is_file()
   build=root/'kotlin/bindings/kotlin/ContinuityPackageConsumer';shutil.copytree(source,build)
   notices=root/'kotlin/LICENSES';notices.mkdir(parents=True)
   for name in ('Apache-2.0.txt','MIT.txt'):shutil.copy2(i/'LICENSES'/name,notices/name)
   tools=base/'continuity-kotlin-development/toolchains/installed';java=tools/'jdk-25.0.4.1+1/Contents/Home';gradle=tools/'gradle-9.8.0/bin/gradle'
   env.update(JAVA_HOME=str(java),GRADLE_USER_HOME=str(w.parent/'enrollment-kotlin-20261004/gradle-home'),PATH=str(java/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
   run([str(gradle),'--no-daemon','--offline','--warning-mode','fail','--dependency-verification','strict','--max-workers','2','-Dorg.gradle.java.installations.auto-download=false','-Pkotlin.compiler.execution.strategy=in-process','-Dorg.gradle.java.home='+str(java),'--project-dir',str(build),'test','-Pqperiapt.continuity.lib='+str(lib)],root)
 except Exception as exc:error=str(exc)
assert all(sha(i/name)==value for name,value in hashes.items())
record=dict(mode=mode,source_hashes=hashes,completed=error is None,error=error,records=records,seconds=time.monotonic()-start,log_sha256=sha(log),scope='Current source development boundary checks only; not an installed release archive or required-witness foreign workflow',release_claim_eligible=False)
if lib.exists():record['native_library_sha256']=sha(lib)
if not error:
 sys.path.insert(0,str(i/'artifact'))
 if mode=='swift':
  import continuity_swift_consumer as gate
  gate.verify_tests(log.read_bytes(),b'')
 if mode=='kotlin':
  import continuity_kotlin_consumer as gate
  record['owner_tests']=gate.verify_test_reports(build/'build/test-results/test')
  for p in (build/'build/test-results/test').glob('TEST-*.xml'):shutil.copy2(p,w/(label+'-'+p.name))
(w/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({k:v for k,v in record.items() if k not in ('records','source_hashes')},indent=2));print(log.read_text()[-6500:])
raise SystemExit(bool(error))
