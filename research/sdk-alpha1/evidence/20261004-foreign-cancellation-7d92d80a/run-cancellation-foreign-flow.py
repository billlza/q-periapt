from pathlib import Path
import os, sys, json, hashlib, subprocess, shutil, time, re
w=Path(__file__).resolve().parent
i=w.parent/'credential-lifecycle-integration'
label,mode=sys.argv[1:]
assert mode in ('c','swift','kotlin')
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244')
tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
root=w/'history-witness-foreign';root.mkdir(exist_ok=True)
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
build=root/'c-consumer'
for origin in (i/'bindings/c/ContinuityPackageConsumer/tests').rglob('*'):
 if origin.is_file():
  dest=build/'tests'/origin.relative_to(i/'bindings/c/ContinuityPackageConsumer/tests')
  if not dest.exists() or origin.read_bytes()!=dest.read_bytes():
   dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(origin,dest)
client=({'c':native/'qpc-c-client','swift':root/'swift-build/debug/ContinuityClient','kotlin':root/'kotlin-client-cancellation-01'})[mode]
env['QPERIAPT_C_OWNER_CLIENT']=str(client)
public_root=root/'public-evidence';public_root.mkdir(mode=0o700,exist_ok=True)
env['QPERIAPT_WITNESSED_CANCELLATION_EVIDENCE']=str(public_root/label)
if mode=='swift':env['QPERIAPT_EXPECTED_CONTINUITY_LIBRARY']=str(lib)
if mode!='c':env['QPERIAPT_INSTALLED_CLIENT_LANGUAGE']=mode.capitalize()
harness={str(p.relative_to(i)):sha(p) for p in (i/'bindings/c/ContinuityPackageConsumer/tests').rglob('*') if p.is_file()}
library_before=sha(lib)
error=None
with log.open('xb') as stream:
 try:
  if mode=='c':
   csource=i/'bindings/c/ContinuityPackageConsumer'
   clang=subprocess.check_output(['/usr/bin/xcrun','--find','clang'],text=True,env=env).strip()
   sdk=subprocess.check_output(['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path'],text=True,env=env).strip()
   run([clang,'-isysroot',sdk,'-std=c11','-Wall','-Wextra','-Werror','-Wpedantic','-pthread',str(csource/'client.c'),str(csource/'recovery_client.c'),str(csource/'opening_client.c'),'-I',str(csource),'-L',str(native),'-lq_periapt_continuity_c_consumer','-Wl,-rpath,@loader_path','-o',str(native/'qpc-c-client')],build)
  client_before=sha(client)
  run([str(tc/'bin/cargo'),'test','--locked','--offline','--test','enrollment_witness','witness_cancellation::','--','--test-threads=1','--nocapture'],build)
 except Exception as exc:error=str(exc)
assert all(sha(i/name)==value for name,value in (hashes|harness).items())
assert sha(lib)==library_before and sha(client)==client_before
match=re.findall(r"Running tests/enrollment_witness.rs \(([^)]+)\)",log.read_text())
assert len(match)==1
record=dict(native_test_binary=dict(path=match[0],sha256=sha(Path(match[0]))),completed=error is None,error=error,records=records,source_hashes=hashes,
 native_library_sha256=sha(lib),client_sha256=sha(client),client_path=str(client),harness_hashes=harness,
 log_sha256=sha(log),seconds=time.monotonic()-start,
 public_evidence=str(public_root/label),scope=mode+' current source eight TCP/TLS live/expired original grant-cancellation cases with killed foreign owners; not an installed release archive or independent engine',release_claim_eligible=False)
(w/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({k:v for k,v in record.items() if k not in ('source_hashes','records','harness_hashes')},indent=2))
print('\n'.join(line[:500] for line in log.read_text().splitlines()[-70:])[-6500:])
raise SystemExit(bool(error))
