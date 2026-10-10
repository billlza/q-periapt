from pathlib import Path
import os, sys, json, hashlib, subprocess, shutil, time, re
w=Path(__file__).resolve().parent
i=Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004')
label,mode=sys.argv[1:]
assert mode in ('c','swift','kotlin')
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244')
tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
root=w/'history-witness-foreign';root.mkdir(exist_ok=True)
native=root/'native';native.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON','JAVA_','JDK_','GRADLE_','KOTLIN_','SWIFT_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(w.parent/'continuity-c-enrollment'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')

assert mode == 'c'
build=root/'c-consumer';lib=native/'libq_periapt_continuity_c_consumer.dylib';client=native/'qpc-c-client'
env['QPERIAPT_C_OWNER_CLIENT']=str(client)
source=i/'bindings/c/ContinuityPackageConsumer'
hashes={str(p.relative_to(i)):sha(p) for p in source.rglob('*') if p.is_file()}
log=w/(label+'.log');start=time.monotonic();records=[];error=None
library_before=sha(lib);client_before=sha(client)
with log.open('xb') as stream:
 for target,test,exact in [('account_witness','tls_loss::',False),('account_witness','tls::account_cleanup_keeps_original_authority_over_mutual_tls',True),('enrollment_witness','c_registration_mutual_tls_requires_current_witness_authority',True)]:
  command=[str(tc/'bin/cargo'),'test','--locked','--offline','--test',target,test,'--','--test-threads=1','--nocapture']
  if exact:command.append('--exact')
  t=time.monotonic();result=subprocess.run(command,cwd=build,env=env,stdout=stream,stderr=subprocess.STDOUT)
  records.append(dict(command=command,cwd=str(build),exit=result.returncode,seconds=time.monotonic()-t))
  if result.returncode:error='failed '+target+'/'+test;break
assert all(sha(i/n)==h for n,h in hashes.items())
assert sha(lib)==library_before and sha(client)==client_before
summaries=re.findall(r'test result: ok\. (\d+) passed; 0 failed;',log.read_text())
completed=error is None and summaries==['2','1','1']
record=dict(completed=completed,error=error,records=records,source_hashes=hashes,log_sha256=sha(log),seconds=time.monotonic()-start,test_summaries=summaries,native_library_sha256=library_before,client_sha256=client_before,scope='Shared encrypted relay regression: both account cleanup4committed-reply-loss cases, regular mutualTLS account cleanup and registration negative controls; C current source, no archive claim',release_claim_eligible=False)
(w/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k not in ('records','source_hashes')},indent=2));print(log.read_text()[-5000:]);raise SystemExit(0 if completed else 1)
