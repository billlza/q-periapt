from pathlib import Path
import os, sys, json, hashlib, subprocess, shutil, time
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

assert mode=='c'
build=root/'c-consumer'
files=list((i/'bindings/c/ContinuityPackageConsumer').rglob('*'))
source_hashes={str(p.relative_to(i)):sha(p) for p in files if p.is_file()}
commands=[
 [str(tc/'bin/cargo'),'clippy','--locked','--offline','--all-targets','--all-features','--','-D','warnings'],
 [str(tc/'bin/cargo'),'test','--locked','--offline','--lib','--','--test-threads=2'],
 [str(tc/'bin/rustfmt'),'--check','--edition','2021',*(str(build/'tests'/name) for name in ('enrollment_witness.rs','enrollment/witness_credential_renewal.rs','enrollment/witness_policy_expiry.rs'))]
]
records=[];log=w/(label+'.log');started=time.monotonic();error=None
with log.open('xb') as stream:
 for command in commands:
  t=time.monotonic();r=subprocess.run(command,cwd=build,env=env,stdout=stream,stderr=subprocess.STDOUT)
  records.append(dict(command=command,exit=r.returncode,seconds=time.monotonic()-t))
  if r.returncode:error='command failed';break
assert all(sha(i/name)==value for name,value in source_hashes.items())
report=dict(completed=error is None,error=error,records=records,source_hashes=source_hashes,log_sha256=sha(log),seconds=time.monotonic()-started)
(w/(label+'.json')).write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='source_hashes'},indent=2));print(log.read_text()[-7000:]);raise SystemExit(bool(error))
