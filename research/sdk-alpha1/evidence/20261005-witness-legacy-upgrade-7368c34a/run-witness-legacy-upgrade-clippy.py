from pathlib import Path
import os,sys,subprocess,hashlib,json,time
w=Path(__file__).resolve().parent;p=w/'witness-legacy-upgrade-02/consume'
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON','JAVA_','JDK_','GRADLE_','KOTLIN_','SWIFT_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(w.parent/'continuity-c-enrollment'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')

command=[str(tc/'bin/cargo'),'clippy','--offline','--manifest-path',str(p/'Cargo.toml'),'--all-targets','--all-features','--','-D','warnings']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sources={str(f.relative_to(p)):sha(f) for f in p.rglob('*.rs')}
log=w/'witness-legacy-upgrade-clippy-01.log';started=time.monotonic()
with log.open('xb') as f:r=subprocess.run(command,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
assert all(sha(p/f)==h for f,h in sources.items())
receipt={'command':command,'returncode':r.returncode,'completed':r.returncode==0,'source_hashes':sources,'seconds':time.monotonic()-started,'log_sha256':sha(log),'scope':'Strict all-target Clippy on the exact three-profile upgraded-source experiment.','release_claim_eligible':False}
(w/'witness-legacy-upgrade-clippy-01.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:v for k,v in receipt.items() if k!='source_hashes'}));print(log.read_text()[-8000:]);raise SystemExit(r.returncode)
