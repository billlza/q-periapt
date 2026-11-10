from pathlib import Path
import os,sys,subprocess,shutil,hashlib,json,time
w=Path(__file__).resolve().parent;c=Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004');label=sys.argv[1];d=w/label;d.mkdir(mode=0o700)
p=c/'research/continuity-identity-candidate'
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON','JAVA_','JDK_','GRADLE_','KOTLIN_','SWIFT_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(w.parent/'continuity-c-enrollment'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
mode=sys.argv[2] if len(sys.argv)>2 else 'tests'
command=[str(tc/'bin/cargo'),'test','--offline','--manifest-path',str(p/'Cargo.toml'),'--all-features','--lib','enrollment::tests::witness_renewal','--','--nocapture']
if mode == 'targeted': command[command.index('enrollment::tests::witness_renewal')]='opaque_witness_target_never_replaces_the_exact_renewal_receipt'
if mode == 'clippy': command=[str(tc/'bin/cargo'),'clippy','--offline','--manifest-path',str(p/'Cargo.toml'),'--all-targets','--all-features','--','-D','warnings']
source_hashes={str(f.relative_to(c)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob('*.rs') if 'target' not in f.relative_to(p).parts}
log=d/'execution.log';start=time.monotonic()
with log.open('xb') as f:r=subprocess.run(command,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
result=dict(command=command,returncode=r.returncode,completed=r.returncode==0,source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=c,text=True).strip(),seconds=time.monotonic()-start,log_sha256=sha(log),source_hashes=source_hashes,modified_test_sha256=sha(p/'src/enrollment/witness_renewal_tests.rs'),source_diff_sha256=hashlib.sha256(subprocess.check_output(['git','diff','HEAD','--','research/continuity-identity-candidate'],cwd=c)).hexdigest(),mode=mode,scope='Actual product checkout candidate regression or all-target strict Clippy. No policy transition or release qualification claim.',release_claim_eligible=False)
(d/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k != 'source_hashes'}));print(log.read_text()[-5000:]);raise SystemExit(r.returncode)
