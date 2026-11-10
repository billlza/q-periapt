from pathlib import Path
import os,sys,subprocess,shutil,hashlib,json,time
w=Path(__file__).resolve().parent;c=Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004');label=sys.argv[1];d=w/label;d.mkdir(mode=0o700)
source=c/'research/continuity-identity-candidate';p=d/'candidate';shutil.copytree(source,p,ignore=shutil.ignore_patterns('target','.git'))
f=p/'Cargo.toml';f.write_text(f.read_text().replace('../../crates/',str(c/'crates')+'/'))
subprocess.run([sys.executable,'-B',str(w/'patch-witness-authorization-experiment.py'),str(p)],check=True)
if len(sys.argv)>3 and sys.argv[3]=='release': subprocess.run([sys.executable,'-B',str(w/'patch-witness-authorization-release.py'),str(p)],check=True)
f=p/'src/anchor/store/renewal_tests.rs';f.write_text(f.read_text()+'\n'+(w/'witness-authorization-probe.rs.txt').read_text())
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON','JAVA_','JDK_','GRADLE_','KOTLIN_','SWIFT_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(w.parent/'continuity-c-enrollment'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
mode=sys.argv[2] if len(sys.argv)>2 else 'focused'
command=[str(tc/'bin/cargo'),'test','--offline','--manifest-path',str(p/'Cargo.toml'),'--all-features','--lib','exact_authorization_probe','--','--nocapture']
if mode == 'anchor': command[command.index('exact_authorization_probe')]='anchor::store::tests'
if mode == 'witness': command[command.index('exact_authorization_probe')]='enrollment::tests::witness_renewal'
if mode == 'clippy': command=[str(tc/'bin/cargo'),'clippy','--offline','--manifest-path',str(p/'Cargo.toml'),'--all-targets','--all-features','--','-D','warnings']
log=d/'execution.log';start=time.monotonic()
with log.open('xb') as f:r=subprocess.run(command,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
result=dict(command=command,returncode=r.returncode,completed=r.returncode==0,source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=c,text=True).strip(),seconds=time.monotonic()-start,log_sha256=sha(log),probe_sha256=sha(w/'witness-authorization-probe.rs.txt'),patcher_sha256=sha(w/'patch-witness-authorization-experiment.py'),release_patch_sha256=sha(w/'patch-witness-authorization-release.py') if len(sys.argv)>3 and sys.argv[3]=='release' else None,mode=mode,modified_source_hashes={str(f.relative_to(p)):sha(f) for f in [p/'src/anchor.rs',p/'src/anchor/store.rs',p/'src/anchor/store/renewal.rs',p/'src/anchor/store/renewal_tests.rs',p/'src/enrollment/witness_renewal_tests.rs',p/'src/durable/anchoring.rs',p/'src/durable/rosters.rs']},modified_test_sha256=sha(p/'src/anchor/store/renewal_tests.rs'),scope='Isolated persistent witness authorization binding using existing credential transactions and store-only target heads. New opcode/schema are experimental. The optional release patch requires the exact journal-derived credential statement at native owner release and denies legacy op4 after adoption. Policy renewal and old-schema migration are not implemented.',release_claim_eligible=False)
(d/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));print(log.read_text()[-5000:]);raise SystemExit(r.returncode)
