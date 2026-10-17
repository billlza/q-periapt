"""Check historical/current authority type boundaries without disturbing a live regression binary."""
from pathlib import Path
import hashlib,json,os,re,subprocess,time
w=Path(__file__).resolve().parent;i=w.parent/'credential-lifecycle-integration'
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
cwd=i/'research/continuity-identity-candidate';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON'))}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(w/'quality-target-1.98.1'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
sources={str(p.relative_to(i)):sha(p) for p in (cwd/'src').rglob('*.rs')}
command=[str(tc/'bin/cargo'),'test','--locked','--offline','--all-features','--doc']
label='cancellation-enrollment-doctests-01';log=w/(label+'.log');start=time.monotonic()
with log.open('xb') as out:r=subprocess.run(command,cwd=cwd,env=env,stdout=out,stderr=subprocess.STDOUT)
assert all(sha(i/n)==h for n,h in sources.items())
counts=re.findall(r'test result: ok\. (\d+) passed;',log.read_text());completed=r.returncode==0 and counts==['2']
record=dict(command=command,cwd=str(cwd),source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=i,text=True).strip(),source_hashes=sources,returncode=r.returncode,passed_tests=sum(map(int,counts)),completed=completed,seconds=time.monotonic()-start,log_sha256=sha(log),scope='Compile-fail historical grant and policy cannot authorize new operational prepare/activation',release_claim_eligible=False)
(w/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k!='source_hashes'},indent=2));print(log.read_text()[-3000:]);raise SystemExit(0 if completed else r.returncode or 1)
