from pathlib import Path, PurePosixPath
import os, json, hashlib, shutil, subprocess, tarfile, time
r=Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite');i=r/'target/credential-lifecycle-integration';w=r/'target/credential-renewal-20261004'
outside=Path('/Users/bill/Documents/Codex/credential-lifecycle-packages-20261004');outside.mkdir(mode=0o700,exist_ok=False)
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
cohort=json.loads((w/'EXPIRED_SDK_DEPENDENCIES.json').read_text())['packages'];patches=[]
for entry in cohort:
 archive=Path(entry['archive']);assert sha(archive)==entry['archive_sha256']
 target=outside/'source/crates'/entry['package'];target.mkdir(parents=True)
 with tarfile.open(archive,'r:gz') as tar:
  members=tar.getmembers();assert all(m.isfile() for m in members)
  observed={}
  for member in members:
   parts=PurePosixPath(member.name).parts;assert len(parts)>1 and '..' not in parts and not member.name.startswith('/')
   rel=Path(*parts[1:]);data=tar.extractfile(member).read();observed[str(rel)]=hashlib.sha256(data).hexdigest()
   dest=target/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
  assert observed==entry['file_hashes']
 patches += ['--config', 'patch.crates-io.'+entry['package']+'.path='+json.dumps(str(target))]
candidate=outside/'source/research/continuity-identity-candidate';source=i/'research/continuity-identity-candidate'
files={}
for p in source.rglob('*'):
 assert not p.is_symlink()
 if p.is_file():
  rel=p.relative_to(source);assert 'target' not in rel.parts
  dest=candidate/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest);files[str(rel)]=sha(p)
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON'))}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(r/'target/continuity-c-enrollment'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
cmd=[str(tc/'bin/cargo'),'package','--locked','--offline','--all-features',*patches]
start=time.monotonic()
with (w/'native-renewal-archive-01.log').open('xb') as log: result=subprocess.run(cmd,cwd=candidate,env=env,stdout=log,stderr=subprocess.STDOUT)
assert all(sha(source/p)==h for p,h in files.items())
record={'outside':str(outside),'command':cmd,'cwd':str(candidate),'exit':result.returncode,'seconds':time.monotonic()-start,'native_source_hashes':files,'SDK_archive_hashes':{e['package']:e['archive_sha256'] for e in cohort},'scope':'Cargo-produced candidate archive verification against nine exact previously sealed SDK package archives; not full release qualification','release_claim_eligible':False}
if result.returncode==0:
 path=r/'target/continuity-c-enrollment/package/q-periapt-continuity-identity-candidate-0.0.0.crate';dest=outside/path.name;shutil.copy2(path,dest);record['archive']={'path':str(dest),'sha256':sha(dest),'bytes':dest.stat().st_size}
(w/'native-renewal-archive-01.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k not in ('command','native_source_hashes','SDK_archive_hashes')},indent=2));print((w/'native-renewal-archive-01.log').read_text()[-5000:]);raise SystemExit(result.returncode)
