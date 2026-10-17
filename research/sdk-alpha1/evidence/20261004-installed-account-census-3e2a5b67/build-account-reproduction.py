from pathlib import Path
import os, subprocess, json, hashlib, shutil, time
w=Path(__file__).resolve().parent
p=Path('/Users/bill/Documents/Codex/credential-lifecycle-packages-20261004'); c=p/'c-consumer'
b=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=b/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
target=Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite/target/continuity-c-enrollment')
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON'))}
env.update(RUSTUP_HOME=str(b/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(b/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(target),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sources={str(x.relative_to(c)):sha(x) for x in c.rglob('*') if x.is_file()}
qualification=json.loads((w/'ARCHIVE_C_QUALIFICATION.json').read_text())
assert sources==qualification['source_hashes']
commands=[]
for phase,args in [('clean',['clean','--locked','--offline','-p','q-periapt-continuity-c-consumer','-p','q-periapt-continuity-identity-candidate']),('build',['test','--locked','--offline','--test','account_witness','--no-run','--message-format=json'])]:
 cmd=[str(tc/'bin/cargo'),*args];start=time.monotonic()
 with (w/f'account-reproduction-{phase}-01.stdout').open('xb') as out,(w/f'account-reproduction-{phase}-01.stderr').open('xb') as err:
  result=subprocess.run(cmd,cwd=c,env=env,stdout=out,stderr=err)
 commands.append(dict(command=cmd,exit=result.returncode,seconds=time.monotonic()-start))
 if result.returncode: raise RuntimeError(commands[-1])
items=[json.loads(l) for l in (w/'account-reproduction-build-01.stdout').read_bytes().splitlines() if l.startswith(b'{')]
artifacts=[Path(x['executable']) for x in items if x.get('reason')=='compiler-artifact' and x.get('target',{}).get('name')=='account_witness' and x.get('executable')]
assert len(artifacts)==1
helper=w/'account-renewal-archive-test';assert not helper.exists();shutil.copy2(artifacts[0],helper)
assert sources=={str(x.relative_to(c)):sha(x) for x in c.rglob('*') if x.is_file()}
r=dict(completed=True,commands=commands,source_record='ARCHIVE_C_QUALIFICATION.json',helper=str(helper),sha256=sha(helper),release_claim_eligible=False)
(w/'ACCOUNT_REPRODUCTION_BUILD.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
