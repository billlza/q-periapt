from pathlib import Path
import os,sys,subprocess,json,hashlib,time
w=Path(__file__).resolve().parent;p=w/'joint-policy-integration/c-consumer-compat';label,mode=sys.argv[1:3];d=w/'joint-policy-integration'/label;d.mkdir(mode=0o700)
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON','JAVA_','JDK_','GRADLE_','KOTLIN_','SWIFT_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(w.parent/'continuity-c-joint-policy'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
args={'metadata':['metadata','--offline','--format-version','1'],'clippy':['clippy','--offline','--locked','--all-features','--all-targets','--message-format=json','--','-D','warnings'],'lib':['test','--offline','--locked','--all-features','--lib','--','--nocapture'],'compile':['test','--offline','--locked','--all-features','--tests','--no-run','--message-format=json']}[mode]
cmd=[str(tc/'bin/cargo'),*args];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();source_hashes={str(f.relative_to(p)):sha(f) for f in p.rglob('*') if f.is_file() and f.name!='Cargo.lock'};lock_before=sha(p/'Cargo.lock');start=time.monotonic()
with (d/'stdout.log').open('xb') as so,(d/'stderr.log').open('xb') as se:r=subprocess.run(cmd,cwd=p,env=env,stdout=so,stderr=se)
assert all(sha(p/n)==h for n,h in source_hashes.items());lock_after=sha(p/'Cargo.lock');assert mode=='metadata' or lock_before==lock_after
summary=dict(command=cmd,returncode=r.returncode,completed=r.returncode==0,seconds=time.monotonic()-start,source_hashes=source_hashes,lock_before=lock_before,lock_after=lock_after,stdout_sha256=sha(d/'stdout.log'),stderr_sha256=sha(d/'stderr.log'),scope='isolated existing C consumer SOURCE compatibility against current joint native source; not an installed archive, cross-language, or release qualification',release_claim_eligible=False)
(d/'RESULT.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({k:v for k,v in summary.items() if k!='source_hashes'}))
if mode in ['clippy','compile']:
 errors=[]
 for line in (d/'stdout.log').read_text().splitlines():
  v=json.loads(line)
  if v.get('reason')=='compiler-message' and v['message']['level'] in ['error','warning']:errors.append(v['message']['rendered'])
 print('\n'.join(errors)[:20000])
elif mode=='lib':print((d/'stdout.log').read_text()[-4000:])
print((d/'stderr.log').read_text()[-4000:]);raise SystemExit(r.returncode)
