from pathlib import Path
import os,sys,subprocess,hashlib,json,time
w=Path(__file__).resolve().parent;p=w/'joint-policy-integration/candidate';label=sys.argv[1];mode=sys.argv[2] if len(sys.argv)>2 else 'check';d=w/'joint-policy-integration'/label;d.mkdir(mode=0o700)
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON','JAVA_','JDK_','GRADLE_','KOTLIN_','SWIFT_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(w.parent/'continuity-c-enrollment'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')

command=[str(tc/'bin/cargo'),'check','--offline','--manifest-path',str(p/'Cargo.toml'),'--all-features','--lib','--message-format=json']
if mode=='compile-tests': command[1]='test';command.append('--no-run')
if mode=='clippy': command=[str(tc/'bin/cargo'),'clippy','--offline','--manifest-path',str(p/'Cargo.toml'),'--all-features','--all-targets','--message-format=json','--','-D','warnings']
if mode=='tests': command=[str(tc/'bin/cargo'),'test','--offline','--manifest-path',str(p/'Cargo.toml'),'--all-features','--lib',sys.argv[3],'--','--nocapture']
if mode=='docs': command=[str(tc/'bin/cargo'),'test','--offline','--manifest-path',str(p/'Cargo.toml'),'--all-features','--doc']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sources={str(f.relative_to(p)):sha(f) for f in p.rglob('*.rs')}
inputs={str(f.relative_to(p)):sha(f) for f in [p/'Cargo.toml',p/'Cargo.lock',*(p/'tests/fixtures/historical-context').rglob('*')] if f.is_file()}
start=time.monotonic();out=d/'stdout.log';err=d/'stderr.log'
with out.open('xb') as so,err.open('xb') as se:r=subprocess.run(command,cwd=p,env=env,stdout=so,stderr=se)
assert all(sha(p/name)==h for name,h in sources.items())
assert all(sha(p/name)==h for name,h in inputs.items())
result={'command':command,'returncode':r.returncode,'completed':r.returncode==0,'seconds':time.monotonic()-start,'source_hashes':sources,'input_hashes':inputs,'stdout_sha256':sha(out),'stderr_sha256':sha(err),'release_claim_eligible':False}
(d/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ('source_hashes','input_hashes')}))
if mode in ('tests','docs'): print(out.read_text()[-9000:])
else:
    errors=[]
    for line in out.read_text().splitlines():
        item=json.loads(line)
        if item.get('reason')=='compiler-message' and item['message']['level'] in ['error','warning']:
            message=item['message'];errors.append({'message':message['message'],'rendered':message.get('rendered'),'spans':message['spans']})
    (d/'DIAGNOSTICS.json').write_text(json.dumps(errors,indent=2)+'\n')
    print(json.dumps({'diagnostics':len(errors),'summary':[{'message':m['message'],'locations':[(s['file_name'],s['line_start']) for s in m['spans'] if s['is_primary']]} for m in errors[:60]]},indent=2))
print(err.read_text()[-4000:]);raise SystemExit(r.returncode)
