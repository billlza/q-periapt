from pathlib import Path
import os,sys,subprocess,time,json,hashlib,datetime
base=Path(__file__).resolve().parent;root=base.parents[1]
source=root/'target/policy-recovery-ffi-current/source';out=base/sys.argv[1];out.mkdir(mode=0o700)
toolbase=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=toolbase/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
def sha(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=source,text=True).strip()
assert not git('status','--porcelain');head=git('rev-parse','HEAD')
compiler={n:sha(tc/'bin'/n) for n in ('rustc','cargo','rustdoc')}
env={k:os.environ[k] for k in ('HOME','USER','LOGNAME','TMPDIR') if k in os.environ}
env.update(PATH=str(tc/'bin')+':/Users/bill/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
 LC_ALL='C',LANG='C',RUSTUP_HOME=str(toolbase/'rustup'),CARGO_HOME=str(toolbase/'apple-cargo-home-ff4a153e'),
 RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTDOC=str(tc/'bin/rustdoc'),CARGO_NET_OFFLINE='true',
 CARGO_BUILD_JOBS='2',QPERIAPT_PYTHON='/opt/homebrew/opt/python@3.14/bin/python3.14',
 QPERIAPT_SWIFT_XCFRAMEWORK_OUT_DIR=str(source/'target'/('apple-recovery-'+sys.argv[1])))
# The release builder forbids caller RUSTC/flag overrides. PATH selects the real
# private compiler binaries above, without changing that checked contract.
command=['sh','artifact/swift-xcframework.sh','--profile','sdk-020'];started=time.monotonic()
record={'at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':str(source),'head':head,
 'command':command,'compiler_before':compiler,'private_rustup_home':env['RUSTUP_HOME'],
 'private_cargo_home':env['CARGO_HOME'],'output_root':env['QPERIAPT_SWIFT_XCFRAMEWORK_OUT_DIR']}
(out/'START.json').write_text(json.dumps(record,indent=2)+'\n')
with (out/'stdout.log').open('wb') as so,(out/'stderr.log').open('wb') as se:
 result=subprocess.run(command,cwd=source,env=env,stdout=so,stderr=se)
record.update(returncode=result.returncode,seconds=time.monotonic()-started,clean_source_after=not git('status','--porcelain'),
 head_unchanged=head==git('rev-parse','HEAD'),compiler_after={n:sha(tc/'bin'/n) for n in compiler},
 stdout_sha256=sha(out/'stdout.log'),stderr_sha256=sha(out/'stderr.log'))
(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)
print((out/'stderr.log').read_text()[-4000:],flush=True);print((out/'stdout.log').read_text()[-4000:],flush=True)
assert record['clean_source_after'] and record['head_unchanged'] and record['compiler_after']==compiler
result.check_returncode()
