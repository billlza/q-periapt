from pathlib import Path
import os,sys,subprocess,time,json,hashlib
base=Path(__file__).resolve().parent; source=base/'source'; out=base/sys.argv[1]; out.mkdir()
toolbase=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244'); tc=toolbase/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
def sha(p):
 with p.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=source,text=True).strip()
assert not git('status','--porcelain'); head=git('rev-parse','HEAD')
env={k:v for k,v in os.environ.items() if not k.startswith(('RUST','CARGO_','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON'))}
env.update(RUSTUP_HOME=str(toolbase/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(toolbase/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='2',DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',QPERIAPT_PYTHON='/opt/homebrew/opt/python@3.14/bin/python3.14',PATH=str(tc/'bin')+':/Users/bill/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
modules=['test_sdk_abi2_contract','test_c_sdk_profile','test_c_package_manifest','test_windows_sdk_profile','test_android_sdk_profile','test_android_sdk_package','test_android_elf','test_jvm_sdk_package','test_apple_sdk_profile','test_source_results_assembler','test_codeql_rust_quality','test_sdk_jni_contract','test_sdk_cbom_contract']
commands={'artifact':['sh','artifact/python-run.sh','-m','unittest','-v',*['artifact/'+m+'.py' for m in modules]],'c-package':['sh','artifact/c-package.sh','--profile','sdk-020'],'fmt':[str(tc/'bin/cargo'),'fmt','--all','--check']}
command=commands[sys.argv[2]]; started=time.monotonic()
with (out/'stdout.log').open('wb') as so,(out/'stderr.log').open('wb') as se: result=subprocess.run(command,cwd=source,env=env,stdout=so,stderr=se)
record={'source':str(source),'head':head,'command':command,'returncode':result.returncode,'seconds':time.monotonic()-started,'clean_source_after':not git('status','--porcelain'),'head_unchanged':head==git('rev-parse','HEAD'),'stdout_sha256':sha(out/'stdout.log'),'stderr_sha256':sha(out/'stderr.log')}
(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n'); print(json.dumps(record),flush=True); print((out/'stderr.log').read_text()[-7000:],flush=True); print((out/'stdout.log').read_text()[-3000:],flush=True)
assert record['clean_source_after'] and record['head_unchanged']; result.check_returncode()
