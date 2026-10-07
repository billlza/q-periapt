from pathlib import Path
import os,sys,json,hashlib,subprocess,shutil,time
w=Path(__file__).resolve().parent
c=Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004')
label=sys.argv[1]
delay_ms=int(sys.argv[2]) if len(sys.argv)>2 else 0
assert delay_ms in (0,10)
diag=w/label;diag.mkdir(mode=0o700)
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244')
tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON','JAVA_','JDK_','GRADLE_','KOTLIN_','SWIFT_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(w.parent/'continuity-c-enrollment'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=c/'research/continuity-identity-candidate';native=diag/'candidate'
shutil.copytree(source,native,ignore=shutil.ignore_patterns('target','.git'))
p=native/'Cargo.toml';p.write_text(p.read_text().replace('../../crates/',str(c/'crates')+'/'))
build=diag/'consumer';shutil.copytree(w/'history-witness-foreign/c-consumer',build,ignore=shutil.ignore_patterns('target'))
shutil.copytree(c/'bindings/c/ContinuityPackageConsumer/tests',build/'tests',dirs_exist_ok=True)
p=build/'Cargo.toml';p.write_text(p.read_text().replace('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite/target/credential-lifecycle-integration/research/continuity-identity-candidate',str(native)).replace('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite/target/credential-lifecycle-integration',str(c)))
def replace(path,old,new):
 s=path.read_text();assert s.count(old)==1,(path,old,s.count(old));path.write_text(s.replace(old,new))
p=native/'src/anchor/tls/channel.rs'
for direction in ['read','write']:
 replace(p,f'''        self.stream
            .set_{direction}_timeout(Some(self.window()?))
            .map_err(timeout_failure)?;''',f'''        let window = self.window()?;
        self.stream
            .set_{direction}_timeout(Some(window))
            .map_err(|error| {{
                eprintln!("DIAGNOSTIC timeout_set direction={direction} positive={{}} nanos={{}} kind={{:?}} raw={{:?}} backtrace={{}}", !window.is_zero(), window.as_nanos(), error.kind(), error.raw_os_error(), std::backtrace::Backtrace::force_capture());
                timeout_failure(error)
            }})?;''')
p=native/'src/anchor/tls.rs'
replace(p,'        let now = clock()?;', '        let now = clock()?;\n        eprintln!("DIAGNOSTIC clock_released opcode={:?}", request.get(204));')
replace(p,'        drop(owner);\n        checked_remaining', '        eprintln!("DIAGNOSTIC owner_handle_returned opcode={:?}", request.get(204));\n        drop(owner);\n        checked_remaining')
replace(p,'        channel.send_frame(&reply)?;\n        channel.close()?;', '''        channel.send_frame(&reply).map_err(|e| { eprintln!("DIAGNOSTIC send_frame_failure kind={:?} cause={:?}",e.kind(),e.get_ref()); e })?;
        channel.close().map_err(|e| { eprintln!("DIAGNOSTIC close_failure kind={:?} cause={:?}",e.kind(),e.get_ref()); e })?;
        eprintln!("DIAGNOSTIC reply_complete opcode={:?}", request.get(204));''')
if delay_ms:
 replace(p,'        channel.close().map_err', '        std::thread::sleep(std::time::Duration::from_millis(10));\n        channel.close().map_err')
p=build/'tests/common/witness_tls.rs'
failure_line = '                        failures.push(error);' if 'failures.push(error);' in p.read_text() else '                        failures.push(format!("{:?}: {error}", error.kind()));'
replace(p,failure_line,'                        eprintln!("DIAGNOSTIC failed_admission before={} after={} kind={:?} cause={:?}", before, calls.load(Ordering::Acquire), error.kind(), error.get_ref());\n'+failure_line)
p=build/'tests/enrollment/witness_cancellation.rs'
replace(p,'    child.0.kill()?;', '''    if std::env::var_os("QPC_DIAGNOSTIC_CONTROL").is_some() {
        eprintln!("DIAGNOSTIC control_release_without_kill cut_index={cut_index}");
        drop(release);
        let status = child.0.wait()?;
        assert!(status.success());
        assert_eq!(fs::read_to_string(path.join("witness-enrollment-cancel-cut.stdout"))?, expected(&proof, 4));
        assert!(fs::read(path.join("witness-enrollment-cancel-cut.stderr"))?.is_empty());
        let server = tls_witness.as_mut().ok_or("control requires TLS")?;
        assert!(server.finish()?.is_empty());
        assert!(server.failed_admissions.lock().map_err(|_| "control failure lock")?.is_empty());
        assert_eq!(server.admitted.load(Ordering::Acquire), cut_index + 1);
        assert_eq!(server.records.lock().map_err(|_| "control records lock")?.len(), cut_index + 1);
        witness.join()?;
        return Ok(format!("DIAGNOSTIC live ACK control succeeded cut_index={cut_index}"));
    }
    child.0.kill()?;''')
replace(p,'    drop(release);\n    let cut_at', '    eprintln!("DIAGNOSTIC killed_reaped signal={:?} cut_index={cut_index}", killed.signal());\n    drop(release);\n    let cut_at')
replace(p,'    for tls in [false, true] {\n        for expired in [false, true] {\n            for ack in [false, true] {','    for tls in [true] {\n        for expired in [false] {\n            for ack in [true] {')
client=w/'history-witness-foreign/native/qpc-c-client';lib=client.parent/'libq_periapt_continuity_c_consumer.dylib'
env['QPERIAPT_C_OWNER_CLIENT']=str(client)
records=[]
for mode,trial in [('control',0)]+[('killed',n) for n in (range(1,4) if delay_ms else range(1,9))]:
 if mode=='control':env['QPC_DIAGNOSTIC_CONTROL']='1'
 else:env.pop('QPC_DIAGNOSTIC_CONTROL',None)
 log=diag/f'{mode}-{trial}.log';command=[str(tc/'bin/cargo'),'test','--offline','--test','enrollment_witness','witness_cancellation::','--','--test-threads=1','--nocapture']
 start=time.monotonic()
 with log.open('xb') as out:r=subprocess.run(command,cwd=build,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=120)
 record=dict(mode=mode,trial=trial,command=command,returncode=r.returncode,seconds=time.monotonic()-start,log_sha256=sha(log));records.append(record)
 print(json.dumps(record),flush=True)
result=dict(source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=c,text=True).strip(),send_close_delay_ms=delay_ms,scope='Isolated instrumented native witness and actual unchanged C client; not release qualification',client_sha256=sha(client),library_sha256=sha(lib),modified_sources={str(p.relative_to(diag)):sha(p) for p in [native/'src/anchor/tls/channel.rs',native/'src/anchor/tls.rs',build/'tests/common/witness_tls.rs',build/'tests/enrollment/witness_cancellation.rs']},records=records)
(diag/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
