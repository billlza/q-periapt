from pathlib import Path
import os,sys,subprocess,shutil,hashlib,json,time
w=Path(__file__).resolve().parent;c=Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004');label=sys.argv[1];d=w/label;d.mkdir(mode=0o700)
state=d/'original-state';state.mkdir(mode=0o700)
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON','JAVA_','JDK_','GRADLE_','KOTLIN_','SWIFT_')) and k not in ('_JAVA_OPTIONS','CLASSPATH')}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(w.parent/'continuity-c-enrollment'),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')

sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report={'base_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=c,text=True).strip(),'probe_sha256':sha(w/'witness-legacy-upgrade-probe.rs.txt'),'steps':[],'completed':False,'scope':'Actual old and isolated new native binaries on the same original private file paths; synthetic trusted times and fixture authorities. No joint policy renewal, installed archive or general upgrade qualification.','release_claim_eligible':False}
start=time.monotonic()
try:
    for phase in ['produce','consume']:
        p=d/phase;shutil.copytree(c/'research/continuity-identity-candidate',p,ignore=shutil.ignore_patterns('target','.git'))
        f=p/'Cargo.toml';f.write_text(f.read_text().replace('../../crates/',str(c/'crates')+'/'))
        if phase=='consume':
            for script in ['patch-witness-authorization-experiment.py','patch-witness-authorization-release.py']:
                subprocess.run([sys.executable,'-B',str(w/script),str(p)],check=True)
        f=p/'src/enrollment/witness_renewal_tests.rs';f.write_text(f.read_text()+'\n'+(w/'witness-legacy-upgrade-probe.rs.txt').read_text())
        hashes={str(f.relative_to(p)):sha(f) for f in p.rglob('*.rs')}
        command=[str(tc/'bin/cargo'),'test','--offline','--manifest-path',str(p/'Cargo.toml'),'--all-features','--lib','--no-run','--message-format=json-render-diagnostics']
        out=d/(phase+'-build.jsonl');err=d/(phase+'-build.stderr')
        with out.open('xb') as so,err.open('xb') as se: result=subprocess.run(command,cwd=p,env=env,stdout=so,stderr=se)
        report['steps'].append({'phase':phase,'kind':'build','command':command,'returncode':result.returncode,'source_hashes':hashes,'stdout_sha256':sha(out),'stderr_sha256':sha(err)})
        if result.returncode: print(err.read_text()[-6000:]);raise RuntimeError(phase+' compilation failed')
        artifacts=[json.loads(line) for line in out.read_text().splitlines()]
        binaries=[item['executable'] for item in artifacts if item.get('reason')=='compiler-artifact' and item.get('executable') and item['target']['name']=='q_periapt_continuity_identity_candidate']
        assert len(binaries)==1,binaries
        binary=d/(phase+'-native-tests');shutil.copyfile(binaries[0],binary);binary.chmod(0o700)
        run_env=env|{'QPERIAPT_EXACT_UPGRADE_ROOT':str(state),'QPERIAPT_EXACT_UPGRADE_PHASE':phase}
        command=[str(binary),'--exact','enrollment::tests::witness_renewal::legacy_exact_authorization_probe::actual_old_new_native_upgrade_preserves_original_state_and_requires_new_authorization','--nocapture']
        log=d/(phase+'.log')
        with log.open('xb') as stream: result=subprocess.run(command,cwd=p,env=run_env,stdout=stream,stderr=subprocess.STDOUT)
        report['steps'].append({'phase':phase,'kind':'execution','command':command,'returncode':result.returncode,'binary_sha256':sha(binary),'log_sha256':sha(log)})
        print(log.read_text()[-6000:],flush=True)
        if result.returncode: raise RuntimeError(phase+' execution failed')
        assert '1 passed; 0 failed;' in log.read_text()
        for path,h in hashes.items(): assert sha(p/path)==h
    report['completed']=True
except Exception as error:
    report['failure']=str(error)
finally:
    report['seconds']=time.monotonic()-start
    (d/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='steps'}),flush=True)
    print(json.dumps([{k:v for k,v in step.items() if k!='source_hashes'} for step in report['steps']]),flush=True)
raise SystemExit(0 if report['completed'] else 1)
