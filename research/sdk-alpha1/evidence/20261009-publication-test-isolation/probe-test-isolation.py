from pathlib import Path
import subprocess,sys,json,shutil,time,hashlib,os
b=Path(__file__).resolve().parent;root=b.parent.parent;source=b/'consumer';target=source/'src/publication.rs';fixed=(root/'bindings/c/ContinuityPackageConsumer/src/publication.rs').read_text();old=subprocess.check_output(['git','show','9882e977:bindings/c/ContinuityPackageConsumer/src/publication.rs'],cwd=root,text=True);assert target.read_text()==fixed
probe=r'''
    #[test]
    fn publication_test_registry_isolation_probe() {
        use std::sync::mpsc;
        use std::time::Duration;
        for (name, operation) in [
            ("header", publication_layouts_and_short_version_prefix_are_checked_before_the_body as fn()),
            ("bounds", publication_invalid_plan_and_short_output_fail_before_owner_lookup as fn()),
        ] {
            let guard = TEST_REGISTRY.lock().expect("test registry");
            let (started_tx, started_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                started_tx.send(()).expect("started receiver");
                operation();
                done_tx.send(()).expect("completion receiver");
            });
            started_rx.recv_timeout(Duration::from_secs(10)).expect("worker started");
            let completed_while_another_test_owned_registry = match done_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => true,
                Err(mpsc::RecvTimeoutError::Timeout) => false,
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!("publication worker disconnected"),
            };
            drop(guard);
            worker.join().expect("publication worker");
            if !completed_while_another_test_owned_registry {
                done_rx.recv_timeout(Duration::from_secs(10)).expect("worker completed after release");
            }
            println!("PUBLICATION_TEST_SCOPE name={name} completed_while_registry_owned={completed_while_another_test_owned_registry}");
            assert!(!completed_while_another_test_owned_registry, "publication FFI test crossed another test's registry scope");
        }
    }
'''
(b/'PUBLICATION_ISOLATION_PROBE.txt').write_text(probe);results={}
try:
 for mode,base in [('before',old),('after',fixed)]:
  text=base[:base.rfind('}')]+probe+'}\n';target.write_text(text);out=b/('publication-controlled-'+mode+'-01');out.mkdir()
  shutil.copy2(target,out/'publication.rs');label='publication-controlled-'+mode+'-build-01'
  p=subprocess.run([sys.executable,str(b/'run-consumer.py'),label,'test','--locked','--offline','--release','--lib','--no-run','--message-format=json'],cwd=root,capture_output=True);(out/'build-driver.stdout').write_bytes(p.stdout);(out/'build-driver.stderr').write_bytes(p.stderr);p.check_returncode()
  rows=[json.loads(line) for line in (b/label/'stdout.log').read_text().splitlines()];binaries=[Path(x['executable']) for x in rows if x.get('reason')=='compiler-artifact' and x['target']['name']=='q_periapt_continuity_c_consumer' and x.get('executable')];assert len(binaries)==1;binary=out/'test-probe';shutil.copy2(binaries[0],binary)
  command=[str(binary),'--exact','publication::tests::publication_test_registry_isolation_probe','--nocapture'];p=subprocess.run(command,cwd=source,capture_output=True,timeout=30);(out/'stdout.log').write_bytes(p.stdout);(out/'stderr.log').write_bytes(p.stderr);results[mode]={'command':command,'returncode':p.returncode,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(text.encode()).hexdigest()};print(mode,p.returncode,p.stdout.decode()[-1800:],p.stderr.decode()[-1000:],flush=True)
  assert (p.returncode!=0 if mode=='before' else p.returncode==0)
finally:
 target.write_text(fixed);(b/'PUBLICATION_ISOLATION_PROBE.json').write_text(json.dumps({'results':results,'scope':'Test-only scheduling probe; identical probe invokes real unchanged FFI tests while another test owns the existing shared registry guard. No debugger/process memory inspection; prototype hook excluded from product.'},indent=2)+'\n')
