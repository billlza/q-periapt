from pathlib import Path
import os,json,hashlib,shlex
import continuity_c_account_witness as q
import continuity_c_account_tls_loss as loss
import continuity_c_account_delivery as delivery
w=Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite/target/credential-renewal-20261004')
p=Path('/Users/bill/Documents/Codex/credential-lifecycle-packages-20261004')
base=w/'account-workload-census-01';base.mkdir(mode=0o700)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
kp=json.loads((w/'KOTLIN_RENEWAL_PACKAGE.json').read_text())
assert all(sha(Path(k))==v for k,v in kp['jars'].items())
kclient=Path(kp['launchers']['Serial']['path']);args=shlex.split(kclient.read_text().splitlines()[1])
java=Path(args[1]);libs=kclient.parent/'consumer/build/install/continuity-installed-consumer/lib'
jvm=dict(jvm_executable=java,jvm_consumer=libs/'continuity-installed-consumer.jar',jvm_sdk=libs/'q-periapt-continuity-kotlin-0.0.0.jar',jvm_stdlib=libs/'kotlin-stdlib-2.4.20.jar',jvm_annotations=libs/'annotations-13.0.jar')
inputs=[('C',p/'c-installed-debug/qpc-c-client',p/'c-installed-debug/libq_periapt_continuity_c_consumer.dylib',None),('Swift',p/'swift-installed-debug/.build/arm64-apple-macosx/debug/ContinuityClient',p/'swift-installed-debug/native/lib/libq_periapt_continuity_c_consumer.dylib',None),('Kotlin',kclient,p/'kotlin-installed-debug/native/lib/libq_periapt_continuity_c_consumer.dylib',jvm)]
records=[]
for language,client,library,runtime in inputs:
 for scenario in ['mutual-tls-loss','own-tls-loss','mutual-tls-delivery','own-tls-delivery']:
  outside=base/(language.lower()+'-'+scenario);outside.mkdir(mode=0o700)
  output=outside/'result';output.mkdir(mode=0o700)
  report=dict(language=language,scenario=scenario,qualified=False)
  try:
   report['qualification']=q.qualify(outside,output,'debug',dict(os.environ),client,w/'account-renewal-archive-test',library,language=language,jvm_runtime=runtime,scenario=scenario)
   report['qualified']=True
  except ValueError as e:
   # Preserve the observed validator rejection as failure, never as qualification.
   report['validation_error']=str(e)
   if str(e) not in {'TLS loss admitted exchange workload differs','account delivery phase workload differs'}:
    (base/'UNEXPECTED_FAILURE.json').write_text(json.dumps(report,indent=2)+'\n'); raise
  traces=list(output.glob('*trace-debug.stdout'));assert len(traces)==1
  report['native_trace']=traces[0].read_text();assert '1 passed; 0 failed;' in report['native_trace']
  if 'loss' in scenario:
   files=list(outside.rglob('account-tls-loss-exchanges'));assert len(files)==1
   selected=files[0].parent
   report['observed']=loss.exchanges(files[0].read_bytes(),(selected/'account-tls-loss-stages').read_bytes())
  else:
   files=list(outside.rglob('account-delivery-phases'));assert len(files)==1
   selected=files[0].parent
   report['observed']=delivery.tls.phases(files[0].read_bytes(),expected_phases=delivery.PHASES)
  report['trace_file']=str(traces[0]);report['raw_selected']=str(selected)
  records.append(report);(base/'CENSUS.json').write_text(json.dumps(dict(completed=False,records=records,release_claim_eligible=False),indent=2)+'\n')
  print(json.dumps({k:v for k,v in report.items() if k not in ['qualification','native_trace']}),flush=True)
(base/'CENSUS.json').write_text(json.dumps(dict(completed=True,scope='Diagnostic actual archive Debug workload census; validator failures remain failures',records=records,release_claim_eligible=False),indent=2)+'\n')
