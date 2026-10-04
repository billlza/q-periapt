from pathlib import Path
import hashlib,json,zipfile,datetime,re
w=Path(__file__).resolve().parent
run=37231009374
results=w/f'ANDROID_APK_TRANSPORT_RESULTS_{run}.json';s=json.loads(results.read_text());cases={}
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for name,entry in s.items():
 p=w/(str(entry['artifact_id'])+'-'+name+'.zip');assert sha(p)==entry['zip_sha256']
 with zipfile.ZipFile(p) as z:
  samples=json.loads(z.read('samples.json'));observation=json.loads(z.read('observation.json'))
  assert samples==entry['samples'] and observation==entry['observation']
  assert observation['source_commit']=='1c1cd04e3b3cab60ac2cb45a40d315204c05457d'
  commands=z.read('commands.log');assert hashlib.sha256(commands).hexdigest()==observation['commands_sha256']
  calls=z.read('syscalls.log').decode()
 events=samples['events'];copies=[e for e in events if e['label'].endswith('-copy')];short=[e for e in copies if not e['exact']]
 failures=[e for e in events if e['label']=='experiment-failed']
 offline=[e for e in events if e.get('returncode')==1 and e.get('stdout')=='adb: device offline\n']
 assert all(e['returncode']==0 and e['stderr_bytes']==0 for e in short)
 assert len(short)==len(failures)==(0 if samples['status']=='observations_completed' else 1)
 if short:assert offline and short[0]['wall_time_ns']<offline[0]['wall_time_ns']
 cases[name]=dict(artifact_id=entry['artifact_id'],zip_file=p.name,zip_sha256=sha(p),completed_samples=samples['completed_samples'],requested_samples=samples['requested_samples'],copy_attempts=len(copies),exact_copies=sum(e['exact'] for e in copies),short_copy_events=short,first_offline=offline[:1],failure_events=failures,kills=[line for line in calls.splitlines() if 'kill(' in line],diagnostics=samples['diagnostics'])
r=dict(run=run,probe_head='1c1cd04e3b3cab60ac2cb45a40d315204c05457d',results_sha256=sha(results),requested_samples=sum(c['requested_samples'] for c in cases.values()),completed_samples=sum(c['completed_samples'] for c in cases.values()),copy_attempts=sum(c['copy_attempts'] for c in cases.values()),exact_copies=sum(c['exact_copies'] for c in cases.values()),cases=cases,root_cause_established=False,scope='Host copy accounting and original diagnostic events from six fixed historical installed APK trials; no cross-clock causal inference or stability/SDK qualification.',next_discriminating_experiment='Same pinned bytes from an uninstalled ordinary file, both output strategies, compared with installed direct-copy reference; tests whether package installation is necessary.',release_claim_eligible=False)
p=w/f'ANDROID_APK_TRANSPORT_ANALYSIS_{run}.json';p.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k!='cases'},indent=2))
