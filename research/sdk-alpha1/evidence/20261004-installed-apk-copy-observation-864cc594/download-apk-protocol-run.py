from pathlib import Path
import subprocess,json,hashlib,zipfile,concurrent.futures,sys
w=Path(__file__).resolve().parent;run=int(sys.argv[1])
meta=json.loads(subprocess.check_output(['gh','api',f'repos/billlza/q-periapt/actions/runs/{run}/artifacts']));(w/f'ANDROID_PROTOCOL_ARTIFACTS_{run}.json').write_text(json.dumps(meta,indent=2)+'\n')
def one(a):
 p=w/(str(a['id'])+'-'+a['name']+'.zip')
 if not p.exists():
  with p.open('xb') as f:subprocess.run(['gh','api',f"repos/billlza/q-periapt/actions/artifacts/{a['id']}/zip"],stdout=f,check=True)
 h=hashlib.sha256(p.read_bytes()).hexdigest();assert 'sha256:'+h==a['digest'];assert p.stat().st_size==a['size_in_bytes']
 with zipfile.ZipFile(p) as z:
  obs=json.loads(z.read('observation.json'));log=z.read('commands.log');assert hashlib.sha256(log).hexdigest()==obs['commands_sha256'];samples=json.loads(z.read('samples.json')) if 'samples.json' in z.namelist() else None
  result=dict(artifact_id=a['id'],zip_path=str(p),zip_sha256=h,observation=obs,samples=samples)
  events=[] if samples is None else samples['events'];copies=[e for e in events if e['label'].endswith('-copy')];brief=dict(arm=a['name'],bytes=p.stat().st_size,source=obs['source_commit'],status=obs['status'],samples=None if samples is None else samples['completed_samples'],failures=[e for e in events if e['label']=='experiment-failed'],short_copies=[{k:e[k] for k in ['label','returncode','bytes','sha256','stderr_bytes']} for e in copies if not e['exact']],preflight=[e['label'] for e in events if e['label'] in ['independent-log-ready','protocol-separated-control']],guest_crash_lines=[l for l in log.decode(errors='replace').splitlines() if any(p in l for p in ['Fatal signal','FATAL EXCEPTION','FATAL EXCEPTION IN SYSTEM PROCESS','ClassCastException'])][:12])
  print(json.dumps(brief),flush=True)
  if samples is None:print(log.decode(errors='replace')[-1300:],flush=True)
  return a['name'],result
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=dict(pool.map(one,meta['artifacts']))
(w/f'ANDROID_PROTOCOL_RESULTS_{run}.json').write_text(json.dumps(results,indent=2)+'\n')
