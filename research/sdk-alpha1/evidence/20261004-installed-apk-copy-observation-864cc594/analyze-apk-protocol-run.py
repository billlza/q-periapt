from pathlib import Path
import json,hashlib,zipfile
w=Path(__file__).resolve().parent;run=37238025840
results=json.loads((w/f'ANDROID_PROTOCOL_RESULTS_{run}.json').read_text());assert len(results)==4
report=dict(run=run,source='5ab0698d2b101d74fbd4424e2347017119df4fa7',arms={},release_claim_eligible=False)
for mode in ['uninstalled-pipe-copy','uninstalled-shell-copy']:
 for trial in [1,2]:
  name=f'android-apk-transport-{mode}-{trial}';r=results[name];p=Path(r['zip_path']);assert hashlib.sha256(p.read_bytes()).hexdigest()==r['zip_sha256']
  with zipfile.ZipFile(p) as z:
   obs=json.loads(z.read('observation.json'));samples=json.loads(z.read('samples.json'));log=z.read('commands.log');assert obs==r['observation'] and samples==r['samples'];assert hashlib.sha256(log).hexdigest()==obs['commands_sha256']
  assert obs['source_commit']==report['source'] and not obs['sdk_installation_attempted'] and not obs['sdk_installation_requested'] and obs['uninstalled_blob_staging_attempted']
  assert obs['output_limit_bytes']==16777216 and len(log)<obs['output_limit_bytes']
  e=samples['events'];labels=[x['label'] for x in e]
  absence=e[labels.index('package-absence-before')];assert absence['returncode']==0 and absence['stdout']==''
  assert labels.index('independent-log-ready')<labels.index('protocol-features')<labels.index('protocol-separated-control')<labels.index('sample-01-copy')
  for stage in ['protocol-features','protocol-shell-route','protocol-exec-route']:
   assert e[labels.index(stage)]['returncode']==0
  assert 'shell_v2' in e[labels.index('protocol-features')]['stdout'].splitlines()
  assert 'shell,v2,raw:true' in e[labels.index('protocol-shell-route')]['stdout']
  assert 'exec:true' in e[labels.index('protocol-exec-route')]['stdout']
  control=e[labels.index('protocol-separated-control')];assert (control['returncode'],control['stdout'],control['stderr'])==(7,'QP_OUT\n','QP_ERR\n')
  copies=[x for x in e if x['label'].endswith('-copy')];short=[]
  for x in copies:
   tail=['shell','-T','-n','cat','/data/local/tmp/qperiapt-transport-probe.bin'] if mode=='uninstalled-shell-copy' else ['exec-out','cat','/data/local/tmp/qperiapt-transport-probe.bin']
   assert x['command'][-len(tail):]==tail
   if x['exact']:assert x['bytes']==13608912 and x['sha256']=='e2548ac0343802f35bc880804805d60448bf131e436dd0e7e0fb859d0f900724' and x['returncode']==0
   else:
    short.append({k:x[k] for k in ['label','returncode','bytes','sha256','stderr_bytes','wall_time_ns']})
  if obs['status']=='observations_completed':
   assert samples['completed_samples']==24 and len(copies)==24 and not short
   after=e[labels.index('package-absence-after')];assert after['returncode']==0 and after['stdout']==''
  else:
   assert obs['status']=='observation_failed' and len(short)==1 and len(copies)==samples['completed_samples']+1
  report['arms'][name]=dict(artifact_id=r['artifact_id'],zip_sha256=r['zip_sha256'],status=obs['status'],completed=samples['completed_samples'],copies=len(copies),short=short,preflight_verified=True,guest_fatal_signature_captured=any(t in log for t in [b'Fatal signal',b'FATAL EXCEPTION',b'ClassCastException']))
raw=report['arms']['android-apk-transport-uninstalled-pipe-copy-2']['short'][0];shell=report['arms']['android-apk-transport-uninstalled-shell-copy-1']['short'][0]
assert (raw['bytes'],raw['returncode'],shell['bytes'],shell['returncode'])==(0,0,4096,255)
report.update(completed=True,attempts=75,exact_copies=73,observed='Both rawexec-out andshell_v2 disconnected in one of two finite trials. Raw0-bytecopyreturned0; shell_v24096-bytecopyreturned255. Actualshell-v2completion signaledfailure but didnotrepairdisconnect. Bothsuccessarmscompleted24exactcopies.',not_proven=['Underlyingtransport/guestcause','Statisticalstability orrelativefailurefrequency','Allguestcrashbuffers/tails captured','SamecauseaspreinstallframeworkSIGSEGV orpriorClassCastException','InstalledSDKqualification'])
(w/f'ANDROID_PROTOCOL_ANALYSIS_{run}.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'completed':True,'attempts':75,'exact_copies':73,'raw_failure':raw,'shell_failure':shell}))
