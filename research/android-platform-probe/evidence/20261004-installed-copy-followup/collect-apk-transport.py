"""Retain exact hosted experiment state and public diagnostics; never qualify release."""
from pathlib import Path
import datetime,hashlib,json,subprocess,zipfile,sys
w=Path(__file__).resolve().parent;run=int(sys.argv[1]) if len(sys.argv)>1 else 37228323299
expected=sys.argv[2] if len(sys.argv)>2 else "7d36483e9c5e880acf6e09398f0f4931fae231c0"
state=json.loads(subprocess.check_output(['gh','run','view',str(run),'--repo','billlza/q-periapt','--json','headSha,status,conclusion,jobs'],text=True))
assert state['headSha']==expected
state['observed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
state['jobs']=[{k:j[k] for k in ('databaseId','name','status','conclusion','url','steps')} for j in state['jobs']]
(w/('ANDROID_APK_TRANSPORT_HOSTED_'+str(run)+'.json')).write_text(json.dumps(state,indent=2)+'\n')
print(json.dumps({'status':state['status'],'conclusion':state['conclusion'],'jobs':[{'name':j['name'],'status':j['status'],'conclusion':j['conclusion'],'current_step':[s['name'] for s in j['steps'] if s['status']=='in_progress']} for j in state['jobs']]},indent=2))
if state['status']!='completed' and sys.argv[3:]!=['--partial']:raise SystemExit(0)
artifacts=json.loads(subprocess.check_output(['gh','api',f'repos/billlza/q-periapt/actions/runs/{run}/artifacts'],text=True))['artifacts']
reports={}
for artifact in artifacts:
 name=artifact['name'];assert name.startswith('android-apk-transport-')
 assert not artifact['expired']
 path=w/(str(artifact['id'])+'-'+name+'.zip')
 if not path.exists():
  with path.open('xb') as stream:subprocess.run(['gh','api',f"repos/billlza/q-periapt/actions/artifacts/{artifact['id']}/zip"],stdout=stream,check=True)
 digest=hashlib.sha256(path.read_bytes()).hexdigest();assert artifact['digest']=='sha256:'+digest
 with zipfile.ZipFile(path) as z:
  names=z.namelist();assert len(names)==len(set(names)) and set(names)<= {'observation.json','commands.log','samples.json','syscalls.log'}
  assert all(n.file_size<=64*1024*1024 for n in z.infolist())
  observation=json.loads(z.read('observation.json'))
  samples=json.loads(z.read('samples.json')) if 'samples.json' in names else None
  log=z.read('commands.log').decode(errors='replace') if 'commands.log' in names else ''
  reports[name]=dict(artifact_id=artifact['id'],zip_sha256=digest,observation=observation,samples=samples,command_tail=log[-12000:],syscalls_present='syscalls.log' in names)
(w/('ANDROID_APK_TRANSPORT_RESULTS_'+str(run)+'.json')).write_text(json.dumps(reports,indent=2)+'\n')
print(json.dumps({name:{'observation_status':r['observation']['status'],'driver_exit':r['observation'].get('driver_exit_status'),'samples_status':r['samples']['status'] if r['samples'] else None,'completed_samples':r['samples']['completed_samples'] if r['samples'] else None} for name,r in reports.items()},indent=2))
