from pathlib import Path
import hashlib,json,re,zipfile
w=Path(__file__).resolve().parent
reports=json.loads((w/'ANDROID_APK_TRANSPORT_RESULTS_37228953002.json').read_text())
assert len(reports)==6
summary={};identities=[]
for name,record in reports.items():
 path=w/(str(record['artifact_id'])+'-'+name+'.zip')
 assert hashlib.sha256(path.read_bytes()).hexdigest()==record['zip_sha256']
 with zipfile.ZipFile(path) as z:
  sample=json.loads(z.read('samples.json'));assert sample==record['samples']
  observation=json.loads(z.read('observation.json'));assert observation==record['observation']
  assert observation['source_commit']=='3b4bb57bf113c63b710d6fa6e6ae2ce71f659f41'
  assert observation['apk_source']['apk_sha256']=='e2548ac0343802f35bc880804805d60448bf131e436dd0e7e0fb859d0f900724'
  log=z.read('commands.log').decode();trace=z.read('syscalls.log').decode()
  hashes={p:h for h,p in re.findall(r'^([0-9a-f]{64})  (/[^\n]+)$',log,re.M)}
  wanted=['/usr/local/lib/android/sdk/platform-tools/adb','/usr/local/lib/android/sdk/emulator/emulator','/usr/local/lib/android/sdk/emulator/qemu/linux-x86_64/qemu-system-x86_64-headless','/usr/local/lib/android/sdk/system-images/android-35/google_apis_ps16k/x86_64/kernel-ranchu','/usr/local/lib/android/sdk/system-images/android-35/google_apis_ps16k/x86_64/system.img']
  identities.append({p:hashes[p] for p in wanted})
  copies=[x for x in sample['events'] if x['label'].endswith('-copy')]
  failures=[x for x in sample['events'] if x['label']=='experiment-failed']
  summary[name]=dict(artifact_id=record['artifact_id'],zip_sha256=record['zip_sha256'],completed_samples=sample['completed_samples'],status=sample['status'],copies=len(copies),exact_copies=sum(x['exact'] for x in copies),copy_zero_exits=sum(x['returncode']==0 for x in copies),failure=failures,host_disconnects=[x for x in log.splitlines() if 'connection terminated' in x],kill_syscalls=[x for x in trace.splitlines() if re.search(r'\b(?:kill|tgkill|tkill)\(',x)])
  if name.endswith('file-copy-1'):
   short=[x for x in copies if not x['exact']];assert len(short)==1 and short[0]['bytes']==12570112 and short[0]['returncode']==0
   summary[name]['short_copy']=short[0];assert '3732  1791143027.937517 exit_group(0)' in trace
   assert summary[name]['kill_syscalls']==['3549  1791143033.017238 kill(-3737, SIGKILL) = 0']
  if name.endswith('path-only-1'):
   entries={x['label']:x for x in sample['events']};assert entries['sample-10-identity']['stdout'].splitlines()[2]=='561 2771'
   process_table=entries['final-state']['stdout'].splitlines()
   summary[name]['ambiguous_processes']=[x for x in process_table if re.match(r'(?:system|shell)\s+(?:561|2771|436)\s',x)]
assert all(x==identities[0] for x in identities)
result=dict(run=37228953002,head='3b4bb57bf113c63b710d6fa6e6ae2ce71f659f41',same_tool_and_image_hashes=identities[0],cases=summary,requested_samples=144,completed_samples=sum(x['completed_samples'] for x in summary.values()),copy_attempts=sum(x['copies'] for x in summary.values()),exact_copies=sum(x['exact_copies'] for x in summary.values()),conclusions=['Direct-file cat returned zero with 1,038,800 missing bytes and subsequent offline; bounded PIPE is not necessary for this observed failure.','The captured SIGKILL occurred 5.080s after host disconnect and targeted a later logcat client, not the copy client. Normal close(3) ordering within the same millisecond remains unresolved.','Path-only failure was a two-PID shape refusal, not observed replacement of the original system_server. Original 561 remained with PPID 356; second 2771 had PPID 1 and state t. Its origin is unknown.','Four complete trials and exact hash enforcement do not establish stable cleanup or explain why the guest/emulator transport closed.'],not_proven=['Underlying guest/emulator/host transport cause','Same APK identity as the original failed push','Current product archive/device qualification'],release_claim_eligible=False)
(w/'ANDROID_APK_TRANSPORT_ANALYSIS_37228953002.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('cases','same_tool_and_image_hashes')},indent=2))
