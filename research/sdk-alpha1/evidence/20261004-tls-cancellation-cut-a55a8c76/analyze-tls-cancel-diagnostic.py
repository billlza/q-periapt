from pathlib import Path
import json,re,hashlib
w=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
result={'scope':'Local real C killed-owner TLS ACK experiment; controlled 10ms send/close scheduling gap. Original CI lacks syscall stage telemetry, so its precise interleaving is not claimed. Not release qualification.','release_claim_eligible':False,'variants':{}}
for name,count,code,delay in [('tls-cancel-diagnostic-01',8,0,0),('tls-cancel-diagnostic-delay-01',3,101,10),('tls-cancel-diagnostic-fixed-01',3,0,10)]:
 root=w/name;r=json.loads((root/'RESULT.json').read_text());assert len(r['records'])==count+1
 rows=[]
 for row in r['records']:
  p=root/f"{row['mode']}-{row['trial']}.log";assert sha(p)==row['log_sha256'];text=p.read_text();assert row['returncode']==(0 if row['mode']=='control' else code)
  if row['mode']=='control':
   assert 'DIAGNOSTIC control_release_without_kill' in text and 'DIAGNOSTIC live ACK control succeeded' in text
   assert 'DIAGNOSTIC timeout_set' not in text and 'DIAGNOSTIC killed_reaped' not in text
  elif delay:
   assert len(re.findall('DIAGNOSTIC timeout_set',text))==1
   assert 'direction=write positive=true nanos=25000000 kind=InvalidInput raw=Some(22)' in text
   assert 'DIAGNOSTIC close_failure kind=ConnectionAborted cause=Some(Os { code: 22' in text
   assert 'channel::Channel>::close' in text
   cut=int(re.search(r'DIAGNOSTIC killed_reaped signal=Some\(9\) cut_index=(\d+)',text)[1])
   a,b=map(int,re.search(r'DIAGNOSTIC failed_admission before=(\d+) after=(\d+)',text).groups());assert a==cut and b==cut+1
   point=text.index('DIAGNOSTIC killed_reaped');tail=text[point:];assert tail.index('clock_released opcode=Some(8)')<tail.index('owner_handle_returned opcode=Some(8)')<tail.index('DIAGNOSTIC timeout_set')<tail.index('DIAGNOSTIC close_failure')
   assert ('unexpected TLS failure:' in text)==(code==101)
   if code==0:assert f'TLS_CANCELLATION_CUT_FAILURE index={cut}' in text and 'WITNESSED_CANCELLATION case=tls-live-ack' in text
  else:
   assert 'DIAGNOSTIC killed_reaped signal=Some(9)' in text and 'DIAGNOSTIC timeout_set' not in text
  rows.append({'mode':row['mode'],'trial':row['trial'],'returncode':row['returncode'],'log_sha256':row['log_sha256']})
 result['variants'][name]={'send_close_delay_ms':delay,'rows':rows,'result_sha256':sha(root/'RESULT.json'),'client_sha256':r['client_sha256'],'library_sha256':r['library_sha256']}
for rel in ['src/anchor/tls.rs','src/anchor/tls/channel.rs']:
 assert (w/'tls-cancel-diagnostic-delay-01/candidate'/rel).read_bytes()==(w/'tls-cancel-diagnostic-fixed-01/candidate'/rel).read_bytes()
result['native_instrumentation_identical_in_red_green']=True
result['completed']=True
(w/'TLS_CANCELLATION_DIAGNOSTIC_ANALYSIS.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'completed':True,'unmodified_timing_trials':8,'red_trials':3,'green_trials':3,'no_kill_controls':3,'analysis_sha256':sha(w/'TLS_CANCELLATION_DIAGNOSTIC_ANALYSIS.json')}))
