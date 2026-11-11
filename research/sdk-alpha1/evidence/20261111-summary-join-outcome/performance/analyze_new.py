from pathlib import Path
import zipfile,json,re,datetime,hashlib,collections
BASE=Path('/workspace/scratch/4b61438fb07b/summary-performance')
ZIP=Path('/workspace/scratch/4b61438fb07b/summary-join-readback-42956070561')
START=re.compile(r'Starting to evaluate predicate (.+?)@[^ (]+ \(iteration (\d+)\)')
DELTA=re.compile(r'- (.+)_delta has (\d+) rows')
MEM=re.compile(r'([0-9.]+)([KMGT]?i?)B (in memory written to disk|forgotten|UNREACHABLE|VITAL)')
PREFIX='TaintReach::TaintReachFlow::Flow::Stage'
UNITS={'':1,'Ki':2**10,'Mi':2**20,'Gi':2**30,'Ti':2**40}
ALL={}
for arm,aid in [('heap-2048','13844956987'),('heap-1536','13844887141')]:
 out=BASE/arm;out.mkdir(parents=True,exist_ok=True)
 with zipfile.ZipFile(ZIP/(aid+'.zip')) as z:
  result=json.loads(z.read('RESULT.json')); obs=json.loads(z.read('EVALUATOR_OBSERVATIONS.json')); resource=json.loads(z.read('PROCESS_RESOURCES.json'))
  for name in ('RESULT.json','EVALUATOR_OBSERVATIONS.json','PROCESS_RESOURCES.json'):(out/name).write_bytes(z.read(name))
  samples=[json.loads(line) for line in z.read('PROCESS_RESOURCES.jsonl').splitlines()]
  java=[]
  for row in samples:
   js=[p for p in row['processes'] if p['comm']=='java']
   if not js:continue
   if len(js)!=1:raise ValueError('expected single observed java')
   java.append((row['elapsed_seconds'],row['tree_rss_bytes'],js[0]))
  def window(lo,hi):
   rows=[r for r in java if lo<=r[0]<=hi]
   if len(rows)<2:return None
   a,b=rows[0],rows[-1]; ticks=resource['clock_ticks_per_second']
   cpu=((b[2]['user_ticks']+b[2]['system_ticks'])-(a[2]['user_ticks']+a[2]['system_ticks']))/ticks
   io=[r for r in rows if r[2]['io'] is not None]
   return {'first_seconds':a[0],'last_seconds':b[0],'samples':len(rows),'peak_tree_rss_GiB':max(r[1] for r in rows)/2**30,'mean_tree_rss_GiB':sum(r[1] for r in rows)/len(rows)/2**30,'java_cpu_seconds':cpu,'java_mean_cores':cpu/(b[0]-a[0]),'io_samples':len(io),'io_first_seconds':io[0][0] if io else None,'io_last_seconds':io[-1][0] if io else None,'java_io_GiB':{k:(io[-1][2]['io'][k]-io[0][2]['io'][k])/2**30 for k in ('read_bytes','write_bytes','cancelled_write_bytes')} if io else None}
  res={'total':window(0,20000),'hourly':{str(t):window(t,t+3600) for t in range(0,18000,3600)},'final_600_seconds':window(17400,20000),'sampler':resource}
  (out/'RESOURCE_WINDOWS.json').write_text(json.dumps(res,indent=2)+'\n')
  logname=next(n for n in z.namelist() if re.fullmatch(r'evaluator/execute-queries-.*\.log',n))
  starts={};stages={};iterations={};timing=collections.Counter();counts=collections.Counter();rowmax={};completed=[];evictions=collections.Counter();mem=collections.Counter();first=None;last=None;tail=collections.deque(maxlen=24);hashlog=hashlib.sha256();last_start=None;linecount=0;djo=collections.Counter();djo_examples=[]
  with z.open(logname) as stream:
   for n,raw in enumerate(stream,1):
    linecount=n;hashlog.update(raw)
    if not raw.startswith(b'['):continue
    if first is None:first=datetime.datetime.fromisoformat(raw[1:20].decode()).replace(tzinfo=datetime.timezone.utc).timestamp()
    if not any(key in raw for key in (b'TaintReach::TaintReachFlow::Flow::Stage',b'Pausing evaluation to evict ',b'Unpausing evaluation:',b'dynamic join',b'Dynamic join',b'join order',b'Join order')):continue
    text=raw.decode('utf8','strict').rstrip();stamp=datetime.datetime.fromisoformat(text[1:20]).replace(tzinfo=datetime.timezone.utc).timestamp();last=stamp
    if 'Pausing evaluation to evict ' in text:evictions[str(int((stamp-first)//3600))]+=1
    if 'Unpausing evaluation:' in text:
     for number,unit,category in MEM.findall(text):mem[category]+=float(number)*UNITS[unit]
    if any(k in text for k in ('dynamic join','Dynamic join','join order','Join order')):
     djo['matching_lines']+=1
     if len(djo_examples)<12:djo_examples.append({'line':n,'text':text})
    if PREFIX not in text:continue
    tail.append({'line':n,'text':text})
    m=START.search(text)
    if m:
     predicate=m[1];it=int(m[2]);stage=re.search(r'Stage(\d+)::',predicate)[1];key=predicate.rsplit('/',1)[0]
     starts[key]=(stamp,it,n)
     stages.setdefault(stage,{'first_seconds':stamp-first,'last_seconds':stamp-first,'max_iteration':0})
     stages[stage]['last_seconds']=stamp-first;stages[stage]['max_iteration']=max(stages[stage]['max_iteration'],it)
     iterations.setdefault(stage,{}).setdefault(str(it),stamp-first)
     last_start={'predicate':predicate,'iteration':it,'seconds':stamp-first,'line':n,'text':text}
    m=DELTA.search(text)
    if m:
     key=m[1];rows=int(m[2]);rowmax[key]=max(rowmax.get(key,0),rows)
     if key in starts:
      a,it,ln=starts.pop(key);dt=stamp-a;timing[key]+=dt;counts[key]+=1
      completed.append({'predicate':key,'iteration':it,'seconds':dt,'delta_rows':rows,'start_seconds':a-first,'finish_seconds':stamp-first,'start_line':ln,'finish_line':n})
  phases={'artifact':aid,'log':logname,'log_sha256':hashlog.hexdigest(),'log_sha_matches_receipt':hashlog.hexdigest()==obs['logs'][0]['sha256'],'line_count':linecount,'first_epoch_seconds':first,'last_relevant_seconds':last-first,'stages':stages,'iterations':iterations,'evictions_by_hour':dict(evictions),'logical_unpause_GiB':{k:v/2**30 for k,v in mem.items()},'top_delta_predicates':[{'predicate':k,'matched_seconds':v,'matched_deltas':counts[k],'max_delta_rows':rowmax.get(k)} for k,v in timing.most_common(20)],'longest_completed_deltas':sorted(completed,key=lambda r:r['seconds'],reverse=True)[:20],'last_start':last_start,'unmatched_starts':len(starts),'djo_matches':dict(djo),'djo_examples':djo_examples}
  (out/'EVALUATOR_PHASES.json').write_text(json.dumps(phases,indent=2)+'\n')
  (out/'MATCHED_DELTAS.json').write_text(json.dumps(completed,indent=2)+'\n')
  (out/'TAIL_EXCERPTS.json').write_text(json.dumps(list(tail),indent=2)+'\n')
  ALL[arm]={'resources':res,'phases':phases,'host':{'cpu':next(x for x in result['host']['cpuinfo'].splitlines() if x.startswith('model name')),'cpus':result['host']['cpus'],'kernel':result['host']['kernel']},'query_seconds':result['evaluation']['seconds']}
  print(arm,'resources',json.dumps(res['total']),flush=True)
  print(arm,'top',json.dumps(phases['top_delta_predicates'][:4]),'stages',json.dumps(stages),'last',json.dumps(last_start),flush=True)
(BASE/'NEW_ANALYSIS.json').write_text(json.dumps(ALL,indent=2)+'\n')
