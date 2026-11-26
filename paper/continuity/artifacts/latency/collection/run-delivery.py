#!/usr/bin/env python3
"""Collect the public-API same-host durable-delivery run, then audit sync syscalls separately."""
import datetime, hashlib, json, os, pathlib, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/'measurement-358b';OUT.mkdir(exist_ok=True)
BASE=OUT/'journals';BASE.mkdir(mode=0o700,exist_ok=True)
BIN=ROOT/'protocol-delivery-target/release/qperiapt-paper-delivery-harness'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):
    try:return pathlib.Path(p).read_text()
    except OSError:return None
def capture(args):
    p=subprocess.run(list(map(str,args)),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    return {'argv':list(map(str,args)),'exit_code':p.returncode,'output':p.stdout}
def state():return {'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'loadavg':os.getloadavg(),'proc_stat':read('/proc/stat'),'pressure_cpu':read('/proc/pressure/cpu'),'pressure_io':read('/proc/pressure/io')}
cpu=min(os.sched_getaffinity(0))
meta={
 'schema':'qperiapt-local-durable-delivery-v1','source_commit':'358b921ab3469ce49f166633fc9a762ff6ed7e3d',
 'binary_sha256':sha(BIN),'lock_sha256':sha(ROOT/'protocol-driver/Cargo.lock'),
 'cpu_affinity':[cpu],'base_directory':str(BASE),'filesystem':capture(['stat','-f','-c','%T',BASE]),
 'mount':capture(['findmnt','--json','-T',BASE,'-o','TARGET,SOURCE,FSTYPE,OPTIONS']),
 'scope':'same process, two real distinct FileBackend journals, no socket/network; one 1024-byte message with 32-byte AD from next_message_id entry through committed receiver plaintext return',
 'outside_timed_interval':['credential/policy/prekey provisioning','full initial three-flight handshake','message-chain activation','plaintext equality checks','application consume','acknowledgement creation and acceptance','directory deletion'],
 'journal':'original DeviceJournal with immediate redb durability and two-phase commit; FileBackend synchronization retained',
 'workload':{'pairs':16,'warmup_deliveries_per_pair':2,'timed_deliveries_per_pair':16,'total_timed_deliveries':256,'directions':'alternating; 128 each','payload_bytes':1024,'associated_data_bytes':32,'loss':False,'reordering':False,'rekey_in_interval':False,'calls_to_os_randomness':'unchanged original APIs'},
 'start':state(),
}
with (OUT/'delivery-raw.csv').open('w') as f,(OUT/'delivery-stderr.txt').open('w') as err:
 p=subprocess.run([str(BIN),str(BASE)],stdout=f,stderr=err,preexec_fn=lambda:os.sched_setaffinity(0,{cpu}))
meta['end']=state();meta['exit_code']=p.returncode;meta['raw_sha256']=sha(OUT/'delivery-raw.csv');meta['stderr']=read(OUT/'delivery-stderr.txt')
(OUT/'delivery-environment.json').write_text(json.dumps(meta,indent=2))
print(json.dumps({k:meta[k] for k in ['exit_code','stderr','filesystem']},indent=2),flush=True)
if p.returncode:raise SystemExit(p.returncode)
if '--skip-audit' in sys.argv:raise SystemExit(0)
# One separate unpooled audit delivery; strace overhead never enters the 256 timing samples.
with (OUT/'sync-audit-raw.csv').open('w') as f,(OUT/'sync-audit-stderr.txt').open('w') as err:
 cmd=['strace','-f','-e','trace=fsync,fdatasync,write','-s','100','-o',str(OUT/'sync-audit.strace'),str(BIN),str(BASE),'--sync-audit']
 p=subprocess.run(cmd,stdout=f,stderr=err,preexec_fn=lambda:os.sched_setaffinity(0,{cpu}))
text=(OUT/'sync-audit.strace').read_text();start=text.index('QPERIAPT_DELIVERY_BEGIN');end=text.index('QPERIAPT_DELIVERY_END',start);segment=text[start:end]
syncs=[line for line in segment.splitlines() if 'fdatasync(' in line or 'fsync(' in line]
audit={'schema':'qperiapt-sync-audit-v1','separate_instrumented_run':True,'excluded_from_timing_summary':True,'exit_code':p.returncode,'command':cmd,'sync_calls_inside_delivery':len(syncs),'calls':syncs,'all_success':bool(syncs) and all('= 0' in line for line in syncs),'strace_sha256':sha(OUT/'sync-audit.strace'),'binary_sha256':sha(BIN)}
(OUT/'sync-audit.json').write_text(json.dumps(audit,indent=2));print(json.dumps(audit,indent=2))
assert audit['exit_code']==0 and audit['all_success']
