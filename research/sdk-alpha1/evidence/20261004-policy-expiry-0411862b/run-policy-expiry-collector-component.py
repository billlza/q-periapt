from pathlib import Path
import os,sys,subprocess,json,hashlib,time
w=Path(__file__).resolve().parent;i=w.parent/'credential-lifecycle-integration'
sys.path.insert(0,str(i/'artifact'))
import continuity_witnessed_policy_expiry as gate
label=sys.argv[1];outside=w/(label+'-runtime');output=w/(label+'-output')
outside.mkdir(mode=0o700);output.mkdir(mode=0o700)
binary=w.parent/'continuity-c-enrollment/debug/deps/enrollment_witness-8e65a00f20d7238d'
client=w/'history-witness-foreign/native/qpc-c-client'
env={k:v for k,v in os.environ.items() if not k.startswith(('QPERIAPT_','QPC_','DYLD_','LD_','PYTHON'))}
env['QPERIAPT_C_OWNER_CLIENT']=str(client)
records=[];start=time.monotonic()
def run(command,label,*,runtime):
 r=subprocess.run(command,env=runtime,cwd=outside,capture_output=True)
 (output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr)
 records.append({'command':command,'exit':r.returncode})
 if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace')[-4000:]+r.stdout.decode(errors='replace')[-4000:])
 return r.stdout
result=None;error=None
try:result=gate.qualify(outside,output,'debug',env,binary,run)
except Exception as exc:error=str(exc)
r={'completed':error is None,'error':error,'records':records,'seconds':time.monotonic()-start,
 'scope':'Shared collector component exercised with current development binaries; no archive provenance or release claim',
 'source_hashes':{'artifact/'+n:hashlib.sha256((i/'artifact'/n).read_bytes()).hexdigest() for n in ('continuity_witnessed_policy_expiry.py','continuity_witnessed_renewal.py','continuity_c_enrollment.py','continuity_c_consumer.py')},
 'release_claim_eligible':False,'public_files':len(result['public_readbacks']) if result else None}
log=b''.join(p.read_bytes() for p in sorted(output.glob('*.stdout')))+b''.join(p.read_bytes() for p in sorted(output.glob('*.stderr')))
(w/(label+'.log')).write_bytes(log)
r['log_sha256']=hashlib.sha256(log).hexdigest()
(w/(label+'.json')).write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2));raise SystemExit(error is not None)
