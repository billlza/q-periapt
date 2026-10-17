from pathlib import Path
import os,sys,subprocess,json,hashlib,time
base=Path(__file__).resolve().parent; root=base.parents[1]; out=base/sys.argv[1]; out.mkdir(mode=0o700)
def sha(p):
 with p.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
vectors=root/'bindings/sdk-policy-recovery-vectors.json'; fields=json.loads(vectors.read_text()); assert len(fields)==19
parts=['/* Reproducible public vectors only; no private key material. */','#include <stdint.h>']
for name,value in fields.items():
 data=bytes.fromhex(value); variable='expected_'+name if name in ('enrollment_message','approval_message','possession_message','authorization') else name
 parts.append('static const uint8_t '+variable+'[] = {')
 parts.extend('    '+', '.join(str(b) for b in data[i:i+24])+',' for i in range(0,len(data),24)); parts.append('};')
(out/'recovery_fixture.h').write_text('\n'.join(parts)+'\n')
records=[]; record={'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'fixture_sha256':sha(vectors),'consumer_sha256':sha(base/'recovery_consumer.c'),'runs':records}
env={k:v for k,v in os.environ.items() if not k.startswith(('DYLD_','LD_'))}
for profile in ('debug','release'):
 lib=root/'target/native-stack-debug/build'/profile; library=lib/'libq_periapt_ffi_abi2.dylib'; before=sha(library)
 for kind,source,headers in (
  ('legacy',root/'bindings/c/smoke.c',root/'crates/q-periapt-ffi/abi/v0.1.5'),
  ('owned',root/'bindings/c/sdk_smoke.c',root/'crates/q-periapt-ffi/include'),
  ('recovery',base/'recovery_consumer.c',root/'crates/q-periapt-ffi/include')):
  label=profile+'-'+kind; exe=out/label
  compile=['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Wpedantic','-Werror',str(source),'-I'+str(headers),'-I'+str(out),'-L'+str(lib),'-lq_periapt_ffi_abi2','-Wl,-rpath,'+str(lib),'-o',str(exe)]
  arguments=[str(exe)]
  if kind=='recovery':
   store=out/(label+'-store');store.mkdir(mode=0o700);arguments.append(str(store/'policy.redb'))
  for phase,command in [('compile',compile),('execute',arguments)]:
   start=time.monotonic();r=subprocess.run(command,cwd=root,env=env,capture_output=True);prefix=out/(label+'-'+phase);prefix.with_suffix('.stdout').write_bytes(r.stdout);prefix.with_suffix('.stderr').write_bytes(r.stderr)
   entry={'label':label,'phase':phase,'command':command,'returncode':r.returncode,'seconds':time.monotonic()-start,'stdout_sha256':sha(prefix.with_suffix('.stdout')),'stderr_sha256':sha(prefix.with_suffix('.stderr')),'library_sha256':before}
   records.append(entry);(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(entry),flush=True)
   if r.returncode:print(r.stderr.decode(),flush=True)
   r.check_returncode();assert b'warning:' not in r.stderr.lower();assert sha(library)==before
  assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
record['pass']=True;(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
