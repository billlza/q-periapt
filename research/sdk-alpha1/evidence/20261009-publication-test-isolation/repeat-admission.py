from pathlib import Path
import sys,subprocess,json,hashlib,time,shutil,os
b=Path(__file__).resolve().parent;label,binary,rounds=sys.argv[1:];out=b/label;out.mkdir();source=Path(binary);copy=out/'admission-tests';shutil.copy2(source,copy);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();identity=sha(copy);env={k:v for k,v in os.environ.items() if not k.startswith(('QPC','QPERIAPT','DYLD','LD_','RUST_TEST'))};env['RUST_BACKTRACE']='0'
# Every FFI admission case remains real and parallel; only unrelated long
# native protocol fixtures are excluded from this scheduler-isolation experiment.
cmd=[str(copy),'opening::tests::','publication::tests::','recovery::invocation_tests::','tests::full_call_budget','--test-threads=16','--nocapture'];record={'command':cmd,'binary_sha256':identity,'planned_runs':int(rounds),'runs':[]};start=time.monotonic()
for index in range(int(rounds)):
 p=subprocess.run(cmd,cwd=b/'consumer',env=env,capture_output=True,timeout=30);(out/f'{index:03d}.stdout').write_bytes(p.stdout);(out/f'{index:03d}.stderr').write_bytes(p.stderr);record['runs'].append({'index':index,'returncode':p.returncode})
 if p.returncode:break
assert sha(copy)==identity;record['seconds']=time.monotonic()-start;record['observed_failure']=any(x['returncode']!=0 for x in record['runs']);(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record));print(p.stdout.decode()[-1800:]);print(p.stderr.decode()[-1800:])
