from pathlib import Path
import os,sys,json,subprocess,hashlib,time,shlex,shutil
w=Path(__file__).resolve().parent;i=w.parent/'credential-lifecycle-integration';root=w/'history-witness-foreign';build=root/'kotlin-cancellation-foreign-kotlin-build-01/bindings/kotlin/ContinuityPackageConsumer';native=root/'native/libq_periapt_continuity_c_consumer.dylib'
label=sys.argv[1];consumer=root/('consumer-'+label);base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244/continuity-kotlin-development/toolchains/installed');java=base/'jdk-25.0.4.1+1/Contents/Home';gradle=base/'gradle-9.8.0/bin/gradle'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','JAVA_','JDK_','GRADLE_','KOTLIN_','PYTHON')) and k not in ('_JAVA_OPTIONS','CLASSPATH')};env.update(JAVA_HOME=str(java),GRADLE_USER_HOME=str(root/'gradle-home'),PATH=str(java/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
sys.path.insert(0,str(i/'artifact'));import continuity_kotlin_consumer as gate
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();source=i/'bindings/kotlin/ContinuityPackageConsumer';hashes={str(p.relative_to(i)):sha(p) for p in source.rglob('*') if p.is_file()};native_hash=sha(native)
common=[str(gradle),'--no-daemon','--offline','--warning-mode','fail','--dependency-verification','strict','--max-workers','2','-Dorg.gradle.java.installations.auto-download=false','-Pkotlin.compiler.execution.strategy=in-process','-Dorg.gradle.java.home='+str(java)]
records=[];start=time.monotonic();log=w/(label+'.log');verified=None;closure=None;error=None
def run(cmd):
 t=time.monotonic();r=subprocess.run(cmd,cwd=root,env=env,stdout=stream,stderr=subprocess.STDOUT);records.append(dict(command=cmd,exit=r.returncode,seconds=time.monotonic()-t));
 if r.returncode:raise RuntimeError('command failed '+str(r.returncode))
shutil.copytree(source/'consumer',consumer)
with log.open('xb') as stream:
 try:
  run(common+['--project-dir',str(build),'publishContinuityPublicationToCandidateRepository'])
  published=build/'build/candidate-maven';contract=gate.maven_contract();maven=root/'cancellation-kotlin-maven'
  # Export the fixed version cohort, matching the existing archive producer.
  # Publisher-level changing version-list metadata is retained in published.
  for p in (published/contract.path).iterdir():
   dest=maven/contract.path/p.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
  verified=gate.jvm.verify_maven(maven,contract=contract)
  gate.jvm.pin_consumer_dependencies(consumer,maven,contract=contract)
  run(common+['--project-dir',str(consumer),'installDist','recordRuntime','-Pqperiapt.repository='+str(maven)])
  distribution=consumer/'build/install/continuity-installed-consumer'
  closure=gate.runtime_closure((consumer/'build/runtime.tsv').read_bytes(),distribution,verified['jar_sha256'],root)
 except Exception as exc:error=str(exc)
assert sha(native)==native_hash and all(sha(i/p)==h for p,h in hashes.items())
r=dict(completed=error is None,error=error,seconds=time.monotonic()-start,records=records,source_hashes=hashes,native_library_sha256=native_hash,maven=verified,runtime_closure=closure,log_sha256=sha(log),scope='Current Kotlin source published to a private local Maven directory and compiled consumer; not a distributed release archive or witnessed end-to-end run',release_claim_eligible=False)
(w/(label+'.json')).write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k not in ('records','source_hashes','maven','runtime_closure')},indent=2));print(log.read_text()[-6000:]);raise SystemExit(bool(error))
