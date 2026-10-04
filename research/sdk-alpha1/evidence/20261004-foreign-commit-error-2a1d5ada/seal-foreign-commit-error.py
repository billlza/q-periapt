"""Seal real foreign error-return recovery; keep archive and release gates open."""
from pathlib import Path
import gzip,hashlib,io,json,shutil,subprocess,sys,tarfile
w=Path(__file__).resolve().parent;c=Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004')
source='2a1d5adae849483763ea006b545f067a3b85ef4b';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=c,text=True).strip()
assert git('rev-parse','HEAD')==source and not git('status','--porcelain')
flows={k:'foreign-commit-error-'+k.lower()+'-flow-01' for k in ['C','Swift','Kotlin']}
regressions={'foreign-commit-error-kill-regression-01':('expiry','C',312),'foreign-commit-error-cancellation-regression-01':('cancellation','Swift',544)}
labels=list(flows.values())+list(regressions)+['foreign-commit-error-quality-01','foreign-commit-error-swift-build-01','foreign-commit-error-kotlin-consumer-01','foreign-commit-error-readers-01','foreign-commit-error-ci-wiring-01','foreign-commit-error-source-01']
receipts={};hashes={}
for label in labels:
 r=json.loads((w/(label+'.json')).read_text());assert r['completed'],label
 assert r.get('returncode',0)==0 and all(x['exit']==0 for x in r.get('records',[])),label
 assert sha(w/(label+'.log'))==r['log_sha256'],label
 for n,h in (r.get('source_hashes',{})|r.get('harness_hashes',{})).items():assert sha(c/n)==h,(label,n);hashes[n]=h
 receipts[label]=r
assert receipts['foreign-commit-error-readers-01']['observed_test_summary'][0][0]==90
assert receipts['foreign-commit-error-ci-wiring-01']['tests']==1
assert receipts['foreign-commit-error-source-01']['source_commit']==source
assert b'test result: ok. 9 passed;' in (w/'foreign-commit-error-quality-01.log').read_bytes()
assert b'Executed 28 tests, with 0 failures' in (w/'foreign-commit-error-swift-build-01.log').read_bytes()
unchanged=['research/continuity-identity-candidate/src','bindings/c/ContinuityPackageConsumer/src','bindings/c/ContinuityPackageConsumer/qpc_owner.h','bindings/swift/ContinuityPackageConsumer/Sources/QPeriaptContinuity','bindings/kotlin/ContinuityPackageConsumer/src','crates/q-periapt-sdk','crates/q-periapt-ffi']
assert not git('diff','44c9ff7910d3c243a5b517360e59df06c9097f94',source,'--',*unchanged)
for n,h in hashes.items():assert hashlib.sha256(subprocess.check_output(['git','show',source+':'+n],cwd=c)).hexdigest()==h,n
lib=w/'history-witness-foreign/native/libq_periapt_continuity_c_consumer.dylib'
production=json.loads((w/'cancellation-foreign-c-build-02.json').read_text());assert production['completed'] and sha(lib)==production['native_library_sha256']
compiled={n:h for n,h in production['source_hashes'].items() if n.startswith(('bindings/c/ContinuityPackageConsumer/src/','research/continuity-identity-candidate/src/')) or n=='bindings/c/ContinuityPackageConsumer/qpc_owner.h'}
assert compiled
for n,h in compiled.items():assert sha(c/n)==h,n
sys.path.insert(0,str(c/'artifact'))
import continuity_witnessed_commit_error as error
import continuity_witnessed_policy_expiry as expiry
import continuity_witnessed_cancellation as cancellation
import continuity_c_consumer as abi
symbols=subprocess.check_output(['/usr/bin/nm','-gU',str(lib)],text=True)
assert {s.split()[-1].removeprefix('_') for s in symbols.splitlines() if s.strip()}==abi.EXPORTS and len(abi.EXPORTS)==73
assert subprocess.check_output(['/usr/bin/lipo','-archs',str(lib)],text=True).strip()=='arm64'
public={}
for language,label in flows.items():
 r=receipts[label];assert sha(lib)==r['native_library_sha256']
 assert sha(Path(r['client_path']))==r['client_sha256'] and sha(Path(r['native_test_binary']['path']))==r['native_test_binary']['sha256']
 public[label]=error.verify((w/(label+'.log')).read_bytes(),Path(r['public_evidence']),language=language);assert len(public[label]['public_readbacks'])==260
for label,(module,language,count) in regressions.items():
 r=receipts[label];assert sha(lib)==r['native_library_sha256']
 assert sha(Path(r['client_path']))==r['client_sha256'] and sha(Path(r['native_test_binary']['path']))==r['native_test_binary']['sha256']
 public[label]={'expiry':expiry,'cancellation':cancellation}[module].verify((w/(label+'.log')).read_bytes(),Path(r['public_evidence']),language=language);assert len(public[label]['public_readbacks'])==count
runtime=json.loads((w/'FOREIGN_COMMIT_ERROR_KOTLIN_RUNTIME.json').read_text())
for path,h in runtime['runtime_jars'].items():assert sha(Path(path))==h,path
saved=w/'foreign-commit-error-binaries-2a1d5ada';saved.mkdir()
for path,name in [(lib,lib.name),(Path(receipts[flows['C']]['native_test_binary']['path']),'foreign-witness-test')]+[(Path(receipts[label]['client_path']),language.lower()+'-client') for language,label in flows.items()]:shutil.copy2(path,saved/name)
(saved/'kotlin-runtime').mkdir()
for path in runtime['runtime_jars']:shutil.copy2(path,saved/'kotlin-runtime'/Path(path).name)
binaries={str(p.relative_to(saved)):sha(p) for p in saved.rglob('*') if p.is_file()}
dest=c/'research/sdk-alpha1/evidence/20261004-foreign-commit-error-2a1d5ada';dest.mkdir()
for label in labels:
 shutil.copy2(w/(label+'.json'),dest/(label+'.json'))
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for label in ['foreign-commit-error-actionlint-01','foreign-commit-loss-actionlint-baseline']:
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for label,report in public.items():
 folder=Path(receipts[label]['public_evidence']);raw=io.BytesIO()
 with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT) as archive:
  for name,h in sorted(report['public_readbacks'].items()):
   data=(folder/name).read_bytes();assert hashlib.sha256(data).hexdigest()==h
   member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o600;member.mtime=0;archive.addfile(member,io.BytesIO(data))
 (dest/(label+'-public.tar.gz')).write_bytes(gzip.compress(raw.getvalue(),mtime=0))
 (dest/(label+'-public.json')).write_text(json.dumps(report,indent=2)+'\n')
for name in ['run-commit-error-flow.py','run-commit-loss-quality.py','run-commit-error-language-build.py','run-commit-error-kotlin-consumer.py','run-commit-error-cancellation-regression.py','run-commit-loss-flow.py','run-ci-preflight.py','seal-foreign-commit-error.py','FOREIGN_COMMIT_ERROR_KOTLIN_RUNTIME.json']:
 shutil.copy2(w/name,dest/name)
qualification=dict(completed=False,foreign_commit_error_component_verified=True,source_commit=source,source_hashes=hashes,compiled_native_inputs=compiled,
 macos_scope='Apple Silicon only',candidate_c_exports=73,product_abi2_and_native_engine_unchanged=True,c_unit_tests=9,swift_unit_tests=28,reader_cohort_codeql_tests=90,ci_wiring_tests=1,
 actual_error_return_cases=12,error_public_files=780,prior_sigkill_regression_cases=12,regression_public_files=856,total_public_files=1636,
 binaries=binaries,binary_archive_directory=str(saved),
 scope='C Swift Kotlin actual Commit returns exactly218 after witness durable Applied with a withheld TCP prefix or encrypted mutualTLS reply. Same-handle Closed, C output sentinel unchanged, explicit close and normal exit. Fresh original Pending is verified before native fresh Applied Status; live/real-expired recovery reaches exact target and one ACK. Unique original Commit and read-only retry; same native engine, current-source development evidence only.',
 kotlin_scope='Changed consumer compiled with warning-mode fail against unchanged hash-verified private Maven wrapper; previous25 wrapper unit tests not rerun for the CLI-only change.',
 regression_scope='Current shared fault selectors preserve C four-case policy-expiry SIGKILL/Closed workflow and Swift eight-case target-free cancellation/Status/ACK SIGKILL workflow; every public file reread.',
 local_environment_limits=['Full repository suite not rerun; prior6 publication-tool checks reject actual group-writable /Users/bill ancestry; guard and permissions unchanged','actionlint reports same2 unknown ubuntu-26.04 labels as44c9predecessor baseline; no new findings'],
 hosted_ci_for_new_candidate='Not dispatched at seal time; previous44c9fullCI37232506398 andCodeQL37232506434 stillrunning at last check',release_claim_eligible=False,
 remaining=['Exact current-source installed Debug/Release C Swift Kotlin Serial/G1 and fullCI','Remaining lifecycle preparation/process-loss/concurrency boundaries, authority renewal, device/root replacement and upgrade path','Android root cause/stablecleanup: raw bulkcopy/offline nowreproduced without package installation; no SDKexecution required in that fixture, actual transport layer unproven','Physical platform/current and minimum devices, independent implementation/endpoint, retained-secret PQ recovery analysis, full-path performance and external review, full0.2.0release gates'])
(dest/'QUALIFICATION.json').write_text(json.dumps(qualification,indent=2)+'\n')
manifest={str(p.relative_to(dest)):sha(p) for p in dest.rglob('*') if p.is_file()};(dest/'MANIFEST.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
for n,h in manifest.items():assert sha(dest/n)==h
print(json.dumps(dict(path=str(dest),source_commit=source,files=len(manifest),manifest_sha256=sha(dest/'MANIFEST.json'),release_claim_eligible=False),indent=2))
