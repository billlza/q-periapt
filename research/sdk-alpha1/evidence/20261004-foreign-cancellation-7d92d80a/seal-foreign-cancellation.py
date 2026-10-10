"""Seal actual foreign cancellation without claiming installed/release qualification."""
from pathlib import Path
import gzip,hashlib,io,json,re,shutil,subprocess,sys,tarfile
w=Path(__file__).resolve().parent;i=w.parent/'credential-lifecycle-integration'
source='7d92d80a4b6b217c7f571ff336df68bf80edbdfc';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=i,text=True).strip()==source
assert subprocess.check_output(['git','status','--porcelain'],cwd=i,text=True)==''
flows={'C':'cancellation-foreign-c-flow-04','Swift':'cancellation-foreign-swift-flow-02','Kotlin':'cancellation-foreign-kotlin-flow-02'}
labels=list(flows.values())+['cancellation-foreign-c-quality-02','cancellation-foreign-swift-build-02','cancellation-foreign-kotlin-build-02','cancellation-foreign-fixture-regression-01','cancellation-foreign-codeql-tests-01','cancellation-foreign-readers-04','cancellation-foreign-source-01']
receipts={};sources={}
for label in labels:
 r=json.loads((w/(label+'.json')).read_text());assert r['completed'],label
 assert r.get('returncode',0)==0 and all(x['exit']==0 for x in r.get('records',[])),label
 assert sha(w/(label+'.log'))==r['log_sha256'],label
 for name,value in (r.get('source_hashes',{})|r.get('harness_hashes',{})).items():
  assert sha(i/name)==value,(label,name)
  sources[name]=value
 receipts[label]=r
assert receipts['cancellation-foreign-readers-04']['observed_test_summary'][0][0]=='67'
assert receipts['cancellation-foreign-codeql-tests-01']['observed_test_summary'][0][0]=='43'
assert receipts['cancellation-foreign-source-01']['source_commit']==source
assert 'test result: ok. 9 passed;' in (w/'cancellation-foreign-c-quality-02.log').read_text()
assert 'Executed 28 tests, with 0 failures' in (w/'cancellation-foreign-swift-build-02.log').read_text()
assert receipts['cancellation-foreign-kotlin-build-02']['owner_tests']['tests']==25
assert receipts['cancellation-foreign-fixture-regression-01']['test_summaries']==['1','1','1']
# Native implementation has not changed since its previous 490-test qualification.
assert subprocess.check_output(['git','diff','6419be2eecc0ec6a236d7cdff7df571a158f6501',source,'--','research/continuity-identity-candidate'],cwd=i)==b''
lib=w/'history-witness-foreign/native/libq_periapt_continuity_c_consumer.dylib'
production=json.loads((w/'cancellation-foreign-c-build-02.json').read_text())
assert production['completed'] and sha(lib)==production['native_library_sha256']
production_inputs={n:h for n,h in production['source_hashes'].items() if n.startswith(('bindings/c/ContinuityPackageConsumer/src/','research/continuity-identity-candidate/src/')) or n=='bindings/c/ContinuityPackageConsumer/qpc_owner.h'}
assert production_inputs
for n,h in production_inputs.items():assert sha(i/n)==h,n
for n,h in sources.items():assert hashlib.sha256(subprocess.check_output(['git','show',source+':'+n],cwd=i)).hexdigest()==h,n
sys.path.insert(0,str(i/'artifact'))
import continuity_c_consumer as c
import continuity_witnessed_cancellation as reader
symbols=subprocess.check_output(['/usr/bin/nm','-gU',str(lib)],text=True)
assert {line.split()[-1].removeprefix('_') for line in symbols.splitlines() if line.strip()}==c.EXPORTS
assert len(c.EXPORTS)==73 and subprocess.check_output(['/usr/bin/lipo','-archs',str(lib)],text=True).strip()=='arm64'
public={}
for language,label in flows.items():
 r=receipts[label];assert sha(lib)==r['native_library_sha256']
 assert sha(Path(r['client_path']))==r['client_sha256']
 assert sha(Path(r['native_test_binary']['path']))==r['native_test_binary']['sha256']
 public[label]=reader.verify((w/(label+'.log')).read_bytes(),Path(r['public_evidence']),language=language)
 assert len(public[label]['public_readbacks'])==544
runtime=json.loads((w/'FOREIGN_CANCELLATION_KOTLIN_RUNTIME.json').read_text())
for p,h in runtime['runtime_jars'].items():assert sha(Path(p))==h,p
saved=w/'foreign-cancellation-binaries-7d92d80a';saved.mkdir()
for p,name in [(lib,lib.name),(Path(receipts[flows['C']]['native_test_binary']['path']),'foreign-witness-test')]+[(Path(receipts[label]['client_path']),language.lower()+'-client') for language,label in flows.items()]:shutil.copy2(p,saved/name)
(saved/'kotlin-runtime').mkdir()
for p in runtime['runtime_jars']:shutil.copy2(p,saved/'kotlin-runtime'/Path(p).name)
binaries={str(p.relative_to(saved)):sha(p) for p in saved.rglob('*') if p.is_file()}
dest=i/'research/sdk-alpha1/evidence/20261004-foreign-cancellation-7d92d80a';dest.mkdir()
for label in labels+['cancellation-foreign-c-quality-01','cancellation-foreign-c-build-02','cancellation-foreign-kotlin-consumer-01']:
 shutil.copy2(w/(label+'.json'),dest/(label+'.json'))
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for label in ['cancellation-foreign-readers-02','cancellation-foreign-readers-03','cancellation-foreign-format-01']:
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for p in w.glob('cancellation-foreign-kotlin-build-02-TEST-*.xml'):shutil.copy2(p,dest/p.name)
for label,report in public.items():
 folder=Path(receipts[label]['public_evidence']);raw=io.BytesIO()
 with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT) as archive:
  for name,h in sorted(report['public_readbacks'].items()):
   data=(folder/name).read_bytes();assert hashlib.sha256(data).hexdigest()==h
   member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o600;member.mtime=0;archive.addfile(member,io.BytesIO(data))
 (dest/(label+'-public.tar.gz')).write_bytes(gzip.compress(raw.getvalue(),mtime=0))
 (dest/(label+'-public.json')).write_text(json.dumps(report,indent=2)+'\n')
for name in ['run-cancellation-foreign-flow.py','run-cancellation-c-quality.py','run-cancellation-fixture-regression.py','run-cancellation-readers.py','run-foreign-cancellation-codeql-tests.py','run-history-foreign.py','run-cancellation-kotlin-consumer.py','seal-foreign-cancellation.py','FOREIGN_CANCELLATION_KOTLIN_RUNTIME.json','HOSTED_6419BE2E_PROGRESS.json']:
 shutil.copy2(w/name,dest/name)
qualification=dict(completed=False,foreign_cancellation_component_verified=True,source_commit=source,source_hashes=sources,compiled_native_inputs=production_inputs,
 macos_scope='Apple Silicon only',candidate_c_exports=73,product_ABI2_unchanged=True,c_unit_tests=9,swift_unit_tests=28,kotlin_unit_tests=25,parser_and_cohort_tests=67,codeql_boundary_tests=43,
 actual_cancellation_cases=24,public_files=1632,shared_tls_regression_tests=3,shared_tls_regression_cases='original proposal TCP/TLS Applied/Closed, mutual-TLS registration negative controls, account cleanup including pre-admission failures',
 binaries=binaries,binary_archive_directory=str(saved),native_production_unchanged_from='6419be2eecc0ec6a236d7cdff7df571a158f6501',prior_native_tests=490,
 scope='C, Swift and Kotlin target-free original grant reservation and SIGKILL recovery at signed TCP reply / mutual TLS admission, under real live/expired policy. Exact cancellation scope, failure ordinal, unchanged image, durable Closed before ACK, no-SDK historical cleanup. Shared native engine; no independent implementation claim.',
 repaired_checks=['Shared TLS failed-admission field initially unused in account test binary; final finish validates complete admission accounting without suppressions','Synthetic live-policy fixture initially encoded the expired interval; fixture corrected and all 67 parser/cohort tests passed'],
 all_local_repository_checks_passed=False,full_repository_suite_this_head='not rerun; changed-boundary tests and source gate passed; hosted exact-head full suite required',prior_unresolved_local_environment='Six publication-tool tests on prior head rejected group-writable real /Users/bill ancestry. Permissions, guard and tests were not relaxed.',
 source_gate_not_release_qualification=True,hosted_ci_for_this_candidate='not yet dispatched at sealing',release_claim_eligible=False,
 remaining=['Current-head installed archive C/Swift/Kotlin execution and CI','Android after-copy transport root cause/stable cleanup; previous counterexample remains open despite newer successes','Complete credential/policy/witness renewal, device/root replacement and upgrade lifecycle','Physical platform validation, independent implementation/endpoint evidence, persistent compromise recovery proof and actual-path performance, external review and full 0.2.0 release gates'])
(dest/'QUALIFICATION.json').write_text(json.dumps(qualification,indent=2)+'\n')
manifest={str(p.relative_to(dest)):sha(p) for p in dest.rglob('*') if p.is_file()};(dest/'MANIFEST.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
for n,h in manifest.items():assert sha(dest/n)==h
print(json.dumps(dict(destination=str(dest),manifest_sha256=sha(dest/'MANIFEST.json'),files=len(manifest),public_files=1632,source_commit=source,release_claim_eligible=False),indent=2))
