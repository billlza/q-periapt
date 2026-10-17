"""Seal native target-free cancellation and existing three-language compatibility.

This does not qualify new foreign cancellation entry points, devices or release.
"""
from pathlib import Path
import gzip,hashlib,io,json,re,shutil,subprocess,sys,tarfile
w=Path(__file__).resolve().parent;i=w.parent/'credential-lifecycle-integration'
commit='6b7a940ef4354692f311fcaee13164ecb5b26be0';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=i,text=True).strip()==commit
assert subprocess.check_output(['git','status','--porcelain'],cwd=i,text=True)==''
base='cancellation-enrollment-'
labels=[base+n for n in ['native-regression-01','tests-03','write-intent-01','clippy-04','min-clippy-02','rustdoc-01','doctests-01','format-check-02','source-03','codeql-tests-02','c-build-01','swift-build-01','kotlin-build-01']]
flows=[base+lang+'-'+kind+'-flow-01' for lang in ['c','swift','kotlin'] for kind in ['legacy','expiry']]
labels+=flows
receipts={};sources={};test_import_only=[]
for label in labels:
 r=json.loads((w/(label+'.json')).read_text());assert r['completed'],label
 assert all(r.get(key,0)==0 for key in ('exit','returncode')),label
 assert all(x['exit']==0 for x in r.get('records',[])),label
 if 'log_sha256' in r:assert sha(w/(label+'.log'))==r['log_sha256'],label
 for name,value in (r.get('source_hashes',{})|r.get('harness_hashes',{})).items():
  if name.startswith(('src/','tests/','examples/')):name='research/continuity-identity-candidate/'+name
  path=i/name;current=sha(path)
  if current!=value:
   assert label in (base+'tests-03',base+'c-build-01'),(label,name)
   assert name=='research/continuity-identity-candidate/src/enrollment/witness_cancellation_tests.rs',name
   # Exactly rustfmt import order, after these two completed runs. No executable
   # test statement, production source or FFI source changed.
   previous=path.read_bytes().replace(b'use crate::AnchorCredentialRenewalCancellation as Cancellation;\nuse redb::ReadableTable;',b'use redb::ReadableTable;\nuse crate::AnchorCredentialRenewalCancellation as Cancellation;')
   assert hashlib.sha256(previous).hexdigest()==value,(label,name)
   test_import_only.append(dict(receipt=label,file=name,old_sha256=value,current_sha256=current))
  sources[name]=current
 receipts[label]=r
for name,value in sources.items():assert hashlib.sha256(subprocess.check_output(['git','show',commit+':'+name],cwd=i)).hexdigest()==value,name
assert receipts[base+'native-regression-01']['passed_tests']==490
assert receipts[base+'tests-03']['passed_tests']==21
assert receipts[base+'write-intent-01']['passed_tests']==8
assert receipts[base+'doctests-01']['passed_tests']==2
assert receipts[base+'source-03']['source_commit']==commit
artifact=json.loads((w/(base+'artifact-tests-01.json')).read_text())
assert not artifact['completed'] and artifact['returncode']==1
assert artifact['observed_test_summary'][0][0]==2577
artifact_log=(w/(base+'artifact-tests-01.log')).read_text()
expected_failures={'test_tracked_inventory_is_nonempty_and_nul_terminated','test_production_lock_is_persistent_exclusive_and_outside_worktrees','test_production_lock_rejects_symlink_root_and_lock_hardlink','test_production_uploader_consumes_only_exact_stdin_bytes','test_production_uploader_passes_explicit_proxy_without_ambient_trust','test_real_publish_cli_passes_derived_authority_to_lock_and_uploader','test_sdk_and_legacy_namespace_locks_are_independent_and_cannot_be_cross_selected'}
assert set(re.findall(r'^(test_\w+) \([^\n]+\) \.\.\. (?:ERROR|FAIL)$',artifact_log,re.M))==expected_failures
assert 'FAILED (failures=1, errors=6)' in artifact_log
assert 'publication account home ancestry is not trusted' in artifact_log
assert receipts[base+'codeql-tests-02']['completed']
assert receipts[base+'codeql-tests-02']['observed_test_summary'][0][0]=='43'

log=(w/(base+'tests-03.log')).read_text()
for line in ['cancellation journal reservation cuts=4','cancellation configuration reservation cuts=6','cancellation intent retirement cuts=6','cancellation terminal configuration cuts=8','witness enrollment real process cuts=12']:
 assert line in log,line
assert 'Executed 27 tests, with 0 failures' in (w/(base+'swift-build-01.log')).read_text()
assert receipts[base+'kotlin-build-01']['owner_tests']['tests']==24
assert 'test result: ok. 9 passed;' in (w/(base+'c-build-01.log')).read_text()
for label,count in [('native-regression-01',490),('tests-03',21),('write-intent-01',8),('doctests-01',2)]:
 assert re.findall(r'test result: ok\. (\d+) passed;', (w/(base+label+'.log')).read_text())==[str(count)]
sys.path.insert(0,str(i/'artifact'))
import continuity_c_consumer as c
import continuity_witnessed_renewal as legacy
import continuity_witnessed_policy_expiry as expiry
lib=w/'history-witness-foreign/native/libq_periapt_continuity_c_consumer.dylib'
symbols=subprocess.check_output(['/usr/bin/nm','-gU',str(lib)],text=True)
assert {line.split()[-1].removeprefix('_') for line in symbols.splitlines() if line.strip()}==c.EXPORTS
assert len(c.EXPORTS)==72 and subprocess.check_output(['/usr/bin/lipo','-archs',str(lib)],text=True).strip()=='arm64'
public={}
for label in flows:
 r=receipts[label];assert sha(lib)==r['native_library_sha256']
 assert sha(Path(r['client_path']))==r['client_sha256']
 assert sha(Path(r['native_test_binary']['path']))==r['native_test_binary']['sha256']
 reader=expiry if '-expiry-' in label else legacy
 public[label]=reader.verify((w/(label+'.log')).read_bytes(),Path(r['public_evidence']))
reuse=json.loads((w/'CANCELLATION_ENROLLMENT_KOTLIN_REUSE.json').read_text())
kroot=w/'history-witness-foreign/consumer-policy-expiry-kotlin-consumer-01/build/install/continuity-installed-consumer/lib'
for name,h in reuse['actual_runtime_jar_sha256'].items():assert sha(kroot/name)==h
saved=w/'enrollment-cancellation-binaries-6b7a940e';saved.mkdir()
native_binary=w.parent/'continuity-renewal-journal/debug/deps/q_periapt_continuity_identity_candidate-c4e516a635a68dd1'
for src,name in [(native_binary,'native-regression-test'),(lib,lib.name),(Path(receipts[base+'c-legacy-flow-01']['native_test_binary']['path']),'foreign-witness-test')]+[(Path(receipts[base+lang+'-legacy-flow-01']['client_path']),lang+'-client') for lang in ['c','swift','kotlin']]:shutil.copy2(src,saved/name)
(saved/'kotlin-runtime').mkdir()
for name in reuse['actual_runtime_jar_sha256']:shutil.copy2(kroot/name,saved/'kotlin-runtime'/name)
binaries={str(p.relative_to(saved)):sha(p) for p in saved.rglob('*') if p.is_file()}
dest=i/'research/sdk-alpha1/evidence/20261004-enrollment-cancellation-6b7a940e';dest.mkdir()
failures=[base+n for n in ['initial-01','tests-02','clippy-01','clippy-02','format-check-01','artifact-tests-01','codeql-tests-01']]
for label in labels+failures:
 shutil.copy2(w/(label+'.json'),dest/(label+'.json'))
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for p in w.glob(base+'kotlin-build-01-TEST-*.xml'):shutil.copy2(p,dest/p.name)
for label,report in public.items():
 folder=Path(receipts[label]['public_evidence']);raw=io.BytesIO()
 with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT) as archive:
  for name,h in sorted(report['public_readbacks'].items()):
   data=(folder/name).read_bytes();assert hashlib.sha256(data).hexdigest()==h
   member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o600;member.mtime=0;archive.addfile(member,io.BytesIO(data))
 (dest/(label+'-public.tar.gz')).write_bytes(gzip.compress(raw.getvalue(),mtime=0))
 (dest/(label+'-public.json')).write_text(json.dumps(report,indent=2)+'\n')
for name in ['run-development.py','run-native-quality.py','run-ci-preflight.py','run-history-foreign.py','run-history-witness-flow.py','run-policy-expiry-foreign.py','run-cancellation-doctests.py','run-cancellation-codeql-tests.py','seal-enrollment-cancellation.py','CANCELLATION_ENROLLMENT_ARTIFACT_FAILURES.json','CANCELLATION_ENROLLMENT_FOREIGN_NEXT_WORK.json','CANCELLATION_ENROLLMENT_KOTLIN_REUSE.json','CI_29C4_ANDROID16K_DIAGNOSIS.json','HOSTED_29C4DF42_PROGRESS.json','ci-29c4-android16k-push-diagnostics.zip']:
 shutil.copy2(w/name,dest/name)
for name in ['ci-29c4-android16k-push-failure.log',base+'artifact-diagnosis-01.log']:
 (dest/(name+'.gz')).write_bytes(gzip.compress((w/name).read_bytes(),mtime=0))
qualification=dict(completed=False,native_component_verified=True,all_local_checks_passed=False,source_commit=commit,native_implementation_commit='59a0bfb46690de0d739423af6b0c0fa32a0f437e',source_hashes=sources,native_tests=490,
 artifact_tests=dict(run=2577,passed=2570,failed=7,source_commit=artifact['source_commit'],codeql_inventory_failure_fixed_and_retested=True,remaining_environment_failures=6,reason='Unchanged production publication guard rejects group-writable actual passwd-home ancestor /Users/bill mode0770. User permissions not modified; guard/test strength unchanged; hosted exact-head qualification remains required.'),
 focused_enrollment_tests=21,focused_write_intent_tests=8,cancellation_sync_cuts=24,process_cuts=dict(all=12,new_cancellation=4),historical_type_compile_fail_tests=2,
 c_unit_tests=9,swift_unit_tests=27,kotlin_unit_tests=24,legacy_foreign_cases=12,real_policy_expiry_foreign_cases=12,
 public_files=sum(len(v['public_readbacks']) for v in public.values()),candidate_c_exports=72,product_ABI2_unchanged=True,macos_scope='Apple Silicon only',
 pre_format_test_only_receipts=test_import_only,binaries=binaries,binary_archive_directory=str(saved),
 scope='Native target-free QPWINT03 reservation and QPENST05 original enrollment coordination, with durable Closed before ACK. Existing proposal flows verified with current native engine through C, Swift and Kotlin. New cancellation FFI and actual foreign cancellation flows remain unimplemented.',
 android_counterexample=dict(head='29c4df42',push_run=37219990138,failed_job=111489291014,PR_run=37219996163,PR_android_runtime_and_replay_passed=True,cleanup_stability_qualified=False,transport_root_cause='unproven'),
 source_gate_not_release_qualification=True,hosted_ci_for_this_candidate='not yet dispatched at sealing',release_claim_eligible=False,
 remaining=['Cancellation FFI, controlled wrappers, real foreign cancellation and expiry flows','Android after-copy transport diagnosis and stable cleanup','Six local publication-tool tests blocked by untrusted current account-home ancestry; exact-head hosted CI still required','Physical platform validation, independent implementation/endpoint evidence, product interface admission, persistent compromise recovery proof and performance, external review and full 0.2.0 release gates'])
(dest/'QUALIFICATION.json').write_text(json.dumps(qualification,indent=2)+'\n')
manifest={str(p.relative_to(dest)):sha(p) for p in dest.rglob('*') if p.is_file()};(dest/'MANIFEST.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
for n,h in manifest.items():assert sha(dest/n)==h
print(json.dumps(dict(destination=str(dest),manifest_sha256=sha(dest/'MANIFEST.json'),files=len(manifest),public_files=qualification['public_files'],source_commit=commit,release_claim_eligible=False),indent=2))
