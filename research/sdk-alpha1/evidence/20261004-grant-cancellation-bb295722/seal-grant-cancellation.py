"""Seal the native cancellation primitive and the Android diagnostic correction.

This is not original-enrollment cancellation or all-platform qualification.
"""
from pathlib import Path
import hashlib,json,gzip,io,tarfile,shutil,subprocess,sys,re
w=Path(__file__).resolve().parent;i=w.parent/'credential-lifecycle-integration'
commit='bb295722609b78c19b51d3c56d7e22d4b2f01c3d';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=i,text=True).strip()==commit
assert subprocess.check_output(['git','status','--porcelain'],cwd=i,text=True)==''
checks=['grant-cancellation-native-regression-01','grant-cancellation-clippy-02','grant-cancellation-min-clippy-02',
        'grant-cancellation-rustdoc-01','grant-cancellation-format-01','grant-cancellation-source-01',
        'grant-cancellation-tests-01','grant-cancellation-c-build-01','grant-cancellation-c-legacy-flow-01',
        'grant-cancellation-c-expiry-flow-01','android-cleanup-deadline-tests-02']
receipts={};sources={}
for label in checks:
 r=json.loads((w/(label+'.json')).read_text());assert r['completed'],label
 assert all(r.get(key,0)==0 for key in ('exit','returncode')),label
 assert all(v['exit']==0 for v in r.get('records',[])),label
 if 'log_sha256' in r: assert sha(w/(label+'.log'))==r['log_sha256'],label
 if r.get('passed_tests') is not None:
  counts=re.findall(r'test result: ok\. (\d+) passed;', (w/(label+'.log')).read_text())
  assert counts and sum(map(int,counts))==r['passed_tests'],label
 for name,value in (r.get('source_hashes',{})|r.get('harness_hashes',{})).items():
  if name.startswith(('src/','tests/','examples/')):name='research/continuity-identity-candidate/'+name
  assert sha(i/name)==value,(label,name)
  sources[name]=value
 receipts[label]=r
assert receipts['grant-cancellation-native-regression-01']['passed_tests']==480
assert receipts['grant-cancellation-tests-01']['observed_test_summary'][0][0]==2577
assert receipts['grant-cancellation-source-01']['source_commit']==commit
assert receipts['android-cleanup-deadline-tests-02']['test_count']==191
for name,value in sources.items():assert hashlib.sha256(subprocess.check_output(['git','show',commit+':'+name],cwd=i)).hexdigest()==value
# Rustdoc compile-fail inputs are unchanged. The later Clippy correction changed
# checked indexing only in cfg(test) modules not compiled by these doc examples.
doc=json.loads((w/'grant-cancellation-doctests-01.json').read_text());assert doc['completed'] and doc['passed_tests']==2
doc_test_differences=[]
for name,value in doc['source_hashes'].items():
 if sha(i/'research/continuity-identity-candidate'/name)!=value:
  assert name in ('src/identity/renewal/tests.rs','src/anchor/store/renewal_tests.rs'),name
  doc_test_differences.append(name)
doc_log=(w/'grant-cancellation-doctests-01.log').read_text()
assert 'HistoricalCredentialRenewal' in doc_log and 'HistoricalSessionPolicy' in doc_log
assert re.findall(r'test result: ok\. (\d+) passed;',doc_log)==['2']
redgreen=json.loads((w/'ANDROID_CLEANUP_DEADLINE_RED_GREEN.json').read_text())
assert redgreen['baseline']['errors']==1 and not redgreen['baseline']['passed'] and redgreen['current']['passed']
for stage in ('baseline','current'):
 assert sha(w/('android-cleanup-deadline-'+stage+'-redgreen-01.log'))==redgreen[stage]['log_sha256']
sys.path.insert(0,str(i/'artifact'))
import continuity_c_consumer as c
import continuity_witnessed_renewal as legacy
import continuity_witnessed_policy_expiry as expiry
lib=w/'history-witness-foreign/native/libq_periapt_continuity_c_consumer.dylib'
symbols=subprocess.check_output(['/usr/bin/nm','-gU',str(lib)],text=True)
assert {line.split()[-1].removeprefix('_') for line in symbols.splitlines() if line.strip()}==c.EXPORTS
assert len(c.EXPORTS)==72 and subprocess.check_output(['/usr/bin/lipo','-archs',str(lib)],text=True).strip()=='arm64'
public={}
for suffix,reader in [('legacy-flow-01',legacy),('expiry-flow-01',expiry)]:
 label='grant-cancellation-c-'+suffix;r=receipts[label]
 assert r['native_library_sha256']==sha(lib) and sha(Path(r['client_path']))==r['client_sha256']
 assert sha(Path(r['native_test_binary']['path']))==r['native_test_binary']['sha256']
 public[label]=reader.verify((w/(label+'.log')).read_bytes(),Path(r['public_evidence']))
assert sum(len(r['public_readbacks']) for r in public.values())==572
saved=w/'grant-cancellation-binaries-bb295722';saved.mkdir()
for source,name in [(w.parent/'continuity-renewal-journal/debug/deps/q_periapt_continuity_identity_candidate-c4e516a635a68dd1','native-regression-test'),
 (lib,lib.name),(Path(receipts['grant-cancellation-c-legacy-flow-01']['native_test_binary']['path']),'c-witness-test'),
 (Path(receipts['grant-cancellation-c-legacy-flow-01']['client_path']),'c-client')]:shutil.copy2(source,saved/name)
binaries={str(p):sha(p) for p in saved.iterdir()}
dest=i/'research/sdk-alpha1/evidence/20261004-grant-cancellation-bb295722';dest.mkdir()
for label in checks+['grant-cancellation-doctests-01']:
 shutil.copy2(w/(label+'.json'),dest/(label+'.json'))
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for label in ('grant-cancellation-store-01','grant-cancellation-store-03','grant-cancellation-clippy-01','grant-cancellation-min-clippy-01'):
 shutil.copy2(w/(label+'.json'),dest/(label+'.json'))
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for label,report in public.items():
 folder=Path(receipts[label]['public_evidence']);raw=io.BytesIO()
 with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT) as archive:
  for name,digest in sorted(report['public_readbacks'].items()):
   data=(folder/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest
   member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o600;member.mtime=0;archive.addfile(member,io.BytesIO(data))
 (dest/(label+'-public.tar.gz')).write_bytes(gzip.compress(raw.getvalue(),mtime=0))
 (dest/(label+'-public.json')).write_text(json.dumps(report,indent=2)+'\n')
for name in ('ANDROID_CLEANUP_DEADLINE_RED_GREEN.json','CI_6053_ANDROID16K_DIAGNOSIS.json',
 'GRANT_CANCELLATION_ENROLLMENT_NEXT_WORK.json','ci-6053-android16k-diagnostics.zip',
 'run-development.py','run-native-quality.py','run-history-foreign.py','run-history-witness-flow.py','run-policy-expiry-foreign.py',
 'run-ci-preflight.py','seal-grant-cancellation.py'):
 shutil.copy2(w/name,dest/name)
for name in ('ci-6053-android16k-failure.log','android-cleanup-deadline-baseline-redgreen-01.log','android-cleanup-deadline-current-redgreen-01.log'):
 (dest/(name+'.gz')).write_bytes(gzip.compress((w/name).read_bytes(),mtime=0))
qualification=dict(completed=True,source_commit=commit,source_hashes=sources,native_tests=480,artifact_tests=2577,
 c_unit_tests=9,c_legacy_flow_cases=4,c_policy_expiry_cases=4,c_public_files=572,android_deadline_tests=191,
 historical_type_compile_fail_tests=2,doc_example_source_unchanged=True,cfg_test_only_changes_since_doctests=doc_test_differences,
 focused_cancel_sync_cuts=8,focused_joint_sync_cuts=22,
 focused_fault_scope='store03 measured8newcancel/ACKcuts and22existingjointcuts; later changes only checked test indexing for strictClippy. Full480run includes both fault tests at finalsource.',
 candidate_exports=72,product_ABI2_unchanged=True,macos='arm64 only',binaries=binaries,
 scope='Native independent grant-only cancellation primitive and historicalgrant reconstruction. Current originalenrollment/foreignowners still lack target-free cancellation reservation/coordination. Existing C renewal/expiry flows verified with the new engine; no new foreign cancellation claim.',
 android=dict(original_CI_head='6053faef',original_job=111478842487,original_failure_preserved=True,
 diagnostic_correction='Only deadline-only read-only package queries become retryable:query-timeout. No package fact is released; structural or mixed failures remain fatal. Budgets, single recovery and exact ownership requirements unchanged.',
 root_disconnect_cause_unproven=True,offline_fixed=False),
 invariants=['grant cancellation contains no target and uses independent domain','no device request creates cancellation',
 'existing proposal preserved inclApplied; no slot/floor-onlyNoCommit','floor+Closed persisttogether witholdoperationalstate unchanged',
 'currentPrepare/newCommit authority not grantedbyHistorical type','ordinaryAdvance/Fence excludeduntilACK; exactoldACKcannoteraseanewslot'],
 remaining=['durable target-free journal reservation and original enrollment terminal-before-ACK recovery',
 'cross-language APIs/installed flows and process-kill matrix for new cancellation',
 'bounded real emulator A/B diagnosis and correction of Android16KiB offline instability',
 'independent protocol implementation, PQ recovery proof, performance, platforms and complete0.2.0 release objective'],
 release_claim_eligible=False,full_goal_complete=False)
(dest/'QUALIFICATION.json').write_text(json.dumps(qualification,indent=2)+'\n')
manifest={str(p.relative_to(dest)):sha(p) for p in sorted(dest.rglob('*')) if p.is_file()}
(dest/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(dict(path=str(dest),manifest_files=len(manifest),manifest_sha256=sha(dest/'MANIFEST.json'),binaries=binaries),indent=2))
