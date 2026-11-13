"""Seal source-bound foreign Commit loss; retain incomplete release gates."""
from pathlib import Path
import gzip,hashlib,io,json,shutil,subprocess,sys,tarfile
w=Path(__file__).resolve().parent;c=Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004')
source='dc1c2fd1d2aa3fb23a3b888009bd5449370ea761'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=c,text=True).strip()
assert git('rev-parse','HEAD')==source and not git('status','--porcelain')
flows={k:'foreign-commit-loss-'+k.lower()+'-flow-01' for k in ['C','Swift','Kotlin']}
labels=list(flows.values())+['foreign-commit-loss-quality-03','foreign-commit-loss-relay-regression-01','foreign-commit-loss-readers-01','foreign-commit-loss-codeql-02','foreign-commit-loss-ci-wiring-02','foreign-commit-loss-source-01']
receipts={};hashes={}
for label in labels:
 r=json.loads((w/(label+'.json')).read_text());assert r['completed'],label
 assert r.get('returncode',0)==0 and all(x['exit']==0 for x in r.get('records',[])),label
 assert sha(w/(label+'.log'))==r['log_sha256'],label
 for n,h in (r.get('source_hashes',{})|r.get('harness_hashes',{})).items():
  assert sha(c/n)==h,(label,n)
  hashes[n]=h
 receipts[label]=r
assert receipts['foreign-commit-loss-readers-01']['observed_test_summary'][0][0]==41
assert receipts['foreign-commit-loss-codeql-02']['observed_test_summary'][0][0]==43
assert receipts['foreign-commit-loss-ci-wiring-02']['observed_test_summary'][0][0]==1
assert receipts['foreign-commit-loss-source-01']['source_commit']==source
assert receipts['foreign-commit-loss-relay-regression-01']['test_summaries']==['2','1','1']
assert b'test result: ok. 9 passed;' in (w/'foreign-commit-loss-quality-03.log').read_bytes()
unchanged=['research/continuity-identity-candidate/src','bindings/c/ContinuityPackageConsumer/src','bindings/c/ContinuityPackageConsumer/qpc_owner.h','bindings/c/ContinuityPackageConsumer/client.c','bindings/c/ContinuityPackageConsumer/enrollment_client.c','bindings/c/ContinuityPackageConsumer/recovery_client.c','bindings/c/ContinuityPackageConsumer/opening_client.c','bindings/swift/ContinuityPackageConsumer','bindings/kotlin/ContinuityPackageConsumer','crates/q-periapt-sdk','crates/q-periapt-ffi']
assert not git('diff','7d92d80a4b6b217c7f571ff336df68bf80edbdfc',source,'--',*unchanged)
for n,h in hashes.items():assert hashlib.sha256(subprocess.check_output(['git','show',source+':'+n],cwd=c)).hexdigest()==h,n
lib=w/'history-witness-foreign/native/libq_periapt_continuity_c_consumer.dylib'
production=json.loads((w/'cancellation-foreign-c-build-02.json').read_text());assert production['completed'] and sha(lib)==production['native_library_sha256']
compiled={n:h for n,h in production['source_hashes'].items() if n.startswith(('bindings/c/ContinuityPackageConsumer/src/','research/continuity-identity-candidate/src/')) or n=='bindings/c/ContinuityPackageConsumer/qpc_owner.h'}
assert compiled
for n,h in compiled.items():assert sha(c/n)==h,n
prior_doc_changes=[]
for receipt in ['cancellation-foreign-swift-build-02.json','cancellation-foreign-kotlin-consumer-01.json']:
 r=json.loads((w/receipt).read_text());assert r['completed']
 for n,h in r['source_hashes'].items():
  if sha(c/n)!=h:
   assert receipt=='cancellation-foreign-kotlin-consumer-01.json' and n=='bindings/kotlin/ContinuityPackageConsumer/README.md'
   assert h=='ddc070b119a2a39ea96d58fad2beda026ada177f3ed4a90c5039d19ec27c42d2'
   assert hashlib.sha256(subprocess.check_output(['git','show','7d92d80a:'+n],cwd=c)).hexdigest()==sha(c/n)
   prior_doc_changes.append(dict(receipt=receipt,path=n,compiled_receipt_sha256=h,unchanged_since_7d92d80a_sha256=sha(c/n),scope='README documentation updated before previous source seal; not compiled Kotlin source'))
sys.path.insert(0,str(c/'artifact'))
import continuity_witnessed_policy_expiry as gate
import continuity_c_consumer as abi
symbols=subprocess.check_output(['/usr/bin/nm','-gU',str(lib)],text=True)
assert {s.split()[-1].removeprefix('_') for s in symbols.splitlines() if s.strip()}==abi.EXPORTS and len(abi.EXPORTS)==73
assert subprocess.check_output(['/usr/bin/lipo','-archs',str(lib)],text=True).strip()=='arm64'
public={}
for language,label in flows.items():
 r=receipts[label];assert sha(lib)==r['native_library_sha256']
 assert sha(Path(r['client_path']))==r['client_sha256'] and sha(Path(r['native_test_binary']['path']))==r['native_test_binary']['sha256']
 public[label]=gate.verify((w/(label+'.log')).read_bytes(),Path(r['public_evidence']),language=language)
 assert len(public[label]['public_readbacks'])==312
runtime=json.loads((w/'FOREIGN_CANCELLATION_KOTLIN_RUNTIME.json').read_text())
for path,h in runtime['runtime_jars'].items():assert sha(Path(path))==h,path
saved=w/'foreign-commit-loss-binaries-dc1c2fd1';saved.mkdir()
for path,name in [(lib,lib.name),(Path(receipts[flows['C']]['native_test_binary']['path']),'foreign-witness-test')]+[(Path(receipts[label]['client_path']),language.lower()+'-client') for language,label in flows.items()]:shutil.copy2(path,saved/name)
(saved/'kotlin-runtime').mkdir()
for path in runtime['runtime_jars']:shutil.copy2(path,saved/'kotlin-runtime'/Path(path).name)
binaries={str(p.relative_to(saved)):sha(p) for p in saved.rglob('*') if p.is_file()}
dest=c/'research/sdk-alpha1/evidence/20261004-foreign-commit-loss-dc1c2fd1';dest.mkdir()
for label in labels+['foreign-commit-loss-quality-01','foreign-commit-loss-quality-02']:
 shutil.copy2(w/(label+'.json'),dest/(label+'.json'))
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for label in ['foreign-commit-loss-codeql-01','foreign-commit-loss-ci-wiring-01','foreign-commit-loss-actionlint-01','foreign-commit-loss-actionlint-baseline']:
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for label,report in public.items():
 folder=Path(receipts[label]['public_evidence']);raw=io.BytesIO()
 with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT) as archive:
  for name,h in sorted(report['public_readbacks'].items()):
   data=(folder/name).read_bytes();assert hashlib.sha256(data).hexdigest()==h
   member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o600;member.mtime=0;archive.addfile(member,io.BytesIO(data))
 (dest/(label+'-public.tar.gz')).write_bytes(gzip.compress(raw.getvalue(),mtime=0))
 (dest/(label+'-public.json')).write_text(json.dumps(report,indent=2)+'\n')
for name in ['run-commit-loss-flow.py','run-commit-loss-quality.py','run-commit-loss-relay-regression.py','run-ci-preflight.py','seal-foreign-commit-loss.py','FOREIGN_CANCELLATION_KOTLIN_RUNTIME.json','CI_230F98B6_INSTALLED_RUST_DISPOSITION.json']:
 shutil.copy2(w/name,dest/name)
for p in w.glob('ci-230f98b6-C_WITNESSED_CANCELLATION_*.json'):shutil.copy2(p,dest/p.name)
for p in w.glob('ci-230f98b6-c-witnessed-cancellation-*'):
 if p.suffix in ['.stdout','.stderr']:(dest/(p.name+'.gz')).write_bytes(gzip.compress(p.read_bytes(),mtime=0))
qualification=dict(completed=False,foreign_commit_loss_component_verified=True,source_commit=source,source_hashes=hashes,compiled_native_inputs=compiled,prior_documentation_changes=prior_doc_changes,
 macos_scope='Apple Silicon only',candidate_c_exports=73,product_abi2_unchanged=True,c_unit_tests=9,parser_cohort_tests=41,codeql_boundary_tests=43,ci_wiring_tests=1,shared_tls_regression_tests=4,
 actual_real_expiry_cases=12,actual_foreign_commit_kills=6,public_files=936,binaries=binaries,binary_archive_directory=str(saved),
 scope='C Swift Kotlin original foreign Commit -> witness durable Applied -> withheld TCP prefix or encrypted mutualTLS reply -> reaped SIGKILL -> original local Pending and sealed image retained -> native original-signer fresh Applied Status -> real policy expiry -> fresh foreign historical recovery and one ACK; no new Commit after expiry. Closed controls retained. Same shared native engine, source development evidence only.',
 unchanged_bindings='Prior built C/Swift/Kotlin production source and runtime hashes revalidated; wrappers were not changed or rebuilt for this test-only increment.',
 checked_boundaries=['Bounded encrypted relay shared with prior account reply-loss fixtures; four regressions passed','Native signed Status verification follows child reap and local Pending assertion without enrollment reconciliation','All 936 exported public files reread; public parsers do not verify signatures or secret journal MACs','CI job30minute cancellation retained as cancellation despite completed nested report; all1088 cancellation public files missing from uploaded artifact; upload paths and job allowance corrected for next run'],
 local_environment_limits=['Current full repository suite not rerun; prior6 publication-tool checks rejected actual group-writable /Users/bill ancestry, with guard and permissions unchanged','actionlint reports same2 unknown ubuntu-26.04 runner labels as exact230f98b6 baseline; no new diagnostics'],
 repaired_checks=['Initial validator return/error conversions failed compilation and were fixed without suppressions','New316 trackedRust count initially failed stale315 guide claim; guide corrected and43boundarytests passed','First selected CI test command used a nested fixture class name; corrected actual class and1test passed'],
 hosted_ci_for_new_candidate='Not dispatched at seal time',release_claim_eligible=False,
 remaining=['Exact current-head installed archive Debug/Release C/Swift/Kotlin Serial/G1 and CI evidence uploads','Foreign Commit transport-error return boundary, live-policy lost-result recovery and broader lifecycle cancellation/concurrency boundaries','Android short-exit0 copy/offline root cause and separate captured PackageManager framework fatal; no shared cause established','Full credential/policy/witness renewal, device/root replacement and upgrade lifecycle','Physical devices/current and minimum versions, independent implementation/endpoint, retained-secret PQ recovery proof, actual-path performance and external review, full0.2.0 release gates'])
(dest/'QUALIFICATION.json').write_text(json.dumps(qualification,indent=2)+'\n')
manifest={str(p.relative_to(dest)):sha(p) for p in dest.rglob('*') if p.is_file()};(dest/'MANIFEST.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
for n,h in manifest.items():assert sha(dest/n)==h
print(json.dumps(dict(path=str(dest),source_commit=source,files=len(manifest),manifest_sha256=sha(dest/'MANIFEST.json'),release_claim_eligible=False),indent=2))
