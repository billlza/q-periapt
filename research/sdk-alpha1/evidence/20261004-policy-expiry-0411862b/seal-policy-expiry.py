"""Seal real-expiry development evidence only after exact-source checks finish."""
from pathlib import Path
import gzip, hashlib, io, json, shutil, subprocess, sys, tarfile
w=Path(__file__).resolve().parent;i=w.parent/'credential-lifecycle-integration'
commit='0411862be1b02ee3a5cde57df6ee5b889e7df2c8'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=i,text=True).strip()==commit
assert subprocess.check_output(['git','status','--porcelain'],cwd=i,text=True)==''
sys.path.insert(0,str(i/'artifact'))
import continuity_witnessed_policy_expiry as expiry
import continuity_witnessed_renewal as renewal
import continuity_c_consumer as c
checks=['policy-expiry-c-quality-01','policy-expiry-swift-build-01','policy-expiry-kotlin-consumer-01',
        'policy-expiry-metadata-01','policy-expiry-source-01','policy-expiry-tests-01','policy-expiry-collector-component-01']
checks += ['policy-expiry-'+lang+'-'+mode for lang in ('c','swift','kotlin') for mode in ('flow-02','baseline-01')]
receipts={};bindings={};doc_differences=[]
for label in checks:
 r=json.loads((w/(label+'.json')).read_text());assert r['completed'],label
 assert all(r.get(key,0)==0 for key in ('returncode','exit')),label
 assert all(item['exit']==0 for item in r.get('records',[])),label
 assert sha(w/(label+'.log'))==r['log_sha256'],label
 for name,value in (r.get('source_hashes',{})|r.get('harness_hashes',{})).items():
  actual=sha(i/name)
  if actual!=value:
   assert name.endswith('.md'),(label,name)
   doc_differences.append(dict(receipt=label,file=name,at_execution=value,at_commit=actual))
  else:bindings[name]=value
 receipts[label]=r
for name,value in bindings.items():
 assert hashlib.sha256(subprocess.check_output(['git','show',commit+':'+name],cwd=i)).hexdigest()==value
assert receipts['policy-expiry-tests-01']['observed_test_summary'][0][0]==2572
assert receipts['policy-expiry-source-01']['source_commit']==receipts['policy-expiry-tests-01']['source_commit']==commit
assert receipts['policy-expiry-metadata-01']['observed_test_summary'][0][0]==41
# Only test/consumer/collector/docs changed: no native engine or binding ABI mutation.
unchanged=['research/continuity-identity-candidate/src','bindings/c/ContinuityPackageConsumer/src',
           'bindings/swift/ContinuityPackageConsumer/Sources/QPeriaptContinuity','bindings/kotlin/ContinuityPackageConsumer/src',
           'bindings/c/ContinuityPackageConsumer/qpc_owner.h','crates/q-periapt-ffi','crates/q-periapt-sdk']
assert all((i/name).exists() for name in unchanged)
assert subprocess.check_output(['git','diff','--name-only','bbd0815d',commit,'--',*unchanged],cwd=i,text=True)==''
lib=w/'history-witness-foreign/native/libq_periapt_continuity_c_consumer.dylib'
symbols=subprocess.check_output(['/usr/bin/nm','-gU',str(lib)],text=True)
exports={line.split()[-1].removeprefix('_') for line in symbols.splitlines() if line.strip()}
assert exports==c.EXPORTS and len(exports)==72
assert subprocess.check_output(['/usr/bin/lipo','-archs',str(lib)],text=True).strip()=='arm64'
public={};public_directories={}
for lang in ('c','swift','kotlin'):
 for mode,reader,count in [('flow-02',expiry,300),('baseline-01',renewal,272)]:
  label='policy-expiry-'+lang+'-'+mode;r=receipts[label]
  assert sha(lib)==r['native_library_sha256'] and sha(Path(r['client_path']))==r['client_sha256']
  assert sha(Path(r['native_test_binary']['path']))==r['native_test_binary']['sha256']
  report=reader.verify((w/(label+'.log')).read_bytes(),Path(r['public_evidence']),language={'c':'C','swift':'Swift','kotlin':'Kotlin'}[lang])
  assert len(report['public_readbacks'])==count
  public[label]=report;public_directories[label]=Path(r['public_evidence'])
label='policy-expiry-collector-component-01'
folder=w/(label+'-runtime')/'c-witnessed-policy-expiry-debug-runtime'
report=expiry.verify((w/(label+'.log')).read_bytes(),folder)
component=json.loads((w/(label+'-output')/'C_WITNESSED_POLICY_EXPIRY_DEBUG.json').read_text())
assert report=={k:v for k,v in component.items() if k not in ('binary','foreign_client_sha256')}
assert len(report['public_readbacks'])==300 and receipts[label]['public_files']==300
assert component['binary']['sha256']==receipts['policy-expiry-c-flow-02']['native_test_binary']['sha256']
assert component['foreign_client_sha256']==receipts['policy-expiry-c-flow-02']['client_sha256']
public[label]=report;public_directories[label]=folder
saved=w/'policy-expiry-binaries-0411862b';saved.mkdir()
source=receipts['policy-expiry-c-flow-02']['native_test_binary']['path']
shutil.copy2(source,saved/'witness-test')
shutil.copy2(lib,saved/lib.name)
for lang in ('c','swift','kotlin'):
 shutil.copy2(receipts['policy-expiry-'+lang+'-flow-02']['client_path'],saved/(lang+'-client'))
kotlin=w/'history-witness-foreign/consumer-policy-expiry-kotlin-consumer-01/build/install/continuity-installed-consumer/lib'
shutil.copytree(kotlin,saved/'kotlin-runtime')
binaries={str(p.relative_to(saved)):sha(p) for p in saved.rglob('*') if p.is_file()}
dest=i/'research/sdk-alpha1/evidence/20261004-policy-expiry-0411862b';dest.mkdir()
for label in checks:
 shutil.copy2(w/(label+'.json'),dest/(label+'.json'))
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for label,report in public.items():
 folder=public_directories[label];raw=io.BytesIO()
 with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT) as tar:
  for name,value in sorted(report['public_readbacks'].items()):
   data=(folder/name).read_bytes();assert hashlib.sha256(data).hexdigest()==value
   member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o600;member.mtime=0
   tar.addfile(member,io.BytesIO(data))
 (dest/(label+'-public.tar.gz')).write_bytes(gzip.compress(raw.getvalue(),mtime=0))
 (dest/(label+'-public.json')).write_text(json.dumps(report,indent=2)+'\n')
for label in ('policy-expiry-c-build-01','policy-expiry-c-build-02','policy-expiry-c-build-03'):
 for ext in ('.json','.log'):
  p=w/(label+ext)
  if p.exists():
   if ext=='.log':(dest/(p.name+'.gz')).write_bytes(gzip.compress(p.read_bytes(),mtime=0))
   else:shutil.copy2(p,dest/p.name)
for name in ('run-policy-expiry-foreign.py','run-policy-expiry-quality.py','run-policy-expiry-collector-component.py','run-history-witness-flow.py',
             'run-history-foreign.py','run-history-kotlin-consumer.py','run-ci-preflight.py','seal-policy-expiry.py'):
 shutil.copy2(w/name,dest/name)
qualification=dict(completed=True,source_commit=commit,source_hashes=bindings,documentation_differences=doc_differences,
 native_engine_and_product_abi_unchanged=True,candidate_exports=72,architecture='macos-arm64 only',
 artifact_tests=2572,metadata_tests=41,c_unit_tests=9,swift_unit_tests=27,
 kotlin_consumer='current CLI compiled against unchanged private-Maven wrapper; no wrapper changes or new wrapper-unit run claimed',
 local_expiry_cases=12,baseline_cases=12,public_files=2016,public_readback_reports=list(public),collector_component=dict(receipt='policy-expiry-collector-component-01',selected_language='C',profile='debug',public_files=300),
 binary_archive_directory=str(saved),binaries=binaries,
 scope='Current-source development foreign consumers using one native engine; original-policy real-wall-clock expiry, live SDK/C1 and exact Applied/Closed recovery. Final harness shared by all six runs. Not fresh installed release archive or physical platform qualification.',
 applied_setup='Native public coordinator withholds exact Applied reply; independent fresh signed Status verifies Applied with original local image/pending unchanged; subsequent expired recovery uses the selected foreign client.',
 validation_notes=['Full artifact single run passes all2572 checks at source commit; includes5 new expiry-reader negative-control tests and the new missing/mismatched C-cohort guard.',
 'The final native harness was formatted and strictly linted; allthree final expiry and allthree baseline runs use the same recorded binary hash.',
 'Native471-test engine pass belongs to unchanged bbd0815d checkpoint; not rerun for these consumer/test/collector additions.',
 'First compile failures from guessed PolicyCheckpoint constructor/missing Result tail and strictClippy chunk iteration were corrected; original failures retained. No checks weakened.'],
 remaining=['Before-local-preparation grant closure after expiry; absence of a proposal is never NoCommit',
 'Foreign-originated Commit-result loss, ACK-loss, Busy/cancel/close and preparation process-kill matrix',
 'Fresh Debug/Release installed archive and current/minimum physical platforms',
 'Independent protocol engine, retained-secret PQ recovery proof, controlled performance and external review',
 'Full0.2.0 lifecycle, upgrade and release/maintenance objective'],
 release_claim_eligible=False,full_goal_complete=False)
(dest/'QUALIFICATION.json').write_text(json.dumps(qualification,indent=2)+'\n')
manifest={str(p.relative_to(dest)):sha(p) for p in sorted(dest.rglob('*')) if p.is_file()}
(dest/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(dict(path=str(dest),files=len(manifest),manifest_sha256=sha(dest/'MANIFEST.json'),source_commit=commit),indent=2))
