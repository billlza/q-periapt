"""Seal actual killed-peer diagnosis and bounded typed-error fixture correction."""
from pathlib import Path
import difflib,gzip,hashlib,io,json,shutil,subprocess,tarfile
w=Path(__file__).resolve().parent;c=Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=c,text=True).strip()
source=git('rev-parse','HEAD');assert source!='c82244fa1a2d61e2ee04266886c7907ddc7f5dd8' and not git('status','--porcelain')
changed=['bindings/c/ContinuityPackageConsumer/tests/common/witness_tls.rs','bindings/c/ContinuityPackageConsumer/tests/enrollment/witness_cancellation.rs']
assert set(git('diff','--name-only','c82244fa1a2d61e2ee04266886c7907ddc7f5dd8',source).splitlines())==set(changed)
flows={language:'tls-cut-typed-'+language.lower()+'-flow-'+('02' if language=='Kotlin' else '01') for language in ['C','Swift','Kotlin']}
labels=list(flows.values())+['tls-cut-typed-quality-01','tls-cut-typed-shared-regression-01','tls-cut-typed-collector-tests-01','tls-cut-typed-source-01']
receipts={};hashes={}
for label in labels:
 r=json.loads((w/(label+'.json')).read_text());assert r['completed'],label;assert sha(w/(label+'.log'))==r['log_sha256'],label
 for n,h in (r.get('source_hashes',{})|r.get('harness_hashes',{})).items():assert sha(c/n)==h,(label,n);hashes[n]=h
 receipts[label]=r
assert receipts['tls-cut-typed-source-01']['source_commit']==source
assert len(receipts['tls-cut-typed-collector-tests-01']['summary'])==1 and receipts['tls-cut-typed-collector-tests-01']['summary'][0].startswith('Ran 31 tests in ')
analysis=json.loads((w/'TLS_CANCELLATION_DIAGNOSTIC_ANALYSIS.json').read_text());assert analysis['completed']
lib=w/'history-witness-foreign/native/libq_periapt_continuity_c_consumer.dylib';assert sha(lib)=='b3fd608402efc935b042b385e12a0372d3eb986c8c379a84086256172cbd0070'
runtime=json.loads((w/'FOREIGN_COMMIT_ERROR_KOTLIN_RUNTIME.json').read_text())
for n,h in runtime['runtime_jars'].items():assert sha(Path(n))==h
saved=w/('tls-cut-typed-binaries-'+source[:8]);saved.mkdir()
shutil.copy2(lib,saved/lib.name)
for language,label in flows.items():
 r=receipts[label];assert r['native_library_sha256']==sha(lib)
 for entry in [('client_path','client_sha256')]:assert sha(Path(r[entry[0]]))==r[entry[1]]
 assert sha(Path(r['native_test_binary']['path']))==r['native_test_binary']['sha256']
 shutil.copy2(r['client_path'],saved/(language.lower()+'-client'))
shutil.copy2(receipts[flows['C']]['native_test_binary']['path'],saved/'foreign-witness-test')
(saved/'kotlin-runtime').mkdir()
for n in runtime['runtime_jars']:shutil.copy2(n,saved/'kotlin-runtime'/Path(n).name)
dest=c/'research/sdk-alpha1/evidence'/('20261004-tls-cancellation-cut-'+source[:8]);dest.mkdir()
for label in labels:
 shutil.copy2(w/(label+'.json'),dest/(label+'.json'))
 (dest/(label+'.log.gz')).write_bytes(gzip.compress((w/(label+'.log')).read_bytes(),mtime=0))
for language,label in flows.items():
 report=json.loads((w/(label+'-readback.json')).read_text());assert len(report['public_readbacks'])==544
 folder=Path(receipts[label]['public_evidence']);raw=io.BytesIO()
 with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT) as archive:
  for n,h in sorted(report['public_readbacks'].items()):
   p=folder/n;assert sha(p)==h;data=p.read_bytes();member=tarfile.TarInfo(n);member.size=len(data);member.mode=0o600;member.mtime=0;archive.addfile(member,io.BytesIO(data))
 (dest/(label+'-public.tar.gz')).write_bytes(gzip.compress(raw.getvalue(),mtime=0))
 shutil.copy2(w/(label+'-readback.json'),dest/(label+'-public.json'))
for name in analysis['variants']:
 folder=w/name;target=dest/name;target.mkdir()
 r=json.loads((folder/'RESULT.json').read_text())
 for n,h in r['modified_sources'].items():assert sha(folder/n)==h,(name,n)
 shutil.copy2(folder/'RESULT.json',target/'RESULT.json')
 for p in folder.glob('*.log'):(target/(p.name+'.gz')).write_bytes(gzip.compress(p.read_bytes(),mtime=0))
 for role,files in [('candidate',['src/anchor/tls.rs','src/anchor/tls/channel.rs']),('consumer',['tests/common/witness_tls.rs','tests/enrollment/witness_cancellation.rs'])]:
  for n in files:
   out=target/role/(n+'.txt');out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(folder/role/n,out)
for n in ['ci-44c9ff79-installed-swift.log','ci-44c9ff79-c-witnessed-cancellation-debug.stdout','ci-44c9ff79-c-witnessed-cancellation-debug.stderr','ci-44c9ff79-c-witnessed-cancellation-debug.json']:
 (dest/(n+'.gz')).write_bytes(gzip.compress((w/n).read_bytes(),mtime=0))
assert sha(w/'ci-44c9ff79-installed-swift-artifact.zip')=='cd740f5fdd40421f055288e4edf9d4a69fd39b0fef040cce71ee593888d2b719'
for n in ['TLS_CANCELLATION_DIAGNOSTIC_ANALYSIS.json','analyze-tls-cancel-diagnostic.py','run-tls-cancel-diagnostic.py','run-commit-error-cancellation-regression.py','run-commit-loss-relay-regression.py','run-commit-loss-quality.py','readback-tls-cut-typed.py','run-ci-preflight.py','FOREIGN_COMMIT_ERROR_KOTLIN_RUNTIME.json','seal-tls-cut-typed.py']:shutil.copy2(w/n,dest/n)
qualification=dict(completed=False,fixture_correction_verified=True,source_commit=source,source_hashes=hashes,macos_scope='Apple Silicon only',native_product_engine_and_abi_unchanged=True,candidate_c_exports=73,diagnostic_analysis=analysis,actual_foreign_cancellation_cases=24,public_files=1632,c_unit_tests=9,fixture_rejection_controls=17,collector_tests=31,shared_tls_regression_tests=4,native_library_sha256=sha(lib),native_test_binary_sha256=receipts[flows['C']]['native_test_binary']['sha256'],binary_archive_directory=str(saved),binaries={str(p.relative_to(saved)):sha(p) for p in saved.rglob('*') if p.is_file()},original_ci_failure={'head':'44c9ff7910d3c243a5b517360e59df06c9097f94','run':37232506398,'job':111526715718,'artifact':11314119479,'artifact_sha256':sha(w/'ci-44c9ff79-installed-swift-artifact.zip'),'scope':'Original C Debug live/expired TLS ACK cancellation rejected ConnectionAborted OS22; original failure retained, not retried away.'},scope='Typed error causes and exact failed admission are checked before classifying a known Darwin closed-socket timeout failure. Actual library and foreign consumers are unchanged. Same native engine; source component and isolated interleaving evidence only. Local red/green does not supply absent syscall telemetry for the original hosted failure.',legacy_kotlin_regression='tls-cut-typed-kotlin-flow-01 also passed; current consumer is separately verified in flow02 and is the only Kotlin result counted in the24 cases.',release_claim_eligible=False,remaining=['Exact new-head hosted installed Debug/Release C Swift Kotlin and full CI','Android ADB offline root cause and bounded cleanup, current/minimum physical platforms','Full identity lifecycle, upgrade and authority/device replacement contracts, independent implementation, retained-secret recovery proof, full-path performance and external review'])
(dest/'QUALIFICATION.json').write_text(json.dumps(qualification,indent=2)+'\n')
manifest={str(p.relative_to(dest)):sha(p) for p in dest.rglob('*') if p.is_file()};(dest/'MANIFEST.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
for n,h in manifest.items():assert sha(dest/n)==h
report=dict(path=str(dest),source_commit=source,files=len(manifest),manifest_sha256=sha(dest/'MANIFEST.json'),component_verified=True,release_claim_eligible=False)
(w/'TLS_CANCELLATION_CUT_SEALED.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
