from pathlib import Path
import sys,hashlib,json
r=Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite');i=r/'target/credential-lifecycle-integration';w=r/'target/credential-renewal-20261004';outside=Path('/Users/bill/Documents/Codex/credential-lifecycle-packages-20261004')
sys.path.insert(0,str(i/'artifact'));import third_party_licenses as licenses;from continuity_package_archive import archive,unpack
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
record=json.loads((w/'ARCHIVE_C_QUALIFICATION.json').read_text());assert record['completed']
lib=outside/'c-installed-debug/libq_periapt_continuity_c_consumer.dylib';assert sha(lib)==record['binaries'][str(lib)]
notices=outside/'foreign-native-notices'
if not notices.exists():
 notices.mkdir(mode=0o700)
 metadata=json.loads((w/'archive-c-platform-metadata-01.stdout').read_text())
 licenses.collect(outside/'c-consumer',notices,'aarch64-apple-darwin',root_package='q-periapt-continuity-c-consumer',resolved_metadata=metadata)
source=i/'bindings/swift/ContinuityPackageConsumer'
files={str(p.relative_to(source)):p.read_bytes() for p in source.rglob('*') if p.is_file()}
assert not any(set(Path(p).parts)&{'.build','build'} for p in files)
for name in ('LICENSE','LICENSE-APACHE','LICENSE-MIT'):files[name]=(i/'research/continuity-identity-candidate'/name).read_bytes()
files['native/include/qpc_owner.h']=(i/'bindings/c/ContinuityPackageConsumer/qpc_owner.h').read_bytes();files['native/lib/'+lib.name]=lib.read_bytes()
files['LICENSES/Rust-1.98.1-library.html']=(i/'LICENSES/Rust-1.98.1-library.html').read_bytes()
for name in ('INVENTORY.sha256','LICENSE-INVENTORY.md','LICENSE.mlkem-native','PROVENANCE.md'):files['LICENSES/mlkem-native/'+name]=(i/'crates/q-periapt-mlkem-native-sys/vendor'/name).read_bytes()
for p in notices.rglob('*'):
 if p.is_file():files[str(p.relative_to(notices))]=p.read_bytes()
hashes={p:hashlib.sha256(b).hexdigest() for p,b in files.items()};data=archive(files);zipfile=outside/'q-periapt-continuity-swift-0.0.0-debug.zip'
with zipfile.open('xb') as f:f.write(data)
dest=outside/'swift-installed-debug';unpack(data,hashes,dest);licenses.verify(dest,expected_target='aarch64-apple-darwin',root_package='q-periapt-continuity-c-consumer')
result={'archive':str(zipfile),'sha256':sha(zipfile),'bytes':len(data),'installed':str(dest),'files':hashes,'native_C_package_record':'ARCHIVE_C_QUALIFICATION.json','completed':False,'stage':'Archive unpack and license verification complete; actual installed build and runtime pending','release_claim_eligible':False}
(w/'SWIFT_RENEWAL_PACKAGE.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='files'},indent=2))
