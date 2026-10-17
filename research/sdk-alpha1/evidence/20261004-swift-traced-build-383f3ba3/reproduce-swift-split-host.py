from pathlib import Path
import os,subprocess,json,hashlib,time
w=Path(__file__).resolve().parent;p=w/'swift-split-host-reproduction';p.mkdir()
(p/'Package.swift').write_text('// swift-tools-version: 5.9\nimport PackageDescription\nlet package = Package(name: "HostArchitecture", platforms: [.macOS(.v14)], targets: [.testTarget(name: "HostArchitectureTests")])\n')
t=p/'Tests/HostArchitectureTests';t.mkdir(parents=True)
(t/'HostArchitectureTests.swift').write_text('import XCTest\nfinal class HostArchitectureTests: XCTestCase { func testArm64Execution() {\n#if arch(arm64)\nXCTAssertEqual(1 + 1, 2)\n#else\nXCTFail("arm64 required")\n#endif\n}}\n')
env={k:v for k,v in os.environ.items() if not k.startswith(('DYLD_','LD_','RUST','CARGO_','SWIFT_','QPERIAPT_'))};env['DEVELOPER_DIR']='/Applications/Xcode.app/Contents/Developer'
scratch=p/'scratch';common=['--package-path',str(p),'--scratch-path',str(scratch),'--triple','arm64-apple-macosx14.0','-j','2']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
records=[];binaries={}
for label,cmd in [('translated-build',['swift','build','--build-tests']),('native-test',['/usr/bin/arch','-arm64','/usr/bin/xcrun','swift','test','--skip-build'])]:
 command=['/usr/bin/arch','-x86_64','/bin/sh','-c','exec "$@"','swift-split-host',*cmd,*common]
 start=time.monotonic()
 with (w/f'swift-split-host-{label}-01.log').open('xb') as log:r=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
 text=(w/f'swift-split-host-{label}-01.log').read_text();records.append(dict(command=command,exit=r.returncode,seconds=time.monotonic()-start,warnings=sum('warning:' in l for l in text.splitlines()),executed_test='Executed 1 test' in text))
 assert r.returncode==0,text[-5000:]
 if label=='translated-build':
  for bundle in scratch.rglob('*.xctest'):
   for binary in (bundle/'Contents/MacOS').iterdir():
    assert binary.is_file();arch=subprocess.check_output(['/usr/bin/lipo','-archs',str(binary)],text=True).strip();assert arch=='arm64',arch
    binaries[str(binary)]={'sha256':sha(binary),'architecture':arch}
  assert binaries
 else:
  assert records[-1]['executed_test'];assert all(sha(Path(p))==v['sha256'] for p,v in binaries.items())
 print(label,records[-1],flush=True)
assert all(r['warnings']==0 for r in records)
result=dict(completed=True,scope='Local Rosetta build of arm64 test bundle, followed by native execution of identical binaries; CodeQL extraction must still be verified in hosted CI',records=records,binaries=binaries,release_claim_eligible=False)
(w/'SWIFT_SPLIT_HOST_REPRODUCTION.json').write_text(json.dumps(result,indent=2)+'\n')
