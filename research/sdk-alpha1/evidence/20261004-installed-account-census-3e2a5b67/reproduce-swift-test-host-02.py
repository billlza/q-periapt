from pathlib import Path
import os,subprocess,json,time
w=Path(__file__).resolve().parent;p=w/'swift-test-host-reproduction-02';p.mkdir()
(p/'Package.swift').write_text('// swift-tools-version: 5.9\nimport PackageDescription\nlet package = Package(name: "HostArchitecture", platforms: [.macOS(.v14)], targets: [.testTarget(name: "HostArchitectureTests")])\n')
t=p/'Tests/HostArchitectureTests';t.mkdir(parents=True)
(t/'HostArchitectureTests.swift').write_text('import XCTest\nfinal class HostArchitectureTests: XCTestCase {\n func testArm64Execution() {\n #if arch(arm64)\n XCTAssertEqual(1 + 1, 2)\n #else\n XCTFail("The admitted test bundle must execute on arm64")\n #endif\n }\n}\n')
env={k:v for k,v in os.environ.items() if not k.startswith(('DYLD_','LD_','RUST','CARGO_','SWIFT_','QPERIAPT_'))};env['DEVELOPER_DIR']='/Applications/Xcode.app/Contents/Developer'
records=[]
for label,command in [('translated',['/usr/bin/xcrun','swift']),('native',['/usr/bin/arch','-arm64','/usr/bin/xcrun','swift'])]:
 # Both commands are launched by the same translated parent shell.
 args=['/usr/bin/arch','-x86_64','/bin/sh','-c','exec "$@"','swift-host-test',*command,'test','--package-path',str(p),'--triple','arm64-apple-macosx14.0','-j','2']
 start=time.monotonic()
 with (w/f'swift-test-host-{label}-02.log').open('xb') as log:r=subprocess.run(args,env=env,stdout=log,stderr=subprocess.STDOUT)
 output=(w/f'swift-test-host-{label}-02.log').read_text()
 records.append(dict(label=label,command=args,exit=r.returncode,seconds=time.monotonic()-start,passed_test='Executed 1 test' in output,incompatible_architecture='incompatible architecture' in output or 'current architecture' in output or '其版本不适用于当前架构' in output))
 print(json.dumps(records[-1]),flush=True)
(w/'SWIFT_TEST_HOST_REPRODUCTION_02.json').write_text(json.dumps(dict(records=records,completed=records[0]['exit']!=0 and records[0]['incompatible_architecture'] and records[1]['exit']==0 and records[1]['passed_test'],scope='Local translated-parent SwiftPM/XCTest reproduction; no local CodeQL tracer execution',release_claim_eligible=False),indent=2)+'\n')
