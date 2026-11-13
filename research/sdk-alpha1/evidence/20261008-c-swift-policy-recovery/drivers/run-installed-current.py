from pathlib import Path
import os,sys,subprocess,json,hashlib,tempfile,tarfile,shutil,shlex,time
import apple_sdk_profile as apple

base=Path(__file__).resolve().parent; root=base.parents[1]; out=base/sys.argv[1]; out.mkdir(mode=0o700)
bundle=base/'source/target/qperiapt-c-abi2/q-periapt-c-abi2-0.2.0-aarch64-apple-darwin.tar.gz'
def sha(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
assert sha(bundle)=='127078c0244ce819ff9d781f9526cf02eadd52d1f8af39b0f0d85359cc0dc93a'
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
sources={p:sha(root/p) for p in apple.SHIPPED_SOURCES.values()}
sources.update({str(p.relative_to(root)):sha(p) for p in (root/apple.FIXTURE).rglob('*.swift')})
record={'source_head':head,'native_package_source_head':'1f6e9edf6fe98a5ff4c572e69c346c7e088e17e5',
 'archive_sha256':sha(bundle),'source_files':sources,'scope':'macOS arm64 installed C package recovery and Swift wrapper consumer using that exact static archive. Single-host diagnostic XCFramework; not full Apple release packaging or iOS/device evidence.', 'runs':[]}
env={k:v for k,v in os.environ.items() if not k.startswith(('DYLD_','LD_','PKG_CONFIG','RUST','CARGO_','QPERIAPT_','QPC_','PYTHON'))}
env['PATH']='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin';env['DEVELOPER_DIR']='/Applications/Xcode.app/Contents/Developer'
def run(label,command,cwd,environment=env):
 start=time.monotonic()
 with (out/(label+'.stdout')).open('wb') as so,(out/(label+'.stderr')).open('wb') as se:
  r=subprocess.run(command,cwd=cwd,env=environment,stdout=so,stderr=se)
 text=(out/(label+'.stderr')).read_text(); entry={'label':label,'command':command,'returncode':r.returncode,'seconds':time.monotonic()-start,'stdout_sha256':sha(out/(label+'.stdout')),'stderr_sha256':sha(out/(label+'.stderr'))}
 record['runs'].append(entry);(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(entry),flush=True)
 if r.returncode: print(text[-4000:],flush=True)
 r.check_returncode();assert 'warning:' not in text.lower();return (out/(label+'.stdout')).read_text()
with tempfile.TemporaryDirectory(prefix='qperiapt-recovery-installed-',dir='/private/tmp') as temporary:
 temp=Path(temporary);unpack=temp/'unpack';unpack.mkdir()
 with tarfile.open(bundle) as archive:archive.extractall(unpack,filter='data')
 native=unpack/'q-periapt-c-abi2-0.2.0-aarch64-apple-darwin'; assert native.is_dir()
 header=native/'include/qperiapt/abi2/q_periapt.h';library=native/'lib/libq_periapt_ffi_abi2.a'
 record['native_static_sha256']=sha(library);record['native_header_sha256']=sha(header)
 shutil.copyfile(base/'recovery_consumer.c',temp/'recovery_consumer.c');shutil.copyfile(base/'c-source-01/recovery_fixture.h',temp/'recovery_fixture.h')
 package_env={**env,'PKG_CONFIG_LIBDIR':str(native/'lib/pkgconfig'),'PKG_CONFIG_PATH':str(native/'lib/pkgconfig')}
 for mode in ('shared','static'):
  selector='qperiapt-abi2-static' if mode=='static' else 'qperiapt-abi2'
  flags=shlex.split(run('pkg-config-'+mode,['/opt/homebrew/bin/pkg-config','--cflags','--libs',selector],temp,package_env))
  executable=temp/('recovery-'+mode)
  run('c-compile-'+mode,['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Wpedantic','-Werror',str(temp/'recovery_consumer.c'),*flags,'-Wl,-rpath,'+str(native/'lib'),'-o',str(executable)],temp)
  linked=run('c-link-'+mode,['/usr/bin/otool','-L',str(executable)],temp)
  assert ('libq_periapt' in linked)==(mode=='shared')
  store=temp/('store-'+mode);store.mkdir(mode=0o700)
  assert run('c-run-'+mode,[str(executable),str(store/'policy.redb')],temp).strip()=='SDK_POLICY_RECOVERY_C_PASS'
 package=temp/'QPeriapt';package.mkdir();(package/'Binaries').mkdir()
 (package/'Package.swift').write_text(apple.PACKAGE)
 for relative,original in apple.SHIPPED_SOURCES.items():
  dest=package/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/original,dest)
 headers=temp/'headers';headers.mkdir();shutil.copyfile(header,headers/'q_periapt.h')
 (headers/'module.modulemap').write_text('module CQPeriapt {\n  header "q_periapt.h"\n  export *\n}\n')
 run('xcframework-host',['/usr/bin/xcrun','xcodebuild','-create-xcframework','-library',str(library),'-headers',str(headers),'-output',str(package/'Binaries/CQPeriapt.xcframework')],temp)
 consumer=temp/'QPeriaptSDKConsumer';apple.prepare_consumer(consumer)
 for mode in ('debug','release'):
  output=run('swift-'+mode,['/usr/bin/xcrun','swift','test','--package-path',str(consumer),'--scratch-path',str(temp/('build-'+mode)),'-c',mode,'-Xswiftc','-strict-concurrency=complete','-Xswiftc','-warnings-as-errors'],temp)
  assert 'Executed 5 tests, with 0 failures' in output
  assert 'testInstalledPolicyAuthorityRecoveryAndAdvancedReplay' in output
  selected=list((temp/('build-'+mode)).rglob('libq_periapt_ffi_abi2.a'));assert selected
  assert all(sha(p)==record['native_static_sha256'] for p in selected)
  record['swift_'+mode+'_selected_archives']=[str(p.relative_to(temp)) for p in selected]
 assert all(sha(root/p)==h for p,h in sources.items())
 assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==head
record['pass']=True;(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
