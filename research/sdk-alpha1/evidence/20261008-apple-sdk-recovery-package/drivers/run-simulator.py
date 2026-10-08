from pathlib import Path
import os,sys,subprocess,json,hashlib,tempfile,zipfile,uuid,time,shutil,re
os.umask(0o077)
base=Path(__file__).resolve().parent;root=base.parents[1];out=base/sys.argv[1];out.mkdir(mode=0o700)
archive=root/'target/policy-recovery-ffi-current/source/target/apple-recovery-full-02/q-periapt-swift-0.2.0/QPeriapt-Swift-SDK-0.2.0.zip'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
assert sha(archive)=='3fb15050c6335ac565da5239afa6f90d811d7b9a85ccfd27d9b94a18b9ed093d'
run_id=uuid.uuid4().hex;bundle='dev.qperiapt.SDKSimulator.r'+run_id
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
sources={str(p.relative_to(root)):sha(p) for p in (root/'bindings/apple-device/Sources/QPeriaptDeviceRunner').glob('*.swift')}
record={'source_head':head,'scope':'Installed SDK package on an owned iOS 27 ARM64 simulator only; not physical/current-minimum-device acceptance or durable iOS storage',
 'archive_sha256':sha(archive),'run_id':run_id,'source_hashes':sources,'runs':[],'physical_device_qualified':False}
env={k:os.environ[k] for k in ('HOME','USER','LOGNAME','TMPDIR') if k in os.environ}
env.update(PATH='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',LC_ALL='C',LANG='C')
workspace=Path(tempfile.mkdtemp(prefix='qperiapt-sdk-simulator-',dir='/private/tmp'));record['private_workspace']=str(workspace)
def save(): (out/'RESULT.private.json').write_text(json.dumps(record,indent=2)+'\n')
def run(label,args,timeout=120,environment=env,check=True):
 started=time.monotonic()
 with (out/(label+'.private.stdout')).open('wb') as so,(out/(label+'.private.stderr')).open('wb') as se:
  try:r=subprocess.run(args,cwd=workspace,env=environment,stdout=so,stderr=se,timeout=timeout)
  except subprocess.TimeoutExpired:
   record['runs'].append({'label':label,'command':args,'timeout_seconds':timeout});save();raise
 entry={'label':label,'command':args,'returncode':r.returncode,'seconds':time.monotonic()-started,'stdout_sha256':sha(out/(label+'.private.stdout')),'stderr_sha256':sha(out/(label+'.private.stderr'))};record['runs'].append(entry);save();print(json.dumps({k:entry[k] for k in ('label','returncode','seconds')}),flush=True)
 if check:r.check_returncode()
 return r,(out/(label+'.private.stdout')).read_text()
simulator=None;completed=False
try:
 with zipfile.ZipFile(archive) as z:
  assert all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in z.namelist());z.extractall(workspace)
 package=workspace/'QPeriapt';contents=json.loads((package/'PACKAGE_CONTENTS.json').read_text())
 # The package's closed inventory is checked by the producer; bind these bytes
 # again before the external app can select its simulator static archive.
 native=package/'Binaries/CQPeriapt.xcframework/ios-arm64_x86_64-simulator/libq_periapt_ffi_abi2.a';record['packaged_simulator_archive_sha256']=sha(native)
 appsrc=workspace/'Sources';appsrc.mkdir();resources=workspace/'Resources';resources.mkdir()
 for name in ('DeviceSmoke.swift','SDKDeviceSmoke.swift'):
  original=root/'bindings/apple-device/Sources/QPeriaptDeviceRunner'/name
  (appsrc/name).write_text('import QPeriaptSDK\nimport QPeriaptHybrid\n'+original.read_text())
 main=(root/'bindings/apple-device/Sources/QPeriaptDeviceRunner/main.swift').read_text()
 main=main.replace('QPERIAPT_SDK_DEVICE_PASS','QPERIAPT_SDK_SIMULATOR_PASS').replace('QPERIAPT_DEVICE_','QPERIAPT_SIMULATOR_').replace('qperiapt-device-result','qperiapt-simulator-result')
 (appsrc/'main.swift').write_text(main)
 shutil.copyfile(root/'bindings/apple-device/Sources/QPeriaptDeviceRunner/Info.plist',workspace/'Info.plist')
 for name in ('signed-policy-vectors.json','sdk-policy-revocation-vectors.json','sdk-policy-update-vectors.json'):
  shutil.copyfile(root/'bindings'/name,resources/name)
 spec={'name':'QPeriaptSDKSimulator','options':{'minimumXcodeGenVersion':'2.42.0'},'packages':{'QPeriapt':{'path':str(package)}},
 'targets':{'QPeriaptSDKSimulator':{'type':'application','platform':'iOS','deploymentTarget':'16.0',
 'sources':['Sources',{'path':'Resources','buildPhase':'resources'}],
 'dependencies':[{'package':'QPeriapt','product':'QPeriaptSDK'},{'package':'QPeriapt','product':'QPeriaptHybrid'},{'sdk':'AppIntents.framework','weak':True}],
 'settings':{'base':{'PRODUCT_BUNDLE_IDENTIFIER':bundle,'INFOPLIST_FILE':str(workspace/'Info.plist'),'SWIFT_VERSION':'5.9',
 'SWIFT_ACTIVE_COMPILATION_CONDITIONS':'$(inherited) QPERIAPT_SDK_DEVICE','SWIFT_STRICT_CONCURRENCY':'complete','SWIFT_TREAT_WARNINGS_AS_ERRORS':'YES',
 'OTHER_SWIFT_FLAGS':'$(inherited) -parse-as-library','ENABLE_DEBUG_DYLIB':'NO','CODE_SIGNING_ALLOWED':'NO','SUPPORTED_PLATFORMS':'iphonesimulator',
 'SUPPORTS_MAC_DESIGNED_FOR_IPHONE_IPAD':'NO','SUPPORTS_XR_DESIGNED_FOR_IPHONE_IPAD':'NO','TARGETED_DEVICE_FAMILY':'1,2'}}}}}
 (workspace/'project.json').write_text(json.dumps(spec,indent=2)+'\n');shutil.copyfile(workspace/'project.json',out/'project.private.json')
 run('generate',['/opt/homebrew/bin/xcodegen','generate','--spec',str(workspace/'project.json'),'--project',str(workspace)])
 derived=workspace/'DerivedData'
 run('build',['/usr/bin/xcrun','xcodebuild','-project',str(workspace/'QPeriaptSDKSimulator.xcodeproj'),'-scheme','QPeriaptSDKSimulator','-sdk','iphonesimulator','-destination','generic/platform=iOS Simulator','-configuration','Debug','-derivedDataPath',str(derived),'CODE_SIGNING_ALLOWED=NO','ARCHS=arm64','ONLY_ACTIVE_ARCH=YES','build'],timeout=300)
 build=(out/'build.private.stdout').read_text()+(out/'build.private.stderr').read_text();assert not re.search(r'(?im)(?:^|[^a-z])(warning|error):',build)
 app=derived/'Build/Products/Debug-iphonesimulator/QPeriaptSDKSimulator.app';assert app.is_dir();record['app_executable_sha256']=sha(app/'QPeriaptSDKSimulator')
 selected=derived/'Build/Products/Debug-iphonesimulator/libq_periapt_ffi_abi2.a';assert sha(selected)==record['packaged_simulator_archive_sha256']
 _,created=run('create-simulator',['/usr/bin/xcrun','simctl','create','QPeriapt SDK 0.2 '+run_id[:8],'com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro','com.apple.CoreSimulator.SimRuntime.iOS-27-0'])
 simulator=created.strip();uuid.UUID(simulator);record['simulator_identifier_private']=simulator;save()
 run('boot',['/usr/bin/xcrun','simctl','boot',simulator]);run('boot-status',['/usr/bin/xcrun','simctl','bootstatus',simulator,'-b'],timeout=180)
 run('install',['/usr/bin/xcrun','simctl','install',simulator,str(app)])
 run('launch',['/usr/bin/xcrun','simctl','launch',simulator,bundle],environment={**env,'SIMCTL_CHILD_QPERIAPT_SIMULATOR_RUN_ID':run_id})
 _,container=run('container',['/usr/bin/xcrun','simctl','get_app_container',simulator,bundle,'data']);container=Path(container.strip());assert container.is_absolute()
 marker_file=container/'Documents'/('qperiapt-simulator-result-'+run_id+'.txt');deadline=time.monotonic()+60
 while not marker_file.is_file() and time.monotonic()<deadline:time.sleep(0.5)
 assert marker_file.is_file(),'simulator did not produce its run-bound result'
 marker=marker_file.read_text();(out/'simulator-result.txt').write_text(marker)
 expected='QPERIAPT_SDK_SIMULATOR_PASS profile=sdk-020 version=0.2.0 abi=2 extension=1 tests=compatibilitySignedPolicy,ownedKeysAndPurposeDerivation,expertTransferAndPolicyRevocation,resourceLimitsAndCancellation run-id='+run_id+'\n'
 assert marker==expected,marker
 assert sha(native)==record['packaged_simulator_archive_sha256'] and sha(app/'QPeriaptSDKSimulator')==record['app_executable_sha256']
 assert all(sha(root/p)==h for p,h in sources.items()) and subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==head
 completed=True;record['workload_pass']=True
finally:
 if simulator is not None:
  cleanup=[]
  for label,args in [('uninstall',['uninstall',simulator,bundle]),('shutdown',['shutdown',simulator]),('delete',['delete',simulator])]:
   r,_=run('cleanup-'+label,['/usr/bin/xcrun','simctl',*args],check=False);cleanup.append(r.returncode)
  _,inventory=run('cleanup-inventory',['/usr/bin/xcrun','simctl','list','devices','--json']);absent=all(d['udid']!=simulator for rows in json.loads(inventory)['devices'].values() for d in rows)
  record['cleanup']={'returncodes':cleanup,'owned_simulator_absent':absent};save();assert all(code==0 for code in cleanup) and absent
 record['pass']=completed;save()
 if completed:shutil.rmtree(workspace)
print('INSTALLED_SDK_SIMULATOR_PASS physical_device_qualified=false',flush=True)
