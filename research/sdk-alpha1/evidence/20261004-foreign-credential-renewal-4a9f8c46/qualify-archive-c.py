from pathlib import Path, PurePosixPath
import os,sys,subprocess,json,hashlib,shutil,tarfile,time
r=Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite');i=r/'target/credential-lifecycle-integration';w=r/'target/credential-renewal-20261004'
sys.path.insert(0,str(i/'artifact'));import continuity_c_consumer as cc;import continuity_c_enrollment as ce
produced=json.loads((w/'native-renewal-archive-01.json').read_text());assert produced['exit']==0
outside=Path(produced['outside']);consumer=outside/'c-consumer';shutil.copytree(i/'bindings/c/ContinuityPackageConsumer',consumer)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
cohort=json.loads((w/'EXPIRED_SDK_DEPENDENCIES.json').read_text())['packages'];packages={}
for e in cohort:
 name=e['package']+'-0.2.0';dest=consumer/'packages'/name;shutil.copytree(outside/'source/crates'/e['package'],dest)
 assert {str(p.relative_to(dest)):sha(p) for p in dest.rglob('*') if p.is_file()}==e['file_hashes'];packages[e['package']]=dest
archive=Path(produced['archive']['path']);assert sha(archive)==produced['archive']['sha256']
with tarfile.open(archive,'r:gz') as tar:
 for member in tar.getmembers():
  parts=PurePosixPath(member.name).parts;assert member.isfile() and len(parts)>1 and '..' not in parts and not member.name.startswith('/')
  dest=consumer/'packages'/Path(*parts);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(tar.extractfile(member).read())
name='q-periapt-continuity-identity-candidate';packages[name]=consumer/'packages'/(name+'-0.0.0')
for path,digest in produced['native_source_hashes'].items():
 if path.startswith(('src/','tests/')): assert sha(packages[name]/path)==digest
with (consumer/'Cargo.toml').open('a') as f:
 f.write('\n[patch.crates-io]\n')
 for name,p in packages.items():f.write(name+' = { path = '+json.dumps(str(p.relative_to(consumer)))+' }\n')
shutil.copy2(w/'development-c-owner/Cargo.lock',consumer/'Cargo.lock')
base=Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244');tc=base/'rustup/toolchains/1.98.1-aarch64-apple-darwin';target=r/'target/continuity-c-enrollment'
env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO_','RUST','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON'))}
env.update(RUSTUP_HOME=str(base/'rustup'),RUSTUP_TOOLCHAIN=tc.name,RUSTUP_AUTO_INSTALL='0',RUSTUP_NO_UPDATE_CHECK='1',RUSTC=str(tc/'bin/rustc'),RUSTDOC=str(tc/'bin/rustdoc'),CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(target),DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
files={str(p.relative_to(consumer)):sha(p) for p in consumer.rglob('*') if p.is_file()};records=[]
def run(cmd,label,runtime=None):
 start=time.monotonic()
 with (w/(label+'.stdout')).open('xb') as out,(w/(label+'.stderr')).open('xb') as err: result=subprocess.run(cmd,cwd=consumer,env=env if runtime is None else runtime,stdout=out,stderr=err)
 record={'command':cmd,'cwd':str(consumer),'exit':result.returncode,'seconds':time.monotonic()-start};records.append(record)
 (w/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n')
 print(label+': '+str(result.returncode),flush=True)
 if result.returncode: print((w/(label+'.stderr')).read_text()[-6000:],flush=True);raise RuntimeError(label)
 return (w/(label+'.stdout')).read_bytes()
cargo=str(tc/'bin/cargo');metadata=json.loads(run([cargo,'metadata','--locked','--offline','--all-features','--format-version','1'],'archive-c-metadata-01'))
for name,expected in packages.items():
 found=[p for p in metadata['packages'] if p['name']==name];assert len(found)==1 and Path(found[0]['manifest_path'])==expected/'Cargo.toml'
run([cargo,'clean','--locked','--offline','-p','q-periapt-continuity-c-consumer','-p','q-periapt-continuity-identity-candidate'],'archive-c-clean-01')
run([cargo,'rustc','--locked','--offline','--lib','--','-Dwarnings','-C','link-arg=-Wl,-install_name,@rpath/libq_periapt_continuity_c_consumer.dylib'],'archive-c-build-01')
installed=outside/'c-installed-debug';installed.mkdir();lib=installed/'libq_periapt_continuity_c_consumer.dylib';shutil.copy2(target/'debug'/lib.name,lib)
clang=subprocess.check_output(['/usr/bin/xcrun','--sdk','macosx','--find','clang'],env=env,text=True).strip();sdk=subprocess.check_output(['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path'],env=env,text=True).strip();client=installed/'qpc-c-client'
run([clang,'-isysroot',sdk,'-std=c11','-Wall','-Wextra','-Werror','-Wpedantic','-pthread',str(consumer/'client.c'),str(consumer/'recovery_client.c'),str(consumer/'opening_client.c'),'-I',str(consumer),'-L',str(installed),'-lq_periapt_continuity_c_consumer','-Wl,-rpath,@loader_path','-o',str(client)],'archive-c-clang-01')
symbols=subprocess.check_output(['/usr/bin/nm','-gU',str(lib)],text=True);assert {l.split()[-1].removeprefix('_') for l in symbols.splitlines() if l.strip()}==cc.EXPORTS
cc.verify_linkage(subprocess.check_output(['/usr/bin/otool','-L',str(client)],text=True),subprocess.check_output(['/usr/bin/otool','-l',str(client)],text=True),lib.name,darwin=True)
built=run([cargo,'test','--locked','--offline','--test','enrollment','--no-run','--message-format=json'],'archive-c-enrollment-build-01')
artifacts=[json.loads(line) for line in built.splitlines() if line.startswith(b'{')];choices=[Path(x['executable']) for x in artifacts if x.get('reason')=='compiler-artifact' and x.get('target',{}).get('name')=='enrollment' and x.get('executable')];assert len(choices)==1
trace=outside/'enrollment-native-test';shutil.copy2(choices[0],trace)
identity={str(p):sha(p) for p in (lib,client,trace)};runtime={k:v for k,v in env.items() if not k.startswith(('DYLD_','LD_'))};runtime['QPERIAPT_C_OWNER_CLIENT']=str(client)
stdout=run([str(trace),'credential_renewal::','--nocapture'],'archive-c-renewal-01',runtime);renewal=ce.verify_renewal_execution(stdout)
run([str(trace),'--exact',ce.TEST,'--nocapture'],'archive-c-original-enrollment-01',runtime)
assert all(sha(Path(p))==digest for p,digest in identity.items());assert all(sha(consumer/p)==digest for p,digest in files.items())
report={'completed':True,'outside':str(outside),'consumer':str(consumer),'native_archive':produced['archive'],'SDK_archive_hashes':produced['SDK_archive_hashes'],'source_hashes':files,'binaries':identity,'renewal':renewal,'records':records,'scope':'C debug build from actual candidate plus nine SDK Cargo archives; original enrollment TLS and three renewal traces; macOS arm64, one shared native engine','release_claim_eligible':False}
(w/'ARCHIVE_C_QUALIFICATION.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('source_hashes','records','SDK_archive_hashes')},indent=2),flush=True)
