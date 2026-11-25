#!/usr/bin/env python3
"""Build the exact source closure, then collect new microbench and delivery data.

Requires Linux x86_64, Rust/Cargo 1.98.1 on PATH, a C compiler, and Cargo registry
access (or a populated CARGO_HOME). Does not change the retained paper results.
"""
import argparse, os, pathlib, shutil, subprocess, sys
from prepare_sources import prepare
ROOT=pathlib.Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser();p.add_argument('--work-dir',type=pathlib.Path,required=True);p.add_argument('--output-dir',type=pathlib.Path,required=True);a=p.parse_args()
    if a.output_dir.exists():raise ValueError('output directory must not exist')
    rustc=shutil.which('rustc');cargo=shutil.which('cargo')
    if not rustc or not cargo:raise ValueError('Rust/Cargo 1.98.1 must be on PATH')
    for exe,name in [(rustc,'rustc'),(cargo,'cargo')]:
        version=subprocess.check_output([exe,'--version'],text=True)
        if not version.startswith(name+' 1.98.1 '):raise ValueError('required '+name+' 1.98.1; observed '+version)
    for key in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CC','CFLAGS','AR','CARGO_PROFILE_RELEASE_OPT_LEVEL','CARGO_PROFILE_RELEASE_LTO','CARGO_PROFILE_RELEASE_CODEGEN_UNITS']:
        if os.environ.get(key):raise ValueError('unset compiler override '+key+' to reproduce the recorded default build')
    work=a.work_dir.resolve();prepare(work)
    bindir=work/'toolchain/bin';bindir.mkdir(parents=True)
    for name,exe in [('rustc',rustc),('cargo',cargo)]: (bindir/name).symlink_to(exe)
    manifests=[('protocol-source/Cargo.toml','protocol-target',['-p','qperiapt-paper-latency-harness']),('protocol-driver/Cargo.toml','protocol-delivery-target',[])]
    for manifest,target,extra in manifests:
        env=os.environ.copy();env['CARGO_TARGET_DIR']=str(work/target)
        with (work/(target+'-build.log')).open('w') as log:
            subprocess.run([cargo,'build','--locked','--release','--manifest-path',str(work/manifest),*extra],check=True,env=env,stdout=log,stderr=subprocess.STDOUT)
    subprocess.run([sys.executable,str(work/'run-microbench.py'),'--source','protocol-source','--target','protocol-target','--output','measurement-358b','--commit','358b921ab3469ce49f166633fc9a762ff6ed7e3d','--inventory','protocol-source-inventory.json'],check=True)
    subprocess.run([sys.executable,str(work/'run-delivery.py'),'--skip-audit'],check=True)
    shutil.copytree(work/'measurement-358b',a.output_dir)
    subprocess.run([sys.executable,str(ROOT/'analyze_latency.py'),'--results-dir',str(a.output_dir)],check=True)
    print('New results: '+str(a.output_dir.resolve()))
if __name__=='__main__':main()
