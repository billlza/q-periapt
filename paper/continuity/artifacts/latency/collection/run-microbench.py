#!/usr/bin/env python3
"""Run the release microbenchmark once, retain clocks and machine/build provenance."""
import argparse, datetime, hashlib, json, os, pathlib, platform, subprocess, time
ROOT = pathlib.Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--source', default='source')
parser.add_argument('--target', default='target')
parser.add_argument('--output', default='measurement')
parser.add_argument('--commit', default='9503f0228d74651e33d46be2443092c7fc624d46')
parser.add_argument('--inventory', default='source-inventory.json')
args = parser.parse_args()
OUT = ROOT / args.output
OUT.mkdir(exist_ok=True)
BIN = ROOT / args.target / 'release/qperiapt-paper-latency-harness'
def read(path):
    try: return pathlib.Path(path).read_text()
    except (FileNotFoundError,PermissionError,OSError): return None
def capture(args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return {'argv': list(map(str,args)), 'exit_code': p.returncode, 'output': p.stdout}
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def state():
    return {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'loadavg': os.getloadavg(),
            'proc_stat': read('/proc/stat'), 'proc_pressure_cpu': read('/proc/pressure/cpu'),
            'proc_pressure_io': read('/proc/pressure/io')}
allowed = sorted(os.sched_getaffinity(0)); cpu = allowed[0]
meta = {
    'schema': 'qperiapt-supporting-latency-v1', 'source_commit': args.commit,
    'scope': 'backend API microbenchmark; same-machine Linux container; no protocol, network, journal, or OS RNG acquisition in interval',
    'cpu_affinity': [cpu], 'available_cpu_affinity': allowed, 'platform': platform.platform(),
    'uname': list(platform.uname()), 'os_release': read('/etc/os-release'), 'lscpu': capture(['lscpu','--json']), 'cpuinfo': read('/proc/cpuinfo'),
    'cgroup_cpu_max': read('/sys/fs/cgroup/cpu.max'), 'cgroup_memory_max': read('/sys/fs/cgroup/memory.max'),
    'cpu_governor': read(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor'),
    'rustc': capture([str(ROOT/'toolchain/bin/rustc'),'-vV']), 'cargo': capture([str(ROOT/'toolchain/bin/cargo'),'-Vv']),
    'cc': capture(['cc','--version']), 'binary_sha256': digest(BIN),
    'lock_sha256': digest(ROOT/args.source/'Cargo.lock'), 'source_inventory_sha256': digest(ROOT/args.inventory),
    'build_profile': {'opt_level':3,'lto':'thin','codegen_units':1,'overflow_checks':True,'backend_features':'default (no linux-x86_64-avx2)'},
    'compiler_environment': {k:os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CC','CFLAGS','AR','CARGO_PROFILE_RELEASE_OPT_LEVEL','CARGO_PROFILE_RELEASE_LTO','CARGO_PROFILE_RELEASE_CODEGEN_UNITS']},
    'measurement_clock': 'CLOCK_MONOTONIC_RAW (wall), CLOCK_PROCESS_CPUTIME_ID (CPU)',
    'cpu_interval_detail': 'CPU interval encloses both wall-clock reads; no timer-overhead subtraction',
    'iterations': {'corpus':64,'samples_per_operation':200,'calls_per_sample':8,'warmup_calls_per_operation':256},
    'input': {'message_bytes':1024,'context_bytes':0,'seed_and_coins':'64 distinct deterministic benchmark cases, precomputed outside interval','os_rng_acquisition_included':False},
    'timing_output': 'one row per 8-call batch; batch-average percentiles are not single-call tail latencies',
    'start': state(),
}
with (OUT/'primitive-raw.csv').open('w') as out, (OUT/'primitive-stderr.txt').open('w') as err:
    p = subprocess.run([str(BIN)], stdout=out, stderr=err, preexec_fn=lambda: os.sched_setaffinity(0,{cpu}))
meta['end'] = state(); meta['exit_code'] = p.returncode
meta['raw_sha256'] = digest(OUT/'primitive-raw.csv')
meta['stderr'] = read(OUT/'primitive-stderr.txt')
(OUT/'environment.json').write_text(json.dumps(meta,indent=2))
print(json.dumps({'exit_code':p.returncode,'affinity':[cpu],'raw':str(OUT/'primitive-raw.csv'),'metadata':str(OUT/'environment.json'),'stderr':meta['stderr']},indent=2))
if p.returncode: raise SystemExit(p.returncode)
