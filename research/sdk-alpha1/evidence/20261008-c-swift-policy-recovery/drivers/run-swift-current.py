from pathlib import Path
import os, sys, subprocess, time, json, hashlib, shutil

root = Path(__file__).resolve().parents[2]
out = Path(__file__).resolve().parent / sys.argv[1]
profile = sys.argv[2] if len(sys.argv) > 2 else 'debug'
assert profile in ('debug', 'release')
out.mkdir()
base = Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244')
tc = base / 'rustup/toolchains/1.98.1-aarch64-apple-darwin'
binary = root / 'target/native-stack-debug/build' / profile

def sha(p):
    with p.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def head():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()

paths = sorted(set(p.decode() for p in subprocess.check_output(
    ['git', 'ls-files', '-c', '-o', '--exclude-standard', '-z'], cwd=root).split(b'\0')
    if p and p.startswith((b'crates/', b'bindings/', b'artifact/'))))
sources = {p: sha(root / p) for p in paths if (root / p).is_file()}
start_head = head()
mirror = out / 'mirror'
for p in sources:
    if p.startswith('bindings/swift/') or (p.startswith('bindings/') and p.count('/') == 1 and p.endswith('.json')):
        dest = mirror / p
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / p, dest)
manifest = mirror / 'bindings/swift/Package.swift'
original = manifest.read_text()
assert original.count('"-L../../target/release"') == 2
manifest.write_text(original.replace('"-L../../target/release"', json.dumps('-L' + str(binary))))
mirror_sources = {str(p.relative_to(mirror)): sha(p) for p in mirror.rglob('*') if p.is_file()}
assert all(sources[p] == h for p, h in mirror_sources.items() if p != 'bindings/swift/Package.swift')
env = {k:v for k,v in os.environ.items() if not k.startswith(('RUST','CARGO_','QPERIAPT_','QPC_','DYLD_','LD_','PYTHON'))}
env.update(RUSTUP_HOME=str(base/'rustup'), RUSTUP_TOOLCHAIN=tc.name, RUSTUP_AUTO_INSTALL='0',
    RUSTUP_NO_UPDATE_CHECK='1', RUSTC=str(tc/'bin/rustc'), RUSTDOC=str(tc/'bin/rustdoc'),
    RUSTFLAGS='-D warnings', CARGO_HOME=str(base/'apple-cargo-home-ff4a153e'), CARGO_NET_OFFLINE='true',
    CARGO_BUILD_JOBS='2', CARGO_TARGET_DIR=str(binary.parent), DYLD_FALLBACK_LIBRARY_PATH=str(tc/'lib'),
    DYLD_LIBRARY_PATH=str(binary), DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',
    PATH=str(tc/'bin')+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
commands = [('native', [str(tc/'bin/cargo'), 'build', '--offline', '--locked', '-p', 'q-periapt-ffi'] +
    (['--release'] if profile == 'release' else [])),
    ('swift', ['/usr/bin/xcrun', 'swift', 'test', '--package-path', str(mirror/'bindings/swift'),
    '--scratch-path', str(out/'build'), '-c', profile, '-Xswiftc', '-strict-concurrency=complete',
    '-Xswiftc', '-warnings-as-errors'])]
record = {'head':start_head, 'profile':profile, 'scope':'Source-identical diagnostic Swift mirror; only two native library search paths changed, not an installed-package receipt',
    'sources':sources, 'mirror_sources':mirror_sources, 'runs':[]}
for label, command in commands:
    started = time.monotonic()
    with (out/(label+'.stdout')).open('wb') as so, (out/(label+'.stderr')).open('wb') as se:
        result = subprocess.run(command, cwd=root, env=env, stdout=so, stderr=se)
    warnings = [line for line in (out/(label+'.stderr')).read_text().splitlines() if 'warning:' in line.lower()]
    run = {'name':label, 'command':command, 'returncode':result.returncode, 'seconds':time.monotonic()-started,
        'stdout_sha256':sha(out/(label+'.stdout')), 'stderr_sha256':sha(out/(label+'.stderr')), 'warnings':warnings}
    record['runs'].append(run)
    record['source_unchanged'] = head() == start_head and all(sha(root/p) == h for p,h in sources.items())
    if label == 'native' and result.returncode == 0:
        record['native_libraries'] = {p.name:sha(p) for p in binary.glob('libq_periapt_ffi_abi2.*') if p.suffix in ('.a','.dylib')}
    (out/'RESULT.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(run), flush=True)
    print((out/(label+'.stderr')).read_text()[-2000:], flush=True)
    print((out/(label+'.stdout')).read_text()[-3000:], flush=True)
    assert record['source_unchanged']
    result.check_returncode()
    assert not warnings, warnings
