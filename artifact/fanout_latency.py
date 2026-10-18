"""Compare the fixed fanout snapshot candidate on one native CI host."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import time
import tomllib

from bounded_process import capture_output
from evidence_io import fresh_output_directory, parse_strict_json_bytes, read_regular_snapshot
from fanout_latency_review import BASELINE, PREFIX, BLOCKS, WARMUPS, TEST, catalog, identities, review, samples, snapshot, unpack_source
from rust_sdk_profile import require, write_json

ROOT = Path(__file__).resolve().parents[1]
CHANGED = {'README.md', 'src/durable/messages/fanout.rs'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def binary_digest(path):
    return read_regular_snapshot(path, maximum=256 * 1024**2, label='fanout test binary').sha256


def manifest(data: bytes, root: Path) -> bytes:
    text = data.decode()
    parsed = tomllib.loads(text)
    require(parsed['package']['name'] == 'q-periapt-continuity-identity-candidate'
            and parsed['package']['version'] == '0.0.0' and parsed['package']['publish'] is False,
            'candidate package identity differs')
    require(parsed['profile']['release'] == {'opt-level': 3, 'lto': 'thin', 'codegen-units': 1,
                                             'overflow-checks': True}, 'Release profile differs')
    dependencies = parsed['dependencies'] | parsed['dev-dependencies']
    paths = {v['path'] for v in dependencies.values() if isinstance(v, dict) and 'path' in v}
    require(len(paths) == 7 and all(re.fullmatch(r'\.\./\.\./crates/q-periapt-[a-z-]+', p) for p in paths),
            'candidate dependency paths differ')
    for relative in paths:
        target = root / relative.removeprefix('../../')
        require(target.is_dir() and not target.is_symlink(), 'SDK dependency path is unavailable')
        old = 'path = ' + json.dumps(relative)
        require(text.count(old) == 1, 'dependency path is not uniquely normalized')
        text = text.replace(old, 'path = ' + json.dumps(str(target)))
    return text.encode()


def prepare_sources(run, work: Path, head: str) -> dict:
    require(run(['git', 'diff', BASELINE, head, '--', 'crates', 'Cargo.toml', 'Cargo.lock', '.cargo'],
                'sdk-diff', ROOT) == b'', 'SDK or compiler configuration changed between variants')
    variants = {name: unpack_source(run(['git', 'archive', '--format=tar', ref, '--', PREFIX],
                                      'source-' + name, ROOT, binary=True))
                for name, ref in (('baseline', BASELINE), ('candidate', head))}
    before, after = variants.values()
    require(set(before) == set(after), 'candidate source path set changed')
    changed = {p for p in before if before[p] != after[p]}
    require(changed == CHANGED, 'comparison includes unexpected source changes')
    require(before['Cargo.toml'] == after['Cargo.toml'] and before['Cargo.lock'] == after['Cargo.lock'],
            'variant dependency manifest or lock differs')
    build_files = {}
    for name, files in variants.items():
        destination = work / name / 'source'
        destination.mkdir(parents=True, mode=0o700)
        build_files[name] = {}
        for relative, content in files.items():
            content = manifest(content, ROOT) if relative == 'Cargo.toml' else content
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(content)
            build_files[name][relative] = digest(content)
    return dict(baseline=BASELINE, candidate=head, changed_files=sorted(changed),
                build_files=build_files,
                files={name: {p: digest(data) for p, data in sorted(files.items())}
                       for name, files in variants.items()})


def verify_sources(work: Path, source: dict) -> None:
    for variant, files in source['build_files'].items():
        root = work / variant / 'source'
        require({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} == set(files),
                'source file set changed')
        for name, expected in files.items():
            require(digest(snapshot(root / name)) == expected, 'compiled source changed: ' + name)


def test_binary(data: bytes, source: Path, target: Path) -> Path:
    candidates = []
    for line in data.splitlines():
        row = parse_strict_json_bytes(line, label='Cargo build event')
        require(isinstance(row, dict), 'Cargo build event is not an object')
        if row.get('reason') == 'compiler-artifact' and row['profile']['test'] and row.get('executable'):
            require(row['target']['src_path'] == str(source / 'src/lib.rs'), 'unexpected test executable')
            path = Path(row['executable'])
            require(path == path.resolve(strict=True), 'noncanonical test binary path')
            candidates.append(path)
    require(len(candidates) == 1 and candidates[0].is_relative_to(target), 'test binary identity differs')
    return candidates[0]


def build_binary(run, work: Path, variant: str, environment: dict) -> Path:
    source = work / variant / 'source'
    target = work / variant / 'build'
    environment = dict(environment, CARGO_TARGET_DIR=str(target))
    data = run(['cargo', 'test', '--locked', '--release', '--all-features', '--lib', '--no-run',
                '--message-format=json'], 'build-' + variant, source, environment=environment)
    binary = test_binary(data, source, target)
    require(snapshot(source / 'Cargo.lock') == snapshot(work / 'baseline/source/Cargo.lock'),
            'dependency lock changed during build')
    return binary


def collect(output: Path, host: str) -> dict:
    require(platform.system() in ('Linux', 'Darwin') and os.name == 'posix', 'native Unix host required')
    output = fresh_output_directory(output, within=ROOT / 'target', label='fanout experiment output')
    output.mkdir(parents=True, mode=0o700)
    public, work = output / 'public', output / 'work'
    public.mkdir(); work.mkdir()

    def run(argv, label, cwd, *, environment=None, timeout=900, binary=False, fields=None):
        started = time.monotonic()
        record = dict(argv=argv, cwd=str(cwd), timeout_seconds=timeout, **(fields or {}))
        write_json(public / (label + '.started.json'), record)
        print(f'FANOUT_COMMAND label={label} state=started', flush=True)
        try:
            with contextlib.chdir(cwd):
                result = capture_output(argv, timeout_seconds=timeout, maximum_stdout_bytes=16 * 1024**2,
                                        maximum_stderr_bytes=16 * 1024**2, environment=environment)
        except BaseException as error:
            write_json(public / (label + '.interrupted.json'),
                       dict(record, error_type=type(error).__name__, error=str(error),
                            elapsed_seconds=time.monotonic() - started))
            raise
        (public / (label + '.stdout')).write_bytes(result.stdout)
        (public / (label + '.stderr')).write_bytes(result.stderr)
        write_json(public / (label + '.json'), dict(record, returncode=result.returncode,
                    elapsed_seconds=time.monotonic() - started, load_after=os.getloadavg()))
        require(result.returncode == 0, f'{label} failed; retained streams identify the failure')
        diagnostics = result.stderr if binary else result.stdout + result.stderr
        require(re.search(rb'(?mi)^\s*(warning:|error:)', diagnostics) is None,
                f'{label} emitted warnings/errors')
        print(f'FANOUT_COMMAND label={label} state=finished', flush=True)
        return result.stdout

    head = run(['git', 'rev-parse', 'HEAD'], 'head', ROOT).decode().strip()
    require(re.fullmatch('[0-9a-f]{40}', head) is not None, 'candidate commit identity differs')
    require(run(['git', 'status', '--porcelain', '--untracked-files=no'], 'status', ROOT) == b'',
            'dirty source checkout')
    compiler = run(['rustc', '-vV'], 'rustc', ROOT).decode()
    require(compiler.splitlines()[0] == 'rustc 1.98.1 (48a229cea 2026-09-01)'
            and f'host: {host}\n' in compiler, 'compiler/host differs')
    expected = {'aarch64-apple-darwin': ('Darwin', 'arm64'),
                'x86_64-unknown-linux-gnu': ('Linux', 'x86_64')}
    require(host in expected and (platform.system(), platform.machine()) == expected[host],
            'actual machine differs; Intel macOS is not supported')
    sysroot = Path(run(['rustc', '--print', 'sysroot'], 'sysroot', ROOT).decode().strip())
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(('CARGO_', 'RUST', 'QPC_', 'QPERIAPT_', 'AWS_LC_'))}
    environment.update(PATH=str(sysroot / 'bin') + os.pathsep + environment['PATH'],
                       CARGO_HOME=str(work / 'cargo-home'), CARGO_INCREMENTAL='0',
                       CARGO_TERM_COLOR='never', CARGO_HTTP_MULTIPLEXING='false',
                       RUSTFLAGS='-D warnings', RUSTDOCFLAGS='-D warnings')
    if platform.system() == 'Darwin':
        environment['DYLD_FALLBACK_LIBRARY_PATH'] = str(sysroot / 'lib')
    run([str(sysroot / 'lib/rustlib' / host / 'bin/rust-objcopy'), '--version'],
        'objcopy', ROOT, environment=environment)
    source = prepare_sources(run, work, head)
    write_json(public / 'SOURCE.json', source)
    binaries = {v: build_binary(run, work, v, environment) for v in ('baseline', 'candidate')}
    verify_sources(work, source)
    hashes = {v: binary_digest(p) for v, p in binaries.items()}
    identities(hashes)
    catalogs = {v: catalog(run([str(p), '--list'], 'catalog-' + v, ROOT, timeout=30))
                for v, p in binaries.items()}
    require(catalogs['baseline'] == catalogs['candidate'], 'variant test catalogs differ')
    filtered = len(catalogs['baseline']) - 1
    write_json(public / 'ENVIRONMENT.json', dict(system=platform.platform(), machine=platform.machine(),
               compiler=compiler, host=host, cpu_count=os.cpu_count(), load=os.getloadavg(),
               source=source, binary_sha256=hashes))
    for warmup, count in ((True, WARMUPS), (False, BLOCKS)):
        for block in range(count):
            order = ('baseline', 'candidate') if block % 2 == 0 else ('candidate', 'baseline')
            for position, variant in enumerate(order):
                label = f'{"warmup" if warmup else "block"}-{block:03}-{variant}'
                stdout = run([str(binaries[variant]), '--exact', TEST, '--nocapture', '--test-threads=1'],
                             label, ROOT, environment=environment, timeout=90,
                             fields=dict(variant=variant, warmup=warmup, block=block,
                                         order=position, load_before=os.getloadavg()))
                samples(stdout, snapshot(public / (label + '.stderr')), filtered)
    require(hashes == {v: binary_digest(p) for v, p in binaries.items()},
            'binary changed during execution')
    verify_sources(work, source)
    require(run(['git', 'status', '--porcelain', '--untracked-files=no'], 'final-status', ROOT) == b'',
            'source checkout changed')
    write_json(public / 'EXECUTION.json', dict(completed=True, blocks=BLOCKS, warmups=WARMUPS,
               test=TEST, filtered_tests=filtered, source=source, host=host, binary_sha256=hashes,
               binaries={v: str(p) for v, p in binaries.items()}))
    return review(public, public / 'REVIEW.json', head)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--host', required=True)
    args = parser.parse_args()
    report = collect(args.output, args.host)
    print(json.dumps(dict(completed=True, blocks=report['blocks'], timed_operations=report['timed_operations'],
                          p95_increased_positions=report['p95_increased_positions'],
                          performance_admission=False)))
