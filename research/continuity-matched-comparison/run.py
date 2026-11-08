#!/usr/bin/env python3
"""Prepare isolated source derivatives and execute the matched research run."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib

from schedule import canonical, manifest, require

BASE = '358b921ab3469ce49f166633fc9a762ff6ed7e3d'
SPQR = 'f2589fef855c10f39d72634dab3d14654dd410bf'
SPQR_TREE = '7286f31638620152a770f6c4d2e86ac6862a0319'
SPQR_LOCK = 'e130211d61c7875cf5d94e606487a1da51845446e118633b6099e1f2d0303688'
RUST = '1.98.1'
HERE = Path(__file__).resolve().parent
NATIVE = Path('research/continuity-identity-candidate')
BRAID = Path('research/continuity-spqr-reference')
WHOLE = Path('research/continuity-whole-kem-reference')
SOURCE_PATHS = ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo', 'crates',
                'ctstats', 'models', 'services', 'bindings', 'artifact', str(NATIVE), str(BRAID), str(WHOLE),
                'research/continuity-openssl-peer')


def sha(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f'not a regular file: {path}')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(canonical(data))


def command(args: list[str], *, cwd: Path, logfile: Path, env=None) -> str:
    logfile.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open('xb') as stream:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, check=False, timeout=3600)
    print(f'{args[0]}: exit {result.returncode}; log {logfile.name}', flush=True)
    require(result.returncode == 0, f'command failed ({result.returncode}): {args}; see {logfile}')
    return logfile.read_text()


def git(repository: Path, *args: str) -> bytes:
    return subprocess.run(['git', '-C', str(repository), *args], capture_output=True, check=True, timeout=120).stdout


def archive(repository: Path, revision: str, output: Path, paths: tuple[str, ...] = ()) -> None:
    output.mkdir()
    data = git(repository, 'archive', '--format=tar', revision, *paths)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive_file:
        for item in archive_file:
            name = Path(item.name)
            require(not name.is_absolute() and '..' not in name.parts, 'archive path')
            require(item.isdir() or item.isfile(), f'unsupported source entry: {item.name}')
            path = output / name
            if item.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                content = archive_file.extractfile(item)
                require(content is not None, 'missing archive content')
                with path.open('xb') as stream:
                    shutil.copyfileobj(content, stream)
                path.chmod(item.mode & 0o777)


def replace(path: Path, old: str, new: str) -> None:
    content = path.read_text()
    require(content.count(old) == 1, f'instrumentation anchor is not unique: {path}: {old[:50]}')
    path.write_text(content.replace(old, new))


def inventory(root: Path) -> list[dict]:
    result = []
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if any(part in ('.git', 'target', '__pycache__') for part in rel.parts):
            continue
        require(not path.is_symlink(), f'source symlink: {path}')
        if path.is_file():
            result.append({'path': rel.as_posix(), 'bytes': path.stat().st_size, 'sha256': sha(path)})
    return result


def instrument_reference(root: Path, kind: str) -> None:
    path = root / 'src/main.rs'
    # This observer feed never enters Snapshot/predict/recover_pending. It is
    # private even though reference entropy is a documented public fixture.
    helper = '''
fn measurement_file(output: &Path, name: &str) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(output.join(format!(".private-{name}.keys")))
}
'''
    with path.open('a') as stream:
        stream.write(helper)
    if kind == 'spqr':
        replace(path, '    writer: BufWriter<File>,', '    writer: BufWriter<File>,\n    measurement: BufWriter<File>,')
        replace(path, '        writer: BufWriter::new(file),',
                '        writer: BufWriter::new(file),\n        measurement: BufWriter::new(measurement_file(output, name)?),')
        replace(path, '        self.compromise.sent(sequence, sender, &result.msg, &key)?;',
                '        writeln!(self.measurement, "{sequence} {sender} {}", hex(&key))?;\n        self.compromise.sent(sequence, sender, &result.msg, &key)?;')
        replace(path, '    run.writer.flush()?;', '    run.measurement.flush()?;\n    run.writer.flush()?;')
    else:
        replace(path, '    trace: File,', '    trace: File,\n    measurement: File,')
        replace(path, '        trace: File::create_new(&path)?,',
                '        trace: File::create_new(&path)?,\n        measurement: measurement_file(output, name)?,')
        replace(path, '        self.expected.push(key.clone());',
                '        writeln!(self.measurement, "{sequence} {sender} {}", hex(&key))?;\n        self.expected.push(key.clone());')


def prepare(repository: Path, output: Path) -> dict:
    require(git(repository, 'rev-parse', BASE).decode().strip() == BASE, 'base commit unavailable')
    output.mkdir()
    source = output / 'source'
    archive(repository, BASE, source, SOURCE_PATHS)
    before = inventory(source)
    test = source / NATIVE / 'src/durable/messages/tests.rs'
    with test.open('a') as stream:
        stream.write('\nmod matched_comparison {\n' + (HERE / 'native_driver.rs.txt').read_text() + '\n}\n')
    # Keep a pristine driver for the upstream's already reviewed chunk64 patch.
    shutil.copytree(source / BRAID, output / 'pristine-spqr')
    instrument_reference(source / BRAID, 'spqr')
    instrument_reference(source / WHOLE, 'whole')
    receipt = {'schema': 1, 'status': 'prepared_not_executed', 'base_commit': BASE,
               'base_tree': git(repository, 'rev-parse', BASE + '^{tree}').decode().strip(),
               'research_head': git(repository, 'rev-parse', 'HEAD').decode().strip(),
               'toolchain': RUST, 'source_paths': SOURCE_PATHS, 'before': before, 'after': inventory(source),
               'research_files': [{'path': p.name, 'sha256': sha(p)} for p in sorted(HERE.iterdir())
                                  if p.is_file() and p.suffix in ('.py', '.md', '.txt', '.yml')],
               'schedule': manifest()}
    save(output / 'preparation.json', receipt)
    return receipt


def prepare_variant(source: Path, output: Path, env: dict) -> dict:
    metadata_log = output / 'logs/spqr-metadata.jsonl'
    metadata_text = command(['cargo', '+' + RUST, 'metadata', '--manifest-path', str(source / BRAID / 'Cargo.toml'),
                             '--locked', '--format-version', '1'], cwd=source, logfile=metadata_log, env=env)
    candidates = [json.loads(line) for line in metadata_text.splitlines() if line.startswith('{')]
    require(len(candidates) == 1, 'Cargo metadata document count')
    packages = [p for p in candidates[0]['packages'] if p['name'] == 'spqr']
    require(len(packages) == 1, 'SPQR resolved package count')
    upstream = Path(packages[0]['manifest_path']).parent
    require(git(upstream, 'rev-parse', 'HEAD').decode().strip() == SPQR, 'SPQR upstream commit')
    require(git(upstream, 'rev-parse', 'HEAD^{tree}').decode().strip() == SPQR_TREE, 'SPQR upstream tree')
    require(not git(upstream, 'status', '--porcelain', '--untracked-files=no'), 'SPQR upstream edited')
    require(sha(upstream / 'Cargo.lock') == SPQR_LOCK, 'SPQR dependency lock')
    variant = output / 'variant'
    variant.mkdir()
    archive(upstream, SPQR, variant / 'upstream')
    driver = variant / 'driver'
    driver.mkdir()
    for name in ('Cargo.toml', 'Cargo.lock', 'LICENSE', 'src/main.rs', 'src/compromise.rs'):
        path = driver / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output / 'pristine-spqr' / name, path)
    for folder, patch in ((variant / 'upstream', 'chunk64.patch'), (driver, 'chunk64-driver.patch')):
        command(['git', 'init', '--quiet', '--initial-branch=reference'], cwd=folder,
                logfile=output / f'logs/{patch}-init.log', env=env)
        command(['git', 'apply', '--unidiff-zero', '--check', str(source / BRAID / 'variants' / patch)], cwd=folder,
                logfile=output / f'logs/{patch}-check.log', env=env)
        command(['git', 'apply', '--unidiff-zero', str(source / BRAID / 'variants' / patch)], cwd=folder,
                logfile=output / f'logs/{patch}-apply.log', env=env)
    original = tomllib.loads((output / 'pristine-spqr/Cargo.lock').read_text())
    modified = tomllib.loads((driver / 'Cargo.lock').read_text())
    selected = [p for p in original['package'] if p['name'] == 'spqr']
    require(len(selected) == 1 and selected[0].pop('source') ==
            f'git+https://github.com/signalapp/SparsePostQuantumRatchet?rev={SPQR}#{SPQR}', 'SPQR dependency source')
    require(original == modified, 'chunk64 changed dependency closure')
    instrument_reference(driver, 'spqr')
    receipt = {'schema': 1, 'upstream_commit': SPQR, 'upstream_tree': SPQR_TREE,
               'upstream_lock_sha256': SPQR_LOCK, 'source': inventory(variant)}
    save(output / 'variant-preparation.json', receipt)
    return receipt


def run(repository: Path, output: Path) -> None:
    prepare(repository, output)
    source = output / 'source'
    evidence = output / 'evidence'
    evidence.mkdir()
    env = dict(os.environ)
    env['CARGO_TARGET_DIR'] = str(output / 'build')
    env['RUSTUP_TOOLCHAIN'] = RUST
    env['RUST_BACKTRACE'] = '1'
    env['QPERIAPT_MATCHED_OUTPUT'] = str(evidence / 'native')
    (evidence / 'native').mkdir()
    started = time.time_ns()
    tools = {}
    for name, argv in [('rustc', ['rustc', '+' + RUST, '-Vv']), ('cargo', ['cargo', '+' + RUST, '-V']),
                       ('protoc', ['protoc', '--version'])]:
        tools[name] = command(argv, cwd=source, logfile=output / f'logs/{name}.log', env=env).strip()
    save(output / 'runtime.json', {'schema': 1, 'platform': platform.platform(), 'python': sys.version,
                                'tools': tools, 'started_ns': started})
    # Compilation produces a concrete executable receipt. Its exact test name is
    # obtained from --list, and a zero-test execution cannot pass validation.
    build = command(['cargo', '+' + RUST, 'test', '--manifest-path', str(source / NATIVE / 'Cargo.toml'),
                     '--locked', '--release', '--lib', '--no-run', '--message-format=json'],
                    cwd=source, logfile=output / 'logs/native-build.jsonl', env=env)
    executables = []
    for line in build.splitlines():
        if not line.startswith('{'):
            continue
        record = json.loads(line)
        if record.get('reason') == 'compiler-artifact' and record.get('executable') and record['profile']['test']:
            executables.append(Path(record['executable']))
    require(len(executables) == 1, 'native test executable inventory')
    binary = executables[0]
    listing = command([str(binary), '--list'], cwd=source, logfile=output / 'logs/native-tests.log', env=env)
    names = [line.removesuffix(': test') for line in listing.splitlines()
             if line.endswith('matched_directed_opportunities_native: test')]
    require(len(names) == 1, 'native exact test name')
    executable_records = [{'profile': 'continuity-32,64', 'path': str(binary.relative_to(output)), 'sha256': sha(binary)}]
    command([str(binary), '--exact', names[0], '--nocapture', '--test-threads=1'], cwd=source,
            logfile=output / 'logs/native-run.log', env=env)
    prepare_variant(source, output, env)
    variants = [('spqr-32', source / BRAID, env), ('spqr-64', output / 'variant/driver',
                 {**env, 'CARGO_TARGET_DIR': str(output / 'build-chunk64')}), ('whole-kem', source / WHOLE, env)]
    for profile, folder, build_env in variants:
        command(['cargo', '+' + RUST, 'build', '--manifest-path', str(folder / 'Cargo.toml'), '--locked', '--release'],
                cwd=source, logfile=output / f'logs/{profile}-build.log', env=build_env)
        filename = 'q-periapt-whole-kem-reference' if profile == 'whole-kem' else 'q-periapt-spqr-reference'
        executable = Path(build_env['CARGO_TARGET_DIR']) / 'release' / filename
        executable_records.append({'profile': profile, 'path': str(executable.relative_to(output)), 'sha256': sha(executable)})
        command([str(executable), str(evidence / profile)], cwd=source,
                logfile=output / f'logs/{profile}-run.log', env=build_env)
    save(output / 'executables.json', executable_records)
    from validate import validate_all
    report = validate_all(output)
    require(inventory(source) == json.loads((output / 'preparation.json').read_text())['after'], 'prepared source changed during execution')
    require(inventory(output / 'variant') == json.loads((output / 'variant-preparation.json').read_text())['source'], 'variant source changed during execution')
    require(not list(evidence.rglob('.private-*')), 'private key feed remains')
    report.update({'execution': 'native_compiled_and_executed', 'base_commit': BASE,
                   'elapsed_seconds': (time.time_ns() - started) / 1e9,
                   'executables': executable_records})
    save(evidence / 'matched-report.json', report)
    save(evidence / 'manifest.json', {'schema': 1, 'status': 'complete', 'files': inventory(evidence)})
    print('Complete matched native/reference execution and validation.', flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('prepare', 'run'))
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    try:
        if args.mode == 'prepare':
            prepare(args.repository.resolve(), output)
        else:
            run(args.repository.resolve(), output)
    finally:
        # Private observation feeds are never uploaded, including a failed run.
        if output.exists():
            for path in output.rglob('.private-*.keys'):
                require(path.is_file() and not path.is_symlink(), 'private feed type')
                path.unlink()


if __name__ == '__main__':
    main()
