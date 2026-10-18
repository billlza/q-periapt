#!/usr/bin/env python3
"""Build an installed archive closure and execute an independent Windows C client."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from evidence_io import parse_strict_json_bytes, read_regular_snapshot
import continuity_package_archive as bundle
from installed_rust_graph import require, verify_resolution

LIB = 'q_periapt_continuity_c_consumer'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def consume(args):
    require(os.name == 'nt', 'native Windows is required')
    output = args.output.resolve()
    output.mkdir()
    receipt = parse_strict_json_bytes(read_regular_snapshot(args.input, maximum=16 * 1024**2, label='Windows package receipt').data, label='Windows package receipt')
    payload = args.input.with_name('consumer.zip').read_bytes()
    require(hashlib.sha256(payload).hexdigest() == receipt['zip_sha256'], 'input archive changed')
    outside = Path(tempfile.mkdtemp(prefix='qpc-installed-windows-')).resolve()
    consumer, build = outside / 'consumer', outside / 'build'
    bundle.unpack(payload, receipt['files'], consumer)
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(('CARGO_', 'RUST', 'QPC_', 'QPERIAPT_', 'AWS_LC_'))}
    environment.update(CARGO_HOME=str(outside / 'cargo-home'), CARGO_TARGET_DIR=str(build),
                       CARGO_INCREMENTAL='0', CARGO_TERM_COLOR='never', RUSTFLAGS='-D warnings',
                       RUSTDOCFLAGS='-D warnings', QPC_FIRST_USE_ROOT=str(args.private_root.resolve()))
    # Same private static AWS-LC boundary as artifact/windows-package.ps1.
    # The bundled jitter header exports its internals even in a static build.
    # Remove only that storage-class modifier; retain dllimport, other declspec
    # attributes and every entropy operation. The final export set stays exact.
    aws_lc = {'AWS_LC_SYS_STATIC_x86_64_pc_windows_msvc': '1',
              'AWS_LC_SYS_USE_SYSTEM_x86_64_pc_windows_msvc': '0',
              'AWS_LC_SYS_CFLAGS_x86_64_pc_windows_msvc': '/WX /Ddllexport='}
    environment.update(aws_lc)
    result = {'schema': 1, 'input_sha256': digest(args.input), 'input': receipt, 'aws_lc_build': aws_lc,
              'scope': 'Installed Windows C first-use only; no full session or release admission', 'profiles': {}}
    def run(argv, label, cwd=consumer, timeout=900):
        prefix = output / label
        with prefix.with_suffix('.stdout').open('xb') as out, prefix.with_suffix('.stderr').open('xb') as err:
            child = subprocess.Popen(argv, cwd=cwd, env=environment, stdout=out, stderr=err)
            try:
                code = child.wait(timeout=timeout)
            except BaseException:
                if child.poll() is None:
                    subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'], check=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
                    child.wait(timeout=10)
                raise
        prefix.with_suffix('.json').write_text(json.dumps({'argv': argv, 'cwd': str(cwd), 'returncode': code}))
        require(code == 0, f'{label} failed ({code}); see retained command streams')
        require(all(prefix.with_suffix(ext).stat().st_size <= 16 * 1024**2 for ext in ('.stdout', '.stderr')), 'command log exceeds bound')
        text = prefix.with_suffix('.stdout').read_text(encoding='utf-8')
        diagnostics = prefix.with_suffix('.stderr').read_text(encoding='utf-8')
        require(re.search(r'(?mi)^\s*warning:', text + diagnostics) is None, f'{label} emitted warnings')
        return text
    require(run(['git', 'rev-parse', 'HEAD'], 'source-head', Path(__file__).resolve().parent.parent).strip() == receipt['source_commit'], 'producer and consumer source differ')
    result['rustc'] = run(['rustc', '-vV'], 'rustc')
    result['clang'] = run(['clang', '--version'], 'clang')
    require(result['rustc'].splitlines()[0] == 'rustc 1.98.1 (48a229cea 2026-09-01)', 'consumer compiler differs')
    require('host: x86_64-pc-windows-msvc' in result['rustc'], 'unexpected native Rust target')
    metadata = parse_strict_json_bytes(run(['cargo', 'metadata', '--format-version', '1'], 'metadata').encode(), label='installed Windows Cargo metadata')
    lock = (consumer / 'Cargo.lock').read_bytes()
    result['resolution'] = verify_resolution(metadata, consumer, lock, (consumer / 'original-Cargo.lock').read_bytes(),
        consumer_name=receipt['consumer'], versions=receipt['versions'])
    for row in metadata['packages']:
        if not row['name'].startswith('q-periapt'):
            require(row['source'] == 'registry+https://github.com/rust-lang/crates.io-index', 'non-registry external source')
    candidate = next(row for row in metadata['packages'] if row['name'] == 'q-periapt-continuity-identity-candidate')
    node = next(row for row in metadata['resolve']['nodes'] if row['id'] == candidate['id'])
    require(candidate['publish'] == [] and {'connection-tls', 'control-tls', 'anchor-tls'} <= set(node['features']), 'candidate features changed')
    (output / 'Cargo.lock').write_bytes(lock)
    environment['CARGO_NET_OFFLINE'] = 'true'
    run(['cargo', 'clippy', '--locked', '--lib', '--tests', '--', '-D', 'warnings'], 'clippy')
    for profile in ('debug', 'release'):
        flags = ['--release'] if profile == 'release' else []
        run(['cargo', 'build', '--locked', '--lib', *flags], profile + '-build')
        files = {'qpc_owner.h': (consumer / 'qpc_owner.h').read_bytes()}
        for suffix in ('.dll', '.dll.lib'):
            files[LIB + suffix] = (build / profile / (LIB + suffix)).read_bytes()
        zipped = bundle.archive(files)
        (output / (profile + '-c-input.zip')).write_bytes(zipped)
        hashes = {p: hashlib.sha256(v).hexdigest() for p, v in files.items()}
        installed = outside / (profile + '-installed')
        bundle.unpack(zipped, hashes, installed)
        exports = run(['dumpbin', '/nologo', '/exports', str(installed / (LIB + '.dll'))], profile + '-exports', installed)
        names = re.findall(r'^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)\s*$', exports, re.M)
        require(len(names) == len(receipt['exports']) and set(names) == set(receipt['exports']), 'C export set differs')
        # Compile the client with only the installed public header and import library.
        client_source = outside / (profile + '-client')
        client_source.mkdir()
        for name in receipt['files']:
            if '/' not in name and name.endswith('.c'):
                shutil.copyfile(consumer / name, client_source / name)
        executable = installed / 'first-configuration.exe'
        run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
             str(client_source / 'first_configuration_client.c'), '-I', str(installed),
             str(installed / (LIB + '.dll.lib')), '-o', str(executable)], profile + '-c-compile', client_source)
        guard = run([str(executable), '--guard'], profile + '-guard', installed, timeout=30)
        require(guard.strip() == 'QPC_CONFIGURATION_HEADER_GUARD_PASS', 'C header guard did not pass')
        environment['QPC_FIRST_USE_CLIENT'] = str(executable)
        tests = run(['cargo', 'test', '--locked', '--lib', *flags,
                     'first_install::windows_c_tests::', '--', '--nocapture'], profile + '-runtime')
        stderr = (output / (profile + '-runtime.stderr')).read_text(encoding='utf-8')
        require(re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored;', tests), 'C runtime test did not execute')
        markers = re.findall(r'^WINDOWS_INSTALLED_C_FIRST_USE case=(\w+) trust=(\w+) exit=(\d+) expected=true$', stderr, re.M)
        expected = {(case, trust, '0' if case in ('create', 'reconcile', 'open') else '1')
                    for case in ('create', 'reconcile', 'open', 'duplicate', 'busy', 'missing', 'advanced')
                    for trust in ('fixed', 'recoverable')}
        require(len(markers) == len(expected) and set(markers) == expected, 'C runtime case census differs')
        require(all(digest(installed / name) == sha for name, sha in hashes.items()), 'installed C inputs changed')
        result['profiles'][profile] = {'files': hashes, 'zip_sha256': hashlib.sha256(zipped).hexdigest(),
            'client_sha256': digest(executable), 'header_guard': True, 'cases': sorted(markers)}
    for name, sha in receipt['files'].items():
        require(digest(consumer / name) == (hashlib.sha256(lock).hexdigest() if name == 'Cargo.lock' else sha), 'consumed source changed: ' + name)
    (output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print('WINDOWS_INSTALLED_C_FIRST_USE_PASS profiles=2 trust_modes=2 cases_per_profile=14')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-root', type=Path, required=True)
    consume(parser.parse_args())
