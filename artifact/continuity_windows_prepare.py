#!/usr/bin/env python3
"""Prepare one Windows consumer from nine admitted SDK crates and Cargo's candidate archive."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from continuity_c_consumer import EXPORTS
import continuity_package as candidate
import continuity_package_archive as bundle
import rust_sdk_profile as sdk


def prepare(args) -> None:
    output = args.output.resolve()
    output.mkdir()
    cohort_bytes = sdk.snapshot(args.report).data
    cohort = json.loads(cohort_bytes)
    sdk.require(cohort['base_commit'] == args.sdk_commit and cohort['git_dirty'] is False
                and cohort['sources_unchanged'] is True, 'SDK producer identity differs')
    outside = Path(tempfile.mkdtemp(prefix='qpc-windows-packaging-')).resolve()
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(('CARGO_', 'RUST', 'DYLD_', 'LD_', 'QPERIAPT_'))}
    environment.update(CARGO_HOME=str(outside / 'cargo-home'), CARGO_TARGET_DIR=str(outside / 'build'),
                       CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never',
                       RUSTFLAGS='-D warnings', RUSTDOCFLAGS='-D warnings')
    def run(argv, label, cwd=sdk.ROOT, *, env=None):
        return sdk.command(argv, output / label, cwd, environment=environment if env is None else env)
    compiler = run(['rustc', '-vV'], 'rustc')
    sdk.require(compiler.decode().splitlines()[0] == 'rustc 1.98.1 (48a229cea 2026-09-01)', 'producer compiler differs')
    revision = run(['git', 'rev-parse', 'HEAD'], 'source-head').decode().strip()
    sdk.require(not run(['git', 'status', '--porcelain', '--untracked-files=no'], 'source-status'), 'dirty producer')
    packages = sdk.classify(json.loads(run(['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'], 'workspace')))
    files, versions, archives = {}, {}, {}
    for name in sdk.CONSUMER_CRATES:
        record = cohort['crates'][name]
        archive = sdk.snapshot(args.report.parent / 'crates' / record['file'])
        sdk.require(archive.sha256 == record['sha256'] and archive.size == record['bytes'], 'SDK archive changed')
        members = sdk.validate_archive(archive.data, name, packages[name], set(record['files']))
        versions[name] = sdk.VERSION
        archives[name] = {'sha256': archive.sha256, 'bytes': archive.size}
        files.update({f'packages/{name}-{sdk.VERSION}/{p}': v for p, v in members.items()})
    archive, members = candidate.package_candidate(['cargo'], outside / 'source', outside / 'build',
        args.report.parent, cohort, packages, output, run, environment)
    versions[candidate.NAME] = candidate.VERSION
    archives[candidate.NAME] = {k: archive[k] for k in ('sha256', 'bytes')}
    files.update({f'packages/{candidate.NAME}-{candidate.VERSION}/{p}': v for p, v in members.items()})
    prefix = 'bindings/c/ContinuityPackageConsumer/'
    tracked = run(['git', 'ls-files', prefix], 'facade-inputs').decode().splitlines()
    selected = [p for p in tracked if p[len(prefix):].startswith('src/') or
                p[len(prefix):] in ('Cargo.toml', 'qpc_owner.h', 'first_configuration_client.c') or
                p[len(prefix):].startswith('configuration_') and p.endswith('_client.c')]
    source_hashes = {}
    for relative in selected:
        snap = sdk.snapshot(sdk.ROOT / relative)
        files[relative[len(prefix):]] = snap.data
        source_hashes[relative] = snap.sha256
    files['original-Cargo.lock'] = sdk.snapshot(candidate.CANDIDATE / 'Cargo.lock').data
    files['Cargo.lock'] = files['original-Cargo.lock']
    manifest = files['Cargo.toml'].decode() + '\n[patch.crates-io]\n'
    manifest += ''.join(f'{name} = {{ path = "packages/{name}-{version}" }}\n' for name, version in versions.items())
    files['Cargo.toml'] = manifest.encode()
    zipped = bundle.archive(files)
    (output / 'consumer.zip').write_bytes(zipped)
    sdk.write_json(output / 'INPUT.json', {
        'schema': 1, 'exports': sorted(EXPORTS), 'rustc': compiler.decode(), 'scope': 'Unpublished installed Windows candidate; no protocol or release admission',
        'source_commit': revision, 'sdk_commit': args.sdk_commit,
        'sdk_report_sha256': hashlib.sha256(cohort_bytes).hexdigest(), 'source_files': source_hashes,
        'archives': archives, 'versions': versions, 'consumer': 'q-periapt-continuity-c-consumer',
        'zip_sha256': hashlib.sha256(zipped).hexdigest(),
        'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    })
    print('WINDOWS_INSTALLED_INPUT_PASS sdk_crates=9 candidate_crates=1')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--sdk-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    prepare(parser.parse_args())
