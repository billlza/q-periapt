#!/usr/bin/env python3
"""Prepare one Windows consumer from nine admitted SDK crates and Cargo's candidate archive."""
import argparse
import hashlib
import os
from pathlib import Path
import tempfile

from evidence_io import parse_strict_json_bytes
from continuity_c_consumer import EXPORTS
import continuity_package as candidate
import continuity_package_archive as bundle
from continuity_windows_bundle import components
from continuity_fetch import fetch_locked
from rust_publish_contract import RustPublishContractError
import rust_sdk_profile as sdk


FACADE_PREFIX = 'bindings/c/ContinuityPackageConsumer/'


def consumer_inputs(tracked: list[str]) -> list[str]:
    """Select the installed Windows facade and its independent Rust test inputs."""
    configuration_inputs = {'tests/common/' + name + '.rs' for name in (
        'recovery_inputs', 'credential_request', 'first_account', 'first_connection',
        'first_credential', 'first_expiry', 'first_policy', 'first_policy_credential',
        'peer_bundle', 'policy_request', 'receiver_policy', 'receiver_process',
        'witness', 'witness_tls', 'witness_tls_faults', 'witness_tls_relay', 'witness_tls_outcome')}
    return [p for p in tracked if p[len(FACADE_PREFIX):].startswith('src/') or
            p[len(FACADE_PREFIX):] in ('Cargo.toml', 'tests/c_owner.rs', 'tests/root.rs',
                                     'tests/first_configuration.rs', 'tests/witness_tls_diagnostics.rs') or
            p[len(FACADE_PREFIX):] in configuration_inputs or p[len(FACADE_PREFIX):].startswith('tests/root/') or
            '/' not in p[len(FACADE_PREFIX):] and p.endswith(('.c', '.h'))]


def public_inventory() -> dict:
    from continuity_enrollment import FILES, REOPEN_FILES, REGISTRATION_FILES, ROLES
    from continuity_device_replacement import FILES as replacement, ROLES as replaced_roles
    from continuity_device_retirement import FILES as retirement
    from continuity_roster_renewal import FIXED_FILES as roster
    return {'enrollment': sorted(f'{role}/{name}' for role in ROLES for name in FILES),
            'reopen': sorted(f'{role}/{name}' for role in ROLES for name in REOPEN_FILES),
            'replacement': sorted(set(replacement) | {f'{role}/{name}' for role in replaced_roles for name in REGISTRATION_FILES}),
            'retirement': sorted(retirement), 'roster': sorted(roster)}


def prepare(args) -> None:
    output = args.output.resolve()
    output.mkdir()
    cohort_bytes = sdk.snapshot(args.report).data
    cohort = parse_strict_json_bytes(cohort_bytes, label='admitted SDK archive report')
    sdk.require(cohort['base_commit'] == args.sdk_commit and cohort['git_dirty'] is False
                and cohort['sources_unchanged'] is True, 'SDK producer identity differs')
    outside = Path(tempfile.mkdtemp(prefix='qpc-windows-packaging-')).resolve()
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(('CARGO_', 'RUST', 'DYLD_', 'LD_', 'QPERIAPT_'))}
    environment.update(CARGO_HOME=str(outside / 'cargo-home'), CARGO_TARGET_DIR=str(outside / 'build'),
                       CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never',
                       RUSTFLAGS='-D warnings', RUSTDOCFLAGS='-D warnings')
    def execute(argv, label, cwd=sdk.ROOT, *, env=None):
        return sdk.command(argv, output / label, cwd, environment=environment if env is None else env)
    def run(argv, label, cwd=sdk.ROOT, *, env=None):
        if label == 'fetch':
            return fetch_locked(argv, output, cwd, environment if env is None else env,
                                execute=execute, read=lambda path: sdk.snapshot(path).data,
                                write_json=sdk.write_json,
                                command_errors=(ValueError, RustPublishContractError))
        return execute(argv, label, cwd, env=env)
    compiler = run(['rustc', '-vV'], 'rustc')
    sdk.require(compiler.decode().splitlines()[0] == 'rustc 1.98.1 (48a229cea 2026-09-01)', 'producer compiler differs')
    revision = run(['git', 'rev-parse', 'HEAD'], 'source-head').decode().strip()
    sdk.require(not run(['git', 'status', '--porcelain', '--untracked-files=no'], 'source-status'), 'dirty producer')
    packages = sdk.classify(parse_strict_json_bytes(run(['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'], 'workspace'), label='SDK workspace metadata'))
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
    prefix = FACADE_PREFIX
    tracked = run(['git', 'ls-files', prefix], 'facade-inputs').decode().splitlines()
    selected = consumer_inputs(tracked)
    source_hashes = {}
    for relative in selected:
        snap = sdk.snapshot(sdk.ROOT / relative)
        files[relative[len(prefix):]] = snap.data
        source_hashes[relative] = snap.sha256
    files['original-Cargo.lock'] = sdk.snapshot(candidate.CANDIDATE / 'Cargo.lock').data
    files['Cargo.lock'] = files['original-Cargo.lock']
    manifest = files['Cargo.toml'].decode()
    for target in ('configuration_paths', 'owned_connection'):
        manifest += f'\n[[test]]\nname = "{target}"\npath = "packages/q-periapt-continuity-identity-candidate-0.0.0/tests/{target}.rs"\n'
    manifest += '\n[patch.crates-io]\n'
    manifest += ''.join(f'{name} = {{ path = "packages/{name}-{version}" }}\n' for name, version in versions.items())
    files['Cargo.toml'] = manifest.encode()
    zipped = bundle.archive(files, components=components(versions))
    (output / 'consumer.zip').write_bytes(zipped)
    sdk.write_json(output / 'INPUT.json', {
        'schema': 1, 'network_public_inventory': public_inventory(), 'exports': sorted(EXPORTS), 'rustc': compiler.decode(), 'scope': 'Unpublished installed Windows candidate; no protocol or release admission',
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
