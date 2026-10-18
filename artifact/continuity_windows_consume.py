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
from continuity_connection_public import capture
from continuity_windows_c_public import CASES, capture_case

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
    private_root = args.private_root.resolve()
    require(private_root.is_dir() and not any(private_root.iterdir()), 'fixture parent must be empty')
    environment.update(CARGO_HOME=str(outside / 'cargo-home'), CARGO_TARGET_DIR=str(build),
                       CARGO_INCREMENTAL='0', CARGO_TERM_COLOR='never', RUSTFLAGS='-D warnings',
                       RUSTDOCFLAGS='-D warnings', QPC_FIRST_USE_ROOT=str(private_root),
                       QPERIAPT_PRIVATE_FIXTURE_ROOT=str(private_root))
    # Same private static AWS-LC boundary as artifact/windows-package.ps1.
    # The bundled jitter header exports its internals even in a static build.
    # Remove only that storage-class modifier; retain dllimport, other declspec
    # attributes and every entropy operation. The final export set stays exact.
    aws_lc = {'AWS_LC_SYS_STATIC_x86_64_pc_windows_msvc': '1',
              'AWS_LC_SYS_USE_SYSTEM_x86_64_pc_windows_msvc': '0',
              'AWS_LC_SYS_CFLAGS_x86_64_pc_windows_msvc': '/WX /Ddllexport='}
    environment.update(aws_lc)
    result = {'schema': 1, 'input_sha256': digest(args.input), 'input': receipt, 'aws_lc_build': aws_lc,
              'scope': 'Installed Windows C first use and original C owner integration suite plus archive-shipped Rust lifecycle tests; public lifecycle readbacks require the separate existing verifier; no release admission', 'profiles': {}}
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
    def caller_controls(profile):
        controls = outside / (profile + '-caller-controls')
        controls.mkdir()
        client_source = outside / (profile + '-client')
        client_source.mkdir()
        for name in receipt['files']:
            if '/' not in name and name.endswith(('.c', '.h')) and name != 'qpc_owner.h':
                shutil.copyfile(consumer / name, client_source / name)
        platform_test = controls / 'consumer-platform-test.exe'
        run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
             *(['-O2'] if profile == 'release' else ['-O0', '-g']),
             str(client_source / 'consumer_platform_test.c'), '-o', str(platform_test)],
            profile + '-platform-compile', client_source)
        platform_result = run([str(platform_test)], profile + '-platform-runtime', controls, timeout=30)
        require(platform_result.strip() == 'CONSUMER_PLATFORM_PASS native_worker_join=true monotonic_clock=true sleep_completed=true',
                'native caller platform contract did not execute')
        report_test = controls / 'report-buffer-test.exe'
        run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
             *(['-O2'] if profile == 'release' else ['-O0', '-g']),
             str(client_source / 'report_buffer_test.c'), '-o', str(report_test)],
            profile + '-report-compile', client_source)
        report_result = run([str(report_test)], profile + '-report-runtime', controls, timeout=30)
        require(report_result.strip() == 'REPORT_BUFFER_PASS canonical_bytes=true size_limit=true failure_sticky=true',
                'native bounded report contract did not execute')
        effect_test = controls / 'application-effect-test.exe'
        run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
             *(['-O2'] if profile == 'release' else ['-O0', '-g']),
             str(client_source / 'application_effect_test.c'), '-lntdll', '-ladvapi32', '-o', str(effect_test)],
            profile + '-effect-compile', client_source)
        require(not any(private_root.iterdir()), 'application effect preflight requires an empty owned root')
        rename_probe = controls / 'publication-probe.exe'
        run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
             *(['-O2'] if profile == 'release' else ['-O0', '-g']),
             str(client_source / 'windows_publication_probe.c'), '-lntdll', '-ladvapi32', '-o', str(rename_probe)],
            profile + '-publication-probe-compile', client_source)
        observation = run([str(rename_probe), str(private_root)], profile + '-publication-probe', controls, timeout=30)
        require(observation.endswith('WINDOWS_RENAME_EXPERIMENT_COMPLETE publication_admission=false\n')
                and not any(private_root.iterdir()), 'rename experiment incomplete; original state retained')
        require(observation.splitlines().count('WINDOWS_RENAME_PROBE variant=2 bytes=184 success=1 error=0 source=1 target=0') == 1
                and len(re.findall(r'^WINDOWS_RENAME_COLLISION success=0 error=(?:80|183)$', observation, re.M)) == 1,
                'native relative rename or no-overwrite collision control failed')
        effect = run([str(effect_test), str(private_root)], profile + '-effect-preflight', controls, timeout=30)
        require(effect == 'effect-contract: two exact effects, duplicate idempotence, wrong payload and conflicting replay refused\n'
                'record-contract: bounded read, exact retention, missing and changed originals refused\n',
                'application effect preflight did not execute')
        records = {'application-' + (bytes([identifier]) + bytes(31)).hex():
                   bytes([1]) + bytes(31) + bytes([identifier]) + bytes(31) + body
                   for identifier, body in ((2, b'persisted before process exit'), (3, b'continued after pending recovery'))}
        require({p.name for p in private_root.iterdir()} == set(records), 'application effect preflight leaked or omitted records')
        for name, expected in records.items():
            require(read_regular_snapshot(private_root / name, maximum=128, label='C application effect').data == expected,
                    'application effect preflight bytes differ')
        # Only these two complete public test records belong to this preflight.
        # Failures above retain their state; native Rust later checks fresh records and ACLs.
        for name in records:
            (private_root / name).unlink()
        require(not any(private_root.iterdir()), 'application effect preflight cleanup incomplete')
        run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
             *(['-O2'] if profile == 'release' else ['-O0', '-g']),
             '-c', str(client_source / 'recovery_client.c'), '-I', str(consumer),
             '-o', str(controls / 'recovery-client.obj')],
            profile + '-recovery-compile', client_source)
        run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
             '-fsyntax-only', str(client_source / 'client.c'), str(client_source / 'opening_client.c'),
             '-I', str(consumer)], profile + '-owner-syntax', client_source)
        return client_source, effect_test
    # Check the independent C platform boundary before the expensive Rust build.
    # The actual effect processes still execute under the native Rust reader below.
    caller_checks = {profile: caller_controls(profile) for profile in ('debug', 'release')}
    run(['cargo', 'clippy', '--locked', '--lib', '--tests', '--', '-D', 'warnings'], 'clippy')
    for profile in ('debug', 'release'):
        flags = ['--release'] if profile == 'release' else []
        paths = run(['cargo', 'test', '--locked', '--test', 'configuration_paths', *flags,
                     '--', '--nocapture'], profile + '-configuration-paths')
        require('test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' in paths,
                'public configuration path controls did not execute')
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
        # This client sees only the installed public header/import library.
        client_source, effect_test = caller_checks[profile]
        executable = installed / 'first-configuration.exe'
        run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
             str(client_source / 'first_configuration_client.c'), '-I', str(installed),
             str(installed / (LIB + '.dll.lib')), '-o', str(executable)], profile + '-c-compile', client_source)
        guard = run([str(executable), '--guard'], profile + '-guard', installed, timeout=30)
        require(guard.strip() == 'QPC_CONFIGURATION_HEADER_GUARD_PASS', 'C header guard did not pass')
        environment['QPC_FIRST_USE_CLIENT'] = str(executable)
        environment['QPC_EFFECT_CLIENT'] = str(effect_test)
        tests = run(['cargo', 'test', '--locked', '--lib', *flags,
                     'first_install::windows_c_tests::', '--', '--nocapture'], profile + '-runtime')
        stderr = (output / (profile + '-runtime.stderr')).read_text(encoding='utf-8')
        require(re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored;', tests), 'C runtime test did not execute')
        markers = re.findall(r'^WINDOWS_INSTALLED_C_FIRST_USE case=(\w+) trust=(\w+) exit=(\d+) expected=true$', stderr, re.M)
        expected = {(case, trust, '0' if case in ('create', 'reconcile', 'open') else '1')
                    for case in ('create', 'reconcile', 'open', 'duplicate', 'busy', 'missing', 'advanced')
                    for trust in ('fixed', 'recoverable')}
        require(len(markers) == len(expected) and set(markers) == expected, 'C runtime case census differs')
        effects = re.findall(r'^WINDOWS_C_EFFECT case=([a-z-]+) original_boundary=true$', stderr, re.M)
        require(len(effects) == 6 and set(effects) == {'commit', 'directory-reparse', 'ancestor-reparse',
                'leaf-reparse', 'hardlink', 'public-acl'}, 'C application effect contract census differs')
        require(stderr.splitlines().count('WINDOWS_C_RECORD bounded_read=true exact_retention=true missing_original_refused=true') == 1,
                'C original record read/retention controls did not execute')
        require(all(digest(installed / name) == sha for name, sha in hashes.items()), 'installed C inputs changed')
        result['profiles'][profile] = {'files': hashes, 'zip_sha256': hashlib.sha256(zipped).hexdigest(),
            'client_sha256': digest(executable), 'header_guard': True, 'cases': sorted(markers)}
        require(not any(private_root.iterdir()), 'C fixture leaked private state after closing')
        owner_client = installed / 'owner-client.exe'
        run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
             *(['-O2'] if profile == 'release' else ['-O0', '-g']),
             *(str(client_source / name) for name in ('client.c', 'recovery_client.c', 'opening_client.c')),
             '-I', str(installed), str(installed / (LIB + '.dll.lib')), '-lntdll', '-ladvapi32',
             '-o', str(owner_client)], profile + '-owner-compile', client_source)
        # The shared driver uses an absent override for C; only Swift/Kotlin
        # wrappers supply QPERIAPT_INSTALLED_CLIENT_LANGUAGE.
        environment['QPERIAPT_C_OWNER_CLIENT'] = str(owner_client)
        owner = run(['cargo', 'test', '--locked', '--test', 'c_owner', *flags,
                     '--', '--nocapture'], profile + '-owner-runtime')
        owner_names = re.findall(r'^test ([a-z_:]+) \.\.\. ok$', owner, re.M)
        expected_owner = {
            'c_client_owns_installed_connection_rekeys_and_reconciles_exact_delivery',
            'c_device_parents_keep_peer_lifetimes_and_reconcile_original_delivery',
            'c_configured_peers_reopen_and_reconcile_original_delivery',
            'c_server_preserves_callback_failures_unknown_commits_replay_and_rekey',
            'c_recovery_preserves_complete_loss_accounting_after_revocation_and_process_exit',
            'installed_owner_restores_expired_advertisement_and_reconciles_original_message',
            'c_account_owner_requires_all_devices_and_reconciles_original_members',
            'fixture::service_peer_process',
            'fixture::owned_services_connect_restart_rekey_and_reconcile_unknown_delivery',
            'fixture::reopen::public_session_reopen_after_expiry_reconciles_unknown_commit_over_real_tls',
        }
        require(len(owner_names) == 10 and set(owner_names) == expected_owner and
                'test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' in owner,
                'original C owner integration suite did not execute completely')
        require(not any(private_root.iterdir()), 'C owner fixture leaked private state after closing')
        result['profiles'][profile]['owner_tests'] = sorted(owner_names)
        result['profiles'][profile]['owner_client_sha256'] = digest(owner_client)
        public = {}
        for kind, (test, suffix, _, _) in CASES.items():
            evidence = private_root / (profile + '-owner-' + kind)
            environment['QPERIAPT_PUBLIC_SERVICE_EVIDENCE'] = str(evidence)
            stdout = run(['cargo', 'test', '--locked', '--test', 'c_owner', *flags,
                          '--', '--exact', test, '--nocapture'], profile + '-owner-' + kind)
            environment.pop('QPERIAPT_PUBLIC_SERVICE_EVIDENCE')
            evidence = evidence.with_name(evidence.name + suffix)
            require(set(private_root.iterdir()) == {evidence}, 'C public workload leaked unexpected state')
            public[kind] = capture_case(kind, stdout.encode(), evidence,
                                       output / (profile + '-owner-public') / kind)
            # Only this successful invocation's private fixture is removed,
            # after exact public bytes replay through the original verifier.
            shutil.rmtree(evidence)
            require(not any(private_root.iterdir()), 'C public fixture cleanup incomplete')
        result['profiles'][profile]['owner_public'] = public
        environment.pop('QPERIAPT_C_OWNER_CLIENT')
        evidence = private_root / (profile + '-runtime')
        environment['QPERIAPT_PUBLIC_SERVICE_EVIDENCE'] = str(evidence)
        native = run(['cargo', 'test', '--locked', '--test', 'owned_connection', *flags,
                      '--', '--nocapture'], profile + '-owned-runtime')
        environment.pop('QPERIAPT_PUBLIC_SERVICE_EVIDENCE')
        names = re.findall(r'^test ([a-z_:]+) \.\.\. ok$', native, re.M)
        expected_tests = {'service_peer_process', 'owned_services_connect_restart_rekey_and_reconcile_unknown_delivery',
                          'reopen::public_session_reopen_after_expiry_reconciles_unknown_commit_over_real_tls'}
        require(len(names) == 3 and set(names) == expected_tests and
                'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' in native,
                'public lifecycle suite did not execute all original tests')
        roots = {evidence, *(evidence.with_name(evidence.name + suffix) for suffix in
                  ('-session-reopen', '-roster-renewal', '-device-replacement', '-device-retirement'))}
        require(set(private_root.iterdir()) == roots, 'fixture leaked temporary owners or unexpected state')
        result['profiles'][profile]['network_public'] = capture(evidence, output / (profile + '-network-public'),
                                                               receipt['network_public_inventory'])
        # These five fresh fixture trees are owned by this successful invocation.
        # Only public readbacks were exported; failed executions retain their state.
        for owned in roots:
            shutil.rmtree(owned)
        require(not any(private_root.iterdir()), 'closed fixture state was not removed')

    for name, sha in receipt['files'].items():
        require(digest(consumer / name) == (hashlib.sha256(lock).hexdigest() if name == 'Cargo.lock' else sha), 'consumed source changed: ' + name)
    (output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print('WINDOWS_INSTALLED_C_FIRST_USE_PASS profiles=2 trust_modes=2 cases_per_profile=14')
    print('WINDOWS_INSTALLED_C_OWNER_SUITE_EXECUTED profiles=2 entries_per_profile=10 public_workloads_per_profile=7 independent_host_readback=pending')
    print('WINDOWS_INSTALLED_RUST_LIFECYCLE_EXECUTED profiles=2 public_readback_verification=pending')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-root', type=Path, required=True)
    consume(parser.parse_args())
