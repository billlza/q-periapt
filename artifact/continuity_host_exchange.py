#!/usr/bin/env python3
"""Run the new host-exchange boundary from a source-bound installed reference wheel.

This reuses the existing wheel/installation verifiers. It does not invoke the
fixture native issuer, replay the unchanged full protocol suite, or claim host
login/native interoperability from the independent test issuers.
"""
from __future__ import annotations
import argparse
import ast
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from bounded_process import capture_output
from continuity_independent_python import PACKAGE, inspect_wheel, require, verify_installation
from continuity_independent_python_run import installed_files
from evidence_io import fresh_output_directory, parse_strict_json_bytes, read_regular_snapshot
from git_provenance import git_commit, run_git_bytes

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'research/continuity-openssl-peer'


def snapshot(path):
    return read_regular_snapshot(path, maximum=16 * 1024**2, label='host exchange input')


def inputs(commit):
    paths = [*sorted((SOURCE / PACKAGE).glob('*.py'))]
    paths += [SOURCE / name for name in ('tests/enrollment_exchange.py', 'tests/enrollment_client.py', 'pyproject.toml', 'README.md',
               'ENROLLMENT_EXCHANGE.md', 'ENROLLMENT_CLIENT.md', 'LICENSE-APACHE', 'LICENSE-MIT', 'requirements.txt', 'build-requirements.txt')]
    paths += [ROOT / 'artifact' / name for name in ('continuity_host_exchange.py',
               'continuity_independent_python.py', 'continuity_independent_python_run.py',
               'bounded_process.py', 'evidence_io.py', 'git_provenance.py', 'python_bootstrap.py')]
    result = {}
    for path in paths:
        data = snapshot(path); name = path.relative_to(ROOT).as_posix()
        require(data.data == run_git_bytes(ROOT, ['show', commit + ':' + name]), 'exchange source differs from commit: ' + name)
        result[name] = data.sha256
    return result


def qualify(args):
    require(sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 14), 'CPython 3.14 required')
    require((os.uname().sysname, os.uname().machine) in {('Darwin', 'arm64'), ('Linux', 'x86_64')}, 'unsupported reference platform')
    commit = git_commit(ROOT)  # Preserve the ordinary, non-symlink .git directory gate.
    before = inputs(commit)
    output = fresh_output_directory(args.output, within=ROOT / 'target', label='host exchange qualification')
    output.mkdir(parents=True, mode=0o700)
    wheel = snapshot(args.wheel)
    modules = {p.name: snapshot(p).data for p in sorted((SOURCE / PACKAGE).glob('*.py'))}
    files = inspect_wheel(wheel.data, modules,
                          {name: snapshot(SOURCE / name).data for name in ('LICENSE-APACHE', 'LICENSE-MIT')},
                          snapshot(SOURCE / 'README.md').data)
    provider = args.provider_root.resolve(strict=True)
    require(provider.is_dir() and not provider.is_relative_to(ROOT), 'provider must be outside the selected checkout')
    outside = Path(tempfile.mkdtemp(prefix='qperiapt-host-exchange-')).resolve()
    require(not outside.is_relative_to(ROOT), 'installed consumer must be outside checkout')
    application = outside / 'installed'
    captured = output / (PACKAGE + '-0.0.0-py3-none-any.whl')
    captured.write_bytes(wheel.data)
    requirements = output / 'wheel-requirements.txt'
    requirements.write_text(captured.as_uri() + ' --hash=sha256:' + wheel.sha256 + '\n')
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('PYTHON', 'PIP_', 'DYLD_', 'LD_'))}
    result = {'schema_version':2, 'kind':'qperiapt.host_enrollment_exchange', 'completed':False,
              'release_claim_eligible':False, 'source_commit':commit, 'source_inputs':before,
              'wheel_sha256':wheel.sha256, 'module_count':len(modules), 'outside_root':str(outside)}

    def run(command, label):
        with contextlib.chdir(outside):
            executed = capture_output(command, timeout_seconds=900,
                                      maximum_stdout_bytes=1024**2, maximum_stderr_bytes=1024**2, environment=environment)
        (output / (label + '.stdout')).write_bytes(executed.stdout)
        (output / (label + '.stderr')).write_bytes(executed.stderr)
        (output / (label + '.json')).write_text(json.dumps({'argv':command, 'cwd':str(outside), 'exit':executed.returncode}, indent=2)+'\n')
        require(executed.returncode == 0, 'installed exchange step failed: ' + label)
        return executed

    try:
        run([sys.executable, '-I', '-m', 'pip', 'install', '--isolated', '--disable-pip-version-check',
             '--no-index', '--no-deps', '--no-compile', '--require-hashes', '--target', str(application), '-r', str(requirements)], 'install')
        installed = installed_files(application)
        verify_installation(installed, files, wheel_url=captured.as_uri(), digest=wheel.sha256)
        (output / 'INSTALLED_FILES.json').write_text(json.dumps({n:hashlib.sha256(b).hexdigest() for n,b in installed.items()}, indent=2)+'\n')
        for label, class_name in (('exchange', 'ExchangeChecks'), ('client', 'ClientChecks')):
            test = snapshot(SOURCE / ('tests/enrollment_' + label + '.py'))
            harness = outside / ('enrollment_' + label + '.py'); harness.write_bytes(test.data)
            expected = sorted(node.name for node in ast.walk(ast.parse(test.data))
                              if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
            require(expected and len(expected) == len(set(expected)), label + ' test inventory')
            execution = run([sys.executable, '-I', '-S', '-B', str(harness), '--implementation-root', str(application),
                             '--provider-root', str(provider), '--private-output', str(outside / ('private-' + label))], label)
            observed = parse_strict_json_bytes(execution.stdout, label='installed ' + label + ' results')
            require(observed['successful'] is True and observed['tests'] == len(expected)
                    and all(observed[k] == 0 for k in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')),
                    'installed ' + label + ' test results differ')
            require(observed['implementation'] == str(application / PACKAGE / ('enrollment_' + label + '.py'))
                    and observed['provider_version'] == '48.0.1', 'installed implementation or provider differs')
            for name in expected:
                require((name + ' (__main__.' + class_name + '.' + name + ') ... ok').encode() in execution.stderr,
                        'missing executed ' + label + ' test: ' + name)
            result.update({label + '_test_names':expected, label + '_execution':observed})
        verify_installation(installed_files(application), files, wheel_url=captured.as_uri(), digest=wheel.sha256)
        require(inputs(commit) == before, 'exchange qualification source changed')
        result.update(completed=True,
                      scope='Installed independent adapter/client, CLI processes and SIGKILL recovery with real OpenSSL signatures/journals and explicit test issuers; no native host/browser authorization or deployed policy-publisher admission.')
    except BaseException as error:
        result['failure'] = str(error)
        raise
    finally:
        (output / 'RESULT.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', type=Path, required=True)
    parser.add_argument('--provider-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args), indent=2))


if __name__ == '__main__':
    main()
