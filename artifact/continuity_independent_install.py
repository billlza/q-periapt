#!/usr/bin/env python3
"""Install the exact source-bound reference wheel for separate lifecycle jobs.

This records installation provenance only. Runtime qualification has its own
results and must not be inferred from a completed installation receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

from bounded_process import capture_output
from continuity_independent_python import PACKAGE, inspect_wheel, require, verify_installation
from continuity_independent_python_run import ROOT, SOURCE, WHEEL, installed_files, snapshot, source_inputs
from evidence_io import fresh_output_directory
from git_provenance import git_commit, run_git_bytes


def inputs(commit):
    result = source_inputs(commit)
    path = Path(__file__).resolve()
    name = path.relative_to(ROOT).as_posix()
    data = snapshot(path)
    require(data.data == run_git_bytes(ROOT, ['show', commit + ':' + name]),
            'installation helper differs from selected commit')
    return result | {name: data.sha256}


def qualify(args):
    require(sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 14), 'CPython 3.14 required')
    require((os.uname().sysname, os.uname().machine) in {('Darwin', 'arm64'), ('Linux', 'x86_64')},
            'unsupported reference platform')
    commit = git_commit(ROOT)
    before = inputs(commit)
    wheel = snapshot(args.wheel)
    require(args.wheel.name == WHEEL, 'reference wheel filename differs')
    modules = {p.name: snapshot(p).data for p in sorted((SOURCE / PACKAGE).glob('*.py'))}
    files = inspect_wheel(wheel.data, modules,
                          {name: snapshot(SOURCE / name).data for name in ('LICENSE-APACHE', 'LICENSE-MIT')},
                          snapshot(SOURCE / 'README.md').data)
    output = fresh_output_directory(args.output, within=ROOT / 'target', label='reference wheel installation')
    output.mkdir(parents=True, mode=0o700)
    outside = Path(tempfile.mkdtemp(prefix='qperiapt-reference-install-')).resolve()
    require(not outside.is_relative_to(ROOT), 'installed consumer must be outside checkout')
    application = outside / 'installed'
    captured = output / WHEEL
    captured.write_bytes(wheel.data)
    requirements = output / 'wheel-requirements.txt'
    requirements.write_text(captured.as_uri() + ' --hash=sha256:' + wheel.sha256 + '\n')
    result = {'kind': 'qperiapt.reference_wheel_installation', 'completed': False,
              'runtime_qualified': False, 'release_claim_eligible': False,
              'source_commit': commit, 'source_inputs': before, 'wheel_sha256': wheel.sha256,
              'module_count': len(modules), 'installed': str(application)}
    try:
        command = [sys.executable, '-I', '-m', 'pip', 'install', '--isolated', '--disable-pip-version-check',
                   '--no-index', '--no-deps', '--no-compile', '--require-hashes', '--target', str(application),
                   '-r', str(requirements)]
        environment = {k: v for k, v in os.environ.items() if not k.startswith(('PYTHON', 'PIP_', 'DYLD_', 'LD_'))}
        executed = capture_output(command, timeout_seconds=900, maximum_stdout_bytes=1024**2,
                                  maximum_stderr_bytes=1024**2, environment=environment)
        (output / 'install.stdout').write_bytes(executed.stdout)
        (output / 'install.stderr').write_bytes(executed.stderr)
        result['installation'] = {'argv': command, 'exit': executed.returncode}
        require(executed.returncode == 0, 'reference wheel installation failed')
        installed = installed_files(application)
        verify_installation(installed, files, wheel_url=captured.as_uri(), digest=wheel.sha256)
        result['installed_sha256'] = {n: hashlib.sha256(b).hexdigest() for n, b in installed.items()}
        require(inputs(commit) == before, 'reference installation source changed')
        result['completed'] = True
        return result
    except BaseException as error:
        result['failure'] = str(error)
        raise
    finally:
        (output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args)))


if __name__ == '__main__':
    main()
