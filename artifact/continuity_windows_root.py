"""Installed Windows root-controller process cuts and original public readbacks."""
from pathlib import Path
import hashlib
import shutil

import continuity_c_root as contract
from continuity_c_root_alternatives import VARIANTS as ALTERNATIVES
from continuity_connection_public import copy_selected, exact_tree, read
from evidence_io import parse_strict_json_bytes
from installed_rust_graph import require

VARIANTS = ('original', *ALTERNATIVES)


def verify(stdout, directory, variant):
    return contract.verify_execution(stdout, directory, darwin=False, windows=True, variant=variant)


def qualify(run, profile, environment, installed, client_source, private_root, output, library):
    flags = ['--release'] if profile == 'release' else []
    compile_flags = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
                     *(['-O2'] if profile == 'release' else ['-O0', '-g'])]
    guard = installed / 'root-contract.exe'
    client = installed / 'root-client.exe'
    for source, executable, label, libraries in (
            ('root_contract_client.c', guard, 'root-contract', []),
            ('root_client.c', client, 'root-client', ['-lntdll', '-ladvapi32'])):
        run([*compile_flags, str(client_source / source), '-I', str(installed),
             str(installed / (library + '.dll.lib')), *libraries, '-o', str(executable)],
            profile + '-' + label + '-compile', client_source)
    observed = run([str(guard)], profile + '-root-contract', installed, timeout=30)
    require(observed.strip() == 'ROOT_C_CONTRACT guarded_short_scope=true guarded_short_alternative=true outputs_preserved=true lifecycle_qualified=false',
            'root C guarded options contract did not execute')
    identities = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in
                  (guard, client, installed / 'owner-client.exe', installed / (library + '.dll'))}
    environment.update(QPC_ROOT_CLIENT=str(client),
                       QPERIAPT_C_CLIENT=str(installed / 'owner-client.exe'),
                       QPC_ROOT_CLIENT_LANGUAGE='C')
    public = {}
    for variant in VARIANTS:
        require(not any(private_root.iterdir()), 'root workload needs a fresh owned fixture')
        evidence = private_root / (profile + '-root-' + variant)
        environment.update(QPC_ROOT_EVIDENCE=str(evidence), QPC_ROOT_VARIANT=variant)
        stdout = run(['cargo', 'test', '--locked', '--test', 'root', *flags,
                      '--', '--exact', contract.TEST, '--nocapture'], profile + '-root-' + variant)
        require(set(private_root.iterdir()) == {evidence}, 'root workload leaked private fixture state')
        checked = verify(stdout.encode(), evidence, variant)
        hashes = checked['public_readbacks'] | checked['command_logs']
        target = output / (profile + '-root-public') / variant
        files = copy_selected(evidence, target, set(hashes))
        require({name: row['sha256'] for name, row in files.items()} == hashes,
                'root public bytes changed during export')
        require(verify(stdout.encode(), target, variant) == checked, 'root public export cannot replay')
        public[variant] = {'files': files, 'verification': checked}
        # Remove only this completed and independently replayed owned fixture.
        shutil.rmtree(evidence)
        require(not any(private_root.iterdir()), 'root private fixture cleanup incomplete')
    for key in ('QPC_ROOT_CLIENT', 'QPERIAPT_C_CLIENT', 'QPC_ROOT_CLIENT_LANGUAGE',
                'QPC_ROOT_EVIDENCE', 'QPC_ROOT_VARIANT'):
        environment.pop(key)
    require(all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in identities.items()),
            'root caller, peer or installed library changed during execution')
    return {'public': public, 'binaries': {path.name: digest for path, digest in identities.items()}}


def review(root: Path, profile: str, receipt: dict) -> dict:
    require(set(receipt) == set(VARIANTS), 'root route census differs')
    checked = {}
    for variant in VARIANTS:
        prefix = profile + '-root-' + variant
        command = parse_strict_json_bytes(read(root / (prefix + '.json')), label='root workload command')
        require(command['returncode'] == 0 and command['argv'] ==
                ['cargo', 'test', '--locked', '--test', 'root',
                 *(['--release'] if profile == 'release' else []), '--', '--exact', contract.TEST, '--nocapture'],
                'root public command differs')
        row = receipt[variant]
        require(set(row) == {'files', 'verification'}, 'root public receipt fields differ')
        directory = root / (profile + '-root-public') / variant
        exact_tree(directory, set(row['files']))
        require(0 < len(row['files']) <= 1024, 'root public inventory exceeds bound')
        for name, expected in row['files'].items():
            data = read(directory / name)
            require(expected == {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)},
                    'root public bytes changed')
        result = verify(read(root / (prefix + '.stdout')), directory, variant)
        require(result == row['verification'] and result['public_readbacks'] | result['command_logs'] ==
                {name: info['sha256'] for name, info in row['files'].items()}, 'root public replay differs')
        checked[variant] = result
    return checked
