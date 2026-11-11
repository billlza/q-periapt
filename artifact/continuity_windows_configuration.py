"""Original six first-registration routes through the installed Windows C caller."""
from pathlib import Path
import hashlib
import re
import shutil

import continuity_first_configuration as contract
from continuity_connection_public import copy_selected, exact_tree, read
from evidence_io import parse_strict_json_bytes
from installed_rust_graph import require


def command(profile):
    return ['cargo', 'test', '--locked', '--test', 'first_configuration',
            *(['--release'] if profile == 'release' else []), 'independent_c_',
            '--', '--nocapture', '--test-threads=1']


def verify(stdout, directory):
    return contract.verify_execution(stdout, directory, language='C', catalog_total=11)


def qualify(run, profile, environment, installed, private_root, output, library):
    require(not any(private_root.iterdir()), 'first registration needs an empty owned fixture')
    identities = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in
                  (installed / 'first-configuration.exe', installed / 'owner-client.exe',
                   installed / (library + '.dll'))}
    environment.update(QPC_CONFIGURATION_CLIENT=str(installed / 'first-configuration.exe'),
                       QPC_CONFIGURATION_RECEIVER=str(installed / 'owner-client.exe'),
                       QPC_CONFIGURATION_LANGUAGE='C', QPERIAPT_CONFIGURATION_EVIDENCE=str(private_root))
    stdout = run(command(profile), profile + '-first-registration')
    checked = verify(stdout.encode(), private_root)
    target = output / (profile + '-configuration-public')
    files = copy_selected(private_root, target, set(checked['public_readbacks']))
    require({name: row['sha256'] for name, row in files.items()} == checked['public_readbacks'],
            'first-registration public bytes changed during export')
    require(verify(stdout.encode(), target) == checked, 'first-registration export cannot replay')
    require({p.name for p in private_root.iterdir()} == set(checked['scenarios']),
            'first registration leaked private fixture state')
    # Only these six complete, verified public trees belong to this invocation.
    for name in checked['scenarios']:
        shutil.rmtree(private_root / name)
    require(not any(private_root.iterdir()), 'first-registration cleanup incomplete')
    for key in ('QPC_CONFIGURATION_CLIENT', 'QPC_CONFIGURATION_RECEIVER',
                'QPC_CONFIGURATION_LANGUAGE', 'QPERIAPT_CONFIGURATION_EVIDENCE'):
        environment.pop(key)
    require(all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in identities.items()),
            'first-registration caller, receiver or installed library changed')
    return {'files': files, 'verification': checked,
            'binaries': {path.name: digest for path, digest in identities.items()}}


def review(root: Path, profile: str, receipt: dict) -> dict:
    invocation = parse_strict_json_bytes(read(root / (profile + '-first-registration.json')),
                                         label='first-registration command')
    require(invocation['returncode'] == 0 and invocation['argv'] == command(profile),
            'first-registration execution differs')
    require(set(receipt) == {'files', 'verification', 'binaries'}, 'first-registration receipt fields differ')
    require(set(receipt['binaries']) == {'first-configuration.exe', 'owner-client.exe',
                                        'q_periapt_continuity_c_consumer.dll'}
            and all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
                    for value in receipt['binaries'].values()), 'first-registration binary identities differ')
    directory = root / (profile + '-configuration-public')
    exact_tree(directory, set(receipt['files']))
    for name, expected in receipt['files'].items():
        data = read(directory / name)
        require(expected == {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)},
                'first-registration public bytes changed')
    checked = verify(read(root / (profile + '-first-registration.stdout')), directory)
    require(checked == receipt['verification'] and checked['public_readbacks'] ==
            {name: info['sha256'] for name, info in receipt['files'].items()},
            'first-registration public replay differs')
    return checked
