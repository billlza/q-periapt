"""Verify the downloaded qualification evidence without running its consumers."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

ROOT = Path(__file__).resolve().parent
SOURCE = '96e9a63cf8359b130003cd851008a7ce3649aea7'
TREE = 'd30b89eb9c661bf514618f511f5979ec0b062e9c'
WORKFLOW = '6fa6291f7e2c68a98bcf739b2eea72a59bd165bc'
DEPENDENCIES = ('valgrind', 'qemu-user', 'gcc-riscv64-linux-gnu', 'graphviz',
                'unzip', 'libgtk2.0-dev', 'ocaml', 'pkg-config')

def require(value, message):
    if not value:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

api = json.loads((ROOT / 'ARTIFACTS.json').read_text())
require(api['total_count'] == 1 and len(api['artifacts']) == 1, 'artifact census')
artifact = api['artifacts'][0]
archive_bytes = (ROOT / 'artifact.zip').read_bytes()
require(len(archive_bytes) == artifact['size_in_bytes'], 'archive size')
require('sha256:' + digest(archive_bytes) == artifact['digest'], 'archive digest')
require(artifact['workflow_run']['head_sha'] == WORKFLOW, 'artifact workflow binding')
expected = {'apt-install.log', 'apt-time.txt', 'formal-dependency-consumers.log',
            'installed-after.tsv', 'installed-before.tsv', 'native-cross-consumers.log',
            'openssl-consumer.log', 'package-transition.json', 'runner-architecture.txt', 'source.txt'}
with zipfile.ZipFile(ROOT / 'artifact.zip') as archive:
    require(len(archive.namelist()) == len(expected) and set(archive.namelist()) == expected, 'member census')
    require(archive.testzip() is None, 'archive CRC')
    payload = {name: archive.read(name) for name in expected}
    census = [{'path': name, 'bytes': len(payload[name]), 'sha256': digest(payload[name]),
               'crc32': archive.getinfo(name).CRC} for name in sorted(expected)]
    for name, data in payload.items():
        require((ROOT / 'artifact' / name).read_bytes() == data, 'retained member: ' + name)

def installed(name):
    lines = payload[name].decode().splitlines()
    pairs = [line.split('\t') for line in lines]
    require(all(len(pair) == 2 and all(pair) for pair in pairs), 'TSV fields')
    result = dict(pairs)
    require(len(result) == len(lines), 'duplicate package identity')
    return result

before, after = installed('installed-before.tsv'), installed('installed-after.tsv')
require(set(before) <= set(after), 'installed package removed')
require(all(after[name] == version for name, version in before.items()), 'preexisting version changed')
new = {name: version for name, version in after.items() if name not in before}
transition = {'before_count': len(before), 'after_count': len(after), 'downgrades': 0,
              'removals': 0, 'upgrades': {}, 'new_packages': new}
require(json.loads(payload['package-transition.json']) == transition, 'transition receipt differs from actual TSV')
require(payload['source.txt'].decode().splitlines() == [SOURCE, TREE], 'source receipt')
architecture = payload['runner-architecture.txt'].decode()
require('\namd64\n' in architecture, 'native architecture')
require('APT::Architecture "amd64";' in architecture, 'APT native architecture')
require('APT::Architecture-Variants "amd64v3";' in architecture, 'configured variant')
require('ImageVersion=20261101.186.1' in architecture, 'runner image')
apt = payload['apt-install.log'].decode()
indexes = [line for line in apt.splitlines() if re.match(r'Get:\d+ .* Packages ', line)]
index_counts = {arch: sum(f' {arch} Packages ' in line for line in indexes) for arch in ('amd64', 'amd64v3')}
require(index_counts['amd64v3'] > 0 and sum(index_counts.values()) == len(indexes), 'index architecture evidence')
require(not any(marker in apt for marker in ('The following packages will be DOWNGRADED:',
    'E: Packages were downgraded', '--allow-downgrades', 'NO_PUBKEY', 'Temporary failure resolving')), 'installation error or downgrade override')
require(f'0 upgraded, {len(new)} newly installed, 0 to remove' in apt, 'install summary')
dependencies = {}
for package in DEPENDENCIES:
    matches = {name: version for name, version in after.items() if name.split(':')[0] == package}
    require(len(matches) == 1, 'dependency identity: ' + package)
    name, version = next(iter(matches.items()))
    dependencies[package] = {'binary_package': name, 'version': version, 'newly_installed': name in new}

native = payload['native-cross-consumers.log'].decode()
formal = payload['formal-dependency-consumers.log'].decode()
openssl = payload['openssl-consumer.log'].decode()
for marker in ('ERROR SUMMARY: 0 errors from 0 contexts', 'RISCV_CONSUMER_OK'):
    require(marker in native, 'native/cross consumer: ' + marker)
for marker in ('No errors detected in compressed data', 'OCAML_CONSUMER_OK', 'FORMAL_DEPENDENCY_CONSUMERS_OK'):
    require(marker in formal, 'formal dependency consumer: ' + marker)
for marker in ('witness_tls_peer.c.o', 'OPENSSL_HEADER OpenSSL 3.5.5',
               'OPENSSL_RUNTIME OpenSSL 3.5.5', '100% tests passed out of 1'):
    require(marker in openssl, 'existing OpenSSL consumer: ' + marker)

snapshot = json.loads((ROOT / 'API_SNAPSHOT.json').read_text())
require(snapshot['run']['conclusion'] == 'success' and snapshot['run']['head_sha'] == WORKFLOW, 'terminal workflow result')
jobs = snapshot['jobs']['jobs']
require(len(jobs) == 1 and jobs[0]['id'] == 130667389723 and jobs[0]['conclusion'] == 'success', 'terminal job result')
require(all(step['status'] == 'completed' and step['conclusion'] == 'success' for step in jobs[0]['steps']), 'job step completion')
require(any(step['name'] == 'Verify clean source' for step in jobs[0]['steps']), 'clean-source check')
binding = json.loads((ROOT / 'SOURCE_BINDING.json').read_text())
require(binding['production_candidate']['sha'] == SOURCE and binding['production_candidate']['tree']['sha'] == TREE, 'production source tree')
require(binding['diagnostic_workflow_commit']['sha'] == WORKFLOW, 'workflow source')
require(binding['diagnostic_workflow_commit']['parents'][0]['sha'] == SOURCE, 'workflow source parent')
require(('BOOTSTRAP_SOURCE: ' + SOURCE) in (ROOT / 'workflow.yml').read_text(), 'workflow checkout source')
seconds = float(payload['apt-time.txt'].decode().strip().split('=')[1])
report = {'schema': 1, 'run_id': 43062177678, 'job_id': 130667389723,
          'production_source': SOURCE, 'production_tree': TREE, 'workflow_head': WORKFLOW,
          'artifact_id': artifact['id'], 'artifact_bytes': len(archive_bytes), 'artifact_sha256': digest(archive_bytes),
          'artifact_member_count': len(expected), 'wall_seconds': seconds,
          'before_package_count': len(before), 'after_package_count': len(after), 'new_package_count': len(new),
          'unchanged_existing_count': len(before), 'downgrades': 0, 'removals': 0, 'upgrades': 0,
          'runtime_apt_version': before['apt'], 'runtime_dpkg_version': before['dpkg'],
          'native_architecture': 'amd64', 'apt_architecture_variants': 'amd64v3',
          'package_index_counts': index_counts, 'dependencies': dependencies,
          'consumer_logs_verified': ['native-cross-consumers.log', 'formal-dependency-consumers.log', 'openssl-consumer.log'],
          'all_job_steps_success': True, 'clean_source_check_success': True,
          'configuration_capture_scope': 'All APT::Architecture-prefixed entries emitted by apt-config dump; not the entire unrelated APT configuration.',
          'verification_scope': 'Existing artifact bytes, TSV/JSON receipts, original consumer logs and GitHub metadata only; no APT operation, compilation, consumer execution, test suite or CI run.'}
(ROOT / 'ZIP_MEMBERS.json').write_text(json.dumps(census, indent=2) + '\n')
(ROOT / 'READBACK_VERIFICATION.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
