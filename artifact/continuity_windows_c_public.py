"""Export and replay the existing seven C owner contracts without private stores."""
from functools import partial
from pathlib import Path

import continuity_c_account as account
import continuity_c_consumer as consumer
import continuity_c_device as device
import continuity_c_recovery as recovery
from continuity_connection_public import copy_selected, exact_tree, read
from evidence_io import parse_strict_json_bytes
from installed_rust_graph import require
import rust_sdk_profile as sdk

# Test name, fixture suffix, report filename and unchanged public verifier.
CASES = {
    'client': (consumer.TEST, '', 'c-public-result.json', consumer.verify_execution),
    'device': (device.TEST, '', 'c-device-parent-public-result.json', device.verify_execution),
    'configured': (device.CONFIGURED_TEST, '', 'c-device-parent-public-result.json',
                   partial(device.verify_execution, configured=True)),
    'account': (account.TEST, '-account', 'initiator/c-account-result.json', account.verify_execution),
    'server': (consumer.SERVER_TEST, '', 'c-server-public-result.json', consumer.verify_server_execution),
    'recovery': (recovery.TEST, '', 'c-recovery-public-result.json', recovery.verify_execution),
    'restore': (consumer.RESTORE_TEST, '-session-reopen', 'c-restore-public-result.json',
                consumer.verify_restore_execution),
}


def selected(kind: str, checked: dict, root: Path) -> dict:
    names = {CASES[kind][2]: sdk.snapshot(root / CASES[kind][2]).sha256}
    # The account report's application_readbacks is a numeric count. Only
    # client/server verifiers use that name for their file-hash inventory.
    field = 'application_readbacks' if kind in ('client', 'server') else 'public_readbacks'
    for records in (checked[field], checked['command_logs']):
        for name, digest in records.items():
            require(name not in names or names[name] == digest, 'conflicting C public readback')
            names[name] = digest
    return names


def capture_case(kind: str, stdout: bytes, root: Path, target: Path) -> dict:
    checked = CASES[kind][3](stdout, root)
    names = selected(kind, checked, root)
    files = copy_selected(root, target, set(names))
    require({name: row['sha256'] for name, row in files.items()} == names,
            'C public input changed during export')
    require(CASES[kind][3](stdout, target) == checked, 'exported C execution cannot replay')
    return {'files': files, 'verification': checked}


def review_case(kind: str, stdout: bytes, root: Path, receipt: dict) -> dict:
    require(set(receipt) == {'files', 'verification'}, 'C public receipt fields differ')
    files = receipt['files']
    require(type(files) is dict and 0 < len(files) <= 1024, 'C public inventory differs')
    exact_tree(root, set(files))
    for name, expected in files.items():
        item = sdk.snapshot(root / name, maximum=8 * 1024**2)
        require(expected == {'sha256': item.sha256, 'bytes': item.size}, 'C public bytes changed')
    checked = CASES[kind][3](stdout, root)
    require(selected(kind, checked, root) == {name: row['sha256'] for name, row in files.items()},
            'C public inventory contains unverified files')
    require(checked == receipt['verification'], 'C public verification differs')
    return checked


def review_profile(root: Path, profile: str, receipt: dict) -> dict:
    require(set(receipt) == set(CASES), 'C owner workload census differs')
    checked = {}
    for kind, (test, _, _, _) in CASES.items():
        prefix = profile + '-owner-' + kind
        command = parse_strict_json_bytes(read(root / (prefix + '.json')), label='C owner command')
        require(command['returncode'] == 0 and command['argv'] ==
                ['cargo', 'test', '--locked', '--test', 'c_owner',
                 *(['--release'] if profile == 'release' else []), '--', '--exact', test, '--nocapture'],
                'C owner public workload command differs')
        checked[kind] = review_case(kind, read(root / (prefix + '.stdout')),
                                   root / (profile + '-owner-public') / kind, receipt[kind])
    return checked
