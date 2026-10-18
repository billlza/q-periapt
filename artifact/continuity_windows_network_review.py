#!/usr/bin/env python3
"""Apply the existing complete public lifecycle verifier to native Windows readbacks."""
import argparse
import hashlib
from pathlib import Path

import continuity_package as candidate
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes
from continuity_windows_c_public import review_profile


def review(root: Path, output: Path, expected_head: str) -> dict:
    report = parse_strict_json_bytes(sdk.snapshot(root / 'RESULT.json').data, label='Windows runtime result')
    sdk.require(report['input']['source_commit'] == expected_head, 'runtime source differs')
    sdk.require(report['rustc'].splitlines()[0] == 'rustc 1.98.1 (48a229cea 2026-09-01)'
                and 'host: x86_64-pc-windows-msvc' in report['rustc'], 'native Windows compiler differs')
    observed, c_owners = {}, {}
    for profile in ('debug', 'release'):
        path_command = parse_strict_json_bytes(sdk.snapshot(root / (profile + '-configuration-paths.json')).data,
                                               label='native path admission command')
        sdk.require(path_command['returncode'] == 0 and path_command['argv'] ==
                    ['cargo', 'test', '--locked', '--test', 'configuration_paths',
                     *(['--release'] if profile == 'release' else []), '--', '--nocapture'],
                    'native path admission execution differs')
        path_stdout = sdk.snapshot(root / (profile + '-configuration-paths.stdout')).data
        sdk.require(b'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' in path_stdout,
                    'native path admission controls did not execute')
        folder = root / (profile + '-network-public')
        hashes = report['profiles'][profile]['network_public']
        sdk.require(set(hashes) == {'connection', 'reopen', 'roster', 'replacement', 'retirement'},
                    'public readback sections differ')
        actual = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
        expected = {section + '/' + name for section, rows in hashes.items() for name in rows}
        sdk.require(actual == expected, 'exported public file set differs')
        for section, rows in hashes.items():
            for name, expected_row in rows.items():
                item = sdk.snapshot(folder / section / name, maximum=8 * 1024**2)
                sdk.require(item.sha256 == expected_row['sha256'] and item.size == expected_row['bytes'],
                            'exported readback hash or length changed')
        stdout = sdk.snapshot(root / (profile + '-owned-runtime.stdout')).data
        command = parse_strict_json_bytes(sdk.snapshot(root / (profile + '-owned-runtime.json')).data,
                                          label='native lifecycle command')
        expected_command = ['cargo', 'test', '--locked', '--test', 'owned_connection',
                            *(['--release'] if profile == 'release' else []), '--', '--nocapture']
        sdk.require(command['returncode'] == 0 and command['argv'] == expected_command,
                    'native lifecycle execution or selected workload differs')
        observed[profile] = candidate.verify_execution(stdout, folder / 'connection', folder / 'reopen',
            folder / 'roster', folder / 'replacement', folder / 'retirement')
        c_owners[profile] = review_profile(root, profile, report['profiles'][profile]['owner_public'])
    result = {'source_commit': expected_head, 'native_receipt_sha256': hashlib.sha256(sdk.snapshot(root / 'RESULT.json').data).hexdigest(),
              'profiles': observed, 'c_owners': c_owners,
              'scope': 'Installed archive-shipped Rust lifecycle and seven C owner public contracts on Windows; same engine/host, original existing verifiers and assertions; not independent protocol implementation or release admission'}
    sdk.write_json(output, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--head', required=True)
    args = parser.parse_args()
    review(args.input, args.output, args.head)
    print('WINDOWS_INSTALLED_PUBLIC_LIFECYCLE_READBACK_PASS profiles=2')
