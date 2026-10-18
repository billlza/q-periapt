#!/usr/bin/env python3
"""Apply the existing complete public lifecycle verifier to native Windows readbacks."""
import argparse
import hashlib
from pathlib import Path

import continuity_package as candidate
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes


def review(root: Path, output: Path, expected_head: str) -> dict:
    report = parse_strict_json_bytes(sdk.snapshot(root / 'RESULT.json').data, label='Windows runtime result')
    sdk.require(report['input']['source_commit'] == expected_head, 'runtime source differs')
    sdk.require(report['rustc'].splitlines()[0] == 'rustc 1.98.1 (48a229cea 2026-09-01)'
                and 'host: x86_64-pc-windows-msvc' in report['rustc'], 'native Windows compiler differs')
    observed = {}
    for profile in ('debug', 'release'):
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
    result = {'source_commit': expected_head, 'native_receipt_sha256': hashlib.sha256(sdk.snapshot(root / 'RESULT.json').data).hexdigest(),
              'profiles': observed, 'scope': 'Installed archive-shipped native Rust public lifecycle on Windows; same engine/host, original existing verifier and assertions; separate from C connection or release admission'}
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
