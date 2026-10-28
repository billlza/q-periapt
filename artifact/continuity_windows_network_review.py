#!/usr/bin/env python3
"""Apply the existing complete public lifecycle verifier to native Windows readbacks."""
import argparse
from pathlib import Path
import re

import continuity_package as candidate
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes
from continuity_windows_c_public import review_profile
from continuity_windows_root import review as review_roots
from continuity_windows_configuration import review as review_configuration


def load_profiles(profile_roots: dict[str, Path], expected_head: str) -> tuple[dict, dict]:
    sdk.require(set(profile_roots) == {'debug', 'release'}, 'both Windows profiles are required')
    expected = {}
    for profile, root in profile_roots.items():
        expected.setdefault(root.resolve(), set()).add(profile)
    reports, hashes = {}, {}
    for root, profiles in expected.items():
        snapshot = sdk.snapshot(root / 'RESULT.json')
        report = parse_strict_json_bytes(snapshot.data, label='Windows runtime result')
        sdk.require(report['schema'] == 1 and set(report['profiles']) == profiles,
                    'native profile partition differs')
        sdk.require(report['input']['source_commit'] == expected_head, 'runtime source differs')
        sdk.require(isinstance(report['input_sha256'], str)
                    and re.fullmatch(r'[0-9a-f]{64}', report['input_sha256']) is not None,
                    'native producer input digest is malformed')
        sdk.require(report['rustc'].splitlines()[0] == 'rustc 1.98.1 (48a229cea 2026-09-01)'
                    and 'host: x86_64-pc-windows-msvc' in report['rustc'], 'native Windows compiler differs')
        for profile in profiles:
            reports[profile], hashes[profile] = report, snapshot.sha256
    sdk.require(reports['debug']['input_sha256'] == reports['release']['input_sha256']
                and reports['debug']['input'] == reports['release']['input'],
                'native profiles used different producer inputs')
    return reports, hashes


def review(root: Path, output: Path, expected_head: str) -> dict:
    return review_profiles({'debug': root, 'release': root}, output, expected_head)


def review_split(debug: Path, release: Path, output: Path, expected_head: str) -> dict:
    sdk.require(debug.resolve() != release.resolve(), 'split profiles must have distinct input roots')
    return review_profiles({'debug': debug, 'release': release}, output, expected_head)


def review_profiles(profile_roots: dict[str, Path], output: Path, expected_head: str) -> dict:
    reports, receipt_hashes = load_profiles(profile_roots, expected_head)
    split = len({root.resolve() for root in profile_roots.values()}) == 2
    observed, c_owners, roots, configuration = {}, {}, {}, {}
    for profile in ('debug', 'release'):
        root, report = profile_roots[profile], reports[profile]
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
        roots[profile] = review_roots(root, profile, report['profiles'][profile]['roots']['public'])
        configuration[profile] = review_configuration(root, profile, report['profiles'][profile]['configuration'])
        row = report['profiles'][profile]
        identities = row['configuration']['binaries']
        sdk.require(identities['first-configuration.exe'] == row['client_sha256']
                    and identities['owner-client.exe'] == row['owner_client_sha256']
                    and identities['q_periapt_continuity_c_consumer.dll'] ==
                    row['files']['q_periapt_continuity_c_consumer.dll'],
                    'first-registration binary identities differ from the installed profile')
    result = {'source_commit': expected_head,
              'profiles': observed, 'c_owners': c_owners, 'roots': roots, 'configuration': configuration,
              'scope': 'Installed archive-shipped Rust lifecycle, seven C owner public contracts, four root replacement routes and six first-registration carrier/trust cases on Windows; same engine/host, original readbacks with explicit TerminateProcess cuts; not independent protocol implementation or release admission'}
    if split:
        result['native_receipts_sha256'] = receipt_hashes
        result['producer_input_sha256'] = reports['debug']['input_sha256']
        result['scope'] += '; Debug and Release use separate native jobs with identical producer input'
    else:
        result['native_receipt_sha256'] = receipt_hashes['debug']
    sdk.write_json(output, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--input', type=Path)
    inputs.add_argument('--profile-inputs', type=Path, nargs=2, metavar=('DEBUG', 'RELEASE'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--head', required=True)
    args = parser.parse_args()
    if args.input is not None:
        review(args.input, args.output, args.head)
    else:
        review_split(args.profile_inputs[0], args.profile_inputs[1], args.output, args.head)
    print('WINDOWS_INSTALLED_PUBLIC_LIFECYCLE_READBACK_PASS profiles=2')
