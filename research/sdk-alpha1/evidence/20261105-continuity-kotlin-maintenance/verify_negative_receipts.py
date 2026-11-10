"""Recheck command outcomes using only this evidence directory's sealed files."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import zipfile


def main():
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / 'FILES.json').read_bytes())
    readback = json.loads((root / 'READBACK.json').read_bytes())
    expected_labels = {
        'RawAccountAuthorityProbe', 'RawConfigurationKeyProbe', 'RawConfigurationProbe',
        'denied-native-access', 'directory-library', 'missing-library', 'missing-property',
        'missing-symbol', 'raw-device', 'raw-enrollment', 'raw-native-owner', 'raw-owner',
        'raw-retired', 'raw-setup', 'relative-path'}
    expected = {f'kotlin-negative-{label}-{profile}.json'
                for profile in ['debug', 'release'] for label in expected_labels}
    rows = []
    with ExitStack() as stack:
        archives = {}

        def read(name):
            row = manifest[name]
            archive_name = row['archive']
            if archive_name not in archives:
                archives[archive_name] = stack.enter_context(zipfile.ZipFile(root / archive_name))
            data = archives[archive_name].read(name)
            assert len(data) == row['bytes']
            assert hashlib.sha256(data).hexdigest() == row['sha256']
            return data

        assert read('READBACK.json') == (root / 'READBACK.json').read_bytes()
        for retained in readback['top_level_command_receipts']:
            name = retained['receipt']
            receipt = json.loads(read('output/' + name))
            assert receipt['returncode'] == retained['returncode']
            if name in expected:
                assert receipt['returncode'] == 1
                rejection = receipt['expected_rejection']
                assert isinstance(rejection, str) and rejection
                stdout = read('output/' + name.removesuffix('.json') + '.stdout')
                stderr = read('output/' + name.removesuffix('.json') + '.stderr')
                assert stdout == b'' and rejection.encode() in stderr
                rows.append({'receipt': name, 'returncode': 1, 'expected_rejection': rejection,
                             'stdout_empty': True, 'required_diagnostic_present': True,
                             'receipt_sha256': manifest['output/' + name]['sha256'],
                             'stderr_sha256': hashlib.sha256(stderr).hexdigest()})
            else:
                assert receipt['returncode'] == 0 and receipt.get('expected_rejection') is None
    assert {row['receipt'] for row in rows} == expected
    assert len(readback['top_level_command_receipts']) == 229
    return {'completed': True, 'source': 'Sealed original command receipts and streams; no command rerun',
            'total_top_level_receipts': 229, 'copied_native_build_receipts': 6,
            'new_successful_commands': 193, 'new_expected_rejections': 30,
            'unexpected_nonzero_exits': 0, 'negative_controls': rows,
            'scope': 'Receipt outcome readback; not a replacement for the complete runtime validator or platform qualification',
            'original_bounds': {'parent_seconds': 18000, 'component_seconds': 900,
                                'jvm_command_stream_bytes': 8 * 1024**2,
                                'shared_native_command_stream_ceiling_bytes': 16 * 1024**2}}


if __name__ == '__main__':
    print(json.dumps(main(), indent=2, sort_keys=True))
