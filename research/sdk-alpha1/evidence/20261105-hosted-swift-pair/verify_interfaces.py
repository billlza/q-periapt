"""Compare the retained package interfaces directly with the pinned source capsule."""
from pathlib import Path
import hashlib
import io
import json
import sys
import zipfile

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
root = Path(__file__).resolve().parent
capture = json.loads((root / 'CAPTURE.json').read_text())
sources = {}
with zipfile.ZipFile(root / 'INPUTS.zip') as archive:
    prefix = 'source/bindings/swift/ContinuityPackageConsumer/'
    for name in archive.namelist():
        if name.startswith(prefix):
            sources[name.removeprefix(prefix)] = archive.read(name)
    header = archive.read('source/bindings/c/ContinuityPackageConsumer/qpc_owner.h')
results = {}
for profile in ('DEBUG', 'RELEASE'):
    raw = (root / (profile + '.zip')).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == capture['captures'][profile]['sha256']
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        report = json.loads(archive.read('artifact/SWIFT_CONSUMER.json'))
        selected = report['profiles'][profile.lower()]
        for label, name in [('ordinary', selected['archive']), ('minimum', report['minimum_root']['package'])]:
            data = archive.read('artifact/' + name)
            with zipfile.ZipFile(io.BytesIO(data)) as package:
                assert package.read('native/include/qpc_owner.h') == header
                for relative, expected in sources.items():
                    assert package.read(relative) == expected, (profile, label, relative)
            results[profile.lower() + '/' + label] = {'archive_sha256': hashlib.sha256(data).hexdigest(),
                'source_files_compared': len(sources), 'header_sha256': hashlib.sha256(header).hexdigest()}
record = {'source_commit': capture['source_commit'], 'packages': results,
    'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'scope': 'All four retained Swift packages have the exact pinned interface/header/source bytes; no workload execution or public-ABI admission claim.'}
with (root / 'INTERFACE_READBACK.json').open('x') as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps(record))
