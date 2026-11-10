from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import zipfile

from evidence_io import parse_strict_json_bytes

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
archive_path, manifest_path, work = map(Path, sys.argv[1:])
assert all(path.is_absolute() for path in (archive_path, manifest_path, work))
manifest = parse_strict_json_bytes(manifest_path.read_bytes(), label='capsule inventory')
capture = parse_strict_json_bytes((archive_path.parent / 'CAPTURE.json').read_bytes(), label='capsule identity')
digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
assert digest == capture['sha256']
work.mkdir()
source = work / 'captured-source'
source.mkdir()
controllers = {
    'controller/readback-throughput.py',
    'controller/readback-operation-repeat.py',
    'controller/readback-fanout.py',
    'controller/analyze-throughput.py',
    'controller/validate-throughput-capsule.py',
}
with zipfile.ZipFile(archive_path) as archive:
    assert len(archive.namelist()) == len(manifest) and set(archive.namelist()) == set(manifest)
    for name, expected in manifest.items():
        data = archive.read(name)
        assert len(data) == expected['bytes'] and hashlib.sha256(data).hexdigest() == expected['sha256']
        if name.startswith('reader-source/'):
            relative = Path(name.removeprefix('reader-source/'))
        elif name in controllers:
            relative = Path(name)
        else:
            continue
        assert not relative.is_absolute() and '..' not in relative.parts
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
reader_files = {path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(source.rglob('*')) if path.is_file()}
assert len(reader_files) == 9 and controllers <= reader_files.keys()
env = {key: value for key, value in os.environ.items() if not key.startswith('PYTHON')}
assert Path(env['QPERIAPT_PYTHON']).is_absolute()
argv = ['sh', str(source / 'artifact/python-run.sh'),
        str(source / 'controller/validate-throughput-capsule.py'),
        str(archive_path), str(manifest_path), str(work / 'ARCHIVE_READBACK.json')]
run = subprocess.run(argv, cwd=source, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900)
(work / 'stdout').write_bytes(run.stdout)
(work / 'stderr').write_bytes(run.stderr)
(work / 'COMMAND.json').write_text(json.dumps({'argv': argv, 'cwd': str(source), 'returncode': run.returncode}, indent=2) + '\n')
assert run.returncode == 0 and run.stderr == b''
actual = parse_strict_json_bytes((work / 'ARCHIVE_READBACK.json').read_bytes(), label='archive readback')
assert actual['archive_sha256'] == digest and actual['members_verified'] == len(manifest)
assert len(actual['cohorts']) == 20 and actual['business_files_verified'] == 750
assert actual['negative_controls_reexecuted'] == 500 and actual['phase_groups_reproduced'] == 12
record = {
    'completed': True, 'archive_sha256': digest, 'members_verified': len(manifest),
    'pilot_cohorts_replayed': 4, 'repeated_cohorts_replayed': 16,
    'business_files_verified': 750, 'operation_spans_verified': 1950,
    'phase_intervals_verified': 60, 'negative_controls_reexecuted': 500,
    'phase_groups_reproduced_from_captured_analysis_source': 12,
    'exact_rate_cross_products_checked': actual['exact_rate_cross_products_checked'],
    'captured_reader_source_only': True, 'private_runtime_accessed': False,
    'native_workload_rerun': False, 'reader_files': reader_files,
    'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'archive_readback_sha256': hashlib.sha256((work / 'ARCHIVE_READBACK.json').read_bytes()).hexdigest(),
    'performance_qualified': False, 'release_claim_eligible': False,
}
with (work / 'STANDALONE_REPLAY.json').open('x') as stream:
    stream.write(json.dumps(record, indent=2, sort_keys=True) + '\n')
print(json.dumps(record))
