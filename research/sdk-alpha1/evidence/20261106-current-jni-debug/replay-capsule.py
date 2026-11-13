from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import zipfile

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
archive_path, manifest_path, work = map(Path, sys.argv[1:])
assert all(p.is_absolute() for p in (archive_path,manifest_path,work))
destination = archive_path.parent
manifest = json.loads(manifest_path.read_bytes())
summary = json.loads((destination/'CAPTURE.json').read_bytes())
digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
assert digest == summary['sha256'] and summary['profile'] == 'debug'
work.mkdir()
source = work/'source'
data_root = work/'data'
source.mkdir()
data_root.mkdir()
raw_members = source_members = 0
with zipfile.ZipFile(archive_path) as archive:
    assert len(archive.namelist()) == len(manifest) and set(archive.namelist()) == set(manifest)
    for name,expected in manifest.items():
        data = archive.read(name)
        assert len(data) == expected['bytes'] and hashlib.sha256(data).hexdigest() == expected['sha256']
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        if name.startswith('raw/'):
            target = data_root/relative
            raw_members += 1
        elif name.startswith('source/'):
            target = source/relative.relative_to('source')
            source_members += 1
        else:
            continue
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
    (work/'READER_SOURCE.json').write_bytes(archive.read('readback/READER_SOURCE.json'))
    original_mapper = archive.read('controller/replay-current-jni.py')
    old = b"RAW = SOURCE.parent / ('target/continuity-installed-jni-' + PROFILE + '-current')"
    assert original_mapper.count(old) == 1
    mapper = original_mapper.replace(old,b"RAW = ROOT / 'raw'")
    script = source/'target/current-rust-readback/archive_replay.py'
    script.parent.mkdir(parents=True)
    script.write_bytes(mapper)
    expected_outcomes = json.loads(archive.read('readback/replay-01/REPLAYED.json'))
    expected_readback = json.loads(archive.read('readback/replay-01/RESULT.json'))
env = {key:value for key,value in os.environ.items() if not key.startswith('PYTHON')}
assert Path(env['QPERIAPT_PYTHON']).is_absolute()
argv = ['sh',str(source/'artifact/python-run.sh'),str(script),'replay-01','debug',str(data_root)]
run = subprocess.run(argv,cwd=source,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=900)
(work/'stdout').write_bytes(run.stdout)
(work/'stderr').write_bytes(run.stderr)
(work/'COMMAND.json').write_text(json.dumps({'argv':argv,'cwd':str(source),'returncode':run.returncode},indent=2)+'\n')
assert run.returncode == 0 and run.stderr == b''
readback = json.loads((data_root/'replay-01/RESULT.json').read_bytes())
outcomes = json.loads((data_root/'replay-01/REPLAYED.json').read_bytes())
assert outcomes == expected_outcomes
assert readback == expected_readback
assert len(readback['public_outcome_fields_replayed']) == 20
assert len(readback['loaded_reader_sources']) == 69 and readback['reconstructed_original_files'] == 4376
record = {'archive_sha256':digest,'verified_members':len(manifest),'materialized_raw_members':raw_members,
    'materialized_source_members':source_members,'captured_source_only':True,
    'original_mapper_sha256':hashlib.sha256(original_mapper).hexdigest(),
    'archive_mapper_sha256':hashlib.sha256(mapper).hexdigest(),
    'mapper_change':'Only select raw public records from the extracted capsule instead of the live execution directory.',
    'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'replayed_outcome_fields':20,'reconstructed_files':4376,'loaded_source_modules':69,
    'matches_original_public_readback':True,'private_runtime_materialized':False,
    'private_runtime_read':False,'native_workload_rerun':False,'release_claim_eligible':False}
(work/'ARCHIVE_CHECKS.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
for name,content in {
    'ARCHIVE_REPLAY.json':(data_root/'replay-01/RESULT.json').read_bytes(),
    'STANDALONE_REPLAY.json':json.dumps(record,indent=2,sort_keys=True).encode()+b'\n',
    'ARCHIVE_CHECKS.json':(work/'ARCHIVE_CHECKS.json').read_bytes(),
    'REPLAY_COMMAND.json':(work/'COMMAND.json').read_bytes(),
    'archive_replay.py':mapper,
    'replay-capsule.py':Path(__file__).read_bytes(),
    'replay.stdout':run.stdout,
    'replay.stderr':run.stderr,
}.items():
    with (destination/name).open('xb') as stream:
        stream.write(content)
print(json.dumps(record))
