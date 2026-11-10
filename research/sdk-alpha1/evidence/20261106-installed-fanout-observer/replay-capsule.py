from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import zipfile

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
archive_path,manifest_path,work = map(Path,sys.argv[1:])
assert all(path.is_absolute() for path in (archive_path,manifest_path,work))
manifest = json.loads(manifest_path.read_bytes())
summary = json.loads((archive_path.parent/'CAPTURE.json').read_bytes())
assert hashlib.sha256(archive_path.read_bytes()).hexdigest() == summary['sha256']
work.mkdir()
standalone = work/'captured-source'
standalone.mkdir()
with zipfile.ZipFile(archive_path) as archive:
    assert set(archive.namelist()) == set(manifest) and len(archive.namelist()) == len(manifest)
    for name,expected in manifest.items():
        data = archive.read(name)
        assert len(data) == expected['bytes'] and hashlib.sha256(data).hexdigest() == expected['sha256']
        if name.startswith('reader-source/'):
            relative = Path(name.removeprefix('reader-source/'))
        elif name == 'controller/readback-fanout.py':
            relative = Path(name)
        else:
            continue
        assert not relative.is_absolute() and '..' not in relative.parts
        target = standalone/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
env = {key:value for key,value in os.environ.items() if not key.startswith('PYTHON')}
assert Path(env['QPERIAPT_PYTHON']).is_absolute()
argv = ['sh',str(standalone/'artifact/python-run.sh'),str(standalone/'controller/readback-fanout.py'),
    '--archive',str(archive_path),str(manifest_path),str(work/'ARCHIVE_READBACK.json')]
run = subprocess.run(argv,cwd=standalone,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=900)
(work/'stdout').write_bytes(run.stdout)
(work/'stderr').write_bytes(run.stderr)
(work/'COMMAND.json').write_text(json.dumps({'argv':argv,'cwd':str(standalone),'returncode':run.returncode},indent=2)+'\n')
assert run.returncode == 0 and run.stderr == b''
result = json.loads((work/'ARCHIVE_READBACK.json').read_bytes())
assert result['archive_sha256'] == summary['sha256'] and result['members_verified'] == len(manifest)
assert result['public_business_files_verified'] == 104 and result['private_runtime_accessed'] is False
record = {'completed':True,'archive_sha256':summary['sha256'],'members_verified':len(manifest),
    'cohorts_replayed':4,'business_files_verified':104,'captured_reader_source_only':True,
    'private_runtime_accessed':False,'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'reader_files':{path.relative_to(standalone).as_posix():hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(standalone.rglob('*')) if path.is_file()},
    'archive_readback_sha256':hashlib.sha256((work/'ARCHIVE_READBACK.json').read_bytes()).hexdigest(),
    'performance_qualified':False,'release_claim_eligible':False}
(work/'STANDALONE_REPLAY.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
print(json.dumps(record))
