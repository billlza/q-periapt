from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
import hashlib
import json
import os
import stat
import subprocess
import sys
import zipfile

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
source=Path.cwd();control=source.parent;repo=source.parents[2]
evidence=repo/'research/sdk-alpha1/evidence/20261106-current-rust-contract'
capture=json.loads((evidence/'CAPTURE.json').read_text())
manifest=json.loads((evidence/'FILES.json').read_text())
archive=evidence/'CAPTURE.zip'
assert hashlib.sha256(archive.read_bytes()).hexdigest()==capture['archive_sha256']
destination=control/'standalone-01'
assert not destination.exists()
destination.mkdir()
with zipfile.ZipFile(archive) as z:
    entries=z.infolist()
    assert len(entries)==len(set(z.namelist()))==len(manifest)==capture['members']<5000
    assert set(z.namelist())==set(manifest)
    assert sum(e.file_size for e in entries)<256*1024**2
    for entry in entries:
        name=PurePosixPath(entry.filename)
        assert not name.is_absolute() and '..' not in name.parts and str(name)==entry.filename
        assert stat.S_ISREG(entry.external_attr>>16) and not entry.flag_bits&1
        data=z.read(entry)
        assert len(data)==manifest[str(name)]['bytes'] and hashlib.sha256(data).hexdigest()==manifest[str(name)]['sha256']
        path=destination.joinpath(*name.parts)
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(data)
argv=['sh','artifact/python-run.sh','target/replay.py']
env=dict(os.environ,QPERIAPT_PYTHON='/Users/bhmq03@durham.ac.uk/.local/bin/python3')
with (control/'standalone.stdout').open('xb') as stdout,(control/'standalone.stderr').open('xb') as stderr:
    process=subprocess.run(argv,cwd=destination/'source',env=env,stdout=stdout,stderr=stderr,timeout=60)
record={'utc':datetime.now(timezone.utc).isoformat(),'argv':argv,'cwd':str(destination/'source'),
    'returncode':process.returncode,'archive_sha256':capture['archive_sha256'],'members_verified':len(manifest)}
(control/'STANDALONE_COMMAND.json').write_text(json.dumps(record,indent=2)+'\n')
assert process.returncode==0
result=json.loads((destination/'PUBLIC_REPLAY.json').read_text())
assert result['completed'] and result['public_files_verified']==558
for name,original in [('PUBLIC_REPLAY.json',destination/'PUBLIC_REPLAY.json'),
    ('PUBLIC_REPLAY_COMMAND.json',control/'STANDALONE_COMMAND.json'),('public-replay.stdout',control/'standalone.stdout'),
    ('public-replay.stderr',control/'standalone.stderr'),('PUBLIC_REPLAY_DRIVER.py',Path(__file__))]:
    with (evidence/name).open('xb') as stream:stream.write(original.read_bytes())
print(json.dumps(result))
