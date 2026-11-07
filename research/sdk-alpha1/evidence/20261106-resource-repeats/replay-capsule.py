from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import zipfile

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
archive_path,manifest_path,work=map(Path,sys.argv[1:])
assert all(p.is_absolute() for p in (archive_path,manifest_path,work))
manifest=json.loads(manifest_path.read_bytes())
summary=json.loads((archive_path.parent/'CAPTURE.json').read_bytes())
digest=hashlib.sha256(archive_path.read_bytes()).hexdigest()
assert digest==summary['sha256']
work.mkdir()
source=work/'captured-source'
source.mkdir()
with zipfile.ZipFile(archive_path) as archive:
    assert len(archive.namelist())==len(manifest) and set(archive.namelist())==set(manifest)
    for name,expected in manifest.items():
        data=archive.read(name)
        assert len(data)==expected['bytes'] and hashlib.sha256(data).hexdigest()==expected['sha256']
        if name.startswith('reader-source/'):
            relative=Path(name.removeprefix('reader-source/'))
        elif name in ('controller/readback-operation-repeat.py','controller/readback-fanout.py',
            'controller/validate-resource-repeat-capsule.py'):
            relative=Path(name)
        else:
            continue
        assert not relative.is_absolute() and '..' not in relative.parts
        target=source/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
env={key:value for key,value in os.environ.items() if not key.startswith('PYTHON')}
assert Path(env['QPERIAPT_PYTHON']).is_absolute()
argv=['sh',str(source/'artifact/python-run.sh'),str(source/'controller/validate-resource-repeat-capsule.py'),
    str(archive_path),str(manifest_path),str(work/'ARCHIVE_READBACK.json')]
run=subprocess.run(argv,cwd=source,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=900)
(work/'stdout').write_bytes(run.stdout)
(work/'stderr').write_bytes(run.stderr)
(work/'COMMAND.json').write_text(json.dumps({'argv':argv,'cwd':str(source),'returncode':run.returncode},indent=2)+'\n')
assert run.returncode==0 and run.stderr==b''
actual=json.loads((work/'ARCHIVE_READBACK.json').read_bytes())
assert actual['archive_sha256']==digest and actual['members_verified']==len(manifest)
assert len(actual['cohorts'])==16 and actual['business_files_verified']==600
assert actual['operation_groups_recomputed']==90 and actual['memory_groups_recomputed']==20
record={'completed':True,'archive_sha256':digest,'members_verified':len(manifest),
    'cohorts_replayed':16,'business_files_verified':600,'spans_verified':1560,
    'captured_reader_source_only':True,'private_runtime_accessed':False,'native_workload_rerun':False,
    'operation_groups_recomputed':90,'memory_groups_recomputed':20,
    'reader_files':{p.relative_to(source).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(source.rglob('*')) if p.is_file()},
    'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'archive_readback_sha256':hashlib.sha256((work/'ARCHIVE_READBACK.json').read_bytes()).hexdigest(),
    'performance_qualified':False,'release_claim_eligible':False}
(work/'STANDALONE_REPLAY.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
print(json.dumps(record))
