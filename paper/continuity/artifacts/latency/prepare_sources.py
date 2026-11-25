#!/usr/bin/env python3
"""Unpack verified pinned sources and install only measurement harnesses/manifests."""
if not __debug__:
    raise SystemExit('Refusing optimized Python: source verification requires assertions to remain enabled.')
import argparse, hashlib, json, pathlib, shutil, tarfile
ROOT=pathlib.Path(__file__).resolve().parent
MEMBERS=['q-periapt-core','q-periapt-kem','q-periapt-sig','q-periapt-backends','q-periapt-mlkem-native-sys','q-periapt-policy','q-periapt-sdk','q-periapt-host-store','q-periapt-rustls']
def prepare(work):
    work=work.resolve();source=work/'protocol-source'
    if source.exists():raise ValueError('use a fresh work directory: '+str(source))
    source.mkdir(parents=True)
    inv=json.loads((ROOT/'sources/inventory-358b.json').read_text());expected={e['path']:e for e in inv['files']}
    local={e['path']:e for e in inv.get('added_harness_files',[])}
    with tarfile.open(ROOT/'sources/upstream-358b.tar.gz') as tar:
        assert {m.name for m in tar.getmembers()}==set(expected)|set(local)
        for m in tar.getmembers():
            assert m.isfile() and not m.name.startswith('/') and '..' not in pathlib.PurePosixPath(m.name).parts
            b=tar.extractfile(m).read();e=expected.get(m.name) or local[m.name]
            assert hashlib.sha256(b).hexdigest()==e['sha256'],m.name
            if m.name in expected:assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==e['sha'],m.name
            dest=source/m.name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b)
    manifest=source/'Cargo.toml';original=manifest.read_text();(source/'Cargo.upstream.toml').write_text(original)
    start=original.index('members = [');end=original.index('\n]',start)+2
    updated=original[:start]+'members = [\n'+''.join('    "crates/'+m+'",\n' for m in MEMBERS)+'    "latency-harness",\n]'+original[end:]
    manifest.write_text(updated)
    shutil.copytree(ROOT/'harness/primitives',source/'latency-harness')
    shutil.copytree(ROOT/'harness/delivery',work/'protocol-driver')
    shutil.copyfile(ROOT/'locks/primitives-358b-Cargo.lock',source/'Cargo.lock')
    shutil.copyfile(ROOT/'locks/delivery-358b-Cargo.lock',work/'protocol-driver/Cargo.lock')
    (work/'protocol-source-inventory.json').write_text(json.dumps(inv['files'],indent=2))
    for name in ['run-microbench.py','run-delivery.py']:shutil.copyfile(ROOT/'collection'/name,work/name)
    return source
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--work-dir',type=pathlib.Path,required=True);a=p.parse_args();print(prepare(a.work_dir))
