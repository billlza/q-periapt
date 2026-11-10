from pathlib import Path, PurePosixPath
import hashlib
import json
import sys
import tempfile
import zipfile

import continuity_c_witness_openssl as interop
import continuity_c_witness_tls as native_tls
import rust_sdk_profile as sdk

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
archive_path, inventory_path, output_path = map(Path, sys.argv[1:])
inventory = json.loads(inventory_path.read_bytes())
with zipfile.ZipFile(archive_path) as archive, tempfile.TemporaryDirectory(prefix='qperiapt-current-openssl-replay-') as temporary:
    names = archive.namelist()
    assert len(names) == len(set(names)) == len(inventory) and set(names) == set(inventory)
    assert sum(item.file_size for item in archive.infolist()) < 1024**3
    source_names = set()
    materialized = Path(temporary)
    for name in names:
        path = PurePosixPath(name)
        assert path.as_posix() == name and not path.is_absolute() and '..' not in path.parts and '\\' not in name
        data = archive.read(name)
        assert len(data) == inventory[name]['bytes'] and hashlib.sha256(data).hexdigest() == inventory[name]['sha256']
        if name.startswith('source/artifact/'):
            local = sdk.ROOT / name[len('source/'):]
            assert local.read_bytes() == data, 'replay module differs: ' + name
            source_names.add(str(local.resolve()))
        if name.startswith(('debug/public/', 'release/public/', 'debug/commands/', 'release/commands/')):
            target = materialized / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data)
    for module in tuple(sys.modules.values()):
        filename = getattr(module, '__file__', None)
        if filename is not None and Path(filename).is_relative_to(sdk.ROOT / 'artifact'):
            assert str(Path(filename).resolve()) in source_names, 'uncaptured imported reader module'
    result = json.loads(archive.read('READBACK.json'))
    profiles = {}
    for profile in ['debug', 'release']:
        expected = result['profiles'][profile]
        rows = {}
        for kind in ['server', 'client', 'rejections', 'native-tls']:
            directory = materialized / profile / 'public' / kind
            if kind == 'native-tls':
                stdout = materialized / profile / 'commands' / f'c-witness-tls-trace-{profile}.stdout'
                observed = native_tls.verify_execution(stdout.read_bytes(), directory)
                assert observed == expected['native_tls']
                scope = native_tls.SCOPE
            else:
                stdout = materialized / profile / 'commands' / f'c-witness-openssl-{kind}-{profile}.stdout'
                observed = interop.verify_execution(kind, stdout.read_bytes(), directory)
                assert observed == expected['scenes'][kind]
                scope = interop.SCOPE
            manifest = json.loads((directory / 'PUBLIC_FILES.json').read_bytes())
            files = observed['public_readbacks'] | observed['command_logs']
            assert manifest == {'schema_version': 1, 'completed': True, 'files': files, 'scope': scope, 'release_claim_eligible': False}
            assert {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()} == set(files) | {'PUBLIC_FILES.json'}
            rows[kind] = {'completed': observed['completed'], 'public_files': len(files),
                'witness_exchanges': observed.get('witness_exchanges'), 'client_exchanges': observed.get('exchanges'),
                'store_calls': observed.get('store_calls'), 'cases': observed.get('cases')}
        profiles[profile] = rows
    readback = {'completed': True, 'archive_sha256': hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        'verified_members': len(names), 'source_commit': result['source_commit'], 'profiles': profiles,
        'private_runtime_read': False, 'native_workload_rerun': False, 'controls_rerun': False,
        'scope': 'All captured member bytes and original source-matched public readers; eight completed component transcripts. No native, whole JNI, device or release acceptance.'}
with output_path.open('x') as stream:
    stream.write(json.dumps(readback, indent=2, sort_keys=True) + '\n')
print(json.dumps(readback))
