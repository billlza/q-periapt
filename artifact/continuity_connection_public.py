"""Copy only explicitly selected public connection readbacks; no private store export."""
from pathlib import Path, PurePosixPath
import hashlib
import re

from evidence_io import parse_strict_json_bytes, read_regular_snapshot
from installed_rust_graph import require


def read(path: Path, maximum=8 * 1024**2) -> bytes:
    return read_regular_snapshot(path, maximum=maximum, label='public connection readback').data


def report(path: Path) -> dict:
    value = parse_strict_json_bytes(read(path, 65536), label='connection result')
    require(isinstance(value, dict), 'connection result must be an object')
    return value


def message(value: dict, field: str) -> str:
    text = value.get(field)
    require(isinstance(text, str) and re.fullmatch(r'[0-9a-f]{64}', text) is not None,
            'application filename must use its exact message identity')
    return text


def exact_tree(root: Path, names: set[str]) -> None:
    files, directories = set(), set()
    for path in root.rglob('*'):
        require(not path.is_symlink() and not path.is_junction(), 'public tree contains a link')
        relative = path.relative_to(root).as_posix()
        (directories if path.is_dir() else files).add(relative)
    expected_dirs = {parent.as_posix() for name in names for parent in PurePosixPath(name).parents
                     if parent.as_posix() != '.'}
    require(files == names and directories == expected_dirs, 'public readback inventory differs')


def copy_selected(root: Path, target: Path, names: set[str]) -> dict:
    require(not target.exists(), 'public export must be fresh')
    require(0 < len(names) <= 1024, 'public file count exceeds its bound')
    selected, total = {}, 0
    for name in sorted(names):
        path = PurePosixPath(name)
        require(path.parts and not path.is_absolute() and '..' not in path.parts and '\\' not in name
                and ':' not in name and str(path) == name, 'public filename is not canonical')
        data = read(root / name)
        total += len(data)
        require(total <= 32 * 1024**2, 'public export exceeds its byte bound')
        selected[name] = data
    target.mkdir(parents=True)
    hashes = {}
    for name, data in selected.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
        hashes[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    return hashes


def capture(root: Path, target: Path, inventory: dict) -> dict:
    require(not target.exists(), 'network export must be fresh')
    require(set(inventory) == {'enrollment', 'reopen', 'replacement', 'retirement', 'roster'},
            'public inventory sections differ')
    selected = {}
    current = report(root / 'public-result.json')
    base = {'public-result.json', 'responder/closure-id', 'responder/cleanup-complete', 'responder/cleanup-verified'}
    enrollment = set(inventory['enrollment'])
    exact_tree(root / 'enrollment-public', enrollment)
    base.update('enrollment-public/' + name for name in enrollment)
    for role, field in [('initiator', 'reverse_message'), ('responder', 'forward_message')]:
        name = 'application-' + message(current, field)
        require({p.name for p in (root / role).glob('application-*')} == {name}, 'unexpected application effect')
        base.add(role + '/' + name)
    selected['connection'] = copy_selected(root, target / 'connection', base)

    reopened = root.with_name(root.name + '-session-reopen')
    restored = report(reopened / 'public-reopen-result.json')
    names = set(inventory['reopen']) | {'public-reopen-result.json', 'original-outbox', 'restored-outbox',
        'initiator/reopen-test-time', 'responder/reopen-test-time'}
    name = 'application-' + message(restored, 'message')
    require({p.name for p in (reopened / 'responder').glob('application-*')} == {name}, 'duplicated restored effect')
    names.add('responder/' + name)
    selected['reopen'] = copy_selected(reopened, target / 'reopen', names)

    for section, suffix in [('roster', 'roster-renewal'), ('replacement', 'device-replacement'),
                            ('retirement', 'device-retirement')]:
        source = root.with_name(root.name + '-' + suffix) / 'public'
        names = set(inventory[section])
        if section == 'roster':
            count = report(source / 'public-roster-result.json').get('trace_count')
            require(type(count) is int and 0 < count <= 256, 'witness trace count differs')
            for index in range(count):
                prefix = f'trace-{index:03}'
                outcomes = {suffix for suffix in ('reply', 'rejection') if (source / (prefix + '.' + suffix)).exists()}
                require(len(outcomes) == 1, 'witness trace needs one explicit outcome')
                names.update({prefix + '.request', prefix + '.time', prefix + '.' + next(iter(outcomes))})
        exact_tree(source, names)
        selected[section] = copy_selected(source, target / section, names)
    return selected
