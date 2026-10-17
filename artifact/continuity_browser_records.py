"""Admission of real browser enrollment records; no simulated browser storage."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from evidence_io import parse_strict_json_bytes
from rust_sdk_profile import require

CASES = frozenset({'missing-root', 'root-before-commit', 'root-published',
    'directory-created', 'staged-flush', 'enrollment-published', 'ready-before-commit',
    'ready-published', 'delete-enrollment', 'delete-wrap', 'damage-catalogue', 'request-committed'})


def digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def creation(value: dict) -> None:
    require(value.get('completed') is True and isinstance(value.get('browser'), str), 'creation did not complete')
    rows = value.get('cases', [])
    require(len(rows) == len(CASES) and {row.get('case') for row in rows} == CASES, 'creation case set differs')
    for row in rows:
        name = row['case']
        if name == 'missing-root':
            require('Absent' in row.get('error', ''), 'missing root became first use')
        elif name.startswith('delete-') or name == 'damage-catalogue':
            code = 'Authentication' if name == 'damage-catalogue' else 'Corrupt'
            require(code in row.get('error', '') and code in row.get('again', '')
                    and row.get('unchanged') is True, 'damaged published state was repaired')
        else:
            cut = row.get('cut', {})
            expected = 'request-committed' if name == 'request-committed' else name
            observations = cut.get('lease_observations', [])
            require(cut.get('cut') == expected and observations and observations[-1].get('count') == 0,
                    'real Worker cut or release receipt missing')
            if name == 'root-before-commit':
                require('Absent' in row.get('error', ''), 'unpublished root was inferred')
            elif name == 'request-committed':
                require(digest(cut.get('requestDigest')) and cut['requestDigest'] == row['request']['sha256'],
                        'committed original request changed')
            else:
                before, after = row['before'], row['after']
                require(before.get('vault_extractable') is False and digest(before.get('wrap_sha256'))
                        and before['wrap_sha256'] == after.get('wrap_sha256')
                        and len(after.get('files', [])) == 3 and digest(after.get('database_id'))
                        and after.get('opfs_files') == ['db-' + after['database_id']], 'original storage changed')
                if before.get('database_id') is not None:
                    require(before['database_id'] == after['database_id'], 'published database was replaced')
                require('Conflict' in row.get('wrong', '') and digest(row['resumed'].get('sha256'))
                        and row['resumed']['sha256'] == row['reopened']['sha256'] == row['repeated']['sha256'],
                        'wrong intent or original request recovery differs')
    captures = value.get('captures', [])
    require(len(captures) == 19 and len({row['name'] for row in captures}) == 19, 'request capture set differs')
    require(all(re.fullmatch(r'[A-Za-z0-9.-]+\.bin', row['name']) and digest(row.get('sha256')) for row in captures),
            'request capture identity invalid')
    request_digests = {row['sha256'] for row in captures}
    require(len(request_digests) == 7, 'original request identities differ')
    for row in rows:
        if 'resumed' in row:
            require(row['resumed']['sha256'] in request_digests, 'recovery omitted its captured request')
        if row['case'] == 'request-committed':
            require(row['request']['sha256'] in request_digests, 'post-commit recovery capture absent')


def late(value: dict) -> None:
    require(value.get('completed') is True and isinstance(value.get('browser'), str), 'late completion failed')
    rows = value.get('cases', [])
    require([row.get('mode') for row in rows] == ['decrypt', 'handle', 'open', 'transaction', 'foreign-directory'],
            'late completion case set differs')
    for row in rows[:4]:
        code = 'CommitUnknown' if row['mode'] == 'handle' else 'OpenUnknown'
        observations = row.get('release_observations', [])
        require(row.get('code') == code and row.get('elapsed_ms', 0) >= 19000
                and 'ClosePending' in row.get('causes', []) and 'Busy' in row.get('concurrent', '')
                and observations and observations[-1] == 0 and digest(row.get('request_sha256')),
                'late completion released a lease or lost its original request')
    foreign = rows[-1]
    require('Exists' in foreign.get('create', '') and 'Absent' in foreign.get('resume', '')
            and foreign.get('preserved_sha256') == hashlib.sha256(bytes([2, 7, 1, 8])).hexdigest(),
            'foreign directory was adopted or modified')


def cli_result(data: bytes) -> dict:
    text = data.decode()
    require(text.count('### Result\n') == 1 and '### Error' not in text, 'browser CLI failed')
    value = parse_strict_json_bytes(text.split('### Result\n', 1)[1].split('\n### ', 1)[0].encode(), label='browser creation')
    require(value.get('status') == 'CONTINUITY_BROWSER_CREATION_PASS' and value.get('diagnostics') == [],
            'browser diagnostics or marker differs')
    creation(value['results']['creation']); late(value['results']['late'])
    return value['results']


def request_files(value: dict, directory: Path) -> list[Path]:
    creation(value)
    files = []
    for row in value['captures']:
        path = directory / row['name']
        require(path.is_file() and not path.is_symlink(), 'public request absent')
        wire = path.read_bytes()
        require(len(wire) == 5506 and hashlib.sha256(wire).hexdigest() == row['sha256'], 'request bytes differ')
        files.append(path)
    require({path.name for path in directory.glob('*.bin')} == {path.name for path in files}, 'unaccounted request')
    return files
