"""Native positive/negative control for the two Windows key-reopen paths.

Only the disposable CI checkout is mutated. The retained old fallback branches
are selected by their original platform gates; test assertions remain intact.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess

SOURCE = Path('candidate').resolve(strict=True)
OUT = Path('key-reopen-evidence').resolve()
EXPECTED = '7b9f4507664989e1c5ce23c4bbfb951d66a01611'
FILTER = 'sync_the_original_file_and_parent'
NAMES = (
    'wrapping_key_sync_the_original_file_and_parent_before_returning',
    'signing_roles_sync_the_original_file_and_parent_before_returning',
)

def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)

def command(args):
    return subprocess.run(args, cwd=SOURCE, capture_output=True, text=True,
                          check=True, timeout=30).stdout.strip()

def run(label):
    args = ['cargo', 'test', '--locked', '--manifest-path',
            'research/continuity-identity-candidate/Cargo.toml', '--lib',
            '--no-default-features', FILTER, '--', '--nocapture', '--test-threads=1']
    with (OUT / (label + '.log')).open('xb') as log:
        result = subprocess.run(args, cwd=SOURCE, stdout=log, stderr=subprocess.STDOUT,
                                timeout=900)
    text = (OUT / (label + '.log')).read_text(encoding='utf-8')
    (OUT / (label + '-status.json')).write_text(json.dumps({
        'command': args, 'returncode': result.returncode}, indent=2) + '\n')
    return result.returncode, text

OUT.mkdir()
require(os.name == 'nt', 'native Windows execution required')
require(command(['git', 'rev-parse', 'HEAD']) == EXPECTED, 'source commit differs')
require(not command(['git', 'status', '--porcelain']), 'checkout is dirty')
(OUT / 'commit.txt').write_text(EXPECTED + '\n')
(OUT / 'rustc.txt').write_text(command(['rustc', '-vV']) + '\n')
(OUT / 'driver.sha256').write_text(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() + '\n')
code, positive = run('positive')
require(code == 0, 'unchanged source failed; this is not a valid negative control')
require(re.search(r'test result: ok\. 2 passed; 0 failed; 0 ignored; 0 measured;', positive),
        'positive test count differs')
for name in NAMES:
    require('test windows_key_reopen::' + name + ' ... ' in positive, 'positive test missing')
require('WINDOWS_KEY_REOPEN wrapping=true file_then_parent_sync=true' in positive
        and 'WINDOWS_KEY_REOPEN signing_roles=4 file_then_parent_sync=true' in positive,
        'positive file/parent markers missing')

root = SOURCE / 'research/continuity-identity-candidate/src'
files = [root / 'durable.rs', root / 'crypto/persistence.rs']
original = {path: path.read_bytes() for path in files}
try:
    for path in files:
        text = original[path].decode().replace('\r\n', '\n')
        require(text.count('#[cfg(any(unix, windows))]') == 2, 'shared gate count changed')
        require(text.count('#[cfg(not(any(unix, windows)))]') == 1, 'fallback gate count changed')
        text = text.replace('#[cfg(any(unix, windows))]', '#[cfg(unix)]')
        text = text.replace('#[cfg(not(any(unix, windows)))]', '#[cfg(not(unix))]')
        if path.name == 'durable.rs':
            gate = '#[cfg(any(not(any(unix, windows)), all(test, unix)))]'
            require(text.count(gate) == 1, 'fallback import gate changed')
            text = text.replace(gate, '#[cfg(any(not(unix), test))]')
        path.write_text(text, encoding='utf-8')
    changed = set(command(['git', 'diff', '--name-only']).splitlines())
    require(changed == {p.relative_to(SOURCE).as_posix() for p in files}, 'unexpected mutation')
    (OUT / 'mutation.patch').write_text(command(['git', 'diff', '--no-ext-diff']) + '\n')
    code, negative = run('negative')
    require(code == 101, 'negative test command did not report Rust test failure')
    require(re.search(r'test result: FAILED\. 0 passed; 2 failed; 0 ignored; 0 measured;', negative),
            'negative failure count differs or compilation failed')
    for name in NAMES:
        require('test windows_key_reopen::' + name + ' ... ' in negative,
                'expected negative test did not execute')
        require('    windows_key_reopen::' + name in negative,
                'expected negative assertion did not fail')
    traces = [line for line in negative.splitlines() if line.startswith('WINDOWS_KEY_REOPEN_TRACE ')]
    expected = []
    for prefix, boundary in [('kind=wrapping', 'WrappingFile'),
                             ('kind=signing role=root', 'SigningFile')]:
        points = '[Point { boundary: ' + boundary + ', after: false }, Point { boundary: ' + boundary + ', after: true }]'
        expected.append('WINDOWS_KEY_REOPEN_TRACE ' + prefix + ' owner_returned=true points=' + points)
    require(sorted(traces) == sorted(expected),
            'negative control did not return each owner after file sync without parent sync')
    require(negative.count('assertion `left == right` failed') == 2,
            'negative failures are not the two sync-order assertions')
finally:
    for path, data in original.items():
        path.write_bytes(data)
    require(not command(['git', 'status', '--porcelain']), 'original checkout not restored')

(OUT / 'REVIEW.json').write_text(json.dumps({
    'source_commit': EXPECTED, 'completed': True, 'positive_tests_passed': 2,
    'negative_tests_failed_for_expected_reason': 2,
    'old_fallback_selected': True, 'test_assertions_unchanged': True,
    'observed': 'both owners returned after file sync but without pinned-parent sync',
    'scope': 'controlled selection of retained old fallback branches, not a full historical release',
    'checkout_restored': True,
    'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in OUT.iterdir() if p.is_file()},
}, indent=2) + '\n')
print('WINDOWS_KEY_REOPEN_CONTROL positive=2 negative=2 expected_missing_parent_sync=true', flush=True)
