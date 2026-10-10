"""Seal an exact-source development checkpoint, without release qualification.

All required receipts must be terminal successes before any destination is made.
Older failures and the precise scope of the socket diagnostic remain explicit.
"""
from pathlib import Path
import gzip
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile

w = Path(__file__).resolve().parent
i = w.parent / 'credential-lifecycle-integration'
commit = '3eaa0fc9d4b1bcee7e8796fd1afbe0e3e62d0133'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=i, text=True).strip() == commit
assert subprocess.check_output(['git', 'status', '--porcelain'], cwd=i, text=True) == ''
checks = [
    'history-connect-fixture-regression-03', 'history-connect-fixture-tests-01',
    'history-connect-fixture-min-clippy-01', 'history-connect-fixture-clippy-01',
    'history-final-doc-02', 'history-connect-fixture-format-01',
    'history-final-c-build-03', 'history-final-c-format-02',
    'history-witness-swift-03', 'history-final-kotlin-01',
    'history-witness-kotlin-consumer-03', 'history-final-readers-02',
    'history-final-public-c-01', 'history-final-public-swift-01',
    'history-final-public-kotlin-01', 'history-tls-record-collector-01',
    'historical-foreign-source-03', 'historical-foreign-delta-02',
]
identities = {}
receipts = {}
for label in checks:
    r = json.loads((w / (label + '.json')).read_text())
    assert r['completed'], label
    assert all(r[key] == 0 for key in ('returncode', 'exit') if key in r), label
    for name, value in r.get('source_hashes', {}).items():
        name = ('research/continuity-identity-candidate/' + name
                if name.startswith(('src/', 'tests/', 'examples/')) else name)
        # The collector component records its artifact module basenames.
        if '/' not in name:
            name = 'artifact/' + name
        assert sha(i / name) == value, (label, name)
        identities[name] = value
    receipts[label] = r
for name, value in identities.items():
    assert hashlib.sha256(subprocess.check_output(['git', 'show', commit + ':' + name], cwd=i)).hexdigest() == value, name
full = receipts['history-connect-fixture-regression-03']
assert full['passed_tests'] == 471
assert receipts['history-connect-fixture-tests-01']['passed_tests'] == 9
assert receipts['history-final-readers-02']['observed_tests'] == ['42']
artifact_full = json.loads((w / 'historical-foreign-artifact-tests-02.json').read_text())
assert not artifact_full['completed'] and artifact_full['returncode'] == 1
assert artifact_full['observed_test_summary'][0][0] == 2566
full_text = (w / 'historical-foreign-artifact-tests-02.log').read_text()
failures = re.findall(r'^FAIL: ([^ ]+) \(([^)]+)\)', full_text, re.MULTILINE)
assert failures == [
    ('test_artifact_guide_states_the_enforced_tracked_source_count', 'test_codeql_rust_quality.CodeQLRustQualityTests.test_artifact_guide_states_the_enforced_tracked_source_count'),
    ('test_rust_codeql_compatibility_and_upload_boundary_is_documented', 'test_proof_to_byte_release.BoundVerifierWiringTests.test_rust_codeql_compatibility_and_upload_boundary_is_documented'),
]
assert not re.findall(r'^ERROR:', full_text, re.MULTILINE)
assert receipts['historical-foreign-delta-02']['observed_test_summary'][0][0] == 327
delta_text = (w / 'historical-foreign-delta-02.log').read_text()
assert all(f'{test} ({qualified}) ... ok' in delta_text for test, qualified in failures)
assert subprocess.check_output(['git', 'diff', '--name-only', artifact_full['source_commit'], commit], cwd=i, text=True).splitlines() == ['ARTIFACT.md']

abi = json.loads((w / 'HISTORY_FINAL_C_ABI.json').read_text())
assert abi['completed'] and abi['candidate_exports'] == 72 and abi['architecture'] == 'arm64'
assert sha(Path(abi['library'])) == abi['library_sha256']
for language in ('c', 'swift', 'kotlin'):
    r = receipts['history-final-public-' + language + '-01']
    assert r['native_library_sha256'] == abi['library_sha256']
    assert sha(Path(r['client_path'])) == r['client_sha256']

saved = w / 'historical-foreign-binaries-3eaa0fc9'
saved.mkdir()
binary = w.parent / 'continuity-renewal-journal/debug/deps/q_periapt_continuity_identity_candidate-c4e516a635a68dd1'
shutil.copy2(binary, saved / 'native-regression-test')
shutil.copy2(Path(abi['library']), saved / Path(abi['library']).name)
for language in ('c', 'swift', 'kotlin'):
    src = Path(receipts['history-final-public-' + language + '-01']['client_path'])
    shutil.copy2(src, saved / (language + '-client'))
binaries = {str(p): sha(p) for p in saved.iterdir() if p.is_file()}

dest = i / 'research/sdk-alpha1/evidence/20261004-historical-foreign-3eaa0fc9'
dest.mkdir()
for label in checks:
    shutil.copy2(w / (label + '.json'), dest / (label + '.json'))
    log = w / (label + '.log')
    if log.exists():
        (dest / (label + '.log.gz')).write_bytes(gzip.compress(log.read_bytes(), mtime=0))
for name in ('HISTORY_FINAL_C_ABI.json', 'HISTORICAL_FOREIGN_CENSUS.json',
             'CONNECT_FIXTURE_PROBE_02.json', 'CONNECT_FIXTURE_STABILIZATION.json',
             'HISTORY_TLS_RECORD_FAILED_REGRESSION_BINARY.json'):
    shutil.copy2(w / name, dest / name)
for label in ('history-tls-record-regression-02', 'historical-foreign-delta-01', 'historical-foreign-artifact-tests-01', 'historical-foreign-artifact-tests-02',
              'history-final-readers-01', 'history-final-c-format-01', 'history-tls-record-c-build-01'):
    # Preserve actual failed preflights, with their original status and logs.
    for suffix in ('.json', '.log'):
        src = w / (label + suffix)
        if src.exists():
            if suffix == '.log':
                (dest / (src.name + '.gz')).write_bytes(gzip.compress(src.read_bytes(), mtime=0))
            else:
                shutil.copy2(src, dest / src.name)
for name in ('run-development.py', 'run-native-quality.py', 'run-ci-preflight.py',
             'run-history-foreign.py', 'run-history-witness-flow.py',
             'run-history-kotlin-consumer.py', 'run-witnessed-collector-component.py',
             'seal-historical-foreign.py'):
    shutil.copy2(w / name, dest / name)
prior_runner = (w / 'run-development.py').read_bytes().replace(
    b"elif mode == 'connect-tests':\n    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'connect::tests::', '--', '--test-threads=2', '--nocapture']\n", b'', 1)
assert hashlib.sha256(prior_runner).hexdigest() == 'b24241356528226abf26decd593d75e798945ace9798ec258d1b53cfde87bf1d'
(dest / 'run-development-before-connect-fixture.py').write_bytes(prior_runner)
for report in w.glob('history-final-kotlin-01-TEST-*.xml'):
    shutil.copy2(report, dest / report.name)
for label in ('connect-fixture-probe-02', 'historical-foreign-census-green-02'):
    (dest / (label + '.log.gz')).write_bytes(gzip.compress((w / (label + '.log')).read_bytes(), mtime=0))
diagnostic = io.BytesIO()
with tarfile.open(fileobj=diagnostic, mode='w', format=tarfile.PAX_FORMAT) as archive:
    for name in ('Cargo.toml', 'Cargo.lock', 'src/main.rs'):
        data = (w / 'connect-fixture-probe' / name).read_bytes()
        member = tarfile.TarInfo(name)
        member.size, member.mode, member.mtime = len(data), 0o600, 0
        archive.addfile(member, io.BytesIO(data))
(dest / 'connect-fixture-probe.tar.gz').write_bytes(gzip.compress(diagnostic.getvalue(), mtime=0))
sys.path.insert(0, str(i / 'artifact'))
import continuity_witnessed_renewal as reader
public = {}
for language in ('c', 'swift', 'kotlin'):
    label = 'history-final-public-' + language + '-01'
    folder = w / (label + '-verified')
    printed = {'c': 'C', 'swift': 'Swift', 'kotlin': 'Kotlin'}[language]
    verified = reader.verify((w / (label + '.log')).read_bytes(), folder, language=printed)
    original = json.loads((w / ('HISTORY_FINAL_PUBLIC_' + language.upper() + '.json')).read_text())
    assert verified == original and len(verified['public_readbacks']) == 272
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, value in sorted(verified['public_readbacks'].items()):
            data = (folder / name).read_bytes()
            assert hashlib.sha256(data).hexdigest() == value
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.mtime = len(data), 0o600, 0
            archive.addfile(member, io.BytesIO(data))
    target = dest / (language + '-public-evidence.tar.gz')
    target.write_bytes(gzip.compress(raw.getvalue(), mtime=0))
    shutil.copy2(w / ('HISTORY_FINAL_PUBLIC_' + language.upper() + '.json'),
                 dest / ('HISTORY_FINAL_PUBLIC_' + language.upper() + '.json'))
    public[printed] = dict(files=272, archive=target.name, sha256=sha(target))

qualification = dict(
    completed=True, source_commit=commit, source_hashes=identities, binaries=binaries,
    native_full_tests=471, native_connect_tests=9,
    artifact_validation=dict(last_full_run=dict(tests=2566, passed=2564, failed=2, source_commit=artifact_full['source_commit'], failures=failures),
                             correction='Only ARTIFACT.md changes310 to311 after the full run; both failing document assertions pass in the327-test affected group rerun',
                             affected_group_rerun=receipts['historical-foreign-delta-02']['observed_test_summary'], final_full_single_run_pass_claim=False),
    reader_tests=42, c_unit_tests=9, swift_unit_tests=27, kotlin_unit_tests=24,
    candidate_exports=72, macos_architecture='arm64 only', public_evidence=public,
    scope='Historical policy and original witnessed credential renewal through current development C/Swift/Kotlin owners, with four-case signed TCP/TLS public readback and installed-collector component integration. Shared native engine; not fresh archive, signed-policy real-clock expiry, foreign loss/cancel matrix or release qualification.',
    observations=[
        'Historical policy verifies original independent pin and both signatures without SDK runtime; current activation/new Commit retain live authority',
        'Existing authenticated local proposal repairs absent coordination without resealing or witness mutation; missing local proposal is never NoCommit',
        'The three foreign owners recover Applied and Closed with SDK state absent, but refuse Pending new Commit with error702 and keep original image/pending',
        'Native TLS records are returned only after the original authenticated server path sends and closes; records do not prove client consumption',
        'Public reader rejects terminal Status before original Commit/Close, inflated TLS counts, false no-SDK windows and incomplete/private evidence',
        'Native full suite includes independent expired-policy reconstruction, six preparation configuration failure cuts and eight existing process-kill cuts',
    ],
    failures_and_repairs=[
        'New foreign Rust test changed tracked source count310 to311; exact CodeQL census and required-file assertion updated, failure evidence retained',
        'Full artifact rerun then found both current documentation assertions still reading310; only ARTIFACT.md changed to311 and all327 related checks were rerun. The failed2566-test run remains failed, not rewritten as a full pass.',
        'First final-reader runner selected30 tests but expected42; rerun includes the omitted C consumer module and passes exact42',
        'C source-tree formatting requires installed fixture layout; check rerun on byte-identical staged source with original fixture paths',
        'TLS fixture admitted counter became unused in other targets after record API addition; final fixture checks bounded records against admissions',
        'Original full native run returned WouldBlock from the uninstrumented connect test fixture. Real Darwin probe confirmed inherited nonblocking mode defeats read_timeout; accepted test socket now explicitly blocking before unchanged1s timeout and zero-byte EOF assertion. Production connect prefix is byte-identical. Original FIN race was not separately replayed with step instrumentation.',
    ],
    remaining=[
        'Independent before-local-preparation grant closure after expiry; existing Pending/Suspended remains correct unresolved outcome',
        'Foreign real signed-policy expiry, lost Commit/ACK, Busy/cancel/close, actual preparation process-kill matrix',
        'Fresh Debug/Release installed archive and current/minimum physical platform qualification',
        'Independent protocol implementation, retained-secret PQ recovery construction/proof, performance and external review',
        'Full0.2.0 lifecycle, upgrade and release/maintenance objective',
    ],
    release_claim_eligible=False, full_goal_complete=False,
)
(dest / 'QUALIFICATION.json').write_text(json.dumps(qualification, indent=2) + '\n')
manifest = {str(p.relative_to(dest)): sha(p) for p in sorted(dest.rglob('*')) if p.is_file()}
(dest / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(dict(path=str(dest), files=len(manifest), manifest_sha256=sha(dest / 'MANIFEST.json'), binaries=binaries), indent=2))
