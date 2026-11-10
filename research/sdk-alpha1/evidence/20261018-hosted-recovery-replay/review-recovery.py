"""Read back completed hosted proof inventories without rerunning Tamarin."""
from dataclasses import replace
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'artifact'))
import continuity_recovery_proof as gate
import continuity_recovery_composition as composition
from evidence_io import parse_strict_json_bytes, read_regular_snapshot
from rust_sdk_profile import write_json

raw = read_regular_snapshot(OUT / 'recovery-proof.zip', maximum=4 * 1024**2, label='proof artifact').data
assert len(raw) == 528063 and hashlib.sha256(raw).hexdigest() == '389a15f7f08abee40bb314e88edbcb3c0e58aaaf678648a60d1537bb6f612f05'
with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
    entries = zipped.infolist()
    assert len(entries) == len({e.filename for e in entries}) == 159
    assert sum(e.file_size for e in entries) <= 32 * 1024**2
    files = {}
    for entry in entries:
        path = PurePosixPath(entry.filename)
        assert not path.is_absolute() and '..' not in path.parts and str(path) == entry.filename
        assert '\\' not in entry.filename and stat.S_ISREG(entry.external_attr >> 16)
        assert not entry.flag_bits & 1 and entry.file_size <= gate.MAXIMUM_BYTES
        files[entry.filename] = zipped.read(entry)


def document(name):
    return parse_strict_json_bytes(files[name], label=name)


def check_part(prefix, label, original, case, result):
    started = document(prefix + label + '-started.json')
    argv = started['argv']
    source = Path(argv[1]); output = source.with_name(label + '-checked.spthy')
    assert source.name == label + '-input.spthy' and source.is_absolute()
    assert '..' not in source.parts
    assert argv == ['tamarin-prover', str(source), '--heuristic=s', '--derivcheck-timeout=60',
                    '--quit-on-warning', '--output=' + str(output), '+RTS',
                    f'-N{case.threads}', f'-M{case.heap_gib}G', '-s', '-RTS']
    assert started['timeout_seconds'] == 900 and started['input_sha256'] == case.sha256
    assert files[prefix + label + '-input.spthy'] == original
    assert hashlib.sha256(original).hexdigest() == case.sha256
    stderr = files[prefix + label + '.stderr'].decode('utf-8')
    assert re.search(r'(?im)^\s*(?:warning|error|fatal)\b', stderr) is None
    verified = gate._verify_summary(files[prefix + label + '.stdout'], source, output, case.expected_results())
    assert result['returncode'] == 0 and result['verified'] == verified
    checked = files[prefix + label + '-checked.spthy']
    assert checked and hashlib.sha256(checked).hexdigest() == result['certificate_sha256']
    return verified


reviews = {}
for profile in ('independent', 'key-scoped', 'shared-storage'):
    spec = gate.select_profile(profile); inputs = gate.load_inputs(ROOT, profile)
    receipt = document(profile + '/RESULT.json')
    assert receipt['accepted'] and receipt['release_claim_eligible'] is False
    assert receipt['profile'] == profile and receipt['main_theorem'] == spec.main
    assert receipt['model_sha256'] == spec.model_sha256 and receipt['archive_sha256'] == spec.archive_sha256
    assert all(receipt[key] == value for key, value in gate.source_digests().items())
    assert set(receipt['groups']) == set(spec.cases)
    groups = {}; composed_nodes = 0
    for label, case in spec.cases.items():
        result = receipt['groups'][label]
        if not case.compose_proofs:
            groups[label] = check_part(profile + '/', label, inputs[label], case, result)
            continue
        prefix = profile + '/' + label + '/'
        manifest = document(prefix + 'COMPOSITION.json')
        assert manifest['source_certificate_sha256'] == case.sha256
        assert hashlib.sha256(files[prefix + 'COMPOSITION.json']).hexdigest() == result['composition_sha256']
        nodes = composition.plan(inputs[label], case)
        records = {}
        for index, node in enumerate(nodes):
            part = f'node-{index:02d}'
            record = document(prefix + part + '-result.json')
            assert record == manifest['nodes'][node.name]
            conditional = replace(case, sha256=node.sha256, verified=(node.name,), compose_proofs=False)
            check_part(prefix, part, node.data, conditional, record['result'])
            records[node.name] = record
        verified = composition.combine(inputs[label], records, case)
        assert result['returncode'] == 0 and result['verification_mode'] == 'acyclic-composition'
        assert verified == result['verified'] == manifest['verified']
        groups[label] = verified; composed_nodes = len(nodes)
    universals = {name for label, verified in groups.items() for name in verified
                  if name in spec.cases[label].all_traces}
    witnesses = {name for label, verified in groups.items() for name in verified
                 if name in spec.cases[label].exists_traces}
    assert len(universals) == 20 and len(witnesses) == (3 if profile == 'independent' else 2)
    reviews[profile] = dict(universal_properties=sorted(universals), witnesses=sorted(witnesses),
                            composed_nodes=composed_nodes, groups=groups, main_theorem=spec.main)
    print(profile, len(universals), 'properties;', len(witnesses), 'witnesses;', composed_nodes, 'composition nodes')
output = OUT / 'RECOVERY_READBACK.json'
assert not output.exists()
write_json(output, dict(run=39115804790, job=117641228507, artifact=12133106525,
    head='714217739d642b7f78ea1d15abc523491a4133f1', artifact_sha256=hashlib.sha256(raw).hexdigest(),
    profiles=reviews, verifier_sha256=gate.source_digests(), release_claim_eligible=False,
    scope='Independent readback of pinned source/certificates, every hosted terminal verdict, checked-output '
          'hash and complete acyclic dependency closure. No new prover invocation. Reviewed single-exchange '
          'ideal-primitive profiles only; not unbounded multi-epoch secrecy, concrete security or SDK refinement.'))
