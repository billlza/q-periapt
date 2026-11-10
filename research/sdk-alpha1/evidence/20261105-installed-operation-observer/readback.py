from pathlib import Path
from collections import Counter, defaultdict
import copy
import hashlib
import json
import re
import sys
import zipfile

from evidence_io import parse_strict_json_bytes

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
ROOT = Path(__file__).resolve().parent

def require(value, message):
    if not value:
        raise ValueError(message)

def load(path):
    return parse_strict_json_bytes(path.read_bytes(), label='operation observation')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def natural(value):
    return type(value) is int and value >= 0

def bytes32(value):
    require(type(value) is list and len(value) == 32 and all(type(x) is int and 0 <= x < 256 for x in value), 'invalid 32-byte value')
    return bytes(value)

def check_id(value, epoch, index):
    data = bytes32(value)
    require(int.from_bytes(data[:8], 'big') == epoch and int.from_bytes(data[8:16], 'big') == index, 'message epoch/index changed')
    return data

def validate(value, trace, effects):
    expected_fields = {'completed', 'effects', 'epochs', 'final_witness_snapshot', 'kind', 'ordinary_sends',
        'payload_matrix', 'profile', 'release_claim_eligible', 'resources', 'samples_per_payload_per_epoch',
        'schema_version', 'scope', 'server', 'session', 'spans', 'witness'}
    require(type(value) is dict and set(value) == expected_fields, 'result field set differs')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'qperiapt.installed_operation_resources' and value['completed'] is True
        and value['release_claim_eligible'] is False, 'result completion/scope differs')
    require(value['profile'] in {'local', 'witness'}, 'unknown protection profile')
    require(value['ordinary_sends'] == 48 and value['samples_per_payload_per_epoch'] == 8
        and value['epochs'] == [0, 1] and value['payload_matrix'] == [[64, 0], [1024, 32], [16384, 1024]], 'workload changed')
    session = bytes32(value['session'])
    spans = value['spans']
    require(type(spans) is list and len(spans) == 106 and trace == spans, 'raw span stream and result differ')
    names = ['provision_two_owners', 'open_initiator', 'open_responder', 'establish']
    names += ['next_message_id', 'send_confirmed'] * 24 + ['traffic_independent_rekey']
    names += ['next_message_id', 'send_confirmed'] * 24
    names += ['effect_committed_result_lost', 'reopen_original_owners', 'retry_original_after_reopen', 'pre_cancelled_send', 'close_initiator']
    require([row['operation'] for row in spans] == names, 'operation order differs')
    witness = value['witness']
    require(set(witness) == {'rows', 'closed', 'handle_ns', 'read_ns', 'write_ns', 'framed_bytes'} and witness['closed'] is True, 'Witness did not close')
    rows = witness['rows']
    require(type(rows) is list and len(rows) <= 16384 and (bool(rows) == (value['profile'] == 'witness')), 'Witness profile/row count differs')
    totals = {'requests': 0, 'framed_bytes': 0, 'read_ns': 0, 'handle_ns': 0, 'write_ns': 0}
    prefixes = [dict(totals)]
    for row in rows:
        require(set(row) == {'request_tag', 'reply_tag', 'read_ns', 'handle_ns', 'write_ns'}, 'Witness row shape differs')
        require(all(natural(v) for v in row.values()) and (row['request_tag'], row['reply_tag']) in {(1, 1), (2, 2), (4, 5)}, 'Witness command/outcome differs')
        totals['requests'] += 1
        totals['framed_bytes'] += 7341
        for key in ('read_ns', 'handle_ns', 'write_ns'):
            totals[key] += row[key]
        prefixes.append(dict(totals))
    require(value['final_witness_snapshot'] == totals and all(witness[key] == totals[key] for key in ('framed_bytes', 'read_ns', 'handle_ns', 'write_ns')), 'Witness totals do not conserve rows')
    attributed = 0
    previous_end = 0
    operation_totals = defaultdict(lambda: {'calls': 0, 'elapsed_ns': 0, 'cpu_user_us': 0, 'cpu_system_us': 0,
        'witness_exchanges': 0, 'witness_framed_bytes': 0, 'witness_tags': Counter()})
    for row in spans:
        require(set(row) == {'operation', 'elapsed_ns', 'cpu_user_us', 'cpu_system_us', 'witness_before', 'witness_after', 'outcome'}, 'span fields differ')
        require(natural(row['elapsed_ns']) and 0 < row['elapsed_ns'] < 900_000_000_000
            and natural(row['cpu_user_us']) and natural(row['cpu_system_us']), 'invalid operation timing')
        bounds = []
        for key in ('witness_before', 'witness_after'):
            snap = row[key]
            require(type(snap) is dict and set(snap) == set(totals) and all(natural(x) for x in snap.values()), 'invalid Witness snapshot')
            index = snap['requests']
            require(index <= len(rows) and snap == prefixes[index], 'snapshot is not its exact row prefix')
            bounds.append(index)
        start, end = bounds
        require(previous_end <= start <= end, 'operation Witness intervals overlap or reverse')
        previous_end = end
        attributed += end - start
        total = operation_totals[row['operation']]
        total['calls'] += 1
        for key in ('elapsed_ns', 'cpu_user_us', 'cpu_system_us'):
            total[key] += row[key]
        total['witness_exchanges'] += end - start
        total['witness_framed_bytes'] += (end - start) * 7341
        total['witness_tags'].update(str(r['request_tag']) + '/' + str(r['reply_tag']) for r in rows[start:end])
    require(spans[0]['outcome'] == {'owners': 2} and spans[1]['outcome'] == {'opened': True}
        and spans[2]['outcome']['opened'] is True and spans[2]['outcome']['sdk_open_ns'] > 0, 'owner creation/opening absent')
    establish = spans[3]['outcome']
    require(bytes32(establish['session']) == session and establish['peer']['established'] == value['session'], 'establishment identities differ')
    sends = [row['outcome'] for row in spans if row['operation'] == 'send_confirmed']
    allocations = [row['outcome'] for row in spans if row['operation'] == 'next_message_id']
    bodies = {}
    for index, (sent, allocation) in enumerate(zip(sends, allocations, strict=True)):
        epoch, local = divmod(index, 24)
        round_number, offset = divmod(local, 3)
        length, ad_length = value['payload_matrix'][(round_number + offset) % 3]
        require(sent['index'] == allocation['index'] == index and sent['epoch'] == allocation['epoch'] == epoch, 'sample order/epoch differs')
        message = check_id(sent['message'], epoch, local)
        require(allocation['message'] == sent['message'] and sent['payload_bytes'] == length
            and sent['associated_data_bytes'] == ad_length and sent['exchanges'] == 1, 'sample input/allocation differs')
        peer = sent['peer']
        require(peer['consumed'] is True and peer['duplicate'] is False and peer['calls'] == peer['effects'] == 1
            and bytes32(peer['session']) == session and peer['message'] == sent['message'], 'new application effect missing/duplicated')
        require(message.hex() not in bodies, 'repeated original message ID')
        bodies[message.hex()] = session + message + bytes((index + offset) % 251 for offset in range(length))
    rekey = next(row['outcome'] for row in spans if row['operation'] == 'traffic_independent_rekey')
    require(rekey['epoch'] == rekey['peer']['epoch'] == 1 and rekey['application_effects_before'] == 24
        and natural(rekey['exchanges']) and rekey['exchanges'] > 0, 'independent PQ control absent')
    lost, reopened, retry, cancelled, closed = [row['outcome'] for row in spans[-5:]]
    message = check_id(lost['message'], 1, 24)
    require(lost['attempts'] == 1 and 'UnexpectedEof' in lost['last_error'] and lost['peer']['application_result_lost'] is True
        and lost['peer']['calls'] == lost['peer']['effects'] == 1, 'lost result did not follow one durable effect')
    require(reopened['original_message'] == lost['message'] and reopened['peer']['reopened'] is True, 'original reopen missing')
    require(retry['message'] == retry['peer']['message'] == lost['message'] and retry['peer']['session'] == value['session']
        and retry['peer']['consumed'] is True and retry['peer']['effects'] == 0 and retry['peer']['calls'] == 1,
        'exact recovery duplicated or lost application effect')
    require(natural(retry['wire_bytes']) and retry['wire_bytes'] == 1133, 'replayed wire width differs')
    bytes32(retry['wire_sha3_256'])
    bodies[message.hex()] = session + message + bytes((48 + offset) % 251 for offset in range(1024))
    check_id(cancelled['message'], 1, 25)
    require(cancelled['cancelled'] is True and closed == {'closed': True}, 'cancellation/close missing')
    require(value['server']['closed'] is True and value['server']['effects'] == 49 and value['server']['calls'] == 50, 'server effect/callback census differs')
    require(effects == bodies and len(value['effects']) == len(bodies) == 49, 'durable effect files differ from exact workload')
    for row in value['effects']:
        require(set(row) == {'file', 'bytes', 'sha3_256'} and row['file'] in bodies, 'unexpected public effect')
        body = bodies[row['file']]
        require(row['bytes'] == len(body) and bytes32(row['sha3_256']) == hashlib.sha3_256(body).digest(), 'effect digest or byte length differs')
    require(len({r['file'] for r in value['effects']}) == 49, 'duplicate effect summary')
    resources = value['resources']
    require([row['stage'] for row in resources] == ['established', 'epoch-0-delivered', 'epoch-1-delivered', 'recovered-and-cancelled', 'owners-closed'], 'memory stages differ')
    for row in resources:
        require(set(row) == {'stage', 'resident_bytes', 'physical_footprint_bytes', 'malloc_blocks_in_use',
            'malloc_size_in_use_bytes', 'malloc_max_size_in_use_bytes', 'malloc_size_allocated_bytes',
            'initiator_database_bytes', 'responder_database_bytes'}, 'memory counter inventory differs')
        require(all(natural(v) for k, v in row.items() if k != 'stage') and row['resident_bytes'] > 0
            and row['physical_footprint_bytes'] > 0 and row['initiator_database_bytes'] > 0 and row['responder_database_bytes'] > 0,
            'invalid memory/store observation')
    return {'ordinary_sends': 48, 'effects': 49, 'spans': 106, 'witness_exchanges': len(rows),
        'attributed_witness_exchanges': attributed, 'outside_measured_spans': len(rows) - attributed,
        'operation_totals': dict(operation_totals), 'performance_qualified': False,
        'scope': 'Functional measurement validation during other qualification work; no controlled timing, per-client memory or frozen resource budget.'}

def main():
    label = sys.argv[1]
    require(re.fullmatch(r'validation-(?:local|witness)-[0-9]{2}', label) is not None, 'unknown validation cohort')
    directory = ROOT / label
    run = load(directory / 'RUN.json')
    require(run['completed'] is True and run['performance_qualified'] is False and run['release_claim_eligible'] is False, 'cohort execution incomplete or relabeled')
    raw = (directory / 'RESULT.json').read_bytes()
    require(sha(raw) == run['result_sha256'], 'result bytes changed')
    value = parse_strict_json_bytes(raw, label='operation results')
    require(load(directory / 'runtime.json')['returncode'] == 0 and (directory / 'runtime.stderr').read_bytes() == b'', 'runtime failed/emitted diagnostics')
    stdout = (directory / 'runtime.stdout').read_bytes()
    trace = [parse_strict_json_bytes(line, label='emitted operation') for line in re.findall(rb'OPERATION_RESOURCE_SPAN (.+)$', stdout, re.M)]
    effect_root = Path(run['private_runtime']) / 'installation/responder/measured-effects'
    require(effect_root.is_dir() and not effect_root.is_symlink(), 'business store missing')
    effects = {path.name: path.read_bytes() for path in effect_root.iterdir() if path.is_file() and not path.is_symlink()}
    require(len(effects) == len(list(effect_root.iterdir())), 'business store has nonregular entries')
    actual = validate(value, trace, effects)
    controls = []
    changes = [
        ('completion', lambda v: v.update(completed=False)),
        ('claim', lambda v: v.update(release_claim_eligible=True)),
        ('workload', lambda v: v.update(ordinary_sends=47)),
        ('missing_span', lambda v: v['spans'].pop()),
        ('reordered_span', lambda v: v['spans'].reverse()),
        ('negative_time', lambda v: v['spans'][5].update(elapsed_ns=-1)),
        ('cpu_boolean', lambda v: v['spans'][5].update(cpu_user_us=True)),
        ('next_identity', lambda v: v['spans'][4]['outcome']['message'].__setitem__(0, 1)),
        ('payload', lambda v: v['spans'][5]['outcome'].update(payload_bytes=65)),
        ('duplicate_effect', lambda v: v['spans'][5]['outcome']['peer'].update(effects=2)),
        ('lost_result', lambda v: v['spans'][-5]['outcome']['peer'].update(application_result_lost=False)),
        ('reopen', lambda v: v['spans'][-4]['outcome']['peer'].update(reopened=False)),
        ('retry_effect', lambda v: v['spans'][-3]['outcome']['peer'].update(effects=1)),
        ('cancel', lambda v: v['spans'][-2]['outcome'].update(cancelled=False)),
        ('worker_open', lambda v: v['server'].update(closed=False)),
        ('effect_digest', lambda v: v['effects'][0]['sha3_256'].__setitem__(0, v['effects'][0]['sha3_256'][0] ^ 1)),
        ('rss', lambda v: v['resources'][0].update(resident_bytes=-1)),
        ('witness_total', lambda v: v['witness'].update(framed_bytes=v['witness']['framed_bytes'] + 1)),
        ('prefix_bytes', lambda v: v['spans'][5]['witness_after'].update(framed_bytes=v['spans'][5]['witness_after']['framed_bytes'] + 7341)),
    ]
    if value['profile'] == 'witness':
        changes += [('witness_tag', lambda v: v['witness']['rows'][0].update(request_tag=255)),
            ('boundary', lambda v: v['spans'][5]['witness_after'].update(requests=0))]
    for name, change in changes:
        altered = copy.deepcopy(value)
        change(altered)
        try:
            validate(altered, altered['spans'], effects)
        except ValueError as error:
            controls.append({'name': name, 'rejection': str(error)})
        else:
            raise ValueError('altered observation accepted: ' + name)
    altered_effects = dict(effects)
    first = next(iter(altered_effects))
    altered_effects[first] += b'changed'
    try:
        validate(value, trace, altered_effects)
    except ValueError as error:
        controls.append({'name': 'durable_business_bytes', 'rejection': str(error)})
    else:
        raise ValueError('altered business bytes accepted')
    output = {'source_commit': run['source_commit'], 'binary_sha256': run['binary_sha256'],
        'result_sha256': sha(raw), 'profile': value['profile'], 'validation': actual, 'altered_observation_controls': controls}
    with (directory / 'READBACK.json').open('x') as stream:
        stream.write(json.dumps(output, indent=2, sort_keys=True) + '\n')
    public = directory / 'public-effects'
    public.mkdir()
    for name, data in effects.items():
        with (public / name).open('xb') as stream:
            stream.write(data)
    print(json.dumps({'profile': value['profile'], 'spans': 106, 'effects': 49,
        'negative_controls': len(controls), 'witness_exchanges': actual['witness_exchanges'],
        'unattributed_to_operations': actual['outside_measured_spans'], 'performance_qualified': False}))

def archive_main():
    archive_path, manifest_path, output_path = map(Path, sys.argv[2:])
    manifest = load(manifest_path)
    results = {}
    with zipfile.ZipFile(archive_path) as archive:
        require(len(archive.namelist()) == len(manifest) and set(archive.namelist()) == set(manifest), 'capsule inventory differs')
        for name, expected in manifest.items():
            data = archive.read(name)
            require(len(data) == expected['bytes'] and sha(data) == expected['sha256'], 'capsule member changed: ' + name)
        require(archive.read('controller/readback.py') == Path(__file__).read_bytes(), 'archive reader source differs')
        for label in ('validation-local-01', 'validation-witness-01'):
            prefix = 'cohorts/' + label + '/'
            result_bytes = archive.read(prefix + 'RESULT.json')
            value = parse_strict_json_bytes(result_bytes, label='archived observation')
            run = parse_strict_json_bytes(archive.read(prefix + 'RUN.json'), label='archived execution')
            require(run['completed'] is True and run['performance_qualified'] is False and sha(result_bytes) == run['result_sha256'], 'archived execution changed')
            stdout = archive.read(prefix + 'runtime.stdout')
            trace = [parse_strict_json_bytes(line, label='archived emitted span') for line in re.findall(rb'OPERATION_RESOURCE_SPAN (.+)$', stdout, re.M)]
            effect_prefix = prefix + 'public-effects/'
            effects = {name.removeprefix(effect_prefix): archive.read(name) for name in manifest if name.startswith(effect_prefix)}
            actual = validate(value, trace, effects)
            original = parse_strict_json_bytes(archive.read(prefix + 'READBACK.json'), label='archived first reread')
            require(actual == original['validation'], 'archive-only result differs')
            results[label] = actual
    record = {'archive_sha256': sha(archive_path.read_bytes()), 'members_verified': len(manifest),
        'public_business_files_verified': 98, 'cohorts': results, 'private_runtime_accessed': False,
        'performance_qualified': False, 'release_claim_eligible': False}
    with output_path.open('x') as stream:
        stream.write(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'archive_members': len(manifest), 'cohorts': 2, 'business_files': 98, 'private_runtime_accessed': False}))

if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--archive':
        archive_main()
    else:
        main()
