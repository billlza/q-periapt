from collections import Counter, defaultdict
from pathlib import Path
import copy
import hashlib
import json
import re
import sys
import zipfile
from evidence_io import parse_strict_json_bytes

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode

def require(value, message):
    if not value:
        raise ValueError(message)

def load(path):
    return parse_strict_json_bytes(path.read_bytes(), label='fanout observation')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def natural(value):
    return type(value) is int and value >= 0

def bytes32(value):
    require(type(value) is list and len(value) == 32
        and all(type(x) is int and 0 <= x < 256 for x in value), 'invalid 32-byte value')
    return bytes(value)

def message_id(value, epoch, index):
    data = bytes32(value)
    require(int.from_bytes(data[:8], 'big') == epoch
        and int.from_bytes(data[8:16], 'big') == index, 'member message epoch/index differs')
    return data

def batch_id(value, index):
    data = bytes32(value)
    require(int.from_bytes(data[:8], 'big') == index, 'fanout ordinal differs')
    return data

def witness_accounting(value):
    witness = value['witness']
    require(set(witness) == {'rows', 'closed', 'handle_ns', 'read_ns', 'write_ns', 'framed_bytes'}
        and witness['closed'] is True, 'Witness did not close')
    rows = witness['rows']
    require(type(rows) is list and len(rows) <= 16384
        and bool(rows) == (value['profile'] == 'witness'), 'Witness profile/row count differs')
    totals = {'requests':0, 'framed_bytes':0, 'read_ns':0, 'handle_ns':0, 'write_ns':0}
    prefixes = [dict(totals)]
    for row in rows:
        require(set(row) == {'request_tag', 'reply_tag', 'read_ns', 'handle_ns', 'write_ns'}
            and all(natural(v) for v in row.values())
            and (row['request_tag'], row['reply_tag']) in {(1,1), (2,2), (4,5)}, 'Witness row differs')
        totals['requests'] += 1
        totals['framed_bytes'] += 7341
        for key in ('read_ns', 'handle_ns', 'write_ns'):
            totals[key] += row[key]
        prefixes.append(dict(totals))
    require(value['final_witness_snapshot'] == totals and all(witness[key] == totals[key]
        for key in ('framed_bytes', 'read_ns', 'handle_ns', 'write_ns')), 'Witness totals do not conserve rows')
    groups = defaultdict(lambda: {'calls':0,'elapsed_ns':0,'cpu_user_us':0,'cpu_system_us':0,
        'witness_exchanges':0,'witness_framed_bytes':0,'witness_tags':Counter(),'per_call':[]})
    attributed = previous_end = 0
    for row in value['spans']:
        require(set(row) == {'operation','elapsed_ns','cpu_user_us','cpu_system_us',
            'witness_before','witness_after','outcome'}, 'span field set differs')
        require(natural(row['elapsed_ns']) and 0 < row['elapsed_ns'] < 900_000_000_000
            and natural(row['cpu_user_us']) and natural(row['cpu_system_us']), 'invalid timing counter')
        bounds = []
        for key in ('witness_before','witness_after'):
            snap = row[key]
            require(type(snap) is dict and set(snap) == set(totals)
                and all(natural(n) for n in snap.values()), 'invalid Witness snapshot')
            index = snap['requests']
            require(index <= len(rows) and snap == prefixes[index], 'snapshot differs from exact row prefix')
            bounds.append(index)
        start, end = bounds
        require(previous_end <= start <= end, 'Witness intervals overlap or reverse')
        previous_end = end
        attributed += end - start
        name = row['operation']
        if name == 'deliver_account_member':
            name += '/' + str(row['outcome']['member_order'])
        group = groups[name]
        group['calls'] += 1
        for key in ('elapsed_ns','cpu_user_us','cpu_system_us'):
            group[key] += row[key]
        group['witness_exchanges'] += end - start
        group['witness_framed_bytes'] += (end - start) * 7341
        tags = Counter(str(r['request_tag']) + '/' + str(r['reply_tag']) for r in rows[start:end])
        group['witness_tags'].update(tags)
        group['per_call'].append({'requests':end-start, 'framed_bytes':(end-start)*7341, 'tags':dict(tags)})
    return {'witness_exchanges':len(rows), 'attributed_witness_exchanges':attributed,
        'outside_measured_spans':len(rows)-attributed, 'operation_totals':dict(groups)}

def validate(value, trace, effects, context):
    fields = {'schema_version','kind','completed','profile','layout','recipient_count','account',
        'sessions','ordinary_batches','ordinary_member_deliveries','total_batches','effects','servers',
        'spans','resources','witness','final_witness_snapshot','payload_matrix',
        'samples_per_payload_per_epoch','epochs','scope','release_claim_eligible'}
    require(type(value) is dict and set(value) == fields, 'result field set differs')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'qperiapt.installed_fanout_resources' and value['completed'] is True
        and value['release_claim_eligible'] is False, 'completion/scope differs')
    require(value['profile'] in {'local','witness'} and value['layout'] in {'own','peer'}, 'profile/layout differs')
    require(value['recipient_count'] == 2 and value['ordinary_batches'] == 12
        and value['ordinary_member_deliveries'] == 24 and value['total_batches'] == 13
        and value['samples_per_payload_per_epoch'] == 2 and value['epochs'] == [0,1]
        and value['payload_matrix'] == [[64,0],[1024,32],[16384,1024]], 'workload differs')
    require(set(context) == {'owner_accounts'} and len(context['owner_accounts']) == 3, 'public owner inventory differs')
    accounts = [bytes32(v) for v in context['owner_accounts']]
    require(accounts[1] == accounts[2] == bytes32(value['account'])
        and (accounts[0] == accounts[1]) == (value['layout'] == 'own'), 'owner account layout differs')
    require(len(value['sessions']) == 2, 'session count differs')
    sessions = [bytes32(v) for v in value['sessions']]
    require(sessions[0] != sessions[1], 'recipient sessions collapse')
    spans = value['spans']
    require(type(spans) is list and len(spans) == 89 and spans == trace, 'raw span stream/result differs')
    names = ['provision_three_installed_owners','open_sender','open_recipient','open_recipient',
        'establish_member','establish_member']
    for index in range(12):
        names += ['next_account_id','deliver_account_member','deliver_account_member',
            'retained_member_outcome','retained_member_outcome','retire_account_operation']
        if index == 5:
            names += ['traffic_independent_member_rekey'] * 2
    names += ['next_uncertain_account_id','member_effect_committed_result_lost',
        'reopen_three_original_owners','deliver_original_uncertain_account_member',
        'deliver_original_uncertain_account_member','retire_recovered_account_operation',
        'next_cancelled_account_id','pre_cancelled_account_delivery','close_sender']
    require([row['operation'] for row in spans] == names, 'operation order differs')
    accounting = witness_accounting(value)
    require(spans[0]['outcome'] == {'owners':3,'recipients':2,'layout':value['layout']}
        and spans[1]['outcome'] == {'opened':True}, 'owner provision/open differs')
    for index in range(2):
        opened = spans[index+2]['outcome']
        require(set(opened) == {'recipient','sdk_open_ns'} and opened['recipient'] == index
            and natural(opened['sdk_open_ns']) and opened['sdk_open_ns'] > 0, 'recipient opening differs')
        established = spans[index+4]['outcome']
        require(established['recipient'] == index and bytes32(established['session']) == sessions[index]
            and established['peer']['established'] == value['sessions'][index]
            and established['peer']['calls'] == established['peer']['effects'] == 0, 'bootstrap identity/effects differ')
    bodies = {}
    cursor = 6
    batches = []
    for batch_index in range(12):
        allocation, first, second, retained0, retained1, retired = [row['outcome'] for row in spans[cursor:cursor+6]]
        batch = batch_id(allocation['batch'], batch_index)
        require(allocation['batch_index'] == batch_index, 'allocation order differs')
        batches.append(batch)
        length, ad_length = value['payload_matrix'][batch_index % 3]
        sent_by_recipient = {}
        for offset, sent in enumerate((first,second)):
            index = (batch_index + offset) % 2
            require(sent['recipient'] == index and sent['member_order'] == offset
                and sent['batch_index'] == batch_index and bytes32(sent['batch']) == batch
                and sent['epoch'] == batch_index // 6 and sent['payload_bytes'] == length
                and sent['associated_data_bytes'] == ad_length and sent['exchanges'] == 1, 'member delivery binding differs')
            message = message_id(sent['message'], batch_index // 6, batch_index % 6)
            peer = sent['peer']
            require(peer['consumed'] is True and peer['duplicate'] is False
                and peer['calls'] == peer['effects'] == 1 and bytes32(peer['session']) == sessions[index]
                and peer['message'] == sent['message'], 'ordinary member effect missing/duplicated')
            key = str(index) + '/' + message.hex()
            require(key not in bodies, 'member message ID reused')
            bodies[key] = sessions[index] + message + bytes((batch_index+n) % 251 for n in range(length))
            sent_by_recipient[index] = sent
        for index, retained in enumerate((retained0,retained1)):
            require(retained['recipient'] == index and retained['batch_index'] == batch_index
                and bytes32(retained['batch']) == batch and retained['exchanges'] == 0
                and retained['message'] == sent_by_recipient[index]['message'], 'retained member result differs')
        require(retired == {'batch_index':batch_index,'batch':allocation['batch']}, 'retirement binding differs')
        cursor += 6
        if batch_index == 5:
            for index in range(2):
                updated = spans[cursor+index]['outcome']
                require(updated['recipient'] == index and updated['epoch'] == updated['peer']['epoch'] == 1
                    and natural(updated['exchanges']) and updated['exchanges'] > 0
                    and natural(updated['peer']['exchanges']) and updated['peer']['exchanges'] > 0,
                    'independent PQ member control differs')
            cursor += 2
    require(cursor == 80 and len(set(batches)) == 12, 'ordinary fanout census differs')
    uncertain, lost, reopened, retry0, retry1, retired, next_cancelled, cancelled, closed = [row['outcome'] for row in spans[cursor:]]
    batch = batch_id(uncertain['batch'], 12)
    require(lost['recipient'] == 0 and lost['attempts'] == 1 and 'UnexpectedEof' in lost['last_error']
        and bytes32(lost['batch']) == batch and lost['peer']['application_result_lost'] is True
        and lost['peer']['calls'] == lost['peer']['effects'] == 1, 'lost result did not follow one committed effect')
    require(bytes32(reopened['batch']) == batch and len(reopened['peers']) == 2
        and all(peer['reopened'] is True for peer in reopened['peers']), 'original owner reopening differs')
    for index, retry in enumerate((retry0,retry1)):
        message = message_id(retry['message'], 1, 6)
        peer = retry['peer']
        require(retry['recipient'] == index and bytes32(retry['batch']) == batch
            and peer['message'] == retry['message'] and bytes32(peer['session']) == sessions[index]
            and peer['consumed'] is True and peer['calls'] == 1 and peer['effects'] == index,
            'original fanout retry duplicated/lost effect')
        require(retry['wire_bytes'] == 1133, 'original wire width differs')
        bytes32(retry['wire_sha3_256'])
        key = str(index) + '/' + message.hex()
        require(key not in bodies, 'uncertain member ID reused')
        bodies[key] = sessions[index] + message + bytes((12+n) % 251 for n in range(1024))
    require(retired == uncertain, 'recovered retirement binding differs')
    next_batch = batch_id(next_cancelled['batch'], 13)
    require(bytes32(cancelled['batch']) == next_batch and cancelled['cancelled'] is True
        and closed == {'closed':True}, 'pre-cancellation/close differs')
    require(len(value['servers']) == 2, 'recipient summary count differs')
    for index, server in enumerate(value['servers']):
        require(set(server) == {'closed','calls','effects','application_ns'} and server['closed'] is True
            and server['calls'] == (14 if index == 0 else 13) and server['effects'] == 13
            and natural(server['application_ns']), 'recipient callback/effect census differs')
    require(effects == bodies and len(value['effects']) == len(bodies) == 26, 'durable business files differ')
    public_names = set()
    for row in value['effects']:
        require(set(row) == {'recipient','file','bytes','sha3_256'} and type(row['recipient']) is int
            and row['recipient'] in (0,1), 'effect summary shape differs')
        key = str(row['recipient']) + '/' + row['file']
        require(key in bodies and key not in public_names, 'effect summary repeated/missing')
        public_names.add(key)
        data = bodies[key]
        require(row['bytes'] == len(data) and bytes32(row['sha3_256']) == hashlib.sha3_256(data).digest(),
            'effect size/digest differs')
    resources = value['resources']
    require([row['stage'] for row in resources] == ['established','epoch-zero-complete',
        'ordinary-batches-complete','recovered-and-cancelled','owners-closed'], 'memory stages differ')
    for row in resources:
        require(set(row) == {'stage','resident_bytes','physical_footprint_bytes','malloc_blocks_in_use',
            'malloc_size_in_use_bytes','malloc_max_size_in_use_bytes','malloc_size_allocated_bytes',
            'journal_database_bytes'}, 'resource counter inventory differs')
        require(all(natural(v) for k,v in row.items() if k not in {'stage','journal_database_bytes'})
            and row['resident_bytes'] > 0 and row['physical_footprint_bytes'] > 0
            and len(row['journal_database_bytes']) == 3
            and all(natural(n) and n > 0 for n in row['journal_database_bytes']), 'invalid resource counter')
    return {'ordinary_batches':12,'ordinary_member_deliveries':24,'total_batches':13,'effects':26,
        'spans':89, **accounting, 'performance_qualified':False,
        'scope':'Functional measurement validation. Whole-process observations, no controlled timing, per-client memory, 32-recipient capacity, mobile energy or frozen budget.'}

def trace_spans(stdout):
    require(re.search(rb'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;',
        stdout, re.M) is not None, 'native test result missing')
    return [parse_strict_json_bytes(line, label='emitted fanout span')
        for line in re.findall(rb'OPERATION_RESOURCE_SPAN (.+)$', stdout, re.M)]

def check_run(run, value, raw):
    require(run['completed'] is True and run['performance_qualified'] is False
        and run['release_claim_eligible'] is False and run['sources_unchanged'] is True,
        'execution incomplete or relabeled')
    require(run['result_sha256'] == sha(raw) and run['profile'] == value['profile']
        and run['layout'] == value['layout'], 'execution/result identity differs')
    require(run['source_commit'] == '5678d1019861fa1b04f3a219ba3fde7e0ddaaba8'
        and run['binary_sha256'] == 'b7ec37b3bbab8a9e7600e987461a702442c61ea31e7908e3d10c819a68e93a70',
        'installed source/binary differs')

def negative_controls(value, trace, effects, context):
    controls = []
    changes = [
        ('completion', lambda v: v.update(completed=False)),
        ('claim', lambda v: v.update(release_claim_eligible=True)),
        ('layout', lambda v: v.update(layout='own' if v['layout']=='peer' else 'peer')),
        ('workload', lambda v: v.update(ordinary_batches=11)),
        ('missing_span', lambda v: v['spans'].pop()),
        ('operation_order', lambda v: v['spans'].reverse()),
        ('negative_time', lambda v: v['spans'][7].update(elapsed_ns=-1)),
        ('cpu_boolean', lambda v: v['spans'][7].update(cpu_user_us=True)),
        ('batch_identity', lambda v: v['spans'][6]['outcome']['batch'].__setitem__(0,1)),
        ('recipient_binding', lambda v: v['spans'][7]['outcome'].update(recipient=1)),
        ('member_order', lambda v: v['spans'][7]['outcome'].update(member_order=1)),
        ('member_epoch', lambda v: v['spans'][7]['outcome']['message'].__setitem__(0,1)),
        ('payload', lambda v: v['spans'][7]['outcome'].update(payload_bytes=65)),
        ('duplicate_effect', lambda v: v['spans'][7]['outcome']['peer'].update(effects=2)),
        ('retained_network', lambda v: v['spans'][9]['outcome'].update(exchanges=1)),
        ('retained_identity', lambda v: v['spans'][9]['outcome']['message'].__setitem__(0,1)),
        ('retired_batch', lambda v: v['spans'][11]['outcome']['batch'].__setitem__(0,1)),
        ('rekey', lambda v: v['spans'][42]['outcome'].update(epoch=0)),
        ('lost_result', lambda v: v['spans'][81]['outcome']['peer'].update(application_result_lost=False)),
        ('reopen', lambda v: v['spans'][82]['outcome']['peers'][1].update(reopened=False)),
        ('retry_effect', lambda v: v['spans'][83]['outcome']['peer'].update(effects=1)),
        ('second_recipient_effect', lambda v: v['spans'][84]['outcome']['peer'].update(effects=0)),
        ('cancel', lambda v: v['spans'][87]['outcome'].update(cancelled=False)),
        ('worker_open', lambda v: v['servers'][1].update(closed=False)),
        ('effect_digest', lambda v: v['effects'][0]['sha3_256'].__setitem__(0,v['effects'][0]['sha3_256'][0]^1)),
        ('rss', lambda v: v['resources'][0].update(resident_bytes=-1)),
        ('database_inventory', lambda v: v['resources'][0]['journal_database_bytes'].pop()),
        ('witness_total', lambda v: v['witness'].update(framed_bytes=v['witness']['framed_bytes']+1)),
        ('witness_prefix', lambda v: v['spans'][7]['witness_after'].update(framed_bytes=v['spans'][7]['witness_after']['framed_bytes']+7341)),
    ]
    if value['profile'] == 'witness':
        changes += [('witness_tag', lambda v: v['witness']['rows'][0].update(request_tag=255)),
            ('boundary', lambda v: v['spans'][7]['witness_after'].update(requests=0))]
    for name, change in changes:
        altered = copy.deepcopy(value)
        change(altered)
        try:
            validate(altered, altered['spans'], effects, context)
        except ValueError as error:
            controls.append({'name':name,'rejection':str(error)})
        else:
            raise ValueError('altered measurement accepted: '+name)
    variants = [
        ('durable_business_bytes', value, trace, {**effects,next(iter(effects)):effects[next(iter(effects))]+b'changed'}, context),
        ('stdout_result_mismatch', value, trace[:-1], effects, context),
        ('public_owner_context', value, trace, effects,
            {'owner_accounts':context['owner_accounts'][:1]+[[0]*32]+context['owner_accounts'][2:]})
    ]
    for name, changed, changed_trace, changed_effects, changed_context in variants:
        try:
            validate(changed, changed_trace, changed_effects, changed_context)
        except ValueError as error:
            controls.append({'name':name,'rejection':str(error)})
        else:
            raise ValueError('altered durable evidence accepted: '+name)
    return controls

def main():
    root, label = Path(sys.argv[1]), sys.argv[2]
    require(re.fullmatch(r'validation-(?:local|witness)-(?:peer|own)-[0-9]{2}',label) is not None, 'unknown cohort')
    directory = root / label
    run = load(directory / 'RUN.json')
    raw = (directory / 'RESULT.json').read_bytes()
    value = parse_strict_json_bytes(raw, label='fanout result')
    check_run(run,value,raw)
    require(load(directory / 'runtime.json')['returncode'] == 0
        and (directory / 'runtime.stderr').read_bytes() == b'', 'runtime diagnostics/failure')
    stdout = (directory / 'runtime.stdout').read_bytes()
    require(('FANOUT_RESOURCE_COMPLETE profile='+value['profile']+' layout='+value['layout']+' ordinary=12 effects=26').encode()
        in stdout, 'native completion marker differs')
    trace = trace_spans(stdout)
    private = Path(run['private_runtime']) / 'installation-account'
    owners = [private / name for name in ('initiator','responder','responder-2')]
    context = {'owner_accounts':[list((owner/'local-account').read_bytes()) for owner in owners]}
    effects = {}
    for index, owner in enumerate(owners[1:]):
        folder = owner / 'measured-effects'
        require(folder.is_dir() and not folder.is_symlink(), 'durable business directory missing')
        for path in folder.iterdir():
            require(path.is_file() and not path.is_symlink()
                and re.fullmatch('[0-9a-f]{64}',path.name) is not None, 'nonregular business file')
            effects[str(index)+'/'+path.name] = path.read_bytes()
    actual = validate(value,trace,effects,context)
    controls = negative_controls(value,trace,effects,context)
    output = {'source_commit':run['source_commit'],'binary_sha256':run['binary_sha256'],
        'result_sha256':sha(raw),'profile':value['profile'],'layout':value['layout'],
        'validation':actual,'altered_observation_controls':controls,
        'ciphertext_scope':'The native workload compares original/reopened ciphertext bytes. Public readback validates reported digests and effect bytes; ciphertext itself is not retained here.'}
    public = directory / 'public-effects'
    public.mkdir()
    for name,data in effects.items():
        target = public / name
        target.parent.mkdir(exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
    with (directory/'PUBLIC_CONTEXT.json').open('x') as stream:
        stream.write(json.dumps(context,indent=2,sort_keys=True)+'\n')
    with (directory/'READBACK.json').open('x') as stream:
        stream.write(json.dumps(output,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'profile':value['profile'],'layout':value['layout'],'spans':89,'effects':26,
        'negative_controls':len(controls),'witness_exchanges':actual['witness_exchanges'],
        'outside_measured_spans':actual['outside_measured_spans'],'performance_qualified':False}))

def archive_main():
    archive_path, manifest_path, output_path = map(Path,sys.argv[2:])
    manifest = load(manifest_path)
    results = {}
    with zipfile.ZipFile(archive_path) as archive:
        require(len(archive.namelist()) == len(manifest) and set(archive.namelist()) == set(manifest), 'capsule inventory differs')
        for name,expected in manifest.items():
            data = archive.read(name)
            require(len(data) == expected['bytes'] and sha(data) == expected['sha256'], 'capsule member differs: '+name)
        require(archive.read('controller/readback-fanout.py') == Path(__file__).read_bytes(), 'captured reader differs')
        for profile in ('local','witness'):
            for layout in ('peer','own'):
                label = 'validation-'+profile+'-'+layout+'-01'
                prefix = 'cohorts/'+label+'/'
                raw = archive.read(prefix+'RESULT.json')
                value = parse_strict_json_bytes(raw,label='archived fanout result')
                run = parse_strict_json_bytes(archive.read(prefix+'RUN.json'),label='archived fanout execution')
                check_run(run,value,raw)
                command = parse_strict_json_bytes(archive.read(prefix+'runtime.json'),label='archived runtime receipt')
                require(command['returncode'] == 0 and archive.read(prefix+'runtime.stderr') == b'', 'archived runtime failed')
                trace = trace_spans(archive.read(prefix+'runtime.stdout'))
                context = parse_strict_json_bytes(archive.read(prefix+'PUBLIC_CONTEXT.json'),label='archived public owners')
                effect_prefix = prefix+'public-effects/'
                effects = {name.removeprefix(effect_prefix):archive.read(name) for name in manifest if name.startswith(effect_prefix)}
                actual = validate(value,trace,effects,context)
                original = parse_strict_json_bytes(archive.read(prefix+'READBACK.json'),label='archived first readback')
                require(actual == original['validation'], 'archive-only result differs')
                controls = negative_controls(value,trace,effects,context)
                require(controls == original['altered_observation_controls'], 'archive altered-input controls differ')
                results[label] = actual
    record = {'archive_sha256':sha(archive_path.read_bytes()),'members_verified':len(manifest),
        'public_business_files_verified':104,'cohorts':results,'private_runtime_accessed':False,
        'performance_qualified':False,'release_claim_eligible':False}
    with output_path.open('x') as stream:
        stream.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'archive_members':len(manifest),'cohorts':4,'business_files':104,'private_runtime_accessed':False}))

if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--archive':
        archive_main()
    elif len(sys.argv) == 3:
        main()
    else:
        raise SystemExit('usage: readback-fanout.py ROOT LABEL | --archive ZIP FILES OUTPUT')
