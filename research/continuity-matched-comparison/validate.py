#!/usr/bin/env python3
"""Fail-closed native trace validation and common workload accounting."""
from __future__ import annotations
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import re
import sys

from schedule import (CAPTURE_BEFORE, FRAME_CAP, MESSAGES, SCENARIOS, Emission,
                      canonical, manifest, require, schedule, sender, verify_trace)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def decode(data: str):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def integer(value, low=0, high=(1 << 64) - 1):
    require(type(value) is int and low <= value <= high, 'invalid integer')
    return value


def pair(value):
    require(type(value) is list and len(value) == 2, 'invalid endpoint pair')
    return [integer(x) for x in value]


def wire(value: str) -> bytes:
    require(type(value) is str and re.fullmatch(r'(?:[0-9a-f]{2}){1,8192}', value) is not None,
            'invalid public frame hex')
    return bytes.fromhex(value)


def read_rows(path: Path) -> list[dict]:
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 256*1024*1024,
            'invalid trace file')
    data = path.read_text()
    require(data.endswith('\n'), 'incomplete JSONL tail')
    rows = [decode(line) for line in data.splitlines()]
    require(all(type(row) is dict for row in rows), 'trace row type')
    return rows


def exposure(commits: dict[int, dict], delivered: set[int]) -> list[dict]:
    future = sorted(request for request, row in commits.items() if row['opportunity'] >= CAPTURE_BEFORE)
    result = []
    for owner in (0, 1):
        known = [request for request in future if commits[request]['known'][owner]]
        unknown = sorted(set(future) - set(known))
        result.append({'owner': owner, 'capture_before_opportunity': CAPTURE_BEFORE,
                       'admitted_after_capture': len(future), 'derived_requests': known,
                       'not_derived_requests': unknown,
                       'derived_delivered_requests': sorted(set(known) & delivered),
                       'derived_fraction_of_admitted': len(known) / len(future) if future else None})
    return result


def verify_native(path: Path, profile: str, scenario: str) -> dict:
    rows = read_rows(path)
    config, completed = rows[0], rows[-1]
    expected = {'event': 'configuration', 'schema': 1, 'scenario': scenario, 'profile': profile,
                'opportunities': MESSAGES, 'frame_cap': FRAME_CAP,
                'capture_before_opportunity': CAPTURE_BEFORE, 'payload_bytes': 32}
    require({key: config.get(key) for key in expected} == expected, 'native configuration differs')
    start_revision = pair(config['initial_revisions'])
    require(completed.get('event') == 'completed' and completed.get('status') == 'passed', 'native run incomplete')
    pending = [deque(), deque()]
    offered, admitted = [0, 0], [0, 0]
    commits, emitted, by_logical = {}, {}, {}
    emissions, deliveries, delivered = [], [], set()
    counts, byte_counts, retries, blocked = Counter(), Counter(), Counter(), Counter()
    current, last_checkpoint = -1, -1
    capture = None
    previous_revision, previous_sync = start_revision, [0, 0]
    final_checkpoint = None
    last_indices = {}
    for row in rows[1:-1]:
        event = row.get('event')
        if event == 'capture':
            require(capture is None and current == 0 and last_checkpoint == 0, 'capture micro-order differs')
            require(type(row['before_opportunity']) is int and row['before_opportunity'] == 1,
                    'capture coordinate differs')
            require(row['pending_entropy'] == [False, False] and
                    all(type(x) is bool for x in row['pending_entropy']), 'capture pending entropy differs')
            require(all(x > 0 for x in pair(row['record_bytes'])), 'empty captured record')
            capture = row
        elif event == 'opportunity':
            i = integer(row['opportunity'], 0, MESSAGES - 1)
            require(i == current + 1 and last_checkpoint == current, 'opportunity/checkpoint order')
            require(i < 1 or capture is not None, 'missing before-slot capture')
            owner = integer(row['owner'], 0, 1)
            require(owner == sender(scenario, i) and integer(row['request']) == i, 'offered request differs')
            pending[owner].append(i)
            offered[owner] += 1
            current = i
        elif event in ('commit', 'admission_blocked'):
            i, owner, request = integer(row['opportunity']), integer(row['owner'], 0, 1), integer(row['request'])
            require(i == current and last_checkpoint < i and i not in emitted, 'local event outside send phase')
            require(owner == sender(scenario, i) and pending[owner] and pending[owner][0] == request,
                    'admission changed FIFO demand')
            if event == 'admission_blocked':
                require(row['reason'] in ('Suspended', 'RekeyRequired'), 'unknown admission outcome')
                blocked[row['reason']] += 1
                continue
            require(request not in commits, 'second commit for application request')
            require(type(row['snapshot_active']) is bool and row['snapshot_active'] == (i >= 1), 'capture activation')
            require(type(row['known']) is list and len(row['known']) == 2 and
                    all(type(x) is bool for x in row['known']), 'prediction field')
            epoch, index = integer(row['epoch']), integer(row['index'])
            require(index < int(profile.rsplit('-', 1)[1]), 'native epoch exceeds selected send budget')
            identity = owner, epoch
            require(index == last_indices.get(identity, -1) + 1, 'application chain skips or reuses key index')
            last_indices[identity] = index
            require(row['known'] == [i >= 1 and epoch == 0] * 2, 'native capture-chain prediction differs')
            pending[owner].popleft()
            commits[request] = row
            admitted[owner] += 1
        elif event == 'emit':
            i, owner = integer(row['opportunity'], 0, MESSAGES - 1), integer(row['owner'], 0, 1)
            require(i == current and last_checkpoint < i and i not in emitted, 'emission order or count')
            kind, logical, encoded = row['kind'], row['logical'], wire(row['wire'])
            require(kind in ('application', 'retry', 'control', 'ack'), 'emission kind')
            require(type(logical) is str and len(logical) <= 2048, 'logical identity length')
            identity = owner, logical
            repeated = identity in by_logical
            if repeated:
                require(by_logical[identity]['wire'] == row['wire'], 'exact retry mutation')
                retries[kind if kind != 'retry' else 'application'] += 1
            if kind in ('application', 'retry'):
                require(len(encoded) == 141 and encoded[:8] == b'QPCMSG03' and
                        encoded[40] == owner + 1 and int.from_bytes(encoded[89:93], 'big') == 32,
                        'native application wire shape')
                match = re.fullmatch(r'application-(0|1)-(\d+)', logical)
                require(match is not None and int(match[1]) == owner, 'data logical identity')
                request = int(match[2])
                require(request in commits and commits[request]['owner'] == owner, 'data without commit')
                require(int.from_bytes(encoded[41:49], 'big') == commits[request]['epoch'] and
                        int.from_bytes(encoded[49:57], 'big') == commits[request]['index'],
                        'native public header and commit differ')
                require(repeated == (kind == 'retry'), 'retry/first-emission label')
                if kind == 'application':
                    require(commits[request]['opportunity'] == i, 'new application commit/emit split')
            by_logical[identity] = row
            emissions.append(Emission(i, owner, logical, encoded))
            emitted[i] = row
            counts[kind] += 1
            byte_counts[kind] += len(encoded)
        elif event == 'receive':
            at, source = integer(row['opportunity'], 0, MESSAGES), integer(row['source_opportunity'], 0, MESSAGES - 1)
            require(at == current or (at == MESSAGES and current == MESSAGES - 1), 'receive coordinate')
            require((at == MESSAGES and last_checkpoint == MESSAGES - 1) or last_checkpoint < at,
                    'receive after checkpoint')
            require(source in emitted, 'receive before source transmission')
            original = emitted[source]
            require(integer(row['owner'], 0, 1) == 1 - original['owner'] and
                    all(row[k] == original[k] for k in ('kind', 'logical', 'wire')), 'receive identity differs')
            kind, outcome = row['kind'], row['outcome']
            allowed = {'control': ('accepted', 'retired', 'suspended'), 'ack': ('accepted', 'retired'),
                       'application': ('delivered', 'duplicate_consumed', 'suspended'),
                       'retry': ('delivered', 'duplicate_consumed', 'suspended')}
            require(outcome in allowed[kind], 'receive outcome')
            if kind in ('application', 'retry'):
                request = int(row['logical'].rsplit('-', 1)[1])
                if outcome == 'delivered':
                    require(request not in delivered, 'second logical application delivery')
                    delivered.add(request)
                elif outcome == 'duplicate_consumed':
                    require(request in delivered, 'duplicate before first logical delivery')
            deliveries.append((at, source, wire(row['wire'])))
        elif event == 'checkpoint':
            at = integer(row['opportunity'], 0, MESSAGES)
            require(at == last_checkpoint + 1 and (at == current or at == MESSAGES == current + 1),
                    'checkpoint order')
            revisions, sync = pair(row['revisions']), pair(row['sync_data'])
            require(all(a >= b for a, b in zip(revisions, previous_revision)) and
                    all(a >= b for a, b in zip(sync, previous_sync)), 'persistence counter regressed')
            pair(row['confirmed_epochs']); pair(row['sending_epochs'])
            previous_revision, previous_sync, last_checkpoint = revisions, sync, at
            final_checkpoint = row
        else:
            raise ValueError(f'unknown native event: {event}')
    require(capture is not None and current == MESSAGES - 1 and last_checkpoint == MESSAGES, 'native inventory incomplete')
    require(pair(completed['offered']) == offered and pair(completed['uncommitted']) == [len(q) for q in pending],
            'native request accounting')
    by_receiver = [sum(commits[r]['owner'] == 1 - owner for r in delivered) for owner in (0, 1)]
    require(pair(completed['delivered']) == by_receiver, 'native delivery accounting')
    require(integer(completed['distinct_new_keys']) == len(commits) == counts['application'], 'native key/commit inventory')
    require(sum(offered) == MESSAGES and sum(admitted) + sum(len(q) for q in pending) == MESSAGES, 'native demand partition')
    accounting = verify_trace(scenario, MESSAGES, emissions, deliveries)
    if scenario == 'one_way':
        require(final_checkpoint['confirmed_epochs'] == [0, 0] and final_checkpoint['sending_epochs'][0] == 0,
                'one-way transport claimed a completed rekey')
    return {'profile': profile, 'scenario': scenario, 'capture': capture,
            'transport': accounting, 'frame_counts': dict(counts), 'frame_bytes': dict(byte_counts),
            'exact_frame_retransmissions': dict(retries), 'admission_blocked_attempts': dict(blocked),
            'application': {'offered': offered, 'committed': admitted,
                            'delivered_by_sender': [by_receiver[1], by_receiver[0]],
                            'uncommitted': [len(q) for q in pending]},
            'admission_boundary': 'DeviceJournal committed application ciphertext',
            'persistence': {'durable_image_revision_increments': [a-b for a,b in zip(previous_revision,start_revision)],
                            'physical_sync_data': previous_sync, 'physical_write_bytes': None,
                            'component_state_returns': None},
            'final_confirmed_epochs': final_checkpoint['confirmed_epochs'],
            'exposure': exposure(commits, delivered),
            'authentication_authority': 'separately owned ML-DSA identity signer; session record disclosed',
            'trace_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def payload(request: int, owner: int) -> bytes:
    return request.to_bytes(8, 'big') + bytes([owner]) + bytes([0x51]) * 23


def verify_reference(directory: Path, profile: str, scenario: str, reference, whole) -> dict:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    name = 'ping_pong' if scenario == 'alternating' else scenario
    path = directory / f'{name}.jsonl'
    rows = read_rows(path)
    sends = {row['sequence']: row for row in rows if row['event'] == 'send'}
    require(set(sends) == set(range(MESSAGES)), 'reference send inventory')
    feed = directory / f'.private-{name}.keys'
    require(feed.is_file() and not feed.is_symlink() and feed.stat().st_mode & 0o077 == 0,
            'private observer key-feed permissions')
    lines = feed.read_text().splitlines()
    require(len(lines) == MESSAGES, 'private observer key-feed count')
    frames, components, keys = {}, {}, set()
    component_control_bytes = 0
    piggyback_retransmissions = 0
    previous_controls = set()
    envelope_path = directory / f'{name}.envelopes.jsonl'
    with envelope_path.open('xb') as output:
        for i, line in enumerate(lines):
            parts = line.split()
            require(len(parts) == 3 and parts[0] == str(i) and parts[1] == str(sender(scenario, i)) and
                    re.fullmatch(r'[0-9a-f]{64}', parts[2]) is not None, 'private observer record differs')
            key = bytes.fromhex(parts[2])
            require(key not in keys, 'reference measurement key reuse')
            keys.add(key)
            component = wire(sends[i]['wire'])
            components[i] = component
            prefix = len(component).to_bytes(4, 'big') + component
            ad = b'matched-reference-envelope-v1' + prefix
            clear = payload(i, sender(scenario, i))
            encrypted = ChaCha20Poly1305(key).encrypt(bytes(12), clear, ad)
            require(ChaCha20Poly1305(key).decrypt(bytes(12), encrypted, ad) == clear, 'outer AEAD roundtrip')
            altered = bytes([key[0] ^ 1]) + key[1:]
            rejected = False
            try:
                ChaCha20Poly1305(altered).decrypt(bytes(12), encrypted, ad)
            except InvalidTag:
                rejected = True
            require(rejected, 'outer AEAD wrong-key control accepted')
            frame = prefix + encrypted
            require(len(frame) <= FRAME_CAP, 'reference complete envelope exceeds common cap')
            frames[i] = frame
            if profile.startswith('spqr-'):
                chunk = int(profile.split('-')[1])
                epoch, _, kind, chunk_index = reference.wire_fields(component, chunk_bytes=chunk)
                if chunk_index is not None:
                    body = component[-chunk:]
                    component_control_bytes += chunk
                    identity = sender(scenario,i), epoch, kind, chunk_index, body
                    piggyback_retransmissions += identity in previous_controls
                    previous_controls.add(identity)
            else:
                decoded = whole.wire(component)
                component_control_bytes += len(decoded['body'])
                if decoded['kind']:
                    identity = sender(scenario,i), decoded['epoch'], decoded['kind'], decoded['body']
                    piggyback_retransmissions += identity in previous_controls
                    previous_controls.add(identity)
            output.write(canonical({'event':'envelope', 'opportunity':i, 'owner':sender(scenario,i),
                                    'wire':frame.hex(), 'wrong_key_rejected':True}))
    # The feed is not included in the public report or any hash inventory.
    feed.unlink()
    actual = iter(rows[1:-1])
    emissions, deliveries, delivered = [], [], set()
    for slot in schedule(scenario)[:-1]:
        i = slot['opportunity']
        row = next(actual)
        require(row['event'] == 'send' and row['sequence'] == i and row['sender'] == sender(scenario,i), 'reference slot emission')
        emissions.append(Emission(i, row['sender'], f'application-{row["sender"]}-{i}', frames[i]))
        if slot['drop']:
            row = next(actual)
            require(row['event'] == 'drop' and row['sequence'] == i, 'reference common drop')
        for source in slot['deliveries']:
            row = next(actual)
            require(row['event'] == 'receive' and row['sequence'] == source and row['key_matches'] is True,
                    'reference common delivery')
            deliveries.append((i, source, frames[source])); delivered.add(source)
        if slot['duplicate_last']:
            row = next(actual)
            require(row['event'] == 'duplicate' and row['sequence'] == i, 'reference duplicate')
            deliveries.append((i, i, frames[i]))
    for source in schedule(scenario)[-1]['terminal_delivery_only']:
        row = next(actual)
        require(row['event'] == 'receive' and row['sequence'] == source, 'reference terminal delivery')
        deliveries.append((MESSAGES, source, frames[source])); delivered.add(source)
    require(next(actual, None) is None, 'extra reference action outside slots')
    accounting = verify_trace(scenario, MESSAGES, emissions, deliveries)
    compromise = decode((directory / f'{name}.compromise.json').read_text())
    cases = [case for case in compromise['cases'] if case['cut_before_send'] == CAPTURE_BEFORE]
    require(sorted(case['owner'] for case in cases) == [0, 1], 'reference common capture inventory')
    known = {case['owner']: set(case['predicted_sequences']) for case in cases}
    commits = {i: {'opportunity':i, 'owner':sender(scenario,i), 'known':[i in known[0], i in known[1]]} for i in range(MESSAGES)}
    offered = [sum(sender(scenario,i) == owner for i in range(MESSAGES)) for owner in (0,1)]
    returned = [row for row in rows if row['event'] in ('send','receive')]
    return {'profile':profile, 'scenario':scenario, 'transport':accounting,
            'frame_counts':{'application_with_piggyback':MESSAGES},
            'component_bytes':sum(map(len, components.values())), 'control_body_bytes':component_control_bytes,
            'outer_envelope_bytes':{'length_prefix':4*MESSAGES,'payload':32*MESSAGES,'tag':16*MESSAGES},
            'piggyback_control_body_retransmissions':piggyback_retransmissions,
            'exact_frame_retransmissions':{},
            'application':{'offered':offered,'committed':offered,'uncommitted':[0,0],
                           'delivered_by_sender':[sum(sender(scenario,i)==owner for i in delivered) for owner in (0,1)]},
            'admission_boundary':'component serialized state returned; separate honest transcript AEAD audit',
            'persistence':{'component_state_returns':len(returned),
                           'serialized_bytes_returned':sum(row['state']['bytes'] for row in returned),
                           'durable_image_revision_increments':None,'physical_sync_data':None,'physical_write_bytes':None},
            'capture_cases':cases, 'exposure':exposure(commits,delivered),
            'authentication_authority':'session shared-secret component MAC; no separate identity signer in this harness',
            'trace_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'envelope_sha256':hashlib.sha256(envelope_path.read_bytes()).hexdigest()}


def validate_all(output: Path) -> dict:
    # Reuse the independently maintained full public-wire/predictor validators
    # from the explicit archived base, not from an unpinned installed module.
    sys.path.insert(0, str(output / 'source'))
    from artifact import spqr_reference as reference
    from artifact import whole_kem_reference as whole
    evidence = output / 'evidence'
    checks = {'spqr-32':reference.verify(evidence/'spqr-32'),
              'spqr-64':reference.verify(evidence/'spqr-64', chunk_bytes=64),
              'whole-kem':whole.verify(evidence/'whole-kem')}
    (evidence/'reference-validation.json').write_bytes(canonical(checks))
    rows = []
    expected_native = {f'continuity-{budget}-{scenario}.jsonl' for budget in (32,64) for scenario in SCENARIOS}
    require({p.name for p in (evidence/'native').iterdir()} == expected_native, 'native profile/scenario inventory')
    for budget in (32,64):
        for scenario in SCENARIOS:
            rows.append(verify_native(evidence/'native'/f'continuity-{budget}-{scenario}.jsonl',f'continuity-{budget}',scenario))
    for profile, directory in [('spqr-32',evidence/'spqr-32'),('spqr-64',evidence/'spqr-64'),
                               *[(f'whole-kem-{period}',evidence/'whole-kem'/f'period-{period}') for period in (1,32,64)]]:
        for scenario in SCENARIOS:
            rows.append(verify_reference(directory,profile,scenario,reference,whole))
    require(len(rows) == 49, 'full comparison inventory')
    return {'schema':1,'status':'passed','schedule':manifest(),'rows':rows,
            'metric':'captured-state message-key reconstruction; native actual plaintext recovery; reference honest-transcript AEAD audit',
            'capture':'complete current session state before opportunity 1, passive full public emissions, no future private state or RNG',
            'reference_physical_persistence':'not executed; physical columns are null',
            'timing':'raw component CPU samples retained in source reports; no cross-service speed ranking'}
