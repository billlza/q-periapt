#!/usr/bin/env python3
"""Differential, expected-result and structural-cost checks of indexed closure.

The archived scan/path checker remains the independent finite-model oracle.
Large graph controls exercise only the indexed evaluator: they never construct
or enumerate its path table. Operation counts are reproducible across machines.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import sys
from unittest.mock import patch


BASE = Path(__file__).resolve().parent


def load_sibling(module_name: str, filename: str):
    """Load an exact local source while preserving the bootstrap's stdlib order."""
    spec = importlib.util.spec_from_file_location(module_name, BASE / filename)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load exposure validation source: ' + filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


reference = load_sibling('_q_periapt_guarded_reference_model', 'check_exposure.py')
indexed = load_sibling('_q_periapt_guarded_indexed_check', 'indexed_exposure.py')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def converted(model: reference.Model) -> indexed.IndexedModel:
    return indexed.IndexedModel(list(model.records.values()), model.derives)


def check_work_bound(state: indexed.IndexedClosure) -> None:
    model, work = state.model, state.work
    payloads = sum(len(r.children) + len(r.origins) for r in model.records.values())
    require(work.key_visits <= len(model.keys), 'a key was processed twice')
    require(work.record_visits <= len(model.records), 'a record was processed twice')
    require(work.derivation_visits <= len(model.derives), 'a derivation edge was processed twice')
    require(work.guard_visits <= len(model.records), 'a guard incidence was processed twice')
    require(work.payload_visits <= payloads, 'a payload incidence was processed twice')
    require(work.records_opened <= len(model.records), 'a record was opened twice')
    require(work.sources_added <= len(model.origins), 'a source was emitted twice')


def exhaustive_checks(models: dict[str, reference.Model]) -> dict:
    counts = {}
    for name, old in models.items():
        new = converted(old)
        count = 0
        for acquired in reference.subsets(old.records):
            for disclosed in reference.subsets(old.keys):
                for direct in reference.subsets(old.origins):
                    expected = old.forward(acquired, disclosed, direct)
                    observed = new.forward(acquired, disclosed, direct)
                    normalized, _ = old.normalized(acquired, disclosed, direct)
                    require(observed == expected, f'{name}: complete closure mismatch')
                    require(observed[0] == normalized, f'{name}: guarded normalization mismatch')
                    require(new._reference_model is None, f'{name}: forward built a path table')
                    count += 1
        counts[name] = count
    return {'instances': counts, 'total_assignments': sum(counts.values()),
            'compared': ['all three closure sorts against retained scan',
                         'exposed source set against retained guarded paths']}


def check_history(old: reference.Model, events: list[tuple[str, str]]) -> int:
    old_history = reference.History(old)
    new_history = indexed.IndexedHistory(converted(old))
    emitted: set[str] = set()
    for event in events:
        old_sources = old_history.step(*event)
        delta = new_history.step(*event)
        require(not (emitted & delta), 'a history source was emitted twice')
        emitted.update(delta)
        require(emitted == old_sources, 'prefix source mismatch')
        expected = old.forward(old_history.acquired, old_history.keys, old_history.direct)
        require(new_history.state.snapshot() == expected, 'prefix full closure mismatch')
        require(new_history.live == old_history.live, 'local record availability mismatch')
        check_work_bound(new_history.state)
    require(new_history.event_count == len(events), 'history event count mismatch')
    return len(events)


def history_checks(models: dict[str, reference.Model]) -> dict:
    directed, old_permutations = reference.histories(models)
    prefix_count = 0
    for case in directed:
        events = [(event['kind'], event['item']) for event in case['events']]
        prefix_count += check_history(models[case['model']], events)
    events = [('acquire', 'image'), ('acquire', 'copy'), ('disclose_key', 'journal'),
              ('disclose_key', 'journal-new'), ('disclose_key', 'wrap'), ('delete_local', 'image')]
    permutations = 0
    for order in itertools.permutations(events):
        if order.index(('delete_local', 'image')) < order.index(('acquire', 'image')):
            continue
        prefix_count += check_history(models['independent_wrapping_keys'], list(order))
        permutations += 1
    require(permutations == old_permutations == 360, 'legal history inventory changed')
    duplicate_events = [('acquire', 'image'), ('acquire', 'image'), ('disclose_key', 'journal'),
                        ('disclose_key', 'journal'), ('disclose_key', 'wrap'),
                        ('disclose_key', 'wrap'), ('disclose_origin', 'reservation-0'),
                        ('disclose_origin', 'reservation-0'), ('delete_local', 'image')]
    prefix_count += check_history(models['independent_wrapping_keys'], duplicate_events)
    return {'directed_histories': len(directed), 'legal_event_permutations': permutations,
            'duplicate_event_histories': 1, 'prefix_comparisons': prefix_count}


def expected_checks() -> list[dict]:
    Record, Model = reference.Record, indexed.IndexedModel
    cases = []

    def expect(name, model, acquired, keys, expected, direct=None):
        observed = model.forward(set(acquired), set(keys), set(direct or ()))
        require(observed == tuple(set(x) for x in expected), name)
        cases.append({'case': name, 'status': 'passed'})

    expect('empty_graph', Model([]), set(), set(), (set(), set(), set()))
    no_records = Model([], (('a', 'b'), ('b', 'a')))
    expect('key_cycle_without_records_or_seed', no_records, set(), set(), (set(), set(), set()))
    expect('key_cycle_without_records_with_seed', no_records, set(), {'a'}, (set(), set(), {'a', 'b'}))
    self_loop = Model([Record('token', 'a', origins=('o',))], (('a', 'a'),))
    expect('unseeded_key_self_loop', self_loop, {'token'}, set(), (set(), {'token'}, set()))
    expect('seeded_key_self_loop', self_loop, {'token'}, {'a'}, ({'o'}, {'token'}, {'a'}))
    expect('source_does_not_backderive_keys', self_loop, set(), set(), ({'o'}, set(), set()), {'o'})
    same_name = Model([Record('x', 'x', origins=('x',))])
    expect('same_name_keeps_record_key_source_sorts_separate', same_name, set(), set(),
           ({'x'}, set(), set()), {'x'})
    expect('same_name_acquisition_still_needs_key', same_name, {'x'}, set(),
           (set(), {'x'}, set()))
    reversed_edges = Model([Record('token', 'c', origins=('o',))], (('b', 'c'), ('a', 'b')))
    expect('reverse_ordered_key_edges', reversed_edges, {'token'}, {'a'}, ({'o'}, {'token'}, {'a', 'b', 'c'}))
    disconnected = Model([Record('token', 'a', origins=('o',))], (('b', 'c'),))
    expect('unrelated_keys_do_not_open_record', disconnected, {'token'}, {'b'}, (set(), {'token'}, {'b', 'c'}))
    diamond = Model([Record('leaf', 'leaf-key', origins=('o',)),
                     Record('left', 'left-key', ('leaf',)),
                     Record('right', 'right-key', ('leaf',)),
                     Record('outer', 'outer-key', ('left', 'right'))])
    expect('one_complete_diamond_route_suffices', diamond, {'outer'},
           {'outer-key', 'left-key', 'leaf-key'},
           ({'o'}, {'outer', 'left', 'right', 'leaf'}, {'outer-key', 'left-key', 'leaf-key'}))
    expect('shared_leaf_keeps_intermediate_guard', diamond, {'outer'}, {'outer-key', 'leaf-key'},
           (set(), {'outer', 'left', 'right'}, {'outer-key', 'leaf-key'}))
    two_routes = Model([Record('left-token', 'b', origins=('o',)),
                        Record('left-image', 'a', ('left-token',)),
                        Record('right-token', 'd', origins=('o',)),
                        Record('right-image', 'c', ('right-token',))])
    expect('partial_routes_cannot_be_spliced', two_routes, {'left-image', 'right-image'}, {'a', 'd'},
           (set(), {'left-image', 'right-image', 'left-token'}, {'a', 'd'}))
    duplicate_edges = Model([Record('leaf', 'k', origins=('o', 'o')),
                             Record('outer', 'k', ('leaf', 'leaf'))], (('k', 'k'), ('k', 'k')))
    expect('duplicate_edges_and_payloads_preserve_sets', duplicate_edges, {'outer'}, {'k'},
           ({'o'}, {'outer', 'leaf'}, {'k'}))

    for order in [('acquire', 'disclose_key'), ('disclose_key', 'acquire')]:
        state = Model([Record('token', 'k', origins=('o',))]).new_state()
        result = []
        for kind in order:
            result.append(getattr(state, kind)('token' if kind == 'acquire' else 'k'))
        require(result == [frozenset(), frozenset({'o'})], f'arrival order {order}')
        require(state.is_exposed('o'), 'membership query missed exposed source')
        snapshot = state.snapshot()
        snapshot[0].clear()
        require(state.is_exposed('o'), 'snapshot aliased internal state')
        before = state.work.indexed_visits
        require(state.acquire('token') == state.disclose_key('k') == state.disclose_origin('o') == frozenset(),
                'repeated event emitted a source')
        require(state.work.indexed_visits == before, 'duplicate event rescanned graph')
        check_work_bound(state)
        cases.append({'case': 'then'.join(order), 'status': 'passed'})

    old = reference.Model(list(diamond.records.values()), diamond.derives)
    require(diamond._reference_model is None, 'reference was instantiated before an oracle request')
    require(diamond.routes == old.routes, 'explicit route API differs from retained oracle')
    require(diamond.normalized({'outer'}, set(diamond.keys)) == old.normalized({'outer'}, set(old.keys)),
            'explicit normalization API differs from retained oracle')
    cases.append({'case': 'explicit_lazy_route_and_normalized_api', 'status': 'passed'})
    return cases


def invalid_checks() -> list[str]:
    Record, Model = reference.Record, indexed.IndexedModel
    good = Model([Record('token', 'k', origins=('o',))])
    cases = [
        ('duplicate_identity', lambda: Model([Record('x', 'k'), Record('x', 'k')])),
        ('unknown_child', lambda: Model([Record('x', 'k', ('missing',))])),
        ('empty_record_identity', lambda: Model([Record('', 'k')])),
        ('empty_key_identity', lambda: Model([Record('x', '')])),
        ('record_self_cycle', lambda: Model([Record('x', 'k', ('x',))])),
        ('two_record_cycle', lambda: Model([Record('x', 'k', ('y',)), Record('y', 'k', ('x',))])),
        ('unknown_acquisition', lambda: good.forward({'missing'}, set())),
        ('unknown_key', lambda: good.forward(set(), {'missing'})),
        ('unknown_direct_source', lambda: good.forward(set(), set(), {'missing'})),
        ('unknown_membership_query', lambda: good.new_state().is_exposed('missing')),
        ('unknown_history_event', lambda: indexed.IndexedHistory(good).step('missing', 'token')),
    ]
    rejected = []
    for name, operation in cases:
        try:
            operation()
        except ValueError:
            rejected.append(name)
        else:
            raise AssertionError('invalid input admitted: ' + name)
    history = indexed.IndexedHistory(good)
    history.step('delete_local', 'token')
    for kind in ['acquire', 'delete_local']:
        try:
            history.step(kind, 'token')
        except ValueError:
            rejected.append(kind + '_after_local_deletion')
        else:
            raise AssertionError('unavailable local record admitted: ' + kind)
    require(history.event_count == 1, 'invalid history event changed its event count')
    state = good.new_state()
    for method in ['acquire', 'disclose_key', 'disclose_origin']:
        before = asdict(state.work)
        try:
            getattr(state, method)('missing')
        except ValueError:
            pass
        else:
            raise AssertionError('invalid state input admitted: ' + method)
        require(asdict(state.work) == before and state.snapshot() == (set(), set(), set()),
                'invalid state input mutated closure')
    return rejected


def reverse_chain_scan_visits(size: int) -> int:
    """Instrument the retained Model.forward itself on a reversed key chain."""
    edges = tuple((f'k{i}', f'k{i+1}') for i in reversed(range(size)))
    # This reference graph has one record and exactly one containment path.
    old = reference.Model([reference.Record('token', f'k{size}', origins=('o',))], edges)

    class CountedEdges:
        def __init__(self):
            self.visits = 0

        def __iter__(self):
            for edge in edges:
                self.visits += 1
                yield edge

    counted = CountedEdges()
    old.derives = counted
    observed = old.forward({'token'}, {'k0'})
    expected = ({'o'}, {'token'}, {f'k{i}' for i in range(size + 1)})
    require(observed == expected, 'instrumented retained scan closure mismatch')
    return counted.visits


def scale_checks() -> dict:
    Record, Model = reference.Record, indexed.IndexedModel
    reverse_chains, layered = [], []
    # A failing reference constructor detects any accidental path enumeration.
    with patch.object(indexed, 'ReferenceModel', side_effect=AssertionError('path oracle constructed')):
        for size in [32, 128, 512]:
            model = Model([Record('token', f'k{size}', origins=('o',))],
                          tuple((f'k{i}', f'k{i+1}') for i in reversed(range(size))))
            state = model.new_state()
            state.acquire('token')
            require(state.disclose_key('k0') == frozenset({'o'}), 'reverse-chain source missing')
            check_work_bound(state)
            scan_visits = reverse_chain_scan_visits(size)
            require(scan_visits == size * (size + 1), 'scan control count changed')
            reverse_chains.append({'key_edges': size, 'repeated_scan_key_edge_visits': scan_visits,
                                   'indexed': asdict(state.work),
                                   'indexed_total_visits': state.work.indexed_visits})
        for layers in [8, 32, 128]:
            records = [Record('root', 'k', ('r0a', 'r0b'))]
            for layer in range(layers):
                children = (f'r{layer+1}a', f'r{layer+1}b') if layer + 1 < layers else ()
                origins = () if children else ('o',)
                records.extend(Record(f'r{layer}{side}', 'k', children, origins) for side in ['a', 'b'])
            model = Model(records)
            state = model.new_state()
            state.disclose_key('k')
            require(state.acquire('root') == frozenset({'o'}), 'layered-DAG source missing')
            before = state.work.indexed_visits
            for _ in range(1000):
                require(state.acquire('root') == state.disclose_key('k') == frozenset(),
                        'duplicate stress event changed exposure')
            require(state.work.indexed_visits == before, 'duplicate stress events rescanned graph')
            check_work_bound(state)
            layered.append({'layers': layers, 'records': len(records),
                            'containment_edges': sum(len(r.children) for r in records),
                            'root_to_source_paths_by_combinatorial_count': str(2 ** layers),
                            'indexed': asdict(state.work),
                            'indexed_total_visits': state.work.indexed_visits})
        depth = 4096
        records = [Record(f'r{i}', 'k', (f'r{i+1}',) if i + 1 < depth else (),
                          () if i + 1 < depth else ('o',)) for i in range(depth)]
        model = Model(records)
        state = model.new_state()
        state.acquire('r0')
        require(state.disclose_key('k') == frozenset({'o'}), 'deep-chain source missing')
        check_work_bound(state)
        deep = {'records': depth, 'recursion_used': False, 'indexed': asdict(state.work),
                'indexed_total_visits': state.work.indexed_visits}
    return {'reverse_key_chains': reverse_chains, 'layered_record_dags': layered,
            'deep_record_chain': deep,
            'measurement': 'explicit adjacency/payload and deque-pop counts; no wall-clock threshold',
            'path_oracle': 'constructor patched to raise throughout every large-graph control'}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=BASE / 'indexed-results.json')
    args = parser.parse_args()
    models = reference.fixtures()
    result = {
        'schema': 'q-periapt-indexed-exposure-checks-v1',
        'status': 'passed',
        'scope': 'fixed finite record/key/source derivation graph; supports the indexed closure proposition',
        'output_accounting': 'incremental operations return newly exposed sources; full state exports cost their output size',
        'source_sha256': {name: hashlib.sha256((BASE / name).read_bytes()).hexdigest()
                          for name in ['check_exposure.py', 'indexed_exposure.py', 'check_indexed_exposure.py']},
        'exhaustive': exhaustive_checks(models),
        'histories': history_checks(models),
        'independent_expected_cases': expected_checks(),
        'invalid_inputs_rejected': invalid_checks(),
        'scaling': scale_checks(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'],
                      'exhaustive_assignments': result['exhaustive']['total_assignments'],
                      **result['histories'],
                      'independent_expected_cases': len(result['independent_expected_cases']),
                      'invalid_inputs_rejected': len(result['invalid_inputs_rejected'])}))


if __name__ == '__main__':
    main()
