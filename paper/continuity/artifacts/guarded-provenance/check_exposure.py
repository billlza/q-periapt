#!/usr/bin/env python3
"""Guarded provenance for persistent records; no cryptographic-security claim.

Two algorithms are compared: iterative decryption of concrete record objects,
and evaluation of normalized capture/key guards for original secret sources.
Only Python's standard library is required. Run from any working directory.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Record:
    name: str
    key: str
    children: tuple[str, ...] = ()
    origins: tuple[str, ...] = ()


@dataclass(frozen=True)
class Route:
    acquired: str
    guards: frozenset[str]
    origin: str
    path: tuple[str, ...]


class Model:
    def __init__(self, records: list[Record], derives: tuple[tuple[str, str], ...] = ()):
        self.records = {r.name: r for r in records}
        if len(self.records) != len(records):
            raise ValueError('duplicate record identity')
        self.derives = derives
        self.keys = sorted({r.key for r in records} | {k for pair in derives for k in pair})
        self.origins = sorted({o for r in records for o in r.origins})
        for r in records:
            if not r.key or not r.name:
                raise ValueError('empty record or key identity')
            if any(c not in self.records for c in r.children):
                raise ValueError('unknown child record')
        self.routes = self._routes()

    def _routes(self) -> tuple[Route, ...]:
        out = []
        def visit(start: str, cur: str, guards: frozenset[str], path: tuple[str, ...]):
            if cur in path:
                raise ValueError('cyclic record containment')
            r = self.records[cur]
            g, p = guards | {r.key}, path + (cur,)
            for o in r.origins:
                out.append(Route(start, g, o, p))
            for child in r.children:
                visit(start, child, g, p)
        for start in self.records:
            visit(start, start, frozenset(), ())
        return tuple(out)

    def forward(self, acquired: set[str], disclosed: set[str], direct: set[str] | None = None) -> tuple[set[str], set[str], set[str]]:
        """Concrete semantics: repeatedly decrypt and derive available objects."""
        if not acquired <= self.records.keys() or not disclosed <= set(self.keys):
            raise ValueError('unknown acquisition or key')
        direct = set() if direct is None else direct
        if not direct <= set(self.origins):
            raise ValueError('unknown directly disclosed source')
        available, keys, exposed = set(acquired), set(disclosed), set(direct)
        changed = True
        while changed:
            before = (len(available), len(keys), len(exposed))
            for parent, child in self.derives:
                if parent in keys:
                    keys.add(child)
            for name in tuple(available):
                r = self.records[name]
                if r.key in keys:
                    available.update(r.children)
                    exposed.update(r.origins)
            changed = before != (len(available), len(keys), len(exposed))
        return exposed, available, keys

    def normalized(self, acquired: set[str], disclosed: set[str], direct: set[str] | None = None) -> tuple[set[str], list[dict]]:
        """Guard semantics: graph reachability for keys, then path predicates."""
        if not acquired <= self.records.keys() or not disclosed <= set(self.keys):
            raise ValueError('unknown acquisition or key')
        direct = set() if direct is None else direct
        if not direct <= set(self.origins):
            raise ValueError('unknown directly disclosed source')
        adjacency: dict[str, list[str]] = {k: [] for k in self.keys}
        for parent, child in self.derives:
            adjacency[parent].append(child)
        keys, stack = set(disclosed), list(disclosed)
        while stack:
            for child in adjacency[stack.pop()]:
                if child not in keys:
                    keys.add(child)
                    stack.append(child)
        witnesses = [
            {'origin': r.origin, 'acquired': r.acquired,
             'guards': sorted(r.guards), 'path': list(r.path)}
            for r in self.routes if r.acquired in acquired and r.guards <= keys
        ]
        return set(direct) | {w['origin'] for w in witnesses}, witnesses


class History:
    """Acquisition is cumulative. Delete affects only future local acquisitions."""
    def __init__(self, model: Model):
        self.model = model
        self.live = set(model.records)
        self.acquired: set[str] = set()
        self.keys: set[str] = set()
        self.direct: set[str] = set()
        self.previous: set[str] = set()
        self.events: list[dict] = []

    def step(self, kind: str, item: str) -> set[str]:
        if kind == 'acquire':
            if item not in self.live:
                raise ValueError('acquisition of unavailable local record')
            self.acquired.add(item)
        elif kind == 'disclose_key':
            if item not in self.model.keys:
                raise ValueError('unknown key')
            self.keys.add(item)
        elif kind == 'delete_local':
            if item not in self.live:
                raise ValueError('record already unavailable')
            self.live.remove(item)
        elif kind == 'disclose_origin':
            if item not in self.model.origins:
                raise ValueError('unknown directly disclosed source')
            self.direct.add(item)
        else:
            raise ValueError('unknown event kind')
        a = self.model.forward(self.acquired, self.keys, self.direct)[0]
        b, witnesses = self.model.normalized(self.acquired, self.keys, self.direct)
        assert a == b, (kind, item, a, b)
        assert self.previous <= a, 'attacker knowledge decreased'
        self.previous = a
        self.events.append({'kind': kind, 'item': item, 'exposed_origins': sorted(a),
                            'witnesses': witnesses})
        return a


def subsets(items):
    items = tuple(items)
    for n in range(len(items) + 1):
        for s in itertools.combinations(items, n):
            yield set(s)


def fixtures() -> dict[str, Model]:
    return {
        'native_shared_journal_key': Model([
            Record('gen-token', 'wrap', origins=('generation-0',)),
            Record('enc-token', 'wrap', origins=('encapsulation-0',)),
            Record('image-old', 'journal', ('gen-token',)),
            Record('image-sibling-copy', 'journal', ('gen-token', 'enc-token')),
            Record('pending-target', 'journal', ('gen-token',)),
        ], (('journal', 'wrap'),)),
        'independent_wrapping_keys': Model([
            Record('token', 'wrap', origins=('reservation-0',)),
            Record('image', 'journal', ('token',)),
            Record('copy', 'journal-new', ('token',)),
        ]),
        'rewrapped_origin': Model([
            Record('token-old', 'wrap-old', origins=('reservation-0',)),
            Record('token-new', 'wrap-new', origins=('reservation-0',)),
            Record('old-image', 'journal-old', ('token-old',)),
            Record('new-image', 'journal-new', ('token-new',)),
        ]),
        'nested_aggregate': Model([
            Record('token-a', 'wrap-a', origins=('origin-a',)),
            Record('token-b', 'wrap-b', origins=('origin-b',)),
            Record('inner', 'archive', ('token-a', 'token-b')),
            Record('outer', 'journal', ('inner',)),
            Record('copy', 'journal-new', ('inner',)),
        ], (('journal', 'archive'), ('archive', 'wrap-a'))),
        'same_actual_key_alias': Model([
            Record('token', 'same-key', origins=('origin',)),
            Record('image', 'same-key', ('token',)),
        ]),
        'empty_record_and_unrelated_source': Model([
            Record('empty', 'outer'),
            Record('token', 'inner', origins=('origin',)),
            Record('container', 'outer', ('empty',)),
        ]),
        'key_derivation_cycle_requires_a_seed': Model([
            Record('token', 'key-a', origins=('origin',)),
            Record('image', 'key-b', ('token',)),
        ], (('key-a', 'key-b'), ('key-b', 'key-a'))),
    }


def graph_checks(models: dict[str, Model]) -> dict:
    counts, total = {}, 0
    for name, model in models.items():
        count = 0
        for acquired in subsets(model.records):
            for disclosed in subsets(model.keys):
                for direct in subsets(model.origins):
                    a = model.forward(acquired, disclosed, direct)[0]
                    b = model.normalized(acquired, disclosed, direct)[0]
                    assert a == b, (name, acquired, disclosed, direct, a, b)
                    count += 1
        counts[name] = count
        total += count
    return {'instances': counts, 'total_acquisition_key_assignments': total}


def histories(models: dict[str, Model]) -> tuple[list[dict], int]:
    cases = []
    specifications = [
        ('capture_then_key', 'native_shared_journal_key', [
            ('acquire', 'image-old'), ('disclose_key', 'journal')]),
        ('key_then_capture', 'native_shared_journal_key', [
            ('disclose_key', 'journal'), ('acquire', 'image-old')]),
        ('delete_after_capture_then_key', 'native_shared_journal_key', [
            ('acquire', 'image-old'), ('delete_local', 'image-old'), ('disclose_key', 'journal')]),
        ('sibling_copy_keeps_original_sources', 'native_shared_journal_key', [
            ('delete_local', 'image-old'), ('acquire', 'image-sibling-copy'), ('disclose_key', 'journal')]),
        ('pending_target_is_an_acquisition_surface', 'native_shared_journal_key', [
            ('acquire', 'pending-target'), ('disclose_key', 'journal')]),
        ('outer_key_alone_does_not_remove_inner_guard', 'independent_wrapping_keys', [
            ('acquire', 'image'), ('disclose_key', 'journal'), ('disclose_key', 'wrap')]),
        ('new_wrapper_keeps_old_origin', 'rewrapped_origin', [
            ('acquire', 'new-image'), ('disclose_key', 'journal-new'), ('disclose_key', 'wrap-new')]),
        ('known_keys_without_acquisition', 'native_shared_journal_key', [('disclose_key', 'journal')]),
        ('public_digest_is_not_record_acquisition', 'native_shared_journal_key', []),
        ('direct_entropy_disclosure', 'native_shared_journal_key', [('disclose_origin', 'generation-0')]),
    ]
    for name, key, events in specifications:
        h = History(models[key])
        for kind, item in events:
            h.step(kind, item)
        cases.append({'case': name, 'model': key, 'events': h.events,
                      'final_exposed_origins': sorted(h.previous)})
    m = models['independent_wrapping_keys']
    ev = [('acquire', 'image'), ('acquire', 'copy'), ('disclose_key', 'journal'),
          ('disclose_key', 'journal-new'), ('disclose_key', 'wrap'), ('delete_local', 'image')]
    legal = 0
    for perm in itertools.permutations(ev):
        if perm.index(('delete_local', 'image')) < perm.index(('acquire', 'image')):
            continue
        h = History(m)
        for kind, item in perm:
            h.step(kind, item)
        assert h.previous == {'reservation-0'}
        legal += 1
    assert legal == 360
    return cases, legal


def mutation_checks(models: dict[str, Model]) -> list[dict]:
    out = []
    # These deliberately incorrect interpretations must disagree with the model.
    def killed(name, correct, mutant):
        assert correct != mutant, name
        out.append({'mutation': name, 'detected': True,
                    'correct': sorted(correct), 'mutated': sorted(mutant)})
    m = models['native_shared_journal_key']
    correct = m.forward({'image-old'}, {'journal'})[0]
    killed('discard_captured_record_on_local_delete', correct, m.forward(set(), {'journal'})[0])
    killed('classify_once_at_capture_and_ignore_later_key', correct, m.forward({'image-old'}, set())[0])
    copied = m.forward({'image-sibling-copy'}, {'journal'})[0]
    killed('reset_source_to_latest_image_identifier', copied,
           {'generation-copy', 'encapsulation-copy'})
    independent = models['independent_wrapping_keys']
    correct = independent.forward({'image'}, {'journal'})[0]
    killed('drop_inner_wrapping_key_guard', correct, {'reservation-0'})
    correct = m.forward(set(), {'journal'})[0]
    killed('treat_public_digest_as_captured_image', correct, m.forward({'image-old'}, {'journal'})[0])
    return out


def negative_input_checks() -> list[str]:
    rejected = []
    invalid = [
        ('duplicate_record_identity', lambda: Model([Record('x', 'k'), Record('x', 'k')])),
        ('unknown_child', lambda: Model([Record('x', 'k', ('missing',))])),
        ('containment_cycle', lambda: Model([Record('x', 'k', ('y',)), Record('y', 'k', ('x',))])),
        ('unknown_acquisition', lambda: Model([Record('x', 'k')]).forward({'missing'}, set())),
        ('unknown_key', lambda: Model([Record('x', 'k')]).normalized(set(), {'missing'})),
    ]
    for name, fn in invalid:
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise AssertionError('invalid input admitted: ' + name)
    h = History(Model([Record('x', 'k')]))
    h.step('delete_local', 'x')
    try:
        h.step('acquire', 'x')
    except ValueError:
        rejected.append('capture_deleted_unavailable_record')
    else:
        raise AssertionError('unavailable record acquired')
    return rejected


def main():
    if not __debug__:
        raise SystemExit('validation requires assertions: run without -O or PYTHONOPTIMIZE')
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('results.json'))
    args = parser.parse_args()
    models = fixtures()
    checked = graph_checks(models)
    cases, permutations = histories(models)
    mutations = mutation_checks(models)
    rejected = negative_input_checks()
    result = {
        'schema': 'q-periapt-guarded-provenance-checks-v1',
        'status': 'passed',
        'scope': 'finite abstract decryption/derivation semantics; not a new native experiment or computational security proof',
        'source_commit_for_native_shape': '228c944fc476e3e57d6c08063cacb19bca5b360e',
        'algorithms': ['iterative concrete decryption', 'guarded origin path normalization'],
        'enumeration': checked,
        'legal_event_permutations': permutations,
        'prefix_monotonicity_checks': permutations * 6,
        'directed_histories': cases,
        'mutations': mutations,
        'invalid_inputs_rejected': rejected,
        'checker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], **checked,
                      'legal_event_permutations': permutations,
                      'mutation_witnesses': len(mutations), 'rejected_invalid_inputs': len(rejected)}))


if __name__ == '__main__':
    main()
