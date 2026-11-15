#!/usr/bin/env python3
"""Independent least-model oracle: enumerate Boolean models, not derivations."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import random
import sys
from pathlib import Path


BASE = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module-dir", default=BASE, type=Path,
                        help="directory containing indexed_exposure.py (default: this directory)")
    parser.add_argument("--output", default=BASE / "indexed-review-results.json", type=Path)
    args = parser.parse_args()
    source = args.module_dir.resolve() / 'indexed_exposure.py'
    spec = importlib.util.spec_from_file_location('independently_reviewed_indexed_exposure', source)
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot load indexed evaluator source')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    IndexedModel, Record = module.IndexedModel, module.Record

    rng = random.Random(20261115)
    counts = []
    for graph_id in range(24):
        # Reuse literal names across sorts deliberately: sources do not create keys.
        names, keys, sources = ("a", "b", "c"), ("a", "b"), ("a", "c")
        records = [Record(name, rng.choice(keys),
                          tuple(child for child in names[i + 1:] if rng.randrange(2)),
                          tuple(origin for origin in sources if rng.randrange(2)))
                   for i, name in enumerate(names)]
        derives = tuple((a, b) for a in keys for b in keys if rng.randrange(2))
        model = IndexedModel(records, derives)
        atoms = ([('record', x) for x in names]
                 + [('key', x) for x in sorted(model.keys)]
                 + [('source', x) for x in sorted(model.origins)])
        bit = {atom: 1 << i for i, atom in enumerate(atoms)}
        rules = []
        for parent, child in derives:
            rules.append((bit['key', parent], bit['key', child]))
        for record in records:
            premise = bit['record', record.name] | bit['key', record.key]
            rules += [(premise, bit['record', child]) for child in record.children]
            rules += [(premise, bit['source', origin]) for origin in record.origins]
        valuations = []
        for valuation in range(1 << len(atoms)):
            if all((valuation & premise) != premise or (valuation & conclusion)
                   for premise, conclusion in rules):
                valuations.append(valuation)
        comparisons = 0
        for seeds in range(1 << len(atoms)):
            # Intersect every classical truth assignment satisfying rules and seeds.
            expected = (1 << len(atoms)) - 1
            for valuation in valuations:
                if valuation & seeds == seeds:
                    expected &= valuation
            selected = {atom for atom, mask in bit.items() if seeds & mask}
            observed = model.forward({name for kind, name in selected if kind == 'record'},
                                     {name for kind, name in selected if kind == 'key'},
                                     {name for kind, name in selected if kind == 'source'})
            expected_sets = tuple({name for (kind, name), mask in bit.items()
                                   if kind == sort and expected & mask}
                                  for sort in ['source', 'record', 'key'])
            if observed != expected_sets:
                raise RuntimeError(f"graph {graph_id}, seeds {seeds}: {observed} != {expected_sets}")
            comparisons += 1
        counts.append({'graph': graph_id, 'atoms': len(atoms),
                       'satisfying_valuations': len(valuations),
                       'seed_sets': comparisons})
    result = {
        'status': 'passed',
        'method': 'Enumerate all Boolean satisfying valuations of each typed Horn theory, then intersect those containing each seed set; compare all three closure sorts.',
        'seed': 20261115,
        'graph_count': len(counts),
        'seed_set_comparisons': sum(row['seed_sets'] for row in counts),
        'cross_sort_same_literal_names': True,
        'graphs': counts,
        'source_sha256': hashlib.sha256((args.module_dir / 'indexed_exposure.py').read_bytes()).hexdigest(),
        'review_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ['status', 'graph_count', 'seed_set_comparisons', 'source_sha256']}))


if __name__ == '__main__':
    main()
