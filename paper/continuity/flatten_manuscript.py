#!/usr/bin/env python3
"""Expand the manuscript's local section inputs into one submission source."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INPUT = re.compile(r'(?m)^[ \t]*\\(?:input|include)\{([^{}]+)\}[ \t]*(?:%[^\n]*)?$')
records: dict[str, dict[str, str | int]] = {}

def expand(path: Path, stack: tuple[Path, ...] = ()) -> str:
    path = path.resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError(f'Input escapes manuscript root: {path}')
    if path in stack:
        raise ValueError('Cyclic manuscript input: ' + str(path.relative_to(ROOT)))
    data = path.read_bytes()
    name = path.relative_to(ROOT).as_posix()
    records[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    source = data.decode('utf-8')
    def replace(match: re.Match[str]) -> str:
        child = path.parent / match.group(1)
        if not child.suffix:
            child = child.with_suffix('.tex')
        body = expand(child, stack + (path,))
        child_name = child.resolve().relative_to(ROOT).as_posix()
        return f'% BEGIN SECTION SOURCE: {child_name}\n{body.rstrip()}\n% END SECTION SOURCE: {child_name}'
    result = INPUT.sub(replace, source)
    if re.search(r'(?m)^[^%\n]*\\(?:input|include)\s*[{ ]', result):
        raise ValueError(f'Unsupported unresolved input in {name}')
    return result

source = '% Generated from the modular working source by flatten_manuscript.py.\n' + expand(ROOT / 'main.tex')
out = ROOT / 'joc-submission.tex'
out.write_text(source, encoding='utf-8')
manifest = {
    'schema': 'qperiapt-joc-single-source/1',
    'input_entry': 'main.tex',
    'output': out.name,
    'output_sha256': hashlib.sha256(out.read_bytes()).hexdigest(),
    'inputs': dict(sorted(records.items())),
    'figure': 'figures/confirmation-cut.pdf',
    'bibliography': 'references.bib',
    'class': 'sn-jnl.cls',
    'bibliography_style': 'joc-basic.bst',
}
(ROOT / 'flatten_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(f'Flattened {len(records)} source files to {out.name}.')
