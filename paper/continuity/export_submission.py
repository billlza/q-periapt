#!/usr/bin/env python3
"""Package the verified single-file manuscript with its declared dependencies."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parent
FILES = ['joc-submission.tex', 'references.bib', 'sn-jnl.cls', 'joc-basic.bst',
         'sn-basic.bst', 'figures/confirmation-cut.pdf', 'author-metadata.json']

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    check = json.loads((ROOT / 'build/build-check.json').read_text())
    if check['status'] != 'passed':
        raise SystemExit('The current build check has not passed')
    for name, expected in check['build_inputs'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise SystemExit('Build dependency changed after verification: ' + name)
    digest = hashlib.sha256((ROOT / 'joc-submission.tex').read_bytes()).hexdigest()
    if digest != check['generated_source_sha256']:
        raise SystemExit('Submission source changed after the build check')
    files = {name: (ROOT / name).read_bytes() for name in FILES}
    files['README.md'] = b'''# JoC single-file manuscript

Compile joc-submission.tex with pdfLaTeX and BibTeX, or run:

    latexmk -pdf -interaction=nonstopmode -halt-on-error joc-submission.tex

The class is the official Springer Nature sn-jnl.cls. joc-basic.bst is a named
local derivative of sn-basic.bst that retains all bibliography authors while
preserving its alphabetical sort. The unmodified upstream style is included.
Full working sources, proof notes and review records are in paper/continuity
on the paper/joc-persistent-recovery branch of billlza/q-periapt.
'''
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    files['SHA256SUMS.json'] = (json.dumps(hashes, indent=2) + '\n').encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(args.output, 'w', compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    print(json.dumps({'output': str(args.output), 'files': len(files),
                      'sha256': hashlib.sha256(args.output.read_bytes()).hexdigest()}))

if __name__ == '__main__':
    main()
