#!/usr/bin/env python3
"""Compile a fresh nine-file source export and compare its rendered text."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], cwd: Path) -> bytes:
    result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace')[-2000:] or
                           result.stdout.decode(errors='replace')[-2000:])
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--reading-copy', type=Path, required=True)
    parser.add_argument('--work-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    archive, reading = args.archive.resolve(), args.reading_copy.resolve()
    work = args.work_directory.resolve()
    work.mkdir(parents=True, exist_ok=False)
    expected = {'README.md', 'SHA256SUMS.json', 'author-metadata.json',
                'figures/confirmation-cut.pdf', 'joc-basic.bst',
                'joc-submission.tex', 'references.bib', 'sn-basic.bst', 'sn-jnl.cls'}
    with zipfile.ZipFile(archive) as package:
        if set(package.namelist()) != expected or len(package.infolist()) != len(expected):
            raise ValueError('Unexpected source export inventory')
        hashes = json.loads(package.read('SHA256SUMS.json'))
        if set(hashes) != expected - {'SHA256SUMS.json'}:
            raise ValueError('Incomplete export digest inventory')
        for name in sorted(expected):
            data = package.read(name)
            if name in hashes and hashlib.sha256(data).hexdigest() != hashes[name]:
                raise ValueError('Export digest mismatch: ' + name)
            destination = work / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    build = run(['latexmk', '-pdf', '-interaction=nonstopmode', '-halt-on-error',
                 'joc-submission.tex'], work)
    (work / 'export-build.stdout').write_bytes(build)
    log = (work / 'joc-submission.log').read_text()
    bad = [r'^!', r'Overfull \\[hv]box', r'There were undefined references',
           r'(?:Citation|Reference) .+ undefined', r'Rerun to get cross-references right',
           r'Label .+ multiply defined', r'LaTeX Error:', r'Fatal error']
    if any(re.search(pattern, log, re.M) for pattern in bad):
        raise ValueError('Export build log contains a document failure')
    built = work / 'joc-submission.pdf'
    compared = {}
    for label, options in [('plain', []), ('layout', ['-layout'])]:
        a = run(['pdftotext', *options, str(reading), '-'], work)
        b = run(['pdftotext', *options, str(built), '-'], work)
        if a != b:
            raise ValueError('Export and reading-copy text differs: ' + label)
        compared[label + '_text_identical'] = True
        compared[label + '_text_sha256'] = hashlib.sha256(a).hexdigest()
    fonts = run(['pdffonts', str(built)], work).decode()
    (work / 'embedded-fonts.txt').write_text(fonts)
    font_rows = fonts.splitlines()[2:]
    if not font_rows or any(re.search(r'\s+yes\s+(?:yes|no)\s+(?:yes|no)\s+\d+\s+\d+\s*$', row) is None
                            for row in font_rows):
        raise ValueError('Unembedded or unrecognized PDF font')
    info = run(['pdfinfo', str(built)], work).decode()
    report = {'status': 'passed', 'files': len(expected),
              'pages': int(re.search(r'^Pages:\s+(\d+)', info, re.M).group(1)),
              **compared, 'all_fonts_embedded': True, 'font_count': len(font_rows),
              'undefined_references_or_citations': 0, 'overfull_boxes': 0,
              'zip_sha256': sha(archive), 'pdf_sha256': sha(reading),
              'export_pdf_sha256': sha(built), 'exported_files': sorted(expected),
              'verification_script_sha256': sha(Path(__file__)),
              'method': 'Exact nine-file inventory and digest verification, fresh pdfLaTeX/BibTeX build, complete plain/layout text comparison and font/log checks.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
