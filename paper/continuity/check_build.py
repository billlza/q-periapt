#!/usr/bin/env python3
"""Check the actual compiled manuscript and its single-file source identity."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import re
import subprocess
import sys
from tempfile import TemporaryFile
import unicodedata
from pathlib import Path
from typing import BinaryIO, Iterable

ROOT = Path(__file__).resolve().parent

DIAGNOSTIC = re.compile(
    r"^!|^(?:Under|Over)full \\[hv]box\b|^Missing character:"
    r"|\bwarning(?:\s*\([^)]*\))?\s*(?::|--)"
    r"|LaTeX Error:|Fatal error|There were undefined references"
    r"|(?:Citation|Reference) .+ undefined|Rerun to get cross-references right"
    r"|Label .+ multiply defined",
    re.IGNORECASE,
)


def check_log(lines: Iterable[str], name: str) -> list[str]:
    """Check a final compiler log after references and citations have settled."""
    failures = []
    number = 0
    for number, line in enumerate(lines, 1):
        if DIAGNOSTIC.search(line):
            failures.append(f'{name}:{number}: {line.strip()}')
    if number == 0:
        failures.append(f'{name}: empty compiler log')
    return failures


def log_failures(paths: list[Path]) -> list[str]:
    failures = []
    for path in paths:
        with path.open() as source:
            failures.extend(check_log(source, str(path)))
    return failures


def math_inventory(text: str) -> Counter[str]:
    return Counter(char for char in text if unicodedata.category(char) == 'Sm')


def extraction_failures(text: str, name: str) -> list[str]:
    invalid = {char for char in text if char == '\ufffd' or
               (unicodedata.category(char) == 'Cc' and char not in '\n\r\t\f')}
    return [f'{name}: invalid extracted character U+{ord(char):04X}' for char in sorted(invalid)]


def read_reviewed_pdf(source: BinaryIO) -> tuple[str, str]:
    """Hash and extract text from the same byte stream, including when it is a pipe."""
    digest = hashlib.sha256()
    with TemporaryFile() as snapshot:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
            snapshot.write(block)
        snapshot.seek(0)
        result = subprocess.run(['pdftotext', '-', '-'], stdin=snapshot,
                                check=True, capture_output=True, text=True)
    return result.stdout, digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-log', metavar='LABEL',
                      help='Check the final compiler log on standard input, using LABEL in diagnostics')
    mode.add_argument('--reference-stdin', action='store_true',
                      help='Compare mathematical symbols with the reviewed PDF supplied on standard input')
    args = parser.parse_args()
    if args.check_log is not None:
        diagnostics = check_log(sys.stdin, args.check_log)
        if diagnostics:
            raise SystemExit('\n'.join(diagnostics))
        return

    pdf = ROOT / 'continuity.pdf'
    built = ROOT / 'build/joc-submission.pdf'
    tex_log = built.with_suffix('.log')
    failures = log_failures([tex_log, built.with_suffix('.blg')])
    if pdf.read_bytes() != built.read_bytes():
        failures.append('Reading copy differs from the actual build output')
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = json.loads((ROOT / 'flatten_manifest.json').read_text())
    if digest(ROOT / manifest['output']) != manifest['output_sha256']:
        failures.append('Generated submission-source digest is stale')
    for name, record in manifest['inputs'].items():
        if digest(ROOT / name) != record['sha256']:
            failures.append('Changed unflattened source: ' + name)
    source = (ROOT / 'main.tex').read_text()
    abstract = re.search(r'\\abstract\{(.*?)\}\s*\\keywords', source, re.S)
    keywords = re.search(r'\\keywords\{([^{}]+)\}', source)
    if abstract is None or keywords is None:
        raise SystemExit('Missing abstract or keyword source')
    word_count = len(abstract.group(1).split())
    keyword_count = len(keywords.group(1).split(','))
    if not 150 <= word_count <= 250:
        failures.append(f'Abstract has {word_count} words')
    if not 5 <= keyword_count <= 10:
        failures.append(f'Keyword count is {keyword_count}')
    text = subprocess.run(['pdftotext', '-f', '1', '-l', '1', str(pdf), '-'],
                          check=True, capture_output=True, text=True).stdout
    authors = json.loads((ROOT / 'author-metadata.json').read_text())['authors']
    for author in authors:
        if author['display_name'] not in text:
            failures.append('Author missing from title page: ' + author['display_name'])
        if author['corresponding'] and author['email'] not in text:
            failures.append('Corresponding email missing from title page')
    full_text = subprocess.run(['pdftotext', str(pdf), '-'], check=True,
                               capture_output=True, text=True).stdout
    symbols = math_inventory(full_text)
    failures.extend(extraction_failures(full_text, pdf.name))
    if args.reference_stdin:
        reference, reviewed_digest = read_reviewed_pdf(sys.stdin.buffer)
        failures.extend(extraction_failures(reference, 'reviewed PDF'))
        expected = math_inventory(reference)
        for char in sorted(symbols.keys() | expected.keys()):
            if symbols[char] != expected[char]:
                failures.append(f'U+{ord(char):04X} ({char}): reviewed {expected[char]}, built {symbols[char]}')
    info = subprocess.run(['pdfinfo', str(pdf)], check=True, capture_output=True, text=True).stdout
    pages = re.search(r'^Pages:\s+(\d+)', info, re.M)
    if pages is None:
        failures.append('PDF page count unavailable')
    build_names = sorted(set(manifest['inputs']) | {'joc-submission.tex', 'references.bib',
                       'sn-jnl.cls', 'joc-basic.bst', 'sn-basic.bst',
                       'figures/confirmation-cut.pdf', 'author-metadata.json'})
    build_inputs = {name: digest(ROOT / name) for name in build_names}
    report = {'build_inputs': build_inputs, 'status': 'failed' if failures else 'passed', 'pdf_sha256': digest(pdf),
              'pages': int(pages.group(1)) if pages else None,
              'abstract_words': word_count, 'keywords': keyword_count,
              'math_symbol_counts': dict(sorted(symbols.items())),
              'generated_source_sha256': manifest['output_sha256'],
              'underfull_notices': tex_log.read_text().count('Underfull'), 'failures': failures,
              'scope': 'Build, source identity and document metadata; not a mathematical or experimental security proof.'}
    if args.reference_stdin:
        report['reviewed_pdf_sha256'] = reviewed_digest
        report['reviewed_math_symbols_identical'] = symbols == expected
    (ROOT / 'build/build-check.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    if failures:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
