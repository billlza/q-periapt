"""Restore closed, path-addressed proof fragments into the exact original tree.

This module checks proof *editing*, not proof validity. Its output must undergo a
complete independent Tamarin replay; neither a fragment nor this checker confers
security, ABI, or release qualification. Operational rules and every query remain
unchanged. Unselected and previously closed proof material is preserved verbatim.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Iterable

from continuity_multi_epoch_search import require, theory, uncomment, _HEADER


@dataclass(frozen=True)
class Fragment:
    case_path: tuple[str, ...]
    proof: str


def _text(data: bytes) -> str:
    # Apply the same size, declaration and query checks as the replay entrypoint.
    theory(data)
    return data.decode('utf-8', errors='strict')


def _lemma_span(text: str, name: str) -> tuple[int, int]:
    require(type(name) is str and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name),
            'invalid target lemma name')
    clean = uncomment(text)
    headers = list(_HEADER.finditer(clean))
    selected = [i for i, header in enumerate(headers) if header[1] == name]
    require(len(selected) == 1, 'target lemma missing or ambiguous')
    index = selected[0]
    start = headers[index].end()
    # Header matching has consumed the opening formula quote.
    while start < len(clean):
        if clean[start] == '\\':
            start += 2
        elif clean[start] == '"':
            break
        else:
            start += 1
    require(start < len(clean), 'unterminated target formula')
    end = headers[index + 1].start() if index + 1 < len(headers) else clean.rfind('\nend')
    require(start < end, 'target proof boundary differs')
    return start + 1, end


def case_spans(data: bytes, name: str) -> dict[tuple[str, ...], tuple[int, int]]:
    """Locate case bodies in Tamarin's indentation-based exported proof syntax."""
    text = _text(data)
    start, end = _lemma_span(text, name)
    clean = uncomment(text)
    spans: dict[tuple[str, ...], tuple[int, int]] = {}
    stack: list[tuple[str, int, int]] = []
    offset = start

    def finish() -> None:
        case, _indent, begin = stack.pop()
        path = tuple(row[0] for row in stack) + (case,)
        require(path not in spans, 'duplicate proof case path')
        spans[path] = (begin, offset)

    for line in clean[start:end].splitlines(keepends=True):
        case = re.fullmatch(r'( *)case ([A-Za-z_][A-Za-z_0-9]*)\s*', line)
        boundary = re.fullmatch(r'( *)(?:next|qed)\s*', line)
        if case:
            indent = len(case[1])
            while stack and stack[-1][1] >= indent:
                finish()
            stack.append((case[2], indent, offset + len(line)))
        elif boundary:
            indent = len(boundary[1])
            while stack and stack[-1][1] > indent:
                finish()
        offset += len(line)
    while stack:
        finish()
    return spans


def _is_hole(proof: str) -> bool:
    return re.fullmatch(r'\s*by sorry\s*', uncomment(proof)) is not None


def _closed(proof: str) -> bool:
    clean = uncomment(proof)
    # Invalid steps may be annotated in comments, so check the original too.
    return (bool(clean.strip()) and re.search(r'\b(?:sorry|admit)\b', clean) is None
            and re.search(r'invalid\s+proof\s+step', proof, re.I) is None)


def collect_closed(original: bytes, candidate: bytes, name: str) -> tuple[Fragment, ...]:
    """Select only former holes now closed in a same-contract candidate tree.

    Other candidate proofs can be deliberately open during diagnosis. They are
    not copied: restoration below always starts from the complete original.
    """
    require(theory(original) == theory(candidate), 'candidate changed the theory or queries')
    old, new = _text(original), _text(candidate)
    previous, current = case_spans(original, name), case_spans(candidate, name)
    result = []
    for path, (start, end) in previous.items():
        if not _is_hole(old[start:end]):
            continue
        require(path in current, 'candidate removed an original open case')
        left, right = current[path]
        proof = new[left:right]
        if _closed(proof):
            result.append(Fragment(path, proof))
    return tuple(result)


def restore(original: bytes, expected_sha256: str, name: str,
            fragments: Iterable[Fragment]) -> bytes:
    """Replace exact open leaves; reject overlap, substitutions and empty edits."""
    require(type(expected_sha256) is str
            and re.fullmatch(r'[0-9a-f]{64}', expected_sha256)
            and hashlib.sha256(original).hexdigest() == expected_sha256,
            'original complete proof identity differs')
    contract = theory(original)
    text = _text(original)
    spans = case_spans(original, name)
    edits, seen = [], set()
    for fragment in fragments:
        require(type(fragment) is Fragment and type(fragment.case_path) is tuple
                and fragment.case_path and all(type(x) is str for x in fragment.case_path)
                and type(fragment.proof) is str, 'invalid proof fragment')
        path = fragment.case_path
        require(path not in seen and not any(path[:len(p)] == p or p[:len(path)] == path for p in seen),
                'duplicate or overlapping proof fragments')
        require(path in spans, 'unknown proof case path')
        start, end = spans[path]
        require(_is_hole(text[start:end]), 'fragment would replace non-open proof material')
        require(_closed(fragment.proof), 'fragment remains open or contains invalid steps')
        require(fragment.proof.endswith('\n'), 'fragment must retain its terminal newline')
        seen.add(path)
        edits.append((start, end, fragment.proof))
    require(edits, 'no closed proof fragment to restore')
    # All offsets refer to the original; reverse order avoids displacement.
    for start, end, proof in sorted(edits, reverse=True):
        text = text[:start] + proof + text[end:]
    result = text.encode('utf-8')
    require(theory(result) == contract, 'restored fragment changed the theory or queries')
    # Ensure a malformed indentation/terminator did not redirect another case.
    after = case_spans(result, name)
    restored_text = result.decode('utf-8')
    original_text = original.decode('utf-8')
    for path in set(after) - set(spans):
        require(any(path[:len(p)] == p for p in seen),
                'fragment introduced a case outside its original leaf')
    for path, (start, end) in spans.items():
        if any(path[:len(p)] == p or p[:len(path)] == path for p in seen):
            continue
        require(path in after, 'restoration removed an unrelated proof case')
        left, right = after[path]
        require(restored_text[left:right] == original_text[start:end],
                'restoration changed unrelated proof material')
    return result


def main(argv: list[str] | None = None) -> int:
    """Prepare a complete restored tree; this command never marks it verified."""
    import argparse
    import json
    from pathlib import Path
    from evidence_io import read_regular_snapshot

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', required=True, type=Path)
    parser.add_argument('--original-sha256', required=True)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--lemma', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    original = read_regular_snapshot(args.original, maximum=4*1024*1024,
                                     label='original complete proof')
    candidate = read_regular_snapshot(args.candidate, maximum=4*1024*1024,
                                      label='conditional proof candidate')
    fragments = collect_closed(original.data, candidate.data, args.lemma)
    restored = restore(original.data, args.original_sha256, args.lemma, fragments)
    with args.output.open('xb') as stream:
        stream.write(restored)
    print(json.dumps({'original_sha256': original.sha256, 'candidate_sha256': candidate.sha256,
                      'restored_sha256': hashlib.sha256(restored).hexdigest(),
                      'closed_original_leaves': len(fragments),
                      'case_paths': [list(fragment.case_path) for fragment in fragments],
                      'security_proof_verified': False, 'release_claim_eligible': False,
                      'complete_independent_replay_required': True}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
