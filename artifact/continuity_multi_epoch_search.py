#!/usr/bin/env python3
"""Continue the exact retained multi-epoch frontier without changing its model.

This is a research execution path, not release admission. Incomplete searches
are failures, even when Tamarin exits zero. A successful selected search must
survive a separate no-search replay with every reusable premise discharged.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = Path('research/sdk-alpha1/evidence/20261029-response-origin-derivation')
ARCHIVE_SHA256 = 'd40c0e0035c97a84700d9076f9b3af8b13b25b99434c38d69286b8c892497255'
ARCHIVE_BYTES = 461012
MODEL_SHA256 = 'f7910208a18aaf438e82eb2a2e37812f49322534252a47eae6a54c80b3d56e0b'
QUERY_COUNT = 34
ORIGIN = 'epoch_generation_secret_derivation_origin_with_phase_roots'
ORIGINAL_ORIGIN = 'epoch_generation_secret_derivation_origin'
GOALS = (ORIGIN,)
MAX_BYTES = 4 * 1024 * 1024
TIMEOUT = 900
HEAP_GIB = 12
DEPTH = 16
_HEADER = re.compile(r'^\s*lemma\s+([A-Za-z_][A-Za-z_0-9]*)\s*(\[[^\]]*\])?\s*:\s*(all-traces|exists-trace)?\s*"', re.M)
_ROW = re.compile(r'  (\w+) \((all-traces|exists-trace)\): (verified|analysis incomplete|falsified - found trace) \(([1-9][0-9]*) steps\)')
_TOKEN = re.compile(r"'(?:\\.|[^'\\])*'|[A-Za-z_][A-Za-z_0-9.']*|[0-9]+|==>|<=>|!=|->|[^\s]", re.S)


class SearchContractError(ValueError):
    pass


def require(value, message):
    if not value:
        raise SearchContractError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    def constant(value):
        raise SearchContractError('non-finite JSON constant ' + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def uncomment(text):
    """Blank comments while preserving offsets, newlines and quoted formulas."""
    out = list(text)
    i = 0
    quote = None
    while i < len(text):
        if quote is not None:
            if text[i] == '\\':
                i += 2
                continue
            if text[i] == quote:
                quote = None
            i += 1
        elif text[i] == '"' or (text[i] == "'" and
                                 (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_.'"))):
            quote = text[i]
            i += 1
        elif text.startswith('//', i):
            end = text.find('\n', i)
            end = len(text) if end < 0 else end
            out[i:end] = ' ' * (end - i)
            i = end
        elif text.startswith('/*', i):
            start, depth = i, 1
            i += 2
            while depth and i < len(text):
                if text.startswith('/*', i):
                    depth += 1
                    i += 2
                elif text.startswith('*/', i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            require(depth == 0, 'unterminated theory comment')
            out[start:i] = ['\n' if c == '\n' else ' ' for c in text[start:i]]
        else:
            i += 1
    require(quote is None, 'unterminated theory quote')
    return ''.join(out)


@dataclass(frozen=True)
class Query:
    name: str
    mode: str
    attributes: tuple[str, ...]
    formula: tuple[str, ...]

    @property
    def reusable(self):
        return 'reuse' in self.attributes or 'sources' in self.attributes


@dataclass(frozen=True)
class Theory:
    prefix: tuple[str, ...]
    queries: tuple[Query, ...]

    @property
    def by_name(self):
        return {q.name: q for q in self.queries}


def theory(data):
    require(type(data) is bytes and len(data) <= MAX_BYTES, 'theory exceeds bound')
    clean = uncomment(data.decode('utf-8', errors='strict'))
    headers = list(_HEADER.finditer(clean))
    require(headers, 'theory contains no complete lemma declaration')
    require(len(re.findall(r'^\s*lemma\b', clean, re.M)) == len(headers), 'unsupported lemma declaration')
    require(len(re.findall(r'^\s*end\s*$', clean, re.M)) == 1
            and clean.rstrip().endswith('end'), 'theory must have one terminal end')
    prefix = tuple(_TOKEN.findall(clean[:headers[0].start()]))
    queries = []
    for number, header in enumerate(headers):
        end = header.end()
        while end < len(clean):
            if clean[end] == '\\':
                end += 2
                continue
            if clean[end] == '"':
                break
            end += 1
        require(end < len(clean), 'unclosed lemma formula')
        limit = headers[number + 1].start() if number + 1 < len(headers) else len(clean)
        require(end < limit, 'overlapping lemma definitions')
        body = clean[end + 1:limit]
        require(not re.search(r'^\s*(?:rule|restriction|equations|functions|builtins|theory|tactic|heuristic|include)\b', body, re.M),
                'operational declaration after the first lemma')
        attrs = tuple(_TOKEN.findall(header[2][1:-1])) if header[2] else ()
        formula = tuple(_TOKEN.findall(clean[header.end():end]))
        require(formula, 'empty lemma proposition')
        queries.append(Query(header[1], header[3] or 'all-traces', attrs, formula))
    require(len({q.name for q in queries}) == len(queries), 'duplicate lemma')
    return Theory(prefix, tuple(queries))


def inventory(stdout, source, output, contract):
    lines = [line for line in stdout.decode('utf-8', errors='strict').splitlines() if line.strip()]
    separator = '=' * 78
    require(len(lines) >= 7 and lines[:3] == [separator, 'summary of summaries:', f'analyzed: {source}'],
            'missing or mismatched terminal summary')
    require(lines[3] == f'  output:          {output}' and lines[-1] == separator,
            'summary certificate identity differs')
    require(re.fullmatch(r'  processing time: [0-9]+(?:\.[0-9]+)?s', lines[4]), 'missing prover duration')
    results = {}
    for line in lines[5:-1]:
        row = _ROW.fullmatch(line)
        require(row is not None, 'malformed terminal lemma result')
        name, mode, status, steps = row.groups()
        require(name not in results, 'duplicate terminal lemma result')
        results[name] = {'mode': mode, 'status': status, 'steps': int(steps)}
    require(set(results) == set(contract.by_name), 'terminal query inventory differs')
    for name, query in contract.by_name.items():
        require(results[name]['mode'] == query.mode, 'query mode differs')
        if query.reusable:
            require(results[name]['status'] == 'verified', 'unproved reusable premise: ' + name)
    return results


def load_frontier(root, read):
    archive = read(root / CAPTURE / 'CAPTURE.zip', ARCHIVE_BYTES)
    require(len(archive) == ARCHIVE_BYTES and sha(archive) == ARCHIVE_SHA256, 'retained capture changed')
    manifest = strict_json(read(root / CAPTURE / 'CAPTURE.json', MAX_BYTES))
    require(manifest['archive_sha256'] == ARCHIVE_SHA256 and manifest['archive_bytes'] == ARCHIVE_BYTES,
            'capture metadata differs')
    members = manifest['members']
    require(type(members) is dict and len(members) <= 512, 'capture inventory differs')
    selected = []
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        infos = zipped.infolist()
        require(len(infos) == len(members) and len({v.filename for v in infos}) == len(infos)
                and set(zipped.namelist()) == set(members), 'duplicate, omitted or extra capture members')
        require(sum(v.file_size for v in infos) <= 64 * 1024 * 1024, 'capture expansion exceeds bound')
        for info in infos:
            path = PurePosixPath(info.filename)
            require(not path.is_absolute() and '..' not in path.parts and '\\' not in info.filename
                    and not stat.S_ISLNK(info.external_attr >> 16) and not info.is_dir()
                    and info.file_size <= MAX_BYTES, 'unsafe capture member')
            data = zipped.read(info)
            expected = members[info.filename]
            require(len(data) == expected['bytes'] and sha(data) == expected['sha256'], 'capture member differs')
            if sha(data) == MODEL_SHA256:
                selected.append((info.filename, data))
    require(selected, 'current complete frontier absent')
    # Copies of exactly the same certificate are harmless; choose a stable path.
    selected.sort(key=lambda item: item[0])
    require(all(data == selected[0][1] for _, data in selected), 'ambiguous frontier')
    source = selected[0][1]
    contract = theory(source)
    require(contract.by_name[ORIGIN].formula == contract.by_name[ORIGINAL_ORIGIN].formula,
            'phase-root origin changed the original proposition')
    require(len(contract.queries) == QUERY_COUNT and set(GOALS) <= set(contract.by_name), 'research query contract differs')
    return selected[0][0], source, contract



def run(output):
    from bounded_process import capture_output
    from evidence_io import read_regular_snapshot
    from formal_toolchain_contract import verify_installed
    from continuity_recovery_proof import prover_environment, write_json

    def read(path, limit=MAX_BYTES):
        return read_regular_snapshot(path, maximum=limit, label='multi-epoch input').data

    output = output.absolute()
    require(output.resolve() == output, 'research output must be canonical')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'schema_version': 1, 'scope': 'unchanged symbolic research model only',
              'release_claim_eligible': False, 'selected_theorem_verified': False,
              'resource_limits': {'process_seconds': TIMEOUT, 'heap_gib': HEAP_GIB, 'workers': 1,
                                  'search_depth': DEPTH, 'derivation_seconds': 60},
              'executions': []}
    try:
        verify_installed('tamarin')
        member, source_data, original_contract = load_frontier(ROOT, read)
        report.update(archive_sha256=ARCHIVE_SHA256, source_member=member,
                      frontier_sha256=MODEL_SHA256, source_query_count=len(original_contract.queries))
        source = output / 'original.spthy'
        source.write_bytes(source_data)
        counter = 0

        def execute(data, label, selected=None):
            nonlocal counter
            counter += 1
            prefix = output / f'{counter:02}-{label}'
            source = prefix.with_suffix('.input.spthy')
            certificate = prefix.with_suffix('.proof.spthy')
            source.write_bytes(data)
            contract = theory(data)
            command = ['tamarin-prover', str(source), '--derivcheck-timeout=60', '--quit-on-warning',
                       '--output=' + str(certificate)]
            if selected:
                require(selected in contract.by_name, 'unknown selected theorem')
                require([n for n in contract.by_name if n.startswith(selected)] == [selected], 'ambiguous selected theorem')
                command += ['--prove=' + selected, '--heuristic=i', '--bound=' + str(DEPTH)]
            command += ['+RTS', '-N1', '-M12G', '-c100', '-s', '-RTS']
            row = {'label': label, 'argv': command, 'input_sha256': sha(data), 'search': selected is not None,
                   'selected': selected, 'accepted_execution': False}
            report['executions'].append(row)
            write_json(prefix.with_suffix('.started.json'), row)
            started = time.monotonic()
            try:
                result = capture_output(command, timeout_seconds=TIMEOUT, maximum_stdout_bytes=16 * 1024 * 1024,
                                        maximum_stderr_bytes=16 * 1024 * 1024, environment=prover_environment())
                prefix.with_suffix('.stdout').write_bytes(result.stdout)
                prefix.with_suffix('.stderr').write_bytes(result.stderr)
                row.update(returncode=result.returncode, elapsed_seconds=time.monotonic() - started,
                           stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr))
                require(result.returncode == 0, 'prover process failed: ' + label)
                require(not re.search(rb'warning|invalid proof|wellformedness check failed', result.stderr, re.I),
                        'prover emitted warning or invalid-proof diagnostics')
                produced = read(certificate)
                require(read(source) == data, 'prover input changed')
                require(theory(produced) == contract, 'operational rules or query contract changed')
                results = inventory(result.stdout, source, certificate, contract)
                row.update(output_sha256=sha(produced), results=results, accepted_execution=True)
                return produced, results
            except BaseException as error:
                row.update(elapsed_seconds=time.monotonic() - started,
                           failure={'type': type(error).__name__, 'message': str(error)})
                raise
            finally:
                write_json(prefix.with_suffix('.terminal.json'), row)

        current, results = execute(source_data, 'baseline-replay')
        report['baseline_replayed'] = True
        goal = ORIGIN
        if results[goal]['status'] != 'verified':
            candidate, candidate_results = execute(current, 'origin-search', goal)
            # A zero exit code is not a proof. Independently replay the entire
            # resulting tree and preserve every query and reusable dependency.
            current, results = execute(candidate, 'origin-replay')
            require(candidate_results == results, 'search/replay theorem results differ')
        complete = results[goal]['status'] == 'verified'
        report.update(selected_theorem=goal, selected_theorem_verified=complete,
                      final_results=results, final_certificate_sha256=sha(current),
                      main_multi_epoch_secrecy_verified=False)
        return complete
    except BaseException as error:
        report['failure'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        write_json(output / 'RESULT.json', report)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    raise SystemExit(0 if run(arguments.output) else 1)
