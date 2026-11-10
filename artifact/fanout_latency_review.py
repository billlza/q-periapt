"""Replay the fixed, uninstrumented account-send latency experiment."""
import argparse
import csv
import io
import json
import hashlib
import math
from pathlib import Path, PurePosixPath
import re
import statistics
import tarfile

from bounded_process import capture_output
from evidence_io import parse_strict_json_bytes, read_regular_snapshot
from rust_sdk_profile import require, write_json

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'research/continuity-identity-candidate/'
BASELINE = 'b47eb5417d3c25cb7bd05dd91e56ad73777c56fb'

TEST = 'durable::messages::tests::fanout::account_fanout_payload_boundaries_match_individual_traffic_and_restart'
BLOCKS = 200
WARMUPS = 2
MAX_LOG = 16 * 1024**2
SAMPLE = re.compile(r'^fanout_path_sample same_account=(false|true) sample=(\d+) plaintext=(\d+) ad=(\d+) recipients=(\d+) elapsed_ns=(\d+)$', re.M)


def unpack_source(data: bytes) -> dict[str, bytes]:
    require(len(data) <= 16 * 1024**2, 'source archive exceeds bound')
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts and '\\' not in member.name,
                    'invalid source archive path')
            if member.isdir():
                continue
            require(member.isfile() and member.name.startswith(PREFIX), 'non-regular source member')
            relative = member.name.removeprefix(PREFIX)
            require(relative and str(PurePosixPath(relative)) == relative and relative not in files
                    and member.size <= 4 * 1024**2, 'duplicate or oversized source member')
            total += member.size
            require(total <= 16 * 1024**2, 'expanded source archive exceeds bound')
            stream = archive.extractfile(member)
            require(stream is not None, 'missing source member body')
            with stream:
                files[relative] = stream.read()
            require(len(files[relative]) == member.size, 'source member length differs')
            require(len(files) <= 1024, 'too many source files')
    require(sum(name.endswith('.rs') for name in files) == 373, 'candidate Rust source inventory differs')
    return files


def snapshot(path):
    return read_regular_snapshot(Path(path), maximum=MAX_LOG, label='fanout experiment').data


def document(path):
    return parse_strict_json_bytes(snapshot(path), label='fanout experiment')


def samples(stdout: bytes, stderr: bytes, filtered: int) -> list[dict]:
    text, diagnostics = stdout.decode(), stderr.decode()
    require(text.count(f'test {TEST} ... ok\n') == 1, 'selected test did not pass exactly once')
    summary = f'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out;'
    require(text.count(summary) == 1 and text.count('test result:') == 1, 'test census differs')
    require(re.search(r'(?mi)^\s*(warning:|error:)', text + diagnostics) is None, 'diagnostic failure')
    found = SAMPLE.findall(diagnostics)
    require(len(found) == 12, 'incomplete timing sample set')
    rows = []
    for index, row in enumerate(found):
        same, position, payload, ad, recipients, elapsed = row
        position, payload, ad, recipients, elapsed = map(int, (position, payload, ad, recipients, elapsed))
        require(same == ('false' if index < 6 else 'true') and position == index % 6,
                'sample identity/order differs')
        require((payload, ad) == ((0, 0), (1024, 32), (16384, 1024))[position % 3]
                and recipients == 2 and 0 < elapsed <= 90 * 10**9, 'sample workload/timing differs')
        rows.append(dict(same_account=same == 'true', position=position, plaintext=payload,
                         ad=ad, elapsed_ns=elapsed))
    return rows


def catalog(stdout: bytes) -> list[str]:
    names = re.findall(r'^(\S+): test$', stdout.decode(), re.M)
    require(TEST in names and len(names) == len(set(names)), 'test catalog differs')
    return sorted(names)


def identities(values: dict) -> None:
    require(set(values) == {'baseline', 'candidate'} and all(
        isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in values.values())
        and len(set(values.values())) == 2, 'binaries are missing, substituted or identical')


def review(root: Path, output: Path, expected_head: str) -> dict:
    run = document(root / 'EXECUTION.json')
    require(run['completed'] is True and run['blocks'] == BLOCKS and run['warmups'] == WARMUPS,
            'experiment did not complete the fixed protocol')
    require(run['source']['baseline'] == BASELINE and run['source']['candidate'] == expected_head
            and re.fullmatch('[0-9a-f]{40}', expected_head), 'source revision differs')
    for variant, ref in (('baseline', BASELINE), ('candidate', expected_head)):
        executed = capture_output(['git', '-C', str(ROOT), 'archive', '--format=tar', ref, '--', PREFIX],
                                  timeout_seconds=60, maximum_stdout_bytes=MAX_LOG,
                                  maximum_stderr_bytes=1024**2)
        require(executed.returncode == 0 and not executed.stderr, 'independent source archive failed')
        expected = unpack_source(executed.stdout)
        archived = unpack_source(snapshot(root / ('source-' + variant + '.stdout')))
        require(expected == archived and {p: hashlib.sha256(v).hexdigest() for p, v in expected.items()}
                == run['source']['files'][variant], 'source archive differs from exact Git revision')
    identities(run['binary_sha256'])
    require(run['test'] == TEST, 'selected test changed')
    names = catalog(snapshot(root / 'catalog-baseline.stdout'))
    require(catalog(snapshot(root / 'catalog-candidate.stdout')) == names, 'variant test catalogs differ')
    filtered = len(names) - 1
    require(run['filtered_tests'] == filtered, 'filtered test count differs')
    rows = []
    for warmup, count in ((True, WARMUPS), (False, BLOCKS)):
        for block in range(count):
            order = ('baseline', 'candidate') if block % 2 == 0 else ('candidate', 'baseline')
            for position, variant in enumerate(order):
                label = f'{"warmup" if warmup else "block"}-{block:03}-{variant}'
                command = document(root / (label + '.json'))
                require(command['returncode'] == 0 and command['variant'] == variant
                        and command['block'] == block and command['warmup'] is warmup
                        and command['order'] == position, 'execution identity/order differs')
                require(command['argv'] == [run['binaries'][variant], '--exact', TEST,
                                           '--nocapture', '--test-threads=1'], 'test command differs')
                parsed = samples(snapshot(root / (label + '.stdout')),
                                 snapshot(root / (label + '.stderr')), filtered)
                if not warmup:
                    rows.extend(dict(block=block, variant=variant, **row) for row in parsed)
    require(len(rows) == BLOCKS * 24, 'sample count differs')
    table = []
    for same in (False, True):
        for position in range(6):
            variants = {v: [r['elapsed_ns'] for r in rows if r['variant'] == v
                           and r['same_account'] == same and r['position'] == position]
                        for v in ('baseline', 'candidate')}
            require(all(len(v) == BLOCKS for v in variants.values()), 'workload count differs')
            row = dict(same_account=same, position=position, samples_per_variant=BLOCKS)
            for variant, values in variants.items():
                ordered = sorted(values)
                row[variant + '_median_ms'] = statistics.median(values) / 10**6
                for name, q in (('p95', .95), ('p99', .99)):
                    row[variant + '_' + name + '_ms'] = ordered[math.ceil(q * BLOCKS) - 1] / 10**6
                row[variant + '_max_ms'] = max(values) / 10**6
            row['paired_median_change_percent'] = 100 * (statistics.median(
                c / b for b, c in zip(variants['baseline'], variants['candidate'])) - 1)
            table.append(row)
    csv_path = output.with_suffix('.csv')
    with csv_path.open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    result = dict(completed=True, source=run['source'], host=run['host'], samples=table,
                  blocks=BLOCKS, timed_operations=len(rows), binary_sha256=run['binary_sha256'],
                  raw_csv_sha256=hashlib.sha256(snapshot(csv_path)).hexdigest(),
                  p95_increased_positions=sum(r['candidate_p95_ms'] > r['baseline_p95_ms'] for r in table),
                  interpretation='Observed nearest-rank quantiles at each original workload position; '
                  'no pooling, sample exclusion, confidence interval, speed threshold or release admission. '
                  'Successful execution is not a performance improvement claim.')
    write_json(output, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-head', required=True)
    args = parser.parse_args()
    result = review(args.input, args.output, args.expected_head)
    print(json.dumps(dict(completed=result['completed'], timed_operations=result['timed_operations'],
                          p95_increased_positions=result['p95_increased_positions'])))
