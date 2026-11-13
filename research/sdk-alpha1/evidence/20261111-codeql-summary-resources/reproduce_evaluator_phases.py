"""Reproduce matched predicate intervals; unmatched starts are not a completion claim."""

from pathlib import Path
import zipfile, collections, re, json, datetime, hashlib
import argparse
parser = argparse.ArgumentParser(description='Reproduce the phase observations from two authenticated workflow ZIPs.')
parser.add_argument('--archives', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = args.archives
pins = {'13813588831': (25584177, '43768e3f4346d2ca169ae2f9bc23f631d56a14dd30e51927005b35a64b1cc05e'), '13813748616': (25627939, 'b5a7f3f90b7c40b5abf68e62d7007458a8692c3a9b358c33eb5f02d9559d5a2f')}
for artifact, (size, digest) in pins.items():
    archive_path = root / (artifact + '.zip')
    if archive_path.stat().st_size != size:
        raise ValueError('artifact byte count differs: ' + artifact)
    with archive_path.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
            raise ValueError('artifact digest differs: ' + artifact)
output = {}
for arm, aid in [('heap-1536', '13813588831'), ('heap-2048', '13813748616')]:
    stages = {}
    iterations = {}
    starts = {}
    timing = collections.Counter()
    rowmax = {}
    count = collections.Counter()
    completed = []
    events = []
    evictions = collections.Counter()
    mempause = collections.Counter()
    first = None
    with zipfile.ZipFile(root / (aid + '.zip')) as z:
        n = next((n for n in z.namelist() if re.match('evaluator/execute-queries-.*\\.log$', n)))
        for raw in z.open(n):
            line = raw.decode('utf8', 'strict').rstrip()
            if not line.startswith('['):
                continue
            m = re.match('\\[([0-9-]{10} [0-9:]{8})\\]', line)
            if not m:
                continue
            stamp = datetime.datetime.strptime(m[1], '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp()
            if first is None:
                first = stamp
            if 'Pausing evaluation to evict ' in line:
                evictions[str(int((stamp - first) // 3600))] += 1
            if 'Unpausing evaluation:' in line:
                for number, unit, category in re.findall('([0-9.]+)([KMGT]?i?)B (in memory written to disk|forgotten|UNREACHABLE|VITAL)', line):
                    mempause[category] += float(number) * {'': 1, 'Ki': 2 ** 10, 'Mi': 2 ** 20, 'Gi': 2 ** 30, 'Ti': 2 ** 40}[unit]
            if 'TaintReach::TaintReachFlow::Flow::Stage' not in line:
                continue
            m = re.search('Starting to evaluate predicate (.+?)@[^( ]+ \\(iteration (\\d+)\\)', line)
            if m:
                predicate = m[1]
                iteration = int(m[2])
                stage = re.search('Stage(\\d+)::', predicate)[1]
                key = predicate.rsplit('/', 1)[0]
                starts[key] = (stamp, iteration)
                stages.setdefault(stage, {'first_timestamp': stamp, 'last_timestamp': stamp, 'max_iteration': 0})
                stages[stage]['last_timestamp'] = stamp
                stages[stage]['max_iteration'] = max(stages[stage]['max_iteration'], iteration)
                iterations.setdefault(stage, {}).setdefault(str(iteration), stamp)
            m = re.search('- (.+)_delta has (\\d+) rows', line)
            if m:
                key = m[1]
                rows = int(m[2])
                rowmax[key] = max(rowmax.get(key, 0), rows)
                if key in starts:
                    start, it = starts.pop(key)
                    duration = stamp - start
                    timing[key] += duration
                    count[key] += 1
                    completed.append({'key': key, 'iteration': it, 'duration_seconds': duration, 'delta_rows': rows, 'started_epoch_seconds': start, 'finished_epoch_seconds': stamp})

    def compact(k):
        return k.replace('TaintReach::TaintReachFlow::Flow::', '')
    data = {'start_epoch_seconds': first, 'stages': stages, 'eviction_counts_by_hour': dict(evictions), 'logical_unpause_GiB': {k: round(v / 2 ** 30, 3) for k, v in mempause.items()}, 'top_predicate_delta_durations': [{'predicate': k, 'seconds': v, 'completed_iterations': count[k], 'max_delta_rows': rowmax.get(k)} for k, v in timing.most_common(15)], 'longest_completed_delta_operations': sorted(completed, key=lambda x: x['duration_seconds'], reverse=True)[:15], 'unmatched_start_records': [{'predicate': k, 'started_epoch_seconds': v[0], 'iteration': v[1]} for k, v in starts.items()], 'iteration_start_seconds': {stage: {it: ts - first for it, ts in its.items()} for stage, its in iterations.items()}}
    output[arm] = data
args.output.write_text(json.dumps(output, indent=2) + '\n')
