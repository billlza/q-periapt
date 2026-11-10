"""Independently inspect a retained allocation-arm artifact; never mark partial runs complete."""
from __future__ import annotations

import argparse
from collections import Counter, deque
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

import codeql_summary_control as control


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unpack(archive: Path, output: Path, digest: str, size: int) -> list[dict]:
    assert archive.stat().st_size == size
    assert control.sha(archive) == digest
    output.mkdir(mode=0o700)
    inventory = []
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        assert 0 < len(members) <= 8192
        assert len({item.filename for item in members}) == len(members)
        assert sum(item.file_size for item in members) <= 4 * 1024**3
        for item in members:
            relative = PurePosixPath(item.filename)
            assert relative.parts and not relative.is_absolute() and '..' not in relative.parts
            assert '\\' not in item.filename
            assert item.file_size <= 2 * 1024**3
            mode = item.external_attr >> 16
            assert not stat.S_ISLNK(mode)
            target = output.joinpath(*relative.parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            assert stat.S_IFMT(mode) in (0, stat.S_IFREG)
            target.parent.mkdir(parents=True, exist_ok=True)
            hasher = hashlib.sha256()
            count = 0
            with source.open(item) as stream, target.open('xb') as destination:
                while chunk := stream.read(1024**2):
                    count += len(chunk)
                    assert count <= item.file_size
                    hasher.update(chunk)
                    destination.write(chunk)
            assert count == item.file_size
            target.chmod(0o400)
            inventory.append({'path':relative.as_posix(), 'bytes':count, 'sha256':hasher.hexdigest()})
    return inventory


def check_decoded_results(evidence: Path, report: dict, prefix: str, field: str) -> dict:
    values = report.get(field)
    if not isinstance(values, dict):
        return {'present':False, 'count':0, 'reason':'No decoded result inventory in arm receipt.'}
    checked = {}
    for query, identity in sorted(values.items()):
        bqrs = evidence / (prefix+'bqrs') / Path(query).with_suffix('.bqrs')
        assert control.sha(bqrs) == identity['bqrs_sha256'], query
        stem = prefix + Path(query).stem + '-decoded'
        decoded = control.read_json(evidence / (stem+'.stdout'))
        command = control.read_json(evidence / (stem+'.json'))
        assert command['returncode'] == 0
        assert command['command'][1:4] == ['bqrs','decode','--format=json']
        admitted_suffix = (Path(prefix+'bqrs') / Path(query).with_suffix('.bqrs')).as_posix()
        assert command['command'][-1].endswith('/'+admitted_suffix)
        for table in decoded.values():
            assert isinstance(table, dict) and isinstance(table.get('tuples'), list)
            table['tuples'].sort(key=lambda row:json.dumps(row,sort_keys=True,separators=(',',':')))
        semantic = control.canonical_sha(decoded)
        assert semantic == identity['semantic_sha256'], query
        checked[query] = {'bqrs_sha256':identity['bqrs_sha256'], 'semantic_sha256':semantic,
                          'tuple_counts':{key:len(table['tuples']) for key,table in decoded.items()}}
    return {'present':True, 'count':len(checked), 'queries':checked}


def observe(evidence: Path, report: dict, output: Path) -> dict:
    declared = report.get('observations', {})
    all_counts = Counter()
    started, finished = set(), set()
    iterations = {}
    events = []
    tail = deque(maxlen=40)
    non_evictions = deque(maxlen=80)
    last_predicate = None
    largest_fwd_flow0 = None
    first_timestamp = last_timestamp = None
    def query_name(value: str) -> str:
        matched = re.search(r'(queries/(?:diagnostics|security|summary|telemetry)/.+)$', value)
        assert matched is not None, value
        return matched[1]
    for item in declared.get('logs', []):
        path = evidence/item['path']
        assert path.stat().st_size == item['bytes'] and control.sha(path) == item['sha256']
        with path.open('rb') as stream:
            for raw in stream:
                text = raw.decode('utf-8',errors='replace')
                all_counts['lines'] += 1
                tail.append(text)
                if text.startswith('[') and len(text)>20 and text[20]==']':
                    first_timestamp = first_timestamp or text[1:20]
                    last_timestamp = text[1:20]
                if 'Pausing evaluation to ' in text:
                    all_counts['pause_count'] += 1
                if 'Pausing evaluation to evict ' in text:
                    all_counts['eviction_pause_count'] += 1
                elif 'Unpausing evaluation:' not in text:
                    non_evictions.append(text)
                if '[PROGRESS]' in text:
                    events.append(text)
                    match=re.search(r'Starting evaluation of (.+)\.ql\.',text)
                    if match:
                        all_counts['query_starts'] += 1
                        started.add(query_name(match[1]))
                    match=re.search(r'Evaluation done; writing results to (.+)\.bqrs\.',text)
                    if match:
                        all_counts['query_completions'] += 1
                        finished.add(query_name(match[1]))
                if 'TaintReach::' in text:
                    match=re.search(r'Stage([0-9])::.*\(iteration ([0-9]+)\)',text)
                    if match:
                        stage,iteration=match.groups()
                        iterations[stage]=max(iterations.get(stage,0),int(iteration))
                        if 'Starting to evaluate predicate ' in text:
                            last_predicate=text.strip()
                    if '::fwdFlow0/' in text and '_delta has ' in text:
                        match=re.search(r'_delta has ([0-9]+) rows',text)
                        if match and (largest_fwd_flow0 is None or int(match[1])>largest_fwd_flow0['rows']):
                            largest_fwd_flow0={'rows':int(match[1]),'event':text.strip()}
    for key in ('pause_count','eviction_pause_count','query_starts','query_completions'):
        assert all_counts[key] == declared.get(key), (key,all_counts[key],declared.get(key))
    assert iterations == declared['max_taint_stage_iterations']
    (output/'evaluator-progress.log').write_text(''.join(events))
    (output/'evaluator-last-non-eviction.log').write_text(''.join(non_evictions))
    (output/'evaluator-tail.log').write_text(''.join(tail))
    return {'counts':dict(all_counts),'max_taint_stage_iterations':iterations,
            'started_queries':sorted(started),'completed_queries':sorted(finished),
            'remaining_queries':sorted(started-finished),
            'first_timestamp':first_timestamp,'last_timestamp':last_timestamp,
            'last_taint_predicate':last_predicate,'largest_fwd_flow0_delta':largest_fwd_flow0}


def audit(args: argparse.Namespace) -> dict:
    root=args.output
    inventory=unpack(args.archive,root/'artifact',args.sha256,args.bytes)
    matches=list((root/'artifact').rglob('RESULT.json'))
    assert len(matches)==1
    evidence=matches[0].parent
    report=control.read_json(matches[0])
    profile=report['profile']
    assert profile == args.profile
    assert report['schema']==1 and report['kind']=='qperiapt.codeql_summary_control'
    assert report['source']==control.SOURCE
    assert report['input_identity']==control.INPUT_IDENTITY
    database_inputs=control.read_json(evidence/'DATABASE_INPUTS.json')
    assert control.input_identity(database_inputs)==control.INPUT_IDENTITY
    assert control.canonical_sha({'files':database_inputs['files'],'directories':database_inputs['directories']})==control.INPUT_IDENTITY['database_inventory_sha256']
    cache={key:value for key,value in database_inputs['files'].items() if key.startswith('db-rust/default/cache/')}
    assert len(cache)==1437 and control.canonical_sha(cache)==control.INPUT_IDENTITY['cache_inventory_sha256']
    archive_shape=control.read_json(evidence/'DATABASE_ARCHIVE.json')
    assert archive_shape['inner_bytes']==control.INNER_BYTES and archive_shape['inner_sha256']==control.INNER_SHA256
    assert len(archive_shape['metadata_candidates'])==1 and archive_shape['metadata_candidates'][0]['truncated'] is False
    assert sha(archive_shape['metadata_candidates'][0]['text'].encode())==control.INPUT_IDENTITY['metadata_sha256']
    assert report['cache_scope']==control.CACHE_SCOPE
    assert report['configuration']==control.configuration(profile)
    assert report['experiment_commit']==args.experiment_commit
    assert report['ram_resolution']==control.SOURCE_ALLOCATION
    assert report['release_claim_eligible'] is False and report['sarif_published'] is False
    tool=report['tool_identity']
    assert (evidence/'version.stdout').read_bytes().strip()==control.CLI_VERSION.encode()
    for key,expected in {'codeql_version':control.CLI_VERSION,'query_pack':control.QUERY_VERSION,
                         'tool_bundle_sha256':control.TOOL_BUNDLE_SHA256,'tool_bundle_bytes':control.TOOL_BUNDLE_BYTES,
                         'codeql_sha256':control.CODEQL_LAUNCHER_SHA256}.items():
        assert tool[key]==expected,(key,tool[key],expected)
    assert control.sha(control.QUERY_MANIFEST)==control.MANIFEST_SHA256
    control.validate_query_inventory(report['query_hashes'],control.read_json(control.QUERY_MANIFEST))
    assert set(report['compiled_query_hashes'])==set(report['query_hashes'])
    assert control.canonical_sha(report['compiled_query_hashes'])==control.COMPILED_INVENTORY_SHA256
    heap,native=control.PROFILES[profile]
    assert report['jvm_admission']=={'max_heap_bytes_observed':[heap*1024**2],'codeql_version':control.CLI_VERSION}
    control.validate_observations(report['observations'],profile)
    observed_heap=[]
    for name in ('query.stdout','query.stderr'):
        observed_heap.extend(int(x) for x in re.findall(rb'(?m)^\s*(?:size_t|uintx) MaxHeapSize\s*:?=\s*([0-9]+)\s',(evidence/name).read_bytes()))
    assert observed_heap==[heap*1024**2]
    command=report['query_command']
    output_arg=[Path(arg.removeprefix('--output=')) for arg in command if arg.startswith('--output=')]
    assert len(output_arg)==1
    remote_root=output_arg[0].parent
    assert command==control.query_command(Path(command[0]),remote_root/'database',remote_root,profile)
    assert report['evaluation']['command']==command
    assert report['evaluation']==control.read_json(evidence/'query.json')
    observed=observe(evidence,report,root)
    retained=check_decoded_results(evidence,report,'retained-','retained_results')
    fresh=check_decoded_results(evidence,report,'fresh-','results')
    assert retained['count']==38
    semantic_relation='not available: fresh decoded results are absent'
    if fresh['present']:
        control.validate_retained_results(report['retained_results'],report['results'],report['query_hashes'])
        semantic_relation='all 38 retained query semantics match new results'
    result={'artifact_id':args.artifact_id,'artifact_sha256':args.sha256,'artifact_bytes':args.bytes,
        'profile':profile,'experiment_commit':args.experiment_commit,
        'source_and_tool_identity_match_independent_pins':True,
        'configuration':report['configuration'],'evaluation':report['evaluation'],
        'completed':report['completed'],'failure':report.get('failure'),
        'actual_jvm_max_heap_bytes':observed_heap,'independent_peak_rss_sample':None,
        'observations':observed,'retained_results':retained,'fresh_results':fresh,
        'retained_to_fresh_semantics':semantic_relation,'inventory':inventory,
        'decode_verification_scope':'Recomputed retained BQRS and decoded-JSON hashes and verified decode receipts; no new local CodeQL decode execution.',
        'report_path':str(matches[0])}
    (root/'AUDIT.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--sha256',required=True)
    parser.add_argument('--bytes',type=int,required=True)
    parser.add_argument('--artifact-id',type=int,required=True)
    parser.add_argument('--profile',choices=tuple(control.PROFILES),required=True)
    parser.add_argument('--experiment-commit',required=True)
    args=parser.parse_args()
    args.output.mkdir(mode=0o700)
    result=audit(args)
    print(json.dumps({key:result[key] for key in ('profile','completed','configuration','evaluation','failure','retained_to_fresh_semantics')},indent=2))
    print(json.dumps(result['observations'],indent=2))
