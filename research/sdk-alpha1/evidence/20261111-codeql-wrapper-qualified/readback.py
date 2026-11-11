"""Read original hosted bytes; no extraction, compilation or query execution."""
from pathlib import Path, PurePosixPath
import collections
import hashlib
import json
import re
import shutil
import stat
import subprocess
import zipfile

ROOT = Path('/workspace/scratch/qperiapt-recovery-20261111')
HERE = ROOT / 'third-wrapper-qualified/review'
REPO = ROOT / 'evidence-current'
OUT = REPO / 'research/sdk-alpha1/evidence/20261111-codeql-wrapper-qualified'
SOURCE = 'b5185165283880527a54289b47397fde78ddf553'
WORKFLOW = '74101a672c945d0e952e283a4750748a8da27065'
PREFIX = 'qperiapt-codeql-wrapper-fixture/evidence/'
ARTIFACT_SHA = '8b98728022af8d3a51708e6ac497f1f6184c8a1bb1f33c6f3b80d1bebc1701c3'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def identity(data):
    return {'bytes': len(data), 'sha256': sha(data)}

def canonical(data):
    return sha(json.dumps(data, sort_keys=True, separators=(',', ':')).encode())

def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def source(path):
    return subprocess.check_output(['git', 'show', SOURCE + ':' + path], cwd=REPO)

assert not OUT.exists()
OUT.mkdir(parents=True)
archive = (ROOT / 'third-wrapper-qualified/artifact.zip').read_bytes()
assert len(archive) == 3741772 and sha(archive) == ARTIFACT_SHA
artifacts = json.loads((HERE / 'ARTIFACT_API.json').read_bytes())['artifacts']
metadata, = [value for value in artifacts if value['id'] == 13867679562]
assert metadata['size_in_bytes'] == len(archive)
assert metadata['digest'] == 'sha256:' + ARTIFACT_SHA
assert metadata['workflow_run']['id'] == 43048934821
assert metadata['workflow_run']['head_sha'] == WORKFLOW
jobs = json.loads((HERE / 'JOBS_API.json').read_bytes())['jobs']
job, = [value for value in jobs if value['id'] == 130620449051]
assert job['head_sha'] == WORKFLOW and job['conclusion'] == 'success'
assert next(s for s in job['steps'] if s['name'] == 'Verify the fixture method and workflow contracts')['conclusion'] == 'success'
assert next(s for s in job['steps'] if s['name'].startswith('Extract the frozen fixture'))['conclusion'] == 'success'
job_log = (HERE / 'job.log').read_bytes()
assert b'Ran 9 tests in 0.004s' in job_log
assert b'CodeQL query completions observed: 39/39' in job_log
assert b'CodeQL query completions observed: 39/39' in job_log
(OUT / 'artifact.zip').write_bytes(archive)
for name in ('ARTIFACT_API.json', 'JOBS_API.json', 'job.log'):
    shutil.copyfile(HERE / name, OUT / name)

with zipfile.ZipFile(ROOT / 'third-wrapper-qualified/artifact.zip') as bundle:
    infos = bundle.infolist()
    assert len(infos) == len({x.filename for x in infos}) == 257
    assert sum(x.file_size for x in infos) < 64 * 1024**2
    members = {}
    for item in infos:
        path = PurePosixPath(item.filename)
        assert not path.is_absolute() and '..' not in path.parts and '\\' not in item.filename
        assert str(path) == item.filename and not item.is_dir()
        assert stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG)
        members[item.filename] = {**identity(bundle.read(item)), 'compressed_bytes': item.compress_size, 'crc32': f'{item.CRC:08x}'}
    save('ZIP_MEMBERS.json', members)
    assert sum(name.endswith('.bqrs') for name in members) == 78
    assert bundle.read('qperiapt-wrapper-source.txt').decode().splitlines() == [WORKFLOW, 'edae9dc91aa65f58f403a9ef8112bd73201e09e7']
    selected = ('SOURCE_CONTRACT.json', 'EVALUATOR_OBSERVATIONS.json', 'QUERY_MEMORY.json',
                'analyze.json', 'analyze.started.json', 'analyze.stderr', 'analyze.stdout',
                'extract.json', 'extract.started.json', 'extract.stdout', 'extract.stderr',
                'METHOD.json', 'FIXTURE_WRAPPER_RESULT.json', 'ANALYSIS_PLAN_AFTER.json', 'ANALYSIS_RUNTIME.json',
                'SUMMARY_PLAN.json', 'DATABASE_INPUTS.json', 'RESOURCE_OBSERVATION_STATUS.json',
                'COMPILER_IDENTITY.json', 'OFFICIAL_DOWNLOADS.json', 'results.sarif',
                'QUERY_COMPLETIONS.json', 'FRESH_RESULTS.json', 'PACK_BEFORE.json',
                'decode-summary.json', 'decode-summary.stdout', 'decode-summary.stderr',
                'INITIAL_DATABASE_FILES.json.gz')
    (OUT / 'original').mkdir()
    for name in selected:
        (OUT / 'original' / name).write_bytes(bundle.read(PREFIX + name))
    get = lambda name: json.loads(bundle.read(PREFIX + name))
    contracts = get('SOURCE_CONTRACT.json')
    assert len(contracts) == 12
    source_verification = {}
    for name, expected in contracts.items():
        actual = source('artifact/' + name)
        retained = bundle.read(PREFIX + 'source-' + name.replace('.', '-') + '.stdout')
        assert actual == retained and identity(actual) == expected
        source_verification[name] = expected
    manifest_bytes = source('artifact/codeql_rust_queries.json')
    queries = json.loads(manifest_bytes)['queries']
    assert len(queries) == 39
    expected_results = {'codeql/rust-queries/' + name[:-3] + '.bqrs' for name in queries}
    assert len(expected_results) == 39
    stderr = bundle.read(PREFIX + 'analyze.stderr')
    expression = r'\[([1-9][0-9]?)/39 eval (?:[0-9]{1,6}(?:\.[0-9]{1,3})?(?:ms|h|m|s)){1,3}\] Evaluation done; writing results to ([^\r\n]+\.bqrs)\.'
    completed = []
    completion_events = []
    for index, line in enumerate(stderr.decode().splitlines(), 1):
        match = re.fullmatch(expression, line)
        if match:
            assert 1 <= int(match[1]) <= 39 and match[2] in expected_results
            completed.append(match[2])
            completion_events.append({'line': index, 'text': line, 'query_result': match[2], 'counter': int(match[1])})
    assert len(completed) == len(set(completed)) == 39 and set(completed) == expected_results
    assert sorted(event['counter'] for event in completion_events) == list(range(1, 40))
    log_name, = [name for name in members if '/execute-queries-' in name]
    log = bundle.read(log_name)
    lines = log.decode().splitlines()
    observations = get('EVALUATOR_OBSERVATIONS.json')
    assert observations['query_starts'] == 39 and observations['query_completions'] == 39
    assert observations['query_compilations'] == 0 and observations['evaluator_start_lines'] == 1
    assert observations['logs'] == [{'path': 'evaluator/' + PurePosixPath(log_name).name, **identity(log)}]
    assert sum('[PROGRESS]' in line and 'Starting evaluation of ' in line for line in lines) == 39
    assert sum('Compiling query plan for ' in line for line in lines) == 0
    assert sum('This is codeql execute queries ' in line for line in lines) == 1
    load_paths = [line.split('] Loaded ', 1)[1][:-1] for line in lines if '[PROGRESS]' in line and '] Loaded ' in line and line.endswith('.qlx.')]
    pack = '/home/runner/work/_temp/qperiapt-codeql-wrapper-fixture/analysis-plan/tool/codeql/qlpacks/codeql/rust-queries/0.1.44/'
    assert sorted(load_paths) == sorted(pack + name[:-3] + '.qlx' for name in queries)
    assert sorted(load_paths) == sorted(observations['precompiled_query_loads'])
    internal_events = []
    for index, line in enumerate(lines, 1):
        marker = '[PROGRESS] execute queries> '
        if marker in line:
            match = re.fullmatch(expression, line.split(marker, 1)[1])
            if match:
                internal_events.append({'line': index, 'text': line, 'query_result': match[2]})
    assert len(internal_events) == 39
    missing = sorted(expected_results - {event['query_result'] for event in internal_events})
    assert missing == []
    save('COMPLETION_EVENTS.json', {'stderr': identity(stderr), 'stderr_events': completion_events,
         'internal_log_member': log_name, 'internal_log': identity(log), 'internal_events': internal_events,
         'missing_from_internal_log': missing,
         'diagnosis': 'Both the retained stderr and internal execution log contain the complete admitted completion set in this execution; their observed counts are retained separately.'})
    analysis, extraction, memory, result, decoded_record = (get(name) for name in
        ('analyze.json', 'extract.json', 'QUERY_MEMORY.json', 'FIXTURE_WRAPPER_RESULT.json', 'decode-summary.json'))
    assert analysis['returncode'] == extraction['returncode'] == decoded_record['returncode'] == 0
    assert analysis['source_commit'] == WORKFLOW and analysis['run_id'] == '43048934821' and analysis['maximum_seconds'] == 600
    assert result['status'] == 'complete_equal_summary_valid_sarif'
    assert result['workflow_source_commit'] == WORKFLOW and result['production_source_commit'] == SOURCE
    assert memory['heap_mb'] == 3484 and memory['off_heap_ram_mb'] == 9329 and memory['requested_ram_mb'] == 14000
    assert observations['jvm_heap_mb_arguments'] == [3484] and observations['off_heap_mb_observed'] == [9329]
    assert result['query_memory'] == memory and result['query_threads'] == 4
    assert result['precompiled_query_loads'] == 39 and result['implicit_compilations'] == 0
    completion = get('QUERY_COMPLETIONS.json')
    assert completion == {'schema': 1, 'source': 'analyze.stderr', **identity(stderr), 'queries': sorted(queries)}
    assert result['query_completion_evidence'] == completion
    fresh = get('FRESH_RESULTS.json')
    assert set(fresh) == {name[:-3] + '.bqrs' for name in queries} and len(fresh) == 39
    assert result['fresh_bqrs_count'] == 39
    fresh_verified = {}
    for name, expected in fresh.items():
        evidence_name = PREFIX + 'results/' + name
        database_name = 'qperiapt-codeql-wrapper-fixture/database/results/codeql/rust-queries/' + name
        data = bundle.read(evidence_name)
        assert data == bundle.read(database_name) and identity(data) == expected
        fresh_verified[name] = expected
    import gzip
    initial = json.loads(gzip.decompress(bundle.read(PREFIX + 'INITIAL_DATABASE_FILES.json.gz')))
    inputs = get('DATABASE_INPUTS.json')
    assert len(initial) == inputs['files'] == 6651 and not any(name.endswith('.bqrs') for name in initial)
    assert canonical(initial) == inputs['inventory_sha256'] == result['extracted_database_inventory_sha256']
    pack = get('PACK_BEFORE.json')
    assert len(pack) == 1357 and canonical(pack) == '13705d5f8b164bd69a12219c41a7fe8ba7e304247a4b78d0150c4dd36882d441'
    plan, after, runtime = (get(name) for name in ('SUMMARY_PLAN.json', 'ANALYSIS_PLAN_AFTER.json', 'ANALYSIS_RUNTIME.json'))
    assert after['summary_plan'] == plan == result['summary_plan']
    assert plan['manifest_sha256'] == sha(source('artifact/codeql_summary_projection.json'))
    assert plan['compiler_inputs_digest'] == '6a7530eb694360655ab8331a895c9fcd'
    assert plan['capsule_sha256'] == '5b17fb41cd3c59fea564ec4e9cb49ef586c0ad06ccc3f2445e46b7b5ca8430cb'
    assert plan['query_count'] == 39 and plan['unchanged_other_compiled_queries'] == 38
    assert len(runtime['files']) == 2282 and sum(value['bytes'] for value in runtime['files'].values()) == 231156107
    assert canonical(runtime['files']) == after['tool']['runtime_inventory_sha256'] == '1d61c12cb67e01730a1ec5031aefe669035e52290081dc6822333cb5ab861c90'
    assert result['pack_and_runtime_postchecks_passed'] is True and result['all_fixture_source_members_unchanged'] is True
    assert PREFIX + 'ANALYSIS_PLAN_FAILURE.json' not in members and PREFIX + 'FIXTURE_FAILURE.json' not in members
    method = get('METHOD.json')
    method_bytes = subprocess.check_output(['git', 'show', WORKFLOW + ':artifact/codeql_wrapper_fixture.py'], cwd=REPO)
    assert method['method_source'] == identity(method_bytes)
    sarif = get('results.sarif')
    assert sarif['version'] == '2.1.0' and len(sarif['runs']) == 1
    run = sarif['runs'][0]
    assert run['automationDetails'] == {'id': '/language:rust/'}
    assert run['tool']['driver']['name'] == 'CodeQL' and run['tool']['driver']['semanticVersion'] == '2.27.2'
    assert run['invocations'] and all(invocation['executionSuccessful'] is True for invocation in run['invocations'])
    assert all(note['level'] in ('none', 'note') for invocation in run['invocations'] for note in invocation.get('toolExecutionNotifications', []))
    assert result['sarif'] == identity(bundle.read(PREFIX + 'results.sarif'))
    decoded_bytes = bundle.read(PREFIX + 'decode-summary.stdout')
    baseline = bundle.read(PREFIX + 'retained-summary.stdout')
    assert decoded_bytes == baseline and len(decoded_bytes) == 1185
    assert sha(decoded_bytes) == 'f05f212ce3a9847d01191fb595c9a154aac94a83e33faf6fdc7f85dbb19b259e'
    decoded = json.loads(decoded_bytes)
    assert canonical(decoded) == result['summary_semantic_sha256'] == 'e2582f4726e1866ef348bf49f05d8c70c62afc6ce8a913eb883bf88684101725'
    assert len(decoded['#select']['tuples']) == 29 and len(dict(decoded['#select']['tuples'])) == 29
    assert dict(decoded['#select']['tuples']) == result['summary_values']
    assert result['summary_values']['Taint sources - active'] == 15
    assert result['summary_values']['Taint reach - nodes tainted'] == 106
    assert result['retained_all_baseline_equal'] is True and result['retained_baselines_rerun'] is False
    assert result['summary_decoded'] == identity(decoded_bytes)
    assert result['hosted_profile_receipt_created'] is False and result['three_target_publication_claimed'] is False and result['sarif_uploaded'] is False
    save('READBACK.json', {'schema': 1, 'run_id': 43048934821, 'job_id': 130620449051, 'attempt': 1,
         'workflow_commit': WORKFLOW, 'production_commit': SOURCE, 'workflow_conclusion': 'success',
         'artifact_id': 13867679562, 'artifact': identity(archive), 'source_contract_files_verified': source_verification,
         'wrapper_method_verified': identity(method_bytes),
         'contract_tests': {'tests': 9, 'seconds': 0.004, 'passed': True},
         'analysis': analysis, 'extraction': extraction, 'decode': decoded_record, 'memory': memory,
         'stderr_distinct_completion_count': 39, 'stderr_complete_frozen_query_set': True,
         'completion_receipt': completion,
         'internal_starts': 39, 'internal_completions': len(internal_events), 'internal_precompiled_loads': 39,
         'implicit_compilations': 0, 'evaluator_invocations': 1, 'internal_missing_completion_paths': missing,
         'runtime': {'files': 2282, 'bytes': 231156107, 'inventory_sha256': canonical(runtime['files'])},
         'pack_inventory_files': 1357, 'pack_inventory_sha256': canonical(pack),
         'initial_database_files': len(initial), 'initial_database_inventory_sha256': canonical(initial), 'initial_bqrs_count': 0,
         'projection_before_after_equal': True, 'projection_key': plan['compiler_inputs_digest'],
         'sarif': {**identity(bundle.read(PREFIX + 'results.sarif')), 'version': '2.1.0', 'run_count': 1,
                   'execution_successful': True, 'tool': 'CodeQL 2.27.2', 'category': '/language:rust/',
                   'tool_warning_error_notifications': 0, 'security_result_count': len(run.get('results', []))},
         'fresh_result_count': 39, 'result_copies_verified': 78, 'fresh_result_identities': fresh_verified,
         'decoded_summary': {**identity(decoded_bytes), 'semantic_sha256': canonical(decoded), 'rows': 29,
                             'retained_baseline_byte_equal': True, 'retained_baseline_semantic_equal': True,
                             'values': result['summary_values']},
         'hosted_source_pack_runtime_postchecks_passed': True, 'whole_wrapper_qualified': True,
         'three_target_publication_claimed': False, 'sarif_uploaded': False,
         'readback_execution': 'Original bytes only; no additional CodeQL, JVM, compilation, extraction, query or test run.'})

shutil.copyfile(Path(__file__), OUT / 'readback.py')
print(json.dumps({'directory': str(OUT), 'readback': identity((OUT / 'READBACK.json').read_bytes()),
                  'analysis_seconds': analysis['elapsed_seconds'], 'stderr_completions': len(completed),
                  'internal_completions': len(internal_events)}, sort_keys=True))
