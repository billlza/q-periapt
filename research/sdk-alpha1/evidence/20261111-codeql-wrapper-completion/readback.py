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
HERE = ROOT / 'second-wrapper-failure/review'
REPO = ROOT / 'evidence-current'
OUT = REPO / 'research/sdk-alpha1/evidence/20261111-codeql-wrapper-completion'
SOURCE = '951b8dcaebc11223bf01c79c1c4c3a20349be989'
WORKFLOW = 'cd33c64e34a39046a57010bfa56f6964acdca2c2'
PREFIX = 'qperiapt-codeql-wrapper-fixture/evidence/'
ARTIFACT_SHA = '26a213027695de66807bd2c9999cd4287dbfa932b05cf06435fe027d4c033057'

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
archive = (ROOT / 'second-wrapper-failure/artifact.zip').read_bytes()
assert len(archive) == 3561748 and sha(archive) == ARTIFACT_SHA
artifacts = json.loads((HERE / 'ARTIFACT_API.json').read_bytes())['artifacts']
metadata, = [value for value in artifacts if value['id'] == 13862281372]
assert metadata['size_in_bytes'] == len(archive)
assert metadata['digest'] == 'sha256:' + ARTIFACT_SHA
assert metadata['workflow_run']['id'] == 43032937156
assert metadata['workflow_run']['head_sha'] == WORKFLOW
jobs = json.loads((HERE / 'JOBS_API.json').read_bytes())['jobs']
job, = [value for value in jobs if value['id'] == 130564344658]
assert job['head_sha'] == WORKFLOW and job['conclusion'] == 'failure'
assert next(s for s in job['steps'] if s['name'] == 'Verify the fixture method and workflow contracts')['conclusion'] == 'success'
assert next(s for s in job['steps'] if s['name'].startswith('Extract the frozen fixture'))['conclusion'] == 'failure'
job_log = (HERE / 'job.log').read_bytes()
assert b'Ran 9 tests in 0.006s' in job_log
assert b'CodeQL query completions observed: 39/39' in job_log
assert b'PlanError: production evaluator completion census differs' in job_log
(OUT / 'artifact.zip').write_bytes(archive)
for name in ('ARTIFACT_API.json', 'JOBS_API.json', 'job.log'):
    shutil.copyfile(HERE / name, OUT / name)

with zipfile.ZipFile(ROOT / 'second-wrapper-failure/artifact.zip') as bundle:
    infos = bundle.infolist()
    assert len(infos) == len({x.filename for x in infos}) == 172
    assert sum(x.file_size for x in infos) < 64 * 1024**2
    members = {}
    for item in infos:
        path = PurePosixPath(item.filename)
        assert not path.is_absolute() and '..' not in path.parts and '\\' not in item.filename
        assert str(path) == item.filename and not item.is_dir()
        assert stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG)
        members[item.filename] = {**identity(bundle.read(item)), 'compressed_bytes': item.compress_size, 'crc32': f'{item.CRC:08x}'}
    save('ZIP_MEMBERS.json', members)
    assert not any(name.endswith('.bqrs') for name in members)
    assert bundle.read('qperiapt-wrapper-source.txt').decode().splitlines() == [WORKFLOW, '84247a6370a516e4a8ae414be0e063504e695d1b']
    selected = ('SOURCE_CONTRACT.json', 'EVALUATOR_OBSERVATIONS.json', 'QUERY_MEMORY.json',
                'analyze.json', 'analyze.started.json', 'analyze.stderr', 'analyze.stdout',
                'extract.json', 'extract.started.json', 'extract.stdout', 'extract.stderr',
                'METHOD.json', 'FIXTURE_FAILURE.json', 'ANALYSIS_PLAN_AFTER.json', 'ANALYSIS_RUNTIME.json',
                'SUMMARY_PLAN.json', 'DATABASE_INPUTS.json', 'RESOURCE_OBSERVATION_STATUS.json',
                'COMPILER_IDENTITY.json', 'OFFICIAL_DOWNLOADS.json', 'results.sarif')
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
    assert observations['query_starts'] == 39 and observations['query_completions'] == 37
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
    assert len(internal_events) == 37
    missing = sorted(expected_results - {event['query_result'] for event in internal_events})
    assert missing == ['codeql/rust-queries/queries/security/CWE-295/DisabledCertificateCheck.bqrs',
                       'codeql/rust-queries/queries/security/CWE-319/UseOfHttp.bqrs']
    save('COMPLETION_EVENTS.json', {'stderr': identity(stderr), 'stderr_events': completion_events,
         'internal_log_member': log_name, 'internal_log': identity(log), 'internal_events': internal_events,
         'missing_from_internal_log': missing,
         'diagnosis': 'The retained stderr contains each admitted completion exactly once. The internal execute log omits two completion and produced-BQRS messages. The retained bytes do not establish the upstream logging mechanism responsible for that divergence.'})
    analysis, extraction, memory, failure = (get(name) for name in ('analyze.json', 'extract.json', 'QUERY_MEMORY.json', 'FIXTURE_FAILURE.json'))
    assert analysis['returncode'] == extraction['returncode'] == 0
    assert analysis['source_commit'] == WORKFLOW and analysis['run_id'] == '43032937156' and analysis['maximum_seconds'] == 600
    assert failure['type'] == 'PlanError' and failure['message'] == 'production evaluator completion census differs'
    assert memory['heap_mb'] == 3484 and memory['off_heap_ram_mb'] == 9329 and memory['requested_ram_mb'] == 14000
    assert observations['jvm_heap_mb_arguments'] == [3484] and observations['off_heap_mb_observed'] == [9329]
    plan, after, runtime = (get(name) for name in ('SUMMARY_PLAN.json', 'ANALYSIS_PLAN_AFTER.json', 'ANALYSIS_RUNTIME.json'))
    assert after['summary_plan'] == plan
    assert plan['manifest_sha256'] == sha(source('artifact/codeql_summary_projection.json'))
    assert plan['compiler_inputs_digest'] == '6a7530eb694360655ab8331a895c9fcd'
    assert plan['capsule_sha256'] == '5b17fb41cd3c59fea564ec4e9cb49ef586c0ad06ccc3f2445e46b7b5ca8430cb'
    assert plan['query_count'] == 39 and plan['unchanged_other_compiled_queries'] == 38
    assert len(runtime['files']) == 2282 and sum(value['bytes'] for value in runtime['files'].values()) == 231156107
    assert canonical(runtime['files']) == after['tool']['runtime_inventory_sha256'] == '1d61c12cb67e01730a1ec5031aefe669035e52290081dc6822333cb5ab861c90'
    assert 'qperiapt-codeql-wrapper-fixture/evidence/ANALYSIS_PLAN_FAILURE.json' not in members
    sarif = get('results.sarif')
    assert sarif['version'] == '2.1.0' and len(sarif['runs']) == 1
    run = sarif['runs'][0]
    assert run['automationDetails'] == {'id': '/language:rust/'}
    assert run['tool']['driver']['name'] == 'CodeQL' and run['tool']['driver']['semanticVersion'] == '2.27.2'
    assert run['invocations'] and all(invocation['executionSuccessful'] is True for invocation in run['invocations'])
    assert all(note['level'] in ('none', 'note') for invocation in run['invocations'] for note in invocation.get('toolExecutionNotifications', []))
    save('READBACK.json', {'schema': 1, 'run_id': 43032937156, 'job_id': 130564344658, 'attempt': 1,
         'workflow_commit': WORKFLOW, 'production_commit': SOURCE, 'workflow_conclusion': 'failure',
         'artifact_id': 13862281372, 'artifact': identity(archive), 'source_contract_files_verified': source_verification,
         'contract_tests': {'tests': 9, 'seconds': 0.006, 'passed': True},
         'analysis': analysis, 'extraction': extraction, 'memory': memory,
         'stderr_distinct_completion_count': 39, 'stderr_complete_frozen_query_set': True,
         'internal_starts': 39, 'internal_completions': 37, 'internal_precompiled_loads': 39,
         'implicit_compilations': 0, 'evaluator_invocations': 1, 'internal_missing_completion_paths': missing,
         'runtime': {'files': 2282, 'bytes': 231156107, 'inventory_sha256': canonical(runtime['files'])},
         'projection_before_after_equal': True, 'projection_key': plan['compiler_inputs_digest'],
         'sarif': {**identity(bundle.read(PREFIX + 'results.sarif')), 'version': '2.1.0', 'run_count': 1,
                   'execution_successful': True, 'tool': 'CodeQL 2.27.2', 'category': '/language:rust/',
                   'tool_warning_error_notifications': 0, 'security_result_count': len(run.get('results', [])),
                   'readback_scope': 'Independent structural validation of the retained file after the hosted validator stopped earlier.'},
         'fixture_failure': failure, 'retained_bqrs_files': 0,
         'new_summary_decode_performed': False, 'new_29_row_comparison_performed': False,
         'whole_wrapper_qualified': False, 'readback_execution': 'Original bytes only; no CodeQL, JVM, compilation, extraction, query or test run.'})

shutil.copyfile(Path(__file__), OUT / 'readback.py')
print(json.dumps({'directory': str(OUT), 'readback': identity((OUT / 'READBACK.json').read_bytes()),
                  'analysis_seconds': analysis['elapsed_seconds'], 'stderr_completions': len(completed),
                  'internal_completions': len(internal_events)}, sort_keys=True))
