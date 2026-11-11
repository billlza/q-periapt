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

ROOT = Path(__file__).resolve().parent
HERE = ROOT
OUT = ROOT
PINS = json.loads((ROOT / 'EXPECTED.json').read_bytes())
SOURCE = 'ed38e305552db2825d90622c130973df87e16d50'
WORKFLOW = PINS['workflow_commit']
WORKFLOW_TREE = PINS['workflow_tree']
RUN_ID = PINS['run_id']
JOB_ID = PINS['job_id']
ARTIFACT_ID = PINS['artifact_id']
PREFIX = 'qperiapt-codeql-wrapper-fixture/evidence/'
ARTIFACT_SHA = PINS['artifact_sha256']

def sha(data):
    return hashlib.sha256(data).hexdigest()

def identity(data):
    return {'bytes': len(data), 'sha256': sha(data)}

def canonical(data):
    return sha(json.dumps(data, sort_keys=True, separators=(',', ':')).encode())

def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def source(path):
    assert path.startswith('artifact/')
    return (ROOT / 'source/production' / path.removeprefix('artifact/')).read_bytes()

run_api = json.loads((HERE / 'RUN_API.json').read_bytes())
assert run_api['id'] == RUN_ID and run_api['head_sha'] == WORKFLOW
assert run_api['head_branch'] == 'diagnostic/codeql-unit-state-fixture'
assert run_api['status'] == 'completed' and run_api['conclusion'] == 'success'
assert run_api['run_attempt'] == 1

archive = (ROOT / 'artifact.zip').read_bytes()
assert len(archive) == PINS['artifact_bytes'] and sha(archive) == ARTIFACT_SHA
artifacts = json.loads((HERE / 'ARTIFACT_API.json').read_bytes())['artifacts']
metadata, = [value for value in artifacts if value['id'] == ARTIFACT_ID]
assert metadata['size_in_bytes'] == len(archive)
assert metadata['digest'] == 'sha256:' + ARTIFACT_SHA
assert metadata['workflow_run']['id'] == RUN_ID
assert metadata['workflow_run']['head_sha'] == WORKFLOW
jobs = json.loads((HERE / 'JOBS_API.json').read_bytes())['jobs']
job, = [value for value in jobs if value['id'] == JOB_ID]
assert job['head_sha'] == WORKFLOW and job['conclusion'] == 'success'
assert next(s for s in job['steps'] if s['name'] == 'Verify the fixture method and workflow contracts')['conclusion'] == 'success'
assert next(s for s in job['steps'] if s['name'].startswith('Extract the frozen fixture'))['conclusion'] == 'success'
job_log = (HERE / 'job.log').read_bytes()
contract_test_events = re.findall(rb'Ran ([0-9]+) tests in ([0-9.]+)s', job_log)
assert len(contract_test_events) == 1
contract_count = int(contract_test_events[0][0])
contract_seconds = float(contract_test_events[0][1])
assert contract_count == PINS['contract_tests']
assert re.search(rb'(?m)^[^\r\n]* OK\r?$', job_log) or b'\nOK\n' in job_log
assert b'CodeQL query completions observed: 39/39' in job_log

with zipfile.ZipFile(ROOT / 'artifact.zip') as bundle:
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
    assert bundle.read('qperiapt-wrapper-source.txt').decode().splitlines() == [WORKFLOW, WORKFLOW_TREE]
    selected = ('SOURCE_CONTRACT.json', 'EVALUATOR_OBSERVATIONS.json', 'QUERY_MEMORY.json',
                'analyze.json', 'analyze.started.json', 'analyze.stderr', 'analyze.stdout',
                'extract.json', 'extract.started.json', 'extract.stdout', 'extract.stderr',
                'METHOD.json', 'FIXTURE_WRAPPER_RESULT.json', 'ANALYSIS_PLAN_AFTER.json', 'ANALYSIS_RUNTIME.json',
                'SUMMARY_PLAN.json', 'DATABASE_INPUTS.json', 'RESOURCE_OBSERVATION_STATUS.json',
                'COMPILER_IDENTITY.json', 'OFFICIAL_DOWNLOADS.json', 'results.sarif',
                'QUERY_COMPLETIONS.json', 'FRESH_RESULTS.json', 'PACK_BEFORE.json',
                'decode-summary.json', 'decode-summary.stdout', 'decode-summary.stderr',
                'INITIAL_DATABASE_FILES.json.gz')
    (OUT / 'original').mkdir(exist_ok=True)
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
    assert observations['query_starts'] == 39
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
    assert len(internal_events) == observations['query_completions']
    assert len(internal_events) == len({e['query_result'] for e in internal_events})
    assert {e['query_result'] for e in internal_events} <= expected_results
    missing = sorted(expected_results - {event['query_result'] for event in internal_events})
    save('COMPLETION_EVENTS.json', {'stderr': identity(stderr), 'stderr_events': completion_events,
         'internal_log_member': log_name, 'internal_log': identity(log), 'internal_events': internal_events,
         'missing_from_internal_log': missing,
         'diagnosis': 'The original stderr contains all 39 admitted completion events. The internal progress count and missing paths are measured independently and retained verbatim; fresh BQRS identity validation below is independent of these progress records.'})
    analysis, extraction, memory, result, decoded_record = (get(name) for name in
        ('analyze.json', 'extract.json', 'QUERY_MEMORY.json', 'FIXTURE_WRAPPER_RESULT.json', 'decode-summary.json'))
    assert analysis['returncode'] == extraction['returncode'] == decoded_record['returncode'] == 0
    assert analysis['source_commit'] == WORKFLOW and analysis['run_id'] == str(RUN_ID) and analysis['maximum_seconds'] == 600
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
    assert len(pack) == 1357 and canonical(pack) == '332897d1bbd8506384f3788f1e27635593b815e7a7e739154e6b340885e726be'
    plan, after, runtime = (get(name) for name in ('SUMMARY_PLAN.json', 'ANALYSIS_PLAN_AFTER.json', 'ANALYSIS_RUNTIME.json'))
    assert after['summary_plan'] == plan == result['summary_plan']
    assert plan['manifest_sha256'] == sha(source('artifact/codeql_summary_projection.json'))
    assert plan['compiler_inputs_digest'] == 'c327768d3f383933ff70cd941341916b'
    assert plan['capsule_sha256'] == '35ab9955321008fb55e436c78b38725370fd5930885635e43ed093ab672fc6d3'
    assert plan['query_count'] == 39 and plan['unchanged_other_compiled_queries'] == 38
    assert len(runtime['files']) == 2282 and sum(value['bytes'] for value in runtime['files'].values()) == 231156107
    assert canonical(runtime['files']) == after['tool']['runtime_inventory_sha256'] == '1d61c12cb67e01730a1ec5031aefe669035e52290081dc6822333cb5ab861c90'
    assert result['pack_and_runtime_postchecks_passed'] is True and result['all_fixture_source_members_unchanged'] is True
    assert PREFIX + 'ANALYSIS_PLAN_FAILURE.json' not in members and PREFIX + 'FIXTURE_FAILURE.json' not in members
    method = get('METHOD.json')
    method_bytes = (ROOT / 'source/codeql_wrapper_fixture.py').read_bytes()
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
    save('READBACK.json', {'schema': 1, 'run_id': RUN_ID, 'job_id': JOB_ID, 'attempt': 1,
         'workflow_commit': WORKFLOW, 'production_commit': SOURCE, 'workflow_conclusion': 'success',
         'artifact_id': ARTIFACT_ID, 'artifact': identity(archive), 'source_contract_files_verified': source_verification,
         'wrapper_method_verified': identity(method_bytes),
         'contract_tests': {'tests': contract_count, 'seconds': contract_seconds, 'passed': True},
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

print(json.dumps({'directory': str(OUT), 'readback': identity((OUT / 'READBACK.json').read_bytes()),
                  'analysis_seconds': analysis['elapsed_seconds'], 'stderr_completions': len(completed),
                  'internal_completions': len(internal_events)}, sort_keys=True))

# Independently authenticate the fetched source snapshots and binary closure.
import ast
import gzip
import io

def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def git_tree(entries):
    ordered = sorted(entries, key=lambda e: (e["path"] + ("/" if e["type"] == "tree" else "")).encode())
    data = b"".join(e["mode"].lstrip("0").encode() + b" " + e["path"].encode() + b"\0" + bytes.fromhex(e["sha"]) for e in ordered)
    return hashlib.sha1(b"tree " + str(len(data)).encode() + b"\0" + data).hexdigest()

primary = ROOT / "source"
production_commit = json.loads((primary / "production-commit.json").read_bytes())
workflow_commit = json.loads((primary / "workflow-commit.json").read_bytes())
root_tree = json.loads((primary / "production-root-tree.json").read_bytes())
artifact_tree = json.loads((primary / "production-artifact-tree.json").read_bytes())
assert production_commit["sha"] == SOURCE
assert [entry["sha"] for entry in production_commit["parents"]] == [PINS["production_parent"]]
production_files = json.loads((primary / "production-files.json").read_bytes())
assert production_files["sha"] == SOURCE
assert [entry["sha"] for entry in production_files["parents"]] == [PINS["production_parent"]]
assert {entry["filename"] for entry in production_files["files"]} == {
    "artifact/codeql-summary-projection-plan.zip",
    "artifact/codeql_rust_plan.py",
    "artifact/codeql_summary_projection.json",
    "artifact/codeql_summary_projection.md",
    "artifact/codeql_summary_projection.patch",
    "artifact/codeql_summary_projection.py",
    "artifact/codeql_summary_projection_dependencies.json.gz",
    "artifact/test_codeql_rust_plan.py",
    "artifact/test_codeql_summary_projection.py",
}
assert production_commit["tree"]["sha"] == root_tree["sha"] == git_tree(root_tree["tree"]) == "9daa64caa7814d759397fbde3218b6a2f6721348"
assert next(e for e in root_tree["tree"] if e["path"] == "artifact")["sha"] == artifact_tree["sha"] == git_tree(artifact_tree["tree"])
assert workflow_commit["sha"] == WORKFLOW and workflow_commit["tree"]["sha"] == WORKFLOW_TREE
assert [e["sha"] for e in workflow_commit["parents"]] == [SOURCE]
entries = {e["path"]: e for e in artifact_tree["tree"]}
bound_sources = {}
for name, expected in contracts.items():
    data = source("artifact/" + name)
    assert git_blob(data) == entries[name]["sha"] and len(data) == entries[name]["size"]
    bound_sources[name] = {**identity(data), "git_blob": git_blob(data)}
diagnostic_files = json.loads((primary / "diagnostic-files.json").read_bytes())
assert diagnostic_files["sha"] == WORKFLOW
assert [entry["sha"] for entry in diagnostic_files["parents"]] == [SOURCE]
assert {e["filename"] for e in diagnostic_files["files"]} == {".github/workflows/codeql-wrapper-fixture.yml", "artifact/codeql_wrapper_fixture.py"}
for record in diagnostic_files["files"]:
    local = "qualification-workflow.yml" if record["filename"].startswith(".github/") else "codeql_wrapper_fixture.py"
    assert git_blob((primary / local).read_bytes()) == record["sha"]
assert git_blob(method_bytes) == PINS['method_blob']
declarations = {}
for node in ast.parse(method_bytes).body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        try:
            declarations[node.targets[0].id] = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            pass
assert declarations["PRODUCTION_COMMIT"] == SOURCE and declarations["PLAN_KEY"] == "c327768d3f383933ff70cd941341916b"
assert declarations["PLAN_MANIFEST_SHA256"] == "efd65ee72a4f966620a3d9bd6ac97b0a6d8ef5567017f3c342f654c4e1f55873"
manifest = json.loads(source("artifact/codeql_summary_projection.json"))
assert sha(source("artifact/codeql_summary_projection.json")) == declarations["PLAN_MANIFEST_SHA256"]
expected_plan = {**manifest, "manifest_sha256": declarations["PLAN_MANIFEST_SHA256"], "effective_plan_sha256": manifest["files"][manifest["plan_path"]]["sha256"], "source_sha256": manifest["query_source_sha256"]}
assert plan == after["summary_plan"] == result["summary_plan"] == expected_plan
asset_bindings = {}
for name in ("codeql-summary-projection-plan.zip", "codeql_summary_projection_dependencies.json.gz", "codeql_summary_projection.patch"):
    data = source("artifact/" + name)
    assert git_blob(data) == entries[name]["sha"] and len(data) == entries[name]["size"]
    asset_bindings[name] = {**identity(data), "git_blob": git_blob(data)}
capsule_bytes = source("artifact/codeql-summary-projection-plan.zip")
assert len(capsule_bytes) == manifest["capsule_bytes"] == 621211 and sha(capsule_bytes) == manifest["capsule_sha256"]
with zipfile.ZipFile(io.BytesIO(capsule_bytes)) as capsule:
    assert capsule.testzip() is None and len(capsule.namelist()) == 16 and set(capsule.namelist()) == set(manifest["files"])
    for name in capsule.namelist():
        assert identity(capsule.read(name)) == manifest["files"][name] == pack[name]
    header, separator, _ = capsule.read(manifest["plan_path"]).partition(b"\n...\n")
    assert separator and len(header) <= 16384
    assert re.findall(r"^inputsDigest: ([a-z0-9]+)$", header.decode(), re.M) == [declarations["PLAN_KEY"]]
    stages = re.findall(r"^- filename: ([a-z0-9]+\.bytes\.qlx)$", header.decode(), re.M)
    assert len(stages) == len(set(stages)) == 15
    assert {".codeql/precompiled/" + name for name in stages} == set(manifest["files"]) - {manifest["plan_path"]}
query_manifest = json.loads(source("artifact/codeql_rust_queries.json"))
assert sha(source("artifact/codeql_rust_queries.json")) == manifest["query_manifest_sha256"]
assert all(pack[name]["sha256"] == digest for name, digest in query_manifest["queries"].items())
compiled = {name: pack[name[:-3] + ".qlx"]["sha256"] for name in query_manifest["queries"]}
assert canonical(compiled) == manifest["compiled_inventory_sha256"]
original_compiled = {**compiled, "queries/summary/SummaryStats.ql": manifest["bundled_plan_sha256"]}
assert canonical(original_compiled) == manifest["bundled_compiled_inventory_sha256"]
assert all(pack[name] == expected for name, expected in manifest["query_pack_support_files"].items())
dependencies_raw = source("artifact/codeql_summary_projection_dependencies.json.gz")
assert identity(dependencies_raw) == {key: manifest["dependency_inventory"][key] for key in ("bytes", "sha256")}
dependencies = json.loads(gzip.decompress(dependencies_raw))
assert set(dependencies) == {"original", "candidate"} and len(dependencies["candidate"]) == 1175
assert canonical(dependencies["candidate"]) == manifest["dependency_inventory"]["effective_inventory_sha256"]
assert canonical(dependencies["original"]) == manifest["dependency_inventory"]["upstream_inventory_sha256"]
assert {p for p in dependencies["original"] if dependencies["original"][p] != dependencies["candidate"][p]} == {manifest["vendor_patch"]["dependency_path"]}
assert all(pack[".codeql/libraries/" + name] == expected for name, expected in dependencies["candidate"].items())
with zipfile.ZipFile(ROOT / "artifact.zip") as bundle:
    get = lambda name: json.loads(bundle.read(PREFIX + name))
    assert bundle.read(PREFIX + "SUMMARY_PLAN_DEPENDENCIES.json.gz") == dependencies_raw
    assert bundle.read(PREFIX + "SUMMARY_PLAN_VENDOR_PATCH.patch") == source("artifact/codeql_summary_projection.patch")
    assert identity(bundle.read(PREFIX + "SUMMARY_PLAN_VENDOR_ORIGINAL.qll")) == manifest["vendor_patch"]["upstream"]
    assert sha(bundle.read(PREFIX + "SUMMARY_PLAN_ORIGINAL.qlx")) == manifest["bundled_plan_sha256"]
    fixture = bundle.read(PREFIX + "reproduction-inputs.zip")
    assert fixture == bundle.read(PREFIX + "fixture-archive.stdout") and sha(fixture) == declarations["FIXTURE_ZIP_SHA256"] and len(fixture) == 20895
    fixture_manifest_bytes = (primary / "fixture-members.json").read_bytes()
    assert fixture_manifest_bytes == bundle.read(PREFIX + "fixture-members.stdout") and sha(fixture_manifest_bytes) == declarations["FIXTURE_MEMBERS_SHA256"]
    fixture_manifest = json.loads(fixture_manifest_bytes)
    with zipfile.ZipFile(io.BytesIO(fixture)) as frozen:
        assert frozen.testzip() is None and len(frozen.namelist()) == 13 and set(frozen.namelist()) == set(fixture_manifest["members"])
        assert sum(len(frozen.read(name)) for name in frozen.namelist()) == 77260
        assert all(identity(frozen.read(name)) == expected for name, expected in fixture_manifest["members"].items())
    fixed_fixture_files = {name: expected for name, expected in fixture_manifest["members"].items() if name.startswith("fixture/")}
    assert len(fixed_fixture_files) == 8 and get("FIXTURE_INPUTS.json") == fixed_fixture_files
    assert (primary / "retained-baseline.json").read_bytes() == bundle.read(PREFIX + "retained-summary.stdout") == decoded_bytes
    assert sha(decoded_bytes) == declarations["BASELINE_SHA256"] and canonical(json.loads(decoded_bytes)) == declarations["BASELINE_SEMANTIC"]
    downloads = get("OFFICIAL_DOWNLOADS.json")
    assert set(downloads) == set(declarations["DOWNLOADS"])
    for name, (url, digest) in declarations["DOWNLOADS"].items():
        assert downloads[name]["url"] == url and downloads[name]["sha256"] == digest
        assert get("download-" + name + ".json")["returncode"] == 0
    assert method["workflow_source_commit"] == WORKFLOW and method["production_source_commit"] == SOURCE and method["run_id"] == str(RUN_ID)
    assert method["analysis_seconds"] == 600 and method["query_threads"] == 4 and method["requested_ram_mb"] == 14000
save("SOURCE_PIN_READBACK.json", {
    "schema": 1, "production_commit": SOURCE, "production_tree": production_commit["tree"]["sha"],
    "workflow_commit": WORKFLOW, "workflow_tree": workflow_commit["tree"]["sha"],
    "complete_root_and_artifact_trees_reconstructed": True, "production_source_bindings": bound_sources,
    "primary_assets": asset_bindings, "capsule_members_verified": 16, "referenced_stages_verified": 15,
    "compiler_inputs_digest": declarations["PLAN_KEY"], "manifest_sha256": declarations["PLAN_MANIFEST_SHA256"],
    "full_plan_before_after_matches_primary_manifest": True,
    "root_query_sources_verified": 39, "compiled_root_queries_verified": 39, "unchanged_other_compiled_queries": 38,
    "dependency_files_verified": 1175, "fixture_zip_members_verified": 13, "fixture_source_support_files_verified": 8,
    "retained_baseline_byte_equal": True, "official_download_receipts_bound": 5,
    "source_or_runtime_execution_requested": False})
print(json.dumps({"source_pins_verified": True, "capsule_members": 16, "compiled_queries": 39, "dependency_files": 1175}, sort_keys=True))

