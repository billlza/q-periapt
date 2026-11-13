"""Real Chromium storage acceptance of the exact installed WASM candidate."""
from pathlib import Path
import argparse
import contextlib
import json
import os
import re
import subprocess
import time
import uuid
from urllib.parse import urlsplit

from bounded_process import capture_output
from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk
import wasm_sdk_package as package


def installed_browser_result(value: dict) -> dict:
    sdk.require(set(value) == {'status', 'browser', 'cases'}, 'installed browser envelope differs')
    expected = {'roundtrip': 236, 'no-entropy': 15, 'throwing-entropy': 15,
                'init-fail': 6, 'no-wasm': 6}
    rows = value.get('cases', [])
    sdk.require([(row.get('realm'), row.get('mode')) for row in rows]
                == [(realm, mode) for realm in ('window', 'worker') for mode in expected],
                'installed browser realm or failure scenario omitted')
    origins = set()
    for row in rows:
        mode, realm = row['mode'], row['realm']
        assertions = expected[mode] + (7 if mode == 'roundtrip' and realm == 'window' else 0)
        sdk.require(row.get('status') == 'pass' and type(row.get('assertions')) is int
                    and row['assertions'] == assertions and row.get('errors') == []
                    and row.get('pageErrors') == [], 'installed browser assertions or diagnostics differ')
        diagnostics = row.get('diagnostics')
        sdk.require(diagnostics == [] or (mode == 'init-fail'
                    and isinstance(diagnostics, list) and len(diagnostics) == 1
                    and diagnostics[0].get('type') == 'error' and '404' in diagnostics[0].get('text', '')),
                    'installed browser console diagnostics differ')
        requests = row.get('requests', [])
        sdk.require(len(requests) == 1 and isinstance(requests[0], str), 'installed WASM load count differs')
        address = urlsplit(requests[0])
        path = ('/broken' if mode == 'init-fail' else '') + '/node_modules/q-periapt-sdk-wasm/web/q_periapt_sdk_wasm_bg.wasm'
        sdk.require(address.scheme == 'http' and address.hostname == '127.0.0.1'
                    and address.port is not None and address.username is None and address.password is None
                    and address.path == path and not address.query and not address.fragment,
                    'installed WASM load did not use the controlled package entry')
        origin = address.scheme + '://' + address.netloc
        origins.add(origin)
        sdk.require(row.get('responses') == [{'url': requests[0], 'status': 404 if mode == 'init-fail' else 200}],
                    'installed WASM response differs')
        sdk.require(row.get('workers') == ([origin + '/browser-worker.mjs?mode=' + mode] if realm == 'worker' else []),
                    'installed browser Worker identity differs')
    sdk.require(len(origins) == 1, 'installed browser cases used different consumers')
    return value


def result(data: bytes, marker: str) -> dict:
    text = data.decode()
    sdk.require(text.count('### Result\n') == 1 and '### Error' not in text, 'browser result missing or failed')
    value = parse_strict_json_bytes(text.split('### Result\n', 1)[1].split('\n### ', 1)[0].encode(), label='browser storage')
    sdk.require(isinstance(value, dict) and value.get('status') == marker
                and isinstance(value.get('browser'), str) and value['browser'], 'browser storage result differs')
    if marker == 'WASM_INSTALLED_BROWSER_PASS':
        return installed_browser_result(value)
    sdk.require(value.get('diagnostics') == [], 'browser storage diagnostics differ')
    if marker == 'BROWSER_POLICY_STORAGE_PASS':
        rows = value.get('cases', [])
        cuts = [r for r in rows if r.get('command') == 'Worker-termination']
        sdk.require(len(cuts) == 2 and {r['boundary'] for r in cuts} == {'request-success', 'committed'}, 'Worker cut omitted')
        for cut in cuts:
            observed = cut.get('leaseObservations', [])
            sdk.require(observed and observed[-1]['remaining'] == 0, 'Worker lease release unobserved')
        sdk.require(sum(r.get('command') == 'crypto' and r.get('ok') is True for r in rows) == 6
                    and any(r.get('command') == 'abort' and r.get('code') == 'Aborted' for r in rows)
                    and any(r.get('command') == 'close-update' and r.get('code') == 'Closed' for r in rows), 'real lifecycle scenario missing')
    elif marker == 'BROWSER_POLICY_QUOTA_PASS':
        rows = value.get('results', [])
        sdk.require(value.get('pressureBytes') == 64 * 1024 * 1024
                    and value.get('pressurePattern') == 'webcrypto-random'
                    and value.get('quotaHeadroom') == 8 * 1024 * 1024
                    and [r['scenario'] for r in value.get('contexts', [])] == ['creation-reopen', 'replacement']
                    and all(r['initialUsage']['usage'] == 0 and r['constrained']['overrideActive'] is True
                            and r['constrained']['quota'] == value['quotaHeadroom'] for r in value['contexts'])
                    and [(r.get('scenario'), r.get('command')) for r in rows if r.get('code') == 'QuotaExceeded']
                        == [('creation-reopen', 'create'), ('creation-reopen', 'open'), ('replacement', 'update')]
                    and rows[-1].get('command') == 'close' and rows[-1].get('ok') is True,
                    'real quota failure or cleanup missing')
        original = [r['state'] for r in rows if r.get('scenario') == 'replacement'
                    and r.get('command') in ('create', 'open') and r.get('ok') is True]
        sdk.require(len(original) == 2 and original[0] == original[1]
                    and any(r.get('scenario') == 'replacement' and r.get('command') == 'state'
                            and r.get('code') == 'Closed' for r in rows), 'quota failure changed state or left its owner active')
    elif marker == 'BROWSER_POLICY_DEADLINE_PASS':
        rows = value.get('cases', [])
        sdk.require(value.get('completed') is True and value.get('held_until_receipt') is True
                    and [row.get('mode') for row in rows] == ['transaction-complete', 'database-open'],
                    'native completion receipt controls missing')
        for row in rows:
            transaction = row['mode'] == 'transaction-complete'
            sdk.require(row.get('error') == ('CommitUnknown' if transaction else 'OpenUnknown')
                        and row.get('elapsed_ms', 0) >= 20000
                        and 'ClosePending' in row.get('cleanup', [])
                        and row.get('final_receipt_withheld') is True
                        and row.get('early_owner_admitted') is False and row.get('early_error') == 'Busy'
                        and all(isinstance(row.get(key), str) and re.fullmatch(r'[0-9a-f]{72}', row[key])
                                for key in ('before', 'after'))
                        and (row.get('closed_error') == 'Closed' and row.get('enabled') is False
                             if transaction else row.get('after') == row.get('before')),
                        'deadline released storage or lost the original policy')
    else:
        raise ValueError('unknown browser storage marker')
    return value


def qualify(receipt: Path, output: Path, node: Path, cli: Path) -> dict:
    sdk.require(not output.exists(), 'browser output must be fresh')
    output.mkdir(parents=True)
    source = sdk.snapshot(Path(__file__).resolve()).sha256
    record = parse_strict_json_bytes(sdk.snapshot(receipt).data, label='installed WASM receipt')
    installed = Path(record['installed']); consumer = installed.parent.parent
    sdk.require(installed.is_absolute() and not consumer.is_relative_to(package.ROOT), 'consumer is not external')
    manifest = package.verify(installed, record['manifest_sha256'])
    package.validate_consumer_source(manifest)
    sdk.require(set(record['consumer_inputs']) == set(package.CONSUMER_FILES), 'browser consumer inventory differs')
    for name, digest in record['consumer_inputs'].items():
        sdk.require(sdk.snapshot(consumer / name).sha256 == digest
                    == sdk.snapshot(package.CRATE / 'tests' / name).sha256, 'installed browser consumer changed')
    node, cli = node.resolve(strict=True), cli.resolve(strict=True)
    metadata = parse_strict_json_bytes(sdk.snapshot(cli.parent / 'package.json').data, label='Playwright CLI')
    sdk.require(metadata.get('name') == '@playwright/cli' and metadata.get('version') == '0.1.22', 'browser CLI version differs')
    tools = {'node': sdk.snapshot(node, maximum=256 * 1024 * 1024).sha256, 'cli': sdk.snapshot(cli).sha256}
    session = 'qpc-storage-' + uuid.uuid4().hex
    env = {k: v for k, v in os.environ.items() if k not in ('NODE_OPTIONS', 'NODE_PATH')}
    def command(args, label):
        with contextlib.chdir(output):
            executed = capture_output([str(node), str(cli), '--session', session, *args],
                timeout_seconds=120, maximum_stdout_bytes=2 * 1024 * 1024,
                maximum_stderr_bytes=1024 * 1024, environment=env)
        (output / (label + '.stdout')).write_bytes(executed.stdout)
        (output / (label + '.stderr')).write_bytes(executed.stderr)
        sdk.write_json(output / (label + '.json'), {'returncode': executed.returncode, 'argv': args})
        sdk.require(executed.returncode == 0 and not executed.stderr, 'browser command failed: ' + label)
        return executed.stdout
    report = {'completed': False, 'release_claim_eligible': False, 'archive_sha256': record['sha256'],
              'manifest_sha256': record['manifest_sha256'], 'tools': tools, 'driver_sha256': source}
    with (output / 'server.stdout').open('xb') as stdout, (output / 'server.stderr').open('xb') as stderr:
        execution_complete = False
        server = subprocess.Popen([str(node), 'serve.cjs'], cwd=consumer, env=env, stdin=subprocess.DEVNULL,
                                  stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 10
            while not (output / 'server.stdout').stat().st_size:
                sdk.require(server.poll() is None and time.monotonic() < deadline, 'fixture server did not start')
                time.sleep(0.05)
            startup = parse_strict_json_bytes(sdk.snapshot(output / 'server.stdout').data, label='browser server')
            sdk.require(startup['pid'] == server.pid and startup['url'].startswith('http://127.0.0.1:'), 'fixture server identity differs')
            command(['open', startup['url'], '--browser', 'chrome'], 'open')
            for name, marker in [('browser-acceptance.js', 'WASM_INSTALLED_BROWSER_PASS'),
                                 ('storage-quota-acceptance.js', 'BROWSER_POLICY_QUOTA_PASS'),
                                 ('storage-acceptance.js', 'BROWSER_POLICY_STORAGE_PASS'),
                                 ('storage-deadline-acceptance.js', 'BROWSER_POLICY_DEADLINE_PASS')]:
                report[name] = result(command(['run-code', '--filename', str(consumer / name)], name), marker)
            package.verify(installed, record['manifest_sha256'])
            for name, digest in record['consumer_inputs'].items():
                sdk.require(sdk.snapshot(consumer / name).sha256 == digest
                            == sdk.snapshot(package.CRATE / 'tests' / name).sha256, 'browser fixture changed during execution')
            sdk.require(tools == {'node': sdk.snapshot(node, maximum=256 * 1024 * 1024).sha256,
                                 'cli': sdk.snapshot(cli).sha256}, 'browser runtime changed')
            sdk.require(sdk.snapshot(Path(__file__).resolve()).sha256 == source, 'browser driver changed during execution')
            execution_complete = True
        finally:
            cleanup_complete = False
            try:
                command(['close'], 'close')
                server.terminate(); server.wait(timeout=5)
                sdk.require(sdk.snapshot(output / 'server.stderr').data == b'', 'fixture server emitted diagnostics')
                cleanup_complete = True
            finally:
                if server.poll() is None:
                    server.kill(); server.wait(timeout=5)
                report['completed'] = execution_complete and cleanup_complete
                sdk.write_json(output / 'BROWSER_STORAGE.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('receipt', 'output', 'node', 'cli'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.receipt.resolve(), args.output.resolve(), args.node, args.cli), indent=2))
