"""Build and exercise the experimental shared browser enrollment engine."""
from pathlib import Path
import argparse
import contextlib
import json
import os
import re
import tempfile
import uuid

from bounded_process import capture_output
from c_package_manifest import rust_workspace_source_digest
from continuity_browser_http import serving
from continuity_browser_records import cli_result, request_files
from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / 'research/continuity-identity-candidate'
FIXTURES = CANDIDATE / 'tests/browser'


def source_identity() -> dict:
    paths = [path for name in ('src', 'tests/browser', 'examples')
             for path in (CANDIDATE / name).rglob('*') if path.is_file()]
    paths.extend(CANDIDATE / name for name in ('Cargo.toml', 'Cargo.lock'))
    paths.append(ROOT / 'crates/q-periapt-sdk-wasm/package/web/storage-io.js')
    paths.extend(ROOT / 'artifact' / name for name in (
        'continuity_browser_creation.py', 'continuity_browser_http.py',
        'continuity_browser_records.py', 'bounded_process.py', 'evidence_io.py',
        'rust_sdk_profile.py', 'c_package_manifest.py'))
    return {'rust_workspace_sha256': rust_workspace_source_digest(ROOT),
            'files': {str(path.relative_to(ROOT)): sdk.snapshot(path).sha256 for path in sorted(paths)}}


def stage_web(web: Path, private: Path) -> dict:
    for name in ('root.bin', 'description.bin'):
        sdk.copy(private / name, web / 'inputs' / name)
    for name in ('storage-root.js', 'storage-database.js', 'storage-catalogue.js', 'storage-opening.js'):
        sdk.copy(CANDIDATE / 'src/storage/browser' / name, web / 'pkg' / name)
    sdk.copy(ROOT / 'crates/q-periapt-sdk-wasm/package/web/storage-io.js', web / 'pkg/storage-io.js')
    sdk.copy(CANDIDATE / 'src/browser/bounded-fetch.js', web / 'pkg/bounded-fetch.js')
    sdk.copy(CANDIDATE / 'src/browser/application.js', web / 'pkg/application.js')
    for name in ('index.html', 'worker.js', 'run.js'):
        sdk.copy(FIXTURES / name, web / 'creation' / name)
    sdk.copy(FIXTURES / 'late.html', web / 'late/index.html')
    sdk.copy(FIXTURES / 'late-worker.js', web / 'late/late-worker.js')
    sdk.copy(FIXTURES / 'late-run.js', web / 'late/late-run.js')
    (web / 'index.html').write_text('<!doctype html><meta charset="utf-8"><link rel="icon" href="data:,"><title>Enrollment acceptance</title>')
    return web_identity(web)


def web_identity(web: Path) -> dict:
    return {str(path.relative_to(web)): sdk.snapshot(path).sha256
            for path in sorted(web.rglob('*')) if path.is_file()}


def native_verify(binary: Path, private: Path, captures: Path, value: dict, logs: Path, env: dict) -> list:
    outputs = captures.parent / 'native'
    outputs.mkdir(mode=0o700)
    rows = []
    for index, request in enumerate(request_files(value, captures)):
        grant = outputs / (request.stem + '.grant')
        data = sdk.command([str(binary), 'verify', str(private), str(request), str(grant)],
                           logs / f'verify-{index:02}', ROOT, environment=env)
        match = re.fullmatch(rb'request_sha256=([0-9a-f]{64}) signing_identity=([0-9a-f]{64}) '
                            rb'public_key_sha256=([0-9a-f]{64}) credential_sha256=([0-9a-f]{64})\n', data)
        sdk.require(match is not None, 'native verification output differs')
        row = dict(zip(('request_sha256', 'signing_identity', 'public_key_sha256', 'credential_sha256'),
                       (part.decode() for part in match.groups())))
        sdk.require(row['request_sha256'] == sdk.snapshot(request).sha256
                    and row['credential_sha256'] == sdk.snapshot(grant).sha256, 'native artifact identity differs')
        rows.append({'request': request.name, **row})
    sdk.require(len({row['signing_identity'] for row in rows}) == 7
                and len({row['public_key_sha256'] for row in rows}) == 7, 'native identities differ')
    return rows


def qualify(output: Path, node: Path, cli: Path) -> dict:
    sdk.require(not output.exists(), 'browser output must be fresh')
    output.mkdir(parents=True)
    public = output / 'public'; public.mkdir()
    logs = public / 'logs'; logs.mkdir()
    web = output / 'web'
    node, cli = node.resolve(strict=True), cli.resolve(strict=True)
    metadata = parse_strict_json_bytes(sdk.snapshot(cli.parent / 'package.json').data, label='Playwright CLI')
    sdk.require(metadata.get('name') == '@playwright/cli' and metadata.get('version') == '0.1.22',
                'browser CLI version differs')
    tool_identity = lambda: {'node': sdk.snapshot(node, maximum=256 * 1024 * 1024).sha256,
                             'cli': sdk.snapshot(cli).sha256}
    tools = tool_identity(); source = source_identity()
    env = {key: value for key, value in os.environ.items() if key not in ('NODE_OPTIONS', 'NODE_PATH')}
    env['CARGO_TARGET_DIR'] = str(output / 'build')
    env['RUSTFLAGS'] = (env.get('RUSTFLAGS', '') + ' -D warnings').strip()
    report = {'completed': False, 'release_claim_eligible': False,
              'scope': 'experimental shared source engine; not installed product qualification',
              'source': source, 'tools': tools}
    try:
        for label, argv, pattern in (
            ('node-version', [str(node), '--version'], rb'v(?:2[4-9]|[3-9][0-9])\.[0-9]+\.[0-9]+\n'),
            ('rustc-version', ['rustc', '--version'], rb'rustc 1\.98\.1 .+\n'),
            ('wasm-pack-version', ['wasm-pack', '--version'], rb'wasm-pack 0\.15\.0\n')):
            data = sdk.command(argv, logs / label, ROOT, environment=env)
            sdk.require(re.fullmatch(pattern, data) is not None, label + ' differs')
        sdk.command(['wasm-pack', 'build', str(CANDIDATE), '--mode', 'no-install', '--target', 'web',
                     '--release', '--out-dir', str(web / 'pkg'), '--', '--locked'],
                    logs / 'wasm-build', ROOT, environment=env)
        sdk.command(['cargo', 'build', '--manifest-path', str(CANDIDATE / 'Cargo.toml'),
                     '--example', 'browser_owned_enrollment', '--locked'], logs / 'native-build', ROOT, environment=env)
        binary = output / 'build/debug/examples/browser_owned_enrollment'
        report['native_binary_sha256'] = sdk.snapshot(binary, maximum=256 * 1024 * 1024).sha256
        # This fresh private authority is outside every upload and served directory.
        private = Path(tempfile.mkdtemp(prefix='qpc-browser-authority-')).resolve(strict=True)
        sdk.command([str(binary), 'prepare', str(private)], logs / 'native-prepare', ROOT, environment=env)
        report['served_files'] = stage_web(web, private)
        session = 'qpc-enrollment-' + uuid.uuid4().hex

        def browser(args: list[str], label: str) -> bytes:
            with contextlib.chdir(output):
                result = capture_output([str(node), str(cli), '--session', session, *args],
                    timeout_seconds=200, maximum_stdout_bytes=4 * 1024 * 1024,
                    maximum_stderr_bytes=1024 * 1024, environment=env)
            (logs / (label + '.stdout')).write_bytes(result.stdout)
            (logs / (label + '.stderr')).write_bytes(result.stderr)
            sdk.write_json(logs / (label + '.json'), {'argv': args, 'returncode': result.returncode})
            sdk.require(result.returncode == 0 and not result.stderr, 'browser command failed: ' + label)
            return result.stdout

        with serving(web, public) as origin:
            try:
                browser(['open', origin + '/index.html', '--browser', 'chrome'], 'browser-open')
                results = cli_result(browser(['run-code', '--filename', str(FIXTURES / 'acceptance.js')], 'browser-run'))
                for phase, value in results.items():
                    captured = parse_strict_json_bytes(sdk.snapshot(public / phase / 'RESULT.json').data,
                                                       label=phase + ' capture')
                    sdk.require(captured == value, 'browser capture differs from CLI result')
                report['browser'] = results
                report['native_verified'] = native_verify(binary, private, public / 'creation', results['creation'], logs, env)
            except BaseException as primary:
                try:
                    browser(['close'], 'browser-close')
                except BaseException as cleanup:
                    raise BaseExceptionGroup('browser execution and cleanup failed', [primary, cleanup]) from None
                raise
            else:
                browser(['close'], 'browser-close')
        sdk.require(web_identity(web) == report['served_files'], 'served browser inputs changed')
        sdk.require(source_identity() == source and tool_identity() == tools, 'producer inputs changed')
        sdk.require(sdk.snapshot(binary, maximum=256 * 1024 * 1024).sha256 == report['native_binary_sha256'],
                    'native verifier changed')
        report['completed'] = True
    except BaseException as error:
        report['failure'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        sdk.write_json(public / 'BROWSER_ENROLLMENT.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'node', 'cli'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.output.resolve(), args.node, args.cli)
    print(json.dumps({'completed': result['completed'], 'output': str(args.output)}, indent=2))
