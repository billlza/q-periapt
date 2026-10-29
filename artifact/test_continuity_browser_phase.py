"""Execute the actual browser phase script with a deterministic Page event source.

These lifecycle checks do not replace the installed Chromium/Worker workload.
"""
import ast
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const {script, mode} = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const execute = eval('(' + script + ')');
const events = ['pageerror', 'console', 'requestfailed', 'response'];
class Page extends EventEmitter {
  constructor() {
    super();
    this.failure = new Error('original ' + mode + ' failure');
    this.baseline = new Map(events.map(name => [name, () => {}]));
    for (const [name, listener] of this.baseline) this.on(name, listener);
  }
  async waitForFunction() {
    if (mode === 'readiness') throw this.failure;
  }
  async evaluate(_fn, input) {
    if (input === undefined) {
      if (mode === 'agent') throw this.failure;
      return 'test browser';
    }
    if (mode === 'operation') throw this.failure;
    this.emit('pageerror', new Error('retained page diagnostic'));
    this.emit('console', {type: () => 'warning', text: () => 'retained warning',
      location: () => ({url: 'http://fixture.test/'})});
    const request = {url: () => 'http://fixture.test/witness',
      failure: () => ({errorText: 'net::ERR_ABORTED'}), timing: () => ({startTime: 1}),
      postDataBuffer: () => Buffer.from([1, 2, 3])};
    this.emit('response', {request: () => request, status: () => 503,
      url: () => request.url()});
    this.emit('requestfailed', request);
    return {phase: input.phase};
  }
}
(async () => {
  const page = new Page();
  for (let n = 0; n < (mode === 'repeat' ? 40 : 1); n++) {
    if (['readiness', 'operation', 'agent'].includes(mode)) {
      await assert.rejects(execute(page), error => error === page.failure);
    } else {
      const result = await execute(page);
      assert.equal(result.status, 'INSTALLED_SESSION_PHASE');
      assert.equal(result.phase, 'resume');
      assert.equal(result.diagnostics.length, 2);
      assert.equal(result.requests.length, 1);
      assert.equal(result.http_errors.length, 1);
      assert.equal(result.request_diagnostics.length, 1);
      assert.equal(result.request_diagnostics[0].body_hex, '010203');
      assert.equal(result.request_diagnostics[0].response_status, 503);
      const retained = JSON.stringify(result);
      page.emit('pageerror', new Error('later phase diagnostic'));
      assert.equal(JSON.stringify(result), retained, 'completed diagnostics changed');
    }
    for (const name of events) {
      assert.deepEqual(page.listeners(name), [page.baseline.get(name)],
        'phase leaked listeners or removed an unrelated listener: ' + name);
    }
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
'''


class BrowserPhaseLifecycle(unittest.TestCase):
    def run_phase(self, mode):
        source = ast.parse((ROOT / 'artifact/continuity_browser_session.py').read_text())
        scripts = [node.value for node in ast.walk(source)
                   if isinstance(node, ast.Constant) and isinstance(node.value, str)
                   and node.value.startswith('async page => {')]
        self.assertEqual(len(scripts), 1, 'expected the actual single phase script')
        script = scripts[0].replace('__PHASE__', json.dumps('resume')).replace('__DETAILS__', 'null')
        result = subprocess.run(['node', '--unhandled-rejections=strict', '-e', HARNESS],
                                input=json.dumps({'script': script, 'mode': mode}),
                                text=True, capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, '', 'unexpected Node diagnostics')

    def test_success_releases_only_its_own_listeners(self):
        self.run_phase('success')

    def test_readiness_failure_releases_listeners_and_preserves_error(self):
        self.run_phase('readiness')

    def test_operation_failure_releases_listeners_and_preserves_error(self):
        self.run_phase('operation')

    def test_agent_failure_releases_listeners_and_preserves_error(self):
        self.run_phase('agent')

    def test_repeated_phases_do_not_retain_completed_diagnostics(self):
        self.run_phase('repeat')


if __name__ == '__main__':
    unittest.main()
