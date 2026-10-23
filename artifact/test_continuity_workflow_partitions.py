"""CI partitions must preserve all existing tests and keep their time bounds."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


def native(text):
    block = text.split('  continuity-identity-candidate:\n', 1)[1].split('\n  # Cross-target', 1)[0]
    rows = re.findall(r'- os: (\S+)\n\s+toolchain: (\S+)\n\s+partition: (\S+)', block)
    expected = {(os, toolchain, part) for os, toolchain in (
        ('ubuntu-24.04', '1.98.1'), ('ubuntu-24.04', '1.90.0'), ('macos-15', '1.98.1'))
        for part in ('suite', 'capacity')}
    if len(rows) != len(expected) or set(rows) != expected:
        raise ValueError('each compiler and platform needs both Debug partitions')
    if ('timeout-minutes: 90' not in block or 'fail-fast: false' not in block
            or 'continue-on-error:' in block):
        raise ValueError('native failure or timeout contract changed')
    suite = block.split('      - name: Check and exercise candidate with the selected compiler\n', 1)[1].split('\n      - ', 1)[0]
    capacity = block.split('      - name: Exercise the complete Debug capacity scenario\n', 1)[1].split('\n      - ', 1)[0]
    for part, body in (('suite', suite), ('capacity', capacity)):
        if f"if: matrix.partition == '{part}'" not in body:
            raise ValueError('partition execution condition differs')
        if 'test "$(grep -c -F "$CAPACITY_TEST" "$candidate_log/debug-catalog.txt")" = 1' not in body:
            raise ValueError('missing test or overlapping skip must refuse')
    if ('-- --skip "$CAPACITY_TEST" --nocapture' not in suite
            or '--release -- --nocapture' not in suite
            or '--lib "$CAPACITY_TEST" -- --exact --nocapture' not in capacity
            or 'test result: ok\\. 1 passed; 0 failed; 0 ignored;' not in capacity):
        raise ValueError('complementary Debug or complete Release coverage changed')
    if '${{ matrix.toolchain }}-${{ matrix.partition }}' not in block:
        raise ValueError('native artifacts collide')
    if "if: always() && matrix.os == 'macos-15' && matrix.partition == 'suite'" not in block:
        raise ValueError('public vector artifacts collide')


def independent(text):
    rows = re.findall(r'- os: (\S+)\n\s+arch: (\S+)\n\s+phase: (\S+)', text)
    expected = {(os, arch, phase) for os, arch in (('ubuntu-24.04', 'x86_64'), ('macos-15', 'arm64'))
                for phase in ('source', 'installed')}
    if len(rows) != len(expected) or set(rows) != expected:
        raise ValueError('both complete source and installed phases are required')
    if 'timeout-minutes: 120' not in text or 'continue-on-error:' in text or 'fail-fast: false' not in text:
        raise ValueError('independent failure or timeout contract changed')
    workloads = text.split('      - name: Exchange real flights and exercise rejection and replay boundaries\n', 1)[1]
    workloads = '      - name: Exchange real flights and exercise rejection and replay boundaries\n' + workloads
    source, installed = workloads.split('      - name: Verify registration from the installed Python wheel\n', 1)
    steps = [s for s in source.split('      - name: ') if s.strip()]
    if len(steps) != 20 or any("if: matrix.phase == 'source'" not in step for step in steps):
        raise ValueError('source workload missing or selected in the wrong phase')
    if "if: matrix.phase == 'installed'" not in installed.split('      - name: ', 1)[0]:
        raise ValueError('installed workload condition differs')
    if 'independent-bootstrap-${{ matrix.os }}-${{ matrix.phase }}' not in text:
        raise ValueError('independent artifacts collide')


class ContinuityWorkflowPartitionsTests(unittest.TestCase):
    def setUp(self):
        self.native = (ROOT / '.github/workflows/ci.yml').read_text()
        self.independent = (ROOT / '.github/workflows/independent-continuity.yml').read_text()

    def test_current_workloads_are_complete_and_bounded(self):
        native(self.native)
        independent(self.independent)

    def test_catalog_guards_execute_without_optional_runner_tools(self):
        # Hosted Linux runners do not promise ripgrep. Execute both actual
        # workflow guards with only the standard system tools on PATH.
        guards = [line.strip() for line in self.native.splitlines()
                  if line.strip().startswith('test "$(')
                  and 'debug-catalog.txt' in line]
        self.assertEqual(len(guards), 2)
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / 'debug-catalog.txt'
            binaries = Path(directory) / 'bin'
            binaries.mkdir()
            (binaries / 'grep').symlink_to('/usr/bin/grep')
            environment = {**os.environ, 'PATH': str(binaries),
                           'CAPACITY_TEST': 'module::capacity',
                           'candidate_log': directory}
            for content, accepted in (
                ('module::capacity: test\nmodule::other: test\n', True),
                ('module::other: test\n', False),
                ('module::capacity: test\nmodule::capacity_more: test\n', False),
            ):
                catalog.write_text(content)
                for guard in guards:
                    with self.subTest(content=content, guard=guard):
                        result = subprocess.run(
                            ['/bin/bash', '-euo', 'pipefail', '-c', guard],
                            env=environment, capture_output=True, text=True,
                            timeout=10, check=False)
                        self.assertEqual(result.returncode == 0, accepted,
                                         result.stderr)

    def test_capacity_result_requires_one_executed_passing_test(self):
        checks = [line.strip() for line in self.native.splitlines()
                  if line.strip().startswith('grep ')
                  and 'debug-capacity.log' in line]
        self.assertEqual(len(checks), 1)
        with tempfile.TemporaryDirectory() as directory:
            result_file = Path(directory) / 'debug-capacity.log'
            for content, accepted in (
                ('test result: ok. 1 passed; 0 failed; 0 ignored; 1139 filtered out\n', True),
                ('test result: ok. 0 passed; 0 failed; 0 ignored; 1140 filtered out\n', False),
                ('test result: FAILED. 0 passed; 1 failed; 0 ignored; 1139 filtered out\n', False),
                ('test result: ok. 0 passed; 0 failed; 1 ignored; 1139 filtered out\n', False),
            ):
                result_file.write_text(content)
                with self.subTest(content=content):
                    result = subprocess.run(
                        ['/bin/bash', '-euo', 'pipefail', '-c', checks[0]],
                        env={**os.environ, 'PATH': '/usr/bin:/bin',
                             'candidate_log': directory},
                        capture_output=True, text=True, timeout=10, check=False)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_missing_capacity_or_silent_skipping_refuses(self):
        for before, after in (("partition: capacity", "partition: omitted"),
                              ('-- --exact --nocapture', '-- --nocapture'),
                              ('grep -c -F "$CAPACITY_TEST"', 'grep -c -F -x "$CAPACITY_TEST: test"'),
                              ('--release -- --nocapture', '--release -- --ignored')):
            changed = self.native.replace(before, after)
            self.assertNotEqual(changed, self.native)
            with self.assertRaises(ValueError):
                native(changed)

    def test_missing_installation_or_colliding_artifacts_refuses(self):
        for before, after in (("phase: installed", "phase: omitted"),
                              ("if: matrix.phase == 'source'", "if: false"),
                              ('-${{ matrix.phase }}', ''), ('timeout-minutes: 120', 'timeout-minutes: 240')):
            changed = self.independent.replace(before, after)
            self.assertNotEqual(changed, self.independent)
            with self.assertRaises(ValueError):
                independent(changed)


if __name__ == '__main__':
    unittest.main()
