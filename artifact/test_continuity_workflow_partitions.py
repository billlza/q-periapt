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
    expected.update(('ubuntu-24.04', toolchain, 'release') for toolchain in ('1.98.1', '1.90.0'))
    expected.add(('macos-15', '1.98.1', 'release'))
    expected.update(('ubuntu-24.04', toolchain, part)
                    for toolchain in ('1.98.1', '1.90.0') for part in ('roster-capacity', 'enrollment'))
    if len(rows) != len(expected) or set(rows) != expected:
        raise ValueError('complete Debug partitions and separate Release budgets are required')
    if ('timeout-minutes: 90' not in block or 'fail-fast: false' not in block
            or 'continue-on-error:' in block):
        raise ValueError('native failure or timeout contract changed')
    suite = block.split('      - name: Check and exercise candidate with the selected compiler\n', 1)[1].split('\n      - ', 1)[0]
    capacity = block.split('      - name: Exercise the complete Debug capacity scenario\n', 1)[1].split('\n      - ', 1)[0]
    roster = block.split('      - name: Exercise the complete Debug roster capacity scenario\n', 1)[1].split('\n      - ', 1)[0]
    enrollment = block.split('      - name: Exercise the complete Debug enrollment partition\n', 1)[1].split('\n      - ', 1)[0]
    release = block.split('      - name: Exercise the complete Release candidate\n', 1)[1].split('\n      - ', 1)[0]
    sdk_release = block.split('      - name: Verify sealed SDK operations in Release\n', 1)[1].split('\n      - ', 1)[0]
    for part, body in (('suite', suite), ('capacity', capacity)):
        if f"if: matrix.partition == '{part}'" not in body:
            raise ValueError('partition execution condition differs')
        if 'test "$(grep -c -F "$CAPACITY_TEST" "$candidate_log/debug-catalog.txt")" = 1' not in body:
            raise ValueError('missing test or overlapping skip must refuse')
    if ('-- "${candidate_skips[@]}" --nocapture' not in suite
            or 'candidate_skips=(--skip "$CAPACITY_TEST")' not in suite
            or 'if [ "$RUNNER_OS" = Linux ]; then\n            candidate_skips+=(--skip "$ROSTER_CAPACITY_TEST")\n            candidate_skips+=(--skip \'enrollment::\')\n          fi' not in suite
            or '--release' in suite
            or '--lib "$CAPACITY_TEST" -- --exact --nocapture' not in capacity
            or 'test result: ok\\. 1 passed; 0 failed; 0 ignored;' not in capacity):
        raise ValueError('complementary Debug or complete Release coverage changed')
    guard = 'test "$(grep -c -F "$ROSTER_CAPACITY_TEST" "$candidate_log/debug-catalog.txt")" = 1'
    if (guard not in suite or guard not in roster
            or "if: matrix.partition == 'roster-capacity'" not in roster
            or '--lib "$ROSTER_CAPACITY_TEST" -- --exact --nocapture' not in roster
            or 'test result: ok\\. 1 passed; 0 failed; 0 ignored;' not in roster):
        raise ValueError('complete original-owner roster capacity must execute separately on Linux')
    enrollment_command = ('cargo +"$CANDIDATE_TOOLCHAIN" test --manifest-path "$candidate_manifest" '
                          '--all-features --locked \'enrollment::\' -- --skip "$CAPACITY_TEST" '
                          '--skip "$ROSTER_CAPACITY_TEST" --nocapture')
    if ("if: matrix.partition == 'enrollment'" not in enrollment
            or enrollment.count(enrollment_command) != 1
            or guard not in enrollment
            or 'test "$(grep -c -F "$CAPACITY_TEST" "$candidate_log/debug-catalog.txt")" = 1' not in enrollment
            or 'source-commit.txt' not in enrollment or 'rustc.txt' not in enrollment
            or 'test "$(grep -c -F \'enrollment::\' "$candidate_log/debug-catalog.txt")" -gt 2' not in enrollment):
        raise ValueError('enrollment must complement the Linux suite including non-library tests')
    enrollment_doc_command = ('cargo +"$CANDIDATE_TOOLCHAIN" test --manifest-path "$candidate_manifest" '
                              '--all-features --locked --doc \'enrollment::\' -- --nocapture')
    if (enrollment.count(enrollment_doc_command) != 1
            or 'tee "$candidate_log/debug-enrollment-doc.log"' not in enrollment
            or 'grep \'^test result: ok\\. 2 passed; 0 failed; 0 ignored;\' "$candidate_log/debug-enrollment-doc.log"' not in enrollment):
        raise ValueError('both enrollment type-isolation doctests must actually execute')
    condition = "if: matrix.partition == 'release'"
    if any(condition not in {line.strip() for line in body.splitlines()}
           for body in (release, sdk_release)):
        raise ValueError('Release must run exactly once per compiler outside Debug')
    candidate_command = 'cargo +"$CANDIDATE_TOOLCHAIN" test --manifest-path "$candidate_manifest" --all-features --locked --release -- --nocapture'
    sdk_command = 'cargo +"$CANDIDATE_TOOLCHAIN" test --locked --release -p q-periapt-sdk --features sealed-operations'
    if (release.count(candidate_command) != 1 or block.count(candidate_command) != 1
            or sdk_release.count(sdk_command) != 1 or block.count(sdk_command) != 1
            or '--skip' in release or '--ignored' in release
            or 'source-commit.txt' not in release or 'rustc.txt' not in release):
        raise ValueError('complete candidate and sealed SDK Release execution or provenance changed')
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

    def test_installed_jni_public_directories_survive_artifact_selection(self):
        block = self.native.split('  continuity-installed-swift:\n', 1)[1].split('\n  continuity-installed-coverage:', 1)[0]
        retained = block.split('      - name: Retain native packages and selected public execution evidence\n', 1)[1]
        match = re.search(r'          path: \|\n((?:            [^\n]+\n)+)', retained)
        self.assertIsNotNone(match)
        patterns = [line.strip() for line in match[1].splitlines()]
        routes = (["root-" + route for route in ("original", "transition", "bound-transition", "adoption", "noncommit")]
                  + ["retirement", "roster-local", "roster-peer", "roster-witness", "policy-roster",
                     "recovery-first-use-public", "recovery-witness-calls", "recovery-result-calls"]
                  + ["recovery-oracle-" + str(index) for index in range(4)])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); required = set()
            for profile in ("debug", "release"):
                for route in routes:
                    path = root / f"target/continuity-installed-swift/android-jni-{profile}-{route}/scope/public-result.bin"
                    path.parent.mkdir(parents=True); path.write_bytes(b"public evidence")
                    required.add(path)
            private = root / "target/continuity-installed-swift/private/journal"
            private.parent.mkdir(); private.write_bytes(b"must not be selected")
            selected = {path for pattern in patterns for path in root.glob(pattern) if path.is_file()}
            self.assertEqual(required - selected, set(), "JNI public evidence omitted from uploaded archive")
            self.assertNotIn(private, selected)

    def test_catalog_guards_execute_without_optional_runner_tools(self):
        # Hosted Linux runners do not promise ripgrep. Execute both actual
        # workflow guards with only the standard system tools on PATH.
        guards = [line.strip() for line in self.native.splitlines()
                  if line.strip().startswith('test "$(')
                  and 'debug-catalog.txt' in line and 'enrollment::' not in line]
        self.assertEqual(len(guards), 6)
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / 'debug-catalog.txt'
            binaries = Path(directory) / 'bin'
            binaries.mkdir()
            (binaries / 'grep').symlink_to('/usr/bin/grep')
            environment = {**os.environ, 'PATH': str(binaries),
                           'CAPACITY_TEST': 'module::capacity',
                           'ROSTER_CAPACITY_TEST': 'module::capacity',
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
                  and ('debug-capacity.log' in line or 'debug-roster-capacity.log' in line)]
        self.assertEqual(len(checks), 2)
        with tempfile.TemporaryDirectory() as directory:
            result_file = Path(directory) / 'debug-capacity.log'
            for content, accepted in (
                ('test result: ok. 1 passed; 0 failed; 0 ignored; 1139 filtered out\n', True),
                ('test result: ok. 0 passed; 0 failed; 0 ignored; 1140 filtered out\n', False),
                ('test result: FAILED. 0 passed; 1 failed; 0 ignored; 1139 filtered out\n', False),
                ('test result: ok. 0 passed; 0 failed; 1 ignored; 1139 filtered out\n', False),
            ):
                result_file.write_text(content)
                (Path(directory) / 'debug-roster-capacity.log').write_text(content)
                for check in checks:
                    with self.subTest(content=content, check=check):
                        result = subprocess.run(
                            ['/bin/bash', '-euo', 'pipefail', '-c', check],
                            env={**os.environ, 'PATH': '/usr/bin:/bin',
                                 'candidate_log': directory},
                            capture_output=True, text=True, timeout=10, check=False)
                        self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_enrollment_partition_refuses_an_empty_ordinary_selection(self):
        guards = [line.strip() for line in self.native.splitlines()
                  if line.strip().startswith('test "$(')
                  and "grep -c -F 'enrollment::'" in line]
        self.assertEqual(len(guards), 1)
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / 'debug-catalog.txt'
            for count in (0, 1, 2, 3):
                catalog.write_text(''.join(f'enrollment::case_{n}: test\n' for n in range(count)))
                result = subprocess.run(['/bin/bash', '-euo', 'pipefail', '-c', guards[0]],
                    env={**os.environ, 'PATH': '/usr/bin:/bin', 'candidate_log': directory},
                    capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode == 0, count > 2, result.stderr)

    def test_linux_debug_partition_union_is_complete_without_duplicates(self):
        suite = self.native.split('      - name: Check and exercise candidate with the selected compiler\n', 1)[1].split('\n      - ', 1)[0]
        selection = 'candidate_skips=' + suite.split('candidate_skips=', 1)[1].split('          # Explicit failure', 1)[0]
        catalogue = {'enrollment::fanout_capacity', 'enrollment::roster_capacity',
                     'module::ordinary', 'enrollment::ordinary', 'other::enrollment::nested'}
        for os_name in ('Linux', 'macOS'):
            result = subprocess.run(['/bin/bash', '-euo', 'pipefail', '-c', selection + '\nprintf "%s\\n" "${candidate_skips[@]}"'],
                env={**os.environ, 'RUNNER_OS': os_name, 'CAPACITY_TEST': 'enrollment::fanout_capacity', 'ROSTER_CAPACITY_TEST': 'enrollment::roster_capacity'},
                capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = result.stdout.splitlines()
            expected = (['enrollment::fanout_capacity', 'enrollment::roster_capacity', 'enrollment::']
                        if os_name == 'Linux' else ['enrollment::fanout_capacity'])
            self.assertEqual(args[::2], ['--skip'] * len(expected))
            self.assertEqual(args[1::2], expected)
            executed = [{n for n in catalogue if not any(skip in n for skip in expected)},
                        {'enrollment::fanout_capacity'}]
            if os_name == 'Linux':
                executed.extend([{'enrollment::roster_capacity'},
                    {n for n in catalogue if 'enrollment::' in n
                     and not any(skip in n for skip in expected[:2])}])
            self.assertEqual(set.union(*executed), catalogue)
            self.assertEqual(sum(map(len, executed)), len(catalogue))

    def test_actual_enrollment_doc_command_rejects_missing_or_broken_doctests(self):
        # Exercise Cargo itself: a positional filter on this rlib/cdylib target
        # previously passed without executing any doctests.
        block = self.native.split('      - name: Exercise the complete Debug enrollment partition\n', 1)[1].split('\n      - ', 1)[0]
        lines = [line.strip() for line in block.splitlines()
                 if 'debug-enrollment-doc.log' in line]
        self.assertEqual(len(lines), 2)
        source = '''pub mod enrollment {
    /// ```compile_fail
    /// let _: u8 = "invalid";
    /// ```
    pub struct Original;
    /// ```compile_fail
    /// let _: bool = 0;
    /// ```
    pub struct Retired;
}
/// ```compile_fail
/// let _valid = 1;
/// ```
pub struct OutsideSelection;
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'src').mkdir()
            (root / 'Cargo.toml').write_text(
                '[package]\nname="workflow-doc-selection"\nversion="0.0.0"\nedition="2021"\n'
                '[lib]\ncrate-type=["rlib","cdylib"]\n[workspace]\n')
            (root / 'Cargo.lock').write_text(
                'version = 4\n[[package]]\nname = "workflow-doc-selection"\nversion = "0.0.0"\n')
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(('CARGO_', 'RUST')) or key == 'RUSTUP_HOME'}
            environment.update(CARGO_HOME=str(root / 'cargo-home'),
                               CARGO_TARGET_DIR=str(root / 'build'),
                               CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never',
                               CANDIDATE_TOOLCHAIN='1.98.1',
                               candidate_manifest=str(root / 'Cargo.toml'),
                               candidate_log=str(root))
            for label, selected_source, accepted in (
                ('complete', source, True),
                ('missing', source.replace('    /// ```compile_fail\n    /// let _: bool = 0;\n    /// ```\n', ''), False),
                ('broken', source.replace('let _: bool = 0;', 'let _: bool = true;'), False),
            ):
                with self.subTest(case=label):
                    (root / 'src/lib.rs').write_text(selected_source)
                    result = subprocess.run(
                        ['/bin/bash', '-euo', 'pipefail', '-c', '\n'.join(lines)],
                        cwd=root, env=environment, capture_output=True, text=True,
                        timeout=120, check=False)
                    self.assertEqual(result.returncode == 0, accepted,
                                     result.stdout + result.stderr)
                    output = (root / 'debug-enrollment-doc.log').read_text()
                    if accepted:
                        self.assertIn('enrollment::Original', output)
                        self.assertIn('enrollment::Retired', output)
                    elif label == 'missing':
                        self.assertIn('test result: ok. 1 passed;', output)
                    else:
                        self.assertIn('test result: FAILED.', output)

    def test_enrollment_doctests_cannot_be_omitted_or_weakened(self):
        for before, after in (
            ("--locked --doc 'enrollment::' --", "--locked 'enrollment::' --"),
            ("--doc 'enrollment::'", "--doc 'missing::'"),
            ('debug-enrollment-doc.log', 'omitted.log'),
            ('2 passed; 0 failed; 0 ignored;', '0 passed; 0 failed; 0 ignored;'),
        ):
            changed = self.native.replace(before, after)
            self.assertNotEqual(changed, self.native)
            with self.assertRaises(ValueError):
                native(changed)

    def test_missing_capacity_or_silent_skipping_refuses(self):
        for before, after in (("partition: capacity", "partition: omitted"),
                              ("partition: enrollment", "partition: omitted"),
                              ("candidate_skips+=(--skip 'enrollment::')", "candidate_skips+=(--skip 'missing::')"),
                              ("--locked 'enrollment::' --", "--locked --lib 'enrollment::' --"),
                              ("partition: roster-capacity", "partition: omitted"),
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

    def test_release_cannot_return_to_debug_or_lose_sdk_coverage(self):
        for before, after in (
            ('partition: release', 'partition: omitted'),
            ("if: matrix.partition == 'release'",
             "if: matrix.partition == 'release' || (matrix.os == 'macos-15' && matrix.partition == 'suite')"),
            ("if: matrix.partition == 'release'",
             "if: matrix.partition == 'suite'"),
            ('cargo +"$CANDIDATE_TOOLCHAIN" test --locked --release -p q-periapt-sdk --features sealed-operations',
             'true'),
        ):
            changed = self.native.replace(before, after)
            self.assertNotEqual(changed, self.native)
            with self.assertRaises(ValueError):
                native(changed)

    def test_phase_timing_keeps_test_failures_and_records_cpu_and_wall_time(self):
        lines = [line.strip() for line in self.native.splitlines()
                 if line.strip().startswith('{ time cargo +"$CANDIDATE_TOOLCHAIN" test ')]
        self.assertEqual(len(lines), 8)
        timing = re.search(r"TIMEFORMAT: '(QPERIAPT_CI_TIME [^']+)'", self.native)
        self.assertIsNotNone(timing)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'target/continuity-native-checks'
            output.mkdir(parents=True)
            binaries = Path(directory) / 'bin'
            binaries.mkdir()
            cargo = binaries / 'cargo'
            cargo.write_text('#!/bin/sh\nprintf "timing boundary probe\\n"\nexit "$PROBE_EXIT"\n')
            cargo.chmod(0o700)
            for line in lines:
                for code in (0, 7):
                    with self.subTest(line=line, code=code):
                        result = subprocess.run(
                            ['/bin/bash', '-euo', 'pipefail', '-c', 'candidate_skips=(--skip "$CAPACITY_TEST"); ' + line],
                            cwd=directory, env={**os.environ, 'PATH': str(binaries) + ':/usr/bin:/bin',
                                'CANDIDATE_TOOLCHAIN': '1.98.1', 'candidate_manifest': 'unused',
                                'CAPACITY_TEST': 'unused', 'ROSTER_CAPACITY_TEST': 'unused-roster', 'candidate_log': str(output),
                                'PROBE_EXIT': str(code), 'TIMEFORMAT': timing.group(1)},
                            capture_output=True, text=True, timeout=10, check=False)
                        self.assertEqual(result.returncode, code, result.stderr)
                        self.assertIn('timing boundary probe', result.stdout)
                        self.assertRegex(result.stdout,
                            r'QPERIAPT_CI_TIME wall_seconds=\d+\.\d+ user_seconds=\d+\.\d+ '
                            r'system_seconds=\d+\.\d+ cpu_percent=\d+\.\d+')


if __name__ == '__main__':
    unittest.main()
