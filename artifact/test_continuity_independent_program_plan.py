"""Refuse incomplete, substituted or changed independent-program experiments."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'research/continuity-openssl-peer'
sys.path.append(str(SOURCE))
from native_program_plan import CUTS, NativeProgramPlan


class ProgramPlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / 'plan.json'
        programs = {}
        for index, name in enumerate(('before', 'after'), 1):
            executable = self.root / name
            executable.write_bytes(('distinct test program ' + name).encode())
            report = self.root / (name + '.json')
            report.write_text(json.dumps({'kind': 'qperiapt.independent_installed_counterpart',
                'completed': True, 'sources_unchanged': True, 'source_commit': str(index) * 40,
                'native_sha256': hashlib.sha256(executable.read_bytes()).hexdigest()}))
            programs[name] = {'executable': str(executable), 'installation_report': str(report),
                              'installation_report_sha256': hashlib.sha256(report.read_bytes()).hexdigest()}
        self.value = {'schema_version': 1, 'programs': programs,
                      'restarts': [{'case': case, 'program': 'before' if i % 2 == 0 else 'after'}
                                   for i, case in enumerate(CUTS)]}
        self.initial = self.root / 'before'

    def load(self, value=None):
        self.path.write_text(json.dumps(self.value if value is None else value))
        return NativeProgramPlan(self.path, self.initial)

    def test_all_original_cuts_and_both_directions_are_required(self):
        plan = self.load()
        with self.assertRaisesRegex(ValueError, 'missing restart'):
            plan.finish()
        current = self.initial
        for index, case in enumerate(CUTS):
            selected, receipt = plan.select(case, current)
            self.assertEqual(receipt['index'], index)
            plan.reopened(case, selected)
            current = selected
        self.assertTrue(plan.finish()['completed'])
        with self.assertRaisesRegex(ValueError, 'extra restart'):
            plan.select('new-epoch', current)

    def test_partial_reordered_and_one_direction_plans_are_refused(self):
        mutations = [lambda p: p.update(schema_version=True), lambda p: p.update(extra=True),
                     lambda p: p['restarts'].pop(), lambda p: p['restarts'].reverse(),
                     lambda p: p['restarts'][1].update(case='approved'),
                     lambda p: p['restarts'][1].update(program='fallback'),
                     lambda p: [s.update(program='after') for s in p['restarts']]]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                value = copy.deepcopy(self.value); mutate(value)
                with self.assertRaises(ValueError):
                    self.load(value)

    def test_wrong_start_or_duplicate_program_cannot_qualify(self):
        self.load()
        with self.assertRaisesRegex(ValueError, 'initial executable differs'):
            NativeProgramPlan(self.path, self.root / 'after')
        value = copy.deepcopy(self.value)
        value['programs']['after'] = value['programs']['before']
        with self.assertRaisesRegex(ValueError, 'distinct builds'):
            self.load(value)

    def test_report_and_executable_substitutions_are_refused(self):
        for field in ('installation_report', 'executable'):
            with self.subTest(field=field):
                value = copy.deepcopy(self.value)
                value['programs']['after'][field] = value['programs']['before'][field]
                with self.assertRaises(ValueError):
                    self.load(value)
        link = self.root / 'alias'
        link.symlink_to(self.initial)
        value = copy.deepcopy(self.value)
        value['programs']['before']['executable'] = str(link)
        with self.assertRaisesRegex(ValueError, 'canonical'):
            self.load(value)

    def test_failed_or_unbound_build_report_is_refused(self):
        path = self.root / 'before.json'
        original = json.loads(path.read_text())
        for key, changed in [('completed', False), ('sources_unchanged', False),
                             ('source_commit', 'unknown'), ('kind', 'source-only-counterpart')]:
            with self.subTest(key=key):
                report = original | {key: changed}
                path.write_text(json.dumps(report))
                value = copy.deepcopy(self.value)
                value['programs']['before']['installation_report_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.assertRaises(ValueError):
                    self.load(value)

    def test_changes_after_admission_do_not_advance_plan(self):
        for path in (self.path, self.root / 'after', self.root / 'after.json'):
            with self.subTest(path=path.name):
                plan = self.load()
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b' ')
                    with self.assertRaisesRegex(ValueError, 'changed'):
                        plan.select('approved', self.initial)
                    self.assertEqual(plan.index, 0)
                finally:
                    path.write_bytes(original)

    def test_wrong_cut_or_reopen_cannot_advance_plan(self):
        plan = self.load()
        with self.assertRaisesRegex(ValueError, 'unexpected process or cut'):
            plan.select('reply', self.initial)
        with self.assertRaisesRegex(ValueError, 'unexpected process or cut'):
            plan.select('approved', self.root / 'after')
        with self.assertRaisesRegex(ValueError, 'reopened executable differs'):
            plan.reopened('approved', self.root / 'after')
        self.assertEqual(plan.index, 0)

    def test_duplicate_json_fields_and_wrong_fixture_mode_are_refused(self):
        self.path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            NativeProgramPlan(self.path, self.initial)
        command = [sys.executable, '-I', '-S', '-B', str(ROOT / 'artifact/python_bootstrap.py'),
                   str(SOURCE / 'enrollment_session_checks.py'), '--implementation-root', str(self.root),
                   '--provider-root', str(self.root), '--native', str(self.initial),
                   '--output', str(self.root / 'output'), '--native-restart-program-plan', str(self.path),
                   '--root-successor-process-restart', 'peer-before']
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'requires --root-successor-process-restart peer', result.stderr)
        self.assertFalse((self.root / 'output').exists())


if __name__ == '__main__':
    unittest.main()
