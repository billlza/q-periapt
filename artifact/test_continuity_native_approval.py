"""Qualification boundary tests; no mocked run is counted as SDK execution."""
from pathlib import Path
import hashlib
import json
import tempfile
import unittest
from unittest import mock
import continuity_native_approval_fault as fault
import continuity_native_approval_instrument as instrumenter


class NativeApprovalQualificationTests(unittest.TestCase):
    def test_changed_publication_boundaries_cannot_silently_reduce_fault_coverage(self):
        source = (instrumenter.SOURCE / 'src/approval.rs').read_text()
        result = instrumenter.instrument(source)
        for stage in instrumenter.STAGES:
            self.assertEqual(result.count(f'approval_fault(public, kind, "{stage}", control)?;'), 1)
        for boundary in ('        .tempdir_in(public)?;', '        file.sync_all()?;',
                         '    fs::File::open(staging.path())?.sync_all()?;',
                         '    fs::rename(staging.path(), &destination)?;',
                         '    matches(&destination, &rows)\n}'):
            for changed in (source.replace(boundary, ''), source.replace(boundary, boundary + '\n' + boundary)):
                with self.assertRaises(ValueError):
                    instrumenter.instrument(changed)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / 'artifact').mkdir()
        (root / 'artifact/continuity_native_approval_instrument.py').write_bytes(b'instrumenter fixture')
        (root / 'original-counterpart').write_bytes(b'original fixture; not executable')
        (root / 'fault-counterpart').write_bytes(b'fault fixture; not executable')
        report = {'completed_build': True, 'runtime_qualified': False, 'source_commit': 'a' * 40,
                  'source_inputs': {'native-source.rs': 'b' * 64},
                  'instrumenter_sha256': fault.digest(root / 'artifact/continuity_native_approval_instrument.py'),
                  'native_sha256': fault.digest(root / 'original-counterpart'),
                  'fault_native_sha256': fault.digest(root / 'fault-counterpart')}
        return root, report

    def verify(self, root, report):
        (root / 'BUILD.json').write_text(json.dumps(report))
        with mock.patch.object(fault, 'ROOT', root), \
             mock.patch.object(fault, 'source_inputs', return_value={'native-source.rs': 'b' * 64}), \
             mock.patch.object(fault, 'git_commit', return_value='a' * 40):
            return fault.verify_build(root)

    def test_build_identity_refuses_missing_extra_or_changed_source_and_binary(self):
        root, report = self.fixture()
        self.assertEqual(self.verify(root, report), report)
        for inputs in ({}, {'native-source.rs': 'c' * 64},
                       {'native-source.rs': 'b' * 64, '../../outside': 'd' * 64}):
            with self.assertRaises(ValueError):
                self.verify(root, dict(report, source_inputs=inputs))
        (root / 'fault-counterpart').write_bytes(b'changed fixture')
        with self.assertRaises(ValueError):
            self.verify(root, report)

    def test_stale_commit_and_promoted_build_scope_are_rejected(self):
        root, report = self.fixture()
        for changes in ({'source_commit': 'c' * 40}, {'runtime_qualified': True},
                        {'completed_build': 1}, {'instrumenter_sha256': hashlib.sha256(b'changed').hexdigest()}):
            with self.assertRaises(ValueError):
                self.verify(root, dict(report, **changes))


if __name__ == '__main__':
    unittest.main()
