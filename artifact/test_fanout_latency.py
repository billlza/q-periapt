"""Reject incomplete timing, wrong workloads and source/binary substitution."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from fanout_latency import manifest, test_binary, verify_sources
from fanout_latency_review import PREFIX, TEST, catalog, identities, samples, unpack_source


def fixture():
    stdout = (f'test {TEST} ... ok\n'
              'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out;\n').encode()
    rows = []
    for same in ('false', 'true'):
        for index in range(6):
            payload, ad = ((0, 0), (1024, 32), (16384, 1024))[index % 3]
            rows.append(f'fanout_path_sample same_account={same} sample={index} plaintext={payload} '
                        f'ad={ad} recipients=2 elapsed_ns=1000000\n')
    return stdout, ''.join(rows).encode()


class FanoutLatencyChecks(unittest.TestCase):
    def test_requires_actual_selected_test_and_complete_workload_positions(self):
        stdout, stderr = fixture()
        self.assertEqual(len(samples(stdout, stderr, 42)), 12)
        lines = stderr.splitlines(keepends=True)
        for out, err in ((b'', stderr), (stdout.replace(b'1 passed', b'0 passed'), stderr),
                         (stdout.replace(b'0 ignored', b'1 ignored'), stderr),
                         (stdout, b''.join(lines[:-1])),
                         (stdout, b''.join(lines[:-1] + [lines[0]])),
                         (stdout, stderr.replace(b'plaintext=1024 ', b'plaintext=1023 ')),
                         (stdout, stderr.replace(b'recipients=2', b'recipients=1')),
                         (stdout, stderr.replace(b'elapsed_ns=1000000', b'elapsed_ns=0')),
                         (stdout, stderr + b'warning: retained diagnostic\n')):
            with self.subTest(stdout=out, stderr=err), self.assertRaises(ValueError):
                samples(out, err, 42)

    def test_catalog_rejects_absent_or_duplicate_test(self):
        valid = (TEST + ': test\nanother: test\n').encode()
        self.assertEqual(len(catalog(valid)), 2)
        for invalid in (b'another: test\n', valid + valid):
            with self.assertRaises(ValueError):
                catalog(invalid)

    def test_binary_identity_refuses_shared_target_reuse(self):
        identities({'baseline': 'a' * 64, 'candidate': 'b' * 64})
        for value in ({'baseline': 'a' * 64, 'candidate': 'a' * 64},
                      {'baseline': 'a' * 64}, {'baseline': 'bad', 'candidate': 'b' * 64}):
            with self.assertRaises(ValueError):
                identities(value)

    def test_cargo_artifact_selection_refuses_other_source_and_multiple_executables(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); source = root / 'source'; target = root / 'build'
            source.mkdir(); target.mkdir(); binary = target / 'test-bin'; binary.write_bytes(b'fixture')
            record = {'reason': 'compiler-artifact', 'profile': {'test': True},
                      'executable': str(binary), 'target': {'src_path': str(source / 'src/lib.rs')}}
            encoded = json.dumps(record).encode()
            self.assertEqual(test_binary(encoded, source, target), binary)
            wrong = dict(record, target={'src_path': str(source / 'other.rs')})
            for invalid in (b'', encoded + b'\n' + encoded, json.dumps(wrong).encode()):
                with self.assertRaises(ValueError):
                    test_binary(invalid, source, target)

    def test_archive_refuses_links_traversal_and_duplicate_before_use(self):
        for name, kind in ((PREFIX + '../escape.rs', tarfile.REGTYPE),
                           (PREFIX + 'src/link.rs', tarfile.SYMTYPE),
                           ('outside/file.rs', tarfile.REGTYPE)):
            content = io.BytesIO()
            with tarfile.open(fileobj=content, mode='w') as archive:
                entry = tarfile.TarInfo(name); entry.type = kind
                archive.addfile(entry, io.BytesIO(b''))
            with self.assertRaises(ValueError):
                unpack_source(content.getvalue())
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode='w') as archive:
            for _ in range(2):
                archive.addfile(tarfile.TarInfo(PREFIX + 'src/duplicate.rs'), io.BytesIO(b''))
        with self.assertRaises(ValueError):
            unpack_source(content.getvalue())

    def test_manifest_preserves_profile_and_rejects_path_alias(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / PREFIX / 'Cargo.toml').read_bytes()
        result = manifest(source, root)
        self.assertIn(b'lto = "thin"', result)
        self.assertNotIn(b'path = "../../crates/', result)
        for invalid in (source.replace(b'lto = "thin"', b'lto = false'),
                        source.replace(b'../../crates/', b'xx/xx/crates/')):
            with self.assertRaises(ValueError):
                manifest(invalid, root)

    def test_source_drift_is_refused(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            for variant in ('baseline', 'candidate'):
                root = work / variant / 'source'; root.mkdir(parents=True)
                (root / 'lib.rs').write_bytes(b'original')
            files = {'lib.rs': hashlib.sha256(b'original').hexdigest()}
            source = {'build_files': {'baseline': files, 'candidate': files}}
            verify_sources(work, source)
            (work / 'candidate/source/lib.rs').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                verify_sources(work, source)


if __name__ == '__main__':
    unittest.main()
