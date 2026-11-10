"""Invalid manifest syntax or schema must fail before installed imports."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class InstalledProbeInputTests(unittest.TestCase):
    def test_invalid_expected_modules_never_import_the_package(self):
        cases = (
            (b'{"wire.py":"a","wire.py":"b"}', "duplicate"),
            (b'{"wire.py":NaN}', "non-finite"),
            (b'[]', "json object"),
            (b'\xff', "utf-8"),
            (b'{"wire.py":"' + b'a' * (64 * 1024) + b'"}', "expected installed module hashes"),
            (b'{}', "invalid schema"),
            (b'{"__init__.py":"' + b'a' * 64 + b'","provider.py":false}', "invalid schema"),
            (b'{"__init__.py":"' + b'a' * 64 + b'","provider.py":"' + b'a' * 64
             + b'","../wire.py":"' + b'a' * 64 + b'"}', "invalid schema"),
            (b'{"__init__.py":"' + b'a' * 64 + b'","provider.py":"' + b'A' * 64 + b'"}', "invalid schema"),
        )
        source = Path(__file__).resolve().parent
        for payload, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                helpers = root / "artifact"
                helpers.mkdir()
                for name in ("python_bootstrap.py", "evidence_io.py"):
                    shutil.copyfile(source / name, helpers / name)
                probe = root / "probe.py"
                shutil.copyfile(source / "continuity_independent_python_probe.py", probe)
                application = root / "installed"
                package = application / "qperiapt_continuity_reference"
                package.mkdir(parents=True)
                marker = root / "package-imported"
                # A controlled import sentinel, not a provider or crypto substitute.
                (package / "__init__.py").write_text(
                    f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
                )
                expected = root / "expected.json"
                expected.write_bytes(payload)
                output = root / "provenance.json"
                cache = root / "cache"
                cache.mkdir(mode=0o700)
                argv = [sys.executable, "-I", "-S", "-B", "-X", "pycache_prefix=" + str(cache),
                        str(helpers / "python_bootstrap.py"), str(probe), str(application),
                        str(root / "unused-provider"), str(source.parent), str(expected), str(output)]
                completed = subprocess.run(argv, cwd=root, capture_output=True, timeout=30, check=False)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, b"")
                self.assertFalse(marker.exists(), completed.stderr.decode(errors="replace"))
                self.assertIn(reason, completed.stderr.decode(errors="replace").lower())
                self.assertFalse(output.exists())
                self.assertEqual(expected.read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
