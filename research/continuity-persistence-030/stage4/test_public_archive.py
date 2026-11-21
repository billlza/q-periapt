"""Exercise the public export contract against the retained native observations."""
import json
from pathlib import Path
import runpy
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
verifier = runpy.run_path(str(HERE / "verify.py"))


class PublicArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.folder = root / "run"
        self.archive = root / "public.zip"
        self.original = HERE / "evidence/observations.zip"
        with zipfile.ZipFile(self.original) as z:
            for name in verifier["public_names"]():
                member = self.folder / name
                member.parent.mkdir(parents=True, exist_ok=True)
                member.write_bytes(z.read(name))

    def test_export_keeps_exactly_the_public_observations(self):
        (self.folder / "scratch.txt").write_text("local diagnostic")
        packed = verifier["pack"](self.folder, self.archive)
        self.assertEqual(packed, verifier["verify"](self.archive))
        with zipfile.ZipFile(self.original) as source, zipfile.ZipFile(self.archive) as result:
            self.assertEqual(set(result.namelist()), set(source.namelist()))
            self.assertEqual(len(result.namelist()), 55)
            for name in source.namelist():
                self.assertEqual(result.read(name), source.read(name))
        with zipfile.ZipFile(self.archive, "a") as result:
            result.writestr("scratch.txt", "extra")
        with self.assertRaisesRegex(ValueError, "public archive inventory differs"):
            verifier["verify"](self.archive)

    def test_misbound_log_is_rejected_before_export(self):
        receipt = self.folder / "run.json"
        run = json.loads(receipt.read_bytes())
        run["tests"][0]["log"] = run["tests"][1]["log"]
        receipt.write_text(json.dumps(run))
        with self.assertRaisesRegex(ValueError, "wrong test log binding"):
            verifier["pack"](self.folder, self.archive)
        self.assertFalse(self.archive.exists())

    def test_export_requires_regular_members_throughout_the_directory(self):
        profile = self.folder / "prototype-release"
        sibling = self.folder / "local-copy"
        profile.rename(sibling)
        profile.symlink_to(sibling, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            verifier["pack"](self.folder, self.archive)
        self.assertFalse(self.archive.exists())


if __name__ == "__main__":
    unittest.main()
