"""Archived real account-root executions, bounded exports and negative controls."""
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import tempfile
import unittest
import zipfile

import continuity_android_contract as contract
import continuity_android_root as root_reader
import continuity_android_jni as jni
import rust_sdk_profile as sdk


class AndroidRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.base = Path(temporary.name)
        cls.cases = {}
        for name, routes, catalog in (
            ("20261012-android-root", ("original", "transition", "bound-transition", "adoption"), contract.ROOT_BASE_TESTS),
            ("20261012-android-root-controls", ("noncommit",), contract.TESTS),
        ):
            archive = sdk.ROOT / "research/sdk-alpha1/evidence" / name / "HOST_CAPTURE.zip"
            with zipfile.ZipFile(archive) as bundle:
                for profile in ("debug", "release"):
                    for route in routes:
                        prefix = profile + "-" + route + "/"
                        directory = cls.base / profile / route
                        for member in bundle.namelist():
                            if not member.startswith(prefix): continue
                            relative = PurePosixPath(member.removeprefix(prefix))
                            if relative.is_absolute() or ".." in relative.parts: raise ValueError("unsafe archived member")
                            path = directory.joinpath(*relative.parts)
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_bytes(bundle.read(member))
                        cls.cases[(profile, route)] = (directory, catalog)

    def verify(self, profile="debug", route="noncommit"):
        directory, catalog = self.cases[(profile, route)]
        stdout = (directory / "execution.stdout").read_bytes()
        return root_reader.verify_execution(stdout, directory, route, catalog=catalog)

    @contextmanager
    def change(self, name, value, route="noncommit"):
        path = self.cases[("debug", route)][0] / "signed-fixed" / name
        original = path.read_bytes()
        try:
            if value is None: path.unlink()
            else: path.write_bytes(value)
            yield
        finally:
            path.write_bytes(original)

    def test_normal_driver_and_manifest_include_root_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            launcher = jni._driver(base, Path("/java"), base / "classes.jar", base / "tests", base / "native")
            self.assertTrue(launcher.is_file())
            self.assertIn("('root-', 'RootOwnedProbe')", (base / "driver.py").read_text())
        files = jni.source_files()
        for name in ("jni/root_replacement.c", "src/test/java/RootOwnedProbe.java", "src/test/java/RootControls.java",
                     "src/main/java/dev/qperiapt/continuity/android/RootOperations.java"):
            self.assertIn(name, files)

    def test_real_five_routes_and_bounded_export_reread(self):
        total = 0
        for (profile, route), (directory, catalog) in self.cases.items():
            with self.subTest(profile=profile, route=route):
                records = self.verify(profile, route)
                total += sum(record["foreign_processes"] for record in records.values())
                exported = directory / "exported"
                for trust, record in records.items():
                    for name in record["public_readbacks"]:
                        sdk.copy(directory / ("signed-" + trust) / name, exported / ("signed-" + trust) / name)
                self.assertEqual(root_reader.verify_execution((directory / "execution.stdout").read_bytes(),
                    exported, route, catalog=catalog), records)
        self.assertEqual(total, 724)

    def test_terminal_cancellation_and_original_identity_corruption(self):
        directory = self.cases[("debug", "noncommit")][0] / "signed-fixed"
        for name in ("root-noncommit-retained", "root-noncommit-replayed", "root-bad-noncommit",
                     "root-preparation-cancelled", "root-successor-cancelled", "root-retained",
                     "root-verified", "root-original-effect-after", "root-acknowledged",
                     "root-target.prepared", "original.identity"):
            with self.subTest(record=name):
                changed = bytearray((directory / name).read_bytes())
                changed[4 if name == "root-target.prepared" else -1] ^= 1
                # A successor journal must remain distinct, not equal a predetermined ID.
                if name == "root-target.prepared":
                    changed[4:36] = (directory / "prepared").read_bytes()[4:36]
                with self.change(name, bytes(changed)):
                    with self.assertRaises(ValueError): self.verify()

    def test_missing_approval_report_and_successor_process(self):
        for name in ("inputs/root-next-plan", "root-complete-report", "root-target.request.stdout"):
            with self.subTest(record=name), self.change(name, None):
                with self.assertRaises((ValueError, OSError)): self.verify()

    def test_cut_as_success_and_JNI_diagnostics_are_rejected(self):
        for name, changed in (("root-noncommit-retained.stdout", b"fixed:root-noncommit-unknown:passed\n"),
                              ("root-successor-cancelled.stderr", b"WARNING in native method"),
                              ("root-acknowledged.stdout", b"")):
            with self.subTest(record=name), self.change(name, changed):
                with self.assertRaises(ValueError): self.verify()

    def test_current_execution_census_cannot_use_historical_catalog(self):
        directory, _ = self.cases[("debug", "noncommit")]
        stdout = (directory / "execution.stdout").read_bytes()
        for changed in (stdout.replace(b"29 filtered", b"28 filtered"), stdout.replace(b"1 passed", b"0 passed"),
                        stdout.replace(b"0 ignored", b"1 ignored")):
            with self.assertRaises(ValueError): root_reader.verify_execution(changed, directory, "noncommit")
        previous, _ = self.cases[("debug", "original")]
        with self.assertRaises(ValueError):
            root_reader.verify_execution((previous / "execution.stdout").read_bytes(), previous, "original")
        with self.assertRaises(ValueError):
            root_reader.verify_execution(stdout, directory, "noncommit", catalog=contract.ROOT_BASE_TESTS)


if __name__ == "__main__":
    unittest.main()
