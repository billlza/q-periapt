"""Archive, scope and execution evidence must fail closed for the Swift adapter."""
import hashlib
import io
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

import continuity_swift_consumer as swift


class SwiftConsumerTests(unittest.TestCase):
    def test_swift_dispatch_name_is_preserved_while_target_bytes_are_hashed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            frontend = root / "swift-frontend"
            frontend.write_bytes(b"tool identity fixture")
            frontend.chmod(0o755)
            alias = root / "swift"
            alias.symlink_to(frontend.name)
            command, identity = swift.compiler_command(str(alias))
            self.assertEqual(command, alias)
            self.assertEqual(identity["path"], str(frontend))
            self.assertEqual(identity["sha256"], hashlib.sha256(frontend.read_bytes()).hexdigest())
            with self.assertRaisesRegex(ValueError, "command differs"):
                swift.compiler_command(str(frontend))

    def test_archive_bytes_must_match_before_any_installation(self):
        data = swift.archive({"Package.swift": b"manifest", "Sources/Client.swift": b"source"})
        expected = {"Package.swift": hashlib.sha256(b"manifest").hexdigest(),
                    "Sources/Client.swift": hashlib.sha256(b"source").hexdigest()}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            swift.unpack(data, expected, root / "good")
            self.assertEqual((root / "good/Sources/Client.swift").read_bytes(), b"source")
            with self.assertRaisesRegex(ValueError, "destination"):
                swift.unpack(data, expected, root / "good")
            changed = dict(expected, **{"Sources/Client.swift": "0" * 64})
            with self.assertRaisesRegex(ValueError, "hash"):
                swift.unpack(data, changed, root / "bad")
            self.assertFalse((root / "bad").exists())

    def test_traversal_and_symlink_entries_are_refused_before_writes(self):
        with tempfile.TemporaryDirectory() as folder:
            for index, (name, mode) in enumerate((("../escape", stat.S_IFREG), ("lib", stat.S_IFLNK))):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as zipped:
                    item = zipfile.ZipInfo(name)
                    item.external_attr = (mode | 0o644) << 16
                    zipped.writestr(item, b"target")
                output = Path(folder) / str(index)
                with self.assertRaisesRegex(ValueError, "canonical regular"):
                    swift.unpack(buffer.getvalue(), {name: hashlib.sha256(b"target").hexdigest()}, output)
                self.assertFalse(output.exists())

    def test_passing_summary_without_each_swift_test_is_refused(self):
        with self.assertRaisesRegex(ValueError, "all execute"):
            swift.verify_tests(b"Executed 6 tests, with 0 failures", b"")
        names = (("OwnerTests", "testARCRetiresPendingSlotsAndClosedAliases"),
                 ("OwnerTests", "testDiagnosticRejectsInconsistentAndInvalidUTF8"),
                 ("OwnerTests", "testIDsAndTextsRejectAmbiguousInput"),
                 ("ServerTests", "testCallbackCopiesBorrowedRegions"),
                 ("ServerTests", "testCallbackFailureAndForeignBoundsCannotBecomeConsumption"),
                 ("ServerTests", "testServedRecordRejectsUnknownKindsAndInconsistentBootstrap"))
        output = ("\n".join(f"Test Case '-[QPeriaptContinuityTests.{owner} {name}]' passed" for owner, name in names)
                  + "\nExecuted 6 tests, with 0 failures").encode()
        swift.verify_tests(output, b"")
        with self.assertRaisesRegex(ValueError, "all execute"):
            swift.verify_tests(output + output, b"")

    def test_foreign_library_and_missing_installed_rpath_are_refused(self):
        dependencies = "client:\n\t@rpath/" + swift.LIBRARY + " (compatibility version 0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 0)\n"
        path = Path("/installed/native/lib")
        loader = "cmd LC_RPATH\ncmdsize 128\npath /installed/native/lib (offset 12)"
        self.assertEqual(swift.verify_linkage(dependencies, loader, path), [str(path)])
        with self.assertRaisesRegex(ValueError, "search path"):
            swift.verify_linkage(dependencies, loader.replace("/installed", "/build"), path)
        with self.assertRaisesRegex(ValueError, "unqualified"):
            swift.verify_linkage(dependencies + "\t/tmp/unqualified.dylib (compatibility version 0)\n", loader, path)


if __name__ == "__main__":
    unittest.main()
