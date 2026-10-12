"""Reader rejection controls; synthetic bytes are not cryptographic evidence."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import continuity_android_jni as android


def fixture(root: Path) -> bytes:
    output = []
    for profile in ("fixed", "recoverable"):
        base = root / profile; base.mkdir()
        for label, mode in android.CASES:
            (base / (label + ".stdout")).write_bytes(f"{profile}:{mode}:passed\n".encode())
            (base / (label + ".stderr")).write_bytes(b"")
        for name in ("original.request", "resumed.request", "after-rejection.request", "activated.request"):
            (base / name).write_bytes(b"r" * 5506)
        for name in ("rejected", "active-reopened", "rekeyed", "cancelled"):
            (base / name).write_bytes(b"\x01")
        session = b"s" * 32
        (base / "connected.session").write_bytes(session)
        for name in ("uncertain.message", "acknowledged.message"):
            (base / name).write_bytes(session + b"m" * 32)
        (base / "reverse.result").write_bytes(session + b"n" * 32 + b"reverse delivery after rekey")
        output.append(f"qualified {profile}: 12 foreign processes; registration, original retry, rekey, reverse callback retry, cancellation and concurrent close")
    output += ["test android_lifecycle ... ok", "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out;"]
    return ("\n".join(output) + "\n").encode()


class AndroidJniTests(unittest.TestCase):
    def test_requires_both_trust_profiles_and_actual_test(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); stdout = fixture(root)
            self.assertEqual(android.verify_execution(stdout, root)["fixed"]["foreign_processes"], 12)
            for before, after in ((b"1 passed", b"0 passed"), (b"0 ignored", b"1 ignored"),
                                  (b"test android_lifecycle", b"test other_lifecycle"),
                                  (b"qualified recoverable:", b"missing recoverable:")):
                with self.subTest(before=before), self.assertRaises(ValueError):
                    android.verify_execution(stdout.replace(before, after), root)

    def test_missing_cancellation_or_jni_diagnostics_cannot_pass(self):
        for name, value in (("cancelled", b"\0"), ("cancelled.stdout", b""),
                            ("cancelled.stderr", b"WARNING in native method")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); stdout = fixture(root); (root / "fixed" / name).write_bytes(value)
                with self.assertRaises(ValueError): android.verify_execution(stdout, root)

    def test_replay_and_reverse_substitution_are_rejected(self):
        for name in ("after-rejection.request", "acknowledged.message", "reverse.result"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); stdout = fixture(root); path = root / "recoverable" / name
                original = path.read_bytes(); path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                with self.assertRaises(ValueError): android.verify_execution(stdout, root)

    def test_duplicate_profile_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); stdout = fixture(root)
            with self.assertRaises(ValueError): android.verify_execution(stdout + stdout.splitlines()[0] + b"\n", root)

    def test_source_symlink_is_rejected_before_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / "outside.java").write_bytes(b"source")
            source = root / "source"; source.mkdir(); (source / "borrowed.java").symlink_to(root / "outside.java")
            with patch.object(android, "SOURCE", source), self.assertRaisesRegex(ValueError, "symlink"):
                android.source_files()

    def test_source_manifest_covers_public_owner_and_cancellation_probe(self):
        files = android.source_files()
        self.assertIn("src/main/java/dev/qperiapt/continuity/android/Owner.java", files)
        self.assertIn("src/test/java/CancellationProbe.java", files)
        self.assertIn("jni/peer_server.c", files)


if __name__ == "__main__":
    unittest.main()
