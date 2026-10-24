"""Synthetic reader controls, not signature or protocol evidence."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import continuity_android_contract as contract

import continuity_android_witness as witness


def fixture(root: Path, *, managed: bool = False) -> bytes:
    lines = []
    for carrier in ("signed", "tls"):
        for trust in ("fixed", "recoverable"):
            base = root / (carrier + "-" + trust); base.mkdir()
            for name, operation in witness.cases(carrier, managed=managed):
                (base / (name + ".stdout")).write_bytes(f"{trust}:{operation}:passed\n".encode())
                (base / (name + ".stderr")).write_bytes(b"")
                (base / name).write_bytes(b"r" * 5506)
            if managed:
                checkpoint = b"a" * 32 + (1).to_bytes(8, "big") + b"c" * 32
                for name in ("authority-created", "authority-reopened"): (base / name).write_bytes(checkpoint)
            (base / "wrong-pin").write_bytes(b"\1")
            (base / "genesis").write_bytes((2).to_bytes(4, "big") + b"j" * 64 + b"a" * 32 + b"d" * 32 + b"h" * 32)
            (base / "signed-witness-transcript").write_text("11" * 3674 + " " + "22" * 3659 + " true\n")
            if managed:
                lines.append(f"qualified managed witness {carrier}/{trust}: independent registry, original association, checkpoint refusal, cancelled registry retains admission, closed registry revokes admission, authenticated activation and reopen")
            else:
                lines.append(f"qualified witness {carrier}/{trust}: original registration, independent genesis, refused missing or wrong trust, authenticated activation and reopen")
    test = "android_witness::managed_first_registration" if managed else witness.TEST
    lines += ["test " + test + " ... ok", f"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; {len(contract.TESTS)-1} filtered out;"]
    return ("\n".join(lines) + "\n").encode()


class AndroidWitnessTests(unittest.TestCase):
    def test_export_replays_complete_unmanaged_and_managed_public_results(self):
        for managed in (False, True):
            with self.subTest(managed=managed), tempfile.TemporaryDirectory() as temp:
                source = Path(temp) / "source"; source.mkdir()
                output = Path(temp) / "output"; output.mkdir()
                stdout = fixture(source, managed=managed)
                verify = lambda data, path: witness.verify_execution(data, path, managed=managed)
                expected = verify(stdout, source)
                lane = "authority" if managed else "witness"
                prefix = "android-jni-debug-" + lane + "-"
                witness.export_public(stdout, source, output, prefix, expected,
                                      managed=managed, verifier=verify)
                for label in expected:
                    self.assertEqual((output / (prefix + label + "-original.request.public")).read_bytes(),
                                     (source / label / "original.request").read_bytes())
                self.assertFalse(any(path.is_dir() for path in output.iterdir()))

    def test_missing_export_member_is_rejected_by_original_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"; source.mkdir()
            output = Path(temp) / "output"; output.mkdir()
            stdout = fixture(source)
            expected = witness.verify_execution(stdout, source)
            public = witness.public
            with patch.object(witness, "public", side_effect=lambda carrier, **kwargs:
                              tuple(name for name in public(carrier, **kwargs) if name != "original.request")):
                with self.assertRaises(ValueError):
                    witness.export_public(stdout, source, output, "android-jni-debug-witness-",
                                          expected, verifier=witness.verify_execution)

    def test_export_verifies_retained_bytes_instead_of_source_only(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"; source.mkdir()
            output = Path(temp) / "output"; output.mkdir()
            stdout = fixture(source)
            expected = witness.verify_execution(stdout, source)
            copy = witness.sdk.copy
            def damaged(source_file, target_file, **kwargs):
                copy(source_file, target_file, **kwargs)
                if target_file.name.endswith("original.request.public"):
                    target_file.write_bytes(b"truncated retained request")
            with patch.object(witness.sdk, "copy", side_effect=damaged), self.assertRaises(ValueError):
                witness.export_public(stdout, source, output, "android-jni-debug-witness-",
                                      expected, verifier=witness.verify_execution)

    def test_managed_registry_requires_all_five_extra_processes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); stdout = fixture(root, managed=True)
            self.assertEqual(sum(v["foreign_processes"] for v in witness.verify_execution(stdout, root, managed=True).values()), 50)
            (root / "tls-fixed" / "closed-registry.stderr").write_bytes(b"native diagnostic")
            with self.assertRaises(ValueError): witness.verify_execution(stdout, root, managed=True)

    def test_managed_checkpoint_and_original_request_cannot_be_substituted(self):
        for name in ("authority-reopened", "unselected", "cancelled-registry"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); stdout = fixture(root, managed=True); path = root / "signed-fixed" / name
                old = path.read_bytes(); path.write_bytes(bytes([old[0] ^ 1]) + old[1:])
                with self.assertRaises(ValueError): witness.verify_execution(stdout, root, managed=True)

    def test_requires_all_carriers_and_trust_profiles(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); stdout = fixture(root)
            self.assertEqual(sum(r["foreign_processes"] for r in witness.verify_execution(stdout, root).values()), 30)
            with self.assertRaises(ValueError): witness.verify_execution(stdout.replace(b"tls/recoverable", b"tls/absent"), root)
            with self.assertRaises(ValueError): witness.verify_execution(stdout.replace(b"1 passed", b"0 passed"), root)

    def test_changed_original_and_genesis_are_rejected(self):
        for name in ("missing", "bad-receipt", "active-reopened.request", "genesis", "wrong-pin"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); stdout = fixture(root); path = root / "signed-fixed" / name
                old = path.read_bytes(); path.write_bytes(bytes([old[0] ^ 1]) + old[1:])
                with self.assertRaises(ValueError): witness.verify_execution(stdout, root)

    def test_missing_public_wire_and_jni_diagnostic_are_rejected(self):
        for name, data in (("signed-witness-transcript", b""), ("missing.stderr", b"JNI diagnostic"),
                           ("signed-witness-transcript", b"00 00 true\n")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); stdout = fixture(root); (root / "tls-fixed" / name).write_bytes(data)
                with self.assertRaises(ValueError): witness.verify_execution(stdout, root)


if __name__ == "__main__": unittest.main()
