"""Synthetic reader controls, not signature or protocol evidence."""
from pathlib import Path
import tempfile
import unittest

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
    lines += ["test " + test + " ... ok", "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;"]
    return ("\n".join(lines) + "\n").encode()


class AndroidWitnessTests(unittest.TestCase):
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
