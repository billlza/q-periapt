from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

import continuity_recovery_profiles as profiles
import continuity_recovery_proof as proof
import test_continuity_recovery_proof as common
from bounded_process import BoundedProcessError


class SharedStorageRecoveryProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with zipfile.ZipFile(proof.ROOT / profiles.SHARED_STORAGE.archive) as zipped:
            cls.outputs = {
                label: zipped.read(member + ".stdout")
                for label, member in (
                    ("positive", "experiments/final-12"),
                    ("attack", "prior/sibling-replay-07"),
                    ("execution", "experiments/owner-replay-19"),
                )
            }

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "input.spthy"
        self.output = self.root / "checked.spthy"

    def summary(self, label: str) -> bytes:
        return common.RecoveryProofTests.summary(self, self.outputs[label])

    def populate_inputs(self) -> None:
        for relative in (profiles.SHARED_STORAGE.model, profiles.SHARED_STORAGE.archive):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((proof.ROOT / relative).read_bytes())

    def test_real_certificates_require_the_complete_three_group_inventory(self) -> None:
        inputs = proof.load_inputs(proof.ROOT, "shared-storage")
        self.assertEqual({"positive", "attack", "execution"}, set(inputs))
        for label, count, theorem, steps in (
            ("positive", 20, profiles.KEY_SCOPED_MAIN, 8),
            ("attack", 1, profiles.SHARED_STORAGE_ATTACK, 85),
            ("execution", 1, profiles.SHARED_OWNER_EXECUTION, 168),
        ):
            with self.subTest(label=label):
                verdicts = proof.verify_summary(self.summary(label), label, self.source,
                                                self.output, "shared-storage")
                self.assertEqual(count, len(verdicts))
                self.assertEqual(steps, verdicts[theorem])

    def test_same_named_theorems_do_not_make_another_model_certificate_acceptable(self) -> None:
        # The two positive inventories deliberately have the same names and
        # statuses. Model/certificate byte pins bind the different theories.
        self.assertEqual(profiles.KEY_SCOPED.cases["positive"].expected_results(),
                         profiles.SHARED_STORAGE.cases["positive"].expected_results())
        other = proof.load_inputs(proof.ROOT, "key-scoped")["positive"]
        self.assertNotEqual(profiles.KEY_SCOPED.cases["positive"].sha256,
                            profiles.SHARED_STORAGE.cases["positive"].sha256)
        original = zipfile.ZipFile.read

        def replace_certificate(archive, name, *args, **kwargs):
            if name == profiles.SHARED_STORAGE.cases["positive"].member:
                return other
            return original(archive, name, *args, **kwargs)

        with mock.patch.object(zipfile.ZipFile, "read", new=replace_certificate):
            with self.assertRaisesRegex(proof.RecoveryProofError, "positive differs"):
                proof.load_inputs(proof.ROOT, "shared-storage")
        self.populate_inputs()
        (self.root / profiles.SHARED_STORAGE.model).write_bytes((proof.ROOT / profiles.KEY_SCOPED.model).read_bytes())
        with self.assertRaisesRegex(proof.RecoveryProofError, "model differs"):
            proof.load_inputs(self.root, "shared-storage")

    def test_missing_incomplete_or_wrong_mode_results_are_rejected(self) -> None:
        for label, case in profiles.SHARED_STORAGE.cases.items():
            data = self.summary(label)
            for name in case.verified:
                row = next(line for line in data.splitlines(True) if line.startswith(f"  {name} (".encode()))
                wrong_mode = row.replace(b"all-traces", b"exists-trace") if b"all-traces" in row else row.replace(b"exists-trace", b"all-traces")
                for replacement in (b"", row.replace(b"verified", b"analysis incomplete"), wrong_mode):
                    with self.subTest(label=label, name=name, replacement=replacement):
                        with self.assertRaises(proof.RecoveryProofError):
                            proof.verify_summary(data.replace(row, replacement), label,
                                                 self.source, self.output, "shared-storage")
            placeholder = next(line for line in data.splitlines(True) if b"analysis incomplete" in line)
            with self.assertRaises(proof.RecoveryProofError):
                proof.verify_summary(data.replace(placeholder, b""), label, self.source,
                                     self.output, "shared-storage")

    def test_older_or_swapped_witnesses_cannot_substitute_for_shared_owner_execution(self) -> None:
        with self.assertRaises(proof.RecoveryProofError):
            proof.verify_summary(self.summary("attack"), "execution", self.source,
                                 self.output, "shared-storage")
        with zipfile.ZipFile(proof.ROOT / profiles.KEY_SCOPED.archive) as zipped:
            older = common.RecoveryProofTests.summary(self, zipped.read("experiments/honest-sharing-replay-28.stdout"))
        with self.assertRaises(proof.RecoveryProofError):
            proof.verify_summary(older, "execution", self.source, self.output, "shared-storage")

    def test_model_scope_and_archive_changes_cannot_reuse_the_checkpoint(self) -> None:
        self.populate_inputs()
        model = self.root / profiles.SHARED_STORAGE.model
        original = model.read_bytes()
        for changed in (
            original.replace(profiles.KEY_SCOPED_MAIN.encode(), b"missing_main"),
            original.replace(b"Ex #x. IdentityKeyLeak(sa)@x", b"Ex any_key #x. IdentityKeyLeak(any_key)@x"),
            original.replace(b"\nend", b'\nrestriction NoSnapshots:\n "not (Ex s r #x. Snapshot(s,r)@x)"\nend'),
        ):
            self.assertNotEqual(original, changed)
            model.write_bytes(changed)
            with self.assertRaisesRegex(proof.RecoveryProofError, "model differs"):
                proof.load_inputs(self.root, "shared-storage")
        model.write_bytes(original)
        archive = self.root / profiles.SHARED_STORAGE.archive
        archive.write_bytes(archive.read_bytes() + b"changed")
        with self.assertRaisesRegex(proof.RecoveryProofError, "archive differs"):
            proof.load_inputs(self.root, "shared-storage")

    def test_shared_storage_keeps_the_existing_small_input_and_resource_bounds(self) -> None:
        original = zipfile.ZipFile.read
        members = []

        def read(archive, name, *args, **kwargs):
            members.append(name)
            return original(archive, name, *args, **kwargs)

        with mock.patch.object(zipfile.ZipFile, "read", new=read):
            inputs = proof.load_inputs(proof.ROOT, "shared-storage")
        self.assertEqual([case.member for case in profiles.SHARED_STORAGE.cases.values()], members)
        self.assertEqual(4 * 1024**2, profiles.SHARED_STORAGE.archive_maximum_bytes)
        for label, data in inputs.items():
            directory = self.root / label
            directory.mkdir()
            with mock.patch.object(proof, "capture_output", side_effect=BoundedProcessError("timeout", "deadline")) as run:
                with self.assertRaises(BoundedProcessError):
                    proof.replay(label, data, directory, {"PATH": "/usr/bin"}, "shared-storage")
            argv = run.call_args.args[0]
            self.assertIn("-N1", argv)
            self.assertIn("-M12G" if label == "positive" else "-M6G", argv)
            self.assertFalse(any(arg.startswith("--prove") or arg.startswith("--output-json") for arg in argv))
            self.assertEqual(900, run.call_args.kwargs["timeout_seconds"])
            self.assertEqual(4 * 1024**2, run.call_args.kwargs["maximum_stdout_bytes"])
            self.assertEqual(4 * 1024**2, run.call_args.kwargs["maximum_stderr_bytes"])

    def test_shared_storage_failure_retains_its_identity_and_stops_before_witnesses(self) -> None:
        self.populate_inputs()
        destination = self.root / "target" / "failed"
        with mock.patch.object(proof, "verify_installed"), \
             mock.patch.object(proof.sys, "platform", "linux"), \
             mock.patch.object(proof, "capture_output", side_effect=BoundedProcessError("timeout", "deadline")) as run, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(BoundedProcessError):
                proof.run(self.root, destination, "shared-storage")
        self.assertEqual(1, run.call_count)
        receipt = json.loads((destination / "RESULT.json").read_text())
        self.assertFalse(receipt["accepted"])
        self.assertEqual({}, receipt["groups"])
        self.assertEqual("shared-storage", receipt["profile"])
        self.assertEqual(profiles.SHARED_STORAGE.model_sha256, receipt["model_sha256"])
        self.assertEqual(profiles.SHARED_STORAGE.archive_sha256, receipt["archive_sha256"])
        self.assertEqual(proof.source_digests()["profile_catalog_sha256"], receipt["profile_catalog_sha256"])
        self.assertEqual("C.UTF-8", run.call_args.kwargs["environment"]["LC_ALL"])


if __name__ == "__main__":
    unittest.main()
