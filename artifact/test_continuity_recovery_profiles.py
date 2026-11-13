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
import test_proof_to_byte_release as workflow_tests
from bounded_process import BoundedProcessError


class KeyScopedRecoveryProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with zipfile.ZipFile(proof.ROOT / profiles.KEY_SCOPED.archive) as zipped:
            cls.outputs = {
                label: zipped.read("experiments/" + member + ".stdout")
                for label, member in (
                    ("positive", "final-37"), ("attack", "cross-role-replay-09"),
                    ("execution", "honest-sharing-replay-28"), ("partial", "main-conditional-33"),
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
        for relative in (profiles.KEY_SCOPED.model, profiles.KEY_SCOPED.archive):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((proof.ROOT / relative).read_bytes())

    def test_real_certificates_and_terminal_verdicts_bind_each_profile(self) -> None:
        inputs = proof.load_inputs(proof.ROOT, "key-scoped")
        self.assertEqual({"positive", "attack", "execution"}, set(inputs))
        for label, count, theorem, steps in (
            ("positive", 20, profiles.KEY_SCOPED_MAIN, 8),
            ("attack", 1, profiles.CROSS_ROLE_WITNESS, 55),
            ("execution", 1, profiles.UNRELATED_KEY_WITNESS, 72),
        ):
            with self.subTest(label=label):
                result = proof.verify_summary(self.summary(label), label, self.source,
                                              self.output, "key-scoped")
                self.assertEqual(count, len(result))
                self.assertEqual(steps, result[theorem])
        with self.assertRaises(proof.RecoveryProofError):
            proof.verify_summary(self.summary("positive"), "positive", self.source, self.output)
        with self.assertRaises(proof.RecoveryProofError):
            proof.verify_summary(self.summary("attack"), "execution", self.source, self.output, "key-scoped")

    def test_missing_or_incomplete_properties_and_witnesses_are_rejected(self) -> None:
        for label in ("positive", "attack", "execution"):
            data = self.summary(label)
            for name in profiles.KEY_SCOPED.cases[label].verified:
                row = next(line for line in data.splitlines(True) if line.startswith(f"  {name} (".encode()))
                for replacement in (b"", row.replace(b"verified", b"analysis incomplete")):
                    with self.subTest(label=label, name=name, replacement=replacement):
                        with self.assertRaises(proof.RecoveryProofError):
                            proof.verify_summary(data.replace(row, replacement), label,
                                                 self.source, self.output, "key-scoped")
        # A real exit-zero run displayed the main theorem as verified while
        # its dependencies were deferred. That is not an accepted proof group.
        with self.assertRaises(proof.RecoveryProofError):
            proof.verify_summary(self.summary("partial"), "positive", self.source, self.output, "key-scoped")

    def test_archive_reader_selects_only_small_named_certificates(self) -> None:
        original = zipfile.ZipFile.read
        selected = []

        def read(archive, name, *args, **kwargs):
            selected.append(name)
            return original(archive, name, *args, **kwargs)

        with mock.patch.object(zipfile.ZipFile, "read", new=read):
            inputs = proof.load_inputs(proof.ROOT, "key-scoped")
        self.assertEqual([case.member for case in profiles.KEY_SCOPED.cases.values()], selected)
        self.assertTrue(all(len(data) <= proof.MAXIMUM_BYTES for data in inputs.values()))
        self.assertEqual(4 * 1024 * 1024, proof.MAXIMUM_BYTES)
        self.assertEqual(4 * 1024 * 1024, profiles.INDEPENDENT.archive_maximum_bytes)
        self.assertLess((proof.ROOT / profiles.KEY_SCOPED.archive).stat().st_size,
                        profiles.KEY_SCOPED.archive_maximum_bytes)
        self.assertFalse(any(name.endswith("-traces.json") for name in selected))

    def test_changed_key_scope_and_late_restriction_cannot_reuse_evidence(self) -> None:
        self.populate_inputs()
        model = self.root / profiles.KEY_SCOPED.model
        original = model.read_bytes()
        for changed in (
            original.replace(profiles.KEY_SCOPED_MAIN.encode(), b"missing_main"),
            original.replace(b"Ex #x. IdentityKeyLeak(sa)@x", b"Ex any_key #x. IdentityKeyLeak(any_key)@x"),
            original.replace(b"\nend", b'\nrestriction NoLeaks:\n "not (Ex k #i. IdentityKeyLeak(k)@i)"\nend'),
        ):
            self.assertNotEqual(original, changed)
            model.write_bytes(changed)
            with self.assertRaisesRegex(proof.RecoveryProofError, "model differs"):
                proof.load_inputs(self.root, "key-scoped")

    def test_unknown_profile_or_group_never_falls_back(self) -> None:
        with self.assertRaisesRegex(proof.RecoveryProofError, "profile"):
            proof.run(self.root, self.root / "target" / "replay", "unknown")
        self.assertFalse((self.root / "target").exists())
        with self.assertRaisesRegex(proof.RecoveryProofError, "group"):
            proof.certificate("witnesses", "key-scoped")
        with self.assertRaisesRegex(proof.RecoveryProofError, "group"):
            proof.certificate("attack", "independent")

    def test_key_scoped_failure_keeps_its_identity_and_stops_the_group(self) -> None:
        self.populate_inputs()
        destination = self.root / "target" / "replay"
        with mock.patch.object(proof, "verify_installed"), \
             mock.patch.object(proof.sys, "platform", "linux"), \
             mock.patch.object(proof, "capture_output", side_effect=BoundedProcessError("timeout", "deadline")) as run, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(BoundedProcessError):
                proof.run(self.root, destination, "key-scoped")
        self.assertEqual(1, run.call_count)
        receipt = json.loads((destination / "RESULT.json").read_text())
        self.assertFalse(receipt["accepted"])
        self.assertEqual("key-scoped", receipt["profile"])
        self.assertEqual(profiles.KEY_SCOPED_MAIN, receipt["main_theorem"])
        self.assertEqual(profiles.KEY_SCOPED.model_sha256, receipt["model_sha256"])
        self.assertEqual(proof.source_digests()["profile_catalog_sha256"], receipt["profile_catalog_sha256"])
        argv = run.call_args.args[0]
        self.assertIn("-N1", argv)
        self.assertIn("-M12G", argv)
        self.assertFalse(any(arg.startswith("--prove") or arg.startswith("--output-json") for arg in argv))
        self.assertEqual(900, run.call_args.kwargs["timeout_seconds"])
        self.assertEqual("C.UTF-8", run.call_args.kwargs["environment"]["LC_ALL"])

    def test_changed_catalog_cannot_receive_an_accepted_receipt(self) -> None:
        self.populate_inputs()
        before = proof.source_digests()
        after = {**before, "profile_catalog_sha256": "0" * 64}
        destination = self.root / "target" / "changed-catalog"
        with mock.patch.object(proof, "verify_installed"), \
             mock.patch.object(proof.sys, "platform", "linux"), \
             mock.patch.object(proof, "replay", return_value={"unit_test_stub": True}), \
             mock.patch.object(proof, "source_digests", side_effect=(before, after)), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(proof.RecoveryProofError, "checker changed"):
                proof.run(self.root, destination, "key-scoped")
        self.assertFalse(json.loads((destination / "RESULT.json").read_text())["accepted"])

    def test_ci_requires_all_profiles_and_retains_separate_results(self) -> None:
        workflow = (proof.ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        job = workflow_tests.extract_workflow_job(workflow, "tamarin-proof")
        identity = workflow_tests.extract_named_workflow_step(job, "Verify pinned Tamarin and Maude identities")
        self.assertIn("id: formal_tools\n", identity)
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("|| true", job)
        self.assertEqual(3, job.count("artifact/continuity_recovery_proof.py"))
        for profile, title, deadline in (
            ("independent", "Replay independent-identity recovery and disclosure proofs", 35),
            ("key-scoped", "Replay key-scoped recovery and identity-sharing witnesses", 50),
            ("shared-storage", "Replay shared-storage recovery and device-owner witnesses", 50),
        ):
            with self.subTest(profile=profile):
                step = workflow_tests.extract_named_workflow_step(job, title)
                self.assertLess(job.index(identity), job.index(step))
                self.assertIn("sh artifact/python-run.sh artifact/continuity_recovery_proof.py", step)
                self.assertIn(f"--profile {profile} --output target/continuity-recovery-proof/{profile}\n", step)
                self.assertIn(f"timeout-minutes: {deadline}\n", step)
                if profile != "independent":
                    self.assertIn("if: ${{ !cancelled() && steps.formal_tools.outcome == 'success' }}\n", step)
                else:
                    self.assertNotIn("if:", step)
        retained = workflow_tests.extract_named_workflow_step(job, "Retain Continuity recovery proof results")
        self.assertIn("if: always()\n", retained)
        self.assertIn("path: target/continuity-recovery-proof\n", retained)
        self.assertIn("if-no-files-found: error\n", retained)


if __name__ == "__main__":
    unittest.main()
