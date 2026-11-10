from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock
import zipfile

import continuity_recovery_proof as proof
import continuity_recovery_profiles as profiles
from bounded_process import BoundedProcessError, BoundedResult


class RecoveryProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Terminal output from the real accepted replay, not generated verdicts.
        with zipfile.ZipFile(proof.ROOT / profiles.INDEPENDENT.archive) as zipped:
            cls.positive = zipped.read("receipts/final-positive-53.stdout")
            cls.certificate = zipped.read(profiles.INDEPENDENT.cases["positive"].member)
        disclosure = proof.ROOT / "research/sdk-alpha1/evidence/20261015-recovery-symbolic-disclosure/CAPTURE.zip"
        with zipfile.ZipFile(disclosure) as zipped:
            cls.witnesses = zipped.read("receipts/isolate-42.stdout")

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "input.spthy"
        self.output = self.root / "checked.spthy"

    def summary(self, data: bytes) -> bytes:
        text = data.decode()
        # Earlier witness output also printed its theory before the summary.
        text = text[text.rindex("=" * 78 + "\nsummary of summaries:"):]
        text = re.sub(r"(?m)^analyzed: .+$", "analyzed: " + str(self.source), text)
        if re.search(r"(?m)^  output:", text):
            text = re.sub(r"(?m)^  output:.*$", "  output:          " + str(self.output), text)
        else:
            text = text.replace("  processing time:", f"  output:          {self.output}\n  processing time:")
        return text.encode()

    def test_real_checkpoint_and_two_terminal_inventories(self) -> None:
        inputs = proof.load_inputs(proof.ROOT)
        self.assertEqual({"positive", "witnesses"}, set(inputs))
        positive = proof.verify_summary(self.summary(self.positive), "positive", self.source, self.output)
        witnesses = proof.verify_summary(self.summary(self.witnesses), "witnesses", self.source, self.output)
        self.assertEqual(20, len(positive))
        self.assertEqual(9, positive[profiles.INDEPENDENT.main])
        self.assertEqual({"recovery_is_executable": 59,
                          "pre_cut_generation_reservation_remains_exposed": 80,
                          "later_storage_access_defeats_fresh_reservations": 45}, witnesses)

    def test_each_missing_or_incomplete_dependency_and_main_is_rejected(self) -> None:
        data = self.summary(self.positive).decode()
        for name in profiles.INDEPENDENT_PROPERTIES:
            line = next(line for line in data.splitlines(True) if line.startswith(f"  {name} ("))
            for replacement in ("", line.replace("verified", "analysis incomplete")):
                with self.subTest(name=name, replacement=replacement):
                    with self.assertRaises(proof.RecoveryProofError):
                        proof.verify_summary(data.replace(line, replacement).encode(),
                                             "positive", self.source, self.output)

    def test_summary_does_not_accept_duplicate_mislabelled_or_appended_results(self) -> None:
        data = self.summary(self.positive)
        row = next(line for line in data.splitlines(True) if profiles.INDEPENDENT.main.encode() in line)
        mutations = (
            data.replace(row, row + row), data + data,
            data.replace(b"(all-traces)", b"(exists-trace)", 1),
            data.replace(b"verified", b"falsified - found trace", 1),
            data.replace(b"verified", b"unrecognized status", 1),
            data.replace(b"(142 steps)", b"(0 steps)"),
            data.replace(b"summary of summaries:", b"summary of summaries:\x00"),
            data.replace(b"summary of summaries:", b"summary of summaries:\xff"),
            data.replace(str(self.source).encode(), b"/other/model.spthy"),
            data.replace(str(self.output).encode(), b"/other/output.spthy"),
            data.rstrip().rsplit(b"\n", 1)[0],
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[:80]):
                with self.assertRaises((proof.RecoveryProofError, UnicodeError)):
                    proof.verify_summary(mutation, "positive", self.source, self.output)

    def test_witnesses_cannot_be_omitted_or_substituted_for_universal_proof(self) -> None:
        data = self.summary(self.witnesses)
        for name in profiles.RECORD_WITNESSES:
            row = next(line for line in data.splitlines(True) if name.encode() in line)
            with self.subTest(name=name), self.assertRaises(proof.RecoveryProofError):
                proof.verify_summary(data.replace(row, b""), "witnesses", self.source, self.output)
        with self.assertRaises(proof.RecoveryProofError):
            proof.verify_summary(data, "positive", self.source, self.output)

    def populate_inputs(self) -> None:
        for relative in (profiles.INDEPENDENT.model, profiles.INDEPENDENT.archive):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((proof.ROOT / relative).read_bytes())

    def test_model_changes_cannot_reuse_historical_certificate(self) -> None:
        self.populate_inputs()
        model = self.root / profiles.INDEPENDENT.model
        original = model.read_bytes()
        mutations = (
            original.replace(profiles.INDEPENDENT.main.encode(), b"removed_main", 1),
            original.replace(b"Ex r #x. IdentityLeak(s,r)", b"Ex other r #x. IdentityLeak(other,r)"),
            original.replace(b"\nend", b'\nrestriction DisableSnapshots:\n "not (Ex s r #i. Snapshot(s,r)@i)"\nend'),
        )
        for mutation in mutations:
            self.assertNotEqual(original, mutation)
            model.write_bytes(mutation)
            with self.assertRaisesRegex(proof.RecoveryProofError, "model differs"):
                proof.load_inputs(self.root)

    def test_changed_archive_and_missing_helper_proof_are_rejected(self) -> None:
        self.populate_inputs()
        archive = self.root / profiles.INDEPENDENT.archive
        archive.write_bytes(archive.read_bytes() + b"changed")
        with self.assertRaisesRegex(proof.RecoveryProofError, "archive differs"):
            proof.load_inputs(self.root)
        modified = self.certificate.replace(b"lemma traffic_key_derivation_requires_prior_root", b"lemma removed", 1)
        self.assertNotEqual(self.certificate, modified)
        with self.assertRaisesRegex(proof.RecoveryProofError, "differs"):
            proof.checked_bytes(modified, profiles.INDEPENDENT.cases["positive"].sha256, "certificate")

    def test_exit_zero_with_incomplete_group_is_not_success(self) -> None:
        self.source = self.root / "positive-input.spthy"
        self.output = self.root / "positive-checked.spthy"
        data = self.summary(self.positive).replace(b"verified", b"analysis incomplete", 1)
        with mock.patch.object(proof, "capture_output", return_value=BoundedResult(0, data, b"")):
            with self.assertRaisesRegex(proof.RecoveryProofError, "inventory or status"):
                proof.replay("positive", self.certificate, self.root, {"PATH": "/usr/bin"})
        self.assertEqual(data, (self.root / "positive.stdout").read_bytes())

    def test_nonzero_prover_cannot_pass_with_successful_looking_stdout(self) -> None:
        with mock.patch.object(proof, "capture_output", return_value=BoundedResult(251, self.positive, b"heap exhausted")):
            with self.assertRaisesRegex(proof.RecoveryProofError, "exited 251"):
                proof.replay("positive", self.certificate, self.root, {"PATH": "/usr/bin"})

    def test_timeout_records_failure_and_stops_before_other_group(self) -> None:
        self.populate_inputs()
        destination = self.root / "target" / "replay"
        with mock.patch.object(proof, "verify_installed"), \
             mock.patch.object(proof.sys, "platform", "linux"), \
             mock.patch.object(proof, "capture_output", side_effect=BoundedProcessError("timeout", "deadline")) as run, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(BoundedProcessError):
                proof.run(self.root, destination)
        self.assertEqual(1, run.call_count)
        receipt = json.loads((destination / "RESULT.json").read_text())
        self.assertFalse(receipt["accepted"])
        self.assertIn("deadline", receipt["error"])
        argv = run.call_args.args[0]
        self.assertFalse(any(value.startswith("--prove") for value in argv))
        self.assertIn("--quit-on-warning", argv)
        self.assertEqual(900, run.call_args.kwargs["timeout_seconds"])
        self.assertNotIn("GHCRTS", run.call_args.kwargs["environment"])
        with self.assertRaisesRegex(proof.EvidenceIOError, "fresh"):
            proof.run(self.root, destination)

    def test_prover_locale_decodes_unicode_certificates_without_ambient_rts_overrides(self) -> None:
        self.assertIn("∀".encode(), self.certificate)
        for platform, expected in (("linux", "C.UTF-8"), ("darwin", "en_US.UTF-8")):
            with self.subTest(platform=platform), mock.patch.object(proof.sys, "platform", platform), \
                 mock.patch.dict(proof.os.environ, {"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                                    "LANG": "C", "GHCRTS": "-M1M"}):
                self.assertEqual({"PATH": "/usr/bin:/bin", "LANG": expected, "LC_ALL": expected},
                                 proof.prover_environment())


if __name__ == "__main__":
    unittest.main()
