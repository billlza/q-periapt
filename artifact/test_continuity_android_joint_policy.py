"""Adversarial readback of retained real joint G/T executions, not simulated protocol runs."""
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile
import continuity_android_joint_policy as joint
import rust_sdk_profile as sdk


class JointPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(); cls.addClassCleanup(temp.cleanup); cls.root = Path(temp.name)
        archive = sdk.ROOT / "research/sdk-alpha1/evidence/20261014-android-joint-policy/CAPTURE.zip"
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():
                if not name.startswith(("host/", "device/")): continue
                path = cls.root / name
                if not path.is_relative_to(cls.root) or ".." in Path(name).parts: raise ValueError("archive member")
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(bundle.read(name))

    def verify(self, root, label, surface="host"):
        profile, outcome = label.split("-")
        stdout = (self.root / surface / label / "execution.stdout").read_bytes()
        return joint.verify_execution(stdout, root, profile, outcome == "applied")

    def test_host_and_actual_phone_keep_the_exact_terminal_outcome(self):
        for surface, labels in (("host", joint.TESTS), ("device", ("recoverable-applied", "recoverable-pending"))):
            for label in labels:
                with self.subTest(surface=surface, label=label):
                    value = self.verify(self.root / surface / label / "public", label, surface)
                    self.assertEqual(value["foreign_processes"], 33 if label.endswith("applied") else 26)
                    self.assertEqual(value["historical_reads"], 2)
                    self.assertEqual(value["original_message_retried"], label.endswith("applied"))

    def mutate(self, label, name, change):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "public"; shutil.copytree(self.root / "host" / label / "public", root)
            path = root / ("local-" + label.split("-")[0]) / name
            path.write_bytes(change(path.read_bytes()))
            with self.assertRaises(ValueError): self.verify(root, label)

    def test_reject_changed_predecessor_policy_padding_or_operation(self):
        for name, offset in (("joint-request", 64), ("joint-request", 168), ("joint-request", 33119),
                             ("joint-final-request", 0), ("joint-final-request", 168), ("joint-final-request", 208),
                             ("inputs/credential-statement", 0), ("joint-committed", 4), ("joint-activated", 0)):
            def changed(data, index=offset):
                value = bytearray(data); value[index] ^= 1; return bytes(value)
            with self.subTest(name=name, offset=offset): self.mutate("fixed-applied", name, changed)

    def test_pending_history_cannot_claim_a_commit_or_current_permission(self):
        for name in ("joint-history-0", "joint-history-1", "joint-history-status-0", "joint-expired-current"):
            with self.subTest(name=name): self.mutate("recoverable-pending", name, lambda data: (2).to_bytes(4, "big") + data[4:])

    def test_completed_operation_reuse_and_duplicate_effect_are_refused(self):
        self.mutate("fixed-applied", "joint-request-reused", lambda _: bytes(4))
        self.mutate("fixed-applied", "policy-effect-after", lambda data: data + b"duplicate")
        self.mutate("fixed-applied", "policy-message-acknowledged", lambda data: data[:32] + bytes(32))

    def test_real_expiry_and_complete_process_receipts_are_required(self):
        self.mutate("fixed-applied", "joint-expiry-observation", lambda data: data[:24] + bytes(8))
        self.mutate("fixed-applied", "joint-history-1.stdout", lambda _: b"")
        self.mutate("fixed-applied", "credential-peer-admit.stderr", lambda _: b"transport failure")
        self.mutate("fixed-applied", "policy-process-count", lambda _: (32).to_bytes(8, "big"))


if __name__ == "__main__": unittest.main()
