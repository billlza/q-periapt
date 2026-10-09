"""Synthetic reader/orchestration controls; actual installed execution is separate."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import continuity_peer_configuration as peer
import continuity_c_enrollment as enrollment
import continuity_c_device as device
from test_continuity_c_enrollment import fixture as enrollment_fixture, STDOUT
from test_continuity_c_device import fixture as device_fixture, output


class PeerConfigurationTests(unittest.TestCase):
    def test_configured_trace_cannot_substitute_legacy_or_publication_selection(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            enrollment_fixture(root)
            configured = STDOUT.replace(enrollment.TEST.encode(), enrollment.CONFIGURED_TEST.encode())
            self.assertTrue(enrollment.verify_execution(configured, root, configured=True)["completed"])
            for wrong in (STDOUT, configured + configured, configured.replace(b"29 filtered", b"28 filtered")):
                with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                    enrollment.verify_execution(wrong, root, configured=True)
            with self.assertRaises(ValueError):
                enrollment.verify_execution(configured, root)
            with self.assertRaises(ValueError):
                enrollment.verify_execution(configured, root, configured=True, publication=True)

    def test_configured_device_trace_has_its_own_exact_test_identity(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            device_fixture(root)
            self.assertTrue(device.verify_execution(output(device.CONFIGURED_TEST, 9), root, configured=True)["completed"])
            with self.assertRaises(ValueError):
                device.verify_execution(output(device.TEST, 9), root, configured=True)
            with self.assertRaises(ValueError):
                device.verify_execution(output(device.CONFIGURED_TEST, 9), root)

    def test_foreign_execution_owns_evidence_selection_and_requires_complete_lifetime(self):
        for language, collector in (("Swift", ""), ("Kotlin", "G1"), ("Kotlin", "Serial")):
            for lifetime in (peer.LIFETIME, b"", peer.LIFETIME * 2):
                with self.subTest(language=language, collector=collector, lifetime=lifetime), tempfile.TemporaryDirectory() as name:
                    root = Path(name); helper = root / "helper"; client = root / "client"
                    helper.write_bytes(b"native helper"); client.write_bytes(b"foreign client")
                    original = {"QPERIAPT_PUBLIC_SERVICE_EVIDENCE": "/prior/private-fixture", "QPERIAPT_C_OWNER_CLIENT": "/prior/client"}
                    calls = []
                    def run(command, label, *, runtime):
                        calls.append((command, dict(runtime)))
                        return b"coordinator" if command[0] == str(helper) else lifetime
                    with patch.object(enrollment, "export", return_value={"completed": True, "session": "11" * 32, "public_readbacks": {}}) as verify, patch.object(peer, "export_selected", return_value={}):
                        if lifetime != peer.LIFETIME:
                            with self.assertRaisesRegex(ValueError, "lifetime"):
                                peer._qualify(root, root, "debug", original, helper, client, run, language=language, collector=collector)
                        else:
                            result = peer._qualify(root, root, "debug", original, helper, client, run, language=language, collector=collector)
                            self.assertTrue(result["lifetime"]["completed"])
                        verify.assert_called_once()
                        self.assertTrue(verify.call_args.kwargs["configured"])
                    self.assertEqual(original["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"], "/prior/private-fixture")
                    self.assertEqual(calls[0][0], [str(helper), "--exact", enrollment.CONFIGURED_TEST, "--nocapture"])
                    self.assertNotEqual(calls[0][1]["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"], original["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"])
                    self.assertEqual(calls[1][0][-1], "11" * 32)
                    self.assertEqual(calls[1][0][1], "peer-configuration-lifetime")

    def test_changed_helper_and_incomplete_native_component_refuse(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); helper = root / "helper"; client = root / "client"
            helper.write_bytes(b"helper"); client.write_bytes(b"client")
            def changed(command, label, *, runtime):
                helper.write_bytes(b"changed helper")
                return b"coordinator" if command[0] == str(helper) else peer.LIFETIME
            with patch.object(enrollment, "export", return_value={"completed": True, "session": "11" * 32, "public_readbacks": {}}), patch.object(peer, "export_selected", return_value={}):
                with self.assertRaisesRegex(ValueError, "executable changed"):
                    peer._qualify(root, root, "debug", {}, helper, client, changed, language="Swift")
            with self.assertRaisesRegex(ValueError, "complete native"):
                peer.qualify_foreign(root, root, "debug", {}, {"peer_configuration": {"completed": False}},
                                     changed, client, language="Swift")


if __name__ == "__main__":
    unittest.main()
