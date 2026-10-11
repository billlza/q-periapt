"""Public managed-registration reader controls, not signature verification."""
from pathlib import Path
import shutil
import tempfile
import unittest

import continuity_first_account as account
import continuity_first_configuration as configuration
from test_continuity_first_configuration import fixture as ordinary_fixture


def fixture(root, language="C"):
    ordinary_fixture(root, language)
    for name in ("local-fixed", "local-recoverable"):
        shutil.rmtree(root / name)
    output = f"test {account.TEST} ...\n"
    for index, folder in enumerate(sorted(root.iterdir())):
        for item in folder.iterdir():
            if item.name not in account.BASE | account.policy.names("signed") | account.policy.EXPIRY:
                item.unlink()
        data = {p.name: p.read_bytes() for p in folder.iterdir()}
        identity, family, _, _ = configuration.verify_original(data)
        for name, value in {
            "registry-required.bin": data["request.bin"], "registry-id": bytes([index + 1]) * 32,
            "family": family, "account": identity, "application": bytes([30]) * 32,
            "witness-id": bytes([31]) * 32, "witness-public": bytes([32]) * 1985,
            "revision": (1).to_bytes(8, "big"),
        }.items():
            (folder / name).write_bytes(value)
        commands = dict(account.COMMANDS)
        if language in {"Swift", "Kotlin"}:
            commands.update({"registry-closed": "REGISTRY_CLOSED", "registry-released": "REGISTRY_RELEASED"})
            for name in ("registry-closed.bin", "registry-released.bin"):
                (folder / name).write_bytes(data["request.bin"])
        if language == "Kotlin":
            (folder / "registry-gc.bin").write_bytes((2).to_bytes(8, "big") + (1).to_bytes(4, "big") + (63).to_bytes(4, "big"))
        for command, marker in commands.items():
            (folder / (command + ".stdout")).write_text("QPC_CONFIGURATION_" + marker + "\n")
            (folder / (command + ".stderr")).write_bytes(b"")
        carrier, profile = folder.name.split("-")
        output += account.policy.expiry_marker(language, carrier, profile) + "\n"
        output += account.policy.marker(language, carrier, profile) + "\n"
        output += configuration.connection_marker(language, carrier, profile) + "\n"
        output += account.marker(language, carrier, profile) + "\n"
    return (output + "ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out;\n").encode()


class FirstAccountTests(unittest.TestCase):
    def test_matrix_and_execution_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = fixture(root)
            result = account.verify_execution(output, root, language="C")
            self.assertEqual(len(result["scenarios"]), 4)
            self.assertEqual(result["missing_registry"], 211)
            self.assertFalse(result["release_claim_eligible"])
            self.assertTrue(result["policy_renewal_composition"])
            self.assertTrue(result["real_clock_policy_expiry"])
            self.assertFalse(result["credential_renewal_qualified"])
            for changed in (output + output, output.replace(b"1 passed", b"0 passed"),
                            output.replace(b"carrier=tls", b"carrier=signed"),
                            output.replace(b"missing_registry=211", b"missing_registry=0")):
                with self.assertRaises(ValueError):
                    account.verify_execution(changed, root, language="C")
            with self.assertRaises(ValueError):
                account.verify_execution(output, root, language="Kotlin")

    def test_swift_requires_explicit_and_arc_registry_revocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = fixture(root, "Swift")
            result = account.verify_execution(output, root, language="Swift")
            self.assertEqual(result["registry_lifetime_probes"], ["registry-closed", "registry-released"])
            (root / "tls-fixed" / "registry-released.bin").write_bytes(b"another request")
            with self.assertRaises(ValueError):
                account.verify_execution(output, root, language="Swift")

    def test_kotlin_requires_observed_gc_and_completed_native_reclamation(self):
        for payload in (bytes(16), (2).to_bytes(8, "big") + (1).to_bytes(4, "big") + (62).to_bytes(4, "big"), b"short"):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = fixture(root, "Kotlin")
                result = account.verify_execution(output, root, language="Kotlin")
                self.assertEqual(len(result["gc_observations"]), 4)
                (root / "tls-fixed" / "registry-gc.bin").write_bytes(payload)
                with self.assertRaisesRegex(ValueError, "slot reclamation"):
                    account.verify_execution(output, root, language="Kotlin")

    def test_bindings_and_process_results_cannot_be_substituted(self):
        for leaf in ("account", "family", "revision", "registry-required.bin", "acknowledged.bin",
                     "registry-required.stdout", "uncertain.stderr", "expired-activation.bin"):
            with self.subTest(leaf=leaf), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = fixture(root)
                path = root / "signed-fixed" / leaf
                path.write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    account.verify_execution(output, root, language="C")

    def test_renewal_and_expiry_are_bound_to_the_original_account(self):
        for leaf in ("policy-request.bin", "policy-approvals.bin", "policy-statement.bin",
                     "expired-request.bin", "receiver-policy.bin"):
            with self.subTest(leaf=leaf), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = fixture(root)
                (root / "signed-fixed" / leaf).write_bytes((root / "tls-fixed" / leaf).read_bytes())
                with self.assertRaises(ValueError):
                    account.verify_execution(output, root, language="C")

    def test_expiry_must_precede_renewal_and_original_message_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = fixture(root)
            expired = account.policy.expiry_marker("C", "signed", "fixed").encode()
            renewed = account.policy.marker("C", "signed", "fixed").encode()
            output = output.replace(expired + b"\n" + renewed, renewed + b"\n" + expired)
            with self.assertRaisesRegex(ValueError, "phase order"):
                account.verify_execution(output, root, language="C")

    def test_extra_private_or_duplicated_scenario_is_refused(self):
        for private in (True, False):
            with self.subTest(private=private), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = fixture(root)
                if private:
                    (root / "tls-fixed" / "authority.key").write_bytes(b"reader control only")
                else:
                    shutil.copytree(root / "signed-fixed", root / "unexpected")
                with self.assertRaises(ValueError):
                    account.verify_execution(output, root, language="C")


if __name__ == "__main__":
    unittest.main()
