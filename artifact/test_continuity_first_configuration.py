"""Public configuration evidence refuses partial runs, misbinding and private files."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import continuity_first_configuration as configuration
from test_continuity_configuration_policy import fixture_values


def fixture(root, language="C"):
    stdout = "".join(f"test {name} ...\nok\n" for name in sorted(configuration.TESTS))
    for index, (carrier, profile) in enumerate((c, p) for c in ("local", "signed", "tls") for p in ("fixed", "recoverable")):
        folder = root / f"{carrier}-{profile}"
        folder.mkdir()
        authority = bytes([index + 1]) * 1985
        domain = b"Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1"
        account = hashlib.sha3_256(len(domain).to_bytes(8, "big") + domain + len(authority).to_bytes(8, "big") + authority).digest()
        family, policy_values = fixture_values(index, account, carrier)
        intent = bytes([2]) * 16 + (1).to_bytes(8, "big") + family + (10).to_bytes(8, "big") + (20).to_bytes(8, "big")
        body = b"QPENRQ01" + bytes([index+8])*32 + account + intent[:24] + intent[56:72] + intent[24:56] + bytes([index+16])*1985
        # Reader fixtures contain dummy signature bytes. The reader checks public
        # grammar and replay; only real native execution verifies signatures.
        request = len(body).to_bytes(4, "big") + body + bytes(3373)
        values = {"root.bin": authority, "intent.bin": intent, "request.bin": request, "replayed.bin": request,
                  "manifest.json": json.dumps(dict(schema_version=1, language=language, profile=profile, carrier=carrier,
                                                  release_claim_eligible=False)).encode()}
        if carrier != "local": values["genesis.bin"] = (2).to_bytes(4, "big") + bytes([5])*32 + bytes([5])*32 + bytes([6])*64 + bytes([7])*32
        values.update(policy_values)
        session, message = bytes([index+20])*32, bytes([index+30])*32
        values.update({"session.bin": session, "unknown.bin": session + message,
                       "acknowledged.bin": session + message, "after-traffic.bin": request,
                       "effect.bin": session + message + b"persisted before process exit"})
        for name, data in values.items(): (folder/name).write_bytes(data)
        if carrier == "local":
            stdout += f"INDEPENDENT_CONFIGURATION_PASS language={language} profile={profile} original_request_replayed=true\n"
        else: stdout += f"INDEPENDENT_WITNESS_CONFIGURATION_PASS language={language} carrier={carrier} profile={profile} remote_genesis_only=true original_request_replayed=true\n"
        stdout += configuration.connection_marker(language, carrier, profile) + "\n"
        stdout += configuration.policy.marker(language, carrier, profile) + "\n"
    return (stdout + "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;\n").encode()


class FirstConfigurationTests(unittest.TestCase):
    def test_policy_composition_cannot_fall_back_to_connection_only_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = fixture(root)
            marker = configuration.policy.marker("C", "local", "fixed").encode() + b"\n"
            for changed in (data.replace(marker, b""), data + marker,
                            data.replace(b"uncertain_before_update=true", b"uncertain_before_update=false")):
                with self.assertRaisesRegex(ValueError, "omitted or duplicated"):
                    configuration.verify_execution(changed, root, language="C")
            (root / "local-fixed" / "policy-approvals.bin").unlink()
            with self.assertRaisesRegex(ValueError, "public inventory"):
                configuration.verify_execution(data, root, language="C")

    def test_complete_matrix_and_explicit_language_are_required(self):
        for language in ("C", "Swift", "Kotlin"):
            with self.subTest(language=language), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); data = fixture(root, language)
                result = configuration.verify_execution(data, root, language=language)
                self.assertTrue(result["completed"]); self.assertEqual(len(result["public_readbacks"]), 166)
                self.assertEqual(result["local_connection_recovery_profiles"], ["fixed", "recoverable"])
                self.assertTrue(result["witnessed_connection_composition"])
                self.assertTrue(result["policy_renewal_composition"])
                self.assertFalse(result["sdk_policy_replacement_qualified"])
                self.assertFalse(result["release_claim_eligible"])
                for changed in (data.replace(b"2 passed", b"1 passed"), data.replace(b"0 ignored", b"1 ignored"),
                                data.replace(b"carrier=tls", b"carrier=other"), data + data, data.replace(b"INDEPENDENT_", b"OMITTED_")):
                    with self.assertRaises(ValueError): configuration.verify_execution(changed, root, language=language)
                with self.assertRaises(ValueError): configuration.verify_execution(data, root, language="unknown")

    def test_connection_requires_original_identity_and_uncertain_message_readback(self):
        for carrier in ("local", "signed", "tls"):
            for leaf in ("session.bin", "unknown.bin", "acknowledged.bin", "after-traffic.bin", "effect.bin"):
                for mutation in (lambda b: b[:-1], lambda b: bytes([b[0] ^ 1]) + b[1:]):
                    with self.subTest(carrier=carrier, leaf=leaf), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory); data = fixture(root); path = root / (carrier + "-fixed") / leaf
                        path.write_bytes(mutation(path.read_bytes()))
                        with self.assertRaisesRegex(ValueError, "configuration connection"):
                            configuration.verify_execution(data, root, language="C")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = fixture(root)
            marker = configuration.connection_marker("C", "local", "fixed").encode() + b"\n"
            for changed in (data.replace(marker, b""), data + marker,
                            data.replace(b"effects=1", b"effects=2"),
                            data.replace(b"original_message=true", b"original_message=false")):
                with self.assertRaises(ValueError): configuration.verify_execution(changed, root, language="C")

    def test_public_inputs_replay_and_genesis_must_remain_bound(self):
        mutations = {
            "request.bin": lambda b: b[:-1], "replayed.bin": lambda b: b[:-1] + bytes([1]),
            "root.bin": lambda b: bytes([99])*len(b), "intent.bin": lambda b: bytes([9])+b[1:],
            "genesis.bin": lambda b: b[:36] + bytes([4])*32 + b[68:],
            "manifest.json": lambda b: b.replace(b'false', b'0'),
        }
        for leaf, mutate in mutations.items():
            with self.subTest(leaf=leaf), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); data = fixture(root); path = root/'signed-fixed'/leaf; path.write_bytes(mutate(path.read_bytes()))
                with self.assertRaises(ValueError): configuration.verify_execution(data, root, language="C")

    def test_no_private_or_unlisted_files_may_be_exported(self):
        for name in ("wrap.key", "sdk.redb", "signer.key", "unlisted.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); data = fixture(root); (root/'local-fixed'/name).write_bytes(b"not public")
                with self.assertRaises(ValueError): configuration.verify_execution(data, root, language="C")

    def test_configuration_workload_does_not_reuse_previous_private_fixture_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); outside = root / "outside"; outside.mkdir()
            output = root / "output"; output.mkdir()
            previous = root / "previous"; previous.mkdir()
            helper = root / "helper"; helper.write_bytes(b"helper identity")
            client = root / "client"; client.write_bytes(b"client identity")
            receiver = root / "receiver"; receiver.write_bytes(b"receiver identity")
            original = {"QPERIAPT_PUBLIC_SERVICE_EVIDENCE": str(previous), "UNRELATED_SETTING": "retained",
                        "QPC_CONFIGURATION_RECEIVER": "must-be-overridden"}
            def run(command, label, *, runtime):
                self.assertNotIn("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", runtime)
                self.assertEqual(runtime["UNRELATED_SETTING"], "retained")
                self.assertEqual(runtime["QPC_CONFIGURATION_CLIENT"], str(client))
                self.assertEqual(runtime["QPC_CONFIGURATION_RECEIVER"], str(receiver))
                return fixture(Path(runtime["QPERIAPT_CONFIGURATION_EVIDENCE"]))
            checked = configuration._qualify(outside, output, "debug", original, helper, client, run, receiver=receiver, language="C")
            self.assertTrue(checked["completed"])
            self.assertEqual(original["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"], str(previous))
            self.assertEqual(list(previous.iterdir()), [])

    def test_foreign_receiver_must_match_native_baseline_and_remain_unchanged(self):
        for mutation in ("none", "baseline", "before", "during"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); outside = root / "outside"; outside.mkdir()
                output = root / "output"; output.mkdir()
                helper, client, receiver = (root / name for name in ("helper", "client", "receiver"))
                for path in (helper, client, receiver): path.write_bytes(path.name.encode())
                def identity(path):
                    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
                native = {"first_configuration": dict(completed=True, short_header_guard=True, language="C",
                           binaries={"helper": identity(helper), "receiver": identity(receiver)}),
                          "binaries": {"C_client": identity(receiver)}}
                if mutation == "baseline": native["binaries"]["C_client"]["sha256"] = "0" * 64
                if mutation == "before": receiver.write_bytes(b"replaced before dispatch")
                calls = []
                def run(command, label, *, runtime):
                    calls.append(command)
                    self.assertEqual(runtime["QPC_CONFIGURATION_RECEIVER"], str(receiver))
                    data = fixture(Path(runtime["QPERIAPT_CONFIGURATION_EVIDENCE"]), "Swift")
                    if mutation == "during": receiver.write_bytes(b"replaced during execution")
                    return data
                def execute():
                    return configuration.qualify_foreign(outside, output, "debug",
                        {"QPC_CONFIGURATION_RECEIVER": "untrusted-inherited-selection"}, native, run, client, language="Swift")
                if mutation == "none":
                    result = execute()
                    self.assertEqual(result["binaries"]["receiver"], identity(receiver))
                else:
                    with self.assertRaisesRegex(ValueError, "executable changed" if mutation == "during" else "native receiver differs"):
                        execute()
                self.assertEqual(len(calls), 0 if mutation in ("baseline", "before") else 1)

    def test_ci_retains_selected_public_configuration_evidence(self):
        workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml").read_text()
        for section, prefix in (
            ("Retain native packages and selected public execution evidence", "target/continuity-installed-swift/"),
            ("Retain package and public execution evidence without private test state", "target/continuity-installed-rust/"),
        ):
            upload = workflow.split("- name: " + section + "\n", 1)[1].split("if-no-files-found:", 1)[0]
            self.assertIn(prefix + "configuration-public/**", upload)

    def test_each_scenario_requires_its_own_registration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = fixture(root)
            for path in (root/'local-fixed').iterdir():
                if path.name != "manifest.json":
                    (root/'local-recoverable'/path.name).write_bytes(path.read_bytes())
            with self.assertRaisesRegex(ValueError, "reused"): configuration.verify_execution(data, root, language="C")
