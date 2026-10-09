"""Public configuration evidence refuses partial runs, misbinding and private files."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import continuity_first_configuration as configuration


def fixture(root, language="C"):
    stdout = "".join(f"test {name} ...\nok\n" for name in sorted(configuration.TESTS))
    for index, (carrier, profile) in enumerate((c, p) for c in ("local", "signed", "tls") for p in ("fixed", "recoverable")):
        folder = root / f"{carrier}-{profile}"
        folder.mkdir()
        authority = bytes([index + 1]) * 1985
        intent = bytes([2]) * 16 + (1).to_bytes(8, "big") + bytes([3]) * 32 + (10).to_bytes(8, "big") + (20).to_bytes(8, "big")
        domain = b"Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1"
        account = hashlib.sha3_256(len(domain).to_bytes(8, "big") + domain + len(authority).to_bytes(8, "big") + authority).digest()
        body = b"QPENRQ01" + bytes([index+8])*32 + account + intent[:24] + intent[56:72] + intent[24:56] + bytes([index+16])*1985
        # Reader fixtures contain dummy signature bytes. The reader checks public
        # grammar and replay; only real native execution verifies signatures.
        request = len(body).to_bytes(4, "big") + body + bytes(3373)
        values = {"root.bin": authority, "intent.bin": intent, "request.bin": request, "replayed.bin": request,
                  "manifest.json": json.dumps(dict(schema_version=1, language=language, profile=profile, carrier=carrier,
                                                  release_claim_eligible=False)).encode()}
        if carrier != "local": values["genesis.bin"] = (2).to_bytes(4, "big") + bytes([5])*32 + bytes([5])*32 + bytes([6])*64 + bytes([7])*32
        for name, data in values.items(): (folder/name).write_bytes(data)
        if carrier == "local": stdout += f"INDEPENDENT_CONFIGURATION_PASS language={language} profile={profile} original_request_replayed=true\n"
        else: stdout += f"INDEPENDENT_WITNESS_CONFIGURATION_PASS language={language} carrier={carrier} profile={profile} remote_genesis_only=true original_request_replayed=true\n"
    return (stdout + "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;\n").encode()


class FirstConfigurationTests(unittest.TestCase):
    def test_complete_matrix_and_explicit_language_are_required(self):
        for language in ("C", "Swift", "Kotlin"):
            with self.subTest(language=language), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); data = fixture(root, language)
                result = configuration.verify_execution(data, root, language=language)
                self.assertTrue(result["completed"]); self.assertEqual(len(result["public_readbacks"]), 34)
                self.assertFalse(result["release_claim_eligible"])
                for changed in (data.replace(b"2 passed", b"1 passed"), data.replace(b"0 ignored", b"1 ignored"),
                                data.replace(b"carrier=tls", b"carrier=other"), data + data, data.replace(b"INDEPENDENT_", b"OMITTED_")):
                    with self.assertRaises(ValueError): configuration.verify_execution(changed, root, language=language)
                with self.assertRaises(ValueError): configuration.verify_execution(data, root, language="unknown")

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

    def test_ci_retains_selected_public_configuration_evidence(self):
        workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml").read_text()
        upload = workflow.split("- name: Retain native packages and selected public execution evidence\n", 1)[1]
        upload = upload.split("if-no-files-found:", 1)[0]
        self.assertIn("target/continuity-installed-swift/configuration-public/**", upload)

    def test_each_scenario_requires_its_own_registration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = fixture(root)
            for name in ("request.bin", "replayed.bin", "root.bin", "intent.bin"):
                (root/'local-recoverable'/name).write_bytes((root/'local-fixed'/name).read_bytes())
            with self.assertRaisesRegex(ValueError, "reused"): configuration.verify_execution(data, root, language="C")
