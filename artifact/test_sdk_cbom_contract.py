"""New SDK packages must not inherit the historical nine-asset BOM acceptance."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import package_bom as bom


class SDKCBOMContractTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.boms = self.root / "share/q-periapt/bom"
        self.boms.mkdir(parents=True)
        self.common = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                       "metadata": {"component": {"name": "q-periapt-hybrid-suite", "version": "0.2.0"}}}
        self.document = copy.deepcopy(self.common)
        fixture = Path(bom.__file__).parent / "fixtures/sdk-native-020-tls-inventory.json"
        self.document["metadata"]["properties"] = [
            {"name": "qperiapt:cbom-profile", "value": "native-sdk-020"},
            {"name": "qperiapt:inventory-scope", "value": bom.NATIVE_INVENTORY_SCOPE},
            {"name": "qperiapt:configured-tls-provider", "value": fixture.read_text()},
        ]
        components = []
        for name, (primitive, functions, level) in bom.NATIVE_SDK_ALGORITHMS.items():
            algorithm = {"primitive": primitive, "parameterSetIdentifier": name,
                         "executionEnvironment": "software-plain-ram", "implementationPlatform": "generic",
                         "cryptoFunctions": sorted(functions)}
            if level is not None: algorithm["nistQuantumSecurityLevel"] = level
            components.append({"type": "cryptographic-asset", "name": name, "bom-ref": "crypto/" + name.lower(),
                               "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algorithm}})
        self.document["components"] = components
        self.write("sbom", {**self.common, "components": [{"type": "library", "name": "fixture", "version": "1",
                                                         "bom-ref": "pkg:cargo/fixture@1", "purl": "pkg:cargo/fixture@1"}]})

    def write(self, kind, value):
        (self.boms / f"{kind}.cdx.json").write_text(json.dumps(value, sort_keys=True) + "\n")

    def verify(self, document, profile=bom.BomProfile.NATIVE_SDK_020):
        self.write("cbom", document)
        return bom.verify(self.root, cargo_lock=None, profile=profile)

    def test_closed_native_profile_and_legacy_profile_are_distinct(self):
        self.assertEqual(self.verify(self.document), {"cbom_components": 37, "sbom_components": 1})
        with self.assertRaises(bom.PackageBomError): self.verify(self.document, bom.BomProfile.BACKENDS_V0_1_5)
        legacy = copy.deepcopy(self.document)
        legacy["components"] = [c for c in legacy["components"] if c["name"] in bom.EXPECTED_CRYPTO_ASSETS]
        legacy["metadata"].pop("properties")
        for c in legacy["components"]: c["cryptoProperties"]["algorithmProperties"].setdefault("nistQuantumSecurityLevel", 0)
        self.assertEqual(self.verify(legacy, bom.BomProfile.BACKENDS_V0_1_5)["cbom_components"], 9)
        with self.assertRaises(bom.PackageBomError): self.verify(legacy)

    def test_missing_algorithms_and_invented_strength_or_operations_fail(self):
        for change in ("remove-hkdf", "remove-contextbound", "false-hash-level", "wrong-x25519-function", "rsa-handshake", "duplicate"):
            altered = copy.deepcopy(self.document)
            rows = {c["name"]: c for c in altered["components"]}
            if change == "remove-hkdf": altered["components"].remove(rows["HKDF-SHA-256"])
            elif change == "remove-contextbound": altered["components"].remove(rows["Q-Periapt-ContextBound"])
            elif change == "false-hash-level": rows["SHA-256"]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] = 0
            elif change == "wrong-x25519-function": rows["X25519"]["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"] = ["keygen", "key-agree"]
            elif change == "rsa-handshake": rows["RSA-PKCS1v1.5-SHA-256"]["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"].append("sign")
            else: altered["components"].append(copy.deepcopy(altered["components"][0]))
            with self.subTest(change=change):
                with self.assertRaises(bom.PackageBomError): self.verify(altered)

    def test_changed_tls_groups_certificate_parameters_or_scope_fail(self):
        for change in ("groups", "certificate_algorithms", "scope", "profile", "version", "alpha-version", "boolean-level"):
            altered = copy.deepcopy(self.document)
            facts = {p["name"]: p for p in altered["metadata"]["properties"]}
            if change in ("groups", "certificate_algorithms"):
                snapshot = json.loads(facts["qperiapt:configured-tls-provider"]["value"])
                if change == "groups": snapshot[change] = [29]
                else: snapshot[change].pop()
                facts["qperiapt:configured-tls-provider"]["value"] = json.dumps(snapshot)
            elif change == "scope": facts["qperiapt:inventory-scope"]["value"] = "complete security proof"
            elif change == "profile": facts["qperiapt:cbom-profile"]["value"] = "stable"
            elif change == "version": altered["metadata"]["component"]["version"] = "0.2.1"
            elif change == "alpha-version": altered["metadata"]["component"]["version"] = "0.2.0-alpha.1"
            else:
                next(c for c in altered["components"] if c["name"] == "ML-KEM-512")["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] = True
            with self.subTest(change=change):
                with self.assertRaises(bom.PackageBomError): self.verify(altered)


if __name__ == "__main__":
    unittest.main()
