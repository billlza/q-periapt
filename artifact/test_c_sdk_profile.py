"""The additive C SDK package profile stays distinct from historical receipts."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import c_package_manifest as cpm
import test_c_package_manifest as package_fixture
import test_sdk_cbom_contract as cbom_fixture


class CSDKProfileTests(unittest.TestCase):
    def setUp(self):
        self.repository = Path(__file__).resolve().parent.parent
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        # Reuse the existing structural package and CBOM fixtures. These tests
        # exercise profile admission; actual binaries run in the package gate.
        fixture = package_fixture.CPackageManifestTests()
        fixture.repository = self.repository
        old = fixture._package(self.folder)
        self.package = self.folder / "q-periapt-c-abi2-0.2.0-x86_64-unknown-linux-gnu"
        old.rename(self.package)
        self.manifest = json.loads((self.package / "MANIFEST.json").read_text())
        self.manifest.update(schema_version=3, package=self.package.name, version=cpm.SDK_PACKAGE_VERSION)
        (self.package / "share/q-periapt/abi/q-periapt-c-abi-v2.json").unlink()
        contract = cpm.load_contract(self.repository / cpm.SDK_CONTRACT_PATH)
        shutil.copy2(self.repository / cpm.SDK_CONTRACT_PATH, self.package / cpm.SDK_EMBEDDED_CONTRACT)
        abi = self.manifest["abi"]
        abi.update(contract_path=cpm.SDK_CONTRACT_PATH, embedded_contract_path=cpm.SDK_EMBEDDED_CONTRACT,
                   contract_sha256=contract.sha256, export_count=51,
                   exports_sha256=hashlib.sha256(("\n".join(sorted(contract.export_names)) + "\n").encode()).hexdigest())
        self.manifest["source_inputs_sha256"] = {
            **cpm.source_fingerprints(self.repository, "sdk-020"),
            "third_party_rust_license_inventory": self.manifest["source_inputs_sha256"]["third_party_rust_license_inventory"],
        }
        for packaged, source in cpm.SDK_PAYLOAD_SOURCES.items():
            destination = self.package / packaged
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.repository / source, destination)
        cbom = cbom_fixture.SDKCBOMContractTests()
        cbom.setUp()
        self.addCleanup(cbom.doCleanups)
        (self.package / "share/q-periapt/bom/cbom.cdx.json").write_bytes(cpm.canonical_json(cbom.document))
        self.seal()

    def seal(self):
        entries = []
        for path in sorted(self.package.rglob("*")):
            if not path.is_file() or path.name in {"MANIFEST.json", "SHA256SUMS"}:
                continue
            path.chmod(0o644)
            data = path.read_bytes()
            entries.append({"path": path.relative_to(self.package).as_posix(), "type": "file", "mode": "0o644",
                            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        self.manifest["files"] = entries
        data = cpm.canonical_json(self.manifest)
        (self.package / "MANIFEST.json").write_bytes(data)
        sums = {e["path"]: e["sha256"] for e in entries}
        sums["MANIFEST.json"] = hashlib.sha256(data).hexdigest()
        (self.package / "SHA256SUMS").write_text("".join(f"{value}  {key}\n" for key, value in sorted(sums.items())))

    def verify(self, **kwargs):
        return cpm.verify_package(self.package, self.repository, expected_target="x86_64-unknown-linux-gnu",
                                  **kwargs)

    def test_exact_alpha_profile_and_explicit_diagnostic_boundary(self):
        self.assertEqual(self.verify(profile="sdk-020")["abi"]["export_count"], 51)
        with self.assertRaises(cpm.CPackageManifestError): self.verify()
        self.manifest.update(git_dirty=True, diagnostic_only=True)
        self.seal()
        with self.assertRaisesRegex(cpm.CPackageManifestError, "not clean release"):
            self.verify(profile="sdk-020")
        self.assertTrue(self.verify(profile="sdk-020", allow_diagnostic=True)["diagnostic_only"])
        with self.assertRaises(cpm.CPackageManifestError): self.verify(profile="legacy", allow_diagnostic=True)

    def test_altered_contract_inventory_or_payload_cannot_be_rehashed_into_acceptance(self):
        original = copy.deepcopy(self.manifest)
        for key, value in (("export_count", 9), ("contract_path", cpm.SOURCE_INPUT_PATHS["c_abi_contract"]),
                           ("embedded_contract_path", "share/q-periapt/abi/q-periapt-c-abi-v2.json")):
            self.manifest = copy.deepcopy(original)
            self.manifest["abi"][key] = value
            self.seal()
            with self.subTest(field=key), self.assertRaises(cpm.CPackageManifestError):
                self.verify(profile="sdk-020")
        self.manifest = original
        fixture = self.package / "include/qperiapt/abi2/sdk_policy_update_fixture.h"
        fixture.write_bytes(fixture.read_bytes() + b"\n/* changed fixture */\n")
        self.seal()
        with self.assertRaisesRegex(cpm.CPackageManifestError, "installed source differs"):
            self.verify(profile="sdk-020")

    def test_missing_owner_consumer_extra_files_and_legacy_bom_fail(self):
        owner = self.package / "share/q-periapt/sdk_smoke.c"
        data = owner.read_bytes()
        owner.unlink(); self.seal()
        with self.assertRaisesRegex(cpm.CPackageManifestError, "file set differs"):
            self.verify(profile="sdk-020")
        owner.write_bytes(data)
        extra = self.package / "extra.txt"; extra.write_text("unreviewed payload"); self.seal()
        with self.assertRaisesRegex(cpm.CPackageManifestError, "file set differs"):
            self.verify(profile="sdk-020")
        extra.unlink()
        fixture = package_fixture.CPackageManifestTests(); fixture.repository = self.repository
        fixture._write_boms(self.package); self.seal()
        with self.assertRaisesRegex(cpm.CPackageManifestError, "BOM is invalid"):
            self.verify(profile="sdk-020")

    def test_unknown_profile_is_rejected_before_archive_access(self):
        env = {**os.environ, "QPERIAPT_C_PACKAGE_VERIFY_ARCHIVE": "/not-opened/archive.tar.gz"}
        result = subprocess.run(["sh", str(self.repository / "artifact/c-package.sh"), "--profile", "abi3"],
                                env=env, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("accepts only --profile sdk-020", result.stderr)

    def test_final_byte_check_uses_the_manifest_pinned_before_installation(self):
        manifest = self.package / "MANIFEST.json"
        expected = hashlib.sha256(manifest.read_bytes()).hexdigest()
        cpm.verify_sealed_payload(self.package, expected)
        library = self.package / "lib" / self.manifest["abi"]["shared_filename"]
        library.write_bytes(library.read_bytes() + b"changed after consumer tests")
        with self.assertRaisesRegex(cpm.CPackageManifestError, "payload changed"):
            cpm.verify_sealed_payload(self.package, expected)
        self.seal()
        with self.assertRaisesRegex(cpm.CPackageManifestError, "manifest changed"):
            cpm.verify_sealed_payload(self.package, expected)


if __name__ == "__main__":
    unittest.main()
