"""SDK profile admission with synthetic PE fixtures; native execution stays a separate gate."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import test_sdk_cbom_contract as cbom_fixture
import test_windows_package as legacy_fixture
import windows_package as windows


class WindowsSDKProfileTests(unittest.TestCase):
    def setUp(self):
        self.repository = Path(__file__).resolve().parent.parent
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        fixture = legacy_fixture.WindowsPackageManifestTests()
        fixture.repository_root = self.repository
        old = fixture._package(self.folder)
        self.package = self.folder / f"q-periapt-c-abi2-{windows.SDK_PACKAGE_SEMVER}-{windows.TARGET}"
        old.rename(self.package)
        (self.package / "share/q-periapt/abi/q-periapt-c-abi-v2.json").unlink()
        shutil.copy2(self.repository / windows.SDK_CONTRACT_PATH, self.package / windows.SDK_EMBEDDED_CONTRACT)
        for packaged, source in windows.SDK_PAYLOAD_SOURCES.items():
            path = self.package / packaged
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.repository / source, path)
        cbom = cbom_fixture.SDKCBOMContractTests()
        cbom.setUp()
        self.addCleanup(cbom.doCleanups)
        (self.package / "share/q-periapt/bom/cbom.cdx.json").write_bytes(windows._canonical_json(cbom.document))

    def create(self, profile="sdk-alpha1"):
        return windows.create_manifest(
            self.package, self.repository, package_name=self.package.name, version=windows.SDK_PACKAGE_SEMVER,
            git_commit="a" * 40, git_tree="b" * 40, source_date_epoch=1_700_000_000,
            rustc=windows.EXPECTED_RUSTC_VERSION, cargo=windows.EXPECTED_CARGO_VERSION,
            cl="MSVC 19.44.35222.0", dependencies=["KERNEL32.dll", "bcrypt.dll"], profile=profile)

    def verify(self, profile="sdk-alpha1"):
        return windows.verify_package(self.package, repository_root=self.repository, profile=profile)

    def reseal(self, manifest):
        entries = []
        for path in self.package.rglob("*"):
            if not path.is_file() or path.name in {"MANIFEST.json", "SHA256SUMS"}:
                continue
            data = path.read_bytes()
            entries.append({"path": path.relative_to(self.package).as_posix(), "bytes": len(data),
                            "mode": "0o644", "type": "file", "sha256": hashlib.sha256(data).hexdigest()})
        # The wire format orders exact POSIX strings. WindowsPath ordering
        # instead folds case, which can mask the intended rejection below.
        manifest["files"] = sorted(entries, key=lambda entry: entry["path"])
        document = windows._canonical_json(manifest)
        (self.package / "MANIFEST.json").write_bytes(document)
        hashes = {entry["path"]: entry["sha256"] for entry in entries}
        hashes["MANIFEST.json"] = hashlib.sha256(document).hexdigest()
        (self.package / "SHA256SUMS").write_text("".join(f"{digest}  {path}\n" for path, digest in sorted(hashes.items())))

    def test_explicit_profile_preserves_legacy_and_binds_current_payload(self):
        with self.assertRaisesRegex(windows.WindowsPackageError, "version must be 0.1.5"):
            self.create(profile="legacy")
        manifest = self.create()
        self.assertEqual(manifest["schema_version"], 4)
        self.assertEqual(manifest["kind"], windows.SDK_KIND)
        self.assertEqual((manifest["abi"]["major"], manifest["abi"]["export_count"]), (2, 43))
        self.assertIs(manifest["release_claim_eligible"], False)
        self.assertEqual(manifest["authenticode"]["reason"], windows.SDK_UNSIGNED_REASON)
        self.assertNotIn("attestations", manifest["authenticode"]["reason"])
        self.assertEqual(self.verify(), manifest)
        self.reseal(manifest)
        self.assertEqual(self.verify(), manifest)
        with self.assertRaises(windows.WindowsPackageError):
            self.verify(profile="legacy")
        with self.assertRaisesRegex(windows.WindowsPackageError, "unknown.*profile"):
            self.verify(profile="unknown")

    def test_rehashed_source_or_missing_owner_payload_cannot_pass(self):
        manifest = self.create()
        path = self.package / "share/q-periapt/sdk_smoke.c"
        original = path.read_bytes()
        path.write_bytes(original + b"\n/* substituted consumer */\n")
        self.reseal(manifest)
        with self.assertRaisesRegex(windows.WindowsPackageError, "shipped source differs"):
            self.verify()
        path.unlink()
        self.reseal(manifest)
        with self.assertRaisesRegex(windows.WindowsPackageError, "file set differs"):
            self.verify()

    def test_coherent_schema_version_abi_or_release_relabeling_is_rejected(self):
        original = self.create()
        for key, value in (("schema_version", 3), ("schema_version", 4.0), ("kind", windows.KIND),
                           ("profile", "legacy"), ("version", "0.1.5"), ("release_claim_eligible", True),
                           ("git_dirty", True)):
            changed = copy.deepcopy(original)
            changed[key] = value
            self.reseal(changed)
            with self.subTest(field=key, value=value), self.assertRaises(windows.WindowsPackageError):
                self.verify()
        for key, value in (("major", 3), ("major", 2.0), ("export_count", 9), ("export_count", 43.0)):
            changed = copy.deepcopy(original)
            changed["abi"][key] = value
            self.reseal(changed)
            with self.subTest(abi_field=key, value=value), self.assertRaises(windows.WindowsPackageError):
                self.verify()

    def test_legacy_nine_asset_cbom_cannot_admit_sdk(self):
        manifest = self.create()
        path = self.package / "share/q-periapt/bom/cbom.cdx.json"
        document = json.loads(path.read_text())
        document["components"] = [row for row in document["components"] if row["name"] in windows.EXPECTED_CRYPTO_ASSETS]
        path.write_bytes(windows._canonical_json(document))
        self.reseal(manifest)
        with self.assertRaisesRegex(windows.WindowsPackageError, "asset inventory differs"):
            self.verify()

    def test_sdk_producer_and_archive_verifier_select_profile_and_same_library_names(self):
        script = (self.repository / "artifact/windows-package.ps1").read_text()
        for required in ('[ValidateSet("legacy", "sdk-alpha1")]', '$Version = "0.2.0-alpha.1"',
                         '"--profile", $Profile', '"--profile", "native-sdk-alpha1"',
                         '"--features", "sdk-cbom"', '"share/q-periapt/legacy/q_periapt.h"',
                         '"share/q-periapt/sdk_smoke.c"', '"LICENSES/Rust-1.97.0-library.html"',
                         'dynamic-smoke,sdk-dynamic-smoke,sdk-static-smoke,static-smoke',
                         'SDK output already exists', 'installed SDK consumers must be outside the checkout',
                         'Windows archive changed during consumer execution'):
            with self.subTest(required=required):
                self.assertIn(required, script)
        self.assertIn('"bin/q_periapt_ffi_abi2.dll"', script)
        self.assertNotIn("q_periapt_ffi_abi3", script)
        self.assertEqual(windows.SCHEMA_VERSION, 3)
        self.assertEqual(windows.PACKAGE_SEMVER, "0.1.5")


if __name__ == "__main__":
    unittest.main()
