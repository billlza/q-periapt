from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import tempfile
import tomllib
import unittest

import third_party_licenses
import windows_package
from windows_package import WindowsPackageError


class WindowsPackageManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository_root = pathlib.Path(__file__).resolve().parent.parent

    def _package(self, root: pathlib.Path) -> pathlib.Path:
        package = root / (
            "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-pc-windows-msvc"
        )
        for relative in windows_package.EXPECTED_PAYLOAD_FILES:
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"fixture:{relative}\n".encode())
        license_relative = "THIRD_PARTY/rust/fixture-dependency-1.0.0/LICENSE"
        license_path = package / license_relative
        license_path.parent.mkdir(parents=True, exist_ok=True)
        license_path.write_text("fixture dependency license\n", encoding="utf-8")
        license_bytes = license_path.read_bytes()
        inventory = {
            "schema_version": third_party_licenses.SCHEMA_VERSION,
            "kind": third_party_licenses.KIND,
            "root_package": third_party_licenses.ROOT_PACKAGE,
            "target": windows_package.TARGET,
            "packages": [
                {
                    "checksum": "b" * 64,
                    "license_expression": "MIT",
                    "name": "fixture-dependency",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "version": "1.0.0",
                    "license_files": [
                        {
                            "bytes": len(license_bytes),
                            "path": license_relative,
                            "sha256": hashlib.sha256(license_bytes).hexdigest(),
                        }
                    ],
                }
            ],
        }
        inventory_path = package / third_party_licenses.INVENTORY_RELATIVE
        inventory_path.write_bytes(third_party_licenses.canonical_json(inventory))
        shutil.copy2(
            self.repository_root
            / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
            package / "share/q-periapt/abi/q-periapt-c-abi-v2.json",
        )
        crypto_components = []
        for name in sorted(windows_package.EXPECTED_CRYPTO_ASSETS):
            crypto_components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": f"crypto:{name}",
                    "name": name,
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "fixture",
                            "parameterSetIdentifier": name,
                            "cryptoFunctions": ["other"],
                            "nistQuantumSecurityLevel": 0,
                        },
                    },
                }
            )
        lock = tomllib.loads(
            (self.repository_root / "Cargo.lock").read_text(encoding="utf-8")
        )
        sbom_components = []
        for entry in lock["package"]:
            purl = f"pkg:cargo/{entry['name']}@{entry['version']}"
            sbom_components.append(
                {
                    "type": "library",
                    "bom-ref": purl,
                    "name": entry["name"],
                    "version": entry["version"],
                    "purl": purl,
                }
            )
        common = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"component": {"name": "q-periapt-hybrid-suite"}},
        }
        (package / "share/q-periapt/bom/cbom.cdx.json").write_text(
            json.dumps({**common, "components": crypto_components}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        (package / "share/q-periapt/bom/sbom.cdx.json").write_text(
            json.dumps({**common, "components": sbom_components}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        return package

    def _create(self, package: pathlib.Path) -> dict:
        return windows_package.create_manifest(
            package,
            self.repository_root,
            package_name=package.name,
            version="0.1.0-alpha.2",
            git_commit="a" * 40,
            git_tree="b" * 40,
            source_date_epoch=1_700_000_000,
            rustc="rustc fixture",
            cargo="cargo fixture",
            cl="Microsoft C/C++ fixture",
            dependencies=["KERNEL32.dll", "bcrypt.dll"],
        )

    def test_create_and_verify_are_deterministic_and_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = self._package(pathlib.Path(temporary))
            first = self._create(package)
            first_manifest = (package / "MANIFEST.json").read_bytes()
            first_sums = (package / "SHA256SUMS").read_bytes()

            (package / "MANIFEST.json").unlink()
            (package / "SHA256SUMS").unlink()
            second = self._create(package)

            self.assertEqual(first, second)
            self.assertEqual(first_manifest, (package / "MANIFEST.json").read_bytes())
            self.assertEqual(first_sums, (package / "SHA256SUMS").read_bytes())
            verified = windows_package.verify_package(
                package, repository_root=self.repository_root
            )
            self.assertEqual(verified["target"], windows_package.TARGET)
            self.assertEqual(
                verified["release_class"], "unsigned_experimental_prerelease"
            )
            self.assertFalse(verified["authenticode"]["signed"])

    def test_tampering_extra_files_and_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = self._package(root)
            self._create(package)

            (package / "bin/q_periapt_ffi_abi2.dll").write_bytes(b"tampered")
            with self.assertRaisesRegex(WindowsPackageError, "(?:size|hash) mismatch"):
                windows_package.verify_package(package)

            package = self._package(root / "extra")
            (package / "unexpected.txt").write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(WindowsPackageError, "file set differs"):
                self._create(package)

            package = self._package(root / "symlink")
            target = package / "LICENSE"
            target.unlink()
            target.symlink_to(self.repository_root / "LICENSE")
            with self.assertRaisesRegex(WindowsPackageError, "symlink"):
                self._create(package)

            real_package = self._package(root / "root-link-target")
            self._create(real_package)
            package_link = root / "package-root-link"
            try:
                package_link.symlink_to(real_package, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks unavailable")
            with self.assertRaisesRegex(WindowsPackageError, "root must be a non-symlink"):
                windows_package.verify_package(package_link)

    def test_invalid_dependencies_and_source_metadata_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = self._package(pathlib.Path(temporary))
            with self.assertRaisesRegex(WindowsPackageError, "invalid Windows"):
                windows_package.create_manifest(
                    package,
                    self.repository_root,
                    package_name=package.name,
                    version="0.1.0-alpha.2",
                    git_commit="a" * 40,
                    git_tree="b" * 40,
                    source_date_epoch=1_700_000_000,
                    rustc="rustc fixture",
                    cargo="cargo fixture",
                    cl="Microsoft C/C++ fixture",
                    dependencies=["..\\malicious.dll"],
                )
            with self.assertRaisesRegex(WindowsPackageError, "git commit"):
                windows_package.create_manifest(
                    package,
                    self.repository_root,
                    package_name=package.name,
                    version="0.1.0-alpha.2",
                    git_commit="not-a-commit",
                    git_tree="b" * 40,
                    source_date_epoch=1_700_000_000,
                    rustc="rustc fixture",
                    cargo="cargo fixture",
                    cl="Microsoft C/C++ fixture",
                    dependencies=["KERNEL32.dll"],
                )

    @staticmethod
    def _rewrite_manifest(package: pathlib.Path, mutate) -> None:
        manifest_path = package / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        mutate(manifest)
        manifest_path.write_bytes(windows_package._canonical_json(manifest))
        sums_path = package / "SHA256SUMS"
        lines = []
        for line in sums_path.read_text(encoding="ascii").splitlines():
            digest, relative = line.split("  ", 1)
            if relative == "MANIFEST.json":
                digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {relative}\n")
        sums_path.write_text("".join(lines), encoding="ascii")

    def test_manifest_identity_source_toolchain_and_schema_tampering_fail_closed(self) -> None:
        mutations = {
            "package": lambda value: value.__setitem__("package", "unrelated-package"),
            "generated_at": lambda value: value.__setitem__("generated_at", "not-a-time"),
            "source_date_epoch": lambda value: value.__setitem__("source_date_epoch", False),
            "toolchain": lambda value: value.__setitem__("toolchain", {}),
            "source inputs": lambda value: value.__setitem__("source_inputs_sha256", {}),
            "fields": lambda value: value.__setitem__("unexpected", True),
            "dependency": lambda value: value.__setitem__("native_dependencies", ["evil.dll"]),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            original = self._package(root / "original")
            self._create(original)
            for label, mutation in mutations.items():
                with self.subTest(label=label):
                    package = root / f"tampered-{label.replace(' ', '-')}" / original.name
                    shutil.copytree(original, package)
                    self._rewrite_manifest(package, mutation)
                    with self.assertRaises(WindowsPackageError):
                        windows_package.verify_package(
                            package, repository_root=self.repository_root
                        )

    def test_native_dependency_evidence_and_complete_sbom_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = self._package(root / "package")
            self._create(package)
            with self.assertRaisesRegex(
                WindowsPackageError, "dependencies differ from native dumpbin",
            ):
                windows_package.verify_package(
                    package,
                    repository_root=self.repository_root,
                    expected_dependencies=["KERNEL32.dll"],
                )

            invalid = self._package(root / "invalid-bom")
            sbom_path = invalid / "share/q-periapt/bom/sbom.cdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            sbom["components"].pop()
            sbom_path.write_text(json.dumps(sbom, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsPackageError, "SBOM components do not match Cargo.lock",
            ):
                self._create(invalid)

    def test_powershell_release_wiring_preserves_source_and_external_trust_roots(self) -> None:
        script = (self.repository_root / "artifact/windows-package.ps1").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(
            script.count(
                "Assert-SourceSnapshot -ExpectedCommit $GitCommit -ExpectedTree $GitTree"
            ),
            5,
        )
        for token in (
            "$ExpectedSha256",
            "$ExpectedManifestSha256",
            "$ExpectedContractSha256",
            "$ExpectedGitCommit",
            "$ExpectedGitTree",
            '"--expected-dependency"',
            '"--sha256", $ExpectedArchiveSha256',
        ):
            self.assertIn(token, script)
        stdout_read = script.index("$process.StandardOutput.ReadToEndAsync()")
        stderr_read = script.index("$process.StandardError.ReadToEndAsync()")
        wait = script.index("$process.WaitForExit()")
        self.assertLess(stdout_read, wait)
        self.assertLess(stderr_read, wait)


if __name__ == "__main__":
    unittest.main()
