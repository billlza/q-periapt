from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
import shutil
import tempfile
import tomllib
import unittest

import c_package_manifest
import package_bom
import third_party_licenses


class CPackageManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = pathlib.Path(__file__).resolve().parent.parent

    def _write_boms(self, package: pathlib.Path) -> None:
        common = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"component": {"name": "q-periapt-hybrid-suite"}},
        }
        crypto = []
        for name in sorted(package_bom.EXPECTED_CRYPTO_ASSETS):
            crypto.append(
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
        lock = tomllib.loads((self.repository / "Cargo.lock").read_text(encoding="utf-8"))
        sbom = []
        for entry in lock["package"]:
            purl = f"pkg:cargo/{entry['name']}@{entry['version']}"
            sbom.append(
                {
                    "type": "library",
                    "bom-ref": purl,
                    "name": entry["name"],
                    "version": entry["version"],
                    "purl": purl,
                }
            )
        for relative, components in (
            ("share/q-periapt/bom/cbom.cdx.json", crypto),
            ("share/q-periapt/bom/sbom.cdx.json", sbom),
        ):
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({**common, "components": components}, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    def _package(self, root: pathlib.Path, target: str = "x86_64-unknown-linux-gnu") -> pathlib.Path:
        package = root / f"q-periapt-c-abi2-0.1.0-alpha.2-{target}"
        contract_source = self.repository / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
        contract = json.loads(contract_source.read_text(encoding="utf-8"))
        runtime = contract["package"]["platforms"]["linux"]
        fixed_files = {
            "LICENSE": self.repository / "LICENSE",
            "LICENSES/Apache-2.0.txt": self.repository / "LICENSES/Apache-2.0.txt",
            "LICENSES/MIT.txt": self.repository / "LICENSES/MIT.txt",
            "LICENSES/mlkem-native/INVENTORY.sha256": self.repository / "crates/q-periapt-mlkem-native-sys/vendor/INVENTORY.sha256",
            "LICENSES/mlkem-native/LICENSE-INVENTORY.md": self.repository / "crates/q-periapt-mlkem-native-sys/vendor/LICENSE-INVENTORY.md",
            "LICENSES/mlkem-native/LICENSE.mlkem-native": self.repository / "crates/q-periapt-mlkem-native-sys/vendor/LICENSE.mlkem-native",
            "LICENSES/mlkem-native/PROVENANCE.md": self.repository / "crates/q-periapt-mlkem-native-sys/vendor/PROVENANCE.md",
            "share/q-periapt/abi/q-periapt-c-abi-v2.json": contract_source,
        }
        for relative, source in fixed_files.items():
            destination = package / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        payload_files = {
            "README.md",
            "include/qperiapt/abi2/q_periapt.h",
            "include/qperiapt/abi2/signed_policy_fixture.h",
            f"lib/{runtime['shared_filename']}",
            f"lib/{runtime['static_filename']}",
            "lib/pkgconfig/qperiapt-abi2.pc",
            "lib/pkgconfig/qperiapt-abi2-static.pc",
            "lib/cmake/QPeriaptABI2/QPeriaptABI2Config.cmake",
            "lib/cmake/QPeriaptABI2/QPeriaptABI2ConfigVersion.cmake",
            "share/q-periapt/smoke.c",
        }
        for relative in payload_files:
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture:{relative}\n", encoding="utf-8")
        self._write_boms(package)

        license_relative = "THIRD_PARTY/rust/fixture-dependency-1.0.0/LICENSE"
        license_path = package / license_relative
        license_path.parent.mkdir(parents=True, exist_ok=True)
        license_path.write_text("fixture dependency license\n", encoding="utf-8")
        license_bytes = license_path.read_bytes()
        third_party = {
            "schema_version": third_party_licenses.SCHEMA_VERSION,
            "kind": third_party_licenses.KIND,
            "root_package": third_party_licenses.ROOT_PACKAGE,
            "target": target,
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
        inventory_path.write_bytes(third_party_licenses.canonical_json(third_party))

        entries = []
        for path in sorted(item for item in package.rglob("*") if item.is_file()):
            relative = path.relative_to(package).as_posix()
            data = path.read_bytes()
            entries.append(
                {
                    "path": relative,
                    "type": "file",
                    "mode": "0o644",
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                }
            )
        exports = sorted(item["name"] for item in contract["abi"]["exports"])
        source_inputs = {
            key: c_package_manifest._snapshot(
                self.repository / relative, f"fixture source {relative}"
            ).sha256
            for key, relative in c_package_manifest.SOURCE_INPUT_PATHS.items()
        }
        source_inputs["rust_workspace_build_inputs"] = c_package_manifest._source_tree_hash(
            self.repository
        )
        source_inputs["third_party_rust_license_inventory"] = hashlib.sha256(
            inventory_path.read_bytes()
        ).hexdigest()
        epoch = 1_700_000_000
        manifest = {
            "schema_version": c_package_manifest.SCHEMA_VERSION,
            "package": package.name,
            "version": "0.1.0-alpha.2",
            "host": target,
            "generated_at": dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "source_date_epoch": epoch,
            "git_commit": "a" * 40,
            "git_dirty": False,
            "diagnostic_only": False,
            "rustc": "rustc fixture",
            "cargo": "cargo fixture",
            "platform_compatibility": {
                "target": target,
                "elf_class": "ELF64",
                "elf_machine": c_package_manifest.SUPPORTED_TARGETS[target]["elf_machine"],
                "needed_libraries": ["libc.so.6"],
                "max_glibc_version": "2.35",
                "glibc_policy_max": "2.35",
                "hardening": {
                    "bind_now": True,
                    "debug_sections_absent": True,
                    "gnu_relro": True,
                    "nx_stack": True,
                    "rpath_runpath_absent": True,
                    "textrel_absent": True,
                },
            },
            "abi": {
                "major": 2,
                "contract_path": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
                "embedded_contract_path": "share/q-periapt/abi/q-periapt-c-abi-v2.json",
                "contract_sha256": hashlib.sha256(contract_source.read_bytes()).hexdigest(),
                "exports_sha256": hashlib.sha256(("\n".join(exports) + "\n").encode()).hexdigest(),
                "export_count": 9,
                "platform": "linux",
                "runtime_identity": runtime,
                "shared_filename": runtime["shared_filename"],
                "static_filename": runtime["static_filename"],
            },
            "source_inputs_sha256": source_inputs,
            "files": entries,
        }
        manifest_path = package / "MANIFEST.json"
        manifest_path.write_bytes(c_package_manifest.canonical_json(manifest))
        sums = [*entries, {"path": "MANIFEST.json", "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest()}]
        (package / "SHA256SUMS").write_text(
            "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in sorted(sums, key=lambda item: item["path"])),
            encoding="ascii",
        )
        return package

    def test_complete_package_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = self._package(pathlib.Path(temporary))
            manifest = c_package_manifest.verify_package(
                package,
                self.repository,
                expected_target="x86_64-unknown-linux-gnu",
                expected_commit="a" * 40,
                expected_source_date_epoch=1_700_000_000,
            )
            self.assertEqual("linux", manifest["abi"]["platform"])

    def test_forged_minimal_package_and_unsafe_needed_library_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            minimal = root / "minimal"
            minimal.mkdir()
            (minimal / "MANIFEST.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(c_package_manifest.CPackageManifestError):
                c_package_manifest.verify_package(
                    minimal,
                    self.repository,
                    expected_target="x86_64-unknown-linux-gnu",
                )

            package = self._package(root / "unsafe")
            manifest_path = package / "MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["platform_compatibility"]["needed_libraries"] = [
                "evil.so",
                "libc.so.6",
            ]
            manifest_path.write_bytes(c_package_manifest.canonical_json(manifest))
            sums_path = package / "SHA256SUMS"
            lines = []
            for line in sums_path.read_text(encoding="ascii").splitlines():
                digest, relative = line.split("  ", 1)
                if relative == "MANIFEST.json":
                    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
                lines.append(f"{digest}  {relative}\n")
            sums_path.write_text("".join(lines), encoding="ascii")
            with self.assertRaisesRegex(
                c_package_manifest.CPackageManifestError, "DT_NEEDED allowlist",
            ):
                c_package_manifest.verify_package(
                    package,
                    self.repository,
                    expected_target="x86_64-unknown-linux-gnu",
                )


if __name__ == "__main__":
    unittest.main()
