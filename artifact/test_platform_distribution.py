from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import android_device_proof
import platform_distribution
import windows_package
from deterministic_archive import create_tar_gz, create_zip


class PlatformDistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = pathlib.Path(__file__).resolve().parent.parent
        (cls.repository / "target").mkdir(exist_ok=True)
        cls.abi = platform_distribution._abi_identity(cls.repository)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir=self.repository / "target"
        )
        self.root = pathlib.Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.source = platform_distribution.SourceIdentity(
            commit="a" * 40,
            tree="b" * 40,
            canonical_source_tree_sha256="c" * 64,
            source_date_epoch=1_700_000_000,
        )
        self.android_tools = platform_distribution.AndroidVerificationTools(
            llvm_nm=self.root / "tool-llvm-nm",
            llvm_readelf=self.root / "tool-llvm-readelf",
            apksigner=self.root / "tool-apksigner",
            zipalign=self.root / "tool-zipalign",
        )
        self.aar_bytes = b"fixture Android AAR bytes\n"
        self._build_assets()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_json(path: pathlib.Path, value: dict) -> bytes:
        data = platform_distribution.canonical_json(value)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return data

    def _abi_manifest(self) -> dict:
        return {
            "major": self.abi["major"],
            "contract_sha256": self.abi["contract_sha256"],
            "exports_sha256": self.abi["exports_sha256"],
            "export_count": self.abi["export_count"],
        }

    @staticmethod
    def _windows_hardening() -> dict:
        return {
            "machine": "x86_64",
            "dynamic_base": True,
            "nx_compatible": True,
            "high_entropy_va": True,
            "linker_warnings_as_errors": True,
            "base_relocations": {
                "directory_present": True,
                "dir64_count": 1,
            },
            "debug_directory": {
                "entry_count": 1,
                "entry_type": "IMAGE_DEBUG_TYPE_REPRO",
                "payload_kind": "empty",
                "hash_bytes": 0,
            },
        }

    def _android_manifest(self) -> tuple[dict, bytes]:
        manifest = {
            "schema_version": 3,
            "kind": "qperiapt.android_aar_manifest",
            "package": platform_distribution.ANDROID_AAR,
            "version": platform_distribution.PRODUCT_VERSION,
            "generated_at": "2023-11-14T22:13:20Z",
            "source_date_epoch": self.source.source_date_epoch,
            "git_commit": self.source.commit,
            "git_dirty": False,
            "package_only": True,
            "device_runtime_proof": False,
            "boundary": "package-only fixture",
            "abi": {
                **self._abi_manifest(),
                "platform": "android-aar",
            },
            "android": {
                "ndk": "29.0.14206865",
                "native_page_alignment": 16_384,
            },
            "artifacts": {
                "aar_sha256": hashlib.sha256(self.aar_bytes).hexdigest(),
            },
        }
        return manifest, platform_distribution.canonical_json(manifest)

    def _build_android_bundle(self, manifest_bytes: bytes) -> None:
        stage = self.root / "android-bundle-stage"
        stage.mkdir()
        proof = {
            "schema_version": 3,
            "git_commit": self.source.commit,
            "run_id": "d" * 32,
            "release_candidate_mode": True,
            "device_runtime_proof": True,
            "package_only": False,
            "device": {
                "kind": "emulator",
                "abi": "arm64-v8a",
                "page_size": 16_384,
                "sdk": 35,
            },
        }
        payloads = {
            "proof": platform_distribution.canonical_json(proof),
            "aar": self.aar_bytes,
            "aar_manifest": manifest_bytes,
            "smoke_apk": b"fixture APK\n",
            "apksigner_verify": b"Verified\n",
            "zipalign_verify": b"Verification successful\n",
            "result_txt": b"QPERIAPT_ANDROID_DEVICE_PASS fixture\n",
            "result_json": b'{"status":"pass"}\n',
            "logcat": b"fixture logcat\n",
        }
        records = {}
        for key, relative in android_device_proof.BUNDLE_FILE_PATHS.items():
            data = payloads[key]
            path = stage / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            records[key] = {
                "bytes": len(data),
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        bundle_manifest = {
            "schema_version": android_device_proof.BUNDLE_SCHEMA_VERSION,
            "kind": android_device_proof.BUNDLE_KIND,
            "source_date_epoch": self.source.source_date_epoch,
            "git_commit": self.source.commit,
            "run_id": proof["run_id"],
            "release_candidate_mode": True,
            "device": proof["device"],
            "raw_serial_recorded": False,
            "files": records,
        }
        self._write_json(
            stage / android_device_proof.BUNDLE_MANIFEST_PATH,
            bundle_manifest,
        )
        create_zip(
            stage,
            self.assets / platform_distribution.ANDROID_RUNTIME_BUNDLE,
            root_name=android_device_proof.BUNDLE_ROOT_NAME,
            mtime=self.source.source_date_epoch,
        )

    def _build_linux(self, target: str, filename: str) -> None:
        package_name = (
            f"q-periapt-c-abi2-{platform_distribution.PRODUCT_VERSION}-{target}"
        )
        package = self.root / f"stage-{target}"
        package.mkdir()
        manifest = {
            "schema_version": 2,
            "package": package_name,
            "version": platform_distribution.PRODUCT_VERSION,
            "source_date_epoch": self.source.source_date_epoch,
            "git_commit": self.source.commit,
            "git_dirty": False,
            "diagnostic_only": False,
            "host": target,
            "abi": self._abi_manifest(),
            "platform_compatibility": {"target": target},
        }
        self._write_json(package / "MANIFEST.json", manifest)
        create_tar_gz(
            package,
            self.assets / filename,
            root_name=package_name,
            mtime=self.source.source_date_epoch,
        )

    def _build_windows(self) -> None:
        target = "x86_64-pc-windows-msvc"
        package_name = (
            f"q-periapt-c-abi2-{platform_distribution.PRODUCT_VERSION}-{target}"
        )
        package = self.root / "stage-windows"
        package.mkdir()
        manifest = {
            "schema_version": windows_package.SCHEMA_VERSION,
            "kind": "qperiapt.windows_c_package_manifest",
            "package": package_name,
            "version": platform_distribution.PRODUCT_VERSION,
            "source_date_epoch": self.source.source_date_epoch,
            "git_commit": self.source.commit,
            "git_dirty": False,
            "target": target,
            "release_class": "unsigned_experimental_prerelease",
            "authenticode": {
                "signed": False,
                "certificate_directory_present": False,
                "reason": "fixture",
            },
            "hardening": self._windows_hardening(),
            "abi": self._abi_manifest(),
        }
        self._write_json(package / "MANIFEST.json", manifest)
        create_zip(
            package,
            self.assets / platform_distribution.WINDOWS_X86_64,
            root_name=package_name,
            mtime=self.source.source_date_epoch,
        )

    def _build_assets(self) -> None:
        (self.assets / platform_distribution.ANDROID_AAR).write_bytes(self.aar_bytes)
        android_manifest, manifest_bytes = self._android_manifest()
        self.assertEqual(
            manifest_bytes,
            self._write_json(
                self.assets / platform_distribution.ANDROID_MANIFEST,
                android_manifest,
            ),
        )
        self._build_android_bundle(manifest_bytes)
        self._build_linux(
            "x86_64-unknown-linux-gnu",
            platform_distribution.LINUX_X86_64,
        )
        self._build_linux(
            "aarch64-unknown-linux-gnu",
            platform_distribution.LINUX_AARCH64,
        )
        self._build_windows()

    @staticmethod
    def _verified_manifest(package_root: pathlib.Path, *_args, **_kwargs) -> dict:
        return json.loads((package_root / "MANIFEST.json").read_text(encoding="utf-8"))

    def _verified_windows_manifest(
        self, package_root: pathlib.Path, *_args, **_kwargs
    ) -> dict:
        manifest = json.loads(
            (package_root / "MANIFEST.json").read_text(encoding="utf-8")
        )
        expected_authenticode = {
            "signed": False,
            "certificate_directory_present": False,
            "reason": "fixture",
        }
        if not (
            manifest.get("schema_version") == windows_package.SCHEMA_VERSION
            and manifest.get("hardening") == self._windows_hardening()
            and manifest.get("authenticode") == expected_authenticode
        ):
            raise windows_package.WindowsPackageError(
                "fixture Windows PE evidence differs"
            )
        return manifest

    @staticmethod
    def _verified_bundle_manifest(
        bundle_root: pathlib.Path,
        _manifest: dict,
        *,
        archive_mtime: int,
    ) -> tuple[dict[str, pathlib.Path], dict]:
        del archive_mtime
        selected = {
            key: bundle_root / relative
            for key, relative in android_device_proof.BUNDLE_FILE_PATHS.items()
        }
        proof = json.loads(selected["proof"].read_text(encoding="utf-8"))
        return selected, proof

    def _deep_validator_mocks(self):
        return (
            mock.patch.object(
                platform_distribution,
                "verify_runtime_bundle",
                side_effect=lambda **kwargs: hashlib.sha256(
                    kwargs["bundle"].read_bytes()
                ).hexdigest(),
            ),
            mock.patch.object(
                platform_distribution,
                "verify_bundle_manifest",
                side_effect=self._verified_bundle_manifest,
            ),
            mock.patch.object(
                platform_distribution,
                "verify_proof_freshness",
            ),
            mock.patch.object(
                platform_distribution,
                "verify_c_package",
                side_effect=self._verified_manifest,
            ),
            mock.patch.object(
                platform_distribution,
                "verify_windows_package",
                side_effect=self._verified_windows_manifest,
            ),
        )

    def _assemble(self, output: pathlib.Path) -> dict:
        validators = self._deep_validator_mocks()
        with (
            mock.patch.object(
                platform_distribution,
                "_source_identity",
                return_value=self.source,
            ),
            validators[0],
            validators[1],
            validators[2],
            validators[3],
            validators[4],
        ):
            return platform_distribution.assemble(
                self.repository,
                self.assets,
                output,
                android_tools=self.android_tools,
            )

    def _verify(self, output: pathlib.Path) -> dict:
        validators = self._deep_validator_mocks()
        with (
            mock.patch.object(
                platform_distribution,
                "_source_identity",
                return_value=self.source,
            ),
            validators[0],
            validators[1],
            validators[2],
            validators[3],
            validators[4],
        ):
            return platform_distribution.verify_distribution(
                self.repository,
                output,
                android_tools=self.android_tools,
            )

    def test_assemble_verify_and_rebuild_are_byte_deterministic(self) -> None:
        first_output = self.root / "release-first"
        first = self._assemble(first_output)
        self.assertEqual(6, len(first["assets"]))
        self.assertFalse(
            next(
                asset
                for asset in first["assets"]
                if asset["name"] == platform_distribution.WINDOWS_X86_64
            )["authenticode_signed"]
        )
        self.assertEqual(first, self._verify(first_output))
        first_bytes = {
            path.name: path.read_bytes() for path in first_output.iterdir()
        }

        second_output = self.root / "release-second"
        second = self._assemble(second_output)
        second_bytes = {
            path.name: path.read_bytes() for path in second_output.iterdir()
        }
        self.assertEqual(first, second)
        self.assertEqual(first_bytes, second_bytes)

    def test_windows_fixture_validator_rejects_schema_and_pe_evidence_drift(self) -> None:
        package = self.root / "stage-windows"
        manifest_path = package / "MANIFEST.json"
        original = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            self._verified_windows_manifest(package),
            original,
        )
        mutations = {
            "schema": lambda value: value.__setitem__("schema_version", 2),
            "dynamic base": lambda value: value["hardening"].__setitem__(
                "dynamic_base", False
            ),
            "NX": lambda value: value["hardening"].__setitem__(
                "nx_compatible", False
            ),
            "high entropy": lambda value: value["hardening"].__setitem__(
                "high_entropy_va", False
            ),
            "link warnings": lambda value: value["hardening"].__setitem__(
                "linker_warnings_as_errors", False
            ),
            "entry type": lambda value: value["hardening"][
                "debug_directory"
            ].__setitem__("entry_type", "IMAGE_DEBUG_TYPE_CODEVIEW"),
            "entry count": lambda value: value["hardening"][
                "debug_directory"
            ].__setitem__("entry_count", 2),
            "base relocations": lambda value: value["hardening"][
                "base_relocations"
            ].__setitem__("dir64_count", 0),
            "certificate": lambda value: value["authenticode"].__setitem__(
                "certificate_directory_present", True
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                changed = json.loads(json.dumps(original))
                mutate(changed)
                self._write_json(manifest_path, changed)
                with self.assertRaises(windows_package.WindowsPackageError):
                    self._verified_windows_manifest(package)

    def test_tampered_asset_or_checksum_fails_closed(self) -> None:
        output = self.root / "release"
        self._assemble(output)
        (output / platform_distribution.ANDROID_AAR).write_bytes(b"tampered")
        with self.assertRaisesRegex(
            platform_distribution.PlatformDistributionError,
            "Android AAR manifest digest differs",
        ):
            self._verify(output)

        output = self.root / "release-sums"
        self._assemble(output)
        (output / platform_distribution.RELEASE_SUMS).write_text(
            "0" * 64 + "  " + platform_distribution.ANDROID_AAR + "\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(
            platform_distribution.PlatformDistributionError,
            "SHA256SUMS",
        ):
            self._verify(output)

    def test_extra_input_symlink_and_wrong_tag_commit_fail_closed(self) -> None:
        extra = self.assets / "unexpected.bin"
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(
            platform_distribution.PlatformDistributionError,
            "input asset set differs",
        ):
            self._assemble(self.root / "release-extra")
        extra.unlink()

        aar = self.assets / platform_distribution.ANDROID_AAR
        aar.unlink()
        try:
            aar.symlink_to(self.assets / platform_distribution.ANDROID_MANIFEST)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(
            platform_distribution.PlatformDistributionError,
            "symlink",
        ):
            self._assemble(self.root / "release-link")

        aar.unlink()
        aar.write_bytes(self.aar_bytes)
        output = self.root / "release-tag"
        self._assemble(output)
        wrong = platform_distribution.SourceIdentity(
            commit="e" * 40,
            tree=self.source.tree,
            canonical_source_tree_sha256="f" * 64,
            source_date_epoch=self.source.source_date_epoch,
        )
        with (
            mock.patch.object(
                platform_distribution,
                "_source_identity",
                return_value=wrong,
            ),
            self.assertRaisesRegex(
                platform_distribution.PlatformDistributionError,
                "tag commit differs",
            ),
        ):
            platform_distribution.verify_distribution(
                self.repository,
                output,
                android_tools=self.android_tools,
            )

    def test_deep_validators_are_invoked_with_release_constraints(self) -> None:
        runtime_digest = lambda **kwargs: hashlib.sha256(
            kwargs["bundle"].read_bytes()
        ).hexdigest()
        output = self.root / "release-validator-calls"
        with (
            mock.patch.object(
                platform_distribution,
                "_source_identity",
                return_value=self.source,
            ),
            mock.patch.object(
                platform_distribution,
                "verify_runtime_bundle",
                side_effect=runtime_digest,
            ) as android_verify,
            mock.patch.object(
                platform_distribution,
                "verify_bundle_manifest",
                side_effect=self._verified_bundle_manifest,
            ) as bundle_verify,
            mock.patch.object(
                platform_distribution,
                "verify_proof_freshness",
            ) as freshness_verify,
            mock.patch.object(
                platform_distribution,
                "verify_c_package",
                side_effect=self._verified_manifest,
            ) as linux_verify,
            mock.patch.object(
                platform_distribution,
                "verify_windows_package",
                side_effect=self._verified_windows_manifest,
            ) as windows_verify,
        ):
            platform_distribution.assemble(
                self.repository,
                self.assets,
                output,
                android_tools=self.android_tools,
            )
        self.assertEqual(2, android_verify.call_count)
        self.assertEqual(2, bundle_verify.call_count)
        self.assertEqual(1, freshness_verify.call_count)
        self.assertEqual(4, linux_verify.call_count)
        self.assertEqual(2, windows_verify.call_count)
        for call in android_verify.call_args_list:
            self.assertEqual(35, call.kwargs["expected_device_sdk"])
            self.assertEqual(16_384, call.kwargs["expected_page_size"])
            self.assertTrue(call.kwargs["require_release_mode"])
            self.assertFalse(call.kwargs["allow_dirty_proof"])
        for call in linux_verify.call_args_list:
            self.assertEqual(self.source.commit, call.kwargs["expected_commit"])
            self.assertEqual(
                self.source.source_date_epoch,
                call.kwargs["expected_source_date_epoch"],
            )
        for call in windows_verify.call_args_list:
            self.assertEqual(self.source.commit, call.kwargs["expected_git_commit"])
            self.assertEqual(self.source.tree, call.kwargs["expected_git_tree"])

    def test_each_minimal_forged_platform_is_rejected_by_its_real_validator(self) -> None:
        runtime_digest = lambda **kwargs: hashlib.sha256(
            kwargs["bundle"].read_bytes()
        ).hexdigest()
        common_android_mocks = lambda: (
            mock.patch.object(
                platform_distribution,
                "verify_runtime_bundle",
                side_effect=runtime_digest,
            ),
            mock.patch.object(
                platform_distribution,
                "verify_bundle_manifest",
                side_effect=self._verified_bundle_manifest,
            ),
            mock.patch.object(platform_distribution, "verify_proof_freshness"),
        )

        with (
            mock.patch.object(platform_distribution, "_source_identity", return_value=self.source),
            mock.patch.object(platform_distribution, "verify_c_package", side_effect=self._verified_manifest),
            mock.patch.object(platform_distribution, "verify_windows_package", side_effect=self._verified_windows_manifest),
            self.assertRaisesRegex(
                platform_distribution.PlatformDistributionError,
                "Android runtime evidence bundle verification failed",
            ),
        ):
            platform_distribution.assemble(
                self.repository,
                self.assets,
                self.root / "release-forged-android",
                android_tools=self.android_tools,
            )

        android_mocks = common_android_mocks()
        with (
            mock.patch.object(platform_distribution, "_source_identity", return_value=self.source),
            android_mocks[0],
            android_mocks[1],
            android_mocks[2],
            mock.patch.object(platform_distribution, "verify_windows_package", side_effect=self._verified_windows_manifest),
            self.assertRaisesRegex(
                platform_distribution.PlatformDistributionError,
                "Linux x86_64-unknown-linux-gnu package verification failed",
            ),
        ):
            platform_distribution.assemble(
                self.repository,
                self.assets,
                self.root / "release-forged-linux",
                android_tools=self.android_tools,
            )

        android_mocks = common_android_mocks()
        with (
            mock.patch.object(platform_distribution, "_source_identity", return_value=self.source),
            android_mocks[0],
            android_mocks[1],
            android_mocks[2],
            mock.patch.object(platform_distribution, "verify_c_package", side_effect=self._verified_manifest),
            self.assertRaisesRegex(
                platform_distribution.PlatformDistributionError,
                "Windows package verification failed",
            ),
        ):
            platform_distribution.assemble(
                self.repository,
                self.assets,
                self.root / "release-forged-windows",
                android_tools=self.android_tools,
            )


if __name__ == "__main__":
    unittest.main()
