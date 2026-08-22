from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import android_device_proof
import platform_distribution
import platform_distribution_contract
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
            llvm_nm=self.root / "llvm-nm",
            llvm_readelf=self.root / "llvm-readelf",
            apksigner=self.root / "apksigner",
            zipalign=self.root / "zipalign",
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

    def _android_manifest(self) -> tuple[dict, bytes]:
        manifest = {
            "schema_version": platform_distribution.ANDROID_MANIFEST_SCHEMA_VERSION,
            "kind": "qperiapt.android_aar_manifest",
            "package": platform_distribution.ANDROID_AAR,
            "version": platform_distribution.PRODUCT_VERSION,
            "generated_at": "2023-11-14T22:13:20Z",
            "source_date_epoch": self.source.source_date_epoch,
            "toolchain": {
                "cargo": platform_distribution.ANDROID_EXPECTED_CARGO_VERSION,
                "rustc": platform_distribution.ANDROID_EXPECTED_RUSTC_VERSION,
            },
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
            "schema": android_device_proof.PROOF_SCHEMA_VERSION,
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
        for key in android_device_proof.EMULATOR_BUNDLE_FILE_PATHS:
            payloads[key] = f"fixture {key}\n".encode("ascii")
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
        self.android_proof = proof
        self.android_bundle_manifest = bundle_manifest
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

    @staticmethod
    def _verified_manifest(package_root: pathlib.Path, *_args, **_kwargs) -> dict:
        return json.loads((package_root / "MANIFEST.json").read_text(encoding="utf-8"))

    def _verified_current_android_bundle(self, **kwargs):
        bundle = kwargs["bundle"]
        return hashlib.sha256(bundle.read_bytes()).hexdigest()

    def _verified_current_bundle_manifest(
        self,
        bundle_root: pathlib.Path,
        manifest: dict,
        *,
        archive_mtime: int,
    ):
        self.assertEqual(self.android_bundle_manifest, manifest)
        self.assertEqual(self.source.source_date_epoch, archive_mtime)
        selected = {
            key: bundle_root / relative
            for key, relative in android_device_proof.BUNDLE_FILE_PATHS.items()
        }
        return selected, self.android_proof

    def _deep_validator_mocks(self):
        return (
            mock.patch.object(
                platform_distribution,
                "verify_runtime_bundle",
                side_effect=self._verified_current_android_bundle,
            ),
            mock.patch.object(
                platform_distribution,
                "verify_bundle_manifest",
                side_effect=self._verified_current_bundle_manifest,
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
        ):
            return platform_distribution.verify_distribution(
                self.repository,
                output,
                android_tools=self.android_tools,
            )

    def _transaction_inputs(self, name: str) -> pathlib.Path:
        candidate = pathlib.Path(
            tempfile.mkdtemp(prefix=f"{name}-", dir=self.root)
        )
        for asset_name in platform_distribution.PLATFORM_CANDIDATE_ASSETS:
            (candidate / asset_name).write_bytes(
                (self.assets / asset_name).read_bytes()
            )
        (candidate / platform_distribution_contract.CANDIDATE_SUMS).write_bytes(
            b"verified candidate sums fixture\n"
        )
        (
            candidate / platform_distribution_contract.SOURCE_SECURITY_GATE
        ).write_bytes(b"verified source security gate fixture\n")
        return candidate

    def _assemble_candidate_transaction(
        self,
        name: str,
    ) -> tuple[pathlib.Path, str, pathlib.Path, dict[str, object]]:
        candidate = self._transaction_inputs(f"candidate-{name}")
        validators = self._deep_validator_mocks()
        release_root = self.root / "release-candidates"
        with (
            mock.patch.object(
                platform_distribution,
                "PLATFORM_RELEASE_CANDIDATE_ROOT",
                release_root,
            ),
            mock.patch.object(
                platform_distribution,
                "_source_identity",
                return_value=self.source,
            ),
            validators[0],
            validators[1],
            validators[2],
            validators[3],
        ):
            return platform_distribution.assemble_candidate_transaction(
                self.repository,
                candidate,
                self.assets / platform_distribution.ANDROID_RUNTIME_BUNDLE,
                f"transaction.{name}",
                android_tools=self.android_tools,
            )

    def test_assemble_verify_and_rebuild_are_byte_deterministic(self) -> None:
        first_output = self.root / "release-first"
        first = self._assemble(first_output)
        self.assertEqual(5, len(first["assets"]))
        self.assertEqual("r1", first["distribution_revision"])
        self.assertEqual(
            "abi2-platforms-v0.1.2", first["release_tag"]
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

    def test_candidate_transaction_commits_exact_manifest_last_receipt(self) -> None:
        receipt_path, digest, release, receipt = (
            self._assemble_candidate_transaction("positive")
        )
        self.assertEqual(
            digest,
            hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            {
                platform_distribution.PLATFORM_RELEASE_DIRECTORY_NAME,
                platform_distribution.PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
            },
            {path.name for path in receipt_path.parent.iterdir()},
        )
        self.assertEqual(
            set(platform_distribution.PUBLIC_ASSET_NAMES),
            {path.name for path in release.iterdir()},
        )
        self.assertEqual(
            list(platform_distribution.PUBLIC_ASSET_NAMES),
            [asset["name"] for asset in receipt["assets"]],
        )
        self.assertEqual(
            dict(platform_distribution.PUBLIC_ASSET_CONTENT_TYPES),
            {
                asset["name"]: asset["content_type"]
                for asset in receipt["assets"]
            },
        )
        platform_distribution_contract.validate_release_candidate_receipt(
            receipt
        )
        with mock.patch.object(
            platform_distribution,
            "PLATFORM_RELEASE_CANDIDATE_ROOT",
            receipt_path.parent.parent,
        ):
            self.assertEqual(
                receipt,
                platform_distribution.load_release_candidate_receipt(
                    receipt_path
                ),
            )

    def test_candidate_transaction_is_no_replace_and_uses_bounded_names(self) -> None:
        receipt_path, _digest, _release, _receipt = (
            self._assemble_candidate_transaction("exclusive")
        )
        original = receipt_path.read_bytes()
        with self.assertRaisesRegex(
            platform_distribution.PlatformDistributionError,
            "already exists",
        ):
            self._assemble_candidate_transaction("exclusive")
        self.assertEqual(original, receipt_path.read_bytes())

        candidate = self._transaction_inputs("candidate-invalid-name")
        with self.assertRaisesRegex(
            platform_distribution.PlatformDistributionError,
            "transaction.<bounded-id>",
        ):
            platform_distribution.assemble_candidate_transaction(
                self.repository,
                candidate,
                self.assets / platform_distribution.ANDROID_RUNTIME_BUNDLE,
                "release-candidate",
                android_tools=self.android_tools,
            )

    def test_candidate_receipt_loader_rejects_asset_and_inventory_drift(self) -> None:
        receipt_path, _digest, release, _receipt = (
            self._assemble_candidate_transaction("loader-drift")
        )
        with mock.patch.object(
            platform_distribution,
            "PLATFORM_RELEASE_CANDIDATE_ROOT",
            receipt_path.parent.parent,
        ):
            (release / platform_distribution.ANDROID_AAR).write_bytes(b"drift")
            os.chmod(release / platform_distribution.ANDROID_AAR, 0o644)
            with self.assertRaisesRegex(
                platform_distribution.PlatformDistributionError,
                "platform release candidate",
            ):
                platform_distribution.load_release_candidate_receipt(receipt_path)

        receipt_path, _digest, release, _receipt = (
            self._assemble_candidate_transaction("inventory-drift")
        )
        (release / "unexpected").write_bytes(b"unexpected")
        os.chmod(release / "unexpected", 0o644)
        with mock.patch.object(
            platform_distribution,
            "PLATFORM_RELEASE_CANDIDATE_ROOT",
            receipt_path.parent.parent,
        ):
            with self.assertRaisesRegex(
                platform_distribution.PlatformDistributionError,
                "platform release candidate",
            ):
                platform_distribution.load_release_candidate_receipt(receipt_path)

    def test_candidate_transaction_detects_precommit_asset_race(self) -> None:
        candidate = self._transaction_inputs("candidate-race")
        release_root = self.root / "release-candidates-race"
        real_snapshot = platform_distribution._snapshot_release_assets
        calls = 0

        def snapshot_and_mutate(*args, **kwargs):
            nonlocal calls
            records = real_snapshot(*args, **kwargs)
            calls += 1
            if calls == 1:
                release = args[0]
                path = release.path / platform_distribution.ANDROID_AAR
                path.write_bytes(b"raced")
                os.chmod(path, 0o644)
            return records

        validators = self._deep_validator_mocks()
        with (
            mock.patch.object(
                platform_distribution,
                "PLATFORM_RELEASE_CANDIDATE_ROOT",
                release_root,
            ),
            mock.patch.object(
                platform_distribution,
                "_source_identity",
                return_value=self.source,
            ),
            mock.patch.object(
                platform_distribution,
                "_snapshot_release_assets",
                side_effect=snapshot_and_mutate,
            ),
            validators[0],
            validators[1],
            validators[2],
            validators[3],
            self.assertRaisesRegex(
                platform_distribution.PlatformDistributionError,
                "Android AAR manifest digest differs|changed before receipt commit",
            ),
        ):
            platform_distribution.assemble_candidate_transaction(
                self.repository,
                candidate,
                self.assets / platform_distribution.ANDROID_RUNTIME_BUNDLE,
                "transaction.race",
                android_tools=self.android_tools,
            )
        transaction = release_root / "transaction.race"
        self.assertTrue(transaction.is_dir())
        self.assertFalse(
            (transaction / platform_distribution.PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME).exists()
        )

    def test_candidate_transaction_reverifies_after_assemble_returns(self) -> None:
        candidate = self._transaction_inputs("candidate-post-verify-race")
        release_root = self.root / "release-candidates-post-verify-race"
        real_assemble = platform_distribution.assemble

        def assemble_and_corrupt(*args, **kwargs):
            manifest = real_assemble(*args, **kwargs)
            release = pathlib.Path(args[2])
            sums = release / platform_distribution.RELEASE_SUMS
            sums.write_bytes(b"post-verify corruption\n")
            os.chmod(sums, 0o644)
            return manifest

        validators = self._deep_validator_mocks()
        with (
            mock.patch.object(
                platform_distribution,
                "PLATFORM_RELEASE_CANDIDATE_ROOT",
                release_root,
            ),
            mock.patch.object(
                platform_distribution,
                "_source_identity",
                return_value=self.source,
            ),
            mock.patch.object(
                platform_distribution,
                "assemble",
                side_effect=assemble_and_corrupt,
            ),
            validators[0],
            validators[1],
            validators[2],
            validators[3],
            self.assertRaisesRegex(
                platform_distribution.PlatformDistributionError,
                "SHA256SUMS",
            ),
        ):
            platform_distribution.assemble_candidate_transaction(
                self.repository,
                candidate,
                self.assets / platform_distribution.ANDROID_RUNTIME_BUNDLE,
                "transaction.post-verify-race",
                android_tools=self.android_tools,
            )
        transaction = release_root / "transaction.post-verify-race"
        self.assertTrue((transaction / "release").is_dir())
        self.assertFalse(
            (transaction / platform_distribution.PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME).exists()
        )

    def test_current_contract_is_stable_identity_without_published_hashes(self) -> None:
        self.assertEqual("0.1.2", platform_distribution_contract.PRODUCT_VERSION)
        self.assertEqual("r1", platform_distribution_contract.DISTRIBUTION_REVISION)
        self.assertEqual(
            "abi2-platforms-v0.1.2",
            platform_distribution_contract.RELEASE_TAG,
        )
        self.assertEqual(
            platform_distribution_contract.PLATFORM_INPUT_ASSETS,
            platform_distribution.INPUT_ASSETS,
        )
        contract_source = (
            self.repository / "artifact/platform_distribution_contract.py"
        ).read_text(encoding="utf-8")
        producer_source = (
            self.repository / "artifact/platform_distribution.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("0.1.0-alpha.2", contract_source)
        self.assertNotRegex(contract_source, r"[0-9a-f]{64}")
        self.assertNotIn("from platform_release_contract import", producer_source)
        self.assertNotIn("verify_published_runtime_bundle_v1", producer_source)

    def test_current_bundle_and_proof_schemas_are_bound_into_dynamic_hashes(self) -> None:
        output = self.root / "release-current-android"
        manifest = self._assemble(output)
        self.assertEqual(
            android_device_proof.BUNDLE_SCHEMA_VERSION,
            self.android_bundle_manifest["schema_version"],
        )
        self.assertEqual(
            android_device_proof.PROOF_SCHEMA_VERSION,
            self.android_proof["schema"],
        )
        runtime = next(
            asset
            for asset in manifest["assets"]
            if asset["name"] == platform_distribution.ANDROID_RUNTIME_BUNDLE
        )
        self.assertEqual(
            hashlib.sha256(
                platform_distribution.canonical_json(self.android_bundle_manifest)
            ).hexdigest(),
            runtime["bundle_manifest_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(
                platform_distribution.canonical_json(self.android_proof)
            ).hexdigest(),
            runtime["proof_sha256"],
        )

    def test_noncurrent_bundle_or_proof_schema_fails_closed(self) -> None:
        self.android_proof["schema"] = android_device_proof.PROOF_SCHEMA_VERSION - 1
        with self.assertRaisesRegex(
            platform_distribution.PlatformDistributionError,
            "current proof schema",
        ):
            self._assemble(self.root / "release-old-proof")

        self.android_proof["schema"] = android_device_proof.PROOF_SCHEMA_VERSION
        self.android_bundle_manifest["schema_version"] = (
            android_device_proof.BUNDLE_SCHEMA_VERSION - 1
        )
        stage = self.root / "android-bundle-stage"
        self._write_json(
            stage / android_device_proof.BUNDLE_MANIFEST_PATH,
            self.android_bundle_manifest,
        )
        bundle = self.assets / platform_distribution.ANDROID_RUNTIME_BUNDLE
        bundle.unlink()
        create_zip(
            stage,
            bundle,
            root_name=android_device_proof.BUNDLE_ROOT_NAME,
            mtime=self.source.source_date_epoch,
        )
        with self.assertRaisesRegex(
            platform_distribution.PlatformDistributionError,
            "current bundle schema",
        ):
            self._assemble(self.root / "release-old-bundle")

    def test_cli_requires_current_android_verification_tools(self) -> None:
        parser = platform_distribution.build_parser()
        tools = [
            "--android-llvm-nm",
            "/tools/llvm-nm",
            "--android-llvm-readelf",
            "/tools/llvm-readelf",
            "--android-apksigner",
            "/tools/apksigner",
            "--android-zipalign",
            "/tools/zipalign",
        ]
        assembled = parser.parse_args(
            [
                "assemble",
                "--root",
                "/repository",
                "--candidate-dir",
                "/candidate",
                "--runtime-bundle",
                "/runtime.zip",
                "--transaction-name",
                "transaction.release-1",
                *tools,
            ]
        )
        verified = parser.parse_args(
            [
                "verify",
                "--root",
                "/repository",
                "--release-dir",
                "/release",
                *tools,
            ]
        )
        self.assertEqual("assemble", assembled.command)
        self.assertEqual("verify", verified.command)
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            parser.parse_args(
                ["verify", "--root", "/repository", "--release-dir", "/release"]
            )

    def test_assembly_cli_marker_uses_only_repository_relative_paths(self) -> None:
        receipt = {
            "assets": [{}] * len(platform_distribution.PUBLIC_ASSET_NAMES),
            "source": {"git_commit": self.source.commit},
        }
        receipt_path = (
            self.repository
            / "target/abi2-platform-release-candidates/transaction.marker"
            / platform_distribution.PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME
        )
        release_path = receipt_path.parent / platform_distribution.PLATFORM_RELEASE_DIRECTORY_NAME
        arguments = mock.Mock(
            command="assemble",
            root=self.repository,
            candidate_dir=self.root / "candidate",
            runtime_bundle=self.root / "runtime.zip",
            transaction_name="transaction.marker",
            android_llvm_nm=self.android_tools.llvm_nm,
            android_llvm_readelf=self.android_tools.llvm_readelf,
            android_apksigner=self.android_tools.apksigner,
            android_zipalign=self.android_tools.zipalign,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stdout = io.StringIO()
        with (
            mock.patch.object(platform_distribution, "build_parser", return_value=parser),
            mock.patch.object(
                platform_distribution,
                "assemble_candidate_transaction",
                return_value=(receipt_path, "f" * 64, release_path, receipt),
            ),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(0, platform_distribution.main(["assemble"]))
        marker = stdout.getvalue()
        self.assertIn(
            "receipt=target/abi2-platform-release-candidates/transaction.marker/",
            marker,
        )
        self.assertIn(
            "release_dir=target/abi2-platform-release-candidates/transaction.marker/release",
            marker,
        )
        self.assertNotIn(str(self.repository), marker)

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
                side_effect=self._verified_current_android_bundle,
            ) as android_verify,
            mock.patch.object(
                platform_distribution,
                "verify_bundle_manifest",
                side_effect=self._verified_current_bundle_manifest,
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
        for call in android_verify.call_args_list:
            self.assertEqual(
                hashlib.sha256(call.kwargs["bundle"].read_bytes()).hexdigest(),
                call.kwargs["expected_bundle_sha256"],
            )
            self.assertEqual(self.repository, call.kwargs["root"])
            self.assertEqual(self.android_tools.llvm_nm, call.kwargs["llvm_nm"])
            self.assertEqual(
                self.android_tools.llvm_readelf,
                call.kwargs["llvm_readelf"],
            )
            self.assertEqual(self.android_tools.apksigner, call.kwargs["apksigner"])
            self.assertEqual(self.android_tools.zipalign, call.kwargs["zipalign"])
            self.assertEqual("emulator", call.kwargs["expected_device_kind"])
            self.assertEqual("arm64-v8a", call.kwargs["expected_device_abi"])
            self.assertEqual(16_384, call.kwargs["expected_page_size"])
            self.assertEqual(35, call.kwargs["expected_device_sdk"])
            self.assertTrue(call.kwargs["require_release_mode"])
            self.assertFalse(call.kwargs["allow_dirty_proof"])
        for call in linux_verify.call_args_list:
            self.assertEqual(self.source.commit, call.kwargs["expected_commit"])
            self.assertEqual(
                self.source.source_date_epoch,
                call.kwargs["expected_source_date_epoch"],
            )
    def test_each_minimal_forged_platform_is_rejected_by_its_real_validator(self) -> None:
        def common_android_mocks():
            return (
                mock.patch.object(
                    platform_distribution,
                    "verify_runtime_bundle",
                    side_effect=self._verified_current_android_bundle,
                ),
                mock.patch.object(
                    platform_distribution,
                    "verify_bundle_manifest",
                    side_effect=self._verified_current_bundle_manifest,
                ),
                mock.patch.object(platform_distribution, "verify_proof_freshness"),
            )

        with (
            mock.patch.object(platform_distribution, "_source_identity", return_value=self.source),
            mock.patch.object(platform_distribution, "verify_c_package", side_effect=self._verified_manifest),
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

if __name__ == "__main__":
    unittest.main()
