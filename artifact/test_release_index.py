from __future__ import annotations

import argparse
import copy
import gzip
import io
import json
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import android_elf
import apple_distribution
import c_package_manifest
import release_index


PRODUCER_MANIFEST_CONTRACTS = {
    "c-abi": (2, None),
    "swift": (5, "qperiapt.swift_xcframework_manifest"),
    "android": (4, "qperiapt.android_aar_manifest"),
}


class ReleaseIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository_root = pathlib.Path(__file__).resolve().parent.parent
        cls.contract_source = cls.repository_root / pathlib.Path(
            release_index.CONTRACT_RELATIVE_PATH
        )

    def _root(self, temporary: str) -> pathlib.Path:
        # macOS exposes the temporary root through both /var and /private/var;
        # use the canonical spelling so path-containment tests compare like
        # with like without weakening the production no-symlink checks.
        root = pathlib.Path(temporary).resolve()
        contract = root / pathlib.Path(release_index.CONTRACT_RELATIVE_PATH)
        contract.parent.mkdir(parents=True)
        shutil.copy2(self.contract_source, contract)
        (root / "FIXTURE_SOURCE.txt").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Q-Periapt Test",
                "-c",
                "user.email=q-periapt-test@example.invalid",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
            cwd=root,
            check=True,
        )
        return root

    def _manifest(
        self,
        trust: release_index.AbiTrustRoot,
        face: str,
        package_sha256: str,
        commit: str = "a" * 40,
    ) -> dict:
        common_abi = {
            "major": release_index.ABI_MAJOR,
            "contract_sha256": trust.contract_sha256,
            "exports_sha256": trust.exports_sha256,
            "export_count": release_index.EXPORT_COUNT,
            "contract_path": release_index.CONTRACT_RELATIVE_PATH.as_posix(),
        }
        if face == "c-abi":
            host = "aarch64-apple-darwin"
            platform = "macos"
            identity = trust.platforms[platform]
            return {
                "schema_version": 2,
                "package": f"{trust.archive_prefix}-{trust.version}-{host}",
                "version": trust.version,
                "host": host,
                "generated_at": "1970-01-01T00:00:00Z",
                "source_date_epoch": 0,
                "git_commit": commit,
                "git_dirty": False,
                "diagnostic_only": False,
                "rustc": release_index.EXPECTED_RUSTC_VERSION,
                "cargo": release_index.EXPECTED_CARGO_VERSION,
                "platform_compatibility": {"target": host},
                "abi": {
                    **common_abi,
                    "embedded_contract_path": "share/q-periapt/abi/q-periapt-c-abi-v2.json",
                    "platform": platform,
                    "runtime_identity": identity,
                    "shared_filename": identity["shared_filename"],
                    "static_filename": identity["static_filename"],
                },
                "source_inputs_sha256": "b" * 64,
                "files": [],
            }
        if face == "swift":
            return {
                "schema_version": 5,
                "kind": "qperiapt.swift_xcframework_manifest",
                "package": "q-periapt-swift",
                "version": trust.version,
                "release_identity": {
                    "product_version": trust.version,
                    "revision": "r1",
                    "tag": f"v{trust.version}-r1",
                    "url": (
                        "https://github.com/billlza/q-periapt/releases/tag/"
                        f"v{trust.version}-r1"
                    ),
                },
                "type": "swiftpm-binaryTarget-xcframework",
                "git_commit": commit,
                "git_dirty": False,
                "toolchain": {
                    "cargo": release_index.EXPECTED_CARGO_VERSION,
                    "rust_host": release_index.EXPECTED_SWIFT_RUST_HOST,
                    "rustc": release_index.EXPECTED_RUSTC_VERSION,
                    "swift": release_index.EXPECTED_SWIFT_VERSION,
                    "xcode": list(release_index.EXPECTED_XCODE_VERSION),
                },
                "targets": list(release_index.SWIFT_TARGETS),
                "abi": {
                    **common_abi,
                    "platform": "apple-xcframework",
                    "runtime_identity": {
                        "container": "CQPeriapt.xcframework",
                        "linkage": "static",
                        "slice_library": "libq_periapt_ffi_abi2.a",
                        "targets": list(release_index.SWIFT_TARGETS),
                    },
                    "shared_filename": "CQPeriapt.xcframework",
                    "static_filename": "libq_periapt_ffi_abi2.a",
                },
                "artifacts": {
                    "xcframework_zip": {
                        "path": "CQPeriapt.xcframework.zip",
                        "sha256": package_sha256,
                        "swiftpm_checksum": package_sha256,
                    },
                    "xcframework_info_plist_sha256": "c" * 64,
                },
                "consumer_verification": {},
                "source_inputs": {},
                "build_path_hygiene": {},
                "public_release_boundary": {
                    "consumer_distribution_responsibilities": {
                        "ios": {
                            "requires_final_app_signing_and_provisioning": True,
                            "sdk_notarization_applicable": False,
                        },
                        "macos": {
                            "requires_final_app_notarization": True,
                            "requires_final_app_signing": True,
                        },
                    },
                    "contains_device_udid": False,
                    "contains_mobileprovision": False,
                    "contains_raw_device_proof": False,
                    "distribution_signed": False,
                    "notarization_applicability": "not_applicable_static_sdk_payload",
                    "notarized": False,
                    "requires_clean_tree_for_release": True,
                    "stapled": False,
                },
            }
        if face == "android":
            return {
                "schema_version": 4,
                "kind": "qperiapt.android_aar_manifest",
                "package": f"q-periapt-android-{trust.version}.aar",
                "version": trust.version,
                "generated_at": "1970-01-01T00:00:00Z",
                "source_date_epoch": 0,
                "git_commit": commit,
                "git_dirty": False,
                "diagnostic_only": False,
                "source_tree_sha256": "d" * 64,
                "package_only": True,
                "device_runtime_proof": False,
                "boundary": release_index.ANDROID_PACKAGE_BOUNDARY,
                "toolchain": {
                    "cargo": release_index.EXPECTED_CARGO_VERSION,
                    "rustc": release_index.EXPECTED_RUSTC_VERSION,
                },
                "third_party": {},
                "abi": {
                    **common_abi,
                    "platform": "android-aar",
                    "runtime_identity": {
                        "abis": list(release_index.ANDROID_ABIS),
                        "jni_library": "libqperiapt_jni_abi2.so",
                        "loader_order": [
                            "q_periapt_ffi_abi2",
                            "qperiapt_jni_abi2",
                        ],
                        "runtime_library": "libq_periapt_ffi_abi2.so",
                    },
                    "shared_filename": "libq_periapt_ffi_abi2.so",
                    "static_filename": "not-shipped-abi2",
                },
                "android": {
                    "abis": list(release_index.ANDROID_ABIS),
                    "build_tools": "36.0.0",
                    "min_sdk": 23,
                    "native_page_alignment": 16384,
                    "native_stripped": True,
                    "ndk": "29.0.14206865",
                    "platform": "android-35",
                    "sdk": "local-android-sdk",
                },
                "artifacts": {"aar_sha256": package_sha256},
            }
        raise AssertionError(f"unsupported fixture face: {face}")

    @staticmethod
    def _file_entry(path: pathlib.Path, release_root: pathlib.Path) -> dict:
        observed = release_index.digest_regular_file(path)
        return {
            "path": path.relative_to(release_root).as_posix(),
            "sha256": observed.sha256,
            "bytes": observed.size,
        }

    def _validate_manifest(
        self,
        root: pathlib.Path,
        face: str,
        manifest: dict,
    ) -> dict:
        trust = release_index.load_abi_trust_root(root)
        path = root / "target" / f"{face}-MANIFEST.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        release_index.write_json(path, manifest)
        return release_index.validate_package_manifest(
            path,
            manifest["git_commit"],
            trust.version,
            "diagnostic",
            face,
            trust,
        )

    def _fixture(self, root: pathlib.Path) -> tuple[pathlib.Path, dict]:
        trust = release_index.load_abi_trust_root(root)
        commit = release_index.git_commit(root)
        release_root = (
            root
            / "target/qperiapt-local-release/diagnostic"
            / trust.version
            / commit
        )
        release_root.mkdir(parents=True)
        package_paths = {
            "swift": release_root / "packages/swift/CQPeriapt.xcframework.zip",
            "android": release_root
            / f"packages/android/q-periapt-android-{trust.version}.aar",
        }
        for face, path in package_paths.items():
            path.parent.mkdir(parents=True)
            path.write_bytes(f"{face}-package".encode("ascii"))

        manifests = {
            "swift": self._manifest(
                trust,
                "swift",
                release_index.sha256_file(package_paths["swift"]),
                commit,
            ),
            "android": self._manifest(
                trust,
                "android",
                release_index.sha256_file(package_paths["android"]),
                commit,
            ),
        }
        manifest_paths: dict[str, pathlib.Path] = {}
        sums_paths: dict[str, pathlib.Path] = {}
        for face in ("swift", "android"):
            manifest_path = release_root / f"manifests/{face}/MANIFEST.json"
            sums_path = release_root / f"manifests/{face}/SHA256SUMS"
            manifest_path.parent.mkdir(parents=True)
            release_index.write_json(manifest_path, manifests[face])
            sums_path.write_text("fixture package checksums\n", encoding="utf-8")
            manifest_paths[face] = manifest_path
            sums_paths[face] = sums_path

        c_manifest = self._manifest(trust, "c-abi", "", commit)
        c_manifest_path = release_root / "manifests/c/MANIFEST.json"
        c_sums_path = release_root / "manifests/c/SHA256SUMS"
        c_manifest_path.parent.mkdir(parents=True)
        release_index.write_json(c_manifest_path, c_manifest)
        c_sums_path.write_text("fixture internal checksums\n", encoding="utf-8")
        c_archive = release_root / (
            f"packages/c/{trust.archive_prefix}-{trust.version}-aarch64-apple-darwin.tar.gz"
        )
        c_archive.parent.mkdir(parents=True)
        with tempfile.TemporaryDirectory() as archive_temporary:
            package_root = pathlib.Path(archive_temporary) / (
                f"{trust.archive_prefix}-{trust.version}-aarch64-apple-darwin"
            )
            package_root.mkdir()
            shutil.copy2(c_manifest_path, package_root / "MANIFEST.json")
            shutil.copy2(c_sums_path, package_root / "SHA256SUMS")
            with tarfile.open(c_archive, "w:gz") as bundle:
                bundle.add(package_root, arcname=package_root.name)
        manifests["c-abi"] = c_manifest
        manifest_paths["c-abi"] = c_manifest_path
        sums_paths["c-abi"] = c_sums_path
        package_paths["c-abi"] = c_archive

        artifacts = []
        for face in ("c-abi", "swift", "android"):
            artifact_contract = release_index.indexed_artifact_contract(
                face, manifests[face]
            )
            artifacts.append(
                {
                    "id": artifact_contract["id"],
                    "face": face,
                    "type": artifact_contract["type"],
                    "files": [self._file_entry(package_paths[face], release_root)],
                    "manifest": self._file_entry(manifest_paths[face], release_root),
                    "sha256s": self._file_entry(sums_paths[face], release_root),
                    "package_semantics": release_index.normalized_package_semantics(
                        manifests[face]
                    ),
                    "boundary": artifact_contract["boundary"],
                    "required_leaf_gate": artifact_contract["required_leaf_gate"],
                    "targets": artifact_contract["targets"],
                }
            )
        index = {
            "schema_version": release_index.SCHEMA_VERSION,
            "kind": release_index.KIND,
            "version": trust.version,
            "channel": "diagnostic",
            "diagnostic_only": True,
            "generated_at": "2026-07-12T00:00:00Z",
            "abi": {
                "major": release_index.ABI_MAJOR,
                "contract_path": release_index.CONTRACT_RELATIVE_PATH.as_posix(),
                "contract_sha256": trust.contract_sha256,
                "exports_sha256": trust.exports_sha256,
                "export_count": release_index.EXPORT_COUNT,
            },
            "git": {"commit": commit, "source_tree_dirty": False},
            "release_boundary": {
                "public_release": False,
                "registry_uploaded": False,
                "raw_device_proofs_copied": False,
                "requires_clean_tree_for_release": True,
                "cryptographic_attestation": False,
                "leaf_gate_receipts_embedded": False,
                "local_artifact_store_trusted": True,
            },
            "artifacts": artifacts,
            "proof_summaries": {},
        }
        index_path = release_root / "index.json"
        release_index.write_json(index_path, index)
        release_index.write_release_sums(release_root)
        return index_path, index

    def _write_pointer(
        self, root: pathlib.Path, index_path: pathlib.Path, channel: str = "diagnostic"
    ) -> pathlib.Path:
        target = root / "target"
        release_base = target / "qperiapt-local-release"
        pointer_path = release_base / f"latest-{channel}.json"
        release_index.write_json(
            pointer_path,
            {
                "schema_version": release_index.SCHEMA_VERSION,
                "kind": release_index.POINTER_KIND,
                "version": index_path.parents[1].name,
                "channel": channel,
                "diagnostic_only": channel == "diagnostic",
                "index_path": index_path.relative_to(target).as_posix(),
                "index_sha256": release_index.sha256_file(index_path),
                "generated_at": "2026-07-12T00:00:00Z",
            },
        )
        return pointer_path

    def test_face_contracts_match_authoritative_producers(self) -> None:
        self.assertEqual(
            {
                face: (contract.schema_version, contract.kind)
                for face, contract in release_index.PACKAGE_MANIFEST_CONTRACTS.items()
            },
            PRODUCER_MANIFEST_CONTRACTS,
        )
        self.assertEqual(c_package_manifest.SCHEMA_VERSION, 2)
        self.assertEqual(android_elf.MANIFEST_SCHEMA_VERSION, 4)
        self.assertEqual(tuple(android_elf.REQUIRED_ABIS), release_index.ANDROID_ABIS)
        for expected in (
            c_package_manifest.EXPECTED_RUSTC_VERSION,
            android_elf.EXPECTED_RUSTC_VERSION,
            apple_distribution.EXPECTED_RUSTC_VERSION,
        ):
            self.assertEqual(expected, release_index.EXPECTED_RUSTC_VERSION)
        for expected in (
            c_package_manifest.EXPECTED_CARGO_VERSION,
            android_elf.EXPECTED_CARGO_VERSION,
            apple_distribution.EXPECTED_CARGO_VERSION,
        ):
            self.assertEqual(expected, release_index.EXPECTED_CARGO_VERSION)
        self.assertEqual(
            tuple(apple_distribution.EXPECTED_APPLE_TARGETS),
            release_index.SWIFT_TARGETS,
        )
        self.assertEqual(
            apple_distribution.EXPECTED_SWIFT_VERSION,
            release_index.EXPECTED_SWIFT_VERSION,
        )
        self.assertEqual(
            tuple(apple_distribution.EXPECTED_XCODE_VERSION),
            release_index.EXPECTED_XCODE_VERSION,
        )
        swift_producer = (
            self.repository_root / "artifact/swift-xcframework.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('"schema_version": 5', swift_producer)
        self.assertIn(
            '"kind": "qperiapt.swift_xcframework_manifest"', swift_producer
        )

    def test_each_face_accepts_only_its_exact_current_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            trust = release_index.load_abi_trust_root(root)
            for face, (expected_schema, _kind) in PRODUCER_MANIFEST_CONTRACTS.items():
                manifest = self._manifest(trust, face, "e" * 64)
                with self.subTest(face=face, schema=expected_schema):
                    self._validate_manifest(root, face, manifest)
                rejected = [
                    expected_schema - 1,
                    expected_schema + 1,
                    True,
                    str(expected_schema),
                    float(expected_schema),
                ]
                for schema in rejected:
                    forged = copy.deepcopy(manifest)
                    forged["schema_version"] = schema
                    with self.subTest(face=face, rejected_schema=repr(schema)):
                        with self.assertRaises(SystemExit):
                            self._validate_manifest(root, face, forged)

    def test_release_index_accepts_only_schema_three_as_an_exact_integer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, original = self._fixture(root)
            self.assertEqual(release_index.SCHEMA_VERSION, 3)
            release_index.verify_release_index(
                index_path, root, allow_diagnostic=True
            )
            for schema in (2, 4, True, "3", 3.0):
                forged = copy.deepcopy(original)
                forged["schema_version"] = schema
                release_index.write_json(index_path, forged)
                release_index.write_release_sums(index_path.parent)
                with self.subTest(schema=repr(schema)):
                    with self.assertRaisesRegex(SystemExit, "schema_version"):
                        release_index.verify_release_index(
                            index_path, root, allow_diagnostic=True
                        )

    def test_malformed_index_discriminators_fail_as_domain_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, original = self._fixture(root)
            malformed_channel = copy.deepcopy(original)
            malformed_channel["channel"] = []
            release_index.write_json(index_path, malformed_channel)
            release_index.write_release_sums(index_path.parent)
            with self.assertRaisesRegex(SystemExit, "channel is invalid"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )

            malformed_face = copy.deepcopy(original)
            malformed_face["artifacts"][0]["face"] = []
            release_index.write_json(index_path, malformed_face)
            release_index.write_release_sums(index_path.parent)
            with self.assertRaisesRegex(SystemExit, "unsupported artifact face"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )

    def test_face_envelopes_reject_cross_face_and_runtime_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            trust = release_index.load_abi_trust_root(root)
            c_manifest = self._manifest(trust, "c-abi", "e" * 64)
            swift_manifest = self._manifest(trust, "swift", "e" * 64)
            android_manifest = self._manifest(trust, "android", "e" * 64)
            cases = []

            forged = copy.deepcopy(c_manifest)
            forged["kind"] = release_index.SWIFT_MANIFEST_KIND
            cases.append(("c-abi", forged, "C kind"))
            forged = copy.deepcopy(c_manifest)
            forged["diagnostic_only"] = True
            cases.append(("c-abi", forged, "C diagnostic mismatch"))
            forged = copy.deepcopy(c_manifest)
            forged["host"] = "other-host"
            cases.append(("c-abi", forged, "C host/package mismatch"))
            forged = copy.deepcopy(c_manifest)
            forged["host"] = "x86_64-unknown-linux-gnu"
            forged["package"] = (
                f"{trust.archive_prefix}-{trust.version}-x86_64-unknown-linux-gnu"
            )
            forged["platform_compatibility"]["target"] = forged["host"]
            cases.append(("c-abi", forged, "C host/platform mismatch"))
            forged = copy.deepcopy(c_manifest)
            forged["platform_compatibility"]["target"] = "x86_64-apple-darwin"
            cases.append(("c-abi", forged, "C compatibility target mismatch"))
            forged = copy.deepcopy(c_manifest)
            forged["rustc"] = "rustc other"
            cases.append(("c-abi", forged, "C toolchain"))

            forged = copy.deepcopy(swift_manifest)
            del forged["kind"]
            cases.append(("swift", forged, "Swift missing kind"))
            forged = copy.deepcopy(swift_manifest)
            forged["kind"] = release_index.ANDROID_MANIFEST_KIND
            cases.append(("swift", forged, "Swift cross kind"))
            forged = copy.deepcopy(swift_manifest)
            forged["type"] = "aar"
            cases.append(("swift", forged, "Swift wrong type"))
            forged = copy.deepcopy(swift_manifest)
            forged["targets"] = "aarch64-apple-darwin"
            cases.append(("swift", forged, "Swift string targets"))
            forged = copy.deepcopy(swift_manifest)
            forged["targets"][1] = forged["targets"][0]
            cases.append(("swift", forged, "Swift duplicate targets"))
            forged = copy.deepcopy(swift_manifest)
            forged["toolchain"]["swift"] = "swift other"
            cases.append(("swift", forged, "Swift toolchain"))
            forged = copy.deepcopy(swift_manifest)
            forged["public_release_boundary"]["distribution_signed"] = True
            cases.append(("swift", forged, "Swift signed local package"))
            forged = copy.deepcopy(swift_manifest)
            forged["public_release_boundary"]["contains_raw_device_proof"] = True
            cases.append(("swift", forged, "Swift raw proof claim"))
            forged = copy.deepcopy(swift_manifest)
            forged["public_release_boundary"][
                "consumer_distribution_responsibilities"
            ]["ios"]["requires_final_app_signing_and_provisioning"] = False
            cases.append(("swift", forged, "Swift consumer responsibility"))

            forged = copy.deepcopy(android_manifest)
            forged["kind"] = release_index.SWIFT_MANIFEST_KIND
            cases.append(("android", forged, "Android cross kind"))
            for field, value in (
                ("package_only", False),
                ("package_only", 1),
                ("device_runtime_proof", True),
                ("device_runtime_proof", 0),
            ):
                forged = copy.deepcopy(android_manifest)
                forged[field] = value
                cases.append(("android", forged, f"Android {field}={value!r}"))
            forged = copy.deepcopy(android_manifest)
            forged["diagnostic_only"] = True
            cases.append(("android", forged, "Android diagnostic mismatch"))
            forged = copy.deepcopy(android_manifest)
            forged["boundary"] = "runtime proof included"
            cases.append(("android", forged, "Android boundary"))
            forged = copy.deepcopy(android_manifest)
            forged["toolchain"]["cargo"] = "cargo other"
            cases.append(("android", forged, "Android toolchain"))
            forged = copy.deepcopy(android_manifest)
            forged["android"]["abis"] = forged["android"]["abis"][:-1]
            cases.append(("android", forged, "Android incomplete ABIs"))

            for face, forged, label in cases:
                with self.subTest(label=label):
                    with self.assertRaises(SystemExit):
                        self._validate_manifest(root, face, forged)

    def test_dirty_manifests_are_diagnostic_only_and_never_release_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            trust = release_index.load_abi_trust_root(root)
            for face in PRODUCER_MANIFEST_CONTRACTS:
                manifest = self._manifest(trust, face, "e" * 64)
                manifest["git_dirty"] = True
                if face in {"c-abi", "android"}:
                    manifest["diagnostic_only"] = True
                path = root / "target" / f"dirty-{face}-MANIFEST.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                release_index.write_json(path, manifest)
                with self.subTest(face=face, channel="diagnostic"):
                    release_index.validate_package_manifest(
                        path,
                        manifest["git_commit"],
                        trust.version,
                        "diagnostic",
                        face,
                        trust,
                    )
                with self.subTest(face=face, channel="release"):
                    with self.assertRaisesRegex(SystemExit, "generated dirty"):
                        release_index.validate_package_manifest(
                            path,
                            manifest["git_commit"],
                            trust.version,
                            "release",
                            face,
                            trust,
                        )

    def test_indexed_artifact_metadata_is_derived_from_each_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, original = self._fixture(root)
            cases = (
                ("c-abi", "id", "c-abi/other-host"),
                (
                    "c-abi",
                    "boundary",
                    {
                        "package_only": True,
                        "host_archive_only": True,
                        "multi_target_release_pending": True,
                        "git_dirty": False,
                    },
                ),
                ("swift", "targets", []),
                ("swift", "required_leaf_gate", "fixture"),
                (
                    "swift",
                    "boundary",
                    {
                        "package_only": True,
                        "public_url_uploaded": True,
                        "contains_raw_device_proof": False,
                        "git_dirty": False,
                    },
                ),
                (
                    "android",
                    "boundary",
                    {
                        "package_only": False,
                        "device_runtime_proof": False,
                        "runtime_proof_is_separate": True,
                        "git_dirty": False,
                    },
                ),
            )
            for face, field, value in cases:
                forged = copy.deepcopy(original)
                artifact = next(item for item in forged["artifacts"] if item["face"] == face)
                artifact[field] = value
                release_index.write_json(index_path, forged)
                release_index.write_release_sums(index_path.parent)
                with self.subTest(face=face, field=field):
                    with self.assertRaises(SystemExit):
                        release_index.verify_release_index(
                            index_path, root, allow_diagnostic=True
                        )

            forged = copy.deepcopy(original)
            forged["release_boundary"]["public_release"] = True
            release_index.write_json(index_path, forged)
            release_index.write_release_sums(index_path.parent)
            with self.assertRaisesRegex(SystemExit, "release index boundary"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )

    def test_multiple_package_entries_fail_before_file_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, index = self._fixture(root)
            index["artifacts"][0]["files"].append(
                copy.deepcopy(index["artifacts"][0]["files"][0])
            )
            release_index.write_json(index_path, index)
            release_index.write_release_sums(index_path.parent)
            with mock.patch.object(
                release_index,
                "verify_index_file",
                side_effect=AssertionError("file verification must not start"),
            ), self.assertRaisesRegex(SystemExit, "exactly one package file"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )

    def test_swift_checksum_is_bound_after_outer_hashes_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, index = self._fixture(root)
            release_root = index_path.parent
            swift_artifact = next(
                item for item in index["artifacts"] if item["face"] == "swift"
            )
            manifest_path = release_root / swift_artifact["manifest"]["path"]
            forged = json.loads(manifest_path.read_text(encoding="utf-8"))
            forged["artifacts"]["xcframework_zip"]["swiftpm_checksum"] = "f" * 64
            release_index.write_json(manifest_path, forged)
            swift_artifact["manifest"] = self._file_entry(manifest_path, release_root)
            swift_artifact["package_semantics"] = (
                release_index.normalized_package_semantics(forged)
            )
            release_index.write_json(index_path, index)
            release_index.write_release_sums(release_root)
            with self.assertRaisesRegex(SystemExit, "SwiftPM checksum"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )

    def test_unsynchronized_package_replacement_is_rejected_for_every_face(self) -> None:
        # This is an aggregate hash-linkage test, not a leaf-package verifier.
        # Coordinated rewrites of a mutable local package and all of its local
        # metadata remain outside schema 3's explicitly recorded trust boundary.
        for face in PRODUCER_MANIFEST_CONTRACTS:
            with self.subTest(face=face), tempfile.TemporaryDirectory() as temporary:
                root = self._root(temporary)
                index_path, index = self._fixture(root)
                release_root = index_path.parent
                artifact = next(
                    item for item in index["artifacts"] if item["face"] == face
                )
                package_path = release_root / artifact["files"][0]["path"]
                package_path.write_bytes(f"replaced-{face}".encode("ascii"))
                artifact["files"][0] = self._file_entry(package_path, release_root)
                release_index.write_json(index_path, index)
                release_index.write_release_sums(release_root)
                with self.assertRaises(SystemExit):
                    release_index.verify_release_index(
                        index_path, root, allow_diagnostic=True
                    )

    def test_proof_summaries_reject_unknown_claim_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, index = self._fixture(root)
            index["proof_summaries"] = {
                "production_certification": {
                    "kind": "production_certification",
                    "sha256": "e" * 64,
                    "generated_at": "2026-07-12T00:00:00Z",
                    "source_tree_dirty": False,
                    "copied_raw_proof": False,
                    "diagnostic_only": False,
                    "certified": True,
                }
            }
            release_index.write_json(index_path, index)
            release_index.write_release_sums(index_path.parent)
            with self.assertRaisesRegex(SystemExit, "unsupported proof summary"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )

    def test_proof_summary_fields_and_hash_use_one_file_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proof_path = pathlib.Path(temporary).resolve() / "proof.json"

            def android_proof(model: str) -> dict:
                return {
                    "git_commit": "a" * 40,
                    "generated_at": "2026-07-12T00:00:00Z",
                    "source_tree_dirty": False,
                    "run_id": "a" * 32,
                    "device": {
                        "kind": "physical",
                        "model": model,
                        "sdk": 35,
                        "abi": "arm64-v8a",
                        "serial_sha256_prefix": "b" * 12,
                        "raw_serial_recorded": False,
                    },
                    "result": {
                        "status": "pass",
                        "test_count": 1,
                        "passed_tests": ["fixture"],
                    },
                }

            release_index.write_json(proof_path, android_proof("FIRST"))
            expected_sha256 = release_index.sha256_file(proof_path)
            original_loader = release_index.load_json_object_snapshot

            def replace_after_snapshot(*args: object, **kwargs: object):
                snapshot = original_loader(*args, **kwargs)
                release_index.write_json(proof_path, android_proof("SECOND"))
                return snapshot

            with mock.patch.object(
                release_index,
                "load_json_object_snapshot",
                side_effect=replace_after_snapshot,
            ), mock.patch.object(
                release_index,
                "sha256_file",
                side_effect=AssertionError("proof_summary must not reopen the proof"),
            ):
                summary = release_index.proof_summary(
                    proof_path, "android_runtime"
                )
            self.assertEqual(summary["device"]["model"], "FIRST")
            self.assertEqual(summary["sha256"], expected_sha256)

            snapshot = original_loader(
                proof_path,
                label="Android proof fixture",
            )
            release_index.proof_summary_snapshot(
                snapshot,
                "android_runtime",
                expected_commit="a" * 40,
            )
            with self.assertRaisesRegex(SystemExit, "commit differs"):
                release_index.proof_summary_snapshot(
                    snapshot,
                    "android_runtime",
                    expected_commit="b" * 40,
                )

    def test_index_verification_binds_live_worktree_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, _ = self._fixture(root)
            release_index.verify_release_index(
                index_path, root, allow_diagnostic=True
            )
            (root / "FIXTURE_SOURCE.txt").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "source_tree_dirty differs"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )

    def test_source_bound_index_accepts_only_an_evidence_only_successor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, _ = self._fixture(root)
            release_index.verify_release_index(
                index_path,
                root,
                allow_diagnostic=True,
            )

            results_path = root / "artifact/results.json"
            results_path.parent.mkdir(parents=True)
            results_path.write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "add", "artifact/results.json"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Q-Periapt Test",
                    "-c",
                    "user.email=q-periapt-test@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "evidence successor",
                ],
                cwd=root,
                check=True,
            )
            release_index.verify_release_index(
                index_path,
                root,
                allow_diagnostic=True,
            )

            (root / "FIXTURE_SOURCE.txt").write_text("changed\n", encoding="utf-8")
            subprocess.run(["git", "add", "FIXTURE_SOURCE.txt"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Q-Periapt Test",
                    "-c",
                    "user.email=q-periapt-test@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "source successor",
                ],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(SystemExit, "canonical source inputs"):
                release_index.verify_release_index(
                    index_path,
                    root,
                    allow_diagnostic=True,
                )

    def test_timestamps_reject_bool_and_invalid_unicode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            trust = release_index.load_abi_trust_root(root)
            manifest = self._manifest(trust, "android", "e" * 64)
            manifest["source_date_epoch"] = True
            with self.assertRaisesRegex(SystemExit, "source_date_epoch"):
                self._validate_manifest(root, "android", manifest)
            index_path, index = self._fixture(root)
            index["generated_at"] = True
            release_index.write_json(index_path, index)
            release_index.write_release_sums(index_path.parent)
            with self.assertRaisesRegex(SystemExit, "generated_at"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )
        with self.assertRaisesRegex(SystemExit, "valid Unicode scalar text"):
            release_index.require_utc_timestamp("\ud800", "fixture timestamp")

    def test_tar_metadata_rejects_empty_member_paths_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "fixture.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                entry = tarfile.TarInfo(".")
                entry.type = tarfile.DIRTYPE
                bundle.addfile(entry)
            with self.assertRaisesRegex(SystemExit, "unsafe empty C archive path"):
                release_index.tar_metadata_bytes(archive, "/MANIFEST.json")

    def test_tar_metadata_rejects_noncanonical_path_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "fixture.tar.gz"
            payload = b"{}\n"
            with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as bundle:
                for name in ("fixture/MANIFEST.json", "fixture//MANIFEST.json"):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(payload)
                    bundle.addfile(entry, io.BytesIO(payload))
            with self.assertRaisesRegex(SystemExit, "non-canonical C archive path"):
                release_index.tar_metadata_bytes(archive, "/MANIFEST.json")

    def test_tar_metadata_requires_the_exact_top_level_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "fixture.tar.gz"
            payload = b"{}\n"
            with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as bundle:
                entry = tarfile.TarInfo("fixture/nested/MANIFEST.json")
                entry.size = len(payload)
                bundle.addfile(entry, io.BytesIO(payload))
            with self.assertRaisesRegex(SystemExit, "exactly one /MANIFEST.json"):
                release_index.tar_metadata_bytes(archive, "/MANIFEST.json")

    def test_tar_stream_bounds_include_pax_headers_and_compressed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "fixture.tar.gz"
            payload = b"x" * 2048
            with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as bundle:
                entry = tarfile.TarInfo(f"fixture/{'a' * 180}")
                entry.size = len(payload)
                bundle.addfile(entry, io.BytesIO(payload))

            with mock.patch.object(
                release_index, "MAX_TAR_UNCOMPRESSED_BYTES", 1024
            ), self.assertRaisesRegex(SystemExit, "decompressed stream"):
                release_index.tar_metadata_bytes(archive, "/MANIFEST.json")

            with mock.patch.object(
                release_index,
                "MAX_TAR_ARCHIVE_BYTES",
                archive.stat().st_size - 1,
            ), self.assertRaisesRegex(SystemExit, "C archive exceeds"):
                release_index.tar_metadata_bytes(archive, "/MANIFEST.json")

    def test_tar_metadata_rejects_truncated_or_concatenated_gzip_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "fixture.tar.gz"
            payload = b"{}\n"
            with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as bundle:
                entry = tarfile.TarInfo("fixture/MANIFEST.json")
                entry.size = len(payload)
                bundle.addfile(entry, io.BytesIO(payload))
            original = archive.read_bytes()
            self.assertEqual(
                release_index.tar_metadata_bytes(archive, "/MANIFEST.json"),
                payload,
            )

            for removed in (1, 8, 20):
                archive.write_bytes(original[:-removed])
                with self.subTest(removed=removed), self.assertRaisesRegex(
                    SystemExit, "truncated|cannot inspect"
                ):
                    release_index.tar_metadata_bytes(archive, "/MANIFEST.json")

            corrupt_crc = bytearray(original)
            corrupt_crc[-8] ^= 1
            archive.write_bytes(corrupt_crc)
            with self.assertRaisesRegex(SystemExit, "cannot inspect"):
                release_index.tar_metadata_bytes(archive, "/MANIFEST.json")

            corrupt_size = bytearray(original)
            corrupt_size[-4] ^= 1
            archive.write_bytes(corrupt_size)
            with self.assertRaisesRegex(SystemExit, "cannot inspect"):
                release_index.tar_metadata_bytes(archive, "/MANIFEST.json")

            archive.write_bytes(original + gzip.compress(b"unexpected member"))
            with self.assertRaisesRegex(SystemExit, "more than one gzip member"):
                release_index.tar_metadata_bytes(archive, "/MANIFEST.json")

    def test_tar_metadata_requires_two_aligned_zero_trailer_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "fixture.tar.gz"
            payload = b"{}\n"
            in_memory = io.BytesIO()
            with tarfile.open(
                fileobj=in_memory, mode="w:", format=tarfile.USTAR_FORMAT
            ) as bundle:
                entry = tarfile.TarInfo("fixture/MANIFEST.json")
                entry.size = len(payload)
                bundle.addfile(entry, io.BytesIO(payload))
            tar_bytes = in_memory.getvalue()
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as bundle:
                for _member in bundle:
                    pass
                tar_end = bundle.offset

            archive.write_bytes(gzip.compress(tar_bytes[:tar_end] + b"\0" * 1024))
            self.assertEqual(
                release_index.tar_metadata_bytes(archive, "/MANIFEST.json"),
                payload,
            )
            for trailer, error in (
                (b"\0" * 512, "malformed tar trailer"),
                (b"\0" * 1024 + b"x", "malformed tar trailer"),
                (b"\0" * 1024 + b"x" * 512, "non-zero tar trailer"),
            ):
                archive.write_bytes(gzip.compress(tar_bytes[:tar_end] + trailer))
                with self.subTest(trailer_bytes=len(trailer)), self.assertRaisesRegex(
                    SystemExit, error
                ):
                    release_index.tar_metadata_bytes(archive, "/MANIFEST.json")

    def test_index_file_size_and_hash_come_from_one_descriptor_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_root = pathlib.Path(temporary).resolve()
            path = release_root / "payload.bin"
            path.write_bytes(b"snapshot")
            observed = release_index.digest_regular_file(path)
            item = {
                "path": path.name,
                "sha256": observed.sha256,
                "bytes": observed.size,
            }
            real_stat = pathlib.Path.stat

            def reject_following_stat(
                candidate: pathlib.Path,
                *arguments: object,
                **keywords: object,
            ) -> os.stat_result:
                if keywords.get("follow_symlinks") is False:
                    return real_stat(candidate, *arguments, **keywords)
                raise AssertionError("pathname stat must not supply indexed metadata")

            with mock.patch.object(
                pathlib.Path,
                "stat",
                autospec=True,
                side_effect=reject_following_stat,
            ):
                self.assertEqual(
                    release_index.verify_index_file(release_root, item),
                    path,
                )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires POSIX")
    def test_release_tree_rejects_unindexed_special_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, _ = self._fixture(root)
            fifo = index_path.parent / "unindexed.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(SystemExit, "special file"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )

    def test_release_tree_rejects_regular_files_not_declared_by_the_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, _ = self._fixture(root)
            private_file = index_path.parent / "private.mobileprovision"
            private_file.write_text("must not be indexed\n", encoding="utf-8")
            release_index.write_release_sums(index_path.parent)
            with self.assertRaisesRegex(SystemExit, "declared file set mismatch"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )

    def test_output_dir_is_derived_from_fixed_release_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            output = release_index.resolve_release_output(
                root,
                channel="release",
                version="0.1.0-alpha.2",
                commit="a" * 40,
            )
            self.assertEqual(
                output,
                root
                / "target/qperiapt-local-release/release/0.1.0-alpha.2"
                / ("a" * 40),
            )

    def test_existing_release_tree_is_immutable_and_pointer_remains_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, index = self._fixture(root)
            self._write_pointer(root, index_path)

            with self.assertRaisesRegex(SystemExit, "immutable and already exists"):
                release_index.resolve_release_output(
                    root,
                    channel="diagnostic",
                    version=index["version"],
                    commit=index["git"]["commit"],
                )

            selection = release_index.release_pointer_selection(root, "diagnostic")
            verified = release_index.verify_release_index_snapshot(
                selection.path,
                root,
                allow_diagnostic=True,
                expected_index_sha256=selection.expected_sha256,
                expected_generated_at=selection.expected_generated_at,
            )
            self.assertEqual(verified.path, index_path)

    def test_verified_staging_tree_uses_the_final_identity_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, _ = self._fixture(root)
            release_root = index_path.parent
            staging_root = release_root.parent / f".{release_root.name}.staging-fixture"
            release_root.rename(staging_root)
            staging_index = staging_root / "index.json"

            with self.assertRaisesRegex(SystemExit, "channel/version/commit identity"):
                release_index.verify_release_index_snapshot(
                    staging_index,
                    root,
                    allow_diagnostic=True,
                )

            verified = release_index.verify_release_index_snapshot(
                staging_index,
                root,
                allow_diagnostic=True,
                identity_index_path=index_path,
            )
            self.assertEqual(verified.path, staging_index)

    @unittest.skipUnless(os.name == "posix", "SIGTERM staging recovery is POSIX-only")
    def test_sigterm_during_staging_cannot_poison_the_final_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            version = "0.1.0-alpha.2"
            commit = "a" * 40
            final_root = (
                root
                / "target/qperiapt-local-release/diagnostic"
                / version
                / commit
            )
            (root / "target").mkdir(mode=0o700)
            module_root = pathlib.Path(release_index.__file__).resolve().parent
            child_source = f"""
import pathlib
import sys
import time
sys.path.insert(0, {str(module_root)!r})
import release_index
root = pathlib.Path(sys.argv[1]).resolve()
target = root / 'target'
final_root = target / 'qperiapt-local-release/diagnostic/{version}/{commit}'
staging_root, _identity = release_index.create_release_staging_tree(final_root, target)
(staging_root / 'partial.bin').write_bytes(b'partial')
print(staging_root, flush=True)
time.sleep(60)
"""
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            process = subprocess.Popen(
                [sys.executable, "-B", "-c", child_source, str(root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
            )
            try:
                self.assertIsNotNone(process.stdout)
                staging_line = process.stdout.readline().strip()
                self.assertTrue(staging_line)
                staging_root = pathlib.Path(staging_line)
                process.send_signal(signal.SIGTERM)
                self.assertLess(process.wait(timeout=10), 0)

                self.assertFalse(final_root.exists())
                self.assertEqual(
                    release_index.resolve_release_output(
                        root,
                        channel="diagnostic",
                        version=version,
                        commit=commit,
                    ),
                    final_root,
                )
                self.assertTrue(staging_root.is_dir())
                release_index.cleanup_stale_release_staging_trees(
                    final_root,
                    root / "target",
                )
                self.assertFalse(staging_root.exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "atomic publication rollback is POSIX-only",
    )
    def test_pending_sigterm_and_pointer_failure_roll_back_before_unmask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            target = root / "target"
            target.mkdir(mode=0o700)
            version = "0.1.0-alpha.2"
            commit = "a" * 40
            final_root = (
                target
                / "qperiapt-local-release/diagnostic"
                / version
                / commit
            )
            pointer_path = target / "qperiapt-local-release/latest-diagnostic.json"
            module_root = pathlib.Path(release_index.__file__).resolve().parent
            child_source = f"""
import os
import pathlib
import signal
import sys
sys.path.insert(0, {str(module_root)!r})
import release_index
root = pathlib.Path(sys.argv[1]).resolve()
target = root / 'target'
final_root = target / 'qperiapt-local-release/diagnostic/{version}/{commit}'
pointer_path = target / 'qperiapt-local-release/latest-diagnostic.json'
staging_root, identity = release_index.create_release_staging_tree(final_root, target)
(staging_root / 'verified.bin').write_bytes(b'verified')
def fail_before_pointer_commit(*_args, **_kwargs):
    os.kill(os.getpid(), signal.SIGTERM)
    raise OSError('injected pointer precommit failure')
release_index.write_json = fail_before_pointer_commit
release_index.publish_release_transaction(
    staging_root=staging_root,
    release_root=final_root,
    staging_identity=identity,
    target=target,
    pointer_path=pointer_path,
    pointer={{'fixture': True}},
)
"""
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            completed = subprocess.run(
                [sys.executable, "-B", "-c", child_source, str(root)],
                capture_output=True,
                text=True,
                env=environment,
                timeout=10,
                check=False,
            )

            self.assertEqual(completed.returncode, -signal.SIGTERM, completed.stderr)
            self.assertFalse(final_root.exists())
            self.assertFalse(pointer_path.exists())
            staging_entries = list(final_root.parent.glob(f".{commit}.staging-*"))
            self.assertEqual(staging_entries, [])
            self.assertEqual(
                release_index.resolve_release_output(
                    root,
                    channel="diagnostic",
                    version=version,
                    commit=commit,
                ),
                final_root,
            )

    def test_staging_recovery_rejects_unowned_names_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            target = root / "target"
            target.mkdir(mode=0o700)
            commit = "a" * 40
            final_root = (
                target
                / "qperiapt-local-release/diagnostic/0.1.0-alpha.2"
                / commit
            )
            release_index.ensure_private_directory(final_root.parent, target)
            malformed = final_root.parent / f".{commit}.staging-not-a-token"
            malformed.mkdir(mode=0o700)
            with self.assertRaisesRegex(SystemExit, "invalid owned name"):
                release_index.cleanup_stale_release_staging_trees(final_root, target)
            self.assertTrue(malformed.is_dir())
            malformed.rmdir()

            outside = root / "outside"
            outside.mkdir()
            symlink = final_root.parent / f".{commit}.staging-{'b' * 32}"
            symlink.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(SystemExit, "not one owned private directory"):
                release_index.cleanup_stale_release_staging_trees(final_root, target)
            self.assertTrue(symlink.is_symlink())
            self.assertTrue(outside.is_dir())
            symlink.unlink()

            stale_roots = [
                final_root.parent / f".{commit}.staging-{character * 32}"
                for character in ("c", "d")
            ]
            for stale_root in stale_roots:
                stale_root.mkdir(mode=0o700)
            with (
                mock.patch.object(
                    release_index,
                    "MAX_STALE_RELEASE_STAGING_TREES",
                    1,
                ),
                self.assertRaisesRegex(SystemExit, "too many stale staging trees"),
            ):
                release_index.cleanup_stale_release_staging_trees(final_root, target)
            self.assertTrue(all(stale_root.is_dir() for stale_root in stale_roots))

            fifo = stale_roots[1] / "unexpected.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(SystemExit, "special file"):
                release_index.cleanup_stale_release_staging_trees(final_root, target)
            self.assertTrue(all(stale_root.is_dir() for stale_root in stale_roots))
            fifo.unlink()
            release_index.cleanup_stale_release_staging_trees(final_root, target)
            self.assertTrue(all(not stale_root.exists() for stale_root in stale_roots))

            unrelated = [final_root.parent / name for name in ("one", "two")]
            for directory in unrelated:
                directory.mkdir(mode=0o700)
            with (
                mock.patch.object(
                    release_index,
                    "MAX_RELEASE_STAGING_PARENT_ENTRIES",
                    1,
                ),
                self.assertRaisesRegex(SystemExit, "exceeds its entry limit"),
            ):
                release_index.cleanup_stale_release_staging_trees(final_root, target)
            self.assertTrue(all(directory.is_dir() for directory in unrelated))

    def test_failed_first_emit_removes_unselected_tree_and_allows_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            trust = release_index.load_abi_trust_root(root)
            commit = release_index.git_commit(root)
            target = root / "target"
            host = "aarch64-apple-darwin"
            c_package = f"{trust.archive_prefix}-{trust.version}-{host}"
            c_dir = target / "qperiapt-c-abi2" / c_package
            swift_dir = (
                target
                / "qperiapt-swift-xcframework"
                / f"q-periapt-swift-{trust.version}"
            )
            android_dir = (
                target
                / "qperiapt-android-aar"
                / f"q-periapt-android-{trust.version}"
            )
            source_files = (
                c_dir / "MANIFEST.json",
                target / "qperiapt-c-abi2" / f"{c_package}.tar.gz",
                swift_dir / "MANIFEST.json",
                swift_dir / "CQPeriapt.xcframework.zip",
                android_dir / "MANIFEST.json",
                android_dir / f"q-periapt-android-{trust.version}.aar",
            )
            for source_file in source_files:
                source_file.parent.mkdir(parents=True, exist_ok=True)
                source_file.write_bytes(b"fixture")

            manifests = {
                "c-abi": self._manifest(trust, "c-abi", "e" * 64, commit),
                "swift": self._manifest(trust, "swift", "e" * 64, commit),
                "android": self._manifest(trust, "android", "e" * 64, commit),
            }
            attempts = 0

            def build_tree(
                _args: object,
                **arguments: object,
            ) -> release_index.BuiltReleaseTree:
                nonlocal attempts
                attempts += 1
                release_root = pathlib.Path(arguments["release_root"])
                if attempts == 1:
                    (release_root / "partial.bin").write_bytes(b"partial")
                    raise SystemExit("error: injected first-build failure")
                index_path = release_root / "index.json"
                release_index.write_json(index_path, {"attempt": attempts})
                return release_index.BuiltReleaseTree(
                    index_path=index_path,
                    index_sha256=release_index.sha256_file(index_path),
                    generated_at="2026-07-12T00:00:00Z",
                )

            def validate_manifest(
                _path: pathlib.Path,
                _commit: str,
                _version: str,
                _channel: str,
                face: str,
                _trust: release_index.AbiTrustRoot,
            ) -> dict:
                return manifests[face]

            arguments = argparse.Namespace(
                channel="diagnostic",
                apple_matrix_run="",
                include_android_runtime=False,
            )
            release_root = (
                target
                / "qperiapt-local-release"
                / "diagnostic"
                / trust.version
                / commit
            )
            pointer = target / "qperiapt-local-release/latest-diagnostic.json"
            with (
                mock.patch.object(release_index, "REPOSITORY_ROOT", root),
                mock.patch.object(
                    release_index,
                    "cargo_version",
                    return_value=trust.version,
                ),
                mock.patch.object(release_index, "rust_host", return_value=host),
                mock.patch.object(release_index, "verify_sha256s"),
                mock.patch.object(
                    release_index,
                    "validate_package_manifest",
                    side_effect=validate_manifest,
                ),
                mock.patch.object(
                    release_index,
                    "build_release_tree",
                    side_effect=build_tree,
                ),
            ):
                with self.assertRaisesRegex(SystemExit, "injected first-build failure"):
                    release_index.build_index(arguments)
                self.assertFalse(release_root.exists())
                self.assertFalse(pointer.exists())

                emitted = release_index.build_index(arguments)

            self.assertEqual(emitted, release_root / "index.json")
            self.assertTrue(emitted.is_file())
            self.assertTrue(pointer.is_file())
            self.assertEqual(attempts, 2)

    def test_cli_has_no_caller_controlled_repository_or_output_path(self) -> None:
        source = pathlib.Path(release_index.__file__).read_text(encoding="utf-8")
        for option in (
            "--root",
            "--index",
            "--output-dir",
            "--apple-matrix-proof",
            "--android-proof",
        ):
            self.assertNotIn(f'add_argument("{option}"', source)

    def test_pointer_digest_is_checked_against_the_verified_index_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, _ = self._fixture(root)
            self._write_pointer(root, index_path)
            selection = release_index.release_pointer_selection(root, "diagnostic")
            original = index_path.read_bytes()
            index_path.write_bytes(original + b" ")
            with self.assertRaisesRegex(SystemExit, "pointer index hash mismatch"):
                release_index.verify_release_index(
                    selection.path,
                    root,
                    allow_diagnostic=True,
                    expected_index_sha256=selection.expected_sha256,
                    expected_generated_at=selection.expected_generated_at,
                )

    def test_pointer_generated_at_must_match_the_verified_index_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, _ = self._fixture(root)
            pointer_path = self._write_pointer(root, index_path)
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            pointer["generated_at"] = "2026-07-13T00:00:00Z"
            release_index.write_json(pointer_path, pointer)
            selection = release_index.release_pointer_selection(root, "diagnostic")

            with self.assertRaisesRegex(
                SystemExit,
                "generated_at differs from the verified index snapshot",
            ):
                release_index.verify_release_index(
                    selection.path,
                    root,
                    allow_diagnostic=True,
                    expected_index_sha256=selection.expected_sha256,
                    expected_generated_at=selection.expected_generated_at,
                )

    def test_index_path_must_match_its_declared_commit_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, _ = self._fixture(root)
            replacement_commit = "b" * 40
            moved_release_root = index_path.parent.parent / replacement_commit
            index_path.parent.rename(moved_release_root)
            moved_index = moved_release_root / "index.json"

            with self.assertRaisesRegex(
                SystemExit,
                "path differs from its channel/version/commit identity",
            ):
                release_index.verify_release_index(
                    moved_index,
                    root,
                    allow_diagnostic=True,
                )

    def test_index_snapshot_is_loaded_once_and_pins_the_outer_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, _ = self._fixture(root)
            original_loader = release_index.load_json_object_snapshot
            index_loads = 0

            def count_index_loads(path: pathlib.Path, **arguments: object):
                nonlocal index_loads
                if pathlib.Path(path) == index_path:
                    index_loads += 1
                return original_loader(path, **arguments)

            with mock.patch.object(
                release_index,
                "load_json_object_snapshot",
                side_effect=count_index_loads,
            ):
                release_index.verify_release_index(
                    index_path,
                    root,
                    allow_diagnostic=True,
                )
            self.assertEqual(index_loads, 1)

            sums_path = index_path.parent / "SHA256SUMS"
            lines = sums_path.read_text(encoding="utf-8").splitlines()
            sums_path.write_text(
                "\n".join(
                    f"{'f' * 64}  index.json" if line.endswith("  index.json") else line
                    for line in lines
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                SystemExit, "does not bind the verified snapshot"
            ):
                release_index.verify_release_index(
                    index_path,
                    root,
                    allow_diagnostic=True,
                )

    def test_pointer_path_and_checksum_paths_are_canonically_rebuilt(self) -> None:
        class InputString(str):
            pass

        raw = InputString("packages/c/package.tar.gz")
        canonical = release_index.require_relative_safe(raw, "fixture path")
        self.assertEqual(canonical, raw)
        self.assertIsNot(canonical, raw)
        for unsafe in (
            "packages//c/package.tar.gz",
            "packages/./c/package.tar.gz",
            "packages/../outside",
            "packages/c/package name.tar.gz",
        ):
            with self.subTest(path=unsafe), self.assertRaises(SystemExit):
                release_index.require_relative_safe(unsafe, "fixture path")

    def test_copy_failure_does_not_remove_a_preexisting_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = root / "source.bin"
            release_root = root / "release"
            destination = release_root / "existing.bin"
            source.write_bytes(b"source")
            release_root.mkdir()
            destination.write_bytes(b"preserve")
            with self.assertRaisesRegex(SystemExit, "cannot copy release artifact"):
                release_index.copy_to_release(
                    source,
                    root,
                    release_root,
                    destination.name,
                )
            self.assertEqual(destination.read_bytes(), b"preserve")

    def test_private_writer_migrates_existing_output_to_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            output = root / "pointer.json"
            output.write_bytes(b"old")
            output.chmod(0o644)

            release_index.write_private_bytes(output, b"new")

            self.assertEqual(output.read_bytes(), b"new")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_private_writer_reports_commit_before_post_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            output = root / "pointer.json"
            output.write_bytes(b"old")
            committed = False
            original_fsync = os.fsync
            fsync_calls = 0

            def mark_committed() -> None:
                nonlocal committed
                committed = True

            def fail_directory_fsync(descriptor: int) -> None:
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 2:
                    raise OSError("injected post-replace fsync failure")
                original_fsync(descriptor)

            with mock.patch.object(os, "fsync", side_effect=fail_directory_fsync):
                with self.assertRaisesRegex(SystemExit, "post-replace fsync failure"):
                    release_index.write_private_bytes(
                        output,
                        b"new",
                        on_commit=mark_committed,
                    )

            self.assertTrue(committed)
            self.assertEqual(output.read_bytes(), b"new")

    @unittest.skipUnless(
        hasattr(signal, "pthread_sigmask"),
        "atomic signal handoff requires POSIX signal masks",
    )
    def test_private_writer_commits_before_pending_sigint_is_delivered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            output = root / "pointer.json"
            output.write_bytes(b"old")
            committed = False
            original_replace = os.replace

            def mark_committed() -> None:
                nonlocal committed
                committed = True

            def replace_then_signal(*args: object, **kwargs: object) -> None:
                original_replace(*args, **kwargs)
                os.kill(os.getpid(), signal.SIGINT)

            with mock.patch.object(
                os,
                "replace",
                side_effect=replace_then_signal,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    release_index.write_private_bytes(
                        output,
                        b"new",
                        on_commit=mark_committed,
                    )

            self.assertTrue(committed)
            self.assertEqual(output.read_bytes(), b"new")

    def test_copy_entry_uses_the_copied_stream_and_removes_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = root / "source.bin"
            release_root = root / "release"
            payload = b"copied-stream"
            source.write_bytes(payload)
            release_root.mkdir()
            entry = release_index.copy_to_release(
                source, root, release_root, "copied.bin"
            )
            self.assertEqual(entry["bytes"], len(payload))
            self.assertEqual(entry["sha256"], release_index.sha256_bytes(payload))
            self.assertEqual((release_root / "copied.bin").read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(release_root.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((release_root / "copied.bin").stat().st_mode),
                0o600,
            )

            original_read = os.read
            reads = 0

            def fail_after_first_read(descriptor: int, size: int) -> bytes:
                nonlocal reads
                reads += 1
                if reads > 1:
                    raise OSError("fixture read failure")
                return original_read(descriptor, size)

            with mock.patch.object(os, "read", side_effect=fail_after_first_read):
                with self.assertRaisesRegex(SystemExit, "cannot copy release artifact"):
                    release_index.copy_to_release(
                        source, root, release_root, "partial.bin"
                    )
            self.assertFalse((release_root / "partial.bin").exists())

    def test_complete_diagnostic_fixture_passes_only_with_explicit_allow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, _ = self._fixture(root)
            with self.assertRaisesRegex(SystemExit, "explicit allow_diagnostic"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=False
                )
            release_index.verify_release_index(
                index_path, root, allow_diagnostic=True
            )
            self.assertEqual(len(release_index.parse_sha256s(index_path.parent)), 10)

    def test_forged_manifest_fails_after_all_outer_hashes_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            index_path, index = self._fixture(root)
            release_root = index_path.parent
            swift_artifact = next(
                item for item in index["artifacts"] if item["face"] == "swift"
            )
            swift_manifest_path = release_root / swift_artifact["manifest"]["path"]
            forged = json.loads(swift_manifest_path.read_text(encoding="utf-8"))
            forged["abi"]["contract_sha256"] = "f" * 64
            release_index.write_json(swift_manifest_path, forged)

            # Simulate an attacker who also rewrites every unauthenticated outer
            # digest and the duplicated semantic projection.
            swift_artifact["manifest"] = self._file_entry(
                swift_manifest_path, release_root
            )
            swift_artifact["package_semantics"] = (
                release_index.normalized_package_semantics(forged)
            )
            release_index.write_json(index_path, index)
            release_index.write_release_sums(release_root)

            with self.assertRaisesRegex(SystemExit, "ABI contract hash mismatch"):
                release_index.verify_release_index(
                    index_path, root, allow_diagnostic=True
                )

    def test_cross_face_core_semantics_must_match(self) -> None:
        trust_semantics = {
            "name": "fixture",
            "version": "0.1.0-alpha.2",
            "abi": {
                "major": 2,
                "contract_sha256": "a" * 64,
                "exports_sha256": "b" * 64,
                "export_count": 9,
                "platform": "fixture",
                "runtime_identity": "fixture",
                "shared_filename": "libfixture.so.2",
                "static_filename": "libfixture_abi2.a",
            },
        }
        semantics = {
            face: copy.deepcopy(trust_semantics)
            for face in release_index.EXPECTED_FACES
        }
        semantics["android"]["abi"]["exports_sha256"] = "c" * 64
        with self.assertRaisesRegex(SystemExit, "differs across faces"):
            release_index.validate_cross_face_semantics(semantics)


if __name__ == "__main__":
    unittest.main()
