from __future__ import annotations

import copy
import json
import pathlib
import shutil
import tarfile
import tempfile
import unittest

import release_index


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
        return root

    def _manifest(
        self,
        trust: release_index.AbiTrustRoot,
        face: str,
        package_sha256: str,
    ) -> dict:
        common_abi = {
            "major": release_index.ABI_MAJOR,
            "contract_sha256": trust.contract_sha256,
            "exports_sha256": trust.exports_sha256,
            "export_count": release_index.EXPORT_COUNT,
            "contract_path": release_index.CONTRACT_RELATIVE_PATH.as_posix(),
        }
        if face == "c-abi":
            platform = "macos"
            identity = trust.platforms[platform]
            abi = {
                **common_abi,
                "platform": platform,
                "runtime_identity": identity,
                "shared_filename": identity["shared_filename"],
                "static_filename": identity["static_filename"],
            }
            package = f"{trust.archive_prefix}-{trust.version}-test-host"
            artifacts: dict = {}
        elif face == "swift":
            abi = {
                **common_abi,
                "platform": "apple-xcframework",
                "runtime_identity": {
                    "container": "xcframework",
                    "linkage": "static",
                },
                "shared_filename": "libq_periapt_ffi_abi2.dylib",
                "static_filename": "libq_periapt_ffi_abi2.a",
            }
            package = "q-periapt-swift"
            artifacts = {"xcframework_zip": {"sha256": package_sha256}}
        else:
            abi = {
                **common_abi,
                "platform": "android",
                "runtime_identity": {
                    "jni_dependency": "libq_periapt_ffi_abi2.so"
                },
                "shared_filename": "libq_periapt_ffi_abi2.so",
                "static_filename": "libq_periapt_ffi_abi2.a",
            }
            package = f"q-periapt-android-{trust.version}.aar"
            artifacts = {"aar_sha256": package_sha256}
        return {
            "schema_version": release_index.PACKAGE_MANIFEST_SCHEMA_VERSION,
            "package": package,
            "version": trust.version,
            "git_commit": "a" * 40,
            "git_dirty": False,
            "abi": abi,
            "artifacts": artifacts,
        }

    @staticmethod
    def _file_entry(path: pathlib.Path, release_root: pathlib.Path) -> dict:
        return {
            "path": path.relative_to(release_root).as_posix(),
            "sha256": release_index.sha256_file(path),
            "bytes": path.stat().st_size,
        }

    def _fixture(self, root: pathlib.Path) -> tuple[pathlib.Path, dict]:
        trust = release_index.load_abi_trust_root(root)
        release_root = (
            root
            / "target/qperiapt-local-release/diagnostic"
            / trust.version
            / ("a" * 40)
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
                trust, "swift", release_index.sha256_file(package_paths["swift"])
            ),
            "android": self._manifest(
                trust, "android", release_index.sha256_file(package_paths["android"])
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

        c_manifest = self._manifest(trust, "c-abi", "")
        c_manifest_path = release_root / "manifests/c/MANIFEST.json"
        c_sums_path = release_root / "manifests/c/SHA256SUMS"
        c_manifest_path.parent.mkdir(parents=True)
        release_index.write_json(c_manifest_path, c_manifest)
        c_sums_path.write_text("fixture internal checksums\n", encoding="utf-8")
        c_archive = release_root / (
            f"packages/c/{trust.archive_prefix}-{trust.version}-test-host.tar.gz"
        )
        c_archive.parent.mkdir(parents=True)
        with tempfile.TemporaryDirectory() as archive_temporary:
            package_root = pathlib.Path(archive_temporary) / (
                f"{trust.archive_prefix}-{trust.version}-test-host"
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
        for face, artifact_id, kind in (
            ("c-abi", "c-abi/test-host", "tar.gz"),
            ("swift", "swift/xcframework", "xcframework.zip"),
            ("android", "android/aar", "aar"),
        ):
            artifacts.append(
                {
                    "id": artifact_id,
                    "face": face,
                    "type": kind,
                    "files": [self._file_entry(package_paths[face], release_root)],
                    "manifest": self._file_entry(manifest_paths[face], release_root),
                    "sha256s": self._file_entry(sums_paths[face], release_root),
                    "package_semantics": release_index.normalized_package_semantics(
                        manifests[face]
                    ),
                    "boundary": {},
                    "verified_by": "fixture",
                    "targets": [],
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
            "git": {"commit": "a" * 40, "source_tree_dirty": False},
            "release_boundary": {
                "public_release": False,
                "registry_uploaded": False,
                "raw_device_proofs_copied": False,
                "requires_clean_tree_for_release": True,
            },
            "artifacts": artifacts,
            "proof_summaries": {},
        }
        index_path = release_root / "index.json"
        release_index.write_json(index_path, index)
        release_index.write_release_sums(release_root)
        return index_path, index

    def test_output_dir_rejects_roots_inputs_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = root / "target"
            target.mkdir()
            common = {
                "channel": "release",
                "version": "0.1.0-alpha.2",
                "commit": "a" * 40,
            }
            rejected = (
                target,
                target / "qperiapt-local-release",
                target / "qperiapt-local-release/release",
                target / "qperiapt-c-abi2/input-package",
            )
            for path in rejected:
                with self.subTest(path=path), self.assertRaises(SystemExit):
                    release_index.resolve_release_output(
                        root, str(path), **common
                    )

            channel_root = target / "qperiapt-local-release/release"
            channel_root.mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            link = channel_root / "linked-output"
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(SystemExit, "must not traverse a symlink"):
                release_index.resolve_release_output(root, str(link), **common)

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
